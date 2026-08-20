#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import selectors
import shlex
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIRECTORY = ROOT / "scripts"
sys.path[:0] = [str(SCRIPT_DIRECTORY), str(ROOT)]

import launch_authorization  # noqa: E402
KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
PLACEHOLDER_RE = re.compile(
    r"(<[^>]+>|\$\{[^}]+\}|CHANGE[_-]?ME|REPLACE[_-]?ME|FILL[_-]?ME|TODO|TBD)",
    re.IGNORECASE,
)
EXAMPLE_DOMAIN_RE = re.compile(r"(^|[/:@,])([A-Za-z0-9-]+\.)*example([/:,]|$)", re.IGNORECASE)
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
PRODUCTION_PYTHON_EXECUTABLE_ENV = "SERVERWARE_PRODUCTION_PYTHON_EXECUTABLE"
EXECUTABLE_DIGEST_MANIFEST_ENV = "SERVERWARE_ATTESTATION_EXECUTABLE_SHA256_MANIFEST"
ATTESTATION_HELPER_COMMAND_SETTINGS = (
    "SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE",
    "SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE",
    "SERVERWARE_DATA_PLANE_RECIPIENT_ATTESTATION_COMMAND",
    "SERVERWARE_DATA_PLANE_RESPONSE_PROOF_ATTESTATION_COMMAND",
    "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND",
    "SERVERWARE_CONTROL_PLANE_ATTESTATION_VERIFY_COMMAND",
    "SERVERWARE_RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND",
)
PROOF_COLLECTOR_COMMAND_SETTING = "SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND"
PROXY_PROOF_CONTRACT_ENV = "SERVERWARE_PROXY_PROOF_CONTRACT"
PROXY_STREAM_BODY_FILE_ENV = "SERVERWARE_PROXY_STREAM_BODY_FILE"
PROXY_PROOF_MAX_STREAM_BYTES_ENV = "SERVERWARE_PROXY_PROOF_MAX_STREAM_BYTES"
PROXY_OBSERVATION_BODY_FILE_ENV = "SERVERWARE_PROXY_OBSERVATION_BODY_FILE"
PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV = (
    "SERVERWARE_PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES"
)
PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST_ENV = (
    "SERVERWARE_PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST"
)
BUFFERED_PROXY_PROOF_CONTRACT = "buffered-v3"
OBSERVATION_PROXY_PROOF_CONTRACT = "observation-v1"
STREAMING_PROXY_PROOF_CONTRACT = "streaming-v1"
PROXY_PROOF_CONTRACTS = frozenset(
    (
        BUFFERED_PROXY_PROOF_CONTRACT,
        OBSERVATION_PROXY_PROOF_CONTRACT,
        STREAMING_PROXY_PROOF_CONTRACT,
    )
)
PRODUCTION_DOCKER_EXECUTABLE_ENV = "SERVERWARE_DOCKER_EXECUTABLE"
DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV = "SERVERWARE_DOCKER_COMPOSE_PLUGIN_EXECUTABLE"
DOCKER_COMPOSE_PLUGIN_SHA256_ENV = "SERVERWARE_DOCKER_COMPOSE_PLUGIN_SHA256"
DOCKER_UNIX_SOCKET_ENV = "SERVERWARE_DOCKER_UNIX_SOCKET"
DOCKER_DAEMON_ID_ENV = "SERVERWARE_DOCKER_DAEMON_ID"
DOCKER_COMPOSE_PROJECT_NAME_ENV = "SERVERWARE_DOCKER_COMPOSE_PROJECT_NAME"
VERIFY_PRODUCTION_READINESS_SCRIPT_SHA256_ENV = (
    "SERVERWARE_VERIFY_PRODUCTION_READINESS_SCRIPT_SHA256"
)
VERIFY_RELEASE_COMPLETION_SCRIPT_SHA256_ENV = (
    "SERVERWARE_VERIFY_RELEASE_COMPLETION_SCRIPT_SHA256"
)
PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV = (
    "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256"
)
PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV = "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_MAX_AGE_SECONDS"
PRODUCTION_HOST_PREFLIGHT_SIGNING_PRIVATE_KEY_ENV = (
    "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_SIGNING_PRIVATE_KEY"
)
PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV = (
    "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY"
)
PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV = (
    "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID"
)
PINNED_PYTHON_SCRIPTS = {
    "production_host_preflight.py": PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV,
    "verify_production_readiness.py": VERIFY_PRODUCTION_READINESS_SCRIPT_SHA256_ENV,
    "verify_release_completion.py": VERIFY_RELEASE_COMPLETION_SCRIPT_SHA256_ENV,
}
FINAL_LAUNCHER_CONTRACT_ENV = "SERVERWARE_FINAL_LAUNCHER_CONTRACT"
FINAL_LAUNCHER_CONTRACT = "descriptor-sealed-bootstrap-v3"
BOOTSTRAP_RECEIPT_FD_ENV = "SERVERWARE_BOOTSTRAP_RECEIPT_FD"
BOOTSTRAP_RECEIPT_SHA256_ENV = "SERVERWARE_BOOTSTRAP_RECEIPT_SHA256"
BOOTSTRAP_RECEIPT_API_VERSION_ENV = "SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION"
BOOTSTRAP_RECEIPT_API_VERSION = "serverware.bootstrapReceipt/v3"
BOOTSTRAP_RECEIPT_KIND = "ProductionBootstrapReceipt"
BOOTSTRAP_RECEIPT_FIXED_FD = 198
COMPLETION_PROOF_API_VERSION = "serverware.completionProof/v6"
COMPLETION_PROOF_V6_ENVELOPE_FIELDS = frozenset(
    {
        "proof_core_sha256",
        "independently_authenticated",
        "aggregate_authentication",
        "proof_path",
        "integrity_metadata",
    }
)
FINAL_COMPLETION_RESULT_API_VERSION = (
    "serverware.releaseCompletionVerification/v1"
)
LAUNCH_AUTHORIZATION_REQUEST_API_VERSION = (
    "serverware.launchAuthorizationRequest/v2"
)
LAUNCH_AUTHORIZATION_API_VERSION = "serverware.launchAuthorization/v2"
NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION = (
    "serverware.productionNonceRollbackAssuranceBinding/v1"
)
NONCE_ROLLBACK_ASSURANCE_PINS_API_VERSION = (
    "serverware.productionNonceRollbackAssurancePins/v1"
)
NONCE_ROLLBACK_ASSURANCE_REQUEST_DOMAIN = (
    LAUNCH_AUTHORIZATION_REQUEST_API_VERSION.encode("ascii") + b"\0"
)
NONCE_ROLLBACK_ASSURANCE_AUTHORIZATION_DOMAIN = (
    LAUNCH_AUTHORIZATION_API_VERSION.encode("ascii") + b"\0"
)
MAX_NONCE_ROLLBACK_ASSURANCE_PINS_BYTES = 64 * 1024
NONCE_ROLLBACK_ASSURANCE_JSON_INTEGER_MAX = 9_007_199_254_740_991
PRODUCTION_NONCE_ASSURANCE_PROFILES = (
    {
        "assuranceEvidenceType": "hardwareMonotonicCounterAttestation",
        "backendClass": "hardwareMonotonicCounter",
        "keyProtection": "nonExportableHsm",
        "rollbackMechanism": "hardwareMonotonicCounter",
        "stateCommitment": "monotonicCounterCommitment",
        "verifierStateStoreClass": "hardwareProtectedStateStore",
    },
    {
        "assuranceEvidenceType": "linearizableCasOperatorAttestation",
        "backendClass": "independentlyAdministeredLinearizableCas",
        "keyProtection": "nonExportableKmsHsm",
        "rollbackMechanism": "linearizableCasWithRollbackProtectedStorage",
        "stateCommitment": "hashChainedLinearizableCommitment",
        "verifierStateStoreClass": "independentlyAdministeredLinearizableCas",
    },
    {
        "assuranceEvidenceType": "transparencyLedgerOperatorAttestation",
        "backendClass": "appendOnlyTransparencyLedger",
        "keyProtection": "nonExportableKmsHsm",
        "rollbackMechanism": "appendOnlyWitnessedLedger",
        "stateCommitment": "appendOnlyMerkleCommitment",
        "verifierStateStoreClass": "independentlyAdministeredLinearizableCas",
    },
)
LAUNCH_AUTHORITY_ROOT_PATH = (
    ROOT
    / "data-plane"
    / "decision-gate-rs"
    / "trust"
    / "launch-authority-root.ed25519.hex"
)
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
FINAL_SECURITY_ROLE_NAMES = (
    "launch_authority_signer",
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
)
BOOTSTRAP_RECEIPT_ENV_NAMES = frozenset(
    (
        BOOTSTRAP_RECEIPT_FD_ENV,
        BOOTSTRAP_RECEIPT_SHA256_ENV,
        BOOTSTRAP_RECEIPT_API_VERSION_ENV,
    )
)
BOOTSTRAP_RECEIPT_INPUT_NAMES = frozenset(
    (
        "productionImagesBuild",
        "productionImagesEnv",
        "productionImagesPublished",
        "releaseProvenanceSummary",
        "releaseProvenance",
        "imageSignaturesSummary",
        "imageSignatures",
        "bench",
        "kmsMaterials",
        "policyBundle",
        "policyTrustedPublicKey",
        "policyIdentityVerification",
        "policyActivationVerification",
        "policyActivationSignature",
        "policyActivationTrustedPublicKey",
        "reproducibleBuildVerification",
        "reproducibleBuildSignature",
        "reproducibleBuildTrustedPublicKey",
    )
)
BOOTSTRAP_RECEIPT_COMMITTED_ENV_NAMES = [
    "LANG",
    "LC_ALL",
    "PATH",
    BOOTSTRAP_RECEIPT_API_VERSION_ENV,
    BOOTSTRAP_RECEIPT_FD_ENV,
    BOOTSTRAP_RECEIPT_SHA256_ENV,
    "TZ",
]
POLICY_TRUST_ROOT_ENV = "SERVERWARE_POLICY_IDENTITY_TRUSTED_PUBLIC_KEY"
POLICY_TRUST_ROOT_ID_ENV = "SERVERWARE_POLICY_IDENTITY_TRUSTED_PUBLIC_KEY_ID"
POLICY_ACTIVATION_TRUST_ROOT_ENV = (
    "SERVERWARE_POLICY_ACTIVATION_TRUSTED_PUBLIC_KEY"
)
POLICY_ACTIVATION_TRUST_ROOT_ID_ENV = (
    "SERVERWARE_POLICY_ACTIVATION_TRUSTED_PUBLIC_KEY_ID"
)
REPRODUCIBLE_BUILD_TRUST_ROOT_ENV = (
    "SERVERWARE_REPRODUCIBLE_BUILD_TRUSTED_PUBLIC_KEY"
)
REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV = (
    "SERVERWARE_REPRODUCIBLE_BUILD_TRUSTED_PUBLIC_KEY_ID"
)
FINAL_CONTROL_PLANE_UID = 65532
FINAL_CONTROL_PLANE_GID = 65532
FINAL_SERVICE_USERS = {
    "serverware": "65532:65532",
    "audit-anchor": "nonroot:nonroot",
    "custody-runtime": "65531:65530",
    "decision-gate-rs": "65532:65532",
}
LAUNCHER_TRUSTED_ENV_PATH_INPUT = "SERVERWARE_LAUNCHER_TRUSTED_PRODUCTION_ENV_PATH"
LAUNCHER_TRUSTED_ENV_SHA256_INPUT = "SERVERWARE_LAUNCHER_TRUSTED_PRODUCTION_ENV_SHA256"
LAUNCHER_TRUST_INPUT_NAMES = frozenset(
    (LAUNCHER_TRUSTED_ENV_PATH_INPUT, LAUNCHER_TRUSTED_ENV_SHA256_INPUT)
)
PINNED_EXECUTABLE_COMMAND_SETTINGS = frozenset(
    (
        *ATTESTATION_HELPER_COMMAND_SETTINGS,
        PROOF_COLLECTOR_COMMAND_SETTING,
        PRODUCTION_PYTHON_EXECUTABLE_ENV,
        PRODUCTION_DOCKER_EXECUTABLE_ENV,
    )
)
PROXY_DIGEST_ENV_SETTINGS = {
    "proxy_client_request_digest": "SERVERWARE_PROXY_EXPECTED_CLIENT_REQUEST_DIGEST",
    "proxy_request_digest": "SERVERWARE_PROXY_EXPECTED_REQUEST_DIGEST",
    "proxy_operation_digest": "SERVERWARE_PROXY_EXPECTED_OPERATION_DIGEST",
}
COMPLETION_P99_LIMIT_ENV = "SERVERWARE_COMPLETION_P99_LIMIT_MS"
MAX_COMPLETION_PROOF_BYTES = 64 * 1024 * 1024
MAX_PROXY_STREAM_BODY_BYTES = 64 * 1024 * 1024
MAX_PROXY_OBSERVATION_BODY_BYTES = 16 * 1024 * 1024
MAX_PROXY_TRUST_INPUT_BYTES = 4 * 1024 * 1024
RESPONSE_OBSERVATION_NONCE_LIFETIME_SECONDS = 300
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_PRODUCTION_ENV_BYTES = 8 * 1024 * 1024
MAX_BOOTSTRAP_RECEIPT_BYTES = 4 * 1024 * 1024
COMPLETION_PROOF_FUTURE_SKEW_SECONDS = 5
LINUX_F_GET_SEALS = 1034
LINUX_F_SEAL_SEAL = 0x0001
LINUX_F_SEAL_SHRINK = 0x0002
LINUX_F_SEAL_GROW = 0x0004
LINUX_F_SEAL_WRITE = 0x0008
REQUIRED_BOOTSTRAP_RECEIPT_SEALS = (
    LINUX_F_SEAL_SEAL
    | LINUX_F_SEAL_SHRINK
    | LINUX_F_SEAL_GROW
    | LINUX_F_SEAL_WRITE
)
FINAL_CHILD_FIXED_ENV = {
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "TZ": "UTC",
}
FORBIDDEN_PROCESS_ENV_NAMES = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "GCONV_PATH",
        "GLIBC_TUNABLES",
        "NODE_OPTIONS",
        "PERL5LIB",
        "RUBYLIB",
    }
)
FORBIDDEN_PROCESS_ENV_PREFIXES = (
    "COMPOSE_",
    "DOCKER_",
    "DYLD_",
    "LD_",
    "MALLOC_",
    "PYTHON",
)
PYTHON_FD_BOOTSTRAP = (
    "import os,sys;fd=int(sys.argv[1]);path=sys.argv[2];"
    "root=os.path.dirname(os.path.dirname(path));"
    "sys.path[:0]=[os.path.join(root,'scripts'),root];"
    "os.environ['SERVERWARE_EXECUTING_SCRIPT_FD']=str(fd);"
    "sys.argv=[path,*sys.argv[3:]];"
    "size=os.fstat(fd).st_size;os.lseek(fd,0,os.SEEK_SET);"
    "data=b'';"
    "\nwhile len(data)<size:\n data+=os.read(fd,min(65536,size-len(data)))\n"
    "\nif len(data)!=size: raise RuntimeError('measured Python script changed while executing')\n"
    "scope={'__name__':'__main__','__file__':path,'__package__':None,'__cached__':None};"
    "exec(compile(data,path,'exec'),scope,scope)"
)


@dataclass
class MeasuredExecutable:
    path: Path
    setting: str
    fd: int
    metadata: os.stat_result
    sha256: str

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


@dataclass
class MeasuredScript:
    path: Path
    setting: str
    fd: int
    metadata: os.stat_result
    sha256: str

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load_launch_authority_identity() -> dict[str, Any]:
    path = LAUNCH_AUTHORITY_ROOT_PATH
    validate_secure_ancestors(path, "launch authority trust root")
    raw, metadata = read_regular_file_once(
        path,
        "launch authority trust root",
        max_bytes=65,
    )
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ValueError("launch authority trust root must be owned by root or the executing user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError("launch authority trust root must not be writable by group or other")
    if re.fullmatch(rb"[0-9a-f]{64}\n", raw) is None:
        raise ValueError(
            "launch authority trust root must contain exactly 32 lowercase-hex bytes and one LF"
        )
    spki = ED25519_SPKI_PREFIX + bytes.fromhex(raw[:-1].decode("ascii"))
    try:
        key_id = launch_authorization.spki_key_id(spki)
    except launch_authorization.LaunchAuthorizationError as exc:
        raise ValueError(f"launch authority trust root is invalid: {exc}") from exc
    return {
        "spki": spki,
        "keyId": key_id,
        "rootSha256": sha256_prefixed_bytes(raw),
    }


def load_launch_authority_spki() -> bytes:
    return load_launch_authority_identity()["spki"]


def _validate_v2_launch_authorization_request(value: Any) -> dict[str, Any]:
    try:
        return launch_authorization.validate_launch_authorization_request(value)
    except launch_authorization.LaunchAuthorizationError as exc:
        raise ValueError(
            f"bootstrap receipt launch authorization request is invalid: {exc}"
        ) from exc


def _v2_launch_authorization_request_sha256(request: Any) -> str:
    try:
        return launch_authorization.launch_authorization_request_sha256(request)
    except launch_authorization.LaunchAuthorizationError as exc:
        raise ValueError(
            f"bootstrap receipt launch authorization request is invalid: {exc}"
        ) from exc


def _decode_canonical_ed25519_signature(value: Any) -> bytes:
    if (
        type(value) is not str
        or "=" in value
        or re.fullmatch(r"[A-Za-z0-9_-]+", value, re.ASCII) is None
    ):
        raise ValueError(
            "bootstrap receipt launch authorization signature is not canonical base64url"
        )
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "bootstrap receipt launch authorization signature is not canonical base64url"
        ) from exc
    if (
        len(decoded) != 64
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
        != value
    ):
        raise ValueError(
            "bootstrap receipt launch authorization signature is not exactly 64 canonical bytes"
        )
    return decoded


def _validate_v2_launch_authorization(value: Any) -> dict[str, Any]:
    envelope = _closed_object(
        value,
        {"apiVersion", "kind", "statement", "signature"},
        "launch authorization",
    )
    if (
        envelope["apiVersion"] != LAUNCH_AUTHORIZATION_API_VERSION
        or envelope["kind"] != "ProductionLaunchAuthorization"
    ):
        raise ValueError("bootstrap receipt launch authorization is not v2")
    try:
        statement = launch_authorization.validate_launch_authorization_statement(
            envelope["statement"]
        )
    except launch_authorization.LaunchAuthorizationError as exc:
        raise ValueError(
            f"bootstrap receipt launch authorization statement is invalid: {exc}"
        ) from exc
    _decode_canonical_ed25519_signature(envelope["signature"])
    return {
        "apiVersion": envelope["apiVersion"],
        "kind": envelope["kind"],
        "statement": statement,
        "signature": envelope["signature"],
    }


def _verify_v2_launch_authorization_signature(
    envelope: dict[str, Any],
    *,
    authority_spki: bytes,
    expected_authority_key_id: str,
    expected_request_sha256: str,
    now_unix_seconds: int,
) -> None:
    try:
        public_key = serialization.load_der_public_key(authority_spki)
    except (TypeError, ValueError) as exc:
        raise ValueError("launch authority SPKI is invalid") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("launch authority SPKI is not Ed25519")
    statement = envelope["statement"]
    if (
        statement["authorityKeyId"] != expected_authority_key_id
        or statement["requestSha256"] != expected_request_sha256
    ):
        raise ValueError(
            "bootstrap receipt launch authorization identity binding is invalid"
        )
    if (
        statement["issuedAtUnixSeconds"]
        > now_unix_seconds + launch_authorization.MAX_FUTURE_SKEW_SECONDS
        or now_unix_seconds >= statement["expiresAtUnixSeconds"]
    ):
        raise ValueError(
            "bootstrap receipt launch authorization is outside its validity interval"
        )
    unsigned = {
        "apiVersion": envelope["apiVersion"],
        "kind": envelope["kind"],
        "statement": statement,
    }
    try:
        public_key.verify(
            _decode_canonical_ed25519_signature(envelope["signature"]),
            NONCE_ROLLBACK_ASSURANCE_AUTHORIZATION_DOMAIN
            + launch_authorization.canonical_json_bytes(unsigned),
        )
    except InvalidSignature as exc:
        raise ValueError(
            "bootstrap receipt launch authorization signature is invalid"
        ) from exc


def _validate_receipt_launch_authorization(
    value: Any,
    *,
    verify_signature: bool,
    authority_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    authorization = _closed_object(
        value,
        {
            "request",
            "requestSha256",
            "envelope",
            "authorizationSha256",
            "witnessPublicKeySpkiDerBase64url",
            "verifiedAtUnixSeconds",
        },
        "launchAuthorization",
    )
    try:
        request = _validate_v2_launch_authorization_request(
            authorization["request"]
        )
        request_sha256 = _v2_launch_authorization_request_sha256(request)
        envelope = _validate_v2_launch_authorization(
            authorization["envelope"]
        )
    except (ValueError, launch_authorization.LaunchAuthorizationError) as exc:
        raise ValueError(f"bootstrap receipt launch authorization is invalid: {exc}") from exc
    if not hmac.compare_digest(str(authorization["requestSha256"]), request_sha256):
        raise ValueError("bootstrap receipt launch authorization request digest mismatch")
    envelope_bytes = launch_authorization.canonical_json_bytes(envelope)
    authorization_sha256 = sha256_prefixed_bytes(envelope_bytes)
    if not hmac.compare_digest(
        str(authorization["authorizationSha256"]), authorization_sha256
    ):
        raise ValueError("bootstrap receipt launch authorization envelope digest mismatch")
    witness_public_key_spki = _decode_canonical_ed25519_spki(
        authorization["witnessPublicKeySpkiDerBase64url"],
        "bootstrap receipt launch-authority witness key",
    )
    witness_key_id = launch_authorization.spki_key_id(witness_public_key_spki)
    if not hmac.compare_digest(
        witness_key_id,
        request["launchAuthorityWitnessKeyId"],
    ):
        raise ValueError(
            "bootstrap receipt launch-authority witness key does not match the signed request"
        )
    verified_at = authorization["verifiedAtUnixSeconds"]
    if (
        type(verified_at) is not int
        or verified_at < 1
        or verified_at > launch_authorization.MAX_SAFE_INTEGER
    ):
        raise ValueError("bootstrap receipt launch authorization verification time is invalid")
    statement = envelope["statement"]
    if not hmac.compare_digest(statement["requestSha256"], request_sha256):
        raise ValueError(
            "bootstrap receipt launch authorization statement request digest mismatch"
        )
    if not (
        statement["issuedAtUnixSeconds"]
        <= verified_at + launch_authorization.MAX_FUTURE_SKEW_SECONDS
        and verified_at < statement["expiresAtUnixSeconds"]
    ):
        raise ValueError(
            "bootstrap receipt launch authorization verification time is outside its validity interval"
        )
    if verify_signature:
        trusted_authority = (
            load_launch_authority_identity()
            if authority_identity is None
            else authority_identity
        )
        authority_spki = trusted_authority.get("spki")
        expected_key_id = trusted_authority.get("keyId")
        if (
            type(authority_spki) is not bytes
            or SHA256_RE.fullmatch(str(expected_key_id)) is None
        ):
            raise ValueError("launch authority trust identity is invalid")
        try:
            launch_authorization.verify_launch_authorization_with_witness(
                envelope_bytes,
                authority_public_key_spki_der=authority_spki,
                expected_request=request,
                expected_authority_key_id=expected_key_id,
                witness_public_key_spki_der=witness_public_key_spki,
                expected_witness_key_id=witness_key_id,
                now_unix_seconds=verified_at,
            )
        except (ValueError, launch_authorization.LaunchAuthorizationError) as exc:
            raise ValueError(
                f"bootstrap receipt launch authorization verification failed: {exc}"
            ) from exc
    return {
        "request": request,
        "requestSha256": request_sha256,
        "envelope": envelope,
        "authorizationSha256": authorization_sha256,
        "witnessPublicKeySpkiDerBase64url": authorization[
            "witnessPublicKeySpkiDerBase64url"
        ],
        "verifiedAtUnixSeconds": verified_at,
    }


def _validate_bootstrap_receipt_authorization_bindings(
    receipt: dict[str, Any],
    authorization: dict[str, Any],
    *,
    require_inputs: bool,
) -> None:
    request = authorization["request"]
    bindings = (
        ("launchId", "launcherNonce", receipt.get("launchId")),
        ("bootIdSha256", "bootIdSha256", receipt.get("bootIdSha256")),
        (
            "launcher.sha256",
            "launcherSha256",
            (receipt.get("launcher") or {}).get("sha256")
            if isinstance(receipt.get("launcher"), dict)
            else None,
        ),
        (
            "manifest.sha256",
            "manifestSha256",
            (receipt.get("manifest") or {}).get("sha256")
            if isinstance(receipt.get("manifest"), dict)
            else None,
        ),
        (
            "nonceRollbackAssurance.contractSha256",
            "nonceRollbackAssuranceContractSha256",
            (receipt.get("nonceRollbackAssurance") or {}).get(
                "contractSha256"
            )
            if isinstance(receipt.get("nonceRollbackAssurance"), dict)
            else None,
        ),
        (
            "nonceRollbackAssurance.retainedSnapshotSha256",
            "nonceRollbackAssurancePinsSha256",
            (receipt.get("nonceRollbackAssurance") or {}).get(
                "retainedSnapshotSha256"
            )
            if isinstance(receipt.get("nonceRollbackAssurance"), dict)
            else None,
        ),
        ("sourceTreeDigest", "sourceTreeDigest", receipt.get("sourceTreeDigest")),
    )
    for receipt_label, request_field, receipt_value in bindings:
        request_value = request[request_field]
        if type(receipt_value) is not str or not hmac.compare_digest(
            receipt_value, request_value
        ):
            raise ValueError(
                f"bootstrap receipt {receipt_label} does not match launch authorization {request_field}"
            )
    if not require_inputs:
        return
    inputs = receipt.get("inputs")
    if not isinstance(inputs, dict):
        raise ValueError("bootstrap receipt launch authorization has no measured input bindings")
    for input_name, request_field in (
        ("releaseProvenance", "releaseProvenanceSha256"),
        (
            "reproducibleBuildVerification",
            "reproducibleBuildVerificationSha256",
        ),
    ):
        record = inputs.get(input_name)
        receipt_value = record.get("sha256") if isinstance(record, dict) else None
        if type(receipt_value) is not str or not hmac.compare_digest(
            receipt_value, request[request_field]
        ):
            raise ValueError(
                f"bootstrap receipt inputs.{input_name}.sha256 does not match launch authorization {request_field}"
            )


def validate_bootstrap_receipt_launch_authorization(
    receipt: dict[str, Any],
    *,
    verify_signature: bool,
    require_inputs: bool,
    authority_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    authorization = _validate_receipt_launch_authorization(
        receipt.get("launchAuthorization"),
        verify_signature=verify_signature,
        authority_identity=authority_identity,
    )
    _validate_bootstrap_receipt_authorization_bindings(
        receipt,
        authorization,
        require_inputs=require_inputs,
    )
    return authorization


def bootstrap_launch_authorization_identity(value: dict[str, Any]) -> dict[str, Any]:
    authorization = validate_bootstrap_receipt_launch_authorization(
        value,
        verify_signature=False,
        require_inputs=False,
    )
    request = authorization["request"]
    statement = authorization["envelope"]["statement"]
    witness = statement["monotonicWitness"]
    witness_statement = witness["statement"]
    return {
        "authorization_id": statement["authorizationId"],
        "authorization_sha256": authorization["authorizationSha256"],
        "request_sha256": authorization["requestSha256"],
        "authority_key_id": statement["authorityKeyId"],
        "authority_root_sha256": value["launchAuthorityRootSha256"],
        "authorization_scope": statement["authorizationScope"],
        "freshness_authority": statement["freshnessAuthority"],
        "capability_semantics": statement["capabilitySemantics"],
        "monotonic_witness_sha256": sha256_prefixed_bytes(
            launch_authorization.canonical_json_bytes(witness)
        ),
        "monotonic_witness_key_id": witness_statement["witnessKeyId"],
        "monotonic_witness_identity_sha256": witness_statement[
            "witnessIdentitySha256"
        ],
        "monotonic_witness_administrative_domain_sha256": witness_statement[
            "witnessAdministrativeDomainSha256"
        ],
        "monotonic_witness_store_assurance_sha256": witness_statement[
            "storeAssuranceSha256"
        ],
        "monotonic_witness_checkpoint_sequence": witness_statement[
            "checkpointSequence"
        ],
        "monotonic_witness_predecessor_state_sha256": witness_statement[
            "predecessorStateSha256"
        ],
        "monotonic_witness_successor_state_sha256": witness_statement[
            "successorStateSha256"
        ],
        "launch_id": request["launcherNonce"],
        "boot_id_sha256": request["bootIdSha256"],
        "manifest_sha256": request["manifestSha256"],
        "deployment_audience": request["deploymentAudience"],
        "deployment_identity_sha256": request["deploymentIdentitySha256"],
        "nonce_rollback_assurance_contract_sha256": request[
            "nonceRollbackAssuranceContractSha256"
        ],
        "nonce_rollback_assurance_pins_sha256": request[
            "nonceRollbackAssurancePinsSha256"
        ],
        "release_sequence": request["releaseSequence"],
        "rollback_epoch": request["rollbackEpoch"],
        "release_provenance_sha256": request["releaseProvenanceSha256"],
        "provenance_digest": request["provenanceDigest"],
        "source_tree_digest": request["sourceTreeDigest"],
        "launcher_sha256": request["launcherSha256"],
        "reproducible_build_verification_sha256": request[
            "reproducibleBuildVerificationSha256"
        ],
        "issued_at_unix_seconds": statement["issuedAtUnixSeconds"],
        "expires_at_unix_seconds": statement["expiresAtUnixSeconds"],
        "verified_at_unix_seconds": authorization["verifiedAtUnixSeconds"],
    }


def bootstrap_receipt_environment(
    environment: dict[str, str] | None = None,
) -> dict[str, str]:
    source = dict(os.environ) if environment is None else environment
    present = BOOTSTRAP_RECEIPT_ENV_NAMES & set(source)
    if not present:
        return {}
    if present != BOOTSTRAP_RECEIPT_ENV_NAMES:
        missing = sorted(BOOTSTRAP_RECEIPT_ENV_NAMES - present)
        raise ValueError(
            "bootstrap receipt environment is incomplete; missing " + ", ".join(missing)
        )
    return {name: source[name] for name in sorted(BOOTSTRAP_RECEIPT_ENV_NAMES)}


def _closed_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"bootstrap receipt {label} does not match its closed schema")
    return value


def _normalized_absolute_receipt_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"bootstrap receipt {label} path is invalid")
    path = Path(value)
    if (
        not path.is_absolute()
        or value == "/"
        or os.path.normpath(value) != value
        or str(path) != value
    ):
        raise ValueError(f"bootstrap receipt {label} path must be normalized and absolute")
    return value


def _validate_receipt_python_layout(
    python_path: str, import_paths: list[str]
) -> None:
    if len(import_paths) != 4:
        raise ValueError(
            "bootstrap receipt python.importRoots must contain exactly four ordered roots"
        )
    release_root = Path(import_paths[0])
    expected_python = release_root / "runtime" / "python" / "bin" / "python3"
    if Path(python_path) != expected_python:
        raise ValueError(
            "bootstrap receipt python path must be releaseRoot/runtime/python/bin/python3"
        )
    stdlib = Path(import_paths[1])
    expected_stdlib_parent = release_root / "runtime" / "python" / "lib"
    if (
        stdlib.parent != expected_stdlib_parent
        or re.fullmatch(r"python3\.(?:0|[1-9][0-9]*)", stdlib.name) is None
    ):
        raise ValueError(
            "bootstrap receipt python.importRoots[1] must be the release CPython stdlib"
        )
    expected_paths = [
        release_root,
        stdlib,
        stdlib / "lib-dynload",
        release_root / "vendor",
    ]
    if [Path(value) for value in import_paths] != expected_paths:
        raise ValueError(
            "bootstrap receipt python.importRoots must be ordered as releaseRoot, stdlib, lib-dynload, vendor"
        )


def _validate_receipt_metadata(
    value: Any,
    label: str,
    *,
    require_single_link: bool = True,
) -> dict[str, Any]:
    metadata = _closed_object(
        value,
        {
            "device",
            "inode",
            "mode",
            "ownerUid",
            "ownerGid",
            "linkCount",
            "size",
            "modifiedUnixNanos",
            "changedUnixNanos",
        },
        f"{label}.metadata",
    )
    for field in ("device", "inode", "mode", "ownerUid", "ownerGid", "linkCount", "size"):
        number = metadata[field]
        if type(number) is not int or number < 0:
            raise ValueError(f"bootstrap receipt {label}.metadata.{field} is invalid")
    for field in ("modifiedUnixNanos", "changedUnixNanos"):
        if type(metadata[field]) is not int:
            raise ValueError(f"bootstrap receipt {label}.metadata.{field} is invalid")
    if metadata["mode"] > 0xFFFFFFFF or metadata["ownerUid"] > 0xFFFFFFFF or metadata["ownerGid"] > 0xFFFFFFFF:
        raise ValueError(f"bootstrap receipt {label} metadata exceeds the platform bounds")
    if require_single_link and metadata["linkCount"] != 1:
        raise ValueError(f"bootstrap receipt {label} must bind a single-link filesystem object")
    return metadata


def _validate_receipt_file(value: Any, label: str) -> dict[str, Any]:
    record = _closed_object(value, {"path", "sha256", "metadata"}, label)
    _normalized_absolute_receipt_path(record["path"], label)
    if SHA256_RE.fullmatch(str(record["sha256"])) is None:
        raise ValueError(f"bootstrap receipt {label}.sha256 is invalid")
    _validate_receipt_metadata(record["metadata"], label)
    return record


def _validate_receipt_nonce_rollback_assurance(value: Any) -> dict[str, Any]:
    binding = _closed_object(
        value,
        {
            "apiVersion",
            "contractSha256",
            "pinsFile",
            "retainedSnapshotFd",
            "retainedSnapshotSha256",
            "verifierStateService",
        },
        "nonceRollbackAssurance",
    )
    if (
        binding["apiVersion"]
        != NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
    ):
        raise ValueError(
            "bootstrap receipt nonce rollback assurance version is invalid"
        )
    for field in ("contractSha256", "retainedSnapshotSha256"):
        if SHA256_RE.fullmatch(str(binding[field])) is None:
            raise ValueError(
                f"bootstrap receipt nonceRollbackAssurance.{field} is invalid"
            )
    pins_file = _validate_receipt_file(
        binding["pinsFile"],
        "nonceRollbackAssurance.pinsFile",
    )
    if not hmac.compare_digest(
        pins_file["sha256"],
        binding["retainedSnapshotSha256"],
    ):
        raise ValueError(
            "bootstrap receipt retained nonce rollback snapshot digest differs from its source file"
        )
    descriptor = binding["retainedSnapshotFd"]
    if (
        type(descriptor) is not int
        or descriptor <= 2
        or descriptor > (1 << 31) - 1
        or descriptor == BOOTSTRAP_RECEIPT_FIXED_FD
    ):
        raise ValueError(
            "bootstrap receipt retained nonce rollback snapshot descriptor is "
            "invalid or collides with the fixed bootstrap receipt descriptor"
        )
    verifier_state_service = _closed_object(
        binding["verifierStateService"],
        {
            "signingPublicKeySpkiDerBase64url",
            "storeAdministrativeDomainSha256",
            "storeAssuranceEvidenceSha256",
            "storeAttestationPublicKeySpkiDerBase64url",
            "storeIdentitySha256",
        },
        "nonceRollbackAssurance.verifierStateService",
    )
    for field in (
        "storeAdministrativeDomainSha256",
        "storeAssuranceEvidenceSha256",
        "storeIdentitySha256",
    ):
        if SHA256_RE.fullmatch(str(verifier_state_service[field])) is None:
            raise ValueError(
                "bootstrap receipt nonce rollback verifier-state service "
                f"{field} is invalid"
            )
    _decode_canonical_ed25519_spki(
        verifier_state_service["signingPublicKeySpkiDerBase64url"],
        "bootstrap receipt nonce rollback verifier-state signing key",
    )
    _decode_canonical_ed25519_spki(
        verifier_state_service[
            "storeAttestationPublicKeySpkiDerBase64url"
        ],
        "bootstrap receipt nonce rollback verifier-state store attestation key",
    )
    return binding


def _reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
    label: str,
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError(f"{label} contains duplicate field {key!r}")
        value[key] = child
    return value


def _reject_noninteger_json(value: str, label: str) -> None:
    raise ValueError(f"{label} contains non-integer JSON number {value!r}")


def _decode_canonical_ed25519_spki(value: Any, label: str) -> bytes:
    if type(value) is not str or not value or "=" in value:
        raise ValueError(f"{label} must be unpadded canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{label} is not valid base64url") from exc
    if (
        base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value
        or len(decoded) != len(ED25519_SPKI_PREFIX) + 32
        or not decoded.startswith(ED25519_SPKI_PREFIX)
    ):
        raise ValueError(f"{label} is not canonical Ed25519 SPKI DER")
    return decoded


def validate_nonce_rollback_assurance_contract(
    value: Any,
) -> dict[str, Any]:
    contract = _closed_object(
        value,
        {"apiVersion", "independentVerifierPins", "publicConfigPins"},
        "nonce rollback assurance pins",
    )
    if contract["apiVersion"] != NONCE_ROLLBACK_ASSURANCE_PINS_API_VERSION:
        raise ValueError("nonce rollback assurance pins version is invalid")
    independent = _closed_object(
        contract["independentVerifierPins"],
        {
            "expectedNonceAuthorityAssuranceIssuerSpkiSha256",
            "expectedNonceAuthorityAssuranceSha256",
        },
        "independent nonce rollback verifier pins",
    )
    public = _closed_object(
        contract["publicConfigPins"],
        {
            "nonceAuthorityAssurance",
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityAssuranceSha256",
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256",
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256",
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreIdentitySha256",
        },
        "public nonce rollback config pins",
    )
    assurance = _closed_object(
        public["nonceAuthorityAssurance"],
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
    rollback = _closed_object(
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
    digest_values = (
        independent["expectedNonceAuthorityAssuranceIssuerSpkiSha256"],
        independent["expectedNonceAuthorityAssuranceSha256"],
        public["nonceAuthorityAssuranceSha256"],
        public[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ],
        public[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ],
        public["nonceAuthorityVerifierStateStoreIdentitySha256"],
        assurance["administrativeDomainSha256"],
        assurance["assuranceEvidenceSha256"],
        assurance["authorityIdentitySha256"],
    )
    if any(type(item) is not str or SHA256_RE.fullmatch(item) is None for item in digest_values):
        raise ValueError("nonce rollback assurance pins contain an invalid digest")
    evidence_spki = _decode_canonical_ed25519_spki(
        public[
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
        ],
        "nonce authority assurance evidence key",
    )
    verifier_state_spki = _decode_canonical_ed25519_spki(
        public[
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
        ],
        "nonce authority verifier-state key",
    )
    verifier_state_store_attestation_spki = _decode_canonical_ed25519_spki(
        public[
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
        ],
        "nonce authority verifier-state store attestation key",
    )
    evidence_key_id = sha256_prefixed_bytes(evidence_spki)
    verifier_state_key_id = sha256_prefixed_bytes(verifier_state_spki)
    verifier_state_store_attestation_key_id = sha256_prefixed_bytes(
        verifier_state_store_attestation_spki
    )
    assurance_sha256 = sha256_prefixed_bytes(
        canonical_json(assurance).encode("ascii")
    )
    profile = {
        "assuranceEvidenceType": assurance["assuranceEvidenceType"],
        "backendClass": assurance["backendClass"],
        "keyProtection": rollback["keyProtection"],
        "rollbackMechanism": rollback["mechanism"],
        "stateCommitment": rollback["stateCommitment"],
        "verifierStateStoreClass": rollback["verifierStateStoreClass"],
    }
    administrative_and_service_identities = {
        assurance["administrativeDomainSha256"],
        assurance["authorityIdentitySha256"],
        public[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ],
        public["nonceAuthorityVerifierStateStoreIdentitySha256"],
    }
    if (
        assurance["apiVersion"] != "serverware.nonceAuthorityAssurance/v1"
        or assurance["productionEligible"] is not True
        or assurance["assuranceLevel"] != "productionRollbackProtected"
        or type(assurance["authorityEpoch"]) is not int
        or not 1
        <= assurance["authorityEpoch"]
        <= NONCE_ROLLBACK_ASSURANCE_JSON_INTEGER_MAX
        or type(assurance["authorityGeneration"]) is not int
        or not 1
        <= assurance["authorityGeneration"]
        <= NONCE_ROLLBACK_ASSURANCE_JSON_INTEGER_MAX
        or rollback["administrativeRollbackResistance"] is not True
        or rollback["backendAttestationRequired"] is not True
        or rollback["exactSuccessorRequired"] is not True
        or rollback["freshVerifierChallengeRequired"] is not True
        or profile not in PRODUCTION_NONCE_ASSURANCE_PROFILES
        or public["nonceAuthorityAssuranceSha256"] != assurance_sha256
        or independent["expectedNonceAuthorityAssuranceSha256"]
        != assurance_sha256
        or independent[
            "expectedNonceAuthorityAssuranceIssuerSpkiSha256"
        ]
        != evidence_key_id
        or len(
            {
                evidence_key_id,
                verifier_state_key_id,
                verifier_state_store_attestation_key_id,
            }
        )
        != 3
        or len(administrative_and_service_identities) != 4
        or evidence_key_id in administrative_and_service_identities
        or verifier_state_key_id in administrative_and_service_identities
        or verifier_state_store_attestation_key_id
        in administrative_and_service_identities
        or public[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ]
        == assurance["assuranceEvidenceSha256"]
    ):
        raise ValueError(
            "nonce rollback assurance pins do not form the closed production rollback profile"
        )
    return contract


def validate_retained_nonce_rollback_assurance(
    *,
    retained_path: Any,
    expected_pins_sha256: Any,
    expected_contract_sha256: Any,
    bootstrap_receipt: dict[str, Any] | None,
    required: bool,
) -> dict[str, Any]:
    supplied = (
        retained_path,
        expected_pins_sha256,
        expected_contract_sha256,
    )
    if bootstrap_receipt is None:
        if any(value is not None for value in supplied):
            raise ValueError(
                "launcher nonce rollback assurance arguments require a sealed v3 bootstrap receipt"
            )
        if required:
            raise ValueError(
                "launcher-enforced nonce rollback assurance requires a sealed v3 bootstrap receipt"
            )
        return {
            "apiVersion": NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION,
            "enforcement": "not-native-launcher-enforced",
            "verified": False,
        }
    if any(type(value) is not str or not value for value in supplied):
        raise ValueError(
            "launcher nonce rollback assurance arguments must be supplied together"
        )
    binding = _validate_receipt_nonce_rollback_assurance(
        bootstrap_receipt.get("nonceRollbackAssurance")
    )
    path_match = re.fullmatch(r"/proc/self/fd/([1-9][0-9]*)", retained_path)
    if path_match is None:
        raise ValueError(
            "launcher nonce rollback assurance pins must use the retained /proc/self/fd descriptor"
        )
    descriptor = int(path_match.group(1))
    if descriptor != binding["retainedSnapshotFd"]:
        raise ValueError(
            "launcher nonce rollback assurance descriptor differs from the bootstrap receipt"
        )
    for actual, receipt_value, label in (
        (
            expected_pins_sha256,
            binding["retainedSnapshotSha256"],
            "pins digest",
        ),
        (
            expected_contract_sha256,
            binding["contractSha256"],
            "contract digest",
        ),
    ):
        if (
            SHA256_RE.fullmatch(actual) is None
            or not hmac.compare_digest(actual, receipt_value)
        ):
            raise ValueError(
                f"launcher nonce rollback assurance {label} differs from the bootstrap receipt"
            )
    request = bootstrap_receipt["launchAuthorization"]["request"]
    if (
        request["nonceRollbackAssurancePinsSha256"]
        != expected_pins_sha256
        or request["nonceRollbackAssuranceContractSha256"]
        != expected_contract_sha256
    ):
        raise ValueError(
            "launcher nonce rollback assurance digests differ from the signed launch request"
        )
    try:
        before = os.fstat(descriptor)
    except OSError as exc:
        raise ValueError(
            "launcher nonce rollback assurance descriptor is not open"
        ) from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or not 1 <= before.st_size <= MAX_NONCE_ROLLBACK_ASSURANCE_PINS_BYTES
    ):
        raise ValueError(
            "launcher nonce rollback assurance descriptor is not a bounded regular file"
        )
    try:
        seals = fcntl.fcntl(descriptor, LINUX_F_GET_SEALS)
    except OSError as exc:
        raise ValueError(
            "launcher nonce rollback assurance descriptor is not a sealable memfd"
        ) from exc
    if seals & REQUIRED_BOOTSTRAP_RECEIPT_SEALS != REQUIRED_BOOTSTRAP_RECEIPT_SEALS:
        raise ValueError(
            "launcher nonce rollback assurance descriptor is missing immutable seals"
        )
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(
            descriptor,
            min(64 * 1024, before.st_size - offset),
            offset,
        )
        if not chunk:
            raise ValueError(
                "launcher nonce rollback assurance descriptor ended early"
            )
        chunks.append(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(
        getattr(before, field) != getattr(after, field)
        for field in stable_fields
    ):
        raise ValueError(
            "launcher nonce rollback assurance descriptor changed while it was read"
        )
    raw = b"".join(chunks)
    if not hmac.compare_digest(
        sha256_prefixed_bytes(raw),
        expected_pins_sha256,
    ):
        raise ValueError(
            "launcher nonce rollback assurance snapshot digest mismatch"
        )
    try:
        contract = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=lambda pairs: _reject_duplicate_pairs(
                pairs,
                "nonce rollback assurance pins",
            ),
            parse_float=lambda value: _reject_noninteger_json(
                value,
                "nonce rollback assurance pins",
            ),
            parse_constant=lambda value: _reject_noninteger_json(
                value,
                "nonce rollback assurance pins",
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "launcher nonce rollback assurance snapshot is not strict UTF-8 JSON"
        ) from exc
    contract = validate_nonce_rollback_assurance_contract(contract)
    public_config = contract["publicConfigPins"]
    expected_verifier_state_service = {
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
    if binding["verifierStateService"] != expected_verifier_state_service:
        raise ValueError(
            "launcher nonce rollback verifier-state service configuration "
            "differs from the retained contract"
        )
    canonical = canonical_json(contract).encode("ascii")
    if raw != canonical + b"\n":
        raise ValueError(
            "launcher nonce rollback assurance snapshot is not canonical JSON plus LF"
        )
    if not hmac.compare_digest(
        sha256_prefixed_bytes(canonical),
        expected_contract_sha256,
    ):
        raise ValueError(
            "launcher nonce rollback assurance canonical contract digest mismatch"
        )
    return {
        "apiVersion": NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION,
        "contractSha256": expected_contract_sha256,
        "enforcement": "native-launcher-measured-retained-snapshot",
        "pinsFile": binding["pinsFile"],
        "retainedSnapshotFd": descriptor,
        "retainedSnapshotSha256": expected_pins_sha256,
        "verifierStateService": expected_verifier_state_service,
        "sealed": True,
        "sealMask": seals,
        "verified": True,
    }


def validate_bootstrap_receipt_summary(value: Any) -> dict[str, Any]:
    summary = _closed_object(
        value,
        {
            "apiVersion",
            "kind",
            "launchId",
            "sha256",
            "bootIdSha256",
            "sourceTreeDigest",
            "launchAuthorization",
            "launchAuthorityKeyId",
            "launchAuthorityRootSha256",
            "launcher",
            "manifest",
            "nonceRollbackAssurance",
            "argv",
            "environment",
            "sealed",
            "sealMask",
        },
        "summary",
    )
    if summary["apiVersion"] != BOOTSTRAP_RECEIPT_API_VERSION or summary["kind"] != BOOTSTRAP_RECEIPT_KIND:
        raise ValueError("bootstrap receipt summary identity is invalid")
    if re.fullmatch(r"[0-9a-f]{64}", str(summary["launchId"])) is None:
        raise ValueError("bootstrap receipt summary launchId is invalid")
    for field in ("sha256", "bootIdSha256", "sourceTreeDigest"):
        if SHA256_RE.fullmatch(str(summary[field])) is None:
            raise ValueError(f"bootstrap receipt summary {field} is invalid")
    launcher = _validate_receipt_file(summary["launcher"], "launcher")
    launcher_hex = str(launcher["sha256"])[len("sha256:") :]
    expected_launcher_path = (
        f"/opt/serverware/launchers/sha256-{launcher_hex}/serverware-production-launcher"
    )
    if launcher["path"] != expected_launcher_path:
        raise ValueError("bootstrap receipt launcher path is not content-addressed by its digest")
    _validate_receipt_file(summary["manifest"], "manifest")
    _validate_receipt_nonce_rollback_assurance(
        summary["nonceRollbackAssurance"]
    )
    validate_bootstrap_receipt_launch_authorization(
        summary,
        verify_signature=False,
        require_inputs=False,
    )
    launch_statement = summary["launchAuthorization"]["envelope"]["statement"]
    if (
        SHA256_RE.fullmatch(str(summary["launchAuthorityKeyId"])) is None
        or summary["launchAuthorityKeyId"] != launch_statement["authorityKeyId"]
    ):
        raise ValueError("bootstrap receipt summary launch authority key binding is invalid")
    if SHA256_RE.fullmatch(str(summary["launchAuthorityRootSha256"])) is None:
        raise ValueError("bootstrap receipt summary launch authority root digest is invalid")
    argv = _closed_object(summary["argv"], {"preflightSha256", "readinessSha256"}, "argv")
    for field in ("preflightSha256", "readinessSha256"):
        if SHA256_RE.fullmatch(str(argv[field])) is None:
            raise ValueError(f"bootstrap receipt argv.{field} is invalid")
    environment = _closed_object(summary["environment"], {"names", "sha256"}, "environment")
    if environment["names"] != BOOTSTRAP_RECEIPT_COMMITTED_ENV_NAMES:
        raise ValueError("bootstrap receipt environment names do not match the closed launcher environment")
    if SHA256_RE.fullmatch(str(environment["sha256"])) is None:
        raise ValueError("bootstrap receipt environment digest is invalid")
    if summary["sealed"] is not True or type(summary["sealMask"]) is not int:
        raise ValueError("bootstrap receipt summary does not claim an immutable sealed descriptor")
    if summary["sealMask"] & REQUIRED_BOOTSTRAP_RECEIPT_SEALS != REQUIRED_BOOTSTRAP_RECEIPT_SEALS:
        raise ValueError("bootstrap receipt summary seal mask is incomplete")
    return summary


def load_sealed_bootstrap_receipt(
    environment: dict[str, str] | None = None,
    *,
    required: bool,
) -> tuple[dict[str, Any] | None, int | None]:
    receipt_env = bootstrap_receipt_environment(environment)
    if not receipt_env:
        if required:
            raise ValueError("final execution requires a sealed native-launcher bootstrap receipt")
        return None, None
    if not sys.platform.startswith("linux"):
        raise ValueError("sealed bootstrap receipts require Linux")

    raw_descriptor = receipt_env[BOOTSTRAP_RECEIPT_FD_ENV]
    if re.fullmatch(r"[1-9][0-9]*", raw_descriptor) is None:
        raise ValueError("bootstrap receipt descriptor must be a positive decimal integer")
    descriptor = int(raw_descriptor)
    if descriptor != BOOTSTRAP_RECEIPT_FIXED_FD:
        raise ValueError(
            f"bootstrap receipt descriptor must be exactly {BOOTSTRAP_RECEIPT_FIXED_FD}"
        )
    expected_sha256 = receipt_env[BOOTSTRAP_RECEIPT_SHA256_ENV]
    if SHA256_RE.fullmatch(expected_sha256) is None:
        raise ValueError("bootstrap receipt digest must be sha256:<64 lowercase hex>")
    if receipt_env[BOOTSTRAP_RECEIPT_API_VERSION_ENV] != BOOTSTRAP_RECEIPT_API_VERSION:
        raise ValueError("bootstrap receipt environment has the wrong API version")

    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise ValueError("bootstrap receipt descriptor is not open") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("bootstrap receipt descriptor must refer to a regular memfd")
    if metadata.st_size <= 0 or metadata.st_size > MAX_BOOTSTRAP_RECEIPT_BYTES:
        raise ValueError("bootstrap receipt size is outside the accepted bound")
    try:
        seals = fcntl.fcntl(descriptor, LINUX_F_GET_SEALS)
    except OSError as exc:
        raise ValueError("bootstrap receipt descriptor is not a sealable memfd") from exc
    if seals & REQUIRED_BOOTSTRAP_RECEIPT_SEALS != REQUIRED_BOOTSTRAP_RECEIPT_SEALS:
        raise ValueError("bootstrap receipt memfd is missing mandatory immutable seals")

    chunks: list[bytes] = []
    offset = 0
    while offset < metadata.st_size:
        chunk = os.pread(descriptor, min(64 * 1024, metadata.st_size - offset), offset)
        if not chunk:
            raise ValueError("bootstrap receipt ended before its declared size")
        chunks.append(chunk)
        offset += len(chunk)
    data = b"".join(chunks)
    actual_sha256 = sha256_prefixed_bytes(data)
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise ValueError("bootstrap receipt bytes do not match the launcher digest")
    try:
        receipt = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("bootstrap receipt is not valid UTF-8 JSON") from exc
    required_keys = {
        "apiVersion",
        "kind",
        "launchId",
        "bootIdSha256",
        "launcher",
        "manifest",
        "sourceTreeDigest",
        "launchAuthorization",
        "nonceRollbackAssurance",
        "productionEnv",
        "python",
        "scripts",
        "composeFile",
        "inputs",
        "argv",
        "environment",
    }
    if not isinstance(receipt, dict) or set(receipt) != required_keys:
        raise ValueError("bootstrap receipt must use the closed v3 top-level schema")
    if receipt.get("apiVersion") != BOOTSTRAP_RECEIPT_API_VERSION:
        raise ValueError("bootstrap receipt has the wrong API version")
    if receipt.get("kind") != BOOTSTRAP_RECEIPT_KIND:
        raise ValueError("bootstrap receipt has the wrong kind")
    if re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("launchId", ""))) is None:
        raise ValueError("bootstrap receipt launchId must be 32 random bytes in lowercase hex")
    for field in ("bootIdSha256", "sourceTreeDigest"):
        if SHA256_RE.fullmatch(str(receipt.get(field, ""))) is None:
            raise ValueError(f"bootstrap receipt {field} must be a SHA-256 digest")
    launcher = _validate_receipt_file(receipt["launcher"], "launcher")
    launcher_hex = str(launcher["sha256"])[len("sha256:") :]
    if launcher["path"] != (
        f"/opt/serverware/launchers/sha256-{launcher_hex}/serverware-production-launcher"
    ):
        raise ValueError("bootstrap receipt launcher path is not content-addressed by its digest")
    for field in ("manifest", "productionEnv", "composeFile"):
        _validate_receipt_file(receipt[field], field)
    _validate_receipt_nonce_rollback_assurance(
        receipt["nonceRollbackAssurance"]
    )
    python_record = _closed_object(
        receipt["python"],
        {"path", "sha256", "metadata", "importRoots"},
        "python",
    )
    python_path = _normalized_absolute_receipt_path(python_record["path"], "python")
    if SHA256_RE.fullmatch(str(python_record["sha256"])) is None:
        raise ValueError("bootstrap receipt python.sha256 is invalid")
    _validate_receipt_metadata(python_record["metadata"], "python")
    import_roots = python_record["importRoots"]
    if not isinstance(import_roots, list) or len(import_roots) != 4:
        raise ValueError(
            "bootstrap receipt python.importRoots must contain exactly four ordered roots"
        )
    seen_import_roots: set[str] = set()
    import_paths: list[str] = []
    for index, value in enumerate(import_roots):
        label = f"python.importRoots[{index}]"
        root = _closed_object(value, {"path", "sha256", "metadata"}, label)
        path = _normalized_absolute_receipt_path(root["path"], label)
        if path in seen_import_roots:
            raise ValueError("bootstrap receipt python.importRoots contains a duplicate path")
        seen_import_roots.add(path)
        import_paths.append(path)
        if SHA256_RE.fullmatch(str(root["sha256"])) is None:
            raise ValueError(f"bootstrap receipt {label}.sha256 is invalid")
        _validate_receipt_metadata(root["metadata"], label, require_single_link=False)
    _validate_receipt_python_layout(python_path, import_paths)
    scripts = _closed_object(receipt["scripts"], {"preflight", "runner"}, "scripts")
    _validate_receipt_file(scripts["preflight"], "scripts.preflight")
    _validate_receipt_file(scripts["runner"], "scripts.runner")
    inputs = receipt["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != BOOTSTRAP_RECEIPT_INPUT_NAMES:
        raise ValueError("bootstrap receipt inputs do not match the closed production input set")
    for name, value in inputs.items():
        _validate_receipt_file(value, f"inputs.{name}")
    launch_authority_identity = load_launch_authority_identity()
    launch_authorization_receipt = validate_bootstrap_receipt_launch_authorization(
        receipt,
        verify_signature=True,
        require_inputs=True,
        authority_identity=launch_authority_identity,
    )
    current_unix_seconds = int(time.time())
    try:
        launch_authorization.verify_launch_authorization_with_witness(
            launch_authorization.canonical_json_bytes(
                launch_authorization_receipt["envelope"]
            ),
            authority_public_key_spki_der=launch_authority_identity["spki"],
            expected_request=launch_authorization_receipt["request"],
            expected_authority_key_id=launch_authority_identity["keyId"],
            witness_public_key_spki_der=_decode_canonical_ed25519_spki(
                launch_authorization_receipt[
                    "witnessPublicKeySpkiDerBase64url"
                ],
                "bootstrap receipt launch-authority witness key",
            ),
            expected_witness_key_id=launch_authorization_receipt["request"][
                "launchAuthorityWitnessKeyId"
            ],
            now_unix_seconds=current_unix_seconds,
        )
    except launch_authorization.LaunchAuthorizationError as exc:
        raise ValueError(
            "bootstrap receipt launch authorization is not current at consumption"
        ) from exc
    argv = _closed_object(receipt["argv"], {"preflightSha256", "readinessSha256"}, "argv")
    for field in ("preflightSha256", "readinessSha256"):
        if SHA256_RE.fullmatch(str(argv[field])) is None:
            raise ValueError(f"bootstrap receipt argv.{field} is invalid")
    committed_environment = _closed_object(
        receipt["environment"], {"names", "sha256"}, "environment"
    )
    if committed_environment["names"] != BOOTSTRAP_RECEIPT_COMMITTED_ENV_NAMES:
        raise ValueError("bootstrap receipt environment names do not match the closed launcher environment")
    if SHA256_RE.fullmatch(str(committed_environment["sha256"])) is None:
        raise ValueError("bootstrap receipt environment.sha256 is invalid")
    if canonical_json(receipt).encode("ascii") != data:
        raise ValueError("bootstrap receipt is not canonical compact JSON")
    summary = {
        "apiVersion": receipt["apiVersion"],
        "kind": receipt["kind"],
        "launchId": receipt["launchId"],
        "sha256": actual_sha256,
        "bootIdSha256": receipt["bootIdSha256"],
        "sourceTreeDigest": receipt["sourceTreeDigest"],
        "launchAuthorization": launch_authorization_receipt,
        "launchAuthorityKeyId": launch_authority_identity["keyId"],
        "launchAuthorityRootSha256": launch_authority_identity["rootSha256"],
        "launcher": receipt["launcher"],
        "manifest": receipt["manifest"],
        "nonceRollbackAssurance": receipt["nonceRollbackAssurance"],
        "argv": receipt["argv"],
        "environment": receipt["environment"],
        "sealed": True,
        "sealMask": seals,
    }
    return validate_bootstrap_receipt_summary(summary), descriptor


def revalidate_bootstrap_launch_authorization_at_completion(
    *,
    expected_receipt: dict[str, Any],
    expected_descriptor: int,
    generated_at_unix: int,
    now_unix_seconds: int | None = None,
    receipt_loader: Any | None = None,
) -> dict[str, Any]:
    if expected_descriptor != BOOTSTRAP_RECEIPT_FIXED_FD:
        raise ValueError(
            f"completion must revalidate bootstrap authorization on exact FD "
            f"{BOOTSTRAP_RECEIPT_FIXED_FD}"
        )
    if type(generated_at_unix) is not int or generated_at_unix <= 0:
        raise ValueError("completion generation time is invalid")
    load_receipt = load_sealed_bootstrap_receipt if receipt_loader is None else receipt_loader
    current_receipt, current_descriptor = load_receipt(required=True)
    if (
        current_descriptor != BOOTSTRAP_RECEIPT_FIXED_FD
        or current_receipt != expected_receipt
    ):
        raise ValueError(
            "sealed FD 198 bootstrap receipt changed before completion publication"
        )
    validate_bootstrap_receipt_summary(current_receipt)
    identity = bootstrap_launch_authorization_identity(current_receipt)
    expires_at = identity["expires_at_unix_seconds"]
    current_time = (
        int(time.time())
        if now_unix_seconds is None
        else now_unix_seconds
    )
    if (
        type(current_time) is not int
        or current_time <= 0
        or generated_at_unix >= expires_at
        or current_time >= expires_at
    ):
        raise ValueError(
            "FD 198 launch authorization expired before completion generation "
            "or output publication"
        )
    return {
        "authorizationSha256": identity["authorization_sha256"],
        "descriptor": current_descriptor,
        "expiresAtUnixSeconds": expires_at,
        "generatedAtUnix": generated_at_unix,
        "publishedAtUnix": current_time,
        "freshAtCompletion": True,
    }


def normalize_command_value(value: Any, label: str) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a string list or null")
    return list(value)


def normalize_environment_hashes(value: Any, label: str) -> list[dict[str, str]]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError(f"{label} environment must be an object")
    normalized = []
    for name, raw in sorted(value.items()):
        if not isinstance(name, str) or not name or "=" in name:
            raise ValueError(f"{label} environment contains an invalid variable name")
        if raw is None:
            rendered = ""
        elif isinstance(raw, bool):
            rendered = "true" if raw else "false"
        else:
            rendered = str(raw)
        normalized.append(
            {
                "name": name,
                "value_sha256": sha256_prefixed_bytes(rendered.encode("utf-8")),
            }
        )
    return normalized


def normalize_string_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a string list")
    return sorted(value)


def normalize_compose_networks(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return sorted(value)
    if isinstance(value, dict) and all(isinstance(item, str) for item in value):
        return sorted(value)
    raise ValueError(f"{label} networks must be a string list or object")


def normalize_compose_devices(value: Any, label: str) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} devices must be a list")
    devices: list[dict[str, str]] = []
    for item in value:
        if isinstance(item, str):
            parts = item.split(":")
            source = parts[0]
            target = parts[1] if len(parts) > 1 and parts[1] else source
            permissions = parts[2] if len(parts) > 2 else "rwm"
        elif isinstance(item, dict):
            source = item.get("source") or item.get("path_on_host")
            target = item.get("target") or item.get("path_in_container") or source
            permissions = item.get("permissions") or item.get("cgroup_permissions") or "rwm"
        else:
            raise ValueError(f"{label} device entry is invalid")
        if not all(isinstance(field, str) and field for field in (source, target, permissions)):
            raise ValueError(f"{label} device entry is incomplete")
        devices.append(
            {"source": source, "target": target, "permissions": permissions}
        )
    return sorted(devices, key=lambda item: (item["target"], item["source"], item["permissions"]))


def normalize_compose_mounts(value: Any, label: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} volumes must be a list")
    mounts: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{label} volume entry must be an object")
        mount_type = item.get("type")
        source = item.get("source")
        target = item.get("target")
        if mount_type not in {"bind", "volume", "tmpfs"} or not isinstance(target, str):
            raise ValueError(f"{label} volume entry is invalid")
        if mount_type != "tmpfs" and not isinstance(source, str):
            raise ValueError(f"{label} volume source is invalid")
        normalized = {
            "type": mount_type,
            "source": source if isinstance(source, str) else "",
            "target": target,
            "read_only": bool(item.get("read_only", False)),
            "bind": json.loads(canonical_json(item.get("bind") or {})),
            "volume": json.loads(canonical_json(item.get("volume") or {})),
            "tmpfs": json.loads(canonical_json(item.get("tmpfs") or {})),
            "consistency": str(item.get("consistency") or ""),
        }
        mounts.append(normalized)
    return sorted(mounts, key=lambda item: (item["target"], item["type"], item["source"]))


def normalize_tmpfs(value: Any, label: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} tmpfs must be a list")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, str):
            target, separator, raw_options = item.partition(":")
            options = normalize_tmpfs_options(raw_options.split(",") if separator else [])
        elif isinstance(item, dict):
            target = item.get("target")
            options_value = item.get("options") or []
            options = normalize_tmpfs_options(options_value)
        else:
            raise ValueError(f"{label} tmpfs entry is invalid")
        if not isinstance(target, str) or not target.startswith("/"):
            raise ValueError(f"{label} tmpfs target is invalid")
        normalized.append({"target": target, "options": options})
    return sorted(normalized, key=lambda item: item["target"])


def normalize_tmpfs_options(value: Any) -> list[str]:
    normalized: list[str] = []
    for raw in value:
        option = str(raw)
        if not option:
            continue
        if option.startswith("size="):
            option = "size_bytes=" + str(
                parse_compose_byte_limit(option.split("=", 1)[1], "tmpfs size")
            )
        normalized.append(option)
    return sorted(normalized)


def parse_compose_byte_limit(value: Any, label: str) -> int:
    if value in (None, "", 0, "0"):
        return 0
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an integer byte count or size string")
    match = re.fullmatch(r"([0-9]+)([kmgt]i?b?|b)?", value.strip().lower())
    if match is None:
        raise ValueError(f"{label} has an invalid size")
    powers = {None: 0, "b": 0, "k": 1, "kb": 1, "ki": 1, "kib": 1,
              "m": 2, "mb": 2, "mi": 2, "mib": 2,
              "g": 3, "gb": 3, "gi": 3, "gib": 3,
              "t": 4, "tb": 4, "ti": 4, "tib": 4}
    return int(match.group(1)) * (1024 ** powers[match.group(2)])


def normalize_compose_runtime_model(model: Any) -> dict[str, Any]:
    if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
        raise ValueError("rendered Compose model has no service object")
    services = model["services"]
    if set(services) != set(FINAL_SERVICE_USERS):
        raise ValueError("rendered Compose runtime service set is not closed and complete")
    normalized_services: dict[str, Any] = {}
    for service in sorted(services):
        config = services[service]
        if not isinstance(config, dict):
            raise ValueError(f"rendered Compose service {service} is invalid")
        compose_user = str(config.get("user") or "")
        if service == "serverware" and compose_user != FINAL_SERVICE_USERS[service]:
            raise ValueError("final control-plane Compose user must be exactly 65532:65532")
        normalized_services[service] = {
            "image": str(config.get("image") or ""),
            "compose_user": compose_user,
            "required_runtime_user": FINAL_SERVICE_USERS[service],
            "entrypoint": normalize_command_value(config.get("entrypoint"), service),
            "command": normalize_command_value(config.get("command"), service),
            "working_dir": str(config.get("working_dir") or ""),
            "environment": normalize_environment_hashes(config.get("environment"), service),
            "devices": normalize_compose_devices(config.get("devices"), service),
            "networks": normalize_compose_networks(config.get("networks"), service),
            "mounts": normalize_compose_mounts(config.get("volumes"), service),
            "tmpfs": normalize_tmpfs(config.get("tmpfs"), service),
            "ports": json.loads(canonical_json(config.get("ports") or [])),
            "links": normalize_string_list(config.get("links"), f"{service} links"),
            "external_links": normalize_string_list(
                config.get("external_links"), f"{service} external_links"
            ),
            "host_config": {
                "read_only": bool(config.get("read_only", False)),
                "privileged": bool(config.get("privileged", False)),
                "cap_add": sorted(str(item) for item in (config.get("cap_add") or [])),
                "cap_drop": sorted(str(item) for item in (config.get("cap_drop") or [])),
                "security_opt": sorted(str(item) for item in (config.get("security_opt") or [])),
                "pids_limit": int(config.get("pids_limit") or 0),
                "memory": parse_compose_byte_limit(config.get("mem_limit"), f"{service} mem_limit"),
                "init": bool(config.get("init", False)),
                "group_add": normalize_string_list(
                    config.get("group_add"), f"{service} group_add"
                ),
                "volumes_from": normalize_string_list(
                    config.get("volumes_from"), f"{service} volumes_from"
                ),
                "dns": normalize_string_list(config.get("dns"), f"{service} dns"),
                "dns_search": normalize_string_list(
                    config.get("dns_search"), f"{service} dns_search"
                ),
                "dns_opt": normalize_string_list(
                    config.get("dns_opt"), f"{service} dns_opt"
                ),
                "extra_hosts": normalize_string_list(
                    config.get("extra_hosts"), f"{service} extra_hosts"
                ),
                "pid": str(config.get("pid") or ""),
                "ipc": str(config.get("ipc") or ""),
                "uts": str(config.get("uts") or ""),
                "network_mode": str(config.get("network_mode") or ""),
                "userns_mode": str(config.get("userns_mode") or ""),
                "ulimits": json.loads(canonical_json(config.get("ulimits") or {})),
            },
        }
    resources: dict[str, dict[str, dict[str, Any]]] = {}
    for kind in ("networks", "volumes"):
        raw_resources = model.get(kind) or {}
        if not isinstance(raw_resources, dict):
            raise ValueError(f"rendered Compose {kind} must be an object")
        normalized_resources: dict[str, dict[str, Any]] = {}
        for name, value in sorted(raw_resources.items()):
            if not isinstance(name, str) or not name or not isinstance(value, dict):
                raise ValueError(f"rendered Compose {kind} entry is invalid")
            normalized_resources[name] = {
                "name": (
                    str(value.get("name") or name)
                    if bool(value.get("external", False))
                    else ""
                ),
                "external": bool(value.get("external", False)),
                "driver": str(value.get("driver") or ""),
                "driver_opts": json.loads(
                    canonical_json(value.get("driver_opts") or {})
                ),
            }
        resources[kind] = normalized_resources
    runtime_model = {"services": normalized_services, **resources}
    runtime_model["sha256"] = sha256_prefixed_bytes(
        canonical_json(runtime_model).encode("utf-8")
    )
    return runtime_model


def nested_socket_path(value: Any) -> Any:
    return (value.get("socket") or {}).get("path") if isinstance(value, dict) else None


def sha256_prefixed_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def normalized_file_path(
    path: str | Path,
    label: str,
    *,
    require_absolute: bool,
) -> Path:
    value = os.fspath(path)
    if (
        not value
        or "\x00" in value
        or (require_absolute and not os.path.isabs(value))
        or os.path.normpath(value) != value
        or str(Path(value)) != value
        or Path(value).name in {"", ".", ".."}
    ):
        requirement = "normalized and absolute" if require_absolute else "normalized"
        raise ValueError(f"{label} path must be {requirement}")
    return Path(value)


def require_secure_ancestor(metadata: os.stat_result, path: Path, label: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} ancestors must be non-symlink directories: {path}")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ValueError(f"{label} ancestor must be owned by root or the readiness runner: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError(f"{label} ancestor must not be writable by group/other: {path}")


def open_secure_parent_descriptor(
    path: Path,
    label: str,
    *,
    require_absolute: bool = True,
) -> tuple[Path, int, os.stat_result]:
    path = normalized_file_path(path, label, require_absolute=require_absolute)
    if not all(
        hasattr(os, flag)
        for flag in ("O_DIRECTORY", "O_NOFOLLOW")
    ):
        raise ValueError(f"{label} ancestors cannot be opened safely on this platform")
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path.anchor or ".", flags)
    except OSError as exc:
        raise ValueError(f"{label} path anchor could not be opened safely") from exc
    current = Path(path.anchor or ".")
    try:
        metadata = os.fstat(descriptor)
        require_secure_ancestor(metadata, current, label)
        start = 1 if path.is_absolute() else 0
        for component in path.parts[start:-1]:
            current /= component
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise ValueError(
                    f"{label} ancestor could not be opened without following symlinks: {current}"
                ) from exc
            os.close(descriptor)
            descriptor = child
            metadata = os.fstat(descriptor)
            require_secure_ancestor(metadata, current, label)
        return path, descriptor, metadata
    except Exception:
        os.close(descriptor)
        raise


def validate_secure_ancestors(path: Path, label: str) -> None:
    _, descriptor, _ = open_secure_parent_descriptor(path, label)
    os.close(descriptor)


def validate_proxy_artifact_path_separation(
    output_paths: dict[str, str],
    input_paths: dict[str, str],
) -> None:
    seen_locations: dict[tuple[int, int, str], tuple[str, bool]] = {}
    seen_inodes: dict[tuple[int, int], tuple[str, bool]] = {}
    for label, value, is_output in (
        *((label, value, True) for label, value in output_paths.items()),
        *((label, value, False) for label, value in input_paths.items()),
    ):
        path = normalized_file_path(value, label, require_absolute=True)
        try:
            _, parent_descriptor, parent_metadata = open_secure_parent_descriptor(path, label)
        except ValueError:
            raise
        except OSError as exc:
            raise ValueError(f"{label} parent directory is unavailable: {path.parent}") from exc
        try:
            location = (parent_metadata.st_dev, parent_metadata.st_ino, path.name)
            previous_location = seen_locations.get(location)
            if previous_location is not None and (is_output or previous_location[1]):
                raise ValueError(
                    f"{label} aliases {previous_location[0]}; proxy outputs and collector inputs "
                    "must use different filesystem locations"
                )
            seen_locations[location] = (label, is_output)

            metadata: os.stat_result | None = None
            if is_output:
                flags = (
                    os.O_RDONLY
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                )
                try:
                    descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
                except FileNotFoundError:
                    descriptor = -1
                except OSError as exc:
                    raise ValueError(
                        f"{label} could not be opened without following symlinks: {path}"
                    ) from exc
                if descriptor >= 0:
                    try:
                        metadata = os.fstat(descriptor)
                    finally:
                        os.close(descriptor)
            else:
                try:
                    _, metadata = read_regular_file_once(
                        path,
                        label,
                        max_bytes=MAX_PROXY_TRUST_INPUT_BYTES,
                        owner_only=(label == "proxy collector private key"),
                    )
                except FileNotFoundError as exc:
                    raise ValueError(f"{label} is unavailable: {path}") from exc
                if metadata.st_uid not in {0, os.geteuid()}:
                    raise ValueError(
                        f"{label} must be owned by root or the readiness runner: {path}"
                    )
                if stat.S_IMODE(metadata.st_mode) & 0o022:
                    raise ValueError(f"{label} must not be writable by group/other: {path}")

            if metadata is None:
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError(
                    f"{label} must be a single-link regular file when it exists: {path}"
                )
        finally:
            os.close(parent_descriptor)

        inode = (metadata.st_dev, metadata.st_ino)
        previous_inode = seen_inodes.get(inode)
        if previous_inode is not None and (is_output or previous_inode[1]):
            raise ValueError(
                f"{label} aliases {previous_inode[0]}; proxy outputs and collector inputs "
                "must not share an inode"
            )
        seen_inodes[inode] = (label, is_output)


def read_fd_bytes(
    descriptor: int,
    opened: os.stat_result,
    label: str,
    *,
    max_bytes: int,
) -> bytes:
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    completed = os.fstat(descriptor)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(opened) != identity(completed) or len(data) != opened.st_size:
        raise ValueError(f"{label} changed while being read")
    if len(data) > max_bytes:
        raise ValueError(f"{label} exceeds the {max_bytes}-byte size limit")
    return data


def open_measured_executable(
    path: Path,
    expected_digest: str,
    setting: str,
) -> MeasuredExecutable:
    validate_secure_ancestors(path, setting)
    if SHA256_RE.fullmatch(expected_digest) is None:
        raise ValueError(f"{setting} digest pin is invalid")
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ValueError(f"{setting} could not be opened without following symlinks: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{setting} must be a regular file: {path}")
        if metadata.st_uid not in {0, os.geteuid()}:
            raise ValueError(f"{setting} must be owned by root or the executing user: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError(f"{setting} must not be writable by group/other: {path}")
        if not metadata.st_mode & stat.S_IXUSR:
            raise ValueError(f"{setting} must be executable by its owner: {path}")
        if metadata.st_size <= 0 or metadata.st_size > MAX_EXECUTABLE_BYTES:
            raise ValueError(f"{setting} has an invalid executable size: {path}")
        data = read_fd_bytes(
            descriptor,
            metadata,
            setting,
            max_bytes=MAX_EXECUTABLE_BYTES,
        )
        actual_digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise ValueError(f"{setting} bytes do not match the hashed production env executable pin")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return MeasuredExecutable(path, setting, descriptor, metadata, actual_digest)
    except Exception:
        os.close(descriptor)
        raise


def validate_static_amd64_elf(data: bytes, label: str) -> None:
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:7] != b"\x02\x01\x01":
        raise ValueError(f"{label} must be a 64-bit little-endian ELF executable")
    elf_type, machine, version = struct.unpack_from("<HHI", data, 16)
    if elf_type not in {2, 3} or machine != 62 or version != 1:
        raise ValueError(f"{label} must be an x86-64 executable or static PIE")
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    program_entry_bytes, program_entries = struct.unpack_from("<HH", data, 54)
    if program_entry_bytes != 56 or not 1 <= program_entries <= 256:
        raise ValueError(f"{label} has an invalid ELF program table")
    program_end = program_offset + program_entry_bytes * program_entries
    if program_end > len(data):
        raise ValueError(f"{label} has a truncated ELF program table")
    load_seen = False
    for index in range(program_entries):
        offset = program_offset + index * program_entry_bytes
        program_type = struct.unpack_from("<I", data, offset)[0]
        if program_type == 3:
            raise ValueError(f"{label} must not use PT_INTERP")
        if program_type == 1:
            load_seen = True
        if program_type != 2:
            continue
        dynamic_offset = struct.unpack_from("<Q", data, offset + 8)[0]
        dynamic_bytes = struct.unpack_from("<Q", data, offset + 32)[0]
        dynamic_end = dynamic_offset + dynamic_bytes
        if dynamic_bytes % 16 or dynamic_end > len(data):
            raise ValueError(f"{label} has an invalid ELF dynamic segment")
        for entry in range(dynamic_offset, dynamic_end, 16):
            tag = struct.unpack_from("<Q", data, entry)[0]
            if tag == 1:
                raise ValueError(f"{label} must not contain DT_NEEDED dependencies")
            if tag == 0:
                break
    if not load_seen:
        raise ValueError(f"{label} has no loadable ELF segment")


def open_measured_script(
    path: Path,
    expected_digest: str | None,
    setting: str,
) -> MeasuredScript:
    validate_secure_ancestors(path, setting)
    if expected_digest is not None and SHA256_RE.fullmatch(expected_digest) is None:
        raise ValueError(f"{setting} digest pin is invalid")
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{setting} could not be opened without following symlinks: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{setting} must be a regular file: {path}")
        if metadata.st_uid not in {0, os.geteuid()}:
            raise ValueError(f"{setting} must be owned by root or the executing user: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError(f"{setting} must not be writable by group/other: {path}")
        if metadata.st_size <= 0 or metadata.st_size > MAX_EXECUTABLE_BYTES:
            raise ValueError(f"{setting} has an invalid script size: {path}")
        data = read_fd_bytes(
            descriptor,
            metadata,
            setting,
            max_bytes=MAX_EXECUTABLE_BYTES,
        )
        actual_digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if expected_digest is not None and not hmac.compare_digest(actual_digest, expected_digest):
            raise ValueError(f"{setting} bytes do not match the hashed production env script pin")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return MeasuredScript(path, setting, descriptor, metadata, actual_digest)
    except Exception:
        os.close(descriptor)
        raise


def measured_executable_reference(descriptor: int) -> str:
    if sys.platform.startswith("linux"):
        return f"/proc/self/fd/{descriptor}"
    if sys.platform == "darwin":
        return f"/dev/fd/{descriptor}"
    raise ValueError("measured-descriptor execution is supported only on Linux and macOS")


def run_measured_command(
    argv: list[str],
    *,
    setting: str,
    expected_digest: str,
    after_open: Any | None = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    measured = open_measured_executable(Path(argv[0]), expected_digest, setting)
    try:
        if after_open is not None:
            after_open(measured)
        if not sys.platform.startswith("linux"):
            return subprocess.run(argv, **kwargs)
        inherited = tuple(kwargs.pop("pass_fds", ()))
        return subprocess.run(
            argv,
            executable=measured_executable_reference(measured.fd),
            pass_fds=(*inherited, measured.fd),
            **kwargs,
        )
    finally:
        measured.close()


def run_measured_binary_command_bounded(
    argv: list[str],
    *,
    setting: str,
    expected_digest: str,
    max_stdout_bytes: int,
    max_stderr_bytes: int = 1024 * 1024,
    **kwargs: Any,
) -> subprocess.CompletedProcess[bytes]:
    if max_stdout_bytes < 0 or max_stderr_bytes < 0:
        raise ValueError("measured binary command byte limits must be non-negative")
    measured = open_measured_executable(Path(argv[0]), expected_digest, setting)
    process: subprocess.Popen[bytes] | None = None
    try:
        if not sys.platform.startswith("linux"):
            raise ValueError("bounded measured binary execution requires Linux")
        inherited = tuple(kwargs.pop("pass_fds", ()))
        process = subprocess.Popen(
            argv,
            executable=measured_executable_reference(measured.fd),
            pass_fds=(*inherited, measured.fd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            **kwargs,
        )
        assert process.stdout is not None and process.stderr is not None
        streams = {
            process.stdout.fileno(): (process.stdout, max_stdout_bytes, "stdout"),
            process.stderr.fileno(): (process.stderr, max_stderr_bytes, "stderr"),
        }
        captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
        selector = selectors.DefaultSelector()
        for stream, _, label in streams.values():
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        try:
            while selector.get_map():
                for key, _ in selector.select(timeout=1.0):
                    label = key.data
                    stream = key.fileobj
                    chunk = os.read(stream.fileno(), 64 * 1024)
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    captured[label].extend(chunk)
                    limit = max_stdout_bytes if label == "stdout" else max_stderr_bytes
                    if len(captured[label]) > limit:
                        process.kill()
                        process.wait()
                        raise ValueError(
                            f"measured binary command {label} exceeded {limit} bytes"
                        )
                if process.poll() is not None and not selector.get_map():
                    break
            returncode = process.wait()
        finally:
            selector.close()
        return subprocess.CompletedProcess(
            argv,
            returncode,
            bytes(captured["stdout"]),
            bytes(captured["stderr"]),
        )
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        measured.close()


def run_measured_python_script(
    argv: list[str],
    *,
    python_setting: str,
    python_expected_digest: str,
    script_setting: str,
    script_expected_digest: str | None,
    after_script_open: Any | None = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    if len(argv) < 2:
        raise ValueError("measured Python command is missing its script")
    python = open_measured_executable(Path(argv[0]), python_expected_digest, python_setting)
    script_path = Path(argv[1])
    if not script_path.is_absolute():
        script_path = (Path(kwargs.get("cwd") or os.getcwd()) / script_path).resolve()
    script = open_measured_script(script_path, script_expected_digest, script_setting)
    try:
        if after_script_open is not None:
            after_script_open(script)
        if not sys.platform.startswith("linux"):
            raise ValueError("measured Python script descriptor execution requires Linux")
        inherited = tuple(kwargs.pop("pass_fds", ()))
        command = [
            argv[0],
            "-I",
            "-c",
            PYTHON_FD_BOOTSTRAP,
            str(script.fd),
            str(script_path),
            *argv[2:],
        ]
        return subprocess.run(
            command,
            executable=measured_executable_reference(python.fd),
            pass_fds=(*inherited, python.fd, script.fd),
            **kwargs,
        )
    finally:
        script.close()
        python.close()


def forbidden_process_environment_names(environment: dict[str, str]) -> list[str]:
    return sorted(
        name
        for name in environment
        if name in FORBIDDEN_PROCESS_ENV_NAMES
        or any(name.startswith(prefix) for prefix in FORBIDDEN_PROCESS_ENV_PREFIXES)
    )


def build_final_child_environment(
    loaded: dict[str, str],
    additions: dict[str, str] | None = None,
    *,
    ambient: dict[str, str] | None = None,
) -> dict[str, str]:
    ambient_injections = forbidden_process_environment_names(dict(os.environ) if ambient is None else ambient)
    if ambient_injections:
        raise ValueError(
            "final launcher environment contains forbidden runtime/loader injection settings: "
            + ", ".join(ambient_injections)
        )
    invalid_loaded = sorted(name for name in loaded if not name.startswith("SERVERWARE_"))
    if invalid_loaded:
        raise ValueError(
            "final production env contains non-SERVERWARE child environment settings: "
            + ", ".join(invalid_loaded)
        )
    loaded_injections = forbidden_process_environment_names(loaded)
    if loaded_injections:
        raise ValueError(
            "final production env contains forbidden runtime/loader injection settings: "
            + ", ".join(loaded_injections)
        )
    child = {**FINAL_CHILD_FIXED_ENV, **loaded}
    for name, value in (additions or {}).items():
        if not name.startswith("SERVERWARE_"):
            raise ValueError(f"final child env addition is not allowlisted: {name}")
        child[name] = value
    return child


def docker_subprocess_environment(base: dict[str, str], socket_path: Path) -> dict[str, str]:
    environment = {
        name: value
        for name, value in base.items()
        if not name.startswith("DOCKER_") and not name.startswith("COMPOSE_")
    }
    environment["DOCKER_HOST"] = f"unix://{socket_path}"
    return environment


def require_root_owned_docker_socket_ancestor(
    metadata: os.stat_result | Any,
    path: Path,
) -> None:
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"Docker Unix socket ancestor must be a non-symlink directory: {path}")
    if metadata.st_uid != 0:
        raise ValueError(f"Docker Unix socket ancestor must be owned by UID 0: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ValueError(
            f"Docker Unix socket ancestor must not be writable by group/other: {path}"
        )


def validate_docker_unix_socket(path: Path, *, allow_current_owner: bool = False) -> dict[str, Any]:
    if path != Path("/run/docker.sock") and not allow_current_owner:
        raise ValueError("final Docker Unix socket must be exactly /run/docker.sock")
    validate_secure_ancestors(path, "Docker Unix socket")
    current = Path(path.anchor)
    require_root_owned_docker_socket_ancestor(current.lstat(), current)
    for component in path.parts[1:-1]:
        current /= component
        metadata = current.lstat()
        require_root_owned_docker_socket_ancestor(metadata, current)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"Docker Unix socket is unavailable: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISSOCK(metadata.st_mode):
        raise ValueError("Docker endpoint must be a non-symlink local Unix socket")
    allowed_owners = {0, os.geteuid()} if allow_current_owner else {0}
    if metadata.st_uid not in allowed_owners:
        raise ValueError("Docker Unix socket must be owned by root")
    if stat.S_IMODE(metadata.st_mode) & 0o002:
        raise ValueError("Docker Unix socket must not be world-writable")
    return {
        "path": str(path),
        "owner_uid": metadata.st_uid,
        "mode": oct(stat.S_IMODE(metadata.st_mode)),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "local_unix_socket": True,
        "nofollow": True,
        "secure_ancestors": True,
    }


def verify_docker_daemon_identity(
    *,
    docker_executable: Path,
    docker_sha256: str,
    socket_path: Path,
    expected_daemon_id: str,
    base_env: dict[str, str],
) -> dict[str, Any]:
    socket_binding = validate_docker_unix_socket(socket_path)
    result = run_measured_command(
        [
            str(docker_executable),
            "--host",
            f"unix://{socket_path}",
            "info",
            "--format",
            "{{.ID}}",
        ],
        setting=PRODUCTION_DOCKER_EXECUTABLE_ENV,
        expected_digest=docker_sha256,
        env=docker_subprocess_environment(base_env, socket_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ValueError(f"pinned Docker daemon identity query failed: {detail}")
    actual_daemon_id = result.stdout.strip()
    if not hmac.compare_digest(actual_daemon_id, expected_daemon_id):
        raise ValueError("current Docker daemon ID does not match the hashed production env pin")
    return {
        "daemon_id": actual_daemon_id,
        "daemon_id_verified": True,
        "socket": socket_binding,
    }


def require_stable_docker_daemon_binding(
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    if before != after:
        raise ValueError("Docker socket identity or daemon ID changed during runtime inspection")


def validate_launcher_trusted_env(
    path: Path,
    data: bytes,
    metadata: os.stat_result,
    *,
    expected_path: str | None,
    expected_sha256: str | None,
) -> dict[str, Any]:
    if not isinstance(expected_path, str) or not expected_path:
        raise ValueError(f"launcher trust input {LAUNCHER_TRUSTED_ENV_PATH_INPUT} is required")
    if not isinstance(expected_sha256, str) or SHA256_RE.fullmatch(expected_sha256) is None:
        raise ValueError(
            f"launcher trust input {LAUNCHER_TRUSTED_ENV_SHA256_INPUT} must be sha256:<64 lowercase hex>"
        )
    if not Path(expected_path).is_absolute() or str(path) != expected_path:
        raise ValueError("production env path does not exactly match the out-of-band launcher trust path")
    validate_secure_ancestors(path, "production readiness env")
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ValueError("production readiness env must be owned by root or the executing user")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in {0o400, 0o600}:
        raise ValueError("production readiness env must use mode 0400 or 0600 with no group/world bits")
    actual_digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_sha256):
        raise ValueError("production readiness env does not match the out-of-band launcher trust digest")
    return {
        "path": expected_path,
        "sha256": expected_sha256,
        "owner_uid": metadata.st_uid,
        "mode": oct(mode),
        "regular_file": True,
        "nofollow": True,
        "secure_ancestors": True,
        "authority": "out-of-band launcher trust root",
    }


def validate_final_launcher_contract(loaded: dict[str, str]) -> dict[str, Any]:
    contract = loaded.get(FINAL_LAUNCHER_CONTRACT_ENV)
    if contract != FINAL_LAUNCHER_CONTRACT:
        raise ValueError(
            f"{FINAL_LAUNCHER_CONTRACT_ENV} must be exactly "
            f"{FINAL_LAUNCHER_CONTRACT} for launcher-enforced readiness"
        )
    return {
        "name": contract,
        "enforced_before_python_startup_by": "trusted root-owned launcher/systemd unit",
        "in_process_validation_is_not_startup_attestation": True,
    }


def read_regular_file_once(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    owner_only: bool = False,
    executable: bool = False,
    allow_empty: bool = False,
) -> tuple[bytes, os.stat_result]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError(f"{label} cannot be opened safely on this platform")
    path, parent_descriptor, parent_metadata = open_secure_parent_descriptor(
        path,
        label,
        require_absolute=False,
    )
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
    except FileNotFoundError:
        os.close(parent_descriptor)
        raise
    except OSError as exc:
        os.close(parent_descriptor)
        raise ValueError(f"{label} could not be opened without following symlinks: {path}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ValueError(f"{label} must be a single-link regular file: {path}")
        if opened.st_size > max_bytes or (opened.st_size == 0 and not allow_empty):
            minimum = 0 if allow_empty else 1
            raise ValueError(
                f"{label} must contain between {minimum} and {max_bytes} bytes: {path}"
            )
        if owner_only:
            if stat.S_IMODE(opened.st_mode) not in {0o400, 0o600}:
                raise ValueError(f"{label} must use owner-only mode 0400 or 0600: {path}")
            if opened.st_uid not in {0, os.geteuid()}:
                raise ValueError(f"{label} must be owned by root or the readiness runner: {path}")
        if executable and not opened.st_mode & stat.S_IXUSR:
            raise ValueError(f"{label} must be executable by its owner: {path}")
        data = read_fd_bytes(descriptor, opened, f"{label}: {path}", max_bytes=max_bytes)
        try:
            current_parent_descriptor_path, current_parent_descriptor, current_parent = (
                open_secure_parent_descriptor(path, label, require_absolute=False)
            )
            del current_parent_descriptor_path
        except ValueError as exc:
            raise ValueError(f"{label} path changed while being read: {path}") from exc
        try:
            if (
                current_parent.st_dev,
                current_parent.st_ino,
            ) != (
                parent_metadata.st_dev,
                parent_metadata.st_ino,
            ):
                raise ValueError(f"{label} path changed while being read: {path}")
            try:
                current_descriptor = os.open(
                    path.name,
                    flags,
                    dir_fd=current_parent_descriptor,
                )
            except OSError as exc:
                raise ValueError(f"{label} path changed while being read: {path}") from exc
            try:
                current = os.fstat(current_descriptor)
            finally:
                os.close(current_descriptor)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError(f"{label} path changed while being read: {path}")
        finally:
            os.close(current_parent_descriptor)
        return data, opened
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)


def remeasure_executable(path: Path, expected_digest: str, label: str) -> str:
    measured = open_measured_executable(path, expected_digest, label)
    try:
        return measured.sha256
    finally:
        measured.close()


def parse_executable_digest_manifest(
    loaded: dict[str, str],
    *,
    expected_settings: set[str],
) -> dict[str, str]:
    raw = loaded.get(EXECUTABLE_DIGEST_MANIFEST_ENV)
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{EXECUTABLE_DIGEST_MANIFEST_ENV} is required")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{EXECUTABLE_DIGEST_MANIFEST_ENV} must be valid JSON") from exc
    if not isinstance(parsed, dict) or set(parsed) != expected_settings:
        raise ValueError(f"{EXECUTABLE_DIGEST_MANIFEST_ENV} must contain the exact executable setting set")
    for setting, digest in parsed.items():
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError(
                f"{EXECUTABLE_DIGEST_MANIFEST_ENV} entry {setting} must be sha256:<64 lowercase hex>"
            )
    return dict(parsed)


def parse_python_script_digest_pins(loaded: dict[str, str]) -> dict[str, tuple[str, str]]:
    pins: dict[str, tuple[str, str]] = {}
    for script_name, setting in PINNED_PYTHON_SCRIPTS.items():
        digest = loaded.get(setting)
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise ValueError(f"{setting} must be sha256:<64 lowercase hex>")
        pins[str((ROOT / "scripts" / script_name).resolve())] = (setting, digest)
    return pins


def validate_docker_toolchain_settings(loaded: dict[str, str]) -> dict[str, str]:
    values = {
        name: loaded.get(name)
        for name in (
            DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV,
            DOCKER_COMPOSE_PLUGIN_SHA256_ENV,
            DOCKER_UNIX_SOCKET_ENV,
            DOCKER_DAEMON_ID_ENV,
            DOCKER_COMPOSE_PROJECT_NAME_ENV,
        )
    }
    if not isinstance(values[DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV], str) or not Path(
        values[DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV]
    ).is_absolute():
        raise ValueError(f"{DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV} must be an absolute path")
    if (
        not isinstance(values[DOCKER_COMPOSE_PLUGIN_SHA256_ENV], str)
        or SHA256_RE.fullmatch(values[DOCKER_COMPOSE_PLUGIN_SHA256_ENV]) is None
    ):
        raise ValueError(f"{DOCKER_COMPOSE_PLUGIN_SHA256_ENV} must be sha256:<64 lowercase hex>")
    if not isinstance(values[DOCKER_UNIX_SOCKET_ENV], str) or not Path(
        values[DOCKER_UNIX_SOCKET_ENV]
    ).is_absolute():
        raise ValueError(f"{DOCKER_UNIX_SOCKET_ENV} must be an absolute path")
    daemon_id = values[DOCKER_DAEMON_ID_ENV]
    if (
        not isinstance(daemon_id, str)
        or daemon_id != daemon_id.strip()
        or not 8 <= len(daemon_id) <= 256
        or not all(character.isalnum() or character in "._:-" for character in daemon_id)
    ):
        raise ValueError(f"{DOCKER_DAEMON_ID_ENV} is invalid")
    project_name = values[DOCKER_COMPOSE_PROJECT_NAME_ENV]
    if (
        not isinstance(project_name, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project_name) is None
    ):
        raise ValueError(f"{DOCKER_COMPOSE_PROJECT_NAME_ENV} is invalid")
    return {name: str(value) for name, value in values.items()}


def completion_proof_digest_path(path: Path, generation: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{32}", generation) is None:
        raise ValueError("completion proof checksum generation is invalid")
    return path.with_name(f"{path.name}.sha256.{generation}")


def completion_proof_v6_core(proof: dict[str, Any]) -> dict[str, Any]:
    if not COMPLETION_PROOF_V6_ENVELOPE_FIELDS.issubset(proof):
        raise ValueError(
            "completion proof is missing persisted envelope fields"
        )
    return {
        key: value
        for key, value in proof.items()
        if key not in COMPLETION_PROOF_V6_ENVELOPE_FIELDS
    }


def capture_optional_proof_state(path: Path) -> dict[str, Any]:
    try:
        data, metadata = read_regular_file_once(
            path,
            "pre-run completion proof",
            max_bytes=MAX_COMPLETION_PROOF_BYTES,
            owner_only=True,
        )
    except FileNotFoundError:
        return {"exists": False}
    state: dict[str, Any] = {
        "exists": True,
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return state
    if isinstance(parsed, dict):
        integrity = parsed.get("integrity_metadata")
        if isinstance(integrity, dict) and isinstance(integrity.get("generation"), str):
            state["generation"] = integrity["generation"]
    return state


def sha256_prefixed_base64url(value: str, label: str) -> str:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{label} is not valid base64url") from exc
    if len(decoded) < 32:
        raise ValueError(f"{label} must decode to at least 32 bytes")
    return "sha256:" + hashlib.sha256(decoded).hexdigest()


def verify_completion_output(path: Path, expected: argparse.Namespace | None = None) -> str:
    """Verify a trusted-host readiness completionProof/v6 artifact."""
    proof_bytes, proof_metadata = read_regular_file_once(
        path,
        "completion proof",
        max_bytes=MAX_COMPLETION_PROOF_BYTES,
        owner_only=True,
    )
    try:
        proof = json.loads(proof_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("completion proof is not valid UTF-8 JSON") from exc
    if not isinstance(proof, dict):
        raise ValueError("completion proof must be a JSON object")
    if proof_bytes != canonical_json(proof).encode("utf-8") + b"\n":
        raise ValueError(
            "completion proof must use exact canonical JSON bytes plus LF"
        )
    if proof.get("apiVersion") == FINAL_COMPLETION_RESULT_API_VERSION:
        raise ValueError(
            "releaseCompletionVerification/v1 is final-verifier output and "
            "cannot be consumed by the trusted-host readiness runner"
        )

    if proof.get("apiVersion") != COMPLETION_PROOF_API_VERSION:
        raise ValueError(
            "completion output is not the current readiness envelope"
        )
    if "ok" in proof or "final_completion" in proof:
        raise ValueError(
            "completion proof contains an obsolete top-level authority field"
        )
    persisted_mode = proof.get("verification_mode")
    if persisted_mode != "readiness":
        raise ValueError(
            "completionProof/v6 is a readiness envelope; final mode requires releaseCompletionVerification/v1"
        )
    if (
        expected is not None
        and getattr(expected, "verification_mode", None) != "readiness"
    ):
        raise ValueError(
            "completionProof/v6 cannot satisfy a final-mode readiness runner"
        )
    required_fields = {
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
    if set(proof) != required_fields:
        raise ValueError("completion proof persisted field set does not match the v6 contract")
    runner_mode = expected.verification_mode if expected is not None else persisted_mode
    if runner_mode != "readiness":
        raise ValueError(
            "trusted-host completion verification mode must be exactly readiness"
        )
    if persisted_mode != runner_mode:
        raise ValueError(
            "completion proof verification mode does not match the current runner"
        )
    verification_mode = "readiness"
    launcher_enforced = (
        expected is not None
        and getattr(expected, "bootstrap_receipt", None) is not None
    )
    generated_at_unix = proof.get("generated_at_unix")
    if type(generated_at_unix) is not int or generated_at_unix <= 0:
        raise ValueError("completion proof generated_at_unix is invalid")
    if expected is not None:
        runner_started_at = getattr(
            expected,
            "runner_started_at_unix",
            None,
        )
        if (
            type(runner_started_at) is not int
            or generated_at_unix < runner_started_at
        ):
            raise ValueError(
                "completion proof predates the current readiness runner invocation"
            )
        if (
            generated_at_unix
            > int(time.time()) + COMPLETION_PROOF_FUTURE_SKEW_SECONDS
        ):
            raise ValueError(
                "completion proof generated_at_unix is in the future"
            )
    current_freshness_verified = False
    if launcher_enforced:
        revalidate_bootstrap_launch_authorization_at_completion(
            expected_receipt=expected.bootstrap_receipt,
            expected_descriptor=expected.bootstrap_receipt_fd,
            generated_at_unix=generated_at_unix,
        )
        current_freshness_verified = True
    expected_contract = {
        "apiVersion": COMPLETION_PROOF_API_VERSION,
        "kind": "ServerwarePreEnclaveReadiness",
        "verificationOk": True,
        "finalCompletionVerified": False,
        "actionAuthorization": None,
        "okForAction": False,
        "verification_passed": True,
        "verification_mode": verification_mode,
        "result_scope": "readiness-only",
        "readiness_only": True,
        "readiness_ok": True,
        "completion_status": "pre-enclave-readiness",
        "release_completion": "not-final",
        "hardware_proof": False,
        "proof_path": str(path),
    }
    for field, value in expected_contract.items():
        if proof.get(field) != value:
            raise ValueError(f"completion proof persisted {field} does not match the expected contract")
    bootstrap_launcher = proof.get("bootstrap_launcher")
    if launcher_enforced:
        expected_receipt = getattr(expected, "bootstrap_receipt", None) if expected is not None else None
        if not isinstance(bootstrap_launcher, dict) or bootstrap_launcher.get("sealed") is not True:
            raise ValueError("launcher-enforced readiness proof is missing its sealed bootstrap launcher binding")
        validate_bootstrap_receipt_summary(bootstrap_launcher)
        if expected_receipt is not None and bootstrap_launcher != expected_receipt:
            raise ValueError("readiness proof bootstrap launcher binding changed during execution")
    elif bootstrap_launcher != {"required": False, "verified": False}:
        raise ValueError("manual readiness proof must not claim a verified bootstrap launcher")
    nonce_assurance = proof.get("nonce_rollback_assurance")
    if not isinstance(nonce_assurance, dict):
        raise ValueError("completion proof nonce rollback assurance binding is invalid")
    if launcher_enforced:
        expected_nonce = getattr(expected, "nonce_rollback_assurance", None)
        launch_manifest = nonce_assurance.get("launchManifest")
        if (
            not isinstance(expected_nonce, dict)
            or expected_nonce.get("verified") is not True
            or any(
                nonce_assurance.get(field) != expected_nonce.get(field)
                for field in expected_nonce
            )
            or nonce_assurance.get("purpose") != "readiness-only"
            or not isinstance(launch_manifest, dict)
            or launch_manifest.get("apiVersion")
            != "serverware.productionReadinessLaunch/v3"
            or launch_manifest.get("purpose") != "readiness-only"
            or launch_manifest.get("verified") is not True
            or launch_manifest.get("manifestSha256")
            != bootstrap_launcher["manifest"]["sha256"]
            or launch_manifest.get("contractSha256")
            != expected_nonce["contractSha256"]
            or launch_manifest.get("verifierStateService")
            != expected_nonce.get("verifierStateService")
            or (
                launch_manifest.get("pinsFile")
                if isinstance(launch_manifest.get("pinsFile"), dict)
                else {}
            ).get("sha256")
            != expected_nonce["retainedSnapshotSha256"]
        ):
            raise ValueError(
                "completion proof changed its launcher-enforced nonce rollback assurance identity"
            )
    elif nonce_assurance != {
        "apiVersion": NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION,
        "enforcement": "not-native-launcher-enforced",
        "verified": False,
        "launchManifest": {
            "apiVersion": "serverware.productionReadinessLaunch/v3",
            "purpose": "readiness-only",
            "verified": False,
        },
        "purpose": "readiness-only",
    }:
        raise ValueError(
            "manual readiness proof must not claim launcher-enforced nonce rollback assurance"
        )
    preflight_nonce = (
        proof.get("production_host_preflight", {}).get(
            "nonce_rollback_assurance"
        )
        if isinstance(proof.get("production_host_preflight"), dict)
        else None
    )
    expected_preflight_nonce = {
        key: value
        for key, value in nonce_assurance.items()
        if key not in {"launchManifest", "purpose"}
    }
    preflight_summary = proof.get("production_host_preflight")
    expected_preflight_boundary = {
        "apiVersion": "serverware.productionHostReadinessBoundary/v1",
        "verificationMode": "readiness",
        "launchManifestApiVersion": "serverware.productionReadinessLaunch/v3",
        "launchAuthorizationRequestApiVersion": (
            "serverware.launchAuthorizationRequest/v2"
        ),
        "launchAuthorizationApiVersion": "serverware.launchAuthorization/v2",
        "bootstrapReceiptApiVersion": "serverware.bootstrapReceipt/v3",
        "authorizationScope": "trusted-host-readiness",
        "freshnessAuthority": "trusted-host-wall-clock",
        "launcherEvidenceVerified": launcher_enforced,
        "currentFreshnessVerifiedUsingTrustedHostWallClock": (
            current_freshness_verified
        ),
        "secureTimeProven": False,
        "finalNitroExecutionProven": False,
        "actionAuthority": False,
        "hostBootstrapEvidenceClassification": (
            "non-authoritative-readiness-context-only"
        ),
        "finalAuthority": (
            "independent-manifest-v6-public-nitro-verifier-and-protected-state"
        ),
    }
    if (
        not isinstance(preflight_summary, dict)
        or preflight_summary.get("verification_mode") != "readiness"
        or preflight_summary.get("readiness_only") is not True
        or preflight_summary.get("final_nitro_execution_proven") is not False
        or preflight_summary.get("ok_for_action") is not False
        or preflight_summary.get("authority_boundary")
        != expected_preflight_boundary
    ):
        raise ValueError(
            "completion proof production host preflight crossed its "
            "readiness-only authority boundary"
        )
    if preflight_nonce != expected_preflight_nonce:
        raise ValueError(
            "completion proof nonce rollback assurance differs from production preflight"
        )
    assurance = proof.get("assurance_ceiling")
    if (
        not isinstance(assurance, dict)
        or assurance.get("final_completion") is not False
        or assurance.get("hardware_proof") is not False
        or assurance.get("level") != "pre-enclave-readiness"
    ):
        raise ValueError("completion proof assurance ceiling is inconsistent")
    proof_core_sha256 = proof.get("proof_core_sha256")
    if SHA256_RE.fullmatch(str(proof_core_sha256)) is None:
        raise ValueError("completion proof core digest is invalid")
    expected_proof_core_sha256 = sha256_prefixed_bytes(
        canonical_json(completion_proof_v6_core(proof)).encode("utf-8")
    )
    if not hmac.compare_digest(
        proof_core_sha256,
        expected_proof_core_sha256,
    ):
        raise ValueError(
            "completion proof core digest does not match its canonical "
            "nested readiness core"
        )
    challenge = proof.get("final_challenge_consumption")
    if not isinstance(challenge, dict):
        raise ValueError("completion proof final challenge contract is invalid")
    aggregate = proof.get("aggregate_authentication")
    if challenge != {"required": False, "consumed": False}:
        raise ValueError(
            "readiness proof persisted an invalid final challenge contract"
        )
    if (
        proof.get("independently_authenticated") is not False
        or aggregate
        != {
            "required": False,
            "independently_authenticated": False,
            "scope": "readiness-only",
        }
    ):
        raise ValueError(
            "readiness proof must not claim independent final authentication"
        )

    integrity = proof.get("integrity_metadata")
    readiness_integrity_fields = {
        "generation",
        "detached_sha256_path",
        "scope",
        "independently_authenticated",
        "authenticity_requires_external_signature_or_checkpoint",
    }
    if (
        not isinstance(integrity, dict)
        or set(integrity) != readiness_integrity_fields
    ):
        raise ValueError("completion proof detached integrity metadata is invalid")
    generation = integrity.get("generation")
    if not isinstance(generation, str) or re.fullmatch(
        r"[0-9a-f]{32}", generation
    ) is None:
        raise ValueError("completion proof checksum generation is invalid")
    digest_path = completion_proof_digest_path(path, generation)
    if integrity.get("detached_sha256_path") != str(digest_path):
        raise ValueError("completion proof detached integrity metadata is invalid")
    if (
        integrity.get("scope") != "checksum-only"
        or integrity.get("independently_authenticated") is not False
        or integrity.get(
            "authenticity_requires_external_signature_or_checkpoint"
        )
        is not True
    ):
        raise ValueError("completion proof detached integrity metadata is invalid")
    digest_bytes, digest_metadata = read_regular_file_once(
        digest_path,
        "completion proof detached SHA-256",
        max_bytes=128,
        owner_only=True,
    )
    try:
        detached_digest = digest_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("completion proof detached SHA-256 is non-ASCII") from exc
    if not detached_digest.endswith("\n") or detached_digest.count("\n") != 1:
        raise ValueError("completion proof detached SHA-256 must contain exactly one digest line")
    expected_digest = detached_digest[:-1]
    if SHA256_RE.fullmatch(expected_digest) is None:
        raise ValueError("completion proof detached SHA-256 must be sha256:<64 lowercase hex>")
    actual_digest = "sha256:" + hashlib.sha256(proof_bytes).hexdigest()
    if not hmac.compare_digest(expected_digest, actual_digest):
        raise ValueError("completion proof detached SHA-256 does not match the completion proof bytes")
    if expected is not None:
        previous = getattr(expected, "pre_run_completion_proof_state", {"exists": False})
        if previous.get("exists"):
            if previous.get("sha256") == actual_digest:
                raise ValueError("completion proof path was not changed by the current verifier invocation")
            if previous.get("generation") == generation:
                raise ValueError("completion proof generation was reused from the pre-run output")
            if (previous.get("device"), previous.get("inode")) == (
                proof_metadata.st_dev,
                proof_metadata.st_ino,
            ):
                raise ValueError("completion proof commit marker inode was not replaced")
        runner_started_at_ns = getattr(expected, "runner_started_at_unix", 0) * 1_000_000_000
        if digest_metadata.st_mtime_ns < runner_started_at_ns or proof_metadata.st_mtime_ns < runner_started_at_ns:
            raise ValueError("completion proof generation was not published during the current runner invocation")

    artifacts = proof.get("artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError("completion proof artifact contract is empty")
    reopened_artifacts: dict[str, dict[str, Any]] = {}
    for label, artifact in artifacts.items():
        if (
            not isinstance(label, str)
            or not isinstance(artifact, dict)
            or set(artifact) != {"path", "sha256"}
            or not isinstance(artifact.get("path"), str)
            or SHA256_RE.fullmatch(str(artifact.get("sha256"))) is None
        ):
            raise ValueError("completion proof artifact contract is invalid")
        artifact_max_bytes = MAX_COMPLETION_PROOF_BYTES
        if label == "proxy_stream_body":
            artifact_max_bytes = min(
                MAX_PROXY_STREAM_BODY_BYTES,
                getattr(expected, "proxy_max_stream_bytes", MAX_PROXY_STREAM_BODY_BYTES),
            )
        elif label == "proxy_observation_body":
            artifact_max_bytes = min(
                MAX_PROXY_OBSERVATION_BODY_BYTES,
                getattr(
                    expected,
                    "proxy_max_observation_body_bytes",
                    MAX_PROXY_OBSERVATION_BODY_BYTES,
                ),
            )
        artifact_bytes, _ = read_regular_file_once(
            Path(artifact["path"]),
            f"completion proof artifact {label}",
            max_bytes=artifact_max_bytes,
            allow_empty=label
            in {"proxy_stream_body", "proxy_observation_body"},
        )
        artifact_digest = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
        if not hmac.compare_digest(artifact_digest, artifact["sha256"]):
            raise ValueError(f"completion proof artifact {label} digest does not match current bytes")
        reopened_artifacts[label] = {
            "sha256": artifact_digest,
            "bytes": len(artifact_bytes),
        }
    binding = proof.get("production_env_binding")
    proxy = proof.get("production_proxy_response_proof")
    if not isinstance(binding, dict) or not isinstance(proxy, dict):
        raise ValueError("completion proof proxy/env binding contract is missing")
    if expected is not None:
        expected_proof_contract = getattr(
            expected, "proxy_proof_contract", BUFFERED_PROXY_PROOF_CONTRACT
        )
        if proxy.get("proof_contract") != expected_proof_contract:
            raise ValueError("completion proof proxy contract does not match the independently selected contract")
        if binding.get("proxy_proof_contract") != expected_proof_contract:
            raise ValueError("completion proof production env binding changed the selected proxy proof contract")
        if (
            getattr(expected, "collected_proxy_proof_contract", expected_proof_contract)
            != expected_proof_contract
        ):
            raise ValueError("runner did not retain the independently selected collector proof contract")
        for attribute, env_name in PROXY_DIGEST_ENV_SETTINGS.items():
            value = getattr(expected, attribute)
            if binding.get(env_name) != value:
                raise ValueError(f"completion proof production env binding omitted {env_name}")
        for field, attribute in (
            ("client_request_digest", "proxy_client_request_digest"),
            ("request_digest", "proxy_request_digest"),
            ("operation_digest", "proxy_operation_digest"),
        ):
            if proxy.get(field) != getattr(expected, attribute):
                raise ValueError(f"completion proof proxy response {field} mismatch")
        if expected_proof_contract == STREAMING_PROXY_PROOF_CONTRACT:
            authorization_binding_commitment = proxy.get(
                "authorization_binding_commitment"
            )
            if (
                not isinstance(authorization_binding_commitment, dict)
                or authorization_binding_commitment.get("operation_context_digest")
                != expected.proxy_operation_context_digest
            ):
                raise ValueError(
                    "completion proof proxy response operation_context_digest mismatch"
                )
            if (
                binding.get("proxy_operation_context_digest")
                != expected.proxy_operation_context_digest
                or binding.get("proxy_stream_body")
                != str(expected.proxy_stream_body)
                or binding.get("proxy_max_stream_bytes")
                != expected.proxy_max_stream_bytes
            ):
                raise ValueError(
                    "completion proof production env binding omitted streaming proof settings"
                )
            if any(
                binding.get(field) is not None
                for field in (
                    "proxy_observation_body",
                    "proxy_max_observation_body_bytes",
                )
            ):
                raise ValueError(
                    "streaming completion proof retained observation-only env settings"
                )
        elif expected_proof_contract == OBSERVATION_PROXY_PROOF_CONTRACT:
            if (
                binding.get("proxy_observation_body")
                != str(expected.proxy_observation_body)
                or binding.get("proxy_max_observation_body_bytes")
                != expected.proxy_max_observation_body_bytes
            ):
                raise ValueError(
                    "completion proof production env binding omitted observation proof settings"
                )
            if any(
                binding.get(field) is not None
                for field in (
                    "proxy_stream_body",
                    "proxy_max_stream_bytes",
                    "proxy_operation_context_digest",
                )
            ):
                raise ValueError(
                    "observation completion proof retained streaming-only env settings"
                )
        elif any(
            binding.get(field) is not None
            for field in (
                "proxy_stream_body",
                "proxy_max_stream_bytes",
                "proxy_operation_context_digest",
                "proxy_observation_body",
                "proxy_max_observation_body_bytes",
            )
        ):
            raise ValueError(
                "buffered completion proof retained body-artifact env settings"
            )
        if proxy.get("server_instance_id") != expected.proxy_server_instance_id:
            raise ValueError("completion proof proxy server instance mismatch")
        if proxy.get("principal_id") != expected.proxy_principal_id:
            raise ValueError("completion proof proxy principal mismatch")
        required_proxy_bindings = (
            (
                "vendor_quote_verified",
                "collector_signature_verified",
                "server_statement_signature_verified",
                "terminal_runtime_proof_bound",
                "strict_collector_capture_bound",
                "signed_policy_route_bound",
                "compiled_route_authority_verified",
                "release_artifacts_bound",
            )
            if expected_proof_contract == OBSERVATION_PROXY_PROOF_CONTRACT
            else (
                "vendor_quote_verified",
                "collector_signature_verified",
                "server_statement_signature_verified",
                "fresh_client_nonce_bound",
                "authenticated_external_client_capture_bound",
                "release_authority_bound",
                "compiled_route_authority_verified",
                "embedded_control_plane_authorization_receipt_bound",
                "signed_policy_route_bound",
                "signed_policy_response_headers_bound",
                "upstream_response_bound",
                "release_artifacts_bound",
            )
        )
        for field in required_proxy_bindings:
            if proxy.get(field) is not True:
                raise ValueError(f"completion proof proxy contract omitted {field}")
        control_plane_receipt = proxy.get(
            "control_plane_authorization_receipt"
        )
        if (
            expected_proof_contract
            in {
                BUFFERED_PROXY_PROOF_CONTRACT,
                OBSERVATION_PROXY_PROOF_CONTRACT,
            }
            and (
                not isinstance(control_plane_receipt, dict)
                or control_plane_receipt.get(
                    "custody_authorization_envelope_verified"
                )
                is not True
            )
        ):
            raise ValueError(
                "completion proof control-plane receipt omitted internally "
                "verified custody authorization"
            )
        if binding.get("verification_mode") != verification_mode:
            raise ValueError("completion proof production env binding mode mismatch")
        if binding.get("expected_server_instance_id") != expected.proxy_server_instance_id:
            raise ValueError("completion proof production env binding server instance mismatch")
        if binding.get("expected_proxy_principal_id") != expected.proxy_principal_id:
            raise ValueError("completion proof production env binding principal mismatch")
        if binding.get("production_readiness_env_sha256") != expected.production_readiness_env_sha256:
            raise ValueError("completion proof production env digest mismatch")
        expected_artifact_paths = {
            "production_readiness": expected.readiness_out,
            "production_readiness_config": expected.config_out,
            "production_readiness_env": expected.env_file,
            "production_host_preflight": expected.production_host_preflight,
            "nitro_evidence": expected.nitro_evidence_out,
            "production_images_build": expected.production_images_build,
            "production_images_env": expected.production_images_env,
            "production_images_published": expected.production_images_published,
            "release_provenance_summary": expected.release_provenance_summary,
            "release_provenance": expected.release_provenance,
            "release_provenance_trusted_public_key": expected.release_provenance_trusted_public_key,
            "image_signatures_summary": expected.image_signatures_summary,
            "image_signatures": expected.image_signatures,
            "sigstore_trusted_public_key": expected.sigstore_trusted_public_key,
            "rekor_trusted_public_key": expected.rekor_trusted_public_key,
            "external_checkpoint_trusted_public_key": expected.external_checkpoint_trusted_public_key,
            "bench": expected.bench,
            "policy_bundle": expected.policy_bundle,
            "policy_trusted_public_key": expected.policy_trusted_public_key,
            "policy_identity_verification": expected.policy_identity_verification,
            "policy_activation_verification": expected.policy_activation_verification,
            "policy_activation_signature": expected.policy_activation_signature,
            "policy_activation_trusted_public_key": expected.policy_activation_trusted_public_key,
            "reproducible_build_verification": expected.reproducible_build_verification,
            "reproducible_build_signature": expected.reproducible_build_signature,
            "reproducible_build_trusted_public_key": expected.reproducible_build_trusted_public_key,
            "kms_materials": expected.kms_materials,
            "control_plane_response_signing_public_key": expected.control_plane_response_signing_public_key,
            "proxy_response_proof": expected.proxy_response_proof,
            "proxy_proof_verifier_public_key": expected.proxy_proof_verifier_public_key,
            "proxy_collector_public_key": expected.proxy_collector_public_key,
            "compose_file": expected.compose_file,
        }
        if expected_proof_contract == STREAMING_PROXY_PROOF_CONTRACT:
            expected_artifact_paths["proxy_stream_body"] = expected.proxy_stream_body
        elif expected_proof_contract == OBSERVATION_PROXY_PROOF_CONTRACT:
            expected_artifact_paths["proxy_observation_body"] = (
                expected.proxy_observation_body
            )
        if launcher_enforced:
            expected_artifact_paths["production_host_preflight_signing_public_key"] = (
                expected.production_host_preflight_signing_public_key
            )
        for label, expected_path in expected_artifact_paths.items():
            artifact = artifacts.get(label)
            if not isinstance(artifact, dict) or artifact.get("path") != str(Path(expected_path)):
                raise ValueError(f"completion proof artifact {label} path mismatch")
        unexpected_artifacts = set(artifacts) - set(expected_artifact_paths) - {
            "production_host_preflight_config",
            "kms_ciphertext_broker-kek",
            "kms_ciphertext_decision-gate-ca",
        }
        if unexpected_artifacts:
            raise ValueError(f"completion proof contains unexpected artifact bindings: {sorted(unexpected_artifacts)}")

        required_summaries = {
            "production_readiness",
            "production_readiness_config",
            "current_completion_host",
            "production_env_binding",
            "running_production_containers",
            "production_host_preflight",
            "nitro_kms_evidence",
            "nitro_evidence_binding",
            "hardware_assurance_evidence",
            "production_images_build",
            "production_images_published",
            "release_provenance",
            "image_signatures",
            "benchmark",
            "release_security_evidence",
            "production_proxy_response_proof",
        }
        if any(not isinstance(proof.get(field), dict) or not proof[field] for field in required_summaries):
            raise ValueError("completion proof persisted summary contract is incomplete")
        for field in ("production_readiness", "production_readiness_config"):
            environment = proof[field].get("environment")
            if not isinstance(environment, dict) or environment.get(
                "production_readiness_env_sha256"
            ) != expected.production_readiness_env_sha256:
                raise ValueError(f"completion proof {field} is not bound to the hashed production env")
        launcher_binding = binding.get("launcher_trust")
        expected_launcher_binding = getattr(expected, "launcher_env_binding", None)
        if expected_launcher_binding is not None and launcher_binding != expected_launcher_binding:
            raise ValueError("completion proof launcher trust binding mismatch")
        if binding.get("proxy_proof_max_age_seconds") != expected.proxy_proof_max_age_seconds:
            raise ValueError("completion proof proxy max-age policy mismatch")
        if binding.get("p99_limit_ms") != expected.p99_limit_ms:
            raise ValueError("completion proof p99 policy mismatch")
        if binding.get("docker_executable") != expected.docker_executable:
            raise ValueError("completion proof Docker executable mismatch")
        if launcher_enforced:
            for field, attribute in (
                ("docker_compose_plugin_executable", "docker_compose_plugin_executable"),
                ("docker_compose_plugin_sha256", "docker_compose_plugin_sha256"),
                ("docker_unix_socket", "docker_unix_socket"),
                ("docker_daemon_id", "docker_daemon_id"),
                (
                    "docker_compose_project_name",
                    "docker_compose_project_name",
                ),
                (
                    "production_host_preflight_signing_public_key",
                    "production_host_preflight_signing_public_key",
                ),
                (
                    "production_host_preflight_signing_key_id",
                    "production_host_preflight_signing_key_id",
                ),
                (
                    "production_host_preflight_max_age_seconds",
                    "production_host_preflight_max_age_seconds",
                ),
                ("policy_trusted_public_key_id", "policy_trusted_public_key_id"),
                (
                    "policy_activation_trusted_public_key_id",
                    "policy_activation_trusted_public_key_id",
                ),
                (
                    "reproducible_build_trusted_public_key_id",
                    "reproducible_build_trusted_public_key_id",
                ),
            ):
                if binding.get(field) != getattr(expected, attribute):
                    raise ValueError(f"completion proof production binding mismatch: {field}")
            running = proof["running_production_containers"]
            if (
                running.get("compose_plugin_executable")
                != expected.docker_compose_plugin_executable
                or running.get("compose_plugin_sha256")
                != expected.docker_compose_plugin_sha256
                or running.get("docker_daemon_before")
                != running.get("docker_daemon_after")
                or (running.get("docker_daemon_after") or {}).get("daemon_id")
                != expected.docker_daemon_id
                or nested_socket_path(running.get("docker_daemon_after"))
                != expected.docker_unix_socket
                or running.get("compose_project_name")
                != expected.docker_compose_project_name
            ):
                raise ValueError("completion proof Docker renderer or stable daemon binding mismatch")
            generation_before = running.get("service_generation_before")
            generation_after = running.get("service_generation_after")
            expected_services = set(FINAL_SERVICE_USERS)
            if (
                not isinstance(generation_before, dict)
                or set(generation_before) != expected_services
                or generation_before != generation_after
            ):
                raise ValueError(
                    "completion proof did not retain one stable complete Compose service generation"
                )
            for service, generation_entry in generation_before.items():
                if (
                    not isinstance(generation_entry, dict)
                    or re.fullmatch(
                        r"[0-9a-f]{64}", str(generation_entry.get("container_id"))
                    )
                    is None
                    or not isinstance(generation_entry.get("started_at"), str)
                    or not generation_entry["started_at"]
                    or SHA256_RE.fullmatch(str(generation_entry.get("image_id")))
                    is None
                    or not isinstance(generation_entry.get("runtime_projection"), dict)
                    or not generation_entry["runtime_projection"]
                ):
                    raise ValueError(
                        f"completion proof has an invalid live generation entry for {service}"
                    )
            preflight_runtime_model = proof["production_host_preflight"].get(
                "production_runtime_model"
            )
            if (
                not isinstance(preflight_runtime_model, dict)
                or running.get("runtime_model_sha256")
                != preflight_runtime_model.get("sha256")
            ):
                raise ValueError(
                    "completion proof live runtime projection is not bound to the signed preflight model"
                )
            container_summaries = running.get("containers")
            if (
                not isinstance(container_summaries, list)
                or {item.get("service") for item in container_summaries if isinstance(item, dict)}
                != expected_services
            ):
                raise ValueError("completion proof live container summary set is incomplete")
            for item in container_summaries:
                service = item.get("service")
                if (
                    item.get("container_id")
                    != generation_before[service]["container_id"]
                    or item.get("started_at")
                    != generation_before[service]["started_at"]
                    or item.get("runtime_projection")
                    != generation_before[service]["runtime_projection"]
                ):
                    raise ValueError(
                        f"completion proof live container summary changed generation for {service}"
                    )
                namespace_artifacts = item.get("container_namespace_artifacts")
                expected_artifact_destinations = (
                    {
                        "/run/serverware/release/release-provenance.json",
                        "/run/serverware/release/image-signatures.json",
                    }
                    if service in {"serverware", "decision-gate-rs"}
                    else set()
                )
                if (
                    not isinstance(namespace_artifacts, dict)
                    or set(namespace_artifacts) != expected_artifact_destinations
                    or any(
                        not isinstance(report, dict)
                        or report.get("container_namespace_verified") is not True
                        or report.get("regular_file") is not True
                        or report.get("tar_members") != 1
                        or SHA256_RE.fullmatch(str(report.get("sha256"))) is None
                        or not isinstance(report.get("bytes"), int)
                        or report["bytes"] <= 0
                        for report in namespace_artifacts.values()
                    )
                ):
                    raise ValueError(
                        f"completion proof lacks exact container-namespace artifact evidence for {service}"
                    )
                for destination, artifact_label in (
                    (
                        "/run/serverware/release/release-provenance.json",
                        "release_provenance",
                    ),
                    (
                        "/run/serverware/release/image-signatures.json",
                        "image_signatures",
                    ),
                ):
                    if destination in namespace_artifacts and (
                        namespace_artifacts[destination].get("sha256")
                        != (artifacts.get(artifact_label) or {}).get("sha256")
                    ):
                        raise ValueError(
                            f"completion proof container-visible {artifact_label} differs from the approved snapshot"
                        )
        expected_nonce_digest = sha256_prefixed_base64url(
            expected.proxy_client_nonce,
            "runner proxy client nonce",
        )
        if proxy.get("client_nonce_sha256") != expected_nonce_digest:
            raise ValueError("completion proof proxy nonce does not bind the current runner challenge")
        if expected_proof_contract == OBSERVATION_PROXY_PROOF_CONTRACT:
            expected_channel_digest = "sha256:" + hashlib.sha256(
                expected.proxy_tls_channel_binding.encode("utf-8")
            ).hexdigest()
        else:
            expected_channel_binding = {
                "type": "tls-exporter",
                "value": expected.proxy_tls_channel_binding,
            }
            if expected_proof_contract == STREAMING_PROXY_PROOF_CONTRACT:
                expected_channel_binding["exporter_label"] = (
                    "EXPORTER-Serverware-Proxy-Stream-v1"
                )
            expected_channel_digest = "sha256:" + hashlib.sha256(
                canonical_json(expected_channel_binding).encode("utf-8")
            ).hexdigest()
        if proxy.get("tls_channel_binding_sha256") != expected_channel_digest:
            raise ValueError("completion proof TLS channel binding does not match the current collector result")
        collector_proof_digest = getattr(expected, "collected_proxy_proof_sha256", None)
        proxy_artifact = artifacts.get("proxy_response_proof")
        if collector_proof_digest is None or proxy_artifact.get("sha256") != collector_proof_digest:
            raise ValueError("completion proof does not bind the exact collector proof bytes")
        if expected_proof_contract == STREAMING_PROXY_PROOF_CONTRACT:
            stream_body_artifact = artifacts.get("proxy_stream_body")
            reopened_stream_body = reopened_artifacts.get("proxy_stream_body")
            retained_stream_digest = getattr(
                expected, "collected_proxy_stream_body_sha256", None
            )
            retained_stream_bytes = getattr(
                expected, "collected_proxy_stream_body_bytes", None
            )
            if (
                not isinstance(stream_body_artifact, dict)
                or not isinstance(reopened_stream_body, dict)
                or retained_stream_digest is None
                or stream_body_artifact.get("sha256") != retained_stream_digest
                or reopened_stream_body.get("sha256") != retained_stream_digest
                or reopened_stream_body.get("bytes") != retained_stream_bytes
                or proxy.get("streamed_body_artifact_sha256")
                != retained_stream_digest
                or proxy.get("emitted_body_digest") != retained_stream_digest
                or proxy.get("emitted_body_bytes") != retained_stream_bytes
            ):
                raise ValueError("completion proof does not bind the exact collected streaming body")
        elif expected_proof_contract == OBSERVATION_PROXY_PROOF_CONTRACT:
            observation_body_artifact = artifacts.get("proxy_observation_body")
            reopened_observation_body = reopened_artifacts.get(
                "proxy_observation_body"
            )
            observation_body_binding = proxy.get("observed_body_artifact")
            retained_observation_digest = getattr(
                expected, "collected_proxy_observation_body_sha256", None
            )
            retained_observation_bytes = getattr(
                expected, "collected_proxy_observation_body_bytes", None
            )
            if (
                not isinstance(observation_body_artifact, dict)
                or not isinstance(reopened_observation_body, dict)
                or retained_observation_digest is None
                or observation_body_artifact.get("sha256")
                != retained_observation_digest
                or reopened_observation_body.get("sha256")
                != retained_observation_digest
                or reopened_observation_body.get("bytes")
                != retained_observation_bytes
                or proxy.get("observed_body_artifact_sha256")
                != retained_observation_digest
                or proxy.get("observed_body_artifact_bytes")
                != retained_observation_bytes
                or proxy.get("emitted_body_digest")
                != retained_observation_digest
                or proxy.get("emitted_body_bytes")
                != retained_observation_bytes
                or observation_body_binding
                != {
                    "path": str(Path(expected.proxy_observation_body)),
                    "sha256": retained_observation_digest,
                    "bytes": retained_observation_bytes,
                    "max_bytes": expected.proxy_max_observation_body_bytes,
                }
                or proxy.get("observed_body_artifact_bound") is not True
            ):
                raise ValueError(
                    "completion proof does not bind the exact collected observation body"
                )
        maximum_age = expected.proxy_proof_max_age_seconds
        now = int(time.time())
        for timestamp_field in ("captured_at_unix", "issued_at_unix"):
            timestamp = proxy.get(timestamp_field)
            if not isinstance(timestamp, int) or timestamp > now + COMPLETION_PROOF_FUTURE_SKEW_SECONDS:
                raise ValueError(f"completion proof proxy {timestamp_field} is invalid")
            if now - timestamp > maximum_age or timestamp < expected.runner_started_at_unix - maximum_age:
                raise ValueError(f"completion proof proxy {timestamp_field} is stale")
    if launcher_enforced:
        revalidate_bootstrap_launch_authorization_at_completion(
            expected_receipt=expected.bootstrap_receipt,
            expected_descriptor=expected.bootstrap_receipt_fd,
            generated_at_unix=generated_at_unix,
        )
    return actual_digest


def parse_env_assignment(raw: str, lineno: int) -> tuple[str, str] | None:
    stripped = raw.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].lstrip()
    lexer = shlex.shlex(stripped, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        tokens = list(lexer)
    except ValueError as exc:
        raise ValueError(f"line {lineno}: invalid shell-style quoting: {exc}") from exc
    if len(tokens) != 1 or "=" not in tokens[0]:
        raise ValueError(f"line {lineno}: expected KEY=value assignment")
    key, value = tokens[0].split("=", 1)
    if not KEY_RE.fullmatch(key):
        raise ValueError(f"line {lineno}: invalid environment key {key!r}")
    if value == "":
        raise ValueError(f"line {lineno}: {key} must not be empty")
    return key, value


def load_env_bytes(data: bytes, path: Path) -> dict[str, str]:
    loaded: dict[str, str] = {}
    try:
        text_value = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"production readiness env file is not valid UTF-8: {path}") from exc
    for lineno, raw in enumerate(text_value.splitlines(), start=1):
        parsed = parse_env_assignment(raw, lineno)
        if parsed is None:
            continue
        key, value = parsed
        if key in loaded:
            raise ValueError(f"line {lineno}: duplicate environment key {key}")
        if PLACEHOLDER_RE.search(value):
            raise ValueError(f"line {lineno}: {key} still contains a placeholder value")
        if EXAMPLE_DOMAIN_RE.search(value):
            raise ValueError(f"line {lineno}: {key} still contains an example placeholder domain")
        loaded[key] = value
    if not loaded:
        raise ValueError(f"production readiness env file is empty: {path}")
    return loaded


def load_env_file_snapshot(path: Path) -> tuple[dict[str, str], bytes, os.stat_result]:
    data, metadata = read_regular_file_once(
        path,
        "production readiness env",
        max_bytes=MAX_PRODUCTION_ENV_BYTES,
    )
    return load_env_bytes(data, path), data, metadata


def load_env_file(path: Path) -> dict[str, str]:
    loaded, _, _ = load_env_file_snapshot(path)
    return loaded


def validate_proxy_proof_policy_consistency(
    policy_bundle_path: Path,
    *,
    agent_id: str,
    principal_id: str,
    proof_url: str,
) -> None:
    from serverware.policy_bundle import compile_policy_bundle, strict_json_loads

    try:
        bundle = strict_json_loads(policy_bundle_path.read_bytes())
        if not isinstance(bundle, dict):
            raise ValueError("policy bundle must be a JSON object")
        policy = compile_policy_bundle(
            bundle,
            validate_schema=False,
            verify_signature=False,
        )
    except Exception as exc:
        raise ValueError(
            f"exact --policy-bundle JSON could not be compiled: {exc}"
        ) from exc

    mapped_principals = []
    for principal in policy.principals.values():
        expected_agent_ids = [
            value
            for name, value in principal.required_headers.items()
            if name.lower() == "x-serverware-agent"
        ]
        if expected_agent_ids and all(value == agent_id for value in expected_agent_ids):
            mapped_principals.append(principal.id)
    if mapped_principals != [principal_id]:
        raise ValueError(
            "SERVERWARE_PROXY_PROOF_AGENT_ID and SERVERWARE_PROXY_PROOF_PRINCIPAL_ID "
            "do not map to the same unique principal in the exact --policy-bundle JSON"
        )

    try:
        parsed_url = urlsplit(proof_url)
        proof_host = parsed_url.hostname
        proof_port = parsed_url.port
    except ValueError as exc:
        raise ValueError("SERVERWARE_PROXY_PROOF_URL is invalid") from exc
    if (
        not parsed_url.scheme
        or not proof_host
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.fragment
    ):
        raise ValueError("SERVERWARE_PROXY_PROOF_URL is invalid")
    if proof_port is None:
        proof_port = 443 if parsed_url.scheme.lower() == "https" else 80
    proof_path = parsed_url.path or "/"
    matched = policy.match_route(
        parsed_url.scheme,
        proof_host,
        proof_port,
        "GET",
        proof_path,
        principal_id,
    )
    if matched is None:
        raise ValueError(
            "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID is not authorized for the GET proof URL "
            "scheme, host, port, and path in the exact --policy-bundle JSON"
        )


def generated_client_nonce(proof_contract: str) -> str:
    if proof_contract == OBSERVATION_PROXY_PROOF_CONTRACT:
        expires_at = int(time.time()) + RESPONSE_OBSERVATION_NONCE_LIFETIME_SECONDS
        nonce = expires_at.to_bytes(4, "big") + secrets.token_bytes(28)
    else:
        nonce = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(nonce).rstrip(b"=").decode("ascii")


def collector_command(args: argparse.Namespace) -> dict[str, Any]:
    command = shlex.split(args.proxy_proof_collector_command)
    if not command:
        raise ValueError("proxy proof collector command is empty")
    argv = [
        *command,
        "--proxy",
        args.proxy_address,
        "--url",
        args.proxy_proof_url,
        "--ca",
        args.proxy_proof_ca,
        "--out",
        args.proxy_response_proof,
        "--collector-key",
        args.proxy_collector_key,
        "--verifier-key",
        args.proxy_proof_verifier_public_key,
        "--control-plane-response-key",
        args.control_plane_response_signing_public_key,
        "--expected-server-instance-id",
        args.proxy_server_instance_id,
        "--expected-principal-id",
        args.proxy_principal_id,
        "--max-age-seconds",
        str(args.proxy_proof_max_age_seconds),
        "--nonce",
        args.proxy_client_nonce,
    ]
    if args.proxy_agent_id:
        agent_header = f"X-Serverware-Agent: {args.proxy_agent_id}"
        argv.extend(["--proxy-header", agent_header, "--header", agent_header])
    if args.proxy_proof_contract == STREAMING_PROXY_PROOF_CONTRACT:
        argv.extend(
            [
                "--stream",
                "--body-out",
                args.proxy_stream_body,
                "--max-stream-bytes",
                str(args.proxy_max_stream_bytes),
            ]
        )
    elif args.proxy_proof_contract == OBSERVATION_PROXY_PROOF_CONTRACT:
        argv.extend(
            [
                "--observation",
                "--body-out",
                args.proxy_observation_body,
                "--max-observation-body-bytes",
                str(args.proxy_max_observation_body_bytes),
            ]
        )
    return {"label": "collect-production-proxy-response-proof", "argv": argv}


def completion_command(args: argparse.Namespace) -> dict[str, Any]:
    command = {
        "label": "verify-release-completion",
        "argv": [
            args.python,
            "scripts/verify_release_completion.py",
            "--verification-mode",
            "readiness",
            "--production-readiness",
            str(Path(args.readiness_out)),
            "--production-readiness-config",
            str(Path(args.config_out)),
            "--production-readiness-env",
            args.env_file,
            "--launcher-trusted-production-env-path",
            args.launcher_trusted_production_env_path,
            "--launcher-trusted-production-env-sha256",
            args.launcher_trusted_production_env_sha256,
            "--docker-executable",
            args.docker_executable,
            "--docker-compose-plugin-executable",
            args.docker_compose_plugin_executable,
            "--docker-unix-socket",
            args.docker_unix_socket,
            "--docker-daemon-id",
            args.docker_daemon_id,
            "--compose-file",
            args.compose_file,
            "--production-host-preflight",
            args.production_host_preflight,
            "--production-host-preflight-signing-public-key",
            args.production_host_preflight_signing_public_key,
            "--production-host-preflight-signing-key-id",
            args.production_host_preflight_signing_key_id,
            "--production-host-preflight-max-age-seconds",
            str(args.production_host_preflight_max_age_seconds),
            "--nitro-evidence",
            str(Path(args.nitro_evidence_out)),
            "--production-images-build",
            args.production_images_build,
            "--production-images-env",
            args.production_images_env,
            "--production-images-published",
            args.production_images_published,
            "--release-provenance-summary",
            args.release_provenance_summary,
            "--release-provenance",
            args.release_provenance,
            "--release-provenance-trusted-public-key",
            args.release_provenance_trusted_public_key,
            "--image-signatures-summary",
            args.image_signatures_summary,
            "--image-signatures",
            args.image_signatures,
            "--sigstore-trusted-public-key",
            args.sigstore_trusted_public_key,
            "--rekor-trusted-public-key",
            args.rekor_trusted_public_key,
            "--external-checkpoint-provider",
            args.external_checkpoint_provider,
            "--external-checkpoint-trusted-public-key",
            args.external_checkpoint_trusted_public_key,
            "--bench",
            args.bench,
            "--policy-bundle",
            args.policy_bundle,
            "--policy-trusted-public-key",
            args.policy_trusted_public_key,
            "--policy-trusted-public-key-id",
            args.policy_trusted_public_key_id,
            "--policy-identity-verification",
            args.policy_identity_verification,
            "--policy-activation-verification",
            args.policy_activation_verification,
            "--policy-activation-signature",
            args.policy_activation_signature,
            "--policy-activation-trusted-public-key",
            args.policy_activation_trusted_public_key,
            "--policy-activation-trusted-public-key-id",
            args.policy_activation_trusted_public_key_id,
            "--reproducible-build-verification",
            args.reproducible_build_verification,
            "--reproducible-build-signature",
            args.reproducible_build_signature,
            "--reproducible-build-trusted-public-key",
            args.reproducible_build_trusted_public_key,
            "--reproducible-build-trusted-public-key-id",
            args.reproducible_build_trusted_public_key_id,
            "--kms-materials",
            args.kms_materials,
            "--control-plane-response-signing-public-key",
            args.control_plane_response_signing_public_key,
            "--control-plane-response-signing-public-key-id",
            args.control_plane_response_signing_public_key_id,
            "--proxy-response-proof",
            args.proxy_response_proof,
            "--proxy-proof-contract",
            args.proxy_proof_contract,
            "--proxy-proof-verifier-public-key",
            args.proxy_proof_verifier_public_key,
            "--proxy-collector-public-key",
            args.proxy_collector_public_key,
            "--proxy-server-instance-id",
            args.proxy_server_instance_id,
            "--proxy-client-nonce",
            args.proxy_client_nonce,
            "--proxy-client-request-digest",
            args.proxy_client_request_digest,
            "--proxy-request-digest",
            args.proxy_request_digest,
            "--proxy-operation-digest",
            args.proxy_operation_digest,
            "--proxy-tls-channel-binding",
            args.proxy_tls_channel_binding,
            "--proxy-proof-max-age-seconds",
            str(args.proxy_proof_max_age_seconds),
            "--p99-limit-ms",
            str(args.p99_limit_ms),
            "--out",
            str(Path(args.completion_proof_out)),
        ],
    }
    if args.proxy_proof_contract == STREAMING_PROXY_PROOF_CONTRACT:
        command["argv"].extend(
            [
                "--proxy-stream-body",
                args.proxy_stream_body,
                "--proxy-max-stream-bytes",
                str(args.proxy_max_stream_bytes),
                "--proxy-operation-context-digest",
                args.proxy_operation_context_digest,
            ]
        )
    elif args.proxy_proof_contract == OBSERVATION_PROXY_PROOF_CONTRACT:
        command["argv"].extend(
            [
                "--proxy-observation-body",
                args.proxy_observation_body,
                "--proxy-max-observation-body-bytes",
                str(args.proxy_max_observation_body_bytes),
            ]
        )
    if (
        getattr(args, "launcher_enforced", False)
        and isinstance(getattr(args, "nonce_rollback_assurance", None), dict)
        and args.nonce_rollback_assurance.get("verified") is True
    ):
        command["argv"].extend(
            [
                "--launcher-nonce-rollback-assurance-pins",
                args.launcher_nonce_rollback_assurance_pins,
                "--launcher-nonce-rollback-assurance-pins-sha256",
                args.launcher_nonce_rollback_assurance_pins_sha256,
                "--launcher-nonce-rollback-assurance-contract-sha256",
                args.launcher_nonce_rollback_assurance_contract_sha256,
            ]
        )
    return command


def command_plan(args: argparse.Namespace) -> list[dict[str, Any]]:
    python = args.python
    config_out = str(Path(args.config_out))
    claims_file = str(Path(args.claims_file))
    nitro_evidence_out = str(Path(args.nitro_evidence_out))
    readiness_out = str(Path(args.readiness_out))

    commands: list[dict[str, Any]] = [
        {
            "label": "verify-production-config",
            "argv": [
                python,
                "scripts/verify_production_readiness.py",
                "--mode",
                "config",
                "--expected-control-plane-uid",
                str(args.expected_control_plane_uid),
                "--expected-control-plane-gid",
                str(args.expected_control_plane_gid),
                "--out",
                config_out,
            ],
        }
    ]
    if args.config_only:
        return commands
    if not args.use_existing_claims:
        commands.append(
            {
                "label": "generate-production-readiness-claims",
                "argv": [
                    python,
                    "scripts/generate_production_readiness_claims.py",
                    "--out",
                    claims_file,
                    *args.claims_args,
                ],
            }
        )
    commands.extend(
        [
            {
                "label": "collect-nitro-kms-evidence",
                "argv": [
                    python,
                    "scripts/collect_nitro_kms_evidence.py",
                    "--claims-file",
                    claims_file,
                    "--out",
                    nitro_evidence_out,
                ],
            },
            {
                "label": "verify-production-readiness",
                "argv": [
                    python,
                    "scripts/verify_production_readiness.py",
                    "--mode",
                    "live",
                    "--expected-control-plane-uid",
                    str(args.expected_control_plane_uid),
                    "--expected-control-plane-gid",
                    str(args.expected_control_plane_gid),
                    "--claims-file",
                    claims_file,
                    "--nitro-evidence-file",
                    nitro_evidence_out,
                    "--out",
                    readiness_out,
                ],
            },
            collector_command(args),
            completion_command(args),
        ]
    )
    return commands


def remeasure_command_before_use(
    argv: list[str],
    executable_pins: dict[str, tuple[str, str]] | None,
) -> None:
    if not executable_pins or not argv:
        return
    selected = executable_pins.get(os.path.abspath(argv[0]))
    if selected is None:
        return
    setting, expected_digest = selected
    remeasure_executable(Path(argv[0]), expected_digest, setting)


def run_command_with_optional_pin(
    argv: list[str],
    executable_pins: dict[str, tuple[str, str]] | None,
    *,
    script_digest_pins: dict[str, tuple[str, str]] | None = None,
    isolated_python: bool = False,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    selected = executable_pins.get(os.path.abspath(argv[0])) if executable_pins and argv else None
    if isolated_python and selected is not None and len(argv) >= 2 and argv[1].endswith(".py"):
        script_path = Path(argv[1])
        if not script_path.is_absolute():
            script_path = (Path(kwargs.get("cwd") or os.getcwd()) / script_path).resolve()
        script_pin = (script_digest_pins or {}).get(str(script_path))
        script_setting = script_pin[0] if script_pin else f"one-open Python script {script_path.name}"
        script_digest = script_pin[1] if script_pin else None
        return run_measured_python_script(
            argv,
            python_setting=selected[0],
            python_expected_digest=selected[1],
            script_setting=script_setting,
            script_expected_digest=script_digest,
            **kwargs,
        )
    if selected is None:
        return subprocess.run(argv, **kwargs)
    setting, expected_digest = selected
    return run_measured_command(
        argv,
        setting=setting,
        expected_digest=expected_digest,
        **kwargs,
    )


def run_commands(
    commands: list[dict[str, Any]],
    env: dict[str, str],
    *,
    executable_pins: dict[str, tuple[str, str]] | None = None,
    script_digest_pins: dict[str, tuple[str, str]] | None = None,
    isolated_python: bool = False,
    pass_fds: tuple[int, ...] = (),
) -> None:
    for command in commands:
        label = command["label"]
        argv = command["argv"]
        print(f"==> {label}", file=sys.stderr)
        result = run_command_with_optional_pin(
            argv,
            executable_pins,
            script_digest_pins=script_digest_pins,
            isolated_python=isolated_python,
            cwd=ROOT,
            env=env,
            check=False,
            pass_fds=pass_fds,
        )
        if result.returncode != 0:
            raise SystemExit(result.returncode)


def write_private_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = canonical_json(value).encode("utf-8") + b"\n"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def parse_observation_collector_artifact(
    proof_bytes: bytes,
    summary: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    try:
        document = json.loads(proof_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("production response observation proof is not valid JSON") from exc
    if not isinstance(document, dict) or set(document) != {
        "apiVersion",
        "kind",
        "captured_at_unix",
        "request",
        "response",
        "runtime_proof",
        "collector",
    }:
        raise ValueError(
            "production response observation proof top-level shape is invalid"
        )
    if (
        document.get("apiVersion") != "serverware.responseObservationProof/v1"
        or document.get("kind") != "ServerwareResponseObservationProof"
    ):
        raise ValueError("production response observation proof has the wrong type")
    request = document.get("request")
    response = document.get("response")
    runtime = document.get("runtime_proof")
    statement = runtime.get("server_statement") if isinstance(runtime, dict) else None
    statement_request = statement.get("request") if isinstance(statement, dict) else None
    emitted_response = (
        statement.get("emitted_response") if isinstance(statement, dict) else None
    )
    tls_channel_binding = (
        statement.get("tls_channel_binding") if isinstance(statement, dict) else None
    )
    server_instance = (
        statement.get("server_instance") if isinstance(statement, dict) else None
    )
    if not all(
        isinstance(value, dict)
        for value in (
            request,
            response,
            runtime,
            statement,
            statement_request,
            emitted_response,
            tls_channel_binding,
            server_instance,
        )
    ):
        raise ValueError(
            "production response observation proof runtime statement shape is invalid"
        )
    for field, actual, expected in (
        ("request aggregate", request.get("aggregate_digest"), args.proxy_client_request_digest),
        (
            "signed request aggregate",
            statement_request.get("aggregate_digest"),
            args.proxy_client_request_digest,
        ),
        ("dispatched request", statement.get("request_digest"), args.proxy_request_digest),
        ("operation", statement.get("operation_digest"), args.proxy_operation_digest),
    ):
        if (
            not isinstance(actual, str)
            or SHA256_RE.fullmatch(actual) is None
            or not hmac.compare_digest(actual, expected)
        ):
            raise ValueError(
                f"production response observation proof {field} digest does not match the independent pin"
            )
    if response != emitted_response:
        raise ValueError(
            "production response observation collector response differs from the signed emitted response"
        )
    if summary.get("response_aggregate_digest") != response.get("aggregate_digest"):
        raise ValueError(
            "production response observation collector summary response aggregate differs from the artifact"
        )
    if summary.get("response_status") != response.get("status"):
        raise ValueError(
            "production response observation collector summary status differs from the artifact"
        )
    if server_instance.get("id") != args.proxy_server_instance_id:
        raise ValueError(
            "production response observation statement reached an unexpected server instance"
        )
    if (
        tls_channel_binding.get("type") != "tls-exporter"
        or tls_channel_binding.get("label")
        != "EXPORTER-Serverware-Response-Observation-v1"
    ):
        raise ValueError(
            "production response observation proof TLS exporter contract is invalid"
        )
    tls_exporter = tls_channel_binding.get("value")
    if not isinstance(tls_exporter, str):
        raise ValueError(
            "production response observation proof TLS exporter value is missing"
        )
    sha256_prefixed_base64url(tls_exporter, "response observation TLS exporter")
    nonce = statement.get("client_nonce")
    if nonce != args.proxy_client_nonce:
        raise ValueError(
            "production response observation statement did not bind the runner challenge"
        )
    return {
        "document": document,
        "statement": statement,
        "response": response,
        "tls_exporter": tls_exporter,
        "nonce": nonce,
    }


def run_collector(command: dict[str, Any], args: argparse.Namespace, env: dict[str, str]) -> dict[str, Any]:
    proof_contract = getattr(
        args, "proxy_proof_contract", BUFFERED_PROXY_PROOF_CONTRACT
    )
    if proof_contract not in PROXY_PROOF_CONTRACTS:
        raise ValueError("production proxy proof contract is invalid before collection")
    independent_expected_digests = {
        "client_request_digest": args.proxy_client_request_digest,
        "request_digest": args.proxy_request_digest,
        "operation_digest": args.proxy_operation_digest,
    }
    for field, expected_digest in independent_expected_digests.items():
        if (
            not isinstance(expected_digest, str)
            or SHA256_RE.fullmatch(expected_digest) is None
        ):
            raise ValueError(
                f"independent expected proxy {field} pin must be sha256:<64 lowercase hex> before collection"
            )
    expected_digests = (
        {"request_aggregate_digest": args.proxy_client_request_digest}
        if proof_contract == OBSERVATION_PROXY_PROOF_CONTRACT
        else independent_expected_digests
    )
    print(f"==> {command['label']}", file=sys.stderr)
    result = run_command_with_optional_pin(
        command["argv"],
        getattr(args, "pre_use_executable_pins", None),
        script_digest_pins=getattr(args, "script_digest_pins", None),
        isolated_python=False,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        print(f"production proxy response proof collection failed: {detail}", file=sys.stderr)
        raise SystemExit(result.returncode)
    try:
        summary = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("production proxy response proof collector returned invalid JSON") from exc
    if not isinstance(summary, dict) or summary.get("ok") is not True:
        raise ValueError("production proxy response proof collector did not return ok=true")
    if summary.get("client_nonce") != args.proxy_client_nonce:
        raise ValueError("production proxy response proof collector did not bind the runner challenge")
    for field, expected_digest in expected_digests.items():
        value = summary.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise ValueError(f"production proxy response proof collector returned an invalid {field}")
        if not hmac.compare_digest(value, expected_digest):
            raise ValueError(
                f"production proxy response proof collector {field} does not match the independent expected pin"
            )
    tls_binding = summary.get("tls_channel_binding")
    if proof_contract != OBSERVATION_PROXY_PROOF_CONTRACT and (
        not isinstance(tls_binding, str) or len(tls_binding) < 43
    ):
        raise ValueError(
            "production proxy response proof collector returned an invalid TLS channel binding"
        )
    if summary.get("server_instance_id") != args.proxy_server_instance_id:
        raise ValueError("production proxy response proof collector reached an unexpected server instance")
    expected_proof_path = str(Path(args.proxy_response_proof))
    if summary.get("proof_path") != expected_proof_path:
        raise ValueError("production proxy response proof collector wrote an unexpected proof path")
    proof_path = Path(args.proxy_response_proof)
    proof_bytes, _ = read_regular_file_once(
        proof_path,
        "production proxy response proof",
        max_bytes=MAX_COMPLETION_PROOF_BYTES,
    )
    proof_digest = "sha256:" + hashlib.sha256(proof_bytes).hexdigest()
    if summary.get("proof_sha256") != proof_digest:
        raise ValueError("production proxy response proof collector summary does not bind the proof artifact")
    args.collected_proxy_proof_sha256 = proof_digest
    observation_artifact = None
    if proof_contract == OBSERVATION_PROXY_PROOF_CONTRACT:
        if summary.get("observation_verified") is not True:
            raise ValueError(
                "production response observation collector did not return observation_verified=true"
            )
        observation_artifact = parse_observation_collector_artifact(
            proof_bytes, summary, args
        )
        tls_binding = observation_artifact["tls_exporter"]
    args.collected_proxy_tls_channel_binding = tls_binding
    claimed_contract = summary.get("proof_contract")
    if claimed_contract is not None and claimed_contract != proof_contract:
        raise ValueError("production proxy response proof collector returned a conflicting proof contract")
    args.collected_proxy_proof_contract = proof_contract
    args.collected_proxy_stream_body_sha256 = None
    args.collected_proxy_stream_body_bytes = None
    args.collected_proxy_observation_body_sha256 = None
    args.collected_proxy_observation_body_bytes = None
    if proof_contract in {
        STREAMING_PROXY_PROOF_CONTRACT,
        OBSERVATION_PROXY_PROOF_CONTRACT,
    }:
        is_streaming = proof_contract == STREAMING_PROXY_PROOF_CONTRACT
        if is_streaming and summary.get("stream_verified") is not True:
            raise ValueError(
                "production streaming proxy proof collector did not return stream_verified=true"
            )
        body_path = (
            args.proxy_stream_body if is_streaming else args.proxy_observation_body
        )
        body_limit = (
            args.proxy_max_stream_bytes
            if is_streaming
            else args.proxy_max_observation_body_bytes
        )
        body_label = "streaming" if is_streaming else "response observation"
        expected_body_path = str(Path(body_path))
        if summary.get("body_path") != expected_body_path:
            raise ValueError(
                f"production {body_label} proxy proof collector wrote an unexpected body path"
            )
        body_bytes, _ = read_regular_file_once(
            Path(body_path),
            f"production proxy {body_label} body",
            max_bytes=body_limit,
            allow_empty=True,
        )
        actual_body_bytes = len(body_bytes)
        actual_body_digest = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
        summary_body_bytes = summary.get("body_bytes")
        if type(summary_body_bytes) is not int or summary_body_bytes != actual_body_bytes:
            raise ValueError(
                f"production {body_label} proxy proof collector body byte count does not match the artifact"
            )
        summary_body_digest = summary.get("body_sha256")
        if (
            not isinstance(summary_body_digest, str)
            or SHA256_RE.fullmatch(summary_body_digest) is None
            or not hmac.compare_digest(summary_body_digest, actual_body_digest)
        ):
            raise ValueError(
                f"production {body_label} proxy proof collector body digest does not match the artifact"
            )
        if is_streaming:
            args.collected_proxy_stream_body_sha256 = actual_body_digest
            args.collected_proxy_stream_body_bytes = actual_body_bytes
        else:
            response = observation_artifact["response"]
            if response.get("body_digest") != actual_body_digest:
                raise ValueError(
                    "production response observation artifact body digest does not match the published body"
                )
            if response.get("body_bytes") != actual_body_bytes:
                raise ValueError(
                    "production response observation artifact body byte count does not match the published body"
                )
            args.collected_proxy_observation_body_sha256 = actual_body_digest
            args.collected_proxy_observation_body_bytes = actual_body_bytes
    summary["proof_contract"] = proof_contract
    args.collector_summary = summary
    write_private_json(Path(args.proxy_proof_summary_out), summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Serverware's production readiness gates from a strict env file.")
    parser.add_argument("--env-file", default=os.getenv("PRODUCTION_READINESS_ENV", "ops/production-readiness.env"))
    parser.add_argument("--compose-file", default="docker-compose.production.yml")
    parser.add_argument("--python", default=None)
    parser.add_argument("--docker-executable", default=None)
    parser.add_argument("--docker-compose-plugin-executable", default=None)
    parser.add_argument("--docker-unix-socket", default=None)
    parser.add_argument("--docker-daemon-id", default=None)
    parser.add_argument(
        "--launcher-trusted-production-env-path",
        default=os.getenv(LAUNCHER_TRUSTED_ENV_PATH_INPUT),
    )
    parser.add_argument(
        "--launcher-trusted-production-env-sha256",
        default=os.getenv(LAUNCHER_TRUSTED_ENV_SHA256_INPUT),
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
    parser.add_argument("--expected-control-plane-uid", type=int, default=65532)
    parser.add_argument("--expected-control-plane-gid", type=int, default=65532)
    parser.add_argument("--config-out", default=".tmp/production-readiness-config.json")
    parser.add_argument("--claims-file", default=".tmp/production-readiness-claims.json")
    parser.add_argument("--nitro-evidence-out", default=".tmp/nitro-kms-evidence.json")
    parser.add_argument("--readiness-out", default=".tmp/production-readiness.json")
    parser.add_argument("--completion-proof-out", default=".tmp/serverware-completion-proof.json")
    parser.add_argument("--production-host-preflight", default=".tmp/production-host-preflight.json")
    parser.add_argument("--production-host-preflight-signing-public-key", default=None)
    parser.add_argument("--production-host-preflight-signing-key-id", default=None)
    parser.add_argument("--production-host-preflight-max-age-seconds", type=int, default=None)
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
    parser.add_argument("--verification-mode", choices=("readiness", "final"), default="readiness")
    parser.add_argument("--bench", default=".tmp/decision-gate-rs-bench.json")
    parser.add_argument("--policy-bundle", required=True)
    parser.add_argument("--policy-trusted-public-key", required=True)
    parser.add_argument("--policy-trusted-public-key-id", default=None)
    parser.add_argument("--policy-identity-verification", required=True)
    parser.add_argument("--policy-activation-verification", required=True)
    parser.add_argument("--policy-activation-signature", required=True)
    parser.add_argument("--policy-activation-trusted-public-key", required=True)
    parser.add_argument("--policy-activation-trusted-public-key-id", default=None)
    parser.add_argument("--reproducible-build-verification", required=True)
    parser.add_argument("--reproducible-build-signature", required=True)
    parser.add_argument("--reproducible-build-trusted-public-key", required=True)
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
    parser.add_argument("--proxy-proof-summary-out", default=".tmp/proxy-response-proof-summary.json")
    parser.add_argument("--proxy-proof-collector-command", default=None)
    parser.add_argument("--proxy-address", default=None)
    parser.add_argument("--proxy-proof-url", default=None)
    parser.add_argument("--proxy-proof-ca", default=None)
    parser.add_argument("--proxy-collector-key", default=None)
    parser.add_argument("--proxy-collector-public-key", default=None)
    parser.add_argument("--proxy-proof-verifier-public-key", default=None)
    parser.add_argument("--proxy-server-instance-id", default=None)
    parser.add_argument("--proxy-agent-id", default=None)
    parser.add_argument("--proxy-principal-id", default=None)
    parser.add_argument("--proxy-client-request-digest", default=None)
    parser.add_argument("--proxy-request-digest", default=None)
    parser.add_argument("--proxy-operation-digest", default=None)
    parser.add_argument("--proxy-operation-context-digest", default=None)
    parser.add_argument("--proxy-proof-max-age-seconds", type=int, default=None)
    parser.add_argument("--p99-limit-ms", type=float, default=None)
    parser.add_argument("--control-plane-base", default=None)
    parser.add_argument("--control-plane-ca-bundle", default=None)
    parser.add_argument("--config-only", action="store_true")
    parser.add_argument("--use-existing-claims", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="load and validate the env file, then print the command plan")
    parser.add_argument(
        "--claims-arg",
        dest="claims_args",
        action="append",
        default=[],
        help="extra argument to pass through to generate_production_readiness_claims.py; repeat as needed",
    )
    args = parser.parse_args()
    if args.verification_mode == "final":
        parser.error(
            "this runner is trusted-host readiness only; final verification requires "
            "scripts/verify_release_completion.py --verification-mode final with the "
            "complete public Nitro/Manifest-v6 evidence and protected-state arguments"
        )
    args.runner_started_at_unix = int(time.time())

    env_file = Path(args.env_file)
    try:
        production_env_bytes, production_env_metadata = read_regular_file_once(
            env_file,
            "production readiness env",
            max_bytes=MAX_PRODUCTION_ENV_BYTES,
        )
        launcher_trust_inputs = (
            args.launcher_trusted_production_env_path,
            args.launcher_trusted_production_env_sha256,
        )
        if any(value is not None for value in launcher_trust_inputs):
            if not all(value is not None for value in launcher_trust_inputs):
                raise ValueError(
                    "launcher-enforced readiness requires both the trusted "
                    "production env path and digest"
                )
            args.launcher_env_binding = validate_launcher_trusted_env(
                env_file,
                production_env_bytes,
                production_env_metadata,
                expected_path=args.launcher_trusted_production_env_path,
                expected_sha256=args.launcher_trusted_production_env_sha256,
            )
        else:
            args.launcher_env_binding = None
            args.launcher_trusted_production_env_path = str(env_file)
            args.launcher_trusted_production_env_sha256 = (
                "sha256:" + hashlib.sha256(production_env_bytes).hexdigest()
            )
        args.launcher_enforced = args.launcher_env_binding is not None
        loaded = load_env_bytes(production_env_bytes, env_file)
        if LAUNCHER_TRUST_INPUT_NAMES & set(loaded):
            raise ValueError("out-of-band launcher trust inputs must not be defined inside the production env")
    except Exception as exc:
        print(f"production readiness env error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    env_verification_mode = loaded.get("SERVERWARE_COMPLETION_VERIFICATION_MODE")
    if env_verification_mode and env_verification_mode != "readiness":
        print(
            "production readiness env error: SERVERWARE_COMPLETION_VERIFICATION_MODE "
            "must be readiness; final verification belongs to the independent "
            "Manifest-v6 public Nitro verifier",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if env_verification_mode and env_verification_mode != args.verification_mode:
        print(
            "production readiness env error: --verification-mode must match "
            "SERVERWARE_COMPLETION_VERIFICATION_MODE in the production readiness env file",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.launcher_enforced:
        try:
            args.launcher_env_binding["startup_environment_contract"] = (
                validate_final_launcher_contract(loaded)
            )
            if args.dry_run:
                args.bootstrap_receipt = None
                args.bootstrap_receipt_fd = None
            else:
                (
                    args.bootstrap_receipt,
                    args.bootstrap_receipt_fd,
                ) = load_sealed_bootstrap_receipt(required=True)
                args.launcher_env_binding["bootstrap_receipt"] = args.bootstrap_receipt
            args.nonce_rollback_assurance = (
                validate_retained_nonce_rollback_assurance(
                    retained_path=(
                        args.launcher_nonce_rollback_assurance_pins
                    ),
                    expected_pins_sha256=(
                        args.launcher_nonce_rollback_assurance_pins_sha256
                    ),
                    expected_contract_sha256=(
                        args.launcher_nonce_rollback_assurance_contract_sha256
                    ),
                    bootstrap_receipt=args.bootstrap_receipt,
                    required=not args.dry_run,
                )
            )
            args.launcher_env_binding["nonce_rollback_assurance"] = (
                args.nonce_rollback_assurance
            )
        except ValueError as exc:
            print(f"production readiness env error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        if (
            args.expected_control_plane_uid != FINAL_CONTROL_PLANE_UID
            or args.expected_control_plane_gid != FINAL_CONTROL_PLANE_GID
        ):
            print(
                "production readiness env error: launcher-enforced control-plane UID/GID are fixed at "
                f"{FINAL_CONTROL_PLANE_UID}:{FINAL_CONTROL_PLANE_GID}",
                file=sys.stderr,
            )
            raise SystemExit(1)
    else:
        try:
            args.nonce_rollback_assurance = (
                validate_retained_nonce_rollback_assurance(
                    retained_path=(
                        args.launcher_nonce_rollback_assurance_pins
                    ),
                    expected_pins_sha256=(
                        args.launcher_nonce_rollback_assurance_pins_sha256
                    ),
                    expected_contract_sha256=(
                        args.launcher_nonce_rollback_assurance_contract_sha256
                    ),
                    bootstrap_receipt=None,
                    required=False,
                )
            )
        except ValueError as exc:
            print(f"production readiness env error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc

    supplied_python = args.python
    env_python = loaded.get(PRODUCTION_PYTHON_EXECUTABLE_ENV)
    if args.launcher_enforced:
        if not env_python:
            print(
                f"production readiness env error: {PRODUCTION_PYTHON_EXECUTABLE_ENV} must be pinned for launcher-enforced readiness",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if supplied_python is not None and supplied_python != env_python:
            print(
                f"production readiness env error: --python must match {PRODUCTION_PYTHON_EXECUTABLE_ENV} "
                "for launcher-enforced readiness",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.python = env_python
    else:
        args.python = supplied_python or env_python or sys.executable
    if not Path(args.python).is_absolute():
        print("production readiness env error: production Python executable must be absolute", file=sys.stderr)
        raise SystemExit(1)

    supplied_docker = args.docker_executable
    env_docker = loaded.get(PRODUCTION_DOCKER_EXECUTABLE_ENV)
    if args.launcher_enforced:
        if not env_docker:
            print(
                f"production readiness env error: {PRODUCTION_DOCKER_EXECUTABLE_ENV} must be pinned for launcher-enforced readiness",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if supplied_docker is not None and supplied_docker != env_docker:
            print(
                f"production readiness env error: --docker-executable must match {PRODUCTION_DOCKER_EXECUTABLE_ENV} "
                "for launcher-enforced readiness",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.docker_executable = env_docker
    else:
        args.docker_executable = supplied_docker or env_docker or "/usr/bin/docker"
    if not Path(args.docker_executable).is_absolute():
        print("production readiness env error: Docker executable must be absolute", file=sys.stderr)
        raise SystemExit(1)

    if args.launcher_enforced:
        try:
            docker_toolchain = validate_docker_toolchain_settings(loaded)
        except ValueError as exc:
            print(f"production readiness env error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        for attribute, setting in (
            ("docker_compose_plugin_executable", DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV),
            ("docker_unix_socket", DOCKER_UNIX_SOCKET_ENV),
            ("docker_daemon_id", DOCKER_DAEMON_ID_ENV),
        ):
            supplied = getattr(args, attribute)
            expected_value = docker_toolchain[setting]
            if supplied is not None and supplied != expected_value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {setting} "
                    "for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            setattr(args, attribute, expected_value)
        args.docker_compose_plugin_sha256 = docker_toolchain[
            DOCKER_COMPOSE_PLUGIN_SHA256_ENV
        ]
        args.docker_compose_project_name = docker_toolchain[
            DOCKER_COMPOSE_PROJECT_NAME_ENV
        ]
        if args.docker_unix_socket != "/run/docker.sock":
            print(
                f"production readiness env error: {DOCKER_UNIX_SOCKET_ENV} must be exactly /run/docker.sock for launcher-enforced readiness",
                file=sys.stderr,
            )
            raise SystemExit(1)
    else:
        args.docker_compose_plugin_executable = (
            args.docker_compose_plugin_executable
            or loaded.get(DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV)
            or "/usr/libexec/docker/cli-plugins/docker-compose"
        )
        args.docker_unix_socket = (
            args.docker_unix_socket
            or loaded.get(DOCKER_UNIX_SOCKET_ENV)
            or "/var/run/docker.sock"
        )
        args.docker_daemon_id = args.docker_daemon_id or loaded.get(DOCKER_DAEMON_ID_ENV) or "readiness-unbound"
        args.docker_compose_plugin_sha256 = loaded.get(DOCKER_COMPOSE_PLUGIN_SHA256_ENV)
        args.docker_compose_project_name = loaded.get(
            DOCKER_COMPOSE_PROJECT_NAME_ENV, "readiness-unbound"
        )

    env_p99_limit = loaded.get(COMPLETION_P99_LIMIT_ENV)
    if args.launcher_enforced and env_p99_limit is None:
        print(
            f"production readiness env error: {COMPLETION_P99_LIMIT_ENV} must be pinned for launcher-enforced readiness",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        parsed_env_p99_limit = float(env_p99_limit or "20.0")
    except ValueError as exc:
        print(f"production readiness env error: {COMPLETION_P99_LIMIT_ENV} must be numeric", file=sys.stderr)
        raise SystemExit(1) from exc
    if (
        args.launcher_enforced
        and args.p99_limit_ms is not None
        and args.p99_limit_ms != parsed_env_p99_limit
    ):
        print(
            f"production readiness env error: --p99-limit-ms must match {COMPLETION_P99_LIMIT_ENV} for launcher-enforced readiness",
            file=sys.stderr,
        )
        raise SystemExit(1)
    args.p99_limit_ms = (
        parsed_env_p99_limit
        if args.launcher_enforced or args.p99_limit_ms is None
        else args.p99_limit_ms
    )
    if not math.isfinite(args.p99_limit_ms) or args.p99_limit_ms <= 0:
        print("production readiness env error: completion p99 limit must be finite and positive", file=sys.stderr)
        raise SystemExit(1)

    if args.launcher_enforced:
        for attribute, setting in (
            (
                "production_host_preflight_signing_public_key",
                PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV,
            ),
            (
                "production_host_preflight_signing_key_id",
                PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV,
            ),
        ):
            supplied = getattr(args, attribute)
            pinned = loaded.get(setting)
            if not pinned:
                print(
                    f"production readiness env error: {setting} must be pinned for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if supplied is not None and supplied != pinned:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {setting} "
                    "for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            setattr(args, attribute, pinned)
        if SHA256_RE.fullmatch(args.production_host_preflight_signing_key_id) is None:
            print("production readiness env error: preflight signing key ID must be sha256:<64 lowercase hex>", file=sys.stderr)
            raise SystemExit(1)
        raw_preflight_age = loaded.get(PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV)
        try:
            pinned_preflight_age = int(raw_preflight_age or "")
        except ValueError as exc:
            print(
                f"production readiness env error: {PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV} must be an integer",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
        if not 1 <= pinned_preflight_age <= 900:
            print(
                f"production readiness env error: {PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV} must be between 1 and 900",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if (
            args.production_host_preflight_max_age_seconds is not None
            and args.production_host_preflight_max_age_seconds != pinned_preflight_age
        ):
            print(
                "production readiness env error: --production-host-preflight-max-age-seconds must match "
                f"{PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV} for launcher-enforced readiness",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.production_host_preflight_max_age_seconds = pinned_preflight_age
    else:
        args.production_host_preflight_signing_public_key = (
            args.production_host_preflight_signing_public_key
            or loaded.get(PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV)
            or loaded.get("SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY")
            or "readiness-unbound"
        )
        args.production_host_preflight_signing_key_id = (
            args.production_host_preflight_signing_key_id
            or loaded.get(PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV)
            or "sha256:" + "0" * 64
        )
        args.production_host_preflight_max_age_seconds = (
            args.production_host_preflight_max_age_seconds or 300
        )

    if args.launcher_enforced:
        try:
            env = build_final_child_environment(
                loaded,
                additions=bootstrap_receipt_environment() if not args.dry_run else None,
            )
        except ValueError as exc:
            print(f"production readiness env error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
    else:
        env = os.environ.copy()
        env.update(loaded)
    trust_settings = {
        "release_provenance_trusted_public_key": "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY",
        "sigstore_trusted_public_key": "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY",
        "rekor_trusted_public_key": "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY",
        "external_checkpoint_provider": "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER",
        "external_checkpoint_trusted_public_key": "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY",
        "control_plane_response_signing_public_key": (
            "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY"
        ),
        "control_plane_response_signing_public_key_id": (
            "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID"
        ),
        "policy_trusted_public_key": POLICY_TRUST_ROOT_ENV,
        "policy_activation_trusted_public_key": POLICY_ACTIVATION_TRUST_ROOT_ENV,
        "reproducible_build_trusted_public_key": REPRODUCIBLE_BUILD_TRUST_ROOT_ENV,
    }
    missing_trust = []
    for attribute, env_name in trust_settings.items():
        argument_value = getattr(args, attribute)
        env_value = loaded.get(env_name)
        if args.launcher_enforced:
            if argument_value and env_value and argument_value != env_value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                    "for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            value = env_value
        else:
            value = argument_value or env_value
        if not value:
            if args.launcher_enforced:
                missing_trust.append(f"{env_name} (must be pinned in the production readiness env file)")
            else:
                missing_trust.append(f"--{attribute.replace('_', '-')} or {env_name}")
            continue
        if PLACEHOLDER_RE.search(value) or EXAMPLE_DOMAIN_RE.search(value):
            print(f"production readiness env error: {env_name} contains a placeholder value", file=sys.stderr)
            raise SystemExit(1)
        setattr(args, attribute, value)
        env[env_name] = value
    if missing_trust:
        print(
            "production readiness env error: missing release completion trust settings: "
            + ", ".join(missing_trust),
            file=sys.stderr,
        )
        raise SystemExit(1)
    if args.launcher_enforced:
        for attribute, env_name in (
            ("policy_trusted_public_key_id", POLICY_TRUST_ROOT_ID_ENV),
            (
                "policy_activation_trusted_public_key_id",
                POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
            ),
            (
                "reproducible_build_trusted_public_key_id",
                REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
            ),
        ):
            selected = getattr(args, attribute)
            pinned = loaded.get(env_name)
            if selected is not None and selected != pinned:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match "
                    f"{env_name} for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if not isinstance(pinned, str) or SHA256_RE.fullmatch(pinned) is None:
                print(
                    f"production readiness env error: {env_name} must be sha256:<64 lowercase hex>",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            setattr(args, attribute, pinned)
            env[env_name] = pinned
    else:
        for attribute, env_name in (
            ("policy_trusted_public_key_id", POLICY_TRUST_ROOT_ID_ENV),
            (
                "policy_activation_trusted_public_key_id",
                POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
            ),
            (
                "reproducible_build_trusted_public_key_id",
                REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
            ),
        ):
            value = getattr(args, attribute) or loaded.get(env_name) or "sha256:" + "0" * 64
            setattr(args, attribute, value)
    if (
        SHA256_RE.fullmatch(
            args.control_plane_response_signing_public_key_id
        )
        is None
    ):
        print(
            "production readiness env error: control-plane response signing public key ID "
            "must be sha256:<64 lowercase hex>",
            file=sys.stderr,
        )
        raise SystemExit(1)
    legacy_final_env_names = (
        "SERVERWARE_FINAL_CHALLENGE_RECEIPT",
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY",
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID",
        "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER",
        "SERVERWARE_HARDWARE_ASSURANCE",
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID",
        "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE",
        "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256",
    )
    for env_name in legacy_final_env_names:
        env.pop(env_name, None)
    if any(loaded.get(env_name) for env_name in legacy_final_env_names):
        print(
            "production readiness env error: final hardware and challenge-authority "
            "inputs are not accepted by the readiness runner; use "
            "scripts/verify_release_completion.py --verification-mode final",
            file=sys.stderr,
        )
        raise SystemExit(1)
    env["SERVERWARE_COMPLETION_VERIFICATION_MODE"] = "readiness"
    if not args.config_only:
        missing = []
        env_proof_contract = loaded.get(PROXY_PROOF_CONTRACT_ENV)
        if not env_proof_contract:
            print(
                f"production readiness env error: {PROXY_PROOF_CONTRACT_ENV} must be pinned in the "
                "production readiness env file",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if (
            args.proxy_proof_contract is not None
            and args.proxy_proof_contract != env_proof_contract
        ):
            print(
                f"production readiness env error: --proxy-proof-contract must match {PROXY_PROOF_CONTRACT_ENV} "
                "in the production readiness env file",
                file=sys.stderr,
            )
            raise SystemExit(1)
        proof_contract = env_proof_contract
        if proof_contract not in PROXY_PROOF_CONTRACTS:
            print(
                f"production readiness env error: {PROXY_PROOF_CONTRACT_ENV} must be buffered-v3, "
                "observation-v1, or streaming-v1",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.proxy_proof_contract = proof_contract

        if proof_contract == STREAMING_PROXY_PROOF_CONTRACT:
            if any(
                value is not None
                for value in (
                    args.proxy_observation_body,
                    args.proxy_max_observation_body_bytes,
                    loaded.get(PROXY_OBSERVATION_BODY_FILE_ENV),
                    loaded.get(PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV),
                )
            ):
                print(
                    "production readiness env error: observation body settings are only valid with "
                    "proxy proof contract observation-v1",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            env_operation_context_digest = loaded.get(
                PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST_ENV
            )
            if (
                args.launcher_enforced
                and args.proxy_operation_context_digest is not None
                and args.proxy_operation_context_digest
                != env_operation_context_digest
            ):
                print(
                    "production readiness env error: --proxy-operation-context-digest must match "
                    f"{PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST_ENV} for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            operation_context_digest = (
                env_operation_context_digest
                if args.launcher_enforced
                else args.proxy_operation_context_digest
                or env_operation_context_digest
            )
            if not operation_context_digest:
                missing.append(
                    f"{PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST_ENV} "
                    "(must be pinned in the production readiness env file)"
                    if args.launcher_enforced
                    else "--proxy-operation-context-digest or "
                    f"{PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST_ENV}"
                )
            elif SHA256_RE.fullmatch(operation_context_digest) is None:
                print(
                    "production readiness env error: expected proxy operation context digest must be "
                    "sha256:<64 lowercase hex>",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            else:
                args.proxy_operation_context_digest = operation_context_digest

            env_stream_body = loaded.get(PROXY_STREAM_BODY_FILE_ENV)
            if (
                args.launcher_enforced
                and args.proxy_stream_body is not None
                and args.proxy_stream_body != env_stream_body
            ):
                print(
                    f"production readiness env error: --proxy-stream-body must match {PROXY_STREAM_BODY_FILE_ENV} "
                    "for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            stream_body = (
                env_stream_body
                if args.launcher_enforced
                else args.proxy_stream_body or env_stream_body
            )
            if not stream_body:
                missing.append(
                    f"{PROXY_STREAM_BODY_FILE_ENV} (must be pinned in the production readiness env file)"
                    if args.launcher_enforced
                    else f"--proxy-stream-body or {PROXY_STREAM_BODY_FILE_ENV}"
                )
            elif not Path(stream_body).is_absolute():
                print(
                    f"production readiness env error: {PROXY_STREAM_BODY_FILE_ENV} must be an absolute path",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            else:
                args.proxy_stream_body = stream_body

            env_max_stream_bytes = loaded.get(PROXY_PROOF_MAX_STREAM_BYTES_ENV)
            parsed_env_max_stream_bytes = None
            if env_max_stream_bytes is not None:
                try:
                    parsed_env_max_stream_bytes = int(env_max_stream_bytes)
                except ValueError as exc:
                    print(
                        f"production readiness env error: {PROXY_PROOF_MAX_STREAM_BYTES_ENV} must be an integer",
                        file=sys.stderr,
                    )
                    raise SystemExit(1) from exc
            if (
                args.launcher_enforced
                and args.proxy_max_stream_bytes is not None
                and args.proxy_max_stream_bytes != parsed_env_max_stream_bytes
            ):
                print(
                    f"production readiness env error: --proxy-max-stream-bytes must match "
                    f"{PROXY_PROOF_MAX_STREAM_BYTES_ENV} for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            max_stream_bytes = (
                parsed_env_max_stream_bytes
                if args.launcher_enforced
                else args.proxy_max_stream_bytes
                if args.proxy_max_stream_bytes is not None
                else parsed_env_max_stream_bytes
            )
            if max_stream_bytes is None:
                missing.append(
                    f"{PROXY_PROOF_MAX_STREAM_BYTES_ENV} (must be pinned in the production readiness env file)"
                    if args.launcher_enforced
                    else f"--proxy-max-stream-bytes or {PROXY_PROOF_MAX_STREAM_BYTES_ENV}"
                )
            elif not 1 <= max_stream_bytes <= MAX_PROXY_STREAM_BODY_BYTES:
                print(
                    "production readiness env error: proxy proof max stream bytes must be between 1 and "
                    f"{MAX_PROXY_STREAM_BODY_BYTES}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            else:
                args.proxy_max_stream_bytes = max_stream_bytes
        elif proof_contract == OBSERVATION_PROXY_PROOF_CONTRACT:
            if any(
                value is not None
                for value in (
                    args.proxy_stream_body,
                    args.proxy_max_stream_bytes,
                    args.proxy_operation_context_digest,
                    loaded.get(PROXY_STREAM_BODY_FILE_ENV),
                    loaded.get(PROXY_PROOF_MAX_STREAM_BYTES_ENV),
                    loaded.get(PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST_ENV),
                )
            ):
                print(
                    "production readiness env error: stream body, max stream bytes, and operation context "
                    "digest settings are only valid with proxy proof contract streaming-v1",
                    file=sys.stderr,
                )
                raise SystemExit(1)

            env_observation_body = loaded.get(PROXY_OBSERVATION_BODY_FILE_ENV)
            if (
                args.launcher_enforced
                and args.proxy_observation_body is not None
                and args.proxy_observation_body != env_observation_body
            ):
                print(
                    "production readiness env error: --proxy-observation-body must match "
                    f"{PROXY_OBSERVATION_BODY_FILE_ENV} for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            observation_body = (
                env_observation_body
                if args.launcher_enforced
                else args.proxy_observation_body or env_observation_body
            )
            if not observation_body:
                missing.append(
                    f"{PROXY_OBSERVATION_BODY_FILE_ENV} (must be pinned in the production readiness env file)"
                    if args.launcher_enforced
                    else f"--proxy-observation-body or {PROXY_OBSERVATION_BODY_FILE_ENV}"
                )
            elif not Path(observation_body).is_absolute():
                print(
                    f"production readiness env error: {PROXY_OBSERVATION_BODY_FILE_ENV} must be an absolute path",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            else:
                args.proxy_observation_body = observation_body

            env_max_observation_bytes = loaded.get(
                PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV
            )
            parsed_env_max_observation_bytes = None
            if env_max_observation_bytes is not None:
                try:
                    parsed_env_max_observation_bytes = int(env_max_observation_bytes)
                except ValueError as exc:
                    print(
                        "production readiness env error: "
                        f"{PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV} must be an integer",
                        file=sys.stderr,
                    )
                    raise SystemExit(1) from exc
            if (
                args.launcher_enforced
                and args.proxy_max_observation_body_bytes is not None
                and args.proxy_max_observation_body_bytes
                != parsed_env_max_observation_bytes
            ):
                print(
                    "production readiness env error: --proxy-max-observation-body-bytes must match "
                    f"{PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV} for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            max_observation_bytes = (
                parsed_env_max_observation_bytes
                if args.launcher_enforced
                else args.proxy_max_observation_body_bytes
                if args.proxy_max_observation_body_bytes is not None
                else parsed_env_max_observation_bytes
            )
            if max_observation_bytes is None:
                missing.append(
                    f"{PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV} "
                    "(must be pinned in the production readiness env file)"
                    if args.launcher_enforced
                    else "--proxy-max-observation-body-bytes or "
                    f"{PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV}"
                )
            elif not 1 <= max_observation_bytes <= MAX_PROXY_OBSERVATION_BODY_BYTES:
                print(
                    "production readiness env error: proxy proof max observation body bytes must be between 1 and "
                    f"{MAX_PROXY_OBSERVATION_BODY_BYTES}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            else:
                args.proxy_max_observation_body_bytes = max_observation_bytes
        elif any(
            value is not None
            for value in (
                args.proxy_stream_body,
                args.proxy_max_stream_bytes,
                args.proxy_operation_context_digest,
                args.proxy_observation_body,
                args.proxy_max_observation_body_bytes,
                loaded.get(PROXY_STREAM_BODY_FILE_ENV),
                loaded.get(PROXY_PROOF_MAX_STREAM_BYTES_ENV),
                loaded.get(PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST_ENV),
                loaded.get(PROXY_OBSERVATION_BODY_FILE_ENV),
                loaded.get(PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES_ENV),
            )
        ):
            print(
                "production readiness env error: stream and observation body settings are only valid with "
                "their matching proxy proof contracts",
                file=sys.stderr,
            )
            raise SystemExit(1)

        proof_settings = {
            "proxy_response_proof": "SERVERWARE_PROXY_RESPONSE_PROOF_FILE",
            "proxy_proof_collector_command": "SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND",
            "proxy_address": "SERVERWARE_PROXY_PROOF_ADDRESS",
            "proxy_proof_url": "SERVERWARE_PROXY_PROOF_URL",
            "proxy_proof_ca": "SERVERWARE_PROXY_PROOF_CA_BUNDLE",
            "proxy_collector_key": "SERVERWARE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY",
            "proxy_collector_public_key": "SERVERWARE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY",
            "proxy_proof_verifier_public_key": "SERVERWARE_PROXY_PROOF_VERIFIER_PUBLIC_KEY",
        }
        for attribute, env_name in proof_settings.items():
            argument_value = getattr(args, attribute)
            env_value = loaded.get(env_name)
            if args.launcher_enforced and argument_value is not None and argument_value != env_value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                    "for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            value = env_value if args.launcher_enforced else argument_value or env_value
            if not value:
                missing.append(
                    f"{env_name} (must be pinned in the production readiness env file)"
                    if args.launcher_enforced
                    else f"--{attribute.replace('_', '-')} or {env_name}"
                )
            else:
                setattr(args, attribute, value)
        if proof_contract in {
            STREAMING_PROXY_PROOF_CONTRACT,
            OBSERVATION_PROXY_PROOF_CONTRACT,
        }:
            body_label = (
                "streaming body output"
                if proof_contract == STREAMING_PROXY_PROOF_CONTRACT
                else "observation body output"
            )
            body_path = (
                args.proxy_stream_body
                if proof_contract == STREAMING_PROXY_PROOF_CONTRACT
                else args.proxy_observation_body
            )
            proxy_outputs = {
                "proxy proof output": args.proxy_response_proof,
                body_label: body_path,
            }
            proxy_inputs = {
                "proxy CA bundle": args.proxy_proof_ca,
                "proxy collector private key": args.proxy_collector_key,
                "proxy collector public key": args.proxy_collector_public_key,
                "proxy verifier public key": args.proxy_proof_verifier_public_key,
            }
            if all((*proxy_outputs.values(), *proxy_inputs.values())):
                try:
                    validate_proxy_artifact_path_separation(
                        proxy_outputs,
                        proxy_inputs,
                    )
                except ValueError as exc:
                    print(f"production readiness env error: {exc}", file=sys.stderr)
                    raise SystemExit(1) from exc
        explicit_server_instance = loaded.get("SERVERWARE_PROXY_SERVER_INSTANCE_ID")
        data_plane_instance = loaded.get("SERVERWARE_DATA_PLANE_INSTANCE_ID")
        if explicit_server_instance and data_plane_instance and explicit_server_instance != data_plane_instance:
            print(
                "production readiness env error: SERVERWARE_PROXY_SERVER_INSTANCE_ID and "
                "SERVERWARE_DATA_PLANE_INSTANCE_ID must match",
                file=sys.stderr,
            )
            raise SystemExit(1)
        env_server_instance = explicit_server_instance or data_plane_instance
        if (
            args.launcher_enforced
            and args.proxy_server_instance_id is not None
            and args.proxy_server_instance_id != env_server_instance
        ):
            print(
                "production readiness env error: --proxy-server-instance-id must match the production env "
                "server instance for launcher-enforced readiness",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.proxy_server_instance_id = (
            env_server_instance
            if args.launcher_enforced
            else args.proxy_server_instance_id or env_server_instance
        )
        if not args.proxy_server_instance_id:
            missing.append(
                "SERVERWARE_PROXY_SERVER_INSTANCE_ID or SERVERWARE_DATA_PLANE_INSTANCE_ID"
                if args.launcher_enforced
                else "--proxy-server-instance-id or SERVERWARE_PROXY_SERVER_INSTANCE_ID or "
                "SERVERWARE_DATA_PLANE_INSTANCE_ID"
            )
        for attribute, env_name in (
            ("proxy_agent_id", "SERVERWARE_PROXY_PROOF_AGENT_ID"),
            ("proxy_principal_id", "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID"),
        ):
            argument_value = getattr(args, attribute)
            env_value = loaded.get(env_name)
            if args.launcher_enforced and argument_value is not None and argument_value != env_value:
                print(
                    f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                    "for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            setattr(
                args,
                attribute,
                env_value if args.launcher_enforced else argument_value or env_value,
            )
        if not args.proxy_agent_id:
            missing.append(
                "SERVERWARE_PROXY_PROOF_AGENT_ID (must be pinned in the production readiness env file)"
                if args.launcher_enforced
                else "--proxy-agent-id or SERVERWARE_PROXY_PROOF_AGENT_ID"
            )
        if not args.proxy_principal_id:
            missing.append(
                "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID (must be pinned in the production readiness env file)"
                if args.launcher_enforced
                else "--proxy-principal-id or SERVERWARE_PROXY_PROOF_PRINCIPAL_ID"
            )
        for attribute, env_name in PROXY_DIGEST_ENV_SETTINGS.items():
            argument_value = getattr(args, attribute)
            env_value = loaded.get(env_name)
            if args.launcher_enforced:
                if argument_value and env_value and argument_value != env_value:
                    print(
                        f"production readiness env error: --{attribute.replace('_', '-')} must match {env_name} "
                        "for launcher-enforced readiness",
                        file=sys.stderr,
                    )
                    raise SystemExit(1)
                value = env_value
                if not value:
                    missing.append(f"{env_name} (must be pinned in the production readiness env file)")
                    continue
            else:
                value = argument_value or env_value
                if not value:
                    missing.append(f"--{attribute.replace('_', '-')} or {env_name}")
                    continue
            if SHA256_RE.fullmatch(value) is None:
                print(
                    f"production readiness env error: expected proxy digest {env_name} must be "
                    "sha256:<64 lowercase hex>",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            setattr(args, attribute, value)
        env_max_age = loaded.get("SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS")
        if args.launcher_enforced and env_max_age is None:
            missing.append(
                "SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS (must be pinned in the production readiness env file)"
            )
            max_age = None
        else:
            raw_max_age = env_max_age or "300"
            try:
                parsed_env_max_age = int(raw_max_age)
            except ValueError as exc:
                print(
                    "production readiness env error: SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS must be an integer",
                    file=sys.stderr,
                )
                raise SystemExit(1) from exc
            if (
                args.launcher_enforced
                and args.proxy_proof_max_age_seconds is not None
                and args.proxy_proof_max_age_seconds != parsed_env_max_age
            ):
                print(
                    "production readiness env error: --proxy-proof-max-age-seconds must match "
                    "SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            max_age = (
                parsed_env_max_age
                if args.launcher_enforced or args.proxy_proof_max_age_seconds is None
                else args.proxy_proof_max_age_seconds
            )
        if max_age is not None and not 1 <= max_age <= 900:
            print(
                "production readiness env error: proxy proof max age must be between 1 and 900 seconds",
                file=sys.stderr,
            )
            raise SystemExit(1)
        args.proxy_proof_max_age_seconds = max_age
        if missing:
            print(
                "production readiness env error: missing production proxy proof settings: "
                + ", ".join(missing),
                file=sys.stderr,
            )
            raise SystemExit(1)
        if args.launcher_enforced:
            try:
                collector_words = shlex.split(args.proxy_proof_collector_command)
            except ValueError as exc:
                print(f"production readiness env error: invalid proof collector command: {exc}", file=sys.stderr)
                raise SystemExit(1) from exc
            if len(collector_words) != 1 or not Path(collector_words[0]).is_absolute():
                print(
                    "production readiness env error: SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND must be one "
                    "absolute executable for launcher-enforced readiness",
                    file=sys.stderr,
                )
                raise SystemExit(1)
        try:
            validate_proxy_proof_policy_consistency(
                Path(args.policy_bundle),
                agent_id=args.proxy_agent_id,
                principal_id=args.proxy_principal_id,
                proof_url=args.proxy_proof_url,
            )
        except Exception as exc:
            print(
                f"production readiness env error: proxy proof policy consistency validation failed: {exc}",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc
        args.proxy_client_nonce = generated_client_nonce(args.proxy_proof_contract)
        args.proxy_tls_channel_binding = "$COLLECTOR_SUMMARY.tls_channel_binding"
    if args.launcher_enforced:
        try:
            executable_manifest = parse_executable_digest_manifest(
                loaded,
                expected_settings=set(PINNED_EXECUTABLE_COMMAND_SETTINGS),
            )
            args.script_digest_pins = parse_python_script_digest_pins(loaded)
            for script_path, (setting, digest) in args.script_digest_pins.items():
                measured_script = open_measured_script(Path(script_path), digest, setting)
                measured_script.close()
            compose_plugin = open_measured_executable(
                Path(args.docker_compose_plugin_executable),
                args.docker_compose_plugin_sha256,
                DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV,
            )
            compose_plugin.close()
            if not args.dry_run:
                args.docker_socket_binding = validate_docker_unix_socket(
                    Path(args.docker_unix_socket)
                )
            executable_pins: dict[str, tuple[str, str]] = {}
            pinned_commands = [
                (PRODUCTION_PYTHON_EXECUTABLE_ENV, args.python),
                (PRODUCTION_DOCKER_EXECUTABLE_ENV, args.docker_executable),
            ]
            if not args.config_only:
                pinned_commands.append((PROOF_COLLECTOR_COMMAND_SETTING, collector_words[0]))
            for setting, executable in pinned_commands:
                absolute = os.path.abspath(executable)
                existing = executable_pins.get(absolute)
                pin = executable_manifest[setting]
                if existing is not None and existing[1] != pin:
                    raise ValueError("one executable path has conflicting production digest pins")
                executable_pins[absolute] = (setting, pin)
            args.pre_use_executable_pins = executable_pins
        except Exception as exc:
            print(f"production readiness env error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
    control_plane_base = (
        args.control_plane_base
        or loaded.get("SERVERWARE_PRODUCTION_CONTROL_PLANE_BASE")
        or loaded.get("SERVERWARE_PUBLIC_URL")
        or "https://localhost:3000"
    )
    control_plane_ca_bundle = (
        args.control_plane_ca_bundle
        or loaded.get("SERVERWARE_PRODUCTION_CONTROL_PLANE_CA_BUNDLE")
        or str(Path(loaded.get("SERVERWARE_CONTROL_PLANE_TLS_DIR", "/etc/serverware/control-plane-tls")) / "ca.pem")
    )
    args.claims_args = [
        "--base",
        control_plane_base,
        "--ca-bundle",
        control_plane_ca_bundle,
        *args.claims_args,
    ]
    images_env = Path(args.production_images_env)
    env["SERVERWARE_PRODUCTION_READINESS_ENV_PATH"] = str(env_file)
    env["SERVERWARE_PRODUCTION_READINESS_ENV_SHA256"] = (
        "sha256:" + hashlib.sha256(production_env_bytes).hexdigest()
    )
    args.production_readiness_env_sha256 = env[
        "SERVERWARE_PRODUCTION_READINESS_ENV_SHA256"
    ]
    args.pre_run_completion_proof_state = capture_optional_proof_state(
        Path(args.completion_proof_out)
    )
    env["SERVERWARE_PRODUCTION_IMAGES_ENV_PATH"] = str(images_env)
    if images_env.exists():
        env["SERVERWARE_PRODUCTION_IMAGES_ENV_SHA256"] = sha256_prefixed_file(images_env)
    commands = command_plan(args)
    bootstrap_pass_fds = tuple(
        sorted(
            {
                descriptor
                for descriptor in (
                    getattr(args, "bootstrap_receipt_fd", None),
                    (
                        args.nonce_rollback_assurance.get(
                            "retainedSnapshotFd"
                        )
                        if isinstance(
                            getattr(
                                args,
                                "nonce_rollback_assurance",
                                None,
                            ),
                            dict,
                        )
                        else None
                    ),
                )
                if type(descriptor) is int and descriptor > 2
            }
        )
    )
    if args.dry_run:
        print(
            canonical_json(
                {
                    "ok": True,
                    "env_file": args.env_file,
                    "env_keys": sorted(loaded),
                    "commands": commands,
                }
            )
        )
        return
    if args.config_only:
        run_commands(
            commands,
            env,
            executable_pins=getattr(args, "pre_use_executable_pins", None),
            script_digest_pins=getattr(args, "script_digest_pins", None),
            isolated_python=args.launcher_enforced,
            pass_fds=bootstrap_pass_fds,
        )
        return
    run_commands(
        commands[:-2],
        env,
        executable_pins=getattr(args, "pre_use_executable_pins", None),
        script_digest_pins=getattr(args, "script_digest_pins", None),
        isolated_python=args.launcher_enforced,
        pass_fds=bootstrap_pass_fds,
    )
    run_collector(commands[-2], args, env)
    args.proxy_tls_channel_binding = args.collected_proxy_tls_channel_binding
    run_commands(
        [completion_command(args)],
        env,
        executable_pins=getattr(args, "pre_use_executable_pins", None),
        script_digest_pins=getattr(args, "script_digest_pins", None),
        isolated_python=args.launcher_enforced,
        pass_fds=bootstrap_pass_fds,
    )
    try:
        verify_completion_output(Path(args.completion_proof_out), args)
    except Exception as exc:
        print(f"release completion output integrity error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
