#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import platform
import shlex
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent
EXECUTING_SCRIPT_FD_ENV = "CATCHPLATE_EXECUTING_SCRIPT_FD"


def _is_retained_import_root(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("/proc/self/fd/"):
        return False
    descriptor = value.removeprefix("/proc/self/fd/")
    return descriptor.isdigit() and int(descriptor) >= 3


def _is_retained_import_origin(
    value: object,
    retained_roots: tuple[str, ...],
) -> bool:
    if (
        not isinstance(value, str)
        or not retained_roots
        or any(not _is_retained_import_root(root) for root in retained_roots)
    ):
        return False
    for root in retained_roots:
        prefix = root + "/"
        if value.startswith(prefix):
            suffix = value.removeprefix(prefix)
            return bool(suffix) and all(
                component not in {"", ".", ".."}
                for component in suffix.split("/")
            )
    return False


class _RetainedImportPath(list[str]):
    def __init__(self, values: Any) -> None:
        initial_roots = tuple(values)
        if (
            not initial_roots
            or any(not _is_retained_import_root(value) for value in initial_roots)
        ):
            raise ValueError(
                "launcher retained import roots must be exact /proc/self/fd roots"
            )
        super().__init__(initial_roots)
        self._allowed_roots = initial_roots
        self._allowed_root_set = frozenset(initial_roots)

    @property
    def allowed_roots(self) -> tuple[str, ...]:
        return self._allowed_roots

    def _retained(self, values: Any) -> list[str]:
        return [
            value
            for value in values
            if value in self._allowed_root_set
        ]

    def insert(self, index: int, value: str) -> None:
        if value in self._allowed_root_set and value not in self:
            super().insert(index, value)

    def append(self, value: str) -> None:
        if value in self._allowed_root_set and value not in self:
            super().append(value)

    def extend(self, values: Any) -> None:
        for value in self._retained(values):
            self.append(value)

    def __iadd__(self, values: Any) -> "_RetainedImportPath":
        self.extend(values)
        return self

    def __setitem__(self, key: Any, value: Any) -> None:
        if isinstance(key, slice):
            super().__setitem__(key, self._retained(value))
            return
        if value in self._allowed_root_set:
            super().__setitem__(key, value)


def _configure_project_imports() -> str:
    if os.environ.get(EXECUTING_SCRIPT_FD_ENV) is not None:
        if not sys.path or any(
            not _is_retained_import_root(value) for value in sys.path
        ):
            raise RuntimeError(
                "launcher-mode project imports must resolve exclusively through "
                "retained /proc/self/fd roots"
            )
        sys.path = _RetainedImportPath(sys.path)
        return "launcher-retained-descriptor-roots"

    # Direct execution is for local fixtures and manual readiness only. The
    # native launcher replaces this path with measured retained descriptors.
    direct_roots = (str(ROOT / "scripts"), str(ROOT))
    sys.path[:0] = [path for path in direct_roots if path not in sys.path]
    return "direct-fixture-paths"


PROJECT_IMPORT_MODE = _configure_project_imports()

import generate_production_handoff as handoff  # noqa: E402
import generate_release_provenance  # noqa: E402
import merge_production_images_env  # noqa: E402
import prepare_aws_kms_materials  # noqa: E402
import production_release_input_preflight  # noqa: E402
import run_production_readiness  # noqa: E402
import verify_production_policy_identity  # noqa: E402

if PROJECT_IMPORT_MODE == "launcher-retained-descriptor-roots":
    if not isinstance(sys.path, _RetainedImportPath):
        raise RuntimeError("launcher-mode project import guard was replaced")
    retained_import_roots = sys.path.allowed_roots
    if (
        not sys.path
        or any(value not in retained_import_roots for value in sys.path)
        or any(
            not _is_retained_import_origin(
                module.__file__,
                retained_import_roots,
            )
            for module in (
                handoff,
                generate_release_provenance,
                merge_production_images_env,
                prepare_aws_kms_materials,
                production_release_input_preflight,
                run_production_readiness,
                verify_production_policy_identity,
            )
        )
    ):
        raise RuntimeError(
            "launcher-mode project imports escaped their exact retained "
            "/proc/self/fd roots"
        )

REQUIRED_MATERIALS = {"broker-kek", "decision-gate-ca"}
TEST_ONLY_BYPASS_ENV = "CATCHPLATE_TEST_ONLY_ALLOW_PREFLIGHT_BYPASS"
CONTROL_PLANE_RUNTIME_UID = 65532
MAX_OAUTH_SECRET_BYTES = 4096
MAX_RESPONSE_SIGNING_KEY_BYTES = 64 * 1024
ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV = (
    "CATCHPLATE_ATTESTATION_EXECUTABLE_SHA256_MANIFEST"
)
ATTESTATION_HELPER_COMMAND_SETTINGS = (
    "CATCHPLATE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE",
    "CATCHPLATE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE",
    "CATCHPLATE_DATA_PLANE_RECIPIENT_ATTESTATION_COMMAND",
    "CATCHPLATE_DATA_PLANE_RESPONSE_PROOF_ATTESTATION_COMMAND",
    "CATCHPLATE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND",
    "CATCHPLATE_CONTROL_PLANE_ATTESTATION_VERIFY_COMMAND",
    "CATCHPLATE_RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND",
)
PROOF_COLLECTOR_COMMAND_SETTING = "CATCHPLATE_PROXY_PROOF_COLLECTOR_COMMAND"
PRODUCTION_PYTHON_EXECUTABLE_SETTING = "CATCHPLATE_PRODUCTION_PYTHON_EXECUTABLE"
PRODUCTION_DOCKER_EXECUTABLE_SETTING = "CATCHPLATE_DOCKER_EXECUTABLE"
DOCKER_COMPOSE_PLUGIN_EXECUTABLE_SETTING = (
    run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV
)
DOCKER_COMPOSE_PLUGIN_SHA256_SETTING = run_production_readiness.DOCKER_COMPOSE_PLUGIN_SHA256_ENV
PINNED_EXECUTABLE_COMMAND_SETTINGS = frozenset(
    (
        *ATTESTATION_HELPER_COMMAND_SETTINGS,
        PROOF_COLLECTOR_COMMAND_SETTING,
        PRODUCTION_PYTHON_EXECUTABLE_SETTING,
        PRODUCTION_DOCKER_EXECUTABLE_SETTING,
    )
)
READINESS_MODE = "readiness"
READINESS_AUTHORIZATION_SCOPE = "trusted-host-readiness"
READINESS_FRESHNESS_AUTHORITY = "trusted-host-wall-clock"
READINESS_LAUNCH_MANIFEST_API_VERSION = "catchplate.productionReadinessLaunch/v3"
READINESS_LAUNCH_AUTHORIZATION_REQUEST_API_VERSION = (
    "catchplate.launchAuthorizationRequest/v2"
)
READINESS_LAUNCH_AUTHORIZATION_API_VERSION = "catchplate.launchAuthorization/v2"
READINESS_BOOTSTRAP_RECEIPT_API_VERSION = "catchplate.bootstrapReceipt/v3"
READINESS_BOUNDARY_API_VERSION = "catchplate.productionHostReadinessBoundary/v1"
READINESS_CAPABILITY_SEMANTICS = (
    "time-bounded-idempotent-readiness-authorization"
)
FINAL_AUTHORITY = (
    "independent-manifest-v6-public-nitro-verifier-and-protected-state"
)
GLOBAL_ROLE_REGISTRY_API_VERSION = (
    "catchplate.productionLaunchGlobalRoleRegistry/v1"
)
GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE = (
    "roles-present-in-native-launch-contract"
)
GLOBAL_ROLE_NAMES = frozenset(
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
GLOBAL_ROLES_OUTSIDE_CLAIM = (
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
LAUNCH_ATTEMPT_JOURNAL_API_VERSION = (
    "catchplate.launchAuthorizationAttemptJournal/v1"
)
LAUNCH_ATTEMPT_JOURNAL_DOMAIN = LAUNCH_ATTEMPT_JOURNAL_API_VERSION
LAUNCH_ATTEMPT_RECOVERY_IDENTITY_DOMAIN = (
    b"catchplate.launchAuthorizationAttemptRecoveryIdentity/v1\0"
)


def launcher_bound_readiness(env: dict[str, str]) -> bool:
    return (
        env.get(run_production_readiness.FINAL_LAUNCHER_CONTRACT_ENV)
        == run_production_readiness.FINAL_LAUNCHER_CONTRACT
    )


def readiness_authority_boundary(
    *, launcher_evidence_verified: bool
) -> dict[str, Any]:
    return {
        "apiVersion": READINESS_BOUNDARY_API_VERSION,
        "verificationMode": READINESS_MODE,
        "launchManifestApiVersion": READINESS_LAUNCH_MANIFEST_API_VERSION,
        "launchAuthorizationRequestApiVersion": (
            READINESS_LAUNCH_AUTHORIZATION_REQUEST_API_VERSION
        ),
        "launchAuthorizationApiVersion": (
            READINESS_LAUNCH_AUTHORIZATION_API_VERSION
        ),
        "bootstrapReceiptApiVersion": READINESS_BOOTSTRAP_RECEIPT_API_VERSION,
        "authorizationScope": READINESS_AUTHORIZATION_SCOPE,
        "freshnessAuthority": READINESS_FRESHNESS_AUTHORITY,
        "launcherEvidenceVerified": launcher_evidence_verified,
        "currentFreshnessVerifiedUsingTrustedHostWallClock": (
            launcher_evidence_verified
        ),
        "secureTimeProven": False,
        "finalNitroExecutionProven": False,
        "actionAuthority": False,
        "hostBootstrapEvidenceClassification": (
            "non-authoritative-readiness-context-only"
        ),
        "finalAuthority": FINAL_AUTHORITY,
    }


def validate_readiness_authority_boundary(value: Any) -> dict[str, Any]:
    expected_fields = set(readiness_authority_boundary(
        launcher_evidence_verified=False
    ))
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise ValueError("production host readiness boundary is not a closed object")
    launcher_verified = value.get("launcherEvidenceVerified")
    if type(launcher_verified) is not bool:
        raise ValueError("launcher readiness evidence verification flag is invalid")
    expected = readiness_authority_boundary(
        launcher_evidence_verified=launcher_verified
    )
    if value != expected:
        raise ValueError(
            "production host evidence cannot claim secure time, final Nitro "
            "execution, action authority, or authoritative TEE provenance"
        )
    return value


def validate_launcher_readiness_evidence(
    bootstrap_receipt: Any,
    nonce_rollback_assurance: Any,
    *,
    now_unix_seconds: int | None = None,
) -> dict[str, Any]:
    if _object_key_present(bootstrap_receipt, "useLimit"):
        raise ValueError(
            "launcher-bound readiness rejects obsolete useLimit semantics"
        )
    if (
        not isinstance(bootstrap_receipt, dict)
        or bootstrap_receipt.get("apiVersion")
        != READINESS_BOOTSTRAP_RECEIPT_API_VERSION
        or bootstrap_receipt.get("kind") != "ProductionBootstrapReceipt"
        or bootstrap_receipt.get("sealed") is not True
    ):
        raise ValueError(
            "launcher-bound readiness requires a sealed bootstrap receipt v3"
        )
    authorization = bootstrap_receipt.get("launchAuthorization")
    if not isinstance(authorization, dict):
        raise ValueError(
            "launcher-bound readiness bootstrap receipt has no launch authorization"
        )
    request = authorization.get("request")
    envelope = authorization.get("envelope")
    statement = envelope.get("statement") if isinstance(envelope, dict) else None
    witness = (
        statement.get("monotonicWitness")
        if isinstance(statement, dict)
        else None
    )
    witness_statement = (
        witness.get("statement") if isinstance(witness, dict) else None
    )
    now = int(time.time()) if now_unix_seconds is None else now_unix_seconds
    issued_at = (
        statement.get("issuedAtUnixSeconds")
        if isinstance(statement, dict)
        else None
    )
    expires_at = (
        statement.get("expiresAtUnixSeconds")
        if isinstance(statement, dict)
        else None
    )
    verified_at = authorization.get("verifiedAtUnixSeconds")
    if (
        not isinstance(request, dict)
        or request.get("apiVersion")
        != READINESS_LAUNCH_AUTHORIZATION_REQUEST_API_VERSION
        or request.get("authorizationScope") != READINESS_AUTHORIZATION_SCOPE
        or request.get("freshnessAuthority") != READINESS_FRESHNESS_AUTHORITY
        or not isinstance(envelope, dict)
        or envelope.get("apiVersion")
        != READINESS_LAUNCH_AUTHORIZATION_API_VERSION
        or not isinstance(statement, dict)
        or statement.get("authorizationScope") != READINESS_AUTHORIZATION_SCOPE
        or statement.get("freshnessAuthority") != READINESS_FRESHNESS_AUTHORITY
        or statement.get("capabilitySemantics")
        != READINESS_CAPABILITY_SEMANTICS
        or type(now) is not int
        or now < 0
        or type(issued_at) is not int
        or issued_at < 1
        or type(expires_at) is not int
        or expires_at <= issued_at
        or type(verified_at) is not int
        or verified_at < issued_at
        or verified_at > now
        or now >= expires_at
        or not isinstance(witness_statement, dict)
        or witness_statement.get("operation")
        != "authorize-trusted-host-readiness"
        or witness_statement.get("issuedAtUnixSeconds") != issued_at
        or witness_statement.get("expiresAtUnixSeconds") != expires_at
        or witness_statement.get("witnessKeyId")
        != request.get("launchAuthorityWitnessKeyId")
        or witness_statement.get("witnessIdentitySha256")
        != request.get("launchAuthorityWitnessIdentitySha256")
        or witness_statement.get("witnessAdministrativeDomainSha256")
        != request.get("launchAuthorityWitnessAdministrativeDomainSha256")
        or witness_statement.get("storeAssuranceSha256")
        != request.get("launchAuthorityWitnessStoreAssuranceSha256")
        or witness_statement.get("stateTransitionCommitted") is not True
    ):
        raise ValueError(
            "launcher-bound readiness crossed or omitted its signed request, "
            "authorization, monotonic witness, or store-assurance binding"
        )
    verifier_state_service = (
        nonce_rollback_assurance.get("verifierStateService")
        if isinstance(nonce_rollback_assurance, dict)
        else None
    )
    required_verifier_state_fields = {
        "signingPublicKeySpkiDerBase64url",
        "storeAdministrativeDomainSha256",
        "storeAssuranceEvidenceSha256",
        "storeAttestationPublicKeySpkiDerBase64url",
        "storeIdentitySha256",
    }
    if (
        not isinstance(nonce_rollback_assurance, dict)
        or nonce_rollback_assurance.get("apiVersion")
        != run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
        or nonce_rollback_assurance.get("verified") is not True
        or not isinstance(verifier_state_service, dict)
        or set(verifier_state_service) != required_verifier_state_fields
        or any(
            not isinstance(item, str) or not item
            for item in verifier_state_service.values()
        )
    ):
        raise ValueError(
            "launcher-bound readiness lacks verified nonce verifier-state "
            "store assurance"
        )
    request_global_role_registry = _validate_global_role_registry_core(
        request.get("globalRoleRegistry")
    )
    global_role_registry_sha256 = _global_role_registry_sha256(
        request_global_role_registry
    )
    manifest = bootstrap_receipt.get("manifest")
    if (
        request.get("globalRoleRegistrySha256")
        != global_role_registry_sha256
        or run_production_readiness.SHA256_RE.fullmatch(
            str(request.get("globalRoleRegistryPinsSha256", ""))
        )
        is None
        or statement.get("globalRoleRegistrySha256")
        != global_role_registry_sha256
        or not isinstance(manifest, dict)
        or manifest.get("sha256") != request.get("manifestSha256")
    ):
        raise ValueError(
            "launcher-bound readiness registry or retained manifest binding "
            "is absent from the signed request and authorization"
        )
    if (
        request.get("launchAttemptJournalDomain")
        != LAUNCH_ATTEMPT_JOURNAL_DOMAIN
        or request.get("launchAttemptRecoveryIdentitySha256")
        != _launch_attempt_recovery_identity_sha256(request)
    ):
        raise ValueError(
            "launcher-bound readiness launch-attempt recovery is not bound "
            "to the signed request and retained manifest"
        )
    roles = request_global_role_registry["roles"]
    supplied_role_bindings = {
        "launchAuthority": statement.get("authorityKeyId"),
        "launchAuthorityWitness": request.get("launchAuthorityWitnessKeyId"),
        "launchAuthorityWitnessReceipt": _spki_sha256_from_base64url(
            authorization.get("witnessPublicKeySpkiDerBase64url"),
            "launch-authority witness receipt key",
        ),
        "nonceAuthorityVerifierState": _spki_sha256_from_base64url(
            verifier_state_service["signingPublicKeySpkiDerBase64url"],
            "verifier-state authority key",
        ),
        "nonceAuthorityVerifierStateStoreAttestation": (
            _spki_sha256_from_base64url(
                verifier_state_service[
                    "storeAttestationPublicKeySpkiDerBase64url"
                ],
                "verifier-state store-assurance key",
            )
        ),
    }
    if (
        supplied_role_bindings["launchAuthority"]
        != roles["launchAuthority"]
        or supplied_role_bindings["launchAuthorityWitness"]
        != roles["launchAuthorityWitness"]
        or supplied_role_bindings["launchAuthorityWitnessReceipt"]
        != roles["launchAuthorityWitness"]
        or supplied_role_bindings["nonceAuthorityVerifierState"]
        != roles["nonceAuthorityVerifierState"]
        or supplied_role_bindings[
            "nonceAuthorityVerifierStateStoreAttestation"
        ]
        != roles["nonceAuthorityVerifierStateStoreAttestation"]
    ):
        raise ValueError(
            "launcher-bound readiness global role registry is cross-wired "
            "against supplied launch-path keys"
        )
    for field in (
        "storeAdministrativeDomainSha256",
        "storeAssuranceEvidenceSha256",
        "storeIdentitySha256",
    ):
        if (
            run_production_readiness.SHA256_RE.fullmatch(
                verifier_state_service[field]
            )
            is None
        ):
            raise ValueError(
                "launcher-bound readiness verifier-state store assurance "
                f"{field} is invalid"
            )
    return validate_readiness_authority_boundary(
        readiness_authority_boundary(launcher_evidence_verified=True)
    )


def _spki_sha256_from_base64url(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError(f"{label} is not canonical unpadded base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{label} is not canonical unpadded base64url"
        ) from exc
    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if not decoded or not hmac.compare_digest(canonical, value):
        raise ValueError(f"{label} is not canonical unpadded base64url")
    return "sha256:" + hashlib.sha256(decoded).hexdigest()


def _validate_global_role_registry_core(value: Any) -> dict[str, Any]:
    expected_fields = {
        "apiVersion",
        "claimScope",
        "roles",
        "rolesOutsideClaim",
    }
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise ValueError(
            "launcher-bound readiness global role registry core is not closed"
        )
    roles = value.get("roles")
    if (
        value.get("apiVersion") != GLOBAL_ROLE_REGISTRY_API_VERSION
        or value.get("claimScope") != GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE
        or not isinstance(roles, dict)
        or set(roles) != GLOBAL_ROLE_NAMES
        or not all(
            isinstance(role, str)
            and run_production_readiness.SHA256_RE.fullmatch(role) is not None
            for role in roles.values()
        )
        or len(set(roles.values())) != len(roles)
        or value.get("rolesOutsideClaim") != list(GLOBAL_ROLES_OUTSIDE_CLAIM)
    ):
        raise ValueError(
            "launcher-bound readiness global role registry core is malformed, "
            "colliding, or exceeds its explicit claim scope"
        )
    return value


def _global_role_registry_sha256(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(value).encode("ascii")
    ).hexdigest()


def _launch_attempt_recovery_identity_sha256(
    request: dict[str, Any],
) -> str:
    launcher_nonce = request.get("launcherNonce")
    witness_challenge = request.get("launchAuthorityWitnessChallenge")
    if (
        not isinstance(launcher_nonce, str)
        or len(launcher_nonce) != 64
        or any(character not in "0123456789abcdef" for character in launcher_nonce)
        or not isinstance(witness_challenge, str)
        or len(witness_challenge) != 64
        or any(
            character not in "0123456789abcdef"
            for character in witness_challenge
        )
    ):
        raise ValueError(
            "launcher-bound readiness recovery nonce or challenge is invalid"
        )
    for field in (
        "bootIdSha256",
        "manifestSha256",
        "globalRoleRegistrySha256",
    ):
        if (
            run_production_readiness.SHA256_RE.fullmatch(
                str(request.get(field, ""))
            )
            is None
        ):
            raise ValueError(
                f"launcher-bound readiness recovery {field} is invalid"
            )
    identity = {
        "domain": LAUNCH_ATTEMPT_JOURNAL_DOMAIN,
        "launcherNonce": launcher_nonce,
        "witnessChallenge": witness_challenge,
        "bootIdSha256": request["bootIdSha256"],
        "manifestSha256": request["manifestSha256"],
        "globalRoleRegistrySha256": request[
            "globalRoleRegistrySha256"
        ],
    }
    return "sha256:" + hashlib.sha256(
        LAUNCH_ATTEMPT_RECOVERY_IDENTITY_DOMAIN
        + canonical_json(identity).encode("ascii")
    ).hexdigest()


def _object_key_present(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(
            _object_key_present(item, key) for item in value.values()
        )
    if isinstance(value, list):
        return any(_object_key_present(item, key) for item in value)
    return False


def secure_directory_failures(path: Path, label: str) -> list[str]:
    failures: list[str] = []
    if not path.is_absolute():
        return [f"{label} must be absolute"]
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            failures.append(f"{label} ancestor is unavailable: {current}: {exc}")
            return failures
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            failures.append(f"{label} and every ancestor must be non-symlink directories: {current}")
            return failures
        mode = stat.S_IMODE(metadata.st_mode)
        if current != path and mode & 0o022:
            failures.append(f"{label} has a group/world-writable ancestor: {current}")
    if failures:
        return failures
    final = path.lstat()
    if final.st_uid not in {0, os.geteuid()}:
        failures.append(f"{label} must be owned by root or UID {os.geteuid()}")
    if stat.S_IMODE(final.st_mode) & 0o022:
        failures.append(f"{label} must not be writable by group/other")
    return failures


def snapshot_pinned_executables(env: dict[str, str]) -> tuple[list[dict[str, Any]], list[str]]:
    helper_dir = Path(env.get("CATCHPLATE_ATTESTATION_HELPER_DIR", ""))
    failures = secure_directory_failures(helper_dir, "attestation helper directory")
    reports: list[dict[str, Any]] = []
    digest_manifest: dict[str, str] = {}
    raw_manifest = env.get(ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV)
    if not isinstance(raw_manifest, str) or not raw_manifest:
        failures.append(f"{ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV} must contain a complete JSON object")
    else:
        try:
            parsed = json.loads(raw_manifest)
        except json.JSONDecodeError as exc:
            failures.append(f"{ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV} must be valid JSON: {exc}")
        else:
            if not isinstance(parsed, dict):
                failures.append(f"{ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV} must be a JSON object")
            else:
                missing = sorted(PINNED_EXECUTABLE_COMMAND_SETTINGS - set(parsed))
                extra = sorted(set(parsed) - PINNED_EXECUTABLE_COMMAND_SETTINGS)
                if missing:
                    failures.append(
                        f"{ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV} is missing entries: {missing}"
                    )
                if extra:
                    failures.append(
                        f"{ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV} contains extra entries: {extra}"
                    )
                for setting in sorted(PINNED_EXECUTABLE_COMMAND_SETTINGS):
                    pin = parsed.get(setting)
                    if not isinstance(pin, str) or run_production_readiness.SHA256_RE.fullmatch(pin) is None:
                        failures.append(
                            f"{ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV} entry {setting} must be "
                            "sha256:<64 lowercase hex>"
                        )
                    else:
                        digest_manifest[setting] = pin

    for setting in sorted(PINNED_EXECUTABLE_COMMAND_SETTINGS):
        direct_path = setting in {
            PRODUCTION_PYTHON_EXECUTABLE_SETTING,
            PRODUCTION_DOCKER_EXECUTABLE_SETTING,
        }
        collector = setting == PROOF_COLLECTOR_COMMAND_SETTING
        try:
            words = shlex.split(env.get(setting, ""))
        except ValueError:
            words = []
        require_single_word = (
            direct_path
            or collector
            or setting == "CATCHPLATE_RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND"
        )
        if (
            not words
            or (require_single_word and len(words) != 1)
            or not Path(words[0]).is_absolute()
            or (not direct_path and Path(words[0]).parent != Path("/opt/catchplate/bin"))
        ):
            qualifier = "one " if require_single_word else "an "
            location = "" if direct_path else " under /opt/catchplate/bin"
            failures.append(f"{setting} must name {qualifier}absolute executable{location}")
            continue
        host_path = Path(words[0]) if direct_path else helper_dir / Path(words[0]).name
        label = (
            "production Python executable"
            if setting == PRODUCTION_PYTHON_EXECUTABLE_SETTING
            else "Docker executable"
            if setting == PRODUCTION_DOCKER_EXECUTABLE_SETTING
            else "response-proof collector"
            if collector
            else "attestation helper"
        )
        try:
            run_production_readiness.validate_secure_ancestors(host_path, label)
            executable_bytes, metadata = run_production_readiness.read_regular_file_once(
                host_path,
                label,
                max_bytes=run_production_readiness.MAX_EXECUTABLE_BYTES,
                executable=True,
            )
        except (OSError, ValueError) as exc:
            failures.append(f"{label} is missing, unsafe, or not executable: {host_path}: {exc}")
            continue
        if setting == "CATCHPLATE_RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND":
            try:
                run_production_readiness.validate_static_amd64_elf(
                    executable_bytes,
                    "response-v2 TEE verifier",
                )
            except ValueError as exc:
                failures.append(str(exc))
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            failures.append(f"{label} must not be writable by group/other: {host_path}")
        if metadata.st_uid not in {0, os.geteuid()}:
            failures.append(f"{label} must be owned by root or UID {os.geteuid()}: {host_path}")
        actual_digest = "sha256:" + hashlib.sha256(executable_bytes).hexdigest()
        expected_digest = digest_manifest.get(setting)
        verified = expected_digest is not None and actual_digest == expected_digest
        reports.append(
            {
                "setting": setting,
                "executable": words[0],
                "host_path": str(host_path),
                "sha256": actual_digest,
                "verified": verified,
            }
        )
        if expected_digest is not None and not verified:
            failures.append(
                f"{label} SHA-256 does not match {ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV} "
                f"entry {setting}: {host_path}"
            )
    return reports, failures


def snapshot_pinned_python_scripts(env: dict[str, str]) -> tuple[list[dict[str, Any]], list[str]]:
    reports: list[dict[str, Any]] = []
    failures: list[str] = []
    try:
        pins = run_production_readiness.parse_python_script_digest_pins(env)
    except ValueError as exc:
        return reports, [str(exc)]
    for path_text, (setting, expected_digest) in sorted(pins.items()):
        try:
            measured = run_production_readiness.open_measured_script(
                Path(path_text), expected_digest, setting
            )
        except (OSError, ValueError) as exc:
            failures.append(f"pinned Python script is missing or unsafe: {path_text}: {exc}")
            continue
        try:
            reports.append(
                {
                    "setting": setting,
                    "path": path_text,
                    "sha256": measured.sha256,
                    "verified": True,
                }
            )
        finally:
            measured.close()
    return reports, failures


def verify_current_preflight_script_binding(env: dict[str, str]) -> dict[str, Any]:
    setting = run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV
    expected_digest = env.get(setting)
    if not isinstance(expected_digest, str) or run_production_readiness.SHA256_RE.fullmatch(
        expected_digest
    ) is None:
        raise ValueError(f"{setting} must be sha256:<64 lowercase hex>")
    raw_descriptor = os.environ.get("CATCHPLATE_EXECUTING_SCRIPT_FD")
    if not isinstance(raw_descriptor, str) or not raw_descriptor.isdigit():
        raise ValueError(
            "launcher-bound production host readiness preflight was not "
            "launched from a retained measured script descriptor"
        )
    descriptor = int(raw_descriptor)
    try:
        metadata = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        data = run_production_readiness.read_fd_bytes(
            descriptor,
            metadata,
            "currently executing production host preflight script",
            max_bytes=run_production_readiness.MAX_EXECUTABLE_BYTES,
        )
    except OSError as exc:
        raise ValueError("production host preflight measured script descriptor is invalid") from exc
    actual_digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_digest):
        raise ValueError(
            "currently executing production host preflight script does not match the hashed env pin"
        )
    configured_path = (ROOT / "scripts" / "production_host_preflight.py").resolve()
    configured = run_production_readiness.open_measured_script(
        configured_path,
        expected_digest,
        setting,
    )
    try:
        if (metadata.st_dev, metadata.st_ino) != (
            configured.metadata.st_dev,
            configured.metadata.st_ino,
        ):
            raise ValueError(
                "currently executing production host preflight script inode differs from the pinned path"
            )
    finally:
        configured.close()
    return {
        "path": str(configured_path),
        "sha256": actual_digest,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "measured_from": f"/proc/self/fd/{descriptor}",
        "matches_pinned_path_inode": True,
    }


def enforce_readiness_only_preflight_boundary(args: argparse.Namespace) -> None:
    expected_path = args.launcher_trusted_production_env_path
    expected_digest = args.launcher_trusted_production_env_sha256
    if expected_path is None or expected_digest is None:
        if args.skip_host_check and os.getenv(TEST_ONLY_BYPASS_ENV) == "1":
            return
        raise ValueError(
            "production host preflight requires the root launcher env path and digest before parsing"
        )
    env_path = Path(args.env_file)
    env_bytes, env_metadata = run_production_readiness.read_regular_file_once(
        env_path,
        "production readiness env",
        max_bytes=run_production_readiness.MAX_PRODUCTION_ENV_BYTES,
    )
    run_production_readiness.validate_launcher_trusted_env(
        env_path,
        env_bytes,
        env_metadata,
        expected_path=expected_path,
        expected_sha256=expected_digest,
    )
    loaded = run_production_readiness.load_env_bytes(env_bytes, env_path)
    mode = loaded.get("CATCHPLATE_COMPLETION_VERIFICATION_MODE")
    if mode != READINESS_MODE:
        raise ValueError(
            "native production_host_preflight.py requires "
            "CATCHPLATE_COMPLETION_VERIFICATION_MODE=readiness; final "
            "authority belongs only to the independent Manifest-v6 public "
            "Nitro verifier"
        )
    if not launcher_bound_readiness(loaded):
        raise ValueError(
            "launcher-bound production host readiness requires the exact "
            "descriptor-sealed bootstrap v3 contract"
        )


def snapshot_docker_toolchain(
    env: dict[str, str],
    *,
    verify_daemon: bool,
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {"ok": False}
    failures: list[str] = []
    try:
        settings = run_production_readiness.validate_docker_toolchain_settings(env)
        plugin = run_production_readiness.open_measured_executable(
            Path(settings[DOCKER_COMPOSE_PLUGIN_EXECUTABLE_SETTING]),
            settings[DOCKER_COMPOSE_PLUGIN_SHA256_SETTING],
            DOCKER_COMPOSE_PLUGIN_EXECUTABLE_SETTING,
        )
        try:
            status["compose_plugin"] = {
                "path": str(plugin.path),
                "sha256": plugin.sha256,
                "verified": True,
            }
        finally:
            plugin.close()
        status["compose_project_name"] = settings[
            run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV
        ]
        if verify_daemon:
            manifest = run_production_readiness.parse_executable_digest_manifest(
                env,
                expected_settings=set(PINNED_EXECUTABLE_COMMAND_SETTINGS),
            )
            status["daemon"] = run_production_readiness.verify_docker_daemon_identity(
                docker_executable=Path(env[PRODUCTION_DOCKER_EXECUTABLE_SETTING]),
                docker_sha256=manifest[PRODUCTION_DOCKER_EXECUTABLE_SETTING],
                socket_path=Path(settings[run_production_readiness.DOCKER_UNIX_SOCKET_ENV]),
                expected_daemon_id=settings[run_production_readiness.DOCKER_DAEMON_ID_ENV],
                base_env=run_production_readiness.build_final_child_environment(env),
            )
        status["ok"] = True
    except (OSError, ValueError) as exc:
        status["error"] = str(exc)
        failures.append(f"Docker toolchain/daemon binding failed: {exc}")
    return status, failures


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sign_readiness_preflight(
    result: dict[str, Any],
    env: dict[str, str],
    *,
    signed_at_unix: int | None = None,
) -> dict[str, Any]:
    if (
        result.get("verification_mode") != READINESS_MODE
        or result.get("readiness_only") is not True
        or result.get("final_nitro_execution_proven") is not False
        or result.get("ok_for_action") is not False
    ):
        raise ValueError(
            "production host preflight signatures are restricted to "
            "non-actionable readiness evidence"
        )
    validate_readiness_authority_boundary(result.get("authority_boundary"))
    private_path = Path(
        env.get(run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_PRIVATE_KEY_ENV, "")
    )
    public_path = Path(
        env.get(run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV, "")
    )
    private_bytes, _, _ = snapshot_runtime_material(
        private_path,
        "production host preflight signing private key",
        private=True,
        max_bytes=64 * 1024,
    )
    public_bytes, _, _ = snapshot_runtime_material(
        public_path,
        "production host preflight signing public key",
        max_bytes=64 * 1024,
    )
    private_key = serialization.load_pem_private_key(private_bytes, password=None)
    public_key = serialization.load_pem_public_key(public_bytes)
    if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("production host preflight signing keys must be Ed25519")
    private_public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if private_public_der != public_der:
        raise ValueError("production host preflight signing private/public keys do not match")
    key_id = "sha256:" + hashlib.sha256(public_der).hexdigest()
    if key_id != env.get(run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV):
        raise ValueError("production host preflight signing key does not match the hashed env key ID")
    signing_time = (
        int(time.time()) if signed_at_unix is None else signed_at_unix
    )
    if type(signing_time) is not int or signing_time <= 0:
        raise ValueError("production host preflight signing time is invalid")
    payload = canonical_json(result).encode("utf-8")
    signature = "ed25519:" + base64.urlsafe_b64encode(private_key.sign(payload)).rstrip(b"=").decode("ascii")
    return {
        "apiVersion": "catchplate.productionHostPreflightSignature/v1",
        "algorithm": "ed25519",
        "key_id": key_id,
        "payload_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "signed_at_unix": signing_time,
        "signature": signature,
    }


def revalidate_launcher_readiness_at_publication(
    *,
    initial_receipt: Any,
    nonce_rollback_assurance: Any,
    now_unix_seconds: int,
) -> None:
    current_receipt, current_fd = (
        run_production_readiness.load_sealed_bootstrap_receipt(required=True)
    )
    if (
        current_fd != run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD
        or current_fd != 198
        or current_receipt != initial_receipt
    ):
        raise ValueError(
            "launcher-bound readiness publication requires the unchanged "
            "sealed bootstrap receipt on exact descriptor 198"
        )
    validate_launcher_readiness_evidence(
        current_receipt,
        nonce_rollback_assurance,
        now_unix_seconds=now_unix_seconds,
    )


def write_result(path: Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def semantic_result_digest(path: Path) -> str:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"config gate result must be a JSON object: {path}")
    payload = dict(parsed)
    payload.pop("result_path", None)
    payload.pop("result_sha256", None)
    return handoff.sha256_prefixed_bytes(canonical_json(payload).encode("utf-8"))


def set_readiness_env_metadata(env: dict[str, str], *, env_file: Path, production_images_env: Path) -> None:
    env["CATCHPLATE_PRODUCTION_READINESS_ENV_PATH"] = str(env_file)
    env["CATCHPLATE_PRODUCTION_READINESS_ENV_SHA256"] = handoff.file_summary(env_file, "production-readiness-env")["sha256"]
    env["CATCHPLATE_PRODUCTION_IMAGES_ENV_PATH"] = str(production_images_env)
    if production_images_env.exists():
        env["CATCHPLATE_PRODUCTION_IMAGES_ENV_SHA256"] = handoff.file_summary(production_images_env, "production-images-env")["sha256"]


def enforce_test_only_bypass(args: argparse.Namespace) -> None:
    if not (args.skip_host_check or args.skip_config_gate):
        return
    if os.environ.get(TEST_ONLY_BYPASS_ENV) == "1":
        return
    raise SystemExit(
        f"--skip-host-check and --skip-config-gate are test-only; set {TEST_ONLY_BYPASS_ENV}=1 in fixture tests"
    )


def host_check(*, skip_host_check: bool) -> tuple[dict[str, Any], list[str]]:
    system = platform.system()
    status = {
        "ok": True,
        "skipped": skip_host_check,
        "system": system,
        "machine": platform.machine(),
        "linux": system == "Linux",
        "nitro_nsm_device": Path("/dev/nsm").exists(),
        "apparmor_sysfs": Path("/sys/module/apparmor").exists(),
    }
    failures = []
    if not skip_host_check:
        for key, message in (
            ("linux", "production host must be Linux"),
            ("nitro_nsm_device", "production host must expose /dev/nsm"),
            ("apparmor_sysfs", "production host must expose AppArmor sysfs"),
        ):
            if status[key] is not True:
                failures.append(message)
    status["ok"] = not failures
    return status, failures


def oauth_secret_mounts_check(
    env: dict[str, str],
    *,
    skip_host_check: bool,
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {
        "ok": False,
        "skipped": skip_host_check,
        "runtime_uid": CONTROL_PLANE_RUNTIME_UID,
        "files": [],
        "secret_values_redacted": True,
    }
    if skip_host_check:
        status["ok"] = True
        return status, []

    failures: list[str] = []
    for setting in (
        "CATCHPLATE_GOOGLE_OAUTH_CLIENT_SECRET_FILE",
        "CATCHPLATE_X_OAUTH_CLIENT_SECRET_FILE",
    ):
        path = Path(env.get(setting, ""))
        item: dict[str, Any] = {"setting": setting, "path": str(path)}
        try:
            run_production_readiness.validate_secure_ancestors(path, setting)
            secret_bytes, file_stat = run_production_readiness.read_regular_file_once(
                path,
                setting,
                max_bytes=MAX_OAUTH_SECRET_BYTES,
            )
        except (OSError, ValueError) as exc:
            failures.append(f"{setting} must reference a safe existing host secret file: {exc}")
            status["files"].append(item)
            continue
        mode = stat.S_IMODE(file_stat.st_mode)
        item.update(
            {
                "mode": oct(mode),
                "owner_uid": file_stat.st_uid,
                "bytes": len(secret_bytes),
                "sha256": "sha256:" + hashlib.sha256(secret_bytes).hexdigest(),
                "nofollow": True,
                "secure_ancestors": True,
            }
        )
        if mode not in {0o400, 0o600}:
            failures.append(f"{setting} must use mode 0400 or 0600")
        if file_stat.st_uid != CONTROL_PLANE_RUNTIME_UID:
            failures.append(
                f"{setting} must be owned by UID {CONTROL_PLANE_RUNTIME_UID} so the production container can read it"
            )
        if not 1 <= file_stat.st_size <= MAX_OAUTH_SECRET_BYTES:
            failures.append(f"{setting} must contain between 1 and {MAX_OAUTH_SECRET_BYTES} bytes")
        status["files"].append(item)
    status["ok"] = not failures
    return status, failures


def response_signing_key_custody_check(
    env: dict[str, str],
    *,
    skip_host_check: bool,
    expected_control_plane_uid: int,
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {
        "ok": False,
        "skipped": skip_host_check,
        "secret_values_redacted": True,
    }
    if skip_host_check:
        status["ok"] = True
        return status, []

    failures: list[str] = []
    private_path = Path(env.get("CATCHPLATE_RESPONSE_SIGNING_PRIVATE_KEY_FILE", ""))
    public_path = Path(env.get("CATCHPLATE_RESPONSE_SIGNING_PUBLIC_KEY", ""))
    control_public_path = Path(
        env.get("CATCHPLATE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY", "")
    )
    expected_key_id = env.get(
        "CATCHPLATE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID", ""
    )
    try:
        if private_path != private_path.resolve(strict=False):
            raise ValueError("private-key path must be canonical")
        if public_path != public_path.resolve(strict=False):
            raise ValueError("public-key path must be canonical")
        if control_public_path != public_path:
            raise ValueError(
                "online and verifier response-signing public-key paths must match"
            )
        run_production_readiness.validate_secure_ancestors(
            private_path, "response-signing private key"
        )
        run_production_readiness.validate_secure_ancestors(
            public_path, "response-signing public key"
        )
        private_bytes, private_stat = run_production_readiness.read_regular_file_once(
            private_path,
            "response-signing private key",
            max_bytes=MAX_RESPONSE_SIGNING_KEY_BYTES,
        )
        public_bytes, public_stat = run_production_readiness.read_regular_file_once(
            public_path,
            "response-signing public key",
            max_bytes=MAX_RESPONSE_SIGNING_KEY_BYTES,
        )
        mode = stat.S_IMODE(private_stat.st_mode)
        if mode not in {0o400, 0o600}:
            raise ValueError("private key must use mode 0400 or 0600")
        if private_stat.st_uid != expected_control_plane_uid:
            raise ValueError(
                f"private key must be owned by production control-plane UID {expected_control_plane_uid}"
            )
        if stat.S_IMODE(public_stat.st_mode) & 0o022:
            raise ValueError("public key must not be writable by group or world")
        private_key = serialization.load_pem_private_key(private_bytes, password=None)
        public_key = serialization.load_pem_public_key(public_bytes)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("private key must be unencrypted Ed25519 PKCS8 PEM")
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("public key must be Ed25519")
        private_public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        actual_key_id = "sha256:" + hashlib.sha256(public_der).hexdigest()
        if not hmac.compare_digest(private_public_der, public_der):
            raise ValueError("private key does not match the pinned public key")
        if not hmac.compare_digest(actual_key_id, expected_key_id):
            raise ValueError("public key does not match the configured key ID")
        status.update(
            {
                "path": str(private_path),
                "mode": oct(mode),
                "owner_uid": private_stat.st_uid,
                "bytes": private_stat.st_size,
                "key_id": actual_key_id,
                "nofollow": True,
                "single_link": True,
                "secure_ancestors": True,
            }
        )
    except (OSError, TypeError, ValueError) as exc:
        failures.append(f"response-signing key custody is invalid: {exc}")
    status["ok"] = not failures
    return status, failures


def response_v2_release_transparency_inputs_check(
    env: dict[str, str],
    *,
    skip_host_check: bool,
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {
        "ok": False,
        "skipped": skip_host_check,
        "topology_profile": env.get(
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_TEE_TOPOLOGY_PROFILE"
        ),
        "private_keys_present": False,
        "files": [],
        "secret_values_redacted": True,
    }
    if skip_host_check:
        status["ok"] = True
        return status, []

    failures: list[str] = []
    try:
        if status["topology_profile"] != "local-single-node-1-of-1":
            raise ValueError(
                "response-v2 TEE topology must explicitly be local-single-node-1-of-1"
            )
        public_config_dir = Path(
            env.get("CATCHPLATE_RESPONSE_OBSERVATION_V2_PUBLIC_CONFIG_DIR", "")
        )
        if not public_config_dir.is_absolute():
            raise ValueError("response-v2 public config directory must be absolute")

        file_settings = (
            (
                "CATCHPLATE_RESPONSE_OBSERVATION_V2_CUSTODY_CONFIG_FILE",
                "CATCHPLATE_RESPONSE_OBSERVATION_V2_CUSTODY_CONFIG_SHA256",
                "custody.json",
                4 * 1024 * 1024,
            ),
            (
                "CATCHPLATE_RESPONSE_OBSERVATION_V2_TRANSPARENCY_TRUST_PIN_FILE",
                "CATCHPLATE_RESPONSE_OBSERVATION_V2_TRANSPARENCY_TRUST_PIN_SHA256",
                "release-transparency-trust-pin.json",
                1024 * 1024,
            ),
            (
                "CATCHPLATE_RESPONSE_OBSERVATION_V2_RELEASE_TRANSPARENCY_ARTIFACT_FILE",
                "CATCHPLATE_RESPONSE_OBSERVATION_V2_RELEASE_TRANSPARENCY_ARTIFACT_SHA256",
                "release-transparency-artifact.json",
                4 * 1024 * 1024,
            ),
        )
        snapshots: dict[str, tuple[bytes, dict[str, Any]]] = {}
        for path_setting, digest_setting, expected_name, maximum_bytes in file_settings:
            path = Path(env.get(path_setting, ""))
            if (
                not path.is_absolute()
                or path.parent != public_config_dir
                or path.name != expected_name
            ):
                raise ValueError(
                    f"{path_setting} must be the absolute {expected_name} direct child of the response-v2 public config directory"
                )
            run_production_readiness.validate_secure_ancestors(path, path_setting)
            content, metadata = run_production_readiness.read_regular_file_once(
                path,
                path_setting,
                max_bytes=maximum_bytes,
            )
            mode = stat.S_IMODE(metadata.st_mode)
            digest = "sha256:" + hashlib.sha256(content).hexdigest()
            if metadata.st_uid != 0 or mode != 0o444 or metadata.st_nlink != 1:
                raise ValueError(
                    f"{path_setting} must be root-owned mode 0444 with one hard link"
                )
            if not hmac.compare_digest(digest, env.get(digest_setting, "")):
                raise ValueError(
                    f"{path_setting} does not match its independently approved digest"
                )
            report = {
                "setting": path_setting,
                "path": str(path),
                "sha256": digest,
                "owner_uid": metadata.st_uid,
                "mode": oct(mode),
                "bytes": len(content),
                "nofollow": True,
                "secure_ancestors": True,
            }
            snapshots[path_setting] = (content, report)
            status["files"].append(report)

        tee_input_settings = (
            (
                "CATCHPLATE_RESPONSE_V2_TEE_EXPECTATIONS_FILE",
                "CATCHPLATE_RESPONSE_V2_TEE_EXPECTATIONS_SHA256",
                4 * 1024 * 1024,
            ),
            (
                "CATCHPLATE_RESPONSE_V2_NITRO_TRUST_ROOTS_FILE",
                "CATCHPLATE_RESPONSE_V2_NITRO_TRUST_ROOTS_SHA256",
                8 * 1024 * 1024,
            ),
        )
        tee_snapshots: dict[str, bytes] = {}
        for path_setting, digest_setting, maximum_bytes in tee_input_settings:
            path = Path(env.get(path_setting, ""))
            if not path.is_absolute():
                raise ValueError(f"{path_setting} must be an absolute host path")
            run_production_readiness.validate_secure_ancestors(path, path_setting)
            content, metadata = run_production_readiness.read_regular_file_once(
                path,
                path_setting,
                max_bytes=maximum_bytes,
            )
            mode = stat.S_IMODE(metadata.st_mode)
            digest = "sha256:" + hashlib.sha256(content).hexdigest()
            if metadata.st_uid != 0 or mode != 0o444 or metadata.st_nlink != 1:
                raise ValueError(
                    f"{path_setting} must be root-owned mode 0444 with one hard link"
                )
            if not hmac.compare_digest(digest, env.get(digest_setting, "")):
                raise ValueError(
                    f"{path_setting} does not match its independently approved digest"
                )
            parsed = json.loads(content.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError(f"{path_setting} must contain a JSON object")
            tee_snapshots[path_setting] = content
            status["files"].append(
                {
                    "setting": path_setting,
                    "path": str(path),
                    "sha256": digest,
                    "owner_uid": metadata.st_uid,
                    "mode": oct(mode),
                    "bytes": len(content),
                    "nofollow": True,
                    "secure_ancestors": True,
                }
            )

        def parse_public_json(setting: str, *, canonical: bool) -> dict[str, Any]:
            content = snapshots[setting][0]
            parsed = json.loads(content.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError(f"{setting} must contain a JSON object")
            if canonical and content != canonical_json(parsed).encode("utf-8"):
                raise ValueError(f"{setting} must contain exact canonical JSON bytes")
            return parsed

        custody = parse_public_json(
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_CUSTODY_CONFIG_FILE",
            canonical=False,
        )
        trust_pin = parse_public_json(
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_TRANSPARENCY_TRUST_PIN_FILE",
            canonical=True,
        )
        artifact = parse_public_json(
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_RELEASE_TRANSPARENCY_ARTIFACT_FILE",
            canonical=True,
        )
        topology = custody.get("custodyTopology")
        if (
            not isinstance(topology, dict)
            or topology.get("attestationMode") != "tee-hardware"
            or topology.get("hardwareProof") is not True
            or topology.get("faultDomainId") != "host-1"
            or topology.get("quorumMode") != "LOCAL_1_OF_1"
            or topology.get("faultDomainCount") != 1
            or topology.get("externalWitnessCount") != 0
        ):
            raise ValueError(
                "response-v2 topology must honestly declare one local TEE fault domain, LOCAL_1_OF_1, and zero external witnesses"
            )
        tee_expectations = json.loads(
            tee_snapshots["CATCHPLATE_RESPONSE_V2_TEE_EXPECTATIONS_FILE"].decode("utf-8")
        )
        if (
            set(tee_expectations)
            != {"apiVersion", "nitro", "staticClaims", "trustRootsSha256"}
            or tee_expectations.get("apiVersion")
            != "catchplate.responseObservationV2NitroVerifierExpectations/v1"
            or not isinstance(tee_expectations.get("nitro"), dict)
            or not isinstance(tee_expectations.get("staticClaims"), dict)
            or tee_expectations.get("trustRootsSha256")
            != env.get("CATCHPLATE_RESPONSE_V2_NITRO_TRUST_ROOTS_SHA256")
        ):
            raise ValueError(
                "response-v2 TEE expectations do not bind the exact Nitro trust-root input"
            )
        trust_pin_json = env.get(
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_TRANSPARENCY_TRUST_PIN_JSON", ""
        )
        parsed_env_pin = json.loads(trust_pin_json)
        if (
            not isinstance(parsed_env_pin, dict)
            or trust_pin_json != canonical_json(parsed_env_pin)
            or parsed_env_pin != trust_pin
            or custody.get("releaseTransparencyTrustPin") != trust_pin
            or custody.get("releaseTransparencyArtifact") != artifact
        ):
            raise ValueError(
                "response-v2 custody config, canonical environment pin, and root-owned transparency files must agree exactly"
            )

        pins = custody.get("proofIndependentPins")
        proof = artifact.get("releaseTransparencyProof")
        if not isinstance(pins, dict) or not isinstance(proof, dict):
            raise ValueError("response-v2 independent pins or release proof are missing")
        checkpoint = proof.get("checkpoint")
        leaf = proof.get("leaf")
        if not isinstance(checkpoint, dict) or not isinstance(leaf, dict):
            raise ValueError("response-v2 release proof lacks its leaf or checkpoint")
        checkpoint_payload = checkpoint.get("payload")
        checkpoint_auth = checkpoint.get("authentication")
        release_record = leaf.get("releaseRecord")
        if (
            not isinstance(checkpoint_payload, dict)
            or not isinstance(checkpoint_auth, dict)
            or not isinstance(release_record, dict)
            or not isinstance(release_record.get("payload"), dict)
            or not isinstance(release_record.get("authentication"), dict)
        ):
            raise ValueError("response-v2 release proof lacks signed checkpoint or release-record fields")
        release_payload = release_record["payload"]
        release_auth = release_record["authentication"]

        digest_fields = (
            trust_pin.get("logKeySpkiSha256"),
            trust_pin.get("anchorRootSha256"),
            trust_pin.get("trustCheckpointSha256"),
            pins.get("releaseSourceCommitSha256"),
            pins.get("releaseSourceTreeSha256"),
            pins.get("releaseExecutableSha256"),
            pins.get("releaseConfigurationSha256"),
            pins.get("releaseRecordSignerPublicKeySha256"),
            release_auth.get("publicKeySpkiSha256"),
        )
        if any(
            not isinstance(value, str)
            or len(value) != 71
            or not value.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in value[7:])
            for value in digest_fields
        ):
            raise ValueError(
                "response-v2 log, anchor, source, binary, config, and signer pins must be lowercase SHA-256 digests"
            )
        if (
            trust_pin.get("generationId")
            != env.get("CATCHPLATE_RESPONSE_OBSERVATION_V2_GENERATION_ID")
            or trust_pin.get("generationId") != topology.get("generationId")
            or trust_pin.get("providerGeneration") != topology.get("generation")
            or trust_pin.get("proofPinsRootSha256")
            != env.get("CATCHPLATE_RESPONSE_OBSERVATION_V2_PROOF_PINS_ROOT_SHA256")
            or trust_pin.get("trustCheckpointSha256")
            != pins.get("trustCheckpointSha256")
            or trust_pin.get("trustCheckpointSha256")
            != topology.get("trustCheckpointSha256")
            or trust_pin.get("revocationEpoch") != pins.get("revocationEpoch")
            or trust_pin.get("logId") != pins.get("transparencyLogId")
            or trust_pin.get("logKeyId") != pins.get("transparencyLogKeyId")
            or trust_pin.get("logKeySpkiSha256")
            != pins.get("transparencyLogKeySpkiSha256")
            or trust_pin.get("anchorTreeSize")
            != pins.get("transparencyAnchorRevision")
            or trust_pin.get("anchorRootSha256")
            != pins.get("transparencyAnchorRootSha256")
            or checkpoint_payload.get("logId") != trust_pin.get("logId")
            or checkpoint_payload.get("providerGeneration")
            != trust_pin.get("providerGeneration")
            or checkpoint_payload.get("trustCheckpointSha256")
            != trust_pin.get("trustCheckpointSha256")
            or checkpoint_payload.get("revocationEpoch")
            != trust_pin.get("revocationEpoch")
            or checkpoint_auth.get("keyId") != trust_pin.get("logKeyId")
            or checkpoint_auth.get("publicKeySpkiSha256")
            != trust_pin.get("logKeySpkiSha256")
            or release_payload.get("sourceCommitSha256")
            != pins.get("releaseSourceCommitSha256")
            or release_payload.get("generationId") != trust_pin.get("generationId")
            or release_payload.get("providerGeneration")
            != trust_pin.get("providerGeneration")
            or release_payload.get("sourceTreeSha256")
            != pins.get("releaseSourceTreeSha256")
            or release_payload.get("executableSha256")
            != pins.get("releaseExecutableSha256")
            or release_payload.get("configurationSha256")
            != pins.get("releaseConfigurationSha256")
            or release_auth.get("keyId")
            != pins.get("releaseRecordSignerKeyId")
            or release_auth.get("publicKeySha256")
            != pins.get("releaseRecordSignerPublicKeySha256")
            or release_payload.get("sourceCommitSha256")
            != env.get("CATCHPLATE_RESPONSE_OBSERVATION_V2_SOURCE_COMMIT_SHA256")
            or release_payload.get("sourceTreeSha256")
            != env.get("CATCHPLATE_RESPONSE_OBSERVATION_V2_SOURCE_TREE_SHA256")
        ):
            raise ValueError(
                "response-v2 external log/checkpoint/SPKI/anchor/source/binary pins are not independently consistent"
            )

        forbidden_private_fields = {
            "privateKey",
            "privateKeyBase64",
            "privateKeyPem",
            "signingPrivateKey",
        }

        def reject_private_fields(value: Any) -> None:
            if isinstance(value, dict):
                if forbidden_private_fields.intersection(value):
                    raise ValueError("response-v2 public inputs contain private key material")
                for nested in value.values():
                    reject_private_fields(nested)
            elif isinstance(value, list):
                for nested in value:
                    reject_private_fields(nested)

        reject_private_fields(custody)
        reject_private_fields(trust_pin)
        reject_private_fields(artifact)
        status.update(
            {
                "generation_id": trust_pin.get("generationId"),
                "provider_generation": trust_pin.get("providerGeneration"),
                "log_id": trust_pin.get("logId"),
                "log_key_spki_sha256": trust_pin.get("logKeySpkiSha256"),
                "anchor_tree_size": trust_pin.get("anchorTreeSize"),
                "anchor_root_sha256": trust_pin.get("anchorRootSha256"),
                "checkpoint_sha256": proof.get("checkpointSha256"),
                "source_commit_sha256": release_payload.get("sourceCommitSha256"),
                "source_tree_sha256": release_payload.get("sourceTreeSha256"),
                "executable_sha256": release_payload.get("executableSha256"),
                "configuration_sha256": release_payload.get("configurationSha256"),
            }
        )
    except Exception as exc:
        failures.append(f"response-v2 release transparency inputs are invalid: {exc}")
    status["ok"] = not failures
    return status, failures


def snapshot_runtime_material(
    path: Path,
    label: str,
    *,
    private: bool = False,
    max_bytes: int = 8 * 1024 * 1024,
) -> tuple[bytes, os.stat_result, dict[str, Any]]:
    run_production_readiness.validate_secure_ancestors(path, label)
    data, metadata = run_production_readiness.read_regular_file_once(
        path,
        label,
        max_bytes=max_bytes,
    )
    if metadata.st_uid not in {0, os.geteuid()}:
        raise ValueError(f"{label} must be owned by root or UID {os.geteuid()}")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o022:
        raise ValueError(f"{label} must not be writable by group/other")
    if private and mode & 0o077:
        raise ValueError(f"{label} must not grant group/world access")
    return data, metadata, {
        "path": str(path),
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "mode": oct(mode),
        "owner_uid": metadata.st_uid,
        "nofollow": True,
        "secure_ancestors": True,
    }


def runtime_trust_materials_check(
    env: dict[str, str],
    *,
    skip_host_check: bool,
) -> tuple[dict[str, Any], list[str]]:
    tls_dir = Path(env.get("CATCHPLATE_CONTROL_PLANE_TLS_DIR", ""))
    anchor_tls_dir = Path(env.get("CATCHPLATE_AUDIT_ANCHOR_TLS_DIR", ""))
    helper_dir = Path(env.get("CATCHPLATE_ATTESTATION_HELPER_DIR", ""))
    status: dict[str, Any] = {
        "ok": False,
        "skipped": skip_host_check,
        "tls_dir": str(tls_dir),
        "anchor_tls_dir": str(anchor_tls_dir),
        "helper_dir": str(helper_dir),
        "tls_files": [],
        "helper_files": [],
        "anchor_tls_files": [],
        "proof_files": [],
        "proof_collector_files": [],
        "executable_digests": [],
        "python_script_digests": [],
        "docker_toolchain": {},
        "material_digests": {},
        "secret_values_redacted": True,
    }
    if skip_host_check:
        status["ok"] = True
        return status, []

    failures: list[str] = []
    snapshots: dict[str, bytes] = {}

    def capture(key: str, path: Path, label: str, *, private: bool = False) -> None:
        try:
            data, metadata, report = snapshot_runtime_material(path, label, private=private)
        except (OSError, ValueError) as exc:
            failures.append(f"{label} is missing or unsafe: {path}: {exc}")
            return
        snapshots[key] = data
        status["material_digests"][key] = report
        if private:
            status[f"{key}_mode"] = oct(stat.S_IMODE(metadata.st_mode))

    tls_files = {
        "control_plane_certificate": tls_dir / "catchplate.crt",
        "control_plane_private_key": tls_dir / "catchplate.key",
        "control_plane_ca_bundle": tls_dir / "ca.pem",
    }
    for key, path in tls_files.items():
        capture(key, path, key.replace("_", " "), private=key.endswith("private_key"))
        if key in snapshots:
            status["tls_files"].append(path.name)
    if set(tls_files) <= set(snapshots):
        try:
            certificate = x509.load_pem_x509_certificate(snapshots["control_plane_certificate"])
            private_key = serialization.load_pem_private_key(
                snapshots["control_plane_private_key"], password=None
            )
            cert_public = certificate.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_public = private_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if cert_public != key_public:
                failures.append("control-plane TLS certificate does not match its private key")
            now = datetime.now(timezone.utc)
            if not (certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc):
                failures.append("control-plane TLS certificate is not currently valid")
            try:
                dns_names = certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                dns_names = []
            status["certificate_dns_names"] = sorted(dns_names)
            if "catchplate" not in dns_names:
                failures.append("control-plane TLS certificate must include the internal DNS SAN catchplate")
            issuers = x509.load_pem_x509_certificates(snapshots["control_plane_ca_bundle"])
            if not issuers or not any(_directly_issued_by(certificate, issuer) for issuer in issuers):
                failures.append("control-plane TLS certificate is not directly issued by the supplied CA bundle")
            status["certificate_not_after"] = certificate.not_valid_after_utc.isoformat()
            status["ca_certificates"] = len(issuers)
        except Exception as exc:
            failures.append(f"control-plane TLS material is invalid: {exc}")

    anchor_files = {
        "anchor_certificate": anchor_tls_dir / "audit-anchor.crt",
        "anchor_private_key": anchor_tls_dir / "audit-anchor.key",
    }
    for key, path in anchor_files.items():
        capture(key, path, key.replace("_", " "), private=key.endswith("private_key"))
        if key in snapshots:
            status["anchor_tls_files"].append(path.name)
    if set(anchor_files) <= set(snapshots):
        try:
            certificate = x509.load_pem_x509_certificate(snapshots["anchor_certificate"])
            private_key = serialization.load_pem_private_key(snapshots["anchor_private_key"], password=None)
            cert_public = certificate.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            key_public = private_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if cert_public != key_public:
                failures.append("audit-anchor TLS certificate does not match its private key")
            now = datetime.now(timezone.utc)
            if not (certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc):
                failures.append("audit-anchor TLS certificate is not currently valid")
            try:
                dns_names = certificate.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                dns_names = []
            status["anchor_certificate_dns_names"] = sorted(dns_names)
            if "audit-anchor" not in dns_names:
                failures.append("audit-anchor TLS certificate must include the internal DNS SAN audit-anchor")
            issuers = x509.load_pem_x509_certificates(snapshots["control_plane_ca_bundle"])
            if not any(_directly_issued_by(certificate, issuer) for issuer in issuers):
                failures.append("audit-anchor TLS certificate is not directly issued by the control-plane CA bundle")
            status["anchor_certificate_not_after"] = certificate.not_valid_after_utc.isoformat()
        except Exception as exc:
            failures.append(f"audit-anchor TLS material is invalid: {exc}")

    executable_reports, executable_failures = snapshot_pinned_executables(env)
    status["executable_digests"] = executable_reports
    failures.extend(executable_failures)
    status["helper_files"] = sorted(
        Path(item["host_path"]).name
        for item in executable_reports
        if item["setting"] in ATTESTATION_HELPER_COMMAND_SETTINGS
    )
    status["proof_collector_files"] = sorted(
        Path(item["host_path"]).name
        for item in executable_reports
        if item["setting"] == PROOF_COLLECTOR_COMMAND_SETTING
    )
    if launcher_bound_readiness(env):
        script_reports, script_failures = snapshot_pinned_python_scripts(env)
        status["python_script_digests"] = script_reports
        failures.extend(script_failures)
        docker_toolchain, docker_failures = snapshot_docker_toolchain(
            env,
            verify_daemon=True,
        )
        status["docker_toolchain"] = docker_toolchain
        failures.extend(docker_failures)

    proof_paths = {
        "proof_ca_bundle": Path(env.get("CATCHPLATE_PROXY_PROOF_CA_BUNDLE", "")),
        "proof_collector_private_key": Path(env.get("CATCHPLATE_PROXY_PROOF_COLLECTOR_PRIVATE_KEY", "")),
        "proof_collector_public_key": Path(env.get("CATCHPLATE_PROXY_PROOF_COLLECTOR_PUBLIC_KEY", "")),
        "proof_verifier_public_key": Path(env.get("CATCHPLATE_PROXY_PROOF_VERIFIER_PUBLIC_KEY", "")),
    }
    for key, path in proof_paths.items():
        capture(key, path, key.replace("_", " "), private=key.endswith("private_key"))
        if key in snapshots:
            status["proof_files"].append(path.name)
    if "proof_ca_bundle" in snapshots:
        try:
            proof_ca_certificates = x509.load_pem_x509_certificates(snapshots["proof_ca_bundle"])
            if not proof_ca_certificates:
                raise ValueError("contains no certificates")
            status["proof_ca_certificates"] = len(proof_ca_certificates)
        except Exception as exc:
            failures.append(f"response-proof CA bundle is invalid: {exc}")
    required_proof_keys = {
        "proof_collector_private_key",
        "proof_collector_public_key",
        "proof_verifier_public_key",
    }
    if required_proof_keys <= set(snapshots):
        try:
            collector_private = serialization.load_pem_private_key(
                snapshots["proof_collector_private_key"], password=None
            )
            collector_public = serialization.load_pem_public_key(
                snapshots["proof_collector_public_key"]
            )
            verifier_public = serialization.load_pem_public_key(
                snapshots["proof_verifier_public_key"]
            )
            if not isinstance(collector_private, Ed25519PrivateKey):
                raise ValueError("collector private key is not Ed25519")
            if not isinstance(collector_public, Ed25519PublicKey):
                raise ValueError("collector public key is not Ed25519")
            if not isinstance(verifier_public, Ed25519PublicKey):
                raise ValueError("vendor verifier public key is not Ed25519")
            collector_private_der = collector_private.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            collector_public_der = collector_public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            if collector_private_der != collector_public_der:
                raise ValueError("collector private and public keys do not match")
            verifier_public_der = verifier_public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            collector_key_id = "sha256:" + hashlib.sha256(collector_public_der).hexdigest()
            verifier_key_id = "sha256:" + hashlib.sha256(verifier_public_der).hexdigest()
            if collector_key_id != env.get("CATCHPLATE_PROXY_PROOF_COLLECTOR_KEY_ID"):
                raise ValueError("collector public key does not match CATCHPLATE_PROXY_PROOF_COLLECTOR_KEY_ID")
            if verifier_key_id != env.get("CATCHPLATE_PROXY_PROOF_VERIFIER_KEY_ID"):
                raise ValueError("vendor verifier public key does not match CATCHPLATE_PROXY_PROOF_VERIFIER_KEY_ID")
            status["proof_collector_key_id"] = collector_key_id
            status["proof_verifier_key_id"] = verifier_key_id
        except Exception as exc:
            failures.append(f"response-proof signing material is invalid: {exc}")

    if launcher_bound_readiness(env):
        capture(
            "preflight_signing_public_key",
            Path(
                env.get(
                    run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV,
                    "",
                )
            ),
            "production host readiness preflight signing public key",
        )

    for key in ("tls_files", "anchor_tls_files", "helper_files", "proof_files", "proof_collector_files"):
        status[key] = sorted(status[key])
    status["executable_digests"] = sorted(
        status["executable_digests"], key=lambda item: item["setting"]
    )
    status["python_script_digests"] = sorted(
        status["python_script_digests"], key=lambda item: item["setting"]
    )
    status["ok"] = not failures
    return status, failures


def _directly_issued_by(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        certificate.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


def env_check(
    path: Path,
    *,
    production_images_env: Path,
    config_out: Path,
    skip_config_gate: bool,
    expected_control_plane_uid: int = CONTROL_PLANE_RUNTIME_UID,
    expected_control_plane_gid: int = CONTROL_PLANE_RUNTIME_UID,
    launcher_trusted_env_path: str | None = None,
    launcher_trusted_env_sha256: str | None = None,
    launcher_nonce_rollback_assurance_pins: str | None = None,
    launcher_nonce_rollback_assurance_pins_sha256: str | None = None,
    launcher_nonce_rollback_assurance_contract_sha256: str | None = None,
) -> tuple[dict[str, Any], dict[str, str], list[str]]:
    status: dict[str, Any] = {
        "ok": False,
        "path": str(path),
        "env_keys": [],
        "config_gate": {"skipped": skip_config_gate},
        "secret_values_redacted": True,
    }
    failures: list[str] = []
    try:
        env_bytes, env_metadata = run_production_readiness.read_regular_file_once(
            path,
            "production readiness env",
            max_bytes=run_production_readiness.MAX_PRODUCTION_ENV_BYTES,
        )
        status["file"] = {
            "path": str(path),
            "sha256": "sha256:" + hashlib.sha256(env_bytes).hexdigest(),
            "bytes": len(env_bytes),
            "mode": oct(stat.S_IMODE(env_metadata.st_mode)),
            "owner_uid": env_metadata.st_uid,
            "nofollow": True,
        }
        if launcher_trusted_env_path is not None or launcher_trusted_env_sha256 is not None:
            status["launcher_trust"] = run_production_readiness.validate_launcher_trusted_env(
                path,
                env_bytes,
                env_metadata,
                expected_path=launcher_trusted_env_path,
                expected_sha256=launcher_trusted_env_sha256,
            )
        loaded = run_production_readiness.load_env_bytes(env_bytes, path)
        if run_production_readiness.LAUNCHER_TRUST_INPUT_NAMES & set(loaded):
            raise ValueError("out-of-band launcher trust inputs must not be defined inside the production env")
        if loaded.get("CATCHPLATE_COMPLETION_VERIFICATION_MODE") != READINESS_MODE:
            raise ValueError(
                "production host preflight accepts only "
                "CATCHPLATE_COMPLETION_VERIFICATION_MODE=readiness; host "
                "evidence cannot request or satisfy final Nitro verification"
            )
        launcher_enforced = launcher_bound_readiness(loaded)
        if launcher_enforced:
            if "launcher_trust" not in status:
                raise ValueError(
                    "launcher-bound readiness requires out-of-band launcher "
                    "trust path and digest inputs"
                )
            status["launcher_trust"]["startup_environment_contract"] = (
                run_production_readiness.validate_final_launcher_contract(loaded)
            )
            bootstrap_receipt, bootstrap_receipt_fd = (
                run_production_readiness.load_sealed_bootstrap_receipt(
                    required=True
                )
            )
            if (
                bootstrap_receipt_fd
                != run_production_readiness.BOOTSTRAP_RECEIPT_FIXED_FD
                or bootstrap_receipt_fd != 198
            ):
                raise ValueError(
                    "launcher-bound readiness bootstrap receipt must remain "
                    "on exact sealed descriptor 198"
                )
            status["launcher_trust"]["bootstrap_receipt"] = bootstrap_receipt
            status["nonce_rollback_assurance"] = (
                run_production_readiness.validate_retained_nonce_rollback_assurance(
                    retained_path=launcher_nonce_rollback_assurance_pins,
                    expected_pins_sha256=(
                        launcher_nonce_rollback_assurance_pins_sha256
                    ),
                    expected_contract_sha256=(
                        launcher_nonce_rollback_assurance_contract_sha256
                    ),
                    bootstrap_receipt=bootstrap_receipt,
                    required=True,
                )
            )
            status["launcher_trust"]["nonce_rollback_assurance"] = status[
                "nonce_rollback_assurance"
            ]
            status["authority_boundary"] = validate_launcher_readiness_evidence(
                bootstrap_receipt,
                status["nonce_rollback_assurance"],
            )
            status["launcher_trust"]["current_freshness_verified"] = True
            status["launcher_trust"]["freshness_authority"] = (
                READINESS_FRESHNESS_AUTHORITY
            )
            status["launcher_trust"]["secure_time_proven"] = False
            status["executing_script"] = verify_current_preflight_script_binding(loaded)
        else:
            if "launcher_trust" in status:
                raise ValueError(
                    "out-of-band launcher trust inputs cannot be combined with "
                    "a manual readiness env"
                )
            status["nonce_rollback_assurance"] = (
                run_production_readiness.validate_retained_nonce_rollback_assurance(
                    retained_path=launcher_nonce_rollback_assurance_pins,
                    expected_pins_sha256=(
                        launcher_nonce_rollback_assurance_pins_sha256
                    ),
                    expected_contract_sha256=(
                        launcher_nonce_rollback_assurance_contract_sha256
                    ),
                    bootstrap_receipt=None,
                    required=False,
                )
            )
            status["authority_boundary"] = validate_readiness_authority_boundary(
                readiness_authority_boundary(launcher_evidence_verified=False)
            )
    except Exception as exc:
        status["error"] = str(exc)
        return status, {}, [f"production readiness env is invalid: {exc}"]
    status["env_keys"] = sorted(loaded)
    if skip_config_gate:
        status["ok"] = True
        return status, loaded, failures
    launcher_enforced = launcher_bound_readiness(loaded)
    if launcher_enforced and (
        expected_control_plane_uid != run_production_readiness.FINAL_CONTROL_PLANE_UID
        or expected_control_plane_gid != run_production_readiness.FINAL_CONTROL_PLANE_GID
    ):
        status["error"] = (
            "launcher-bound readiness control-plane UID/GID must be fixed at "
            "65532:65532"
        )
        return status, loaded, [status["error"]]
    try:
        env = (
            run_production_readiness.build_final_child_environment(loaded)
            if launcher_enforced
            else {**os.environ, **loaded}
        )
    except ValueError as exc:
        status["error"] = str(exc)
        return status, loaded, [f"production readiness config gate child env is invalid: {exc}"]
    env["CATCHPLATE_PRODUCTION_READINESS_ENV_PATH"] = str(path)
    env["CATCHPLATE_PRODUCTION_READINESS_ENV_SHA256"] = status["file"]["sha256"]
    env["CATCHPLATE_PRODUCTION_IMAGES_ENV_PATH"] = str(production_images_env)
    if production_images_env.exists():
        env["CATCHPLATE_PRODUCTION_IMAGES_ENV_SHA256"] = handoff.file_summary(
            production_images_env, "production-images-env"
        )["sha256"]
    try:
        executable_manifest = run_production_readiness.parse_executable_digest_manifest(
            loaded,
            expected_settings=set(PINNED_EXECUTABLE_COMMAND_SETTINGS),
        )
        python_executable = loaded.get(PRODUCTION_PYTHON_EXECUTABLE_SETTING, "")
        if not Path(python_executable).is_absolute():
            raise ValueError(f"{PRODUCTION_PYTHON_EXECUTABLE_SETTING} must be absolute")
        script_pins = (
            run_production_readiness.parse_python_script_digest_pins(loaded)
            if launcher_enforced
            else {}
        )
    except Exception as exc:
        status["error"] = str(exc)
        return status, loaded, [f"production readiness config gate executable pin is invalid: {exc}"]
    command = [
        python_executable,
        "scripts/verify_production_readiness.py",
            "--mode",
            "config",
            "--expected-control-plane-uid",
            str(expected_control_plane_uid),
            "--expected-control-plane-gid",
            str(expected_control_plane_gid),
            "--out",
            str(config_out),
    ]
    common = {
        "cwd": ROOT,
        "env": env,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "check": False,
        "text": True,
    }
    if launcher_enforced:
        script_path = str((ROOT / "scripts" / "verify_production_readiness.py").resolve())
        script_setting, script_digest = script_pins[script_path]
        result = run_production_readiness.run_measured_python_script(
            command,
            python_setting=PRODUCTION_PYTHON_EXECUTABLE_SETTING,
            python_expected_digest=executable_manifest[PRODUCTION_PYTHON_EXECUTABLE_SETTING],
            script_setting=script_setting,
            script_expected_digest=script_digest,
            **common,
        )
    else:
        result = run_production_readiness.run_measured_command(
            command,
            setting=PRODUCTION_PYTHON_EXECUTABLE_SETTING,
            expected_digest=executable_manifest[PRODUCTION_PYTHON_EXECUTABLE_SETTING],
            **common,
        )
    config_gate: dict[str, Any] = {
        "ok": result.returncode == 0,
        "out": str(config_out),
        "secret_values_redacted": True,
    }
    if config_out.exists():
        config_gate["file"] = handoff.file_summary(config_out, "production-readiness-config")
        try:
            config_gate["semantic_sha256"] = semantic_result_digest(config_out)
        except Exception:
            config_gate["semantic_sha256"] = None
    if result.returncode == 0:
        try:
            parsed = json.loads(result.stdout)
            config_gate["result_sha256"] = parsed.get("result_sha256")
        except json.JSONDecodeError:
            config_gate["result_sha256"] = None
    else:
        config_gate["error"] = "production readiness config gate failed; see config output artifact"
        failures.append("production readiness config gate failed")
    status["config_gate"] = config_gate
    status["ok"] = not failures
    return status, loaded, failures


def production_images_env_check(path: Path) -> tuple[dict[str, Any], str, list[str]]:
    status = handoff.production_images_env_status(path)
    if path.exists():
        status["file"] = handoff.file_summary(path, "production-images-env")
    status["ok"] = status["status"] == "valid"
    if status["ok"]:
        raw = merge_production_images_env.load_images_fragment(path)
        return status, raw, []
    return status, "", [f"production images env is {status['status']}: {status.get('error', path)}"]


def env_merge_check(loaded_env: dict[str, str], production_images_value: str) -> tuple[dict[str, Any], list[str]]:
    env_value = loaded_env.get(merge_production_images_env.KEY, "")
    status = {
        "ok": env_value == production_images_value,
        "key": merge_production_images_env.KEY,
        "production_env_has_key": bool(env_value),
        "matches_images_env": env_value == production_images_value,
        "secret_values_redacted": True,
    }
    if status["ok"]:
        return status, []
    return status, ["production readiness env does not match .tmp/production-images.env CATCHPLATE_PRODUCTION_IMAGES"]


def published_images_check(
    path: Path,
    *,
    production_images: dict[str, Any],
    expected_images: list[dict[str, str]],
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {
        "ok": False,
        "path": str(path),
        "exists": False,
        "secret_values_redacted": True,
    }
    if not path.exists():
        return status, [f"production images published artifact does not exist: {path}"]
    failures: list[str] = []
    try:
        published = handoff.load_json(path, "production images published artifact")
        if published.get("ok") is not True:
            raise ValueError("production images published artifact is not ok")
        build_by_service = {
            str(item["service"]): item
            for item in production_images.get("images", [])
            if isinstance(item, dict) and item.get("service") and item.get("image_id")
        }
        expected_refs = sorted(item["ref"] for item in expected_images)
        expected_digests = sorted(item["digest"] for item in expected_images)
        images = published.get("images")
        if not isinstance(images, list) or not images:
            raise ValueError("production images published artifact has no images")
        published_refs: list[str] = []
        published_digests: list[str] = []
        published_services: list[str] = []
        for item in images:
            if not isinstance(item, dict):
                raise ValueError(f"published image entry must be an object: {item!r}")
            service = str(item.get("service") or "")
            if not service:
                raise ValueError("published image entry is missing service")
            local_image_id = handoff.require_sha256(item.get("local_image_id"), f"{service} local_image_id")
            expected_build = build_by_service.get(service)
            if expected_build is None:
                raise ValueError(f"published image service is not in current build artifact: {service}")
            if local_image_id != str(expected_build["image_id"]):
                raise ValueError(
                    "published production images do not match current no-shell build: "
                    f"service={service} published={local_image_id} build={expected_build['image_id']}"
                )
            handoff.require_sha256(item.get("remote_image_id"), f"{service} remote_image_id")
            if service == "catchplate-decision-gate":
                published_binary = handoff.require_sha256(item.get("binary_digest"), "published decision-gate binary digest")
                expected_binary = handoff.require_sha256(expected_build.get("binary_digest"), "built decision-gate binary digest")
                if published_binary != expected_binary:
                    raise ValueError("published decision-gate executable does not match the measured build executable")
            repo_digest = item.get("repo_digest")
            if not isinstance(repo_digest, str):
                raise ValueError(f"{service} repo_digest must be a digest-pinned ref")
            parsed = merge_production_images_env.validate_production_images(repo_digest)
            published_refs.append(parsed[0]["ref"])
            published_digests.append(parsed[0]["digest"])
            published_services.append(service)
        if sorted(published_services) != sorted(build_by_service):
            raise ValueError(
                "published production image services do not match current build artifact: "
                f"published={sorted(published_services)} build={sorted(build_by_service)}"
            )
        if sorted(published_refs) != expected_refs:
            raise ValueError(
                "published production image refs do not match .tmp/production-images.env: "
                f"published={sorted(published_refs)} env={expected_refs}"
            )
        remote_no_shell = published.get("remote_no_shell")
        if not isinstance(remote_no_shell, dict) or remote_no_shell.get("ok") is not True:
            raise ValueError("published production images did not pass remote no-shell verification")
        env_value = published.get("env") if isinstance(published.get("env"), dict) else {}
        if env_value.get(merge_production_images_env.KEY) and env_value[merge_production_images_env.KEY] != ",".join(expected_refs):
            raise ValueError("published artifact env value does not match .tmp/production-images.env")
        status.update(
            {
                "file": handoff.file_summary(path, "production-images-published"),
                "source_build_file": published.get("source_build_file"),
                "services": sorted(published_services),
                "repo_digests": sorted(published_refs),
                "image_digests": sorted(published_digests),
                "expected_image_digests": expected_digests,
            }
        )
    except Exception as exc:
        failures.append(f"production images published artifact is invalid: {exc}")
        status["error"] = str(exc)
    status["ok"] = not failures
    return status, failures


def artifact_check(
    args: argparse.Namespace,
    expected_images: list[dict[str, str]],
    expected_binary_digest: str | None,
    configured: dict[str, str],
) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    status: dict[str, Any] = {"ok": False}
    try:
        release_trust = handoff.release_trust_from_config(configured)
        production_images = handoff.verify_production_images_build(Path(args.production_images_build), check_current_tree=True)
        published_images, published_failures = published_images_check(
            Path(args.production_images_published),
            production_images=production_images,
            expected_images=expected_images,
        )
        failures.extend(published_failures)
        launch_authority = handoff.launch_authority_binding(
            production_images,
            "production images host preflight evidence",
        )
        release_summary = handoff.verify_summary(
            Path(args.release_provenance_summary),
            label="release provenance summary",
            pass_key="release_provenance",
            digest_key="provenance_digest",
            expected_launch_authority=launch_authority,
        )
        image_summary = handoff.verify_summary(
            Path(args.image_signatures_summary),
            label="image signatures summary",
            pass_key="image_signatures",
            digest_key="image_signature_bundle_digest",
        )
        bench = handoff.verify_bench(Path(args.bench))
        production_gate_binary = next(
            (
                item.get("binary_digest")
                for item in production_images["images"]
                if item.get("service") == "catchplate-decision-gate"
            ),
            None,
        )
        if production_gate_binary != bench["data_plane_binary_digest"]:
            raise ValueError("decision-gate benchmark binary digest does not match the production image binary")
        if not expected_binary_digest:
            raise ValueError("production env is missing CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST")
        if bench["data_plane_binary_digest"] != expected_binary_digest:
            raise ValueError(
                "decision-gate benchmark binary digest does not match "
                "CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST"
            )
        production_launcher_binary = next(
            (
                item.get("launcher_binary_digest")
                for item in production_images["images"]
                if item.get("service") == "catchplate-decision-gate"
            ),
            None,
        )
        production_launcher_binary = handoff.require_sha256(
            production_launcher_binary,
            "production image launcher binary digest",
        )
        release_document = handoff.verify_release_provenance_document(
            Path(args.release_provenance),
            summary_digest=release_summary["digest"],
            expected_source_tree_digest=production_images["source_tree_digest"],
            expected_launcher_binary_digest=production_launcher_binary,
            expected_launch_authority=launch_authority,
            expected_reproducible_build_verification_sha256=handoff.require_sha256(
                release_summary.get("reproducible_build_verification_sha256"),
                "release provenance summary reproducible build verification digest",
            ),
            trust=release_trust,
        )
        signatures = handoff.image_signature_scope(
            Path(args.image_signatures),
            [item["image_id"] for item in production_images["images"]],
            summary_digest=image_summary["digest"],
            expected_provenance_digest=release_summary["digest"],
            expected_published_image_digests=[item["digest"] for item in expected_images],
            expected_published_image_refs=[item["ref"] for item in expected_images],
            expected_release_bindings=release_document,
            trust=release_trust,
        )
        if signatures["covers_published_production_images"] is not True:
            failures.append("image signatures do not cover the published production image digests")
        if signatures["covers_published_production_image_refs"] is not True:
            failures.append("image signatures do not cover the published production image refs")
        status.update(
            {
                "production_images": production_images,
                "production_images_published": published_images,
                "release_provenance": release_summary,
                "release_provenance_document": release_document,
                "image_signatures_summary": image_summary,
                "image_signatures": signatures,
                "bench": bench,
            }
        )
    except Exception as exc:
        failures.append(f"release artifact check failed: {exc}")
        status["error"] = str(exc)
    status["ok"] = not failures
    return status, failures


def release_security_evidence_check(
    args: argparse.Namespace,
    release_artifacts: dict[str, Any],
    production_env: dict[str, str],
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {"ok": False, "secret_values_redacted": True}
    failures: list[str] = []
    try:
        launcher_enforced = launcher_bound_readiness(production_env)
        trust_roots: dict[str, dict[str, Any]] = {}
        if launcher_enforced:
            trust_roles = {
                "policy_identity": (
                    args.policy_trusted_public_key,
                    args.policy_trusted_public_key_id,
                    run_production_readiness.POLICY_TRUST_ROOT_ENV,
                    run_production_readiness.POLICY_TRUST_ROOT_ID_ENV,
                ),
                "policy_activation": (
                    args.policy_activation_trusted_public_key,
                    args.policy_activation_trusted_public_key_id,
                    run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV,
                    run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
                ),
                "reproducible_build": (
                    args.reproducible_build_trusted_public_key,
                    args.reproducible_build_trusted_public_key_id,
                    run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV,
                    run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
                ),
            }
            for role, (selected_path, selected_id, path_setting, id_setting) in trust_roles.items():
                pinned_path = production_env.get(path_setting)
                pinned_id = production_env.get(id_setting)
                if selected_path != pinned_path:
                    raise ValueError(
                        f"selected {role} trust root path does not exactly match {path_setting}"
                    )
                if selected_id is not None and selected_id != pinned_id:
                    raise ValueError(
                        f"selected {role} trust root ID does not exactly match {id_setting}"
                    )
                if not isinstance(pinned_id, str) or run_production_readiness.SHA256_RE.fullmatch(
                    pinned_id
                ) is None:
                    raise ValueError(f"{id_setting} must be sha256:<64 lowercase hex>")
                key_bytes, _metadata, report = snapshot_runtime_material(
                    Path(str(pinned_path)),
                    f"{role} trust root",
                    max_bytes=64 * 1024,
                )
                public_key = serialization.load_pem_public_key(key_bytes)
                spki = public_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                actual_id = "sha256:" + hashlib.sha256(spki).hexdigest()
                if not hmac.compare_digest(actual_id, pinned_id):
                    raise ValueError(
                        f"{role} trust root bytes do not match the hashed production env SPKI pin"
                    )
                trust_roots[role] = {
                    **report,
                    "spki_sha256": actual_id,
                    "verified": True,
                }
            if len({item["spki_sha256"] for item in trust_roots.values()}) != len(
                trust_roots
            ):
                raise ValueError(
                    "policy identity, activation, and reproducible-build trust roots must be distinct"
                )
        identity = verify_production_policy_identity.verify_persisted_report(
            bundle_path=Path(args.policy_bundle),
            trusted_public_key_path=Path(args.policy_trusted_public_key),
            report_path=Path(args.policy_identity_verification),
        )
        bench = release_artifacts.get("bench") or {}
        if bench.get("policy_hash") != identity["policyHash"]:
            raise ValueError("decision-gate benchmark policy hash does not match the identity-verified policy")
        if launcher_enforced and identity.get("trustedPublicKeySha256") != trust_roots[
            "policy_identity"
        ]["sha256"]:
            raise ValueError("policy identity verifier did not use the snapshotted trust-root bytes")

        activation = production_release_input_preflight.verify_externally_signed_report(
            report_path=Path(args.policy_activation_verification),
            signature_path=Path(args.policy_activation_signature),
            trusted_public_key_path=Path(args.policy_activation_trusted_public_key),
            purpose=production_release_input_preflight.ACTIVATION_PURPOSE,
            api_version=production_release_input_preflight.ACTIVATION_API_VERSION,
            kind=production_release_input_preflight.ACTIVATION_KIND,
        )
        if activation["report"].get("production_mode") is not True or activation["report"].get("environment") != "production":
            raise ValueError("policy activation verification is not production evidence")
        if activation["report"].get("candidate_policy_hash") != identity["policyHash"]:
            raise ValueError("policy activation candidate hash does not match the identity-verified policy")
        if launcher_enforced and activation.get("trustedPublicKeySha256") != trust_roots[
            "policy_activation"
        ]["sha256"]:
            raise ValueError("policy activation verifier did not use the snapshotted trust-root bytes")

        reproducibility = production_release_input_preflight.verify_externally_signed_report(
            report_path=Path(args.reproducible_build_verification),
            signature_path=Path(args.reproducible_build_signature),
            trusted_public_key_path=Path(args.reproducible_build_trusted_public_key),
            purpose=production_release_input_preflight.REPRODUCIBILITY_PURPOSE,
            api_version=production_release_input_preflight.REPRODUCIBILITY_API_VERSION,
            kind=production_release_input_preflight.REPRODUCIBILITY_KIND,
        )
        reproducibility_report = reproducibility["report"]
        if reproducibility_report.get("reproducible") is not True:
            raise ValueError("reproducible-build verification did not prove matching artifacts")
        reproducibility_scope = reproducibility_report.get("scope")
        if not isinstance(reproducibility_scope, dict) or reproducibility_scope.get("independent_execution_proven") is not True:
            raise ValueError("reproducible-build verification did not prove two independent trusted builders")
        production_images = release_artifacts.get("production_images") or {}
        if reproducibility_report.get("source_tree_digest") != production_images.get("source_tree_digest"):
            raise ValueError("reproducible-build source digest does not match the production build")
        expected_images = {
            item.get("service"): item.get("image_id")
            for item in production_images.get("images") or []
            if isinstance(item, dict)
        }
        reproduced_images = {
            item.get("service"): item.get("image_id")
            for item in reproducibility_report.get("images") or []
            if isinstance(item, dict)
        }
        if reproduced_images != expected_images:
            raise ValueError("reproducible-build image IDs do not match the production build")
        production_gate = next(
            (item for item in production_images.get("images") or [] if item.get("service") == "catchplate-decision-gate"),
            {},
        )
        reproduced_gate = next(
            (item for item in reproducibility_report.get("images") or [] if item.get("service") == "catchplate-decision-gate"),
            {},
        )
        if reproduced_gate.get("rust_binary_sha256") != production_gate.get("binary_digest"):
            raise ValueError("reproducible-build Rust binary digest does not match the production build")
        if launcher_enforced and reproducibility.get("trustedPublicKeySha256") != trust_roots[
            "reproducible_build"
        ]["sha256"]:
            raise ValueError("reproducible-build verifier did not use the snapshotted trust-root bytes")
        status.update(
            {
                "trust_roots": trust_roots,
                "policy_identity": identity,
                "policy_activation": {key: value for key, value in activation.items() if key != "report"},
                "reproducible_builds": {
                    **{key: value for key, value in reproducibility.items() if key != "report"},
                    "scope": reproducibility_scope,
                    "sourceTreeDigest": reproducibility_report.get("source_tree_digest"),
                    "productionBuildBound": True,
                },
                "benchmarkPolicyBound": True,
            }
        )
    except Exception as exc:
        failures.append(f"release security evidence check failed: {exc}")
        status["error"] = str(exc)
    status["ok"] = not failures
    return status, failures


def release_artifact_mounts_check(
    env: dict[str, str],
    *,
    release_provenance: Path,
    image_signatures: Path,
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {"ok": False, "artifacts": [], "secret_values_redacted": True}
    failures: list[str] = []
    expected = {
        "release-provenance": (
            Path(env.get("CATCHPLATE_RELEASE_PROVENANCE_FILE", "")),
            release_provenance,
        ),
        "image-signatures": (
            Path(env.get("CATCHPLATE_IMAGE_SIGNATURES_FILE", "")),
            image_signatures,
        ),
    }
    for label, (mounted_path, approved_path) in expected.items():
        item: dict[str, Any] = {
            "label": label,
            "mounted_path": str(mounted_path),
            "approved_path": str(approved_path),
        }
        if not mounted_path.is_absolute():
            failures.append(f"{label} production mount path must be absolute")
        elif mounted_path.is_symlink():
            failures.append(f"{label} production mount path must not be a symlink: {mounted_path}")
        elif not mounted_path.is_file() or mounted_path.stat().st_size == 0:
            failures.append(f"{label} production mount artifact is missing or empty: {mounted_path}")
        elif not approved_path.is_file():
            failures.append(f"{label} approved release artifact is missing: {approved_path}")
        else:
            mounted_summary = handoff.file_summary(mounted_path, f"mounted-{label}")
            approved_summary = handoff.file_summary(approved_path, f"approved-{label}")
            mode = stat.S_IMODE(mounted_path.stat().st_mode)
            item.update(
                {
                    "sha256": mounted_summary["sha256"],
                    "bytes": mounted_summary["bytes"],
                    "mode": oct(mode),
                    "matches_approved_artifact": mounted_summary["sha256"] == approved_summary["sha256"],
                }
            )
            if mode & 0o022:
                failures.append(f"{label} production mount artifact must not be writable by group/other")
            if mounted_summary["sha256"] != approved_summary["sha256"]:
                failures.append(f"{label} production mount artifact does not match the approved release artifact")
        status["artifacts"].append(item)
    status["ok"] = not failures
    return status, failures


def production_compose_check(
    *,
    compose_file: Path,
    env_file: Path,
    expected_images: list[dict[str, str]],
    expected_digest: str | None,
    skip_host_check: bool,
    production_env: dict[str, str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {
        "ok": False,
        "skipped": skip_host_check,
        "file": str(compose_file),
        "secret_values_redacted": True,
    }
    if skip_host_check:
        status["ok"] = True
        return status, []
    try:
        if production_env is None:
            production_env = run_production_readiness.load_env_file(env_file)
        executable_manifest = run_production_readiness.parse_executable_digest_manifest(
            production_env,
            expected_settings=set(PINNED_EXECUTABLE_COMMAND_SETTINGS),
        )
        docker_executable = production_env.get(PRODUCTION_DOCKER_EXECUTABLE_SETTING, "")
        if not Path(docker_executable).is_absolute():
            raise ValueError(f"{PRODUCTION_DOCKER_EXECUTABLE_SETTING} must be absolute")
        docker_toolchain = run_production_readiness.validate_docker_toolchain_settings(
            production_env
        )
        compose_plugin = docker_toolchain[DOCKER_COMPOSE_PLUGIN_EXECUTABLE_SETTING]
        compose_plugin_sha256 = docker_toolchain[DOCKER_COMPOSE_PLUGIN_SHA256_SETTING]
        compose_project_name = docker_toolchain[
            run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV
        ]
        docker_env = run_production_readiness.docker_subprocess_environment(
            run_production_readiness.build_final_child_environment(production_env)
            if launcher_bound_readiness(production_env)
            else dict(os.environ),
            Path(docker_toolchain[run_production_readiness.DOCKER_UNIX_SOCKET_ENV]),
        )
        docker_socket_path = Path(
            docker_toolchain[run_production_readiness.DOCKER_UNIX_SOCKET_ENV]
        )
        docker_endpoint = f"unix://{docker_socket_path}"
        launcher_enforced = launcher_bound_readiness(production_env)
        daemon_before = None
        if launcher_enforced:
            daemon_before = run_production_readiness.verify_docker_daemon_identity(
                docker_executable=Path(docker_executable),
                docker_sha256=executable_manifest[PRODUCTION_DOCKER_EXECUTABLE_SETTING],
                socket_path=docker_socket_path,
                expected_daemon_id=docker_toolchain[
                    run_production_readiness.DOCKER_DAEMON_ID_ENV
                ],
                base_env=run_production_readiness.build_final_child_environment(production_env),
            )
        refs = {item.get("name"): item.get("ref") for item in expected_images}
        images = {
            "catchplate-control": {"repo_digests": [refs["control"]]},
            "catchplate-decision-gate": {"repo_digests": [refs["decision-gate"]]},
        }
        original_run = generate_release_provenance.run
        original_load_env = generate_release_provenance.run_production_readiness.load_env_file

        def measured_docker_run(args: list[str], *, input_bytes: bytes | None = None) -> str:
            if len(args) < 2 or args[:2] != ["docker", "compose"]:
                raise ValueError("production Compose renderer attempted an unpinned executable")
            command = [
                compose_plugin,
                "--host",
                docker_endpoint,
                *args[2:],
            ]
            result = run_production_readiness.run_measured_command(
                command,
                setting=DOCKER_COMPOSE_PLUGIN_EXECUTABLE_SETTING,
                expected_digest=compose_plugin_sha256,
                cwd=ROOT,
                env=docker_env,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=input_bytes is None,
            )
            if result.returncode != 0:
                detail = result.stderr.strip() or result.stdout.strip()
                raise ValueError(f"pinned Docker command failed with exit {result.returncode}: {detail}")
            return result.stdout.strip()

        generate_release_provenance.run = measured_docker_run
        generate_release_provenance.run_production_readiness.load_env_file = lambda _path: dict(production_env)
        try:
            canonical_model, summary = generate_release_provenance.production_compose_model(
                compose_file=compose_file,
                env_file=env_file,
                images=images,
            )
        finally:
            generate_release_provenance.run = original_run
            generate_release_provenance.run_production_readiness.load_env_file = original_load_env
        status.update(summary)
        rendered_model = json.loads(canonical_model)
        runtime_model = run_production_readiness.normalize_compose_runtime_model(
            rendered_model
        )
        status["runtime_model"] = runtime_model
        status["runtime_model_sha256"] = runtime_model["sha256"]
        if launcher_enforced:
            daemon_after = run_production_readiness.verify_docker_daemon_identity(
                docker_executable=Path(docker_executable),
                docker_sha256=executable_manifest[PRODUCTION_DOCKER_EXECUTABLE_SETTING],
                socket_path=docker_socket_path,
                expected_daemon_id=docker_toolchain[
                    run_production_readiness.DOCKER_DAEMON_ID_ENV
                ],
                base_env=run_production_readiness.build_final_child_environment(production_env),
            )
            run_production_readiness.require_stable_docker_daemon_binding(
                daemon_before,
                daemon_after,
            )
            status["docker_daemon_before"] = daemon_before
            status["docker_daemon_after"] = daemon_after
        status["docker_executable"] = docker_executable
        status["docker_sha256"] = executable_manifest[PRODUCTION_DOCKER_EXECUTABLE_SETTING]
        status["compose_plugin_executable"] = compose_plugin
        status["compose_plugin_sha256"] = compose_plugin_sha256
        status["compose_project_name"] = compose_project_name
        status["docker_unix_socket"] = docker_toolchain[
            run_production_readiness.DOCKER_UNIX_SOCKET_ENV
        ]
        status["docker_daemon_id"] = docker_toolchain[
            run_production_readiness.DOCKER_DAEMON_ID_ENV
        ]
        if summary["sha256"] != expected_digest:
            raise ValueError(
                "rendered production Compose digest does not match signed release provenance: "
                f"rendered={summary['sha256']} provenance={expected_digest}"
            )
        status["ok"] = True
        return status, []
    except Exception as exc:
        status["error"] = str(exc)
        return status, [f"production Compose check failed: {exc}"]


def ciphertext_blob(config: dict[str, Any], material: str) -> bytes:
    path = config.get("ciphertext_blob_path") or config.get("ciphertextBlobPath")
    if isinstance(path, str) and path:
        data, _metadata, _report = snapshot_runtime_material(
            Path(path),
            f"material {material} ciphertext blob",
            max_bytes=8 * 1024 * 1024,
        )
        return data
    raw = config.get("ciphertext_blob_b64") or config.get("ciphertextBlobB64")
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"material {material} missing ciphertext blob")
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
    except Exception as exc:
        raise ValueError(f"material {material} ciphertext blob is invalid base64") from exc


def kms_materials_check(path: Path) -> tuple[dict[str, Any], list[str]]:
    status: dict[str, Any] = {
        "ok": False,
        "path": str(path),
        "exists": path.exists(),
        "materials": [],
        "secret_values_redacted": True,
    }
    failures: list[str] = []
    try:
        kms_bytes, kms_metadata, kms_report = snapshot_runtime_material(
            path,
            "KMS materials file",
            private=True,
            max_bytes=8 * 1024 * 1024,
        )
        mode = stat.S_IMODE(kms_metadata.st_mode)
        status["exists"] = True
        status["mode"] = oct(mode)
        parsed = json.loads(kms_bytes.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("KMS materials file must be a JSON object")
        prepare_aws_kms_materials.reject_secret_fields(parsed)
        missing = sorted(REQUIRED_MATERIALS - set(parsed))
        if missing:
            failures.append(f"KMS materials file is missing required materials: {missing}")
        unexpected = sorted(set(parsed) - REQUIRED_MATERIALS)
        if unexpected:
            failures.append(f"KMS materials file contains unauthorized materials: {unexpected}")
        materials = []
        for material in sorted(parsed):
            config = parsed[material]
            if not isinstance(config, dict):
                raise ValueError(f"material {material} config must be an object")
            key_id = config.get("key_id") or config.get("keyId") or config.get("kms_key_id")
            if not isinstance(key_id, str) or not key_id:
                raise ValueError(f"material {material} missing key_id")
            ciphertext = ciphertext_blob(config, material)
            context = config.get("encryption_context") or config.get("encryptionContext") or {}
            if not isinstance(context, dict):
                raise ValueError(f"material {material} encryption_context must be an object")
            materials.append(
                {
                    "material": material,
                    "key_id_sha256": handoff.sha256_prefixed_bytes(key_id.encode("utf-8")),
                    "ciphertext_blob_sha256": handoff.sha256_prefixed_bytes(ciphertext),
                    "encryption_context_sha256": handoff.sha256_prefixed_bytes(canonical_json(context).encode("utf-8")),
                }
            )
        status["materials"] = materials
        status["file"] = kms_report
    except Exception as exc:
        failures.append(f"KMS materials file is invalid: {exc}")
    status["ok"] = not failures
    return status, failures


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Preflight trusted-host readiness inputs without claiming final "
            "Nitro execution or action authority."
        )
    )
    parser.add_argument("--env-file", default="ops/production-readiness.env")
    parser.add_argument(
        "--launcher-trusted-production-env-path",
        default=os.getenv(run_production_readiness.LAUNCHER_TRUSTED_ENV_PATH_INPUT),
    )
    parser.add_argument(
        "--launcher-trusted-production-env-sha256",
        default=os.getenv(run_production_readiness.LAUNCHER_TRUSTED_ENV_SHA256_INPUT),
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
    parser.add_argument("--compose-file", default="docker-compose.production.yml")
    parser.add_argument("--production-images-env", default=".tmp/production-images.env")
    parser.add_argument("--production-images-published", default=".tmp/production-images-published.json")
    parser.add_argument("--production-images-build", default=".tmp/production-images-build.json")
    parser.add_argument("--release-provenance-summary", default=".tmp/release-provenance-summary.json")
    parser.add_argument("--release-provenance", default=".tmp/release-provenance.json")
    parser.add_argument("--image-signatures-summary", default=".tmp/image-signatures-summary.json")
    parser.add_argument("--image-signatures", default=".tmp/image-signatures.json")
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
    parser.add_argument("--kms-materials", default="/etc/catchplate/kms-materials.json")
    parser.add_argument("--expected-control-plane-uid", type=int, default=CONTROL_PLANE_RUNTIME_UID)
    parser.add_argument("--expected-control-plane-gid", type=int, default=CONTROL_PLANE_RUNTIME_UID)
    parser.add_argument("--config-out", default=".tmp/production-host-preflight-config.json")
    parser.add_argument("--out", default=".tmp/production-host-preflight.json")
    parser.add_argument(
        "--skip-host-check",
        action="store_true",
        help="Test-only bypass for local trusted-host readiness fixture checks.",
    )
    parser.add_argument("--skip-config-gate", action="store_true", help="Only validate env parsing, not the production config gate.")
    args = parser.parse_args()
    enforce_test_only_bypass(args)
    try:
        enforce_readiness_only_preflight_boundary(args)
    except Exception as exc:
        print(f"production host preflight launcher error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    failures: list[str] = []
    host, host_failures = host_check(skip_host_check=args.skip_host_check)
    failures.extend(host_failures)
    env, loaded_env, env_failures = env_check(
        Path(args.env_file),
        production_images_env=Path(args.production_images_env),
        config_out=Path(args.config_out),
        skip_config_gate=args.skip_config_gate,
        expected_control_plane_uid=args.expected_control_plane_uid,
        expected_control_plane_gid=args.expected_control_plane_gid,
        launcher_trusted_env_path=args.launcher_trusted_production_env_path,
        launcher_trusted_env_sha256=args.launcher_trusted_production_env_sha256,
        launcher_nonce_rollback_assurance_pins=(
            args.launcher_nonce_rollback_assurance_pins
        ),
        launcher_nonce_rollback_assurance_pins_sha256=(
            args.launcher_nonce_rollback_assurance_pins_sha256
        ),
        launcher_nonce_rollback_assurance_contract_sha256=(
            args.launcher_nonce_rollback_assurance_contract_sha256
        ),
    )
    failures.extend(env_failures)
    runtime_trust, runtime_trust_failures = runtime_trust_materials_check(
        loaded_env,
        skip_host_check=args.skip_host_check,
    )
    failures.extend(runtime_trust_failures)
    oauth_secret_mounts, oauth_secret_mount_failures = oauth_secret_mounts_check(
        loaded_env,
        skip_host_check=args.skip_host_check,
    )
    failures.extend(oauth_secret_mount_failures)
    response_signing_key_custody, response_signing_key_custody_failures = (
        response_signing_key_custody_check(
            loaded_env,
            skip_host_check=args.skip_host_check,
            expected_control_plane_uid=args.expected_control_plane_uid,
        )
    )
    failures.extend(response_signing_key_custody_failures)
    response_v2_release_transparency, response_v2_release_transparency_failures = (
        response_v2_release_transparency_inputs_check(
            loaded_env,
            skip_host_check=args.skip_host_check,
        )
    )
    failures.extend(response_v2_release_transparency_failures)
    images_env, images_value, images_failures = production_images_env_check(Path(args.production_images_env))
    failures.extend(images_failures)
    merge_status, merge_failures = env_merge_check(loaded_env, images_value) if loaded_env and images_value else (
        {"ok": False, "secret_values_redacted": True},
        ["production image env merge cannot be verified"],
    )
    failures.extend(merge_failures)
    expected_images = images_env.get("images") if isinstance(images_env.get("images"), list) else []
    artifacts, artifact_failures = artifact_check(
        args,
        [item for item in expected_images if isinstance(item, dict)],
        loaded_env.get("CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST") if loaded_env else None,
        loaded_env,
    )
    failures.extend(artifact_failures)
    release_security, release_security_failures = release_security_evidence_check(
        args,
        artifacts,
        loaded_env,
    )
    failures.extend(release_security_failures)
    compose_status, compose_failures = production_compose_check(
        compose_file=Path(args.compose_file),
        env_file=Path(args.env_file),
        expected_images=[item for item in expected_images if isinstance(item, dict)],
        expected_digest=(artifacts.get("release_provenance_document") or {}).get("compose_config_sha256"),
        skip_host_check=args.skip_host_check,
        production_env=loaded_env,
    )
    failures.extend(compose_failures)
    artifact_mounts, artifact_mount_failures = release_artifact_mounts_check(
        loaded_env,
        release_provenance=Path(args.release_provenance),
        image_signatures=Path(args.image_signatures),
    )
    failures.extend(artifact_mount_failures)
    kms, kms_failures = kms_materials_check(Path(args.kms_materials))
    failures.extend(kms_failures)

    result = {
        "apiVersion": "catchplate.productionHostPreflight/v1",
        "kind": "ProductionHostPreflight",
        "ok": not failures,
        "verification_mode": READINESS_MODE,
        "readiness_only": True,
        "final_nitro_execution_proven": False,
        "ok_for_action": False,
        "generated_at_unix": int(time.time()),
        "authority_boundary": env.get(
            "authority_boundary",
            validate_readiness_authority_boundary(
                readiness_authority_boundary(launcher_evidence_verified=False)
            ),
        ),
        "checks": {
            "host": host,
            "production_env": env,
            "nonce_rollback_assurance": env.get(
                "nonce_rollback_assurance",
                {
                    "apiVersion": (
                        run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
                    ),
                    "enforcement": "not-native-launcher-enforced",
                    "verified": False,
                },
            ),
            "runtime_trust_materials": runtime_trust,
            "oauth_secret_mounts": oauth_secret_mounts,
            "response_signing_key_custody": response_signing_key_custody,
            "response_v2_release_transparency": response_v2_release_transparency,
            "production_images_env": images_env,
            "production_images_env_merge": merge_status,
            "production_compose": compose_status,
            "release_artifacts": artifacts,
            "release_security_evidence": release_security,
            "release_artifact_mounts": artifact_mounts,
            "kms_materials": kms,
        },
        "failures": failures,
        "next_command": "make run-production-readiness PRODUCTION_READINESS_ENV=ops/production-readiness.env" if not failures else None,
        "secret_values_redacted": True,
    }
    if launcher_bound_readiness(loaded_env):
        try:
            publication_time = int(time.time())
            revalidate_launcher_readiness_at_publication(
                initial_receipt=env.get("launcher_trust", {}).get(
                    "bootstrap_receipt"
                ),
                nonce_rollback_assurance=env.get("nonce_rollback_assurance"),
                now_unix_seconds=publication_time,
            )
            result["authenticity"] = sign_readiness_preflight(
                result,
                loaded_env,
                signed_at_unix=publication_time,
            )
        except Exception as exc:
            result["ok"] = False
            result["failures"].append(
                "production host readiness preflight authenticity signing "
                f"failed: {exc}"
            )
            result["next_command"] = None
    write_result(Path(args.out), result)
    print(canonical_json(result))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
