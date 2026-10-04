"""Admit a root-signed local-attestation cohort after static configuration.

Peer launch observations remain assertions of the real receipt signer. Only
the selected local receipt is joined to this process's measured launch guard.
Neither descriptor custody nor the returned observation enrolls a trust root.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import authority_contract as authority
from . import authority_artifact_spec as artifact
from . import authority_launch_guard as guard
from .authority_artifact_spec import (
    ArtifactContractError,
    canonical_json_bytes,
    strict_base64url_decode,
)


SCHEMA = "serverware.signedTrustedHostLocalAttestationCohort/v1"
RECEIPT_SCHEMA = "serverware.trustedHostLocalAuthorityAttestation/v1"
MAX_BYTES = 4 * 1024 * 1024
ROLES = ("executor", "issuer", "planner", "planner-writer", "verifier")
_ENVELOPE_FIELDS = {"schema", "payload", "signature"}
_PAYLOAD_FIELDS = {
    "schema", "sourceRevision", "configurationDigest", "generationDigest",
    "operationManifestDigest", "artifactPackageDigest", "roleBindingDigests",
    "receipts", "issuedAtEpochNs", "expiresAtEpochNs",
}
_LOCAL_CLAIMS = {
    "trustMode": "trusted-host-local", "coLocated": True,
    "hardwareBacked": False, "nativeStageZero": False, "hsmBackedKeys": False,
    "teeVerified": False, "externalWitnessVerified": False,
}
_RECEIPT_FIELDS = {
    "schema", "role", "processMode", "configurationDigest", "sourceRevision",
    "launchManifestDigest", "runtimeClosureDigest", "operationManifestDigest",
    "generationDigest", "stageZeroRequestDigest", "artifactPackageDigest",
    "measurementDigest", "responseSigningSpkiDigest", "issuedAtEpochNs",
    "expiresAtEpochNs", *_LOCAL_CLAIMS,
}


class AttestationCohortError(ValueError):
    pass


@dataclass(frozen=True)
class _AdmittedCohort:
    cohort_bytes: bytes
    cohort_digest: str
    receipts: tuple[tuple[str, bytes, str], ...]
    generation_sequence: int
    generation_digest: str
    valid_from_epoch_ns: int
    valid_until_epoch_ns: int


def _domain_digest(domain: str, *frames: bytes) -> str:
    """Use the existing service receipt framing, not artifact framing."""
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(b"\0")
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def _digest(value: object, label: str) -> str:
    if (
        type(value) is not str or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise AttestationCohortError(f"{label} is not a canonical digest")
    return value


def _positive(value: object, label: str) -> int:
    if type(value) is not int or not 1 <= value <= 2**63 - 1:
        raise AttestationCohortError(f"{label} is not a positive bounded integer")
    return value


def _packages(value: object) -> dict[str, str]:
    if type(value) is not dict or not 1 <= len(value) <= 4096:
        raise AttestationCohortError("package inventory is not bounded")
    held = {}
    for name, version in value.items():
        if any(
            type(part) is not str or not part.isascii() or not 1 <= len(part) <= 256
            for part in (name, version)
        ):
            raise AttestationCohortError("package inventory contains invalid text")
        held[name] = version
    return held


def _static_configuration(value: object) -> tuple:
    if type(value) is not dict:
        raise AttestationCohortError("admitted configuration is not an object")
    roles = value.get("roles")
    bindings = value.get("roleBindingDigests")
    trust = value.get("credentialReleaseTrust")
    if (
        type(roles) is not dict or set(roles) != set(ROLES)
        or type(bindings) is not dict or set(bindings) != set(ROLES)
        or type(trust) is not dict
        or set(trust) != {"schema", "trustMode", "maximumReceiptAgeNs"}
        or trust["schema"] != "serverware.trustedHostLocalCredentialReleaseTrust/v1"
        or trust["trustMode"] != "trusted-host-local"
        or value.get("sourceRevision") != authority.SOURCE_REVISION
    ):
        raise AttestationCohortError("static local cohort policy is invalid")
    held_roles = {}
    held_bindings = {}
    for role in ROLES:
        entry = roles[role]
        if (
            type(entry) is not dict or type(entry.get("processMode")) is not str
            or entry["processMode"] != f"policy-authority-{role}"
        ):
            raise AttestationCohortError("static role policy is invalid")
        held_roles[role] = (
            entry["processMode"],
            _digest(entry.get("measurementDigest"), "role measurement"),
            _digest(entry.get("responseSigningSpkiDigest"), "role response key"),
        )
        held_bindings[role] = _digest(bindings[role], "static role binding")
    return (
        held_roles, held_bindings, _packages(value.get("packageVersions")),
        _positive(trust["maximumReceiptAgeNs"], "maximum receipt age"),
        _digest(value.get("issuerCredentialIssuanceDigest"), "issuer issuance"),
        _digest(value.get("executorCredentialIssuanceDigest"), "executor issuance"),
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise AttestationCohortError("cohort JSON repeats a member")
        result[name] = value
    return result


def _reject_constant(value: str) -> None:
    raise AttestationCohortError("cohort JSON contains a non-finite value")


def _bounded_json(value: object, depth: int = 0, remaining: list[int] | None = None) -> None:
    if remaining is None:
        remaining = [1024]
    remaining[0] -= 1
    if depth > 8 or remaining[0] < 0:
        raise AttestationCohortError("cohort JSON structure exceeds its fixed bound")
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise AttestationCohortError("cohort JSON has an invalid member")
            _bounded_json(item, depth + 1, remaining)
    elif type(value) is list:
        for item in value:
            _bounded_json(item, depth + 1, remaining)
    elif type(value) not in (str, int, bool, type(None)):
        raise AttestationCohortError("cohort JSON has an invalid scalar")


def _envelope(value: object, schema: str, fields: set[str]) -> dict:
    if (
        type(value) is not dict or set(value) != _ENVELOPE_FIELDS
        or value["schema"] != schema or type(value["signature"]) is not str
        or type(value["payload"]) is not dict or set(value["payload"]) != fields
        or value["payload"]["schema"] != schema
    ):
        raise AttestationCohortError("signed attestation object is not closed")
    return value["payload"]


def _verify_signature(envelope: dict, public_key: Ed25519PublicKey) -> None:
    try:
        signature = strict_base64url_decode(
            envelope["signature"], name="attestation signature", decoded_size=64,
        )
        public_key.verify(
            signature,
            _domain_digest(envelope["schema"], canonical_json_bytes(envelope["payload"])).encode("ascii"),
        )
    except (ArtifactContractError, InvalidSignature, ValueError) as exc:
        raise AttestationCohortError("attestation root signature is invalid") from exc


def _times(value: dict, maximum_age: int, now: int) -> tuple[int, int]:
    issued = _positive(value["issuedAtEpochNs"], "receipt issuance")
    expires = _positive(value["expiresAtEpochNs"], "receipt expiry")
    if not issued <= now < expires or not 0 < expires - issued <= maximum_age:
        raise AttestationCohortError("attestation is outside its original validity interval")
    return issued, expires


def _verify_cohort_against_scope(
    *, held_bytes: bytes, held_digest: str, held_key: Ed25519PublicKey,
    static_configuration: tuple, generation_sequence: int,
    generation_digest: str, package_digest: str,
    local_binding: tuple[str, str, str] | None,
    evaluation_epoch_ns: int | None,
) -> tuple[_AdmittedCohort, dict, tuple[dict, ...]]:
    roles, bindings, measured_packages, maximum_age, issuer_issuance, executor_issuance = static_configuration
    try:
        envelope = json.loads(
            held_bytes, object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _bounded_json(envelope)
        if canonical_json_bytes(envelope) != held_bytes:
            raise AttestationCohortError("cohort originals are not canonical")
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ArtifactContractError) as exc:
        raise AttestationCohortError("cohort originals are not bounded canonical JSON") from exc
    payload = _envelope(envelope, SCHEMA, _PAYLOAD_FIELDS)
    receipts = payload["receipts"]
    if type(receipts) is not list or len(receipts) != len(ROLES):
        raise AttestationCohortError("cohort must contain exactly five role receipts")
    inner_payloads = tuple(_envelope(value, RECEIPT_SCHEMA, _RECEIPT_FIELDS) for value in receipts)
    if tuple(value["role"] for value in inner_payloads) != ROLES:
        raise AttestationCohortError("cohort receipts are not the exact sorted role inventory")
    _verify_signature(envelope, held_key)
    if (
        payload["sourceRevision"] != authority.SOURCE_REVISION
        or payload["configurationDigest"] != held_digest
        or payload["generationDigest"] != generation_digest
        or payload["operationManifestDigest"] != authority.OPERATION_MANIFEST_DIGEST
        or payload["artifactPackageDigest"] != package_digest
        or type(payload["roleBindingDigests"]) is not dict
        or payload["roleBindingDigests"] != bindings
    ):
        raise AttestationCohortError("signed cohort scope differs from independent admission")
    now = (
        _positive(time.time_ns(), "current attestation time")
        if evaluation_epoch_ns is None else evaluation_epoch_ns
    )
    cohort_issued, cohort_expires = _times(payload, maximum_age, now)
    admitted = []
    packages_raw = None
    for peer, receipt, observed in zip(ROLES, receipts, inner_payloads):
        _verify_signature(receipt, held_key)
        peer_launch = _digest(observed["launchManifestDigest"], "peer launch manifest")
        peer_request = _digest(observed["stageZeroRequestDigest"], "peer stage-zero request")
        if packages_raw is None:
            # Reuse this invocation's owned inventory bytes at the original
            # first-serialization point; no signatures or live checks are cached.
            packages_raw = canonical_json_bytes(measured_packages)
        expected_closure = _domain_digest(
            "serverware.policyAuthorityRuntimeClosure/v2",
            peer_launch.encode("ascii"), packages_raw,
        )
        if (
            observed["processMode"] != roles[peer][0]
            or observed["configurationDigest"] != held_digest
            or observed["sourceRevision"] != authority.SOURCE_REVISION
            or observed["operationManifestDigest"] != authority.OPERATION_MANIFEST_DIGEST
            or observed["generationDigest"] != generation_digest
            or observed["artifactPackageDigest"] != package_digest
            or observed["measurementDigest"] != roles[peer][1]
            or observed["responseSigningSpkiDigest"] != roles[peer][2]
            or observed["runtimeClosureDigest"] != expected_closure
            or any(
                type(observed[field]) is not type(expected) or observed[field] != expected
                for field, expected in _LOCAL_CLAIMS.items()
            )
            or (
                local_binding is not None and peer == local_binding[0]
                and (peer_launch, peer_request) != local_binding[1:]
            )
        ):
            raise AttestationCohortError("role receipt differs from admitted scope or local observation")
        issued, expires = _times(observed, maximum_age, now)
        if cohort_issued < issued or cohort_expires > expires:
            raise AttestationCohortError("cohort validity extends beyond an original receipt")
        receipt_bytes = canonical_json_bytes(receipt)
        receipt_digest = _domain_digest(RECEIPT_SCHEMA, receipt_bytes)
        if (peer == "issuer" and receipt_digest == issuer_issuance) or (
            peer == "executor" and receipt_digest == executor_issuance
        ):
            raise AttestationCohortError("credential issuance is not a distinct receipt identity")
        admitted.append((peer, receipt_bytes, receipt_digest))

    result = _AdmittedCohort(
        held_bytes, _domain_digest(SCHEMA, held_bytes), tuple(admitted),
        generation_sequence, generation_digest, cohort_issued, cohort_expires,
    )
    return result, payload, inner_payloads


def _admit_on_current_launch(
    *, original_bytes: bytes, role: str, configuration_payload: dict,
    configuration_digest: str, root_public_key: Ed25519PublicKey,
) -> _AdmittedCohort:
    if type(original_bytes) is not bytes or not 2 <= len(original_bytes) <= MAX_BYTES:
        raise AttestationCohortError("cohort originals exceed the runtime evidence slot")
    if type(role) is not str or role not in ROLES:
        raise AttestationCohortError("cohort role is unsupported")
    held_bytes, held_role, held_key = original_bytes, role, root_public_key
    held_digest = _digest(configuration_digest, "configuration")
    static_configuration = _static_configuration(configuration_payload)
    _roles, bindings, packages, maximum_age, issuer_issuance, executor_issuance = static_configuration
    if not isinstance(held_key, Ed25519PublicKey):
        raise AttestationCohortError("admitted attestation root is not Ed25519")

    # Own actual launch observations before any receipt signature callback.
    generation = dict(guard.generation())
    assurance = dict(guard.launch_assurance())
    measured_packages = _packages(dict(guard.package_versions()))
    package_digest = _digest(guard.verified_artifact_package().package_digest, "actual package")
    launch_digest = _digest(guard.require_active(held_role), "actual launch manifest")
    generation_sequence = generation.get("sequence")
    if type(generation_sequence) is not int or not 0 <= generation_sequence <= 2**63 - 1:
        raise AttestationCohortError("actual generation sequence is not a bounded nonnegative integer")
    generation_digest = _digest(generation.get("digest"), "actual generation")
    local_request_digest = _digest(generation.get("stageZeroRequestDigest"), "actual stage-zero request")
    actual_bindings = generation.get("roleBindingDigests")
    if (
        assurance != {"schema": "serverware.authorityLaunchAssurance/v1", **_LOCAL_CLAIMS}
        or measured_packages != packages
        or generation.get("operationManifestDigest") != authority.OPERATION_MANIFEST_DIGEST
        or type(actual_bindings) is not dict or len(actual_bindings) > 256
        or any(actual_bindings.get(peer) != bindings[peer] for peer in ROLES)
        or issuer_issuance == executor_issuance
    ):
        raise AttestationCohortError("cohort policy differs from the admitted local launch")
    result, payload, inner_payloads = _verify_cohort_against_scope(
        held_bytes=held_bytes, held_digest=held_digest, held_key=held_key,
        static_configuration=static_configuration,
        generation_sequence=generation_sequence, generation_digest=generation_digest,
        package_digest=package_digest,
        local_binding=(held_role, launch_digest, local_request_digest),
        evaluation_epoch_ns=None,
    )
    if guard.require_active(held_role) != launch_digest:
        raise AttestationCohortError("local launch changed during cohort admission")
    # The same original intervals remain live through signatures, identity
    # projection and the final local custody check; no lifetime is renewed.
    final_now = _positive(time.time_ns(), "final attestation time")
    _times(payload, maximum_age, final_now)
    for observed in inner_payloads:
        _times(observed, maximum_age, final_now)
    return result


def _capture_historical_json(value: object, *, maximum: int, label: str) -> tuple[object, bytes]:
    """Own plain admitted JSON before receipt-key callbacks; not enrollment."""
    try:
        encoded = canonical_json_bytes(value)
        if not 2 <= len(encoded) <= maximum:
            raise AttestationCohortError(f"{label} exceeds its source byte limit")
        owned = json.loads(encoded, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ArtifactContractError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AttestationCohortError(f"{label} is not bounded JSON") from exc
    return owned, encoded


def _generation_time_ns(value: object, label: str) -> int:
    parsed = artifact._require_timestamp(value, name=label)
    delta = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000


def _admit_at_evaluation_time(
    *, original_bytes: bytes, configuration_payload: dict,
    configuration_digest: str, root_public_key: Ed25519PublicKey,
    generation_statement: dict, expected_generation_digest: str,
    expected_package_digest: str, role_manifests: list,
    package_versions: dict, evaluation_epoch_ns: int,
) -> _AdmittedCohort:
    """Verify historical originals under independently enrolled archive pins.

    The caller must admit the historical root, configuration and package from
    the current-root-authorized archive. These consistency checks neither
    establish journal lineage nor authorize a current launch or release.
    """
    if type(original_bytes) is not bytes or not 2 <= len(original_bytes) <= MAX_BYTES:
        raise AttestationCohortError("cohort originals exceed the runtime evidence slot")
    held_bytes, held_key = original_bytes, root_public_key
    held_digest = _digest(configuration_digest, "historical configuration")
    generation_digest = _digest(expected_generation_digest, "historical generation pin")
    package_digest = _digest(expected_package_digest, "historical package pin")
    evaluated = _positive(evaluation_epoch_ns, "original evaluation time")
    held_packages = _packages(package_versions)
    owned_config, config_bytes = _capture_historical_json(
        configuration_payload, maximum=authority.MAX_REQUEST_BYTES,
        label="historical configuration",
    )
    owned_generation, _ = _capture_historical_json(
        generation_statement, maximum=authority.MAX_RESULT_BYTES,
        label="historical generation",
    )
    owned_roles, _ = _capture_historical_json(
        role_manifests, maximum=authority.MAX_RESULT_BYTES,
        label="historical role manifests",
    )
    static_configuration = _static_configuration(owned_config)
    _roles, bindings, packages, _maximum_age, issuer_issuance, executor_issuance = static_configuration
    if not isinstance(held_key, Ed25519PublicKey):
        raise AttestationCohortError("admitted historical root is not Ed25519")
    try:
        actual_generation_digest = artifact.generation_statement_digest(owned_generation)
        actual_bindings = artifact.role_binding_digests(owned_roles)
        role_set_digest = artifact.domain_digest(
            "serverware.authorityRoleSet/v1", canonical_json_bytes(owned_roles),
        )
        configuration_binding = artifact.configuration_generation_binding_digest(owned_generation)
        runtime_closures = {
            peer: artifact.role_runtime_closure_digest(bindings[peer], packages)
            for peer in ROLES
        }
        valid_from = _generation_time_ns(owned_generation["validFrom"], "generation validFrom")
        valid_until = _generation_time_ns(owned_generation["validUntil"], "generation validUntil")
    except ArtifactContractError as exc:
        raise AttestationCohortError("historical generation or role scope is invalid") from exc
    configuration_schema = artifact.CONFIGURATION_PAYLOAD_SCHEMAS["authority-service"]
    if (
        owned_config.get("schema") != configuration_schema
        or _domain_digest(configuration_schema, config_bytes) != held_digest
        or actual_generation_digest != generation_digest
        or owned_generation["operationManifestDigest"] != authority.OPERATION_MANIFEST_DIGEST
        or owned_generation["trustMode"]["mode"] != "trusted-host-local"
        or not valid_from <= evaluated < valid_until
        or role_set_digest != owned_generation["roleSetDigest"]
        or sorted(entry["sha256"] for entry in owned_roles) != owned_generation["roleManifestDigests"]
        or any(actual_bindings.get(peer) != bindings[peer] for peer in ROLES)
        or owned_config.get("roleRuntimeClosureDigests") != runtime_closures
        or packages != held_packages
        or issuer_issuance == executor_issuance
        or type(owned_config.get("generationSequence")) is not int
        or owned_config.get("generationSequence") != owned_generation["sequence"]
        or owned_config.get("generationBindingDigest") != configuration_binding
        or owned_config.get("generationPredecessorDigest") != owned_generation["predecessorDigest"]
        or type(owned_config.get("generationMinimumRollbackSequence")) is not int
        or owned_config.get("generationMinimumRollbackSequence") != owned_generation["minimumRollbackSequence"]
        or not any(
            entry["role"] == "authority-service"
            and entry["payloadSchema"] == configuration_schema
            and entry["payloadDigest"] == held_digest
            for entry in owned_generation["configurationPayloadBindings"]
        )
    ):
        raise AttestationCohortError("historical cohort scope differs from independent archive admission")
    result, _payload, _receipts = _verify_cohort_against_scope(
        held_bytes=held_bytes, held_digest=held_digest, held_key=held_key,
        static_configuration=static_configuration,
        generation_sequence=owned_generation["sequence"],
        generation_digest=generation_digest, package_digest=package_digest,
        local_binding=None, evaluation_epoch_ns=evaluated,
    )
    return result
