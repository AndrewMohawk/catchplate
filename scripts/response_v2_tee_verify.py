#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
import time
import types
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MAX_NITRO_VERIFIER_MODULE_BYTES = 2 * 1024 * 1024


def bootstrap_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise RuntimeError(f"{label} fields do not match the closed contract")
    return value


def bootstrap_parse_json(raw: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise RuntimeError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise RuntimeError(f"non-finite JSON number is forbidden: {value}")

    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
    )
    if type(value) is not dict:
        raise RuntimeError("response-v2 verifier request must be a JSON object")
    return value


def load_pinned_nitro_verifier(module_input: Any) -> types.ModuleType:
    descriptor_input = bootstrap_exact_keys(
        module_input,
        {"path", "sha256"},
        "response-v2 Nitro verifier module input",
    )
    path_raw = descriptor_input["path"]
    expected = descriptor_input["sha256"]
    if not isinstance(path_raw, str) or not path_raw.startswith("/"):
        raise RuntimeError("response-v2 Nitro verifier module path must be absolute")
    if not isinstance(expected, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", expected) is None:
        raise RuntimeError("response-v2 Nitro verifier module requires an independent SHA-256 pin")
    descriptor = os.open(
        path_raw,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > MAX_NITRO_VERIFIER_MODULE_BYTES
        ):
            raise RuntimeError("pinned Nitro verifier module is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise RuntimeError("pinned Nitro verifier module changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mode != after.st_mode
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    ):
        raise RuntimeError("pinned Nitro verifier module changed during authentication")
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise RuntimeError("pinned Nitro verifier module SHA-256 mismatch")
    module_name = "catchplate_pinned_verify_nitro_tee"
    module = types.ModuleType(module_name)
    module.__file__ = path_raw
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        exec(compile(raw, path_raw, "exec", dont_inherit=True), module.__dict__)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module


nitro: types.ModuleType


REQUEST_VERSION = "catchplate.responseObservationV2AttestationVerifyRequest/v2"
RESULT_VERSION = "catchplate.responseObservationV2AttestationVerifyResult/v2"
EXPECTATIONS_VERSION = (
    "catchplate.responseObservationV2NitroVerifierExpectations/v1"
)
FRESH_ATTESTATION_VERSION = (
    "catchplate.responseObservationFreshResponseAttestation/v1"
)
FRESH_ATTESTATION_SIGNATURE_DOMAIN = (
    b"catchplate.response-v2/fresh-hardware-proof/v1\0"
)
NITRO_EVIDENCE_FORMAT = "catchplate.teeEvidence.nitroDocumentBundle.cbor/v1"
REPORT_DATA_DOMAIN = b"catchplate.response-v2/fresh-tee-report-data/v1"
NITRO_USER_DATA_PREFIX = b"catchplate.response-v2/nitro-user-data/v1\0"
MAX_REQUEST_BYTES = 256 * 1024
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA384_RE = re.compile(r"^sha384:[0-9a-f]{96}$")
CHALLENGE_RE = re.compile(r"^hardware-proof-challenge-[0-9a-f]{64}$")

EXPECTED_FIELDS = {
    "attestationMode",
    "custodyBootId",
    "custodyMeasurementSha256",
    "externalWitnessCount",
    "faultDomainCount",
    "faultTolerance",
    "generationId",
    "outputManifestSha256",
    "proofPinsRootSha256",
    "providerGeneration",
    "quorumThreshold",
    "releaseTransparencyTrustPinSha256",
    "requestSha256",
    "roleIdentityRootSha256",
    "securityClaim",
    "signerKeySha256",
    "sourceCommitSha256",
    "sourceTreeSha256",
    "teeBoundary",
    "topologyProfile",
    "unsignedResponseSha256",
    "verifierExecutableSha256",
    "verifierModuleSha256",
    "expectationsSha256",
    "trustRootsSha256",
}
STATIC_EXPECTED_FIELDS = EXPECTED_FIELDS - {
    "custodyBootId",
    "expectationsSha256",
    "outputManifestSha256",
    "requestSha256",
    "trustRootsSha256",
    "unsignedResponseSha256",
    "verifierExecutableSha256",
    "verifierModuleSha256",
}
ATTESTATION_FIELDS = {
    "apiVersion",
    "attestationEvidenceBase64",
    "attestationEvidenceFormat",
    "attestationEvidenceRetrievalId",
    "attestationEvidenceSha256",
    "attestationMode",
    "authenticatedSessionSha256",
    "challengeNonce",
    "clientIdentitySha256",
    "currentRevocationReceiptSha256",
    "custodyBootId",
    "custodyExecutableMeasurementSha256",
    "custodyKeyMaterialSha256",
    "custodyProviderConfigSha256",
    "custodyTeeMeasurementSha256",
    "deadlineAtEpochMs",
    "expiresAtEpochMs",
    "issuedAtEpochMs",
    "monotonicDeadline",
    "outputManifestSha256",
    "proofIndependentPinsRootSha256",
    "providerGeneration",
    "requestSha256",
    "revocationEpoch",
    "roleIdentityRootSha256",
    "signature",
    "signatureAlgorithm",
    "signerKey",
    "signerKeyId",
    "signerKeyMaterialSha256",
    "signerProviderId",
    "teeReportBinding",
    "trustCheckpointSha256",
    "trustEvidence",
    "unsignedResponseSha256",
}
TEE_REPORT_FIELDS = {
    "authenticatedSessionSha256",
    "challengeNonce",
    "custodyMeasurementSha256",
    "outputManifestSha256",
    "providerGeneration",
    "reportDataSha256",
    "signerKeySha256",
    "unsignedResponseSha256",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise nitro.VerificationError(message)


def require_sha256(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{label} is not SHA-256")
    return value


def require_uint(value: Any, label: str) -> int:
    require(type(value) is int and 0 <= value <= (1 << 63) - 1, f"{label} is not a signed-64 unsigned integer")
    return value


def strict_standard_base64(value: Any, label: str, *, maximum: int) -> bytes:
    require(isinstance(value, str) and value, f"{label} is empty")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise nitro.VerificationError(f"{label} is not canonical standard base64") from exc
    require(1 <= len(raw) <= maximum, f"{label} size is invalid")
    require(base64.b64encode(raw).decode("ascii") == value, f"{label} is not canonical standard base64")
    return raw


def framed_sha256(values: list[bytes]) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return "sha256:" + digest.hexdigest()


def report_data_sha256(attestation: dict[str, Any]) -> str:
    report = nitro.exact_keys(
        attestation["teeReportBinding"],
        TEE_REPORT_FIELDS,
        "response-v2 TEE report binding",
    )
    generation = require_uint(report["providerGeneration"], "report providerGeneration")
    values = [REPORT_DATA_DOMAIN]
    for field in (
        "unsignedResponseSha256",
        "outputManifestSha256",
        "authenticatedSessionSha256",
        "challengeNonce",
        "signerKeySha256",
        "custodyMeasurementSha256",
    ):
        value = report[field]
        if field != "challengeNonce":
            require_sha256(value, f"report {field}")
        require(isinstance(value, str) and value.isascii(), f"report {field} is not ASCII")
        values.append(value.encode("ascii"))
    values.append(generation.to_bytes(8, "big"))
    calculated = framed_sha256(values)
    require(report["reportDataSha256"] == calculated, "response-v2 reportDataSha256 does not match the exact response binding")
    return calculated


def measured_verifier_input(value: Any, label: str) -> tuple[str, str]:
    descriptor = nitro.exact_keys(value, {"path", "sha256"}, label)
    path_raw = descriptor["path"]
    expected_digest = descriptor["sha256"]
    require(
        isinstance(path_raw, str) and path_raw.startswith("/"),
        f"{label} path must be absolute",
    )
    require_sha256(expected_digest, f"{label} SHA-256")
    return path_raw, expected_digest


def load_expectations(
    verifier_inputs: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    path_raw, expected_digest = measured_verifier_input(
        verifier_inputs["expectations"],
        "response-v2 Nitro expectations input",
    )
    trust_path_raw, independently_expected_trust_digest = measured_verifier_input(
        verifier_inputs["trustRoots"],
        "response-v2 Nitro trust-roots input",
    )
    document, raw = nitro.load_json_file(Path(path_raw), "response-v2 Nitro expectations")
    require(nitro.sha256(raw) == expected_digest, "response-v2 Nitro expectations digest differs from the independent pin")
    document = nitro.exact_keys(
        document,
        {"apiVersion", "nitro", "staticClaims", "trustRootsSha256"},
        "response-v2 Nitro expectations",
    )
    require(document["apiVersion"] == EXPECTATIONS_VERSION, "response-v2 Nitro expectations version mismatch")
    static_claims = nitro.exact_keys(
        document["staticClaims"],
        STATIC_EXPECTED_FIELDS,
        "response-v2 static claims",
    )
    nitro_expected = nitro.exact_keys(
        document["nitro"],
        {"eifSha384", "maxFutureSkewSeconds", "maxQuoteAgeSeconds", "moduleId", "pcrs"},
        "response-v2 Nitro measurements",
    )
    require(isinstance(nitro_expected["moduleId"], str) and nitro_expected["moduleId"], "Nitro moduleId is empty")
    require(
        isinstance(nitro_expected["eifSha384"], str)
        and SHA384_RE.fullmatch(nitro_expected["eifSha384"]) is not None,
        "Nitro EIF pin is not SHA-384",
    )
    pcrs = nitro.exact_keys(nitro_expected["pcrs"], {"PCR0", "PCR1", "PCR2"}, "response-v2 Nitro PCR pins")
    require(all(isinstance(value, str) and SHA384_RE.fullmatch(value) for value in pcrs.values()), "Nitro PCR pins are not exact SHA-384 values")
    require(pcrs["PCR0"] == nitro_expected["eifSha384"], "Nitro PCR0 does not equal the independently pinned EIF")
    max_age = require_uint(nitro_expected["maxQuoteAgeSeconds"], "Nitro maximum quote age")
    future_skew = require_uint(nitro_expected["maxFutureSkewSeconds"], "Nitro future skew")
    require(1 <= max_age <= 300, "Nitro maximum quote age must be 1-300 seconds")
    require(future_skew <= 30, "Nitro future skew must be at most 30 seconds")
    trust_digest = require_sha256(document["trustRootsSha256"], "Nitro trust-root bundle")
    require(
        trust_digest == independently_expected_trust_digest,
        "Nitro trust-root bundle differs from the independent verifier-input pin",
    )
    trust_document, trust_raw = nitro.load_json_file(Path(trust_path_raw), "response-v2 Nitro trust roots")
    trust = nitro.load_trust_roots(
        trust_document,
        trust_raw,
        independently_expected_sha256=trust_digest,
    )
    return document, trust


def verify_attestation_signature(attestation: dict[str, Any]) -> None:
    signer = nitro.exact_keys(
        attestation["signerKey"],
        {"kind", "publicKeyBase64", "publicKeySha256"},
        "response-v2 inline signer key",
    )
    require(signer["kind"] == "INLINE_ED25519_PUBLIC_KEY", "response-v2 signer key must be inline Ed25519")
    public_key = strict_standard_base64(signer["publicKeyBase64"], "response-v2 signer public key", maximum=32)
    require(len(public_key) == 32, "response-v2 signer public key must be 32 bytes")
    require_sha256(signer["publicKeySha256"], "response-v2 signer public-key digest")
    require(nitro.sha256(public_key) == signer["publicKeySha256"] == attestation["signerKeyMaterialSha256"], "response-v2 signer public key differs from its pin")
    signature = strict_standard_base64(attestation["signature"], "response-v2 attestation signature", maximum=64)
    require(len(signature) == 64, "response-v2 attestation signature must be 64 bytes")
    unsigned = dict(attestation)
    unsigned["signature"] = ""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            FRESH_ATTESTATION_SIGNATURE_DOMAIN + nitro.canonical_json_bytes(unsigned),
        )
    except InvalidSignature as exc:
        raise nitro.VerificationError("response-v2 attestation signature is invalid") from exc


def verify_request(request: Any) -> dict[str, Any]:
    request = nitro.exact_keys(
        request,
        {"apiVersion", "purpose", "attestation", "expected", "verifierInputs"},
        "response-v2 TEE verification request",
    )
    require(request["apiVersion"] == REQUEST_VERSION, "response-v2 TEE verification request version mismatch")
    require(request["purpose"] == "fresh-response", "response-v2 TEE verification purpose mismatch")
    verifier_inputs = nitro.exact_keys(
        request["verifierInputs"],
        {"module", "expectations", "trustRoots"},
        "response-v2 measured verifier inputs",
    )
    expected = nitro.exact_keys(request["expected"], EXPECTED_FIELDS, "response-v2 expected claims")
    attestation = nitro.exact_keys(request["attestation"], ATTESTATION_FIELDS, "response-v2 fresh attestation")
    expectations, trust = load_expectations(verifier_inputs)
    static_claims = expectations["staticClaims"]
    for field in STATIC_EXPECTED_FIELDS:
        require(expected[field] == static_claims[field], f"response-v2 expected {field} differs from the independent pin")
    for field in (
        "requestSha256",
        "unsignedResponseSha256",
        "outputManifestSha256",
        "signerKeySha256",
        "roleIdentityRootSha256",
        "proofPinsRootSha256",
        "releaseTransparencyTrustPinSha256",
        "sourceCommitSha256",
        "sourceTreeSha256",
        "custodyMeasurementSha256",
        "verifierExecutableSha256",
        "expectationsSha256",
        "trustRootsSha256",
    ):
        require_sha256(expected[field], f"expected {field}")
    module_input = verifier_inputs["module"]
    require(module_input is not None, "reference Nitro verifier requires a measured module input")
    _, module_sha256 = measured_verifier_input(
        module_input,
        "response-v2 Nitro verifier module input",
    )
    require(
        expected["verifierModuleSha256"] == module_sha256,
        "response-v2 verifier module differs from the descriptor-authenticated input",
    )
    _, expectations_sha256 = measured_verifier_input(
        verifier_inputs["expectations"],
        "response-v2 Nitro expectations input",
    )
    _, trust_roots_sha256 = measured_verifier_input(
        verifier_inputs["trustRoots"],
        "response-v2 Nitro trust-roots input",
    )
    require(
        expected["expectationsSha256"] == expectations_sha256,
        "response-v2 expectations differ from the descriptor-authenticated input",
    )
    require(
        expected["trustRootsSha256"] == trust_roots_sha256,
        "response-v2 trust roots differ from the descriptor-authenticated input",
    )
    for field in ("providerGeneration", "faultDomainCount", "quorumThreshold", "externalWitnessCount", "faultTolerance"):
        require_uint(expected[field], f"expected {field}")
    require(expected["attestationMode"] == "tee-hardware", "response-v2 verifier accepts only tee-hardware mode")
    require(
        expected["topologyProfile"] == "local-single-node-1-of-1"
        and expected["faultDomainCount"] == 1
        and expected["quorumThreshold"] == 1
        and expected["externalWitnessCount"] == 0
        and expected["faultTolerance"] == 0,
        "response-v2 topology differs from the explicit local 1-of-1 hardware profile",
    )
    require(attestation["apiVersion"] == FRESH_ATTESTATION_VERSION, "response-v2 fresh attestation version mismatch")
    require(attestation["attestationMode"] == "TEE_HARDWARE", "response-v2 evidence is not hardware mode")
    require(attestation["attestationEvidenceFormat"] == NITRO_EVIDENCE_FORMAT, "response-v2 evidence is not an AWS Nitro document")
    require(attestation["signatureAlgorithm"] == "ED25519", "response-v2 signature algorithm is not Ed25519")
    require(CHALLENGE_RE.fullmatch(attestation["challengeNonce"] or "") is not None, "response-v2 hardware challenge is invalid")
    bindings = {
        "requestSha256": "requestSha256",
        "unsignedResponseSha256": "unsignedResponseSha256",
        "outputManifestSha256": "outputManifestSha256",
        "custodyBootId": "custodyBootId",
        "signerKeyMaterialSha256": "signerKeySha256",
        "roleIdentityRootSha256": "roleIdentityRootSha256",
        "proofIndependentPinsRootSha256": "proofPinsRootSha256",
        "providerGeneration": "providerGeneration",
        "custodyTeeMeasurementSha256": "custodyMeasurementSha256",
    }
    for attestation_field, expected_field in bindings.items():
        require(attestation[attestation_field] == expected[expected_field], f"response-v2 {attestation_field} differs from the expected response")
    report = attestation["teeReportBinding"]
    for report_field, attestation_field in {
        "unsignedResponseSha256": "unsignedResponseSha256",
        "outputManifestSha256": "outputManifestSha256",
        "authenticatedSessionSha256": "authenticatedSessionSha256",
        "challengeNonce": "challengeNonce",
        "signerKeySha256": "signerKeyMaterialSha256",
        "custodyMeasurementSha256": "custodyTeeMeasurementSha256",
        "providerGeneration": "providerGeneration",
    }.items():
        require(report[report_field] == attestation[attestation_field], f"response-v2 report {report_field} is not bound to the signed attestation")
    calculated_report_data = report_data_sha256(attestation)
    verify_attestation_signature(attestation)
    evidence = strict_standard_base64(
        attestation["attestationEvidenceBase64"],
        "response-v2 Nitro attestation document",
        maximum=nitro.MAX_NITRO_BYTES,
    )
    require(nitro.sha256(evidence) == attestation["attestationEvidenceSha256"], "response-v2 Nitro document digest mismatch")
    nitro_expected = expectations["nitro"]
    user_data = NITRO_USER_DATA_PREFIX + bytes.fromhex(calculated_report_data.removeprefix("sha256:"))
    verified = nitro.verify_nitro_document(
        evidence,
        claims=None,
        expected_user_data_bytes=user_data,
        challenge=attestation["challengeNonce"].encode("ascii"),
        expected_pcrs=nitro_expected["pcrs"],
        expected_eif=nitro_expected["eifSha384"],
        roots=trust["awsRoots"],
        crls=trust["awsCrls"],
        certificate_profile=trust["certificateProfile"],
        expected_module_id=nitro_expected["moduleId"],
        now=int(time.time()),
        max_age=nitro_expected["maxQuoteAgeSeconds"],
        future_skew=nitro_expected["maxFutureSkewSeconds"],
    )
    require(verified["attestationDocumentSha256"] == attestation["attestationEvidenceSha256"], "verified Nitro document identity changed")
    return {
        "apiVersion": RESULT_VERSION,
        "ok": True,
        "claims": {
            "requestSha256": expected["requestSha256"],
            "unsignedResponseSha256": expected["unsignedResponseSha256"],
            "outputManifestSha256": expected["outputManifestSha256"],
            "custodyBootId": expected["custodyBootId"],
            "challengeNonce": attestation["challengeNonce"],
            "signerKeySha256": expected["signerKeySha256"],
            "attestationEvidenceSha256": attestation["attestationEvidenceSha256"],
            "reportDataSha256": calculated_report_data,
            "roleIdentityRootSha256": expected["roleIdentityRootSha256"],
            "proofPinsRootSha256": expected["proofPinsRootSha256"],
            "releaseTransparencyTrustPinSha256": expected["releaseTransparencyTrustPinSha256"],
            "generationId": expected["generationId"],
            "providerGeneration": expected["providerGeneration"],
            "sourceCommitSha256": expected["sourceCommitSha256"],
            "sourceTreeSha256": expected["sourceTreeSha256"],
            "custodyMeasurementSha256": expected["custodyMeasurementSha256"],
            "attestationMode": expected["attestationMode"],
            "topologyProfile": expected["topologyProfile"],
            "faultDomainCount": expected["faultDomainCount"],
            "quorumThreshold": expected["quorumThreshold"],
            "externalWitnessCount": expected["externalWitnessCount"],
            "faultTolerance": expected["faultTolerance"],
            "hardwareBacked": True,
            "quoteVerified": True,
            "debug": False,
            "teeBoundary": expected["teeBoundary"],
            "securityClaim": expected["securityClaim"],
            "verifierExecutableSha256": expected["verifierExecutableSha256"],
            "verifierModuleSha256": expected["verifierModuleSha256"],
            "expectationsSha256": expected["expectationsSha256"],
            "trustRootsSha256": expected["trustRootsSha256"],
        },
    }


def main() -> None:
    global nitro
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if not 1 <= len(raw) <= MAX_REQUEST_BYTES:
        raise RuntimeError("response-v2 verifier request size is invalid")
    bootstrap = bootstrap_parse_json(raw)
    bootstrap_exact_keys(
        bootstrap,
        {"apiVersion", "purpose", "attestation", "expected", "verifierInputs"},
        "response-v2 TEE verification request",
    )
    verifier_inputs = bootstrap_exact_keys(
        bootstrap["verifierInputs"],
        {"module", "expectations", "trustRoots"},
        "response-v2 measured verifier inputs",
    )
    if verifier_inputs["module"] is None:
        raise RuntimeError("reference Nitro verifier requires a measured module input")
    nitro = load_pinned_nitro_verifier(verifier_inputs["module"])
    request = nitro.parse_json(raw, "response-v2 TEE verification request")
    result = verify_request(request)
    sys.stdout.buffer.write(nitro.canonical_json_bytes(result) + b"\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"response-v2 Nitro verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
