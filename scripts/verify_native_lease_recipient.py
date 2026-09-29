#!/usr/bin/env python3
"""Configured, fail-closed verifier for native X25519 lease-recipient evidence.

This is a distinct profile, not the RSA/KMS verifier or a production activation
switch. The invoking app must supply its genuinely derived full request digest,
key identity and scope. The quote binds that digest; the echoed scope fields
are not additional standalone signed claims. A successful stdout object is a
process-local app-verifier result, not a signed or transferable admission token.

Both configuration originals require independent CLI digest pins before JSON
parsing. Their provenance/currentness, the app-to-process handoff and the local
clock remain caller responsibilities. No trust input is taken from evidence,
the environment or the request. This process performs no network lookup and
does not reserve a nonce; the existing app owns nonce reservation after success.
The fixed native PKI profile requires an empty CRL inventory per AWS's native
attestation contract; it supplies no vendor-CRL revocation proof. Independently
current pins and app-level revocation remain mandatory.

Independently pinned expectations v2 explicitly selects the native lease request
profile. It requires the app's exact leaseRequestApiVersion marker in input and
echoes it in output; expectations v1 retains its old input/output contract. The
evidence never selects a request profile, and neither profile falls back to the
other. Only the native principal bound is widened; other native IDs retain the
existing producer's 256-byte predicate.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import re
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from verify_nitro_tee import (
    MAX_CERT_BYTES,
    MAX_CERTIFICATES,
    VerificationError,
    b64url_decode,
    b64url_decode_exact,
    basic_constraints,
    canonical_json_bytes,
    certificate_sha256,
    exact_keys,
    parse_json,
    read_regular,
    require,
    require_positive_uint,
    require_sha256,
    require_sha384,
    require_uint,
    sha256,
    verify_native_recipient_nitro_document,
)

EVIDENCE_VERSION = "serverware.nativeCredentialRecipientEvidence/v1"
EXPECTATIONS_VERSION = "serverware.nativeCredentialRecipientExpectations/v1"
NATIVE_EXPECTATIONS_VERSION = "serverware.nativeCredentialRecipientExpectations/v2"
NATIVE_REQUEST_PROFILE = "serverware.nativeCredentialLeaseRequest"
NATIVE_REQUEST_V1 = NATIVE_REQUEST_PROFILE + "/v1"
NATIVE_REQUEST_V2 = NATIVE_REQUEST_PROFILE + "/v2"
TRUST_ROOTS_VERSION = "serverware.nativeCredentialRecipientTrustRoots/v1"
BINDING_DOMAIN = b"serverware/enclave-runtime-key-binding/v1\0"
MAX_INPUT_BYTES = 64 * 1024
MAX_EXPECTATIONS_BYTES = 16 * 1024
MAX_TRUST_ROOTS_BYTES = 1024 * 1024
MAX_DOCUMENT_BYTES = 12 * 1024
MAX_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 30

EXPECTATION_FIELDS = {
    "apiVersion", "releaseRecordSha256", "policyHash", "configurationSha256",
    "caCertificateSha256", "caPublicKeySpkiSha256", "expectedBinaryDigest",
    "expectedPcrs", "expectedEif", "expectedModuleId", "maxAgeSeconds",
    "futureSkewSeconds",
}
SCOPE_FIELDS = (
    "purpose", "requestBindingSha256", "recipientKeyId", "recipientNonce",
    "policyHash", "dataPlaneBinaryDigest", "principalId", "routeId",
    "credentialId",
)


def _pinned_json(path: Path, pin: str, label: str, cap: int) -> Any:
    require_sha256(pin, f"{label} independent digest")
    raw = read_regular(path, label=label, max_bytes=cap)
    require(hmac.compare_digest(sha256(raw), pin), f"{label} independent digest mismatch")
    return parse_json(raw, label)


def _digest_bytes(value: Any, label: str) -> bytes:
    value = require_sha256(value, label)
    original = bytes.fromhex(value.removeprefix("sha256:"))
    require(original != bytes(32), f"{label} must be nonzero")
    return original


def _text(value: Any, label: str, maximum: int) -> str:
    require(
        isinstance(value, str)
        and 1 <= len(value.encode("utf-8")) <= maximum
        and not any(ord(char) < 32 or ord(char) == 127 for char in value),
        f"{label} is invalid",
    )
    return value


def _expectations(document: Any, *, api_version: str = EXPECTATIONS_VERSION,
                  extra_fields: frozenset[str] = frozenset()) -> dict[str, Any]:
    expected = exact_keys(document, EXPECTATION_FIELDS | extra_fields, "native recipient expectations")
    require(expected["apiVersion"] == api_version, "expectations version mismatch")
    for field in (
        "releaseRecordSha256", "policyHash", "configurationSha256",
        "caCertificateSha256", "caPublicKeySpkiSha256", "expectedBinaryDigest",
    ):
        _digest_bytes(expected[field], field)
    pcrs = expected["expectedPcrs"]
    require(isinstance(pcrs, dict) and 3 <= len(pcrs) <= 32
            and {"PCR0", "PCR1", "PCR2"}.issubset(pcrs)
            and all(isinstance(name, str)
                    and re.fullmatch(r"PCR(?:[0-9]|[12][0-9]|3[01])", name) is not None
                    for name in pcrs), "expected complete PCR inventory is invalid")
    for name, value in pcrs.items():
        require_sha384(value, name)
        if name in {"PCR0", "PCR1", "PCR2"}:
            require(value != "sha384:" + "0" * 96, "debug core PCR expectations are forbidden")
        # Every additional locked register, including any reserved zero value,
        # must be independently pinned and matched; none is learned from a quote.
    require_sha384(expected["expectedEif"], "expected EIF")
    require(expected["expectedEif"] == pcrs["PCR0"], "expected EIF does not match PCR0")
    _text(expected["expectedModuleId"], "expected module ID", 256)
    require_positive_uint(expected["maxAgeSeconds"], "maximum quote age", maximum=MAX_AGE_SECONDS)
    require_uint(expected["futureSkewSeconds"], "maximum future skew", maximum=MAX_FUTURE_SKEW_SECONDS)
    return expected


def _recipient_expectations(document: Any) -> dict[str, Any]:
    # This document has already matched an independent CLI digest pin. Never
    # choose the profile from stdin, evidence or a copied verification result.
    if isinstance(document, dict) and document.get("apiVersion") == NATIVE_EXPECTATIONS_VERSION:
        expected = _expectations(
            document, api_version=NATIVE_EXPECTATIONS_VERSION,
            extra_fields=frozenset({"leaseRequestProfile"}),
        )
        require(expected["leaseRequestProfile"] == NATIVE_REQUEST_PROFILE,
                "native lease request profile mismatch")
        return expected
    return _expectations(document)


def _native_identity(value: Any, label: str, maximum: int) -> str:
    value = _text(value, label, maximum)
    require(value == value.strip()
            and not any(unicodedata.category(char) == "Cc" for char in value),
            f"{label} is invalid")
    return value


def _trust_roots(document: Any, *, api_version: str = TRUST_ROOTS_VERSION) -> tuple[list[x509.Certificate], list[x509.CertificateRevocationList], dict[str, Any]]:
    trust = exact_keys(document, {
        "apiVersion", "awsNitroRootCertificatesPem", "awsNitroCrlsDerBase64url",
        "nitroCertificateProfile",
    }, "native recipient trust roots")
    require(trust["apiVersion"] == api_version, "trust-root version mismatch")
    roots_input = trust["awsNitroRootCertificatesPem"]
    require(isinstance(roots_input, list) and 1 <= len(roots_input) <= MAX_CERTIFICATES,
            "Nitro root inventory is invalid")
    roots: list[x509.Certificate] = []
    for pem in roots_input:
        require(isinstance(pem, str) and 1 <= len(pem) <= MAX_CERT_BYTES, "Nitro root PEM is invalid")
        try:
            encoded = pem.encode("ascii")
            certificate = x509.load_pem_x509_certificate(encoded)
        except (ValueError, UnicodeEncodeError) as exc:
            raise VerificationError("Nitro root PEM cannot be parsed") from exc
        require(certificate.public_bytes(serialization.Encoding.PEM) == encoded,
                "Nitro root must be one canonical PEM certificate")
        require(basic_constraints(certificate, "Nitro root").ca, "Nitro root is not a CA")
        roots.append(certificate)
    require(len({certificate_sha256(root) for root in roots}) == len(roots), "Nitro roots repeat")
    crls_input = trust["awsNitroCrlsDerBase64url"]
    require(crls_input == [], "native Nitro profile requires an empty CRL inventory")
    crls: list[x509.CertificateRevocationList] = []
    profile = exact_keys(trust["nitroCertificateProfile"],
                         {"profileId", "allowedLeafExtendedKeyUsageOids"}, "Nitro certificate profile")
    require(profile["profileId"] == "aws-nitro-attestation-pki-native-v1", "unsupported native Nitro certificate profile")
    oids = profile["allowedLeafExtendedKeyUsageOids"]
    require(isinstance(oids, list) and len(oids) <= 32
            and all(isinstance(oid, str) and len(oid) <= 128
                    and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", oid) is not None for oid in oids),
            "Nitro certificate EKU inventory is invalid")
    require(oids == sorted(set(oids)), "Nitro certificate EKUs must be sorted and unique")
    return roots, crls, profile


def _verify_request(raw: bytes, expected: dict[str, Any],
                    roots: list[x509.Certificate], crls: list[x509.CertificateRevocationList],
                    profile: dict[str, Any]) -> dict[str, Any]:
    require(1 <= len(raw) <= MAX_INPUT_BYTES, "native recipient verifier input exceeds its bound")
    request = parse_json(raw, "native recipient verifier input")
    require(isinstance(request, dict), "native recipient verifier input must be an object")
    native = expected["apiVersion"] == NATIVE_EXPECTATIONS_VERSION
    fields = set(SCOPE_FIELDS) | {"recipientAttestation"}
    if native:
        fields.add("leaseRequestApiVersion")
    has_authority = "requestAuthoritySha256" in request
    if has_authority:
        fields.add("requestAuthoritySha256")
    request = exact_keys(request, fields, "native recipient verifier input")
    require(request["purpose"] in ("generationMetadata", "dispatchSecret"), "unknown credential purpose")
    if native:
        version = request["leaseRequestApiVersion"]
        require(version in (NATIVE_REQUEST_V1, NATIVE_REQUEST_V2),
                "native lease request version mismatch")
        require((version == NATIVE_REQUEST_V1 and not has_authority)
                or (version == NATIVE_REQUEST_V2 and has_authority
                    and request["purpose"] == "dispatchSecret"),
                "native lease request authority profile mismatch")
    if has_authority:
        require(request["purpose"] == "dispatchSecret", "generation metadata cannot carry request authority")
        _digest_bytes(request["requestAuthoritySha256"], "request authority digest")
    request_binding = _digest_bytes(request["requestBindingSha256"], "request binding")
    for field in ("recipientKeyId", "policyHash", "dataPlaneBinaryDigest"):
        _digest_bytes(request[field], field)
    for field in ("principalId", "routeId", "credentialId"):
        if native:
            _native_identity(request[field], field, 1024 if field == "principalId" else 256)
        else:
            _text(request[field], field, 1024)
    require(request["policyHash"] == expected["policyHash"], "request policy does not match independent expectations")
    require(request["dataPlaneBinaryDigest"] == expected["expectedBinaryDigest"], "request binary does not match independent expectations")
    nonce = b64url_decode_exact(request["recipientNonce"], "recipient nonce", exact_bytes=32)
    evidence = exact_keys(request["recipientAttestation"],
                          {"apiVersion", "attestationDocumentB64", "recipientPublicKey"}, "native recipient evidence")
    require(evidence["apiVersion"] == EVIDENCE_VERSION, "native recipient evidence version mismatch")
    key = b64url_decode_exact(evidence["recipientPublicKey"], "recipient public key", exact_bytes=32)
    require(key != bytes(32), "recipient public key is zero")
    require(hmac.compare_digest(sha256(key), request["recipientKeyId"]), "recipient public key identity mismatch")
    document = b64url_decode(evidence["attestationDocumentB64"], "original NSM document", max_bytes=MAX_DOCUMENT_BYTES)
    require(bool(document), "original NSM document is empty")
    user_data = BINDING_DOMAIN + b"\x02" + b"".join(
        _digest_bytes(expected[field], field)
        for field in ("releaseRecordSha256", "policyHash", "configurationSha256",
                      "caCertificateSha256", "caPublicKeySpkiSha256")
    ) + hashlib.sha256(key).digest() + request_binding
    # The real app derives the full request digest; these echoed fields are
    # request scope, not independent signed fields extracted from the quote.
    now = time.time_ns() // 1_000_000_000
    require(now > 0, "local verifier time is invalid")
    verified = verify_native_recipient_nitro_document(
        document, expected_public_key=key, expected_user_data_bytes=user_data,
        challenge=nonce, expected_pcrs=expected["expectedPcrs"],
        expected_eif=expected["expectedEif"], roots=roots, crls=crls,
        certificate_profile=profile, expected_module_id=expected["expectedModuleId"],
        now=now, max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"],
    )
    finished = time.time_ns() // 1_000_000_000
    require(finished >= now, "local verifier time moved backwards")
    issued_at = require_uint(verified["issuedAtUnix"], "verified quote issue time")
    require(issued_at <= finished + expected["futureSkewSeconds"]
            and finished - issued_at <= expected["maxAgeSeconds"], "quote expired during verification")
    require(verified["recipientPublicKeySha256"] == request["recipientKeyId"]
            and verified["recipientPublicKeyRawB64"] == evidence["recipientPublicKey"],
            "verified native key identity mismatch")
    result = {"ok": True, "debug": False}
    result.update({field: request[field] for field in SCOPE_FIELDS})
    if native:
        result["leaseRequestApiVersion"] = request["leaseRequestApiVersion"]
    if has_authority:
        result["requestAuthoritySha256"] = request["requestAuthoritySha256"]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--expectations", type=Path, required=True)
    parser.add_argument("--expectations-sha256", required=True)
    parser.add_argument("--trust-roots", type=Path, required=True)
    parser.add_argument("--trust-roots-sha256", required=True)
    args = parser.parse_args()
    expected = _recipient_expectations(_pinned_json(
        args.expectations, args.expectations_sha256,
        "native recipient expectations", MAX_EXPECTATIONS_BYTES,
    ))
    roots, crls, profile = _trust_roots(_pinned_json(args.trust_roots, args.trust_roots_sha256,
                                                  "native recipient trust roots", MAX_TRUST_ROOTS_BYTES))
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    result = _verify_request(raw, expected, roots, crls, profile)
    original = canonical_json_bytes(result)
    require(len(original) + 1 <= MAX_INPUT_BYTES, "native recipient verifier output exceeds its bound")
    sys.stdout.buffer.write(original + b"\n")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except (VerificationError, OSError, ValueError, TypeError, KeyError, OverflowError):
        # No copied verdict, permissive fallback or exception detail on stdout.
        print("native credential recipient verification failed", file=sys.stderr)
        raise SystemExit(1)
