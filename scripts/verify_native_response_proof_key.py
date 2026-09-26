#!/usr/bin/env python3
"""Verify one original role-4 native Ed25519 response-proof-key quote.

This fixed profile reuses real Nitro COSE/chain/PCR verification; neither the
RSA/KMS nor raw-X25519 lease profile is widened. Evidence supplies only original
quote bytes and a public key. Boot ID, proof SPKI identity, control-plane SPKI
identity, fresh challenge and complete scope come from independently pinned
expectations. No expectation is derived from a purported successful verdict.

The result is local verifier output, not transferable hardware admission, a
current witness, final response proof, key-possession proof or authorization.
Pin provenance/currentness, challenge freshness/one-use reservation, trusted
time and watchdog enforcement belong to the invoking authority. A role-4 quote
does not prove ledger anti-rollback or that any response was actually observed.
The shared expectedBinaryDigest is retained configuration metadata, not a
separate signed field in this quote; independent release/PCR admission must
establish its meaning. Native PKI supplies no vendor-CRL revocation proof.
No network, configuration mutation, key generation or activation is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from verify_native_lease_recipient import (
    BINDING_DOMAIN,
    MAX_DOCUMENT_BYTES,
    MAX_EXPECTATIONS_BYTES,
    MAX_TRUST_ROOTS_BYTES,
    _digest_bytes,
    _expectations as _scope_expectations,
    _pinned_json,
    _trust_roots,
)
from verify_nitro_tee import (
    VerificationError,
    _verify_nitro_document_common,
    b64url_decode,
    b64url_decode_exact,
    canonical_json_bytes,
    exact_keys,
    parse_json,
    require,
    require_uint,
    sha256,
)

EVIDENCE_VERSION = "serverware.nativeResponseProofKeyEvidence/v1"
EXPECTATIONS_VERSION = "serverware.nativeResponseProofKeyExpectations/v1"
TRUST_ROOTS_VERSION = "serverware.nativeResponseProofKeyTrustRoots/v1"
RESULT_VERSION = "serverware.nativeResponseProofKeyVerification/v1"
BOOT_BINDING_DOMAIN = b"serverware/native-proof-custody-boot/v1\0"
MAX_INPUT_BYTES = 32 * 1024
MAX_RESULT_BYTES = 4 * 1024
BOOT_EXPECTATION_FIELDS = frozenset({
    "bootId", "keyId", "controlPlaneResponseSigningKeyId", "nonce",
})


def _expectations(document: Any) -> dict[str, Any]:
    expected = _scope_expectations(
        document, api_version=EXPECTATIONS_VERSION,
        extra_fields=BOOT_EXPECTATION_FIELDS,
    )
    b64url_decode_exact(expected["bootId"], "expected boot ID", exact_bytes=32)
    b64url_decode_exact(expected["nonce"], "independent fresh challenge", exact_bytes=32)
    _digest_bytes(expected["keyId"], "expected proof SPKI key ID")
    _digest_bytes(expected["controlPlaneResponseSigningKeyId"], "expected control-plane SPKI key ID")
    return expected


def _verify_evidence(raw: bytes, expected: dict[str, Any],
                     roots: list[x509.Certificate], crls: list[x509.CertificateRevocationList],
                     profile: dict[str, Any]) -> dict[str, Any]:
    require(type(raw) is bytes and 1 <= len(raw) <= MAX_INPUT_BYTES,
            "native response-proof evidence exceeds its bound")
    evidence = exact_keys(parse_json(raw, "native response-proof evidence"),
                          {"apiVersion", "attestationDocumentB64", "responseProofPublicKey"},
                          "native response-proof evidence")
    require(evidence["apiVersion"] == EVIDENCE_VERSION, "native response-proof evidence version mismatch")
    key = b64url_decode_exact(evidence["responseProofPublicKey"], "raw Ed25519 proof key", exact_bytes=32)
    require(key != bytes(32), "raw Ed25519 proof key is zero")
    spki = Ed25519PublicKey.from_public_bytes(key).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Match the existing custody hello identity, NOT SHA256(raw Ed25519 key).
    require(hmac.compare_digest(sha256(spki), expected["keyId"]),
            "response-proof SPKI identity differs from independent expectations")
    boot = b64url_decode_exact(expected["bootId"], "expected boot ID", exact_bytes=32)
    nonce = b64url_decode_exact(expected["nonce"], "independent fresh challenge", exact_bytes=32)
    request_binding = hashlib.sha256(
        BOOT_BINDING_DOMAIN + boot
        + _digest_bytes(expected["keyId"], "expected proof SPKI key ID")
        + _digest_bytes(expected["controlPlaneResponseSigningKeyId"], "expected control-plane SPKI key ID")
    ).digest()
    require(request_binding != bytes(32), "response-proof boot commitment is zero")
    user_data = BINDING_DOMAIN + b"\x04" + b"".join(
        _digest_bytes(expected[field], field)
        for field in ("releaseRecordSha256", "policyHash", "configurationSha256",
                      "caCertificateSha256", "caPublicKeySpkiSha256")
    ) + hashlib.sha256(key).digest() + request_binding
    document = b64url_decode(evidence["attestationDocumentB64"], "original role-4 NSM document",
                             max_bytes=MAX_DOCUMENT_BYTES)
    require(bool(document), "original role-4 NSM document is empty")
    now = time.time_ns() // 1_000_000_000
    require(now > 0, "local verifier time is invalid")
    # The public lease wrapper intentionally accepts only role 2/X25519.
    # Reuse the genuine common native verifier unchanged, then enforce THIS
    # closed role-4 raw-Ed25519 profile; no generic algorithm/role option exists.
    payload, issued_at, _, _, _ = _verify_nitro_document_common(
        document, claims=None, expected_user_data_bytes=user_data,
        challenge=nonce, expected_pcrs=expected["expectedPcrs"],
        expected_eif=expected["expectedEif"], roots=roots, crls=crls,
        certificate_profile=profile, expected_module_id=expected["expectedModuleId"],
        now=now, max_age=expected["maxAgeSeconds"], future_skew=expected["futureSkewSeconds"],
        native_profile=True,
    )
    require(type(payload["public_key"]) is bytes
            and hmac.compare_digest(payload["public_key"], key),
            "signed role-4 key does not match the pinned raw Ed25519 key")
    finished = time.time_ns() // 1_000_000_000
    require(finished >= now, "local verifier time moved backwards")
    require_uint(issued_at, "verified quote issue time")
    require(issued_at <= finished + expected["futureSkewSeconds"]
            and finished - issued_at <= expected["maxAgeSeconds"], "quote expired during verification")
    return {
        "apiVersion": RESULT_VERSION,
        "ok": True,
        "debug": False,
        "resultScope": "local-verifier-only",
        "okForAction": False,
        "bootId": expected["bootId"],
        "keyId": expected["keyId"],
        "controlPlaneResponseSigningKeyId": expected["controlPlaneResponseSigningKeyId"],
        "nonce": expected["nonce"],
        "policyHash": expected["policyHash"],
        "requestBindingSha256": "sha256:" + request_binding.hex(),
        "attestationDocumentSha256": sha256(document),
        "issuedAtUnix": issued_at,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--expectations", type=Path, required=True)
    parser.add_argument("--expectations-sha256", required=True)
    parser.add_argument("--trust-roots", type=Path, required=True)
    parser.add_argument("--trust-roots-sha256", required=True)
    args = parser.parse_args()
    expected = _expectations(_pinned_json(args.expectations, args.expectations_sha256,
                                         "native response-proof expectations", MAX_EXPECTATIONS_BYTES))
    roots, crls, profile = _trust_roots(
        _pinned_json(args.trust_roots, args.trust_roots_sha256,
                     "native response-proof trust roots", MAX_TRUST_ROOTS_BYTES),
        api_version=TRUST_ROOTS_VERSION,
    )
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    result = _verify_evidence(raw, expected, roots, crls, profile)
    original = canonical_json_bytes(result)
    require(len(original) + 1 <= MAX_RESULT_BYTES, "native response-proof verifier output exceeds its bound")
    sys.stdout.buffer.write(original + b"\n")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except (VerificationError, OSError, ValueError, TypeError, KeyError, OverflowError):
        # No partial success, copied verdict or exception detail on stdout.
        print("native response-proof key verification failed", file=sys.stderr)
        raise SystemExit(1)
