#!/usr/bin/env python3
"""Verify an original signed statement plus a fresh same-key native NSM quote.

This distinct local adapter accepts serverware.nativeResponseRuntimeProof/v1,
not the legacy proof client's signed vendor-verifier envelope. It checks the
closed outer/statement-family fields, actual Ed25519 signature, independently
pinned key/scope, original client nonce, policy, binary commitment and ages.
It reconstructs the fixed challenge and invokes the genuine role-4 verifier on
the original Nitro document. No copied successful verdict is accepted.

This is NOT full nested statement-schema, control-plane receipt/authorization,
HTTP response, network observation, TLS exporter, witness or release admission.
An attested key's signed claim is not independently observed response truth.
The result is unsigned local output with okForAction=false. Independent pin
provenance/currentness, nonce freshness/one-use reservation, trusted time and
watchdogs remain the caller's responsibility. Native PKI proves no vendor CRL
revocation. No network, key generation, activation or legacy verifier change.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from verify_native_lease_recipient import (
    MAX_EXPECTATIONS_BYTES,
    MAX_TRUST_ROOTS_BYTES,
    _digest_bytes,
    _expectations as _scope_expectations,
    _pinned_json,
    _trust_roots,
)
from verify_native_response_proof_key import (
    BOOT_EXPECTATION_FIELDS,
    EXPECTATIONS_VERSION as KEY_EXPECTATIONS_VERSION,
    _expectations as _key_expectations,
    _verify_evidence as _verify_key_evidence,
)
from verify_nitro_tee import (
    VerificationError,
    b64url_decode,
    b64url_decode_exact,
    b64url_encode,
    canonical_json_bytes,
    exact_keys,
    reject_duplicate_pairs,
    reject_float,
    require,
    require_uint,
    sha256,
)

EVIDENCE_VERSION = "serverware.nativeResponseRuntimeProof/v1"
EVIDENCE_KIND = "ServerwareNativeResponseRuntimeProof"
EXPECTATIONS_VERSION = "serverware.nativeResponseAttestationExpectations/v1"
TRUST_ROOTS_VERSION = "serverware.nativeResponseAttestationTrustRoots/v1"
RESULT_VERSION = "serverware.nativeResponseAttestationVerification/v1"
CHALLENGE_DOMAIN = b"serverware/native-response-attestation-challenge/v1\0"
MAX_INPUT_BYTES = 512 * 1024
MAX_STATEMENT_BYTES = 256 * 1024
MAX_RESULT_BYTES = 4 * 1024
MAX_JSON_NODES = 100_000
MAX_JSON_DEPTH = 64

BUFFERED_VERSION = "serverware.proxyResponseStatement/v2"
STREAMING_VERSION = "serverware.streamingResponseStatement/v1"
OBSERVATION_VERSION = "serverware.responseObservationStatement/v1"
COMMON_FIELDS = {
    "apiVersion", "issued_at_unix", "client_nonce", "principal_id", "route_id",
    "request_digest", "operation_digest", "runtime_manifest_digest",
    "data_plane_binary_digest", "release_digest", "server_instance", "tls_channel_binding",
}
AUTHORIZED_FIELDS = {
    "client_request_digest", "release_authority", "control_plane_authorization_receipt",
    "upstream_response", "policy_digest",
}
STATEMENT_FIELDS = {
    BUFFERED_VERSION: COMMON_FIELDS | AUTHORIZED_FIELDS | {"response"},
    STREAMING_VERSION: COMMON_FIELDS | AUTHORIZED_FIELDS | {
        "authorization_binding_validation", "control_plane_authorization_receipt_sha256",
        "released_response",
    },
    OBSERVATION_VERSION: COMMON_FIELDS | {
        "observation_id", "request", "policy", "credential", "authorization",
        "response_path", "upstream_attempt", "upstream_observation", "emitted_response",
        "observation_authority",
    },
}


def _parse_original(raw: bytes) -> dict[str, Any]:
    require(type(raw) is bytes and 1 <= len(raw) <= MAX_INPUT_BYTES,
            "native response envelope exceeds its bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_pairs,
                           parse_float=reject_float, parse_constant=reject_float)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise VerificationError("native response envelope is not strict UTF-8 JSON") from exc
    # Do not apply Nitro's field-name counter heuristic or NFC policy to actual
    # signed statement maps. Preserve Rust serde_json UTF-8 string semantics.
    pending = [(value, 0)]
    nodes = 0
    while pending:
        node, depth = pending.pop()
        nodes += 1
        require(nodes <= MAX_JSON_NODES and depth <= MAX_JSON_DEPTH,
                "native response JSON exceeds its structural bound")
        if type(node) is dict:
            require(len(node) <= MAX_JSON_NODES, "native response object is too large")
            for key, child in node.items():
                pending.append((key, depth + 1))
                pending.append((child, depth + 1))
        elif type(node) is list:
            require(len(node) <= MAX_JSON_NODES, "native response array is too large")
            pending.extend((child, depth + 1) for child in node)
        elif type(node) is str:
            require(not any(0xD800 <= ord(character) <= 0xDFFF for character in node),
                    "native response JSON contains a surrogate")
        elif type(node) is int:
            require(-(1 << 63) <= node <= (1 << 64) - 1,
                    "native response integer exceeds the Rust JSON range")
        else:
            require(node is None or type(node) is bool, "native response JSON value is unsupported")
        require(len(pending) + nodes <= MAX_JSON_NODES,
                "native response JSON exceeds its aggregate node bound")
    return exact_keys(value, {
        "apiVersion", "kind", "server_statement", "server_statement_sha256",
        "server_signature", "native_attestation",
    }, "native response envelope")


def _expectations(document: Any) -> dict[str, Any]:
    expected = _scope_expectations(document, api_version=EXPECTATIONS_VERSION,
                                   extra_fields=BOOT_EXPECTATION_FIELDS)
    b64url_decode_exact(expected["bootId"], "expected boot ID", exact_bytes=32)
    nonce = b64url_decode(expected["nonce"], "independent client nonce", max_bytes=64)
    require(32 <= len(nonce) <= 64, "independent client nonce must contain 32..64 bytes")
    _digest_bytes(expected["keyId"], "expected proof SPKI key ID")
    _digest_bytes(expected["controlPlaneResponseSigningKeyId"], "expected control-plane SPKI key ID")
    return expected


def _require_fresh(issued_at: Any, now: int, expected: dict[str, Any], label: str) -> None:
    require_uint(issued_at, label)
    require(issued_at > 0 and issued_at <= now + expected["futureSkewSeconds"]
            and now - issued_at <= expected["maxAgeSeconds"], f"{label} is outside the pinned age window")


def _verify_response(raw: bytes, expected: dict[str, Any],
                     roots: list[x509.Certificate], crls: list[x509.CertificateRevocationList],
                     profile: dict[str, Any]) -> dict[str, Any]:
    envelope = _parse_original(raw)
    require(envelope["apiVersion"] == EVIDENCE_VERSION and envelope["kind"] == EVIDENCE_KIND,
            "native response envelope version/kind mismatch")
    statement = envelope["server_statement"]
    require(type(statement) is dict and type(statement.get("apiVersion")) is str,
            "native server statement is missing its version")
    version = statement["apiVersion"]
    require(version in STATEMENT_FIELDS, "native server statement family is unsupported")
    exact_keys(statement, STATEMENT_FIELDS[version], "native server statement")
    # Rust custody signs sorted compact UTF-8, not ensure_ascii=True JSON. JSON
    # object-key order agrees for valid Unicode scalar strings, with floats and
    # invalid scalars already rejected. Hash and signature use these SAME bytes.
    statement_bytes = json.dumps(statement, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, allow_nan=False).encode("utf-8")
    require(1 <= len(statement_bytes) <= MAX_STATEMENT_BYTES,
            "canonical native statement exceeds its bound")
    statement_digest = sha256(statement_bytes)
    _digest_bytes(envelope["server_statement_sha256"], "native statement digest")
    require(hmac.compare_digest(statement_digest, envelope["server_statement_sha256"]),
            "native statement digest differs from its original canonical bytes")
    nonce = b64url_decode(statement["client_nonce"], "statement client nonce", max_bytes=64)
    require(32 <= len(nonce) <= 64 and (version == BUFFERED_VERSION or len(nonce) == 32),
            "statement client nonce length differs from its fixed family")
    require(hmac.compare_digest(statement["client_nonce"], expected["nonce"]),
            "statement nonce differs from the independently expected original")
    if version == OBSERVATION_VERSION:
        policy = exact_keys(statement["policy"], {
            "digest", "snapshot_epoch", "decision_state", "completion_state",
        }, "observation policy")["digest"]
    else:
        policy = statement["policy_digest"]
    require(type(policy) is str and hmac.compare_digest(policy, expected["policyHash"]),
            "statement policy differs from the independently pinned native scope")
    require(type(statement["data_plane_binary_digest"]) is str
            and hmac.compare_digest(statement["data_plane_binary_digest"], expected["expectedBinaryDigest"]),
            "statement binary differs from the independently pinned release expectation")
    now = time.time_ns() // 1_000_000_000
    require(now > 0, "local verifier time is invalid")
    _require_fresh(statement["issued_at_unix"], now, expected, "statement issue time")

    signed = exact_keys(envelope["server_signature"], {
        "algorithm", "key_id", "public_key_pem", "signature",
    }, "native server signature")
    require(signed["algorithm"] == "Ed25519" and signed["key_id"] == expected["keyId"],
            "native server signature algorithm/key ID mismatch")
    pem = signed["public_key_pem"]
    require(type(pem) is str and 1 <= len(pem) <= 4096, "native proof public PEM is invalid")
    try:
        pem_bytes = pem.encode("ascii")
        key = serialization.load_pem_public_key(pem_bytes)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise VerificationError("native proof public PEM cannot be parsed") from exc
    require(isinstance(key, Ed25519PublicKey), "native proof public key is not Ed25519")
    require(key.public_bytes(serialization.Encoding.PEM,
                             serialization.PublicFormat.SubjectPublicKeyInfo) == pem_bytes,
            "native proof PEM is not one canonical public key")
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(hmac.compare_digest(sha256(spki), expected["keyId"]),
            "native proof public key differs from the independent SPKI pin")
    signature_text = signed["signature"]
    require(type(signature_text) is str and signature_text.startswith("ed25519:"),
            "native server signature has the wrong encoding")
    signature = b64url_decode_exact(signature_text[len("ed25519:"):],
                                    "native statement signature", exact_bytes=64)
    try:
        key.verify(signature, statement_bytes)
    except InvalidSignature as exc:
        raise VerificationError("native statement signature is invalid") from exc
    challenge = hashlib.sha256(CHALLENGE_DOMAIN + bytes([len(nonce)]) + nonce
                               + hashlib.sha256(statement_bytes).digest() + signature).digest()
    # The only expectation changed by this adapter is the fixed derived quote
    # challenge. It is never learned from the quote or a claimed verifier result.
    quote_expected = dict(expected)
    quote_expected["apiVersion"] = KEY_EXPECTATIONS_VERSION
    quote_expected["nonce"] = b64url_encode(challenge)
    quote_expected = _key_expectations(quote_expected)
    verified = _verify_key_evidence(canonical_json_bytes(envelope["native_attestation"]),
                                    quote_expected, roots, crls, profile)
    finished = time.time_ns() // 1_000_000_000
    require(finished >= now, "local verifier time moved backwards")
    _require_fresh(statement["issued_at_unix"], finished, expected, "statement issue time")
    _require_fresh(verified["issuedAtUnix"], finished, expected, "quote issue time")
    return {
        "apiVersion": RESULT_VERSION, "ok": True, "debug": False,
        "resultScope": "local-signature-and-native-quote-only", "okForAction": False,
        "statementApiVersion": version, "serverStatementSha256": statement_digest,
        "signatureSha256": sha256(signature), "clientNonce": expected["nonce"],
        "quoteChallenge": b64url_encode(challenge), "bootId": expected["bootId"],
        "keyId": expected["keyId"],
        "controlPlaneResponseSigningKeyId": expected["controlPlaneResponseSigningKeyId"],
        "policyHash": expected["policyHash"], "dataPlaneBinaryDigest": expected["expectedBinaryDigest"],
        "requestBindingSha256": verified["requestBindingSha256"],
        "attestationDocumentSha256": verified["attestationDocumentSha256"],
        "issuedAtUnix": verified["issuedAtUnix"], "statementIssuedAtUnix": statement["issued_at_unix"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--expectations", type=Path, required=True)
    parser.add_argument("--expectations-sha256", required=True)
    parser.add_argument("--trust-roots", type=Path, required=True)
    parser.add_argument("--trust-roots-sha256", required=True)
    args = parser.parse_args()
    expected = _expectations(_pinned_json(args.expectations, args.expectations_sha256,
                                         "native response expectations", MAX_EXPECTATIONS_BYTES))
    roots, crls, profile = _trust_roots(
        _pinned_json(args.trust_roots, args.trust_roots_sha256,
                     "native response trust roots", MAX_TRUST_ROOTS_BYTES),
        api_version=TRUST_ROOTS_VERSION,
    )
    result = _verify_response(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1), expected, roots, crls, profile)
    original = canonical_json_bytes(result)
    require(len(original) + 1 <= MAX_RESULT_BYTES, "native response verifier output exceeds its bound")
    sys.stdout.buffer.write(original + b"\n")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except (VerificationError, OSError, ValueError, TypeError, KeyError, OverflowError):
        print("native response attestation verification failed", file=sys.stderr)
        raise SystemExit(1)
