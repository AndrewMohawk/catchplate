#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from serverware.http_client import request_bytes as bounded_request_bytes, validate_http_url


MAX_ENROLLMENT_PACKET_BYTES = 8 * 1024 * 1024
MAX_SCOPED_TOKEN_BYTES = 4096
HTTP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}")
CAPABILITY_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,256}")
SESSION_ID_RE = re.compile(r"[A-Za-z0-9_-]{24,128}")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"JSON contains non-standard constant {value!r}")


def load_enrollment_packet(path: Path) -> dict[str, Any]:
    with path.open("rb") as packet_file:
        raw = packet_file.read(MAX_ENROLLMENT_PACKET_BYTES + 1)
    if len(raw) > MAX_ENROLLMENT_PACKET_BYTES:
        raise ValueError(f"enrollment packet exceeds {MAX_ENROLLMENT_PACKET_BYTES} bytes")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise ValueError("enrollment packet is not valid UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("enrollment packet is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("enrollment packet must be a JSON object")
    return value


def _origin(value: Any, *, label: str) -> tuple[str, str, int]:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an HTTP origin")
    parsed = validate_http_url(value)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError(f"{label} must be an HTTP origin without a path, query, or fragment")
    scheme = parsed.scheme.lower()
    hostname = str(parsed.hostname or "").lower()
    if scheme == "http" and hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError(f"{label} must use HTTPS outside loopback development")
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, hostname, port


def _relative_endpoint(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        raise ValueError(f"enrollment CA install session {label} must be a relative URL")
    if any(ord(char) < 32 or ord(char) == 127 or char == "\\" for char in value):
        raise ValueError(f"enrollment CA install session {label} is malformed")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or not parsed.path.startswith("/"):
        raise ValueError(f"enrollment CA install session {label} must be a relative URL")
    return value


def enrollment_install_session(
    packet: dict[str, Any],
    *,
    base: str,
) -> tuple[str, dict[str, Any]]:
    if packet.get("apiVersion") != "serverware.agentEnrollment/v1":
        raise ValueError("enrollment packet apiVersion is invalid")
    serverware = packet.get("serverware")
    if not isinstance(serverware, dict):
        raise ValueError("enrollment packet is missing serverware configuration")
    control_plane_url = serverware.get("controlPlaneUrl")
    if _origin(base, label="--base") != _origin(control_plane_url, label="packet controlPlaneUrl"):
        raise ValueError("--base origin does not match enrollment packet controlPlaneUrl")

    authenticity = packet.get("authenticity")
    if not isinstance(authenticity, dict):
        raise ValueError("enrollment packet is missing authenticity")
    statement = authenticity.get("statement")
    if not isinstance(statement, dict):
        raise ValueError("enrollment packet authenticity statement is invalid")
    signed_packet_digest = statement.get("packetSha256")
    if not isinstance(signed_packet_digest, str) or SHA256_RE.fullmatch(signed_packet_digest) is None:
        raise ValueError("enrollment packet signed digest is invalid")
    unsigned_packet = dict(packet)
    unsigned_packet.pop("authenticity", None)
    unsigned_packet.pop("verificationReceipt", None)
    computed_packet_digest = "sha256:" + hashlib.sha256(
        canonical_json(unsigned_packet).encode("utf-8")
    ).hexdigest()
    if computed_packet_digest != signed_packet_digest:
        raise ValueError("enrollment packet digest does not match its signed statement")
    statement_digest = "sha256:" + hashlib.sha256(canonical_json(statement).encode("utf-8")).hexdigest()
    if authenticity.get("statementSha256") != statement_digest:
        raise ValueError("enrollment packet statement digest mismatch")

    receipt = packet.get("verificationReceipt")
    if not isinstance(receipt, dict):
        raise ValueError("enrollment packet is missing verificationReceipt")
    if (
        receipt.get("apiVersion") != "serverware.agentEnrollmentVerification/v1"
        or receipt.get("kind") != "AgentEnrollmentVerification"
    ):
        raise ValueError("enrollment verificationReceipt type is invalid")
    if receipt.get("packetSha256") != signed_packet_digest:
        raise ValueError("enrollment verificationReceipt does not bind the signed packet digest")
    if receipt.get("statementSha256") != statement_digest:
        raise ValueError("enrollment verificationReceipt does not bind the signed statement digest")
    nonce = packet.get("nonce")
    if not isinstance(nonce, str) or re.fullmatch(r"[A-Za-z0-9_-]{32,256}", nonce) is None:
        raise ValueError("enrollment packet nonce is invalid")
    if receipt.get("nonce") != nonce:
        raise ValueError("enrollment verificationReceipt nonce mismatch")

    ca = packet.get("ca")
    session = ca.get("installSession") if isinstance(ca, dict) else None
    if not isinstance(session, dict):
        raise ValueError("enrollment packet is missing ca.installSession")
    required_session_fields = {"id", "nonce", "token", "tokenHeader", "policyUrl", "downloadUrl", "expiresAt"}
    if set(session) != required_session_fields:
        raise ValueError("enrollment CA install session fields are invalid")
    if session.get("nonce") != nonce:
        raise ValueError("enrollment CA install session nonce mismatch")
    if not isinstance(session.get("id"), str) or SESSION_ID_RE.fullmatch(session["id"]) is None:
        raise ValueError("enrollment CA install session id is invalid")
    if (
        not isinstance(session.get("token"), str)
        or len(session["token"].encode("utf-8")) > MAX_SCOPED_TOKEN_BYTES
        or CAPABILITY_TOKEN_RE.fullmatch(session["token"]) is None
    ):
        raise ValueError("enrollment CA install session token is invalid")
    if session.get("tokenHeader") != "X-Serverware-CA-Install-Token":
        raise ValueError("enrollment CA install session tokenHeader is invalid")
    policy_url = _relative_endpoint(session.get("policyUrl"), label="policyUrl")
    download_url = _relative_endpoint(session.get("downloadUrl"), label="downloadUrl")
    if not isinstance(session.get("expiresAt"), str) or len(session["expiresAt"]) > 64:
        raise ValueError("enrollment CA install session expiresAt is invalid")
    try:
        expires_at = datetime.fromisoformat(session["expiresAt"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("enrollment CA install session expiresAt is invalid") from exc
    if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
        raise ValueError("enrollment CA install session is expired")
    return str(control_plane_url).rstrip("/"), {
        **session,
        "policyUrl": policy_url,
        "downloadUrl": download_url,
    }


def verify_enrollment_packet_signature(
    packet: dict[str, Any],
    *,
    attestation: dict[str, Any],
    response_key_id: str,
) -> None:
    authenticity = packet.get("authenticity")
    statement = authenticity.get("statement") if isinstance(authenticity, dict) else None
    signature = authenticity.get("signature") if isinstance(authenticity, dict) else None
    if not isinstance(statement, dict) or not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ValueError("enrollment packet authenticity signature is invalid")
    public_key_pem = attestation.get("response_signing_public_key_pem")
    if not isinstance(public_key_pem, str):
        raise ValueError("attestation missing enrollment response signing public key")
    pinning = packet.get("pinning")
    if not isinstance(pinning, dict) or pinning.get("responseSigningKeyId") != response_key_id:
        raise ValueError("enrollment response signing key does not match packet pinning")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    try:
        public_key.verify(b64d(signature.split(":", 1)[1]), canonical_json(statement).encode("utf-8"))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ValueError("enrollment packet signature verification failed") from exc


def verify_enrollment_measurements(
    packet: dict[str, Any],
    *,
    attestation: dict[str, Any],
    response_key_id: str,
) -> None:
    pinning = packet.get("pinning")
    if not isinstance(pinning, dict):
        raise ValueError("enrollment packet is missing measurement pinning")
    expected_pins = {
        "policyHash": "policy_bundle_digest",
        "policySigningKeyId": "policy_signing_key_id",
        "policySequence": "policy_sequence",
        "policyHighWaterDigest": "policy_high_water_digest",
        "caIntermediateSpkiSha256": "ca_intermediate_spki_sha256",
        "dataPlaneBinaryDigest": "data_plane_binary_digest",
        "runtimeManifestDigest": "runtime_manifest_digest",
        "responseSigningKeyId": "response_signing_key_id",
        "provenanceDigest": "provenance_digest",
        "imageSignaturesDigest": "image_signatures_digest",
        "sourceTreeDigest": "source_tree_digest",
        "rollbackEpoch": "rollback_epoch",
        "releaseChannel": "release_channel",
    }
    for packet_field, attestation_field in expected_pins.items():
        if pinning.get(packet_field) != attestation.get(attestation_field):
            raise ValueError(f"enrollment pin {packet_field} does not match fresh attestation")
    if pinning.get("responseSigningKeyId") != response_key_id:
        raise ValueError("enrollment response signing key pin mismatch")

    receipt = packet.get("verificationReceipt")
    if not isinstance(receipt, dict):
        raise ValueError("enrollment packet is missing verificationReceipt")
    receipt_bindings = {
        "policyHash": pinning.get("policyHash"),
        "runtimeManifestDigest": pinning.get("runtimeManifestDigest"),
        "responseSigningKeyId": response_key_id,
    }
    for field, expected in receipt_bindings.items():
        if receipt.get(field) != expected:
            raise ValueError(f"enrollment verificationReceipt {field} mismatch")
    # A fresh attestation intentionally produces a distinct signed quote. The
    # receipt records the quote checked during exact-file verification, while
    # the current quote is independently verified above against the same nonce
    # and stable measurement pins.
    if not isinstance(receipt.get("attestationQuoteSha256"), str) or SHA256_RE.fullmatch(
        receipt["attestationQuoteSha256"]
    ) is None:
        raise ValueError("enrollment verificationReceipt attestationQuoteSha256 is invalid")
    verified_at = receipt.get("verifiedAtEpochMs")
    issued_at = packet.get("issuedAtEpochMs")
    expires_at = packet.get("expiresAtEpochMs")
    if (
        type(verified_at) is not int
        or type(issued_at) is not int
        or type(expires_at) is not int
        or not issued_at <= verified_at < expires_at
    ):
        raise ValueError("enrollment verificationReceipt verification time is invalid")
    downloaded_digest = receipt.get("downloadedPacketSha256")
    if not isinstance(downloaded_digest, str) or SHA256_RE.fullmatch(downloaded_digest) is None:
        raise ValueError("enrollment verificationReceipt downloaded packet digest is invalid")
    if receipt.get("expectedPrincipalId") != packet.get("principalId"):
        raise ValueError("enrollment verificationReceipt expected principal mismatch")
    checks = receipt.get("checks")
    required_checks = {
        "attestation-nonce",
        "attestation-quote",
        "runtime-manifest",
        "measurement-pins",
        "packet-expiry",
        "packet-signature",
        "downloaded-file-digest",
        "expected-principal",
        "expected-nonce",
    }
    if (
        not isinstance(checks, list)
        or not all(isinstance(item, str) for item in checks)
        or not required_checks.issubset(set(checks))
    ):
        raise ValueError("enrollment verificationReceipt is missing required checks")

    authenticity = packet.get("authenticity")
    statement = authenticity.get("statement") if isinstance(authenticity, dict) else None
    if not isinstance(statement, dict):
        raise ValueError("enrollment packet authenticity statement is invalid")
    statement_bindings = {
        "principalId": packet.get("principalId"),
        "nonce": packet.get("nonce"),
        "issuedAtEpochMs": packet.get("issuedAtEpochMs"),
        "expiresAtEpochMs": packet.get("expiresAtEpochMs"),
        "policyHash": pinning.get("policyHash"),
        "runtimeManifestDigest": pinning.get("runtimeManifestDigest"),
        "responseSigningKeyId": response_key_id,
    }
    for field, expected in statement_bindings.items():
        if statement.get(field) != expected:
            raise ValueError(f"enrollment authenticity statement {field} mismatch")
    issued_at = packet.get("issuedAtEpochMs")
    expires_at = packet.get("expiresAtEpochMs")
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    if type(issued_at) is not int or type(expires_at) is not int or not issued_at <= now_ms < expires_at:
        raise ValueError("enrollment packet is not currently valid")
    if expires_at - issued_at > 900_000:
        raise ValueError("enrollment packet lifetime exceeds 900 seconds")


def request_json(
    url: str,
    admin_token: str | None = None,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    request_headers = dict(headers or {})
    if admin_token:
        request_headers["X-Serverware-Admin-Token"] = admin_token
    data = None
    if body is not None:
        data = canonical_json(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    response = bounded_request_bytes(request, timeout=10, max_bytes=8 * 1024 * 1024)
    return json.loads(response.body)


def request_bytes(
    url: str,
    admin_token: str | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> bytes:
    request_headers = dict(headers or {})
    if admin_token:
        request_headers["X-Serverware-Admin-Token"] = admin_token
    request = urllib.request.Request(url, headers=request_headers)
    return bounded_request_bytes(request, timeout=10, max_bytes=8 * 1024 * 1024).body


def signature_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(bundle))
    metadata = copied.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
    return copied


def spki_hash_from_public_key_pem(public_key_pem: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def spki_hash_from_cert_pem(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def policy_hash(bundle: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(signature_payload(bundle)).encode("utf-8")).hexdigest()


def verify_policy_signature(bundle: dict[str, Any], public_key_pem: str) -> None:
    signature_value = (bundle.get("metadata") or {}).get("signature")
    if not isinstance(signature_value, str) or not signature_value.startswith("ed25519:"):
        raise ValueError("policy bundle is missing an ed25519 signature")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    payload = canonical_json(signature_payload(bundle)).encode("utf-8")
    try:
        public_key.verify(b64d(signature_value.split(":", 1)[1]), payload)
    except InvalidSignature as exc:
        raise ValueError("policy bundle signature verification failed") from exc


def verify_runtime_digest(attestation: dict[str, Any]) -> None:
    manifest = attestation.get("runtime_manifest")
    if not isinstance(manifest, dict):
        raise ValueError("attestation missing runtime_manifest")
    expected = "sha256:" + hashlib.sha256(repr(sorted(manifest.items())).encode("utf-8")).hexdigest()
    if attestation.get("runtime_manifest_digest") != expected:
        raise ValueError("runtime manifest digest mismatch")


def run_json_command(command: str, payload: dict[str, Any], label: str) -> dict[str, Any]:
    result = subprocess.run(
        shlex.split(command),
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"{label} failed with exit {result.returncode}: {detail}")
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must return a JSON object")
    return value


def verify_quote(attestation: dict[str, Any], tee_verify_command: str | None = None) -> None:
    quote = attestation.get("quote")
    if not isinstance(quote, dict):
        raise ValueError("attestation missing quote")
    if quote.get("provider") != "dev-signed-quote":
        if not tee_verify_command:
            raise ValueError("external TEE quote requires --tee-verify-command")
        verified = run_json_command(tee_verify_command, {"attestation": attestation}, "TEE quote verifier")
        claims = verified.get("claims", verified)
        if not isinstance(claims, dict):
            raise ValueError("TEE quote verifier did not return claims")
    else:
        signature = quote.get("signature")
        public_key_pem = quote.get("quote_signing_public_key_pem")
        if not isinstance(signature, str) or not signature.startswith("ed25519:"):
            raise ValueError("attestation quote missing ed25519 signature")
        if not isinstance(public_key_pem, str):
            raise ValueError("attestation quote missing public key")
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        unsigned = dict(quote)
        unsigned.pop("signature", None)
        try:
            public_key.verify(b64d(signature.split(":", 1)[1]), canonical_json(unsigned).encode("utf-8"))
        except InvalidSignature as exc:
            raise ValueError("attestation quote signature verification failed") from exc
        claims = quote.get("claims")
        if not isinstance(claims, dict):
            raise ValueError("attestation quote missing claims")
    if claims.get("nonce") != attestation.get("nonce"):
        raise ValueError("attestation quote claim nonce mismatch")
    for field in (
        "runtime_manifest_digest",
        "policy_bundle_digest",
        "policy_sequence",
        "policy_high_water_digest",
        "ca_intermediate_spki_sha256",
        "data_plane_binary_digest",
        "rollback_epoch",
        "provenance_digest",
        "image_signatures_digest",
        "source_tree_digest",
        "response_signing_key_id",
        "release_channel",
    ):
        if claims.get(field) != attestation.get(field):
            raise ValueError(f"attestation quote claim {field} mismatch")


def verify_policy_high_water(attestation: dict[str, Any]) -> dict[str, Any]:
    high_water = attestation.get("policy_high_water")
    if not isinstance(high_water, dict):
        raise ValueError("attestation missing policy high-water evidence")
    expected_digest = "sha256:" + hashlib.sha256(
        canonical_json(high_water).encode("utf-8")
    ).hexdigest()
    if attestation.get("policy_high_water_digest") != expected_digest:
        raise ValueError("policy high-water digest mismatch")
    if high_water.get("policyHash") != attestation.get("policy_bundle_digest"):
        raise ValueError("policy high-water hash mismatch")
    if high_water.get("sequence") != attestation.get("policy_sequence"):
        raise ValueError("policy high-water sequence mismatch")
    if high_water.get("rollbackEpoch") != attestation.get("rollback_epoch"):
        raise ValueError("policy high-water rollback epoch mismatch")
    if high_water.get("store") not in {"sqlite", "postgres"}:
        raise ValueError("policy high-water store is invalid")
    return high_water


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Serverware dev attestation before trusting the proxy CA.")
    parser.add_argument("--base", default="http://localhost:3000", help="Serverware control plane base URL")
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN"), help="admin token for protected CA/policy endpoints")
    parser.add_argument(
        "--enrollment-packet",
        type=Path,
        metavar="PATH",
        help="use the scoped CA/policy verifier capability embedded in a verified enrollment packet",
    )
    parser.add_argument("--ca-out", default=".tmp/serverware-verified-ca.pem", help="where to write the verified CA PEM")
    parser.add_argument("--expected-policy-key-hash", help="pin the policy signing public key hash")
    parser.add_argument("--expected-policy-sequence", type=int, help="minimum policy sequence to accept")
    parser.add_argument("--expected-rollback-epoch", type=int, help="minimum rollback epoch to accept")
    parser.add_argument(
        "--tee-verify-command",
        default=os.getenv("SERVERWARE_TEE_QUOTE_VERIFY_COMMAND"),
        help="external TEE quote verifier command for non-dev quote providers",
    )
    args = parser.parse_args()

    enrollment_packet: dict[str, Any] | None = None
    if args.enrollment_packet is not None:
        if args.admin_token:
            raise SystemExit("--enrollment-packet mode forbids --admin-token and SERVERWARE_ADMIN_TOKEN")
        enrollment_packet = load_enrollment_packet(args.enrollment_packet)
        base, install_session = enrollment_install_session(enrollment_packet, base=args.base)
    else:
        if not args.admin_token:
            raise SystemExit("--admin-token or SERVERWARE_ADMIN_TOKEN is required")
        base = args.base.rstrip("/")
        install_session_response = request_json(
            f"{base}/api/ca/install-sessions",
            args.admin_token,
            method="POST",
            body={},
        )
        install_session = install_session_response.get("session")
        if not isinstance(install_session, dict):
            raise ValueError("CA install session endpoint did not return a session")
    nonce = install_session.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise ValueError("CA install session did not return a nonce")
    install_token = install_session.get("token")
    if not isinstance(install_token, str) or not install_token:
        raise ValueError("CA install session did not return a token")
    download_url = install_session.get("downloadUrl")
    if not isinstance(download_url, str) or not download_url.startswith("/"):
        raise ValueError("CA install session did not return a relative downloadUrl")

    attestation = request_json(f"{base}/attestation?nonce={nonce}")
    if attestation.get("nonce") != nonce:
        raise ValueError("attestation nonce mismatch")
    verify_runtime_digest(attestation)
    verify_quote(attestation, args.tee_verify_command)
    high_water = verify_policy_high_water(attestation)

    public_key_pem = attestation.get("policy_signing_public_key_pem")
    if not isinstance(public_key_pem, str):
        raise ValueError("attestation missing policy signing public key")
    key_hash = spki_hash_from_public_key_pem(public_key_pem)
    if attestation.get("policy_signing_key_id") != key_hash:
        raise ValueError("policy signing key hash does not match public key")
    if args.expected_policy_key_hash and args.expected_policy_key_hash != key_hash:
        raise ValueError("policy signing key hash does not match pinned value")
    if enrollment_packet is not None:
        response_public_key_pem = attestation.get("response_signing_public_key_pem")
        if not isinstance(response_public_key_pem, str):
            raise ValueError("attestation missing enrollment response signing public key")
        response_key_id = spki_hash_from_public_key_pem(response_public_key_pem)
        if attestation.get("response_signing_key_id") != response_key_id:
            raise ValueError("enrollment response signing key hash does not match public key")
        verify_enrollment_packet_signature(
            enrollment_packet,
            attestation=attestation,
            response_key_id=response_key_id,
        )
        verify_enrollment_measurements(
            enrollment_packet,
            attestation=attestation,
            response_key_id=response_key_id,
        )

    if args.expected_rollback_epoch is not None:
        rollback_epoch = attestation.get("rollback_epoch")
        if not isinstance(rollback_epoch, int) or rollback_epoch < args.expected_rollback_epoch:
            raise ValueError("rollback epoch is stale")
    if args.expected_policy_sequence is not None:
        policy_sequence = attestation.get("policy_sequence")
        if not isinstance(policy_sequence, int) or policy_sequence < args.expected_policy_sequence:
            raise ValueError("policy sequence is stale")

    token_header = install_session.get("tokenHeader") or "X-Serverware-CA-Install-Token"
    if not isinstance(token_header, str) or HTTP_HEADER_NAME_RE.fullmatch(token_header) is None:
        raise ValueError("CA install session token header is invalid")
    scoped_headers = {token_header: install_token}
    if enrollment_packet is not None:
        policy_status = request_json(
            f"{base}{install_session['policyUrl']}",
            headers=scoped_headers,
        )
    else:
        policy_status = request_json(f"{base}/api/policy", args.admin_token)
    bundle = policy_status.get("bundle")
    if not isinstance(bundle, dict):
        raise ValueError("policy endpoint did not return a signed bundle")
    verify_policy_signature(bundle, public_key_pem)
    computed_policy_hash = policy_hash(bundle)
    if computed_policy_hash != policy_status.get("policy_hash"):
        raise ValueError("policy endpoint hash mismatch")
    if computed_policy_hash != attestation.get("policy_bundle_digest"):
        raise ValueError("attestation policy digest mismatch")
    if enrollment_packet is not None:
        enrollment_pinning = enrollment_packet.get("pinning")
        enrollment_receipt = enrollment_packet.get("verificationReceipt")
        if not isinstance(enrollment_pinning, dict) or enrollment_pinning.get("policyHash") != computed_policy_hash:
            raise ValueError("enrollment packet policy hash mismatch")
        if not isinstance(enrollment_receipt, dict) or enrollment_receipt.get("policyHash") != computed_policy_hash:
            raise ValueError("enrollment verificationReceipt policy hash mismatch")
    metadata = bundle.get("metadata") or {}
    if metadata.get("sequence") != attestation.get("policy_sequence"):
        raise ValueError("attestation policy sequence mismatch")
    status_high_water = policy_status.get("high_water")
    if not isinstance(status_high_water, dict) or {
        "policyId": status_high_water.get("policy_id"),
        "sequence": status_high_water.get("sequence"),
        "rollbackEpoch": status_high_water.get("rollback_epoch"),
        "policyHash": status_high_water.get("policy_hash"),
        "updatedAt": status_high_water.get("updated_at"),
        "store": high_water.get("store"),
    } != high_water:
        raise ValueError("policy endpoint high-water state mismatch")
    if (bundle.get("metadata") or {}).get("signature") != attestation.get("policy_bundle_signature"):
        raise ValueError("attestation policy signature mismatch")

    ca_pem = request_bytes(
        f"{base}{download_url}",
        args.admin_token if enrollment_packet is None else None,
        headers=scoped_headers,
    )
    ca_spki = spki_hash_from_cert_pem(ca_pem)
    if ca_spki != attestation.get("ca_intermediate_spki_sha256"):
        raise ValueError("CA SPKI hash mismatch")
    if enrollment_packet is not None:
        enrollment_ca = enrollment_packet.get("ca")
        if not isinstance(enrollment_ca, dict) or enrollment_ca.get("spkiSha256") != ca_spki:
            raise ValueError("enrollment packet CA SPKI hash mismatch")

    ca_out = Path(args.ca_out)
    ca_out.parent.mkdir(parents=True, exist_ok=True)
    ca_out.write_bytes(ca_pem)
    os.chmod(ca_out, 0o600)

    print(
        json.dumps(
            {
                "ok": True,
                "tee_platform": attestation.get("tee_platform"),
                "policy_hash": computed_policy_hash,
                "policy_sequence": attestation.get("policy_sequence"),
                "policy_high_water_digest": attestation.get("policy_high_water_digest"),
                "policy_signing_key_id": key_hash,
                "ca_intermediate_spki_sha256": ca_spki,
                "data_plane_binary_digest": attestation.get("data_plane_binary_digest"),
                "source_tree_digest": attestation.get("source_tree_digest"),
                "response_signing_key_id": attestation.get("response_signing_key_id"),
                "rollback_epoch": attestation.get("rollback_epoch"),
                "ca_install_session_id": install_session.get("id"),
                "ca_install_method": (
                    install_session.get("installMethod")
                    or ((enrollment_packet.get("ca") or {}).get("installMethod") if enrollment_packet else None)
                ),
                "ca_out": str(ca_out),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, urllib.error.URLError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
