#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from serverware.http_client import request_bytes  # noqa: E402
from serverware.setup_receipts import (  # noqa: E402
    ENROLLMENT_CHECKS,
    ENROLLMENT_RECEIPT_API_VERSION,
    Ed25519TrustRoot,
    SetupAssignment,
    canonical_base64url,
    canonical_json_bytes,
    sha256_digest,
)
from verify_attestation import spki_hash_from_public_key_pem, verify_quote, verify_runtime_digest  # noqa: E402


MAX_ENROLLMENT_PACKET_BYTES = 8 * 1024 * 1024
MAX_ATTESTATION_BYTES = 8 * 1024 * 1024
MAX_SIGNING_KEY_BYTES = 64 * 1024


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"JSON contains non-standard constant {value!r}")


def _reject_json_float(value: str) -> object:
    raise ValueError(f"JSON contains unsupported floating-point value {value!r}")


def parse_json_object(raw: bytes, *, label: str, max_bytes: int) -> dict[str, object]:
    if len(raw) > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def read_file_snapshot(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    require_private_permissions: bool = False,
    require_current_owner: bool = False,
    require_nofollow: bool = False,
) -> bytes:
    if require_nofollow and not hasattr(os, "O_NOFOLLOW"):
        raise ValueError(f"{label} cannot be opened without following symlinks on this platform")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} is not a readable non-symlink file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if require_private_permissions and metadata.st_mode & 0o077:
            raise ValueError(f"{label} must not be accessible by group or other users")
        if require_current_owner and hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise ValueError(f"{label} must be owned by the current process user")
        if metadata.st_size > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{label} exceeds {max_bytes} bytes")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_enrollment_packet_snapshot(path: Path) -> tuple[bytes, dict[str, object]]:
    raw = read_file_snapshot(
        path,
        label="enrollment packet",
        max_bytes=MAX_ENROLLMENT_PACKET_BYTES,
    )
    return raw, parse_json_object(
        raw,
        label="enrollment packet",
        max_bytes=MAX_ENROLLMENT_PACKET_BYTES,
    )


def load_enrollment_packet(path: Path) -> dict[str, object]:
    return load_enrollment_packet_snapshot(path)[1]


def load_setup_receipt_signing_key(
    path: Path,
    *,
    password_env: str | None,
) -> Ed25519PrivateKey:
    raw = read_file_snapshot(
        path,
        label="setup receipt signing key",
        max_bytes=MAX_SIGNING_KEY_BYTES,
        require_private_permissions=True,
        require_current_owner=True,
        require_nofollow=True,
    )
    password: bytes | None = None
    if password_env is not None:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", password_env) is None:
            raise ValueError("setup receipt signing key password environment variable name is invalid")
        password_value = os.getenv(password_env)
        if not password_value:
            raise ValueError(
                f"setup receipt signing key password environment variable {password_env!r} is unset or empty"
            )
        password = password_value.encode("utf-8")
    try:
        key = serialization.load_pem_private_key(raw, password=password)
    except (TypeError, ValueError) as exc:
        raise ValueError("setup receipt signing key is not a valid PEM private key for the supplied password") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("setup receipt signing key must be an Ed25519 private key")
    return key


def canonical_uuid(value: str, *, label: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise ValueError(f"{label} must be a canonical UUID")
    return value


def enrollment_nonce(packet: dict[str, object]) -> str:
    nonce = packet.get("nonce")
    if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", nonce):
        raise ValueError("enrollment packet is missing a valid nonce")
    return nonce


def verify_packet(packet: dict[str, object], attestation: dict[str, object], nonce: str) -> dict[str, object]:
    if not isinstance(packet, dict):
        raise ValueError("enrollment packet must be a JSON object")
    if "verificationReceipt" in packet:
        raise ValueError("enrollment packet already contains an untrusted verificationReceipt")
    if packet.get("nonce") != nonce or attestation.get("nonce") != nonce:
        raise ValueError("enrollment packet or attestation nonce mismatch")
    now_ms = int(time.time() * 1000)
    issued_at = packet.get("issuedAtEpochMs")
    expires_at = packet.get("expiresAtEpochMs")
    if type(issued_at) is not int or type(expires_at) is not int or not issued_at <= now_ms < expires_at:
        raise ValueError("enrollment packet is not currently valid")
    if expires_at - issued_at > 900_000:
        raise ValueError("enrollment packet lifetime exceeds 900 seconds")
    pinning = packet.get("pinning")
    if not isinstance(pinning, dict):
        raise ValueError("enrollment packet is missing pinning")
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
            raise ValueError(f"enrollment pin {packet_field} does not match live attestation")

    authenticity = packet.get("authenticity")
    if not isinstance(authenticity, dict):
        raise ValueError("enrollment packet is missing authenticity")
    statement = authenticity.get("statement")
    signature = authenticity.get("signature")
    if not isinstance(statement, dict) or not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ValueError("enrollment authenticity statement is invalid")
    unsigned_packet = dict(packet)
    unsigned_packet.pop("authenticity", None)
    packet_sha256 = digest(canonical_json(unsigned_packet).encode("utf-8"))
    if statement.get("packetSha256") != packet_sha256:
        raise ValueError("enrollment packet digest mismatch")
    statement_sha256 = digest(canonical_json(statement).encode("utf-8"))
    if authenticity.get("statementSha256") != statement_sha256:
        raise ValueError("enrollment statement digest mismatch")
    public_key_pem = attestation.get("response_signing_public_key_pem")
    if not isinstance(public_key_pem, str):
        raise ValueError("attestation is missing the response signing public key")
    response_key_id = spki_hash_from_public_key_pem(public_key_pem)
    if response_key_id != pinning.get("responseSigningKeyId"):
        raise ValueError("enrollment response signing key does not match its pin")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    try:
        public_key.verify(b64d(signature.split(":", 1)[1]), canonical_json(statement).encode("utf-8"))
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ValueError("enrollment packet signature verification failed") from exc
    return {
        "apiVersion": "serverware.agentEnrollmentVerification/v1",
        "kind": "AgentEnrollmentVerification",
        "verifiedAtEpochMs": now_ms,
        "nonce": nonce,
        "packetSha256": packet_sha256,
        "statementSha256": statement_sha256,
        "attestationQuoteSha256": digest(canonical_json(attestation.get("quote")).encode("utf-8")),
        "policyHash": pinning["policyHash"],
        "runtimeManifestDigest": pinning["runtimeManifestDigest"],
        "responseSigningKeyId": response_key_id,
        "checks": [
            "attestation-nonce",
            "attestation-quote",
            "runtime-manifest",
            "measurement-pins",
            "packet-expiry",
            "packet-signature",
        ],
    }


def verify_attestation_for_packet(
    packet: dict[str, object],
    attestation: dict[str, object],
    nonce: str,
    tee_verify_command: str | None,
) -> dict[str, object]:
    if attestation.get("nonce") != nonce:
        raise ValueError("live attestation nonce does not match enrollment packet")
    verify_runtime_digest(attestation)
    verify_quote(attestation, tee_verify_command)
    quote = attestation.get("quote")
    claims = quote.get("claims") if isinstance(quote, dict) else None
    if not isinstance(claims, dict) or claims.get("nonce") != nonce:
        raise ValueError("attestation quote nonce does not match enrollment packet")
    return verify_packet(packet, attestation, nonce)


def request_attestation(base: str, nonce: str) -> dict[str, object]:
    query = urllib.parse.urlencode({"nonce": nonce})
    request = urllib.request.Request(f"{base.rstrip('/')}/attestation?{query}")
    response = request_bytes(request, timeout=10, max_bytes=MAX_ATTESTATION_BYTES)
    return parse_json_object(response.body, label="live attestation", max_bytes=MAX_ATTESTATION_BYTES)


def verify_downloaded_packet(
    packet_path: Path,
    *,
    base: str,
    tee_verify_command: str | None,
    expected_packet_sha256: str,
    expected_principal: str,
    expected_nonce: str,
) -> dict[str, object]:
    raw_packet, packet = load_enrollment_packet_snapshot(packet_path)
    actual_packet_sha256 = digest(raw_packet)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", expected_packet_sha256) is None:
        raise ValueError("expected enrollment packet SHA-256 is malformed")
    if actual_packet_sha256 != expected_packet_sha256:
        raise ValueError("downloaded enrollment packet SHA-256 does not match the expected file")
    if packet.get("principalId") != expected_principal:
        raise ValueError("enrollment packet principal does not match the expected principal")
    nonce = enrollment_nonce(packet)
    if nonce != expected_nonce:
        raise ValueError("enrollment packet nonce does not match the expected nonce")
    attestation = request_attestation(base, nonce)
    receipt = verify_attestation_for_packet(packet, attestation, nonce, tee_verify_command)
    receipt["downloadedPacketSha256"] = actual_packet_sha256
    receipt["expectedPrincipalId"] = expected_principal
    receipt["checks"].extend(["downloaded-file-digest", "expected-principal", "expected-nonce"])
    packet["verificationReceipt"] = receipt
    return packet


def sign_setup_enrollment_receipt(
    verified_packet: dict[str, object],
    *,
    setup_session_id: str,
    enrollment_session_id: str,
    assignment: SetupAssignment,
    expected_assignment_digest: str,
    trust_profile_sha256: str,
    verifier_provider: str,
    expected_verifier_key_id: str,
    signing_key: Ed25519PrivateKey,
    verifier_nonce: str,
    receipt_id: str | None = None,
    ttl_seconds: int = 300,
    now_unix: int | None = None,
) -> dict[str, object]:
    canonical_uuid(setup_session_id, label="setup session ID")
    canonical_uuid(enrollment_session_id, label="enrollment session ID")
    if receipt_id is None:
        receipt_id = str(uuid.uuid4())
    canonical_uuid(receipt_id, label="receipt ID")
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 900:
        raise ValueError("setup receipt TTL must be between 1 and 900 seconds")
    if not secrets.compare_digest(assignment.digest, expected_assignment_digest):
        raise ValueError("setup assignment does not match the expected assignment digest")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", trust_profile_sha256) is None:
        raise ValueError("setup trust profile digest is malformed")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", expected_verifier_key_id) is None:
        raise ValueError("expected enrollment verifier key ID is malformed")

    public_key_der = signing_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier_trust = Ed25519TrustRoot(verifier_provider, public_key_der)
    if not secrets.compare_digest(verifier_trust.key_id, expected_verifier_key_id):
        raise ValueError("setup receipt signing key does not match the expected enrollment verifier key ID")

    verification = verified_packet.get("verificationReceipt")
    if not isinstance(verification, dict):
        raise ValueError("verified enrollment packet is missing its local verification receipt")
    packet_sha256 = verification.get("packetSha256")
    if not isinstance(packet_sha256, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", packet_sha256) is None:
        raise ValueError("verified enrollment packet digest is unavailable")
    if verified_packet.get("principalId") != assignment.principal_id:
        raise ValueError("verified enrollment packet principal does not match the setup assignment")

    pinning = verified_packet.get("pinning")
    if not isinstance(pinning, dict) or pinning.get("policyHash") != assignment.policy_hash:
        raise ValueError("verified enrollment packet policy does not match the setup assignment")
    routes = verified_packet.get("allowedRoutes")
    matching_routes = (
        [route for route in routes if isinstance(route, dict) and route.get("id") == assignment.route_id]
        if isinstance(routes, list)
        else []
    )
    if len(matching_routes) != 1 or matching_routes[0].get("credentialRef") != assignment.credential_id:
        raise ValueError("verified enrollment packet route and credential do not match the setup assignment")

    ca = verified_packet.get("ca")
    install_session = ca.get("installSession") if isinstance(ca, dict) else None
    if not isinstance(install_session, dict) or install_session.get("id") != enrollment_session_id:
        raise ValueError("verified enrollment packet capability does not match the enrollment session")
    nonce = enrollment_nonce(verified_packet)
    if not secrets.compare_digest(nonce, verifier_nonce):
        raise ValueError("verified enrollment packet nonce does not match the setup verifier nonce")

    issued_at = int(time.time()) if now_unix is None else now_unix
    if type(issued_at) is not int or issued_at < 1:
        raise ValueError("setup receipt issue time must be a positive integer Unix timestamp")
    statement: dict[str, object] = {
        "receipt_id": receipt_id,
        "setup_session_id": setup_session_id,
        "assignment": assignment.as_document(),
        "assignment_digest": assignment.digest,
        "enrollment_session_id": enrollment_session_id,
        "enrollment_packet_sha256": packet_sha256,
        "verifier_nonce_sha256": sha256_digest(verifier_nonce.encode("ascii")),
        "trust_profile_sha256": trust_profile_sha256,
        "verifier_provider": verifier_provider,
        "decision": "verified",
        "checks": list(ENROLLMENT_CHECKS),
        "issued_at_unix": issued_at,
        "expires_at_unix": issued_at + ttl_seconds,
    }
    signature = signing_key.sign(canonical_json_bytes(statement))
    return {
        "apiVersion": ENROLLMENT_RECEIPT_API_VERSION,
        "kind": "EnrollmentVerifierReceipt",
        "statement": statement,
        "signing_key_id": verifier_trust.key_id,
        "signature": "ed25519:" + canonical_base64url(signature),
    }


def emit_packet(packet: dict[str, object]) -> None:
    json.dump(packet, sys.stdout, indent=2, sort_keys=True)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate or verify a Serverware agent enrollment packet, or sign a setup receipt."
    )
    parser.add_argument("--base", default=os.getenv("SERVERWARE_PUBLIC_URL", "http://localhost:3000"))
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN", "dev-admin-token"))
    parser.add_argument(
        "--verify-packet",
        type=Path,
        metavar="PATH",
        help="verify this exact downloaded packet and emit it with verificationReceipt",
    )
    parser.add_argument("--expected-packet-sha256")
    parser.add_argument("--expected-principal")
    parser.add_argument("--expected-nonce")
    parser.add_argument(
        "--sign-setup-receipt",
        action="store_true",
        help="verify --verify-packet and emit only a signed setup enrollment verifier receipt",
    )
    parser.add_argument("--setup-session-id")
    parser.add_argument("--enrollment-session-id")
    parser.add_argument("--route-id")
    parser.add_argument("--credential-id")
    parser.add_argument("--credential-version", type=int)
    parser.add_argument("--policy-hash")
    parser.add_argument("--route-policy-digest")
    parser.add_argument("--expected-assignment-digest")
    parser.add_argument("--trust-profile-sha256")
    parser.add_argument("--verifier-provider")
    parser.add_argument("--setup-receipt-signing-key", type=Path)
    parser.add_argument("--expected-verifier-key-id")
    parser.add_argument("--signing-key-password-env")
    parser.add_argument("--receipt-id")
    parser.add_argument("--receipt-ttl-seconds", type=int, default=300)
    parser.add_argument("--principal-id")
    parser.add_argument("--proxy-url")
    parser.add_argument("--proxy-egress-cidr", action="append")
    parser.add_argument("--control-plane-url", default=None)
    parser.add_argument("--namespace", default="serverware-agents")
    parser.add_argument("--selector", action="append", default=[], help="pod selector label as key=value")
    parser.add_argument("--ca-mount-path", default="/etc/serverware/serverware-ca.pem")
    parser.add_argument("--ttl-seconds", type=int, default=300)
    parser.add_argument(
        "--tee-verify-command",
        default=os.getenv("SERVERWARE_TEE_QUOTE_VERIFY_COMMAND"),
        help="external TEE quote verifier command for non-development attestations",
    )
    args = parser.parse_args()

    if args.sign_setup_receipt:
        required = (
            ("--verify-packet", args.verify_packet),
            ("--expected-packet-sha256", args.expected_packet_sha256),
            ("--expected-principal", args.expected_principal),
            ("--expected-nonce", args.expected_nonce),
            ("--setup-session-id", args.setup_session_id),
            ("--enrollment-session-id", args.enrollment_session_id),
            ("--route-id", args.route_id),
            ("--credential-id", args.credential_id),
            ("--credential-version", args.credential_version),
            ("--policy-hash", args.policy_hash),
            ("--route-policy-digest", args.route_policy_digest),
            ("--expected-assignment-digest", args.expected_assignment_digest),
            ("--trust-profile-sha256", args.trust_profile_sha256),
            ("--verifier-provider", args.verifier_provider),
            ("--setup-receipt-signing-key", args.setup_receipt_signing_key),
            ("--expected-verifier-key-id", args.expected_verifier_key_id),
        )
        missing = [flag for flag, value in required if value is None or value == ""]
        if missing:
            parser.error(f"setup receipt signing mode requires {', '.join(missing)}")
        signing_key = load_setup_receipt_signing_key(
            args.setup_receipt_signing_key,
            password_env=args.signing_key_password_env,
        )
        verified_packet = verify_downloaded_packet(
            args.verify_packet,
            base=args.base,
            tee_verify_command=args.tee_verify_command,
            expected_packet_sha256=args.expected_packet_sha256,
            expected_principal=args.expected_principal,
            expected_nonce=args.expected_nonce,
        )
        assignment = SetupAssignment(
            principal_id=args.expected_principal,
            route_id=args.route_id,
            credential_id=args.credential_id,
            credential_version=args.credential_version,
            policy_hash=args.policy_hash,
            route_policy_digest=args.route_policy_digest,
        )
        emit_packet(
            sign_setup_enrollment_receipt(
                verified_packet,
                setup_session_id=args.setup_session_id,
                enrollment_session_id=args.enrollment_session_id,
                assignment=assignment,
                expected_assignment_digest=args.expected_assignment_digest,
                trust_profile_sha256=args.trust_profile_sha256,
                verifier_provider=args.verifier_provider,
                expected_verifier_key_id=args.expected_verifier_key_id,
                signing_key=signing_key,
                verifier_nonce=args.expected_nonce,
                receipt_id=args.receipt_id,
                ttl_seconds=args.receipt_ttl_seconds,
            )
        )
        return

    if args.verify_packet is not None:
        missing = [
            flag
            for flag, value in (
                ("--expected-packet-sha256", args.expected_packet_sha256),
                ("--expected-principal", args.expected_principal),
                ("--expected-nonce", args.expected_nonce),
            )
            if not value
        ]
        if missing:
            parser.error(f"verification mode requires {', '.join(missing)}")
        emit_packet(
            verify_downloaded_packet(
                args.verify_packet,
                base=args.base,
                tee_verify_command=args.tee_verify_command,
                expected_packet_sha256=args.expected_packet_sha256,
                expected_principal=args.expected_principal,
                expected_nonce=args.expected_nonce,
            )
        )
        return

    missing = [
        flag
        for flag, value in (
            ("--principal-id", args.principal_id),
            ("--proxy-url", args.proxy_url),
            ("--proxy-egress-cidr", args.proxy_egress_cidr),
        )
        if not value
    ]
    if missing:
        parser.error(f"generation mode requires {', '.join(missing)}")

    selector: dict[str, str] = {}
    for item in args.selector:
        key, sep, value = item.partition("=")
        if not sep or not key or not value:
            raise SystemExit(f"invalid --selector {item!r}; expected key=value")
        selector[key] = value

    base = args.base.rstrip("/")
    nonce = secrets.token_urlsafe(32)
    payload = {
        "principalId": args.principal_id,
        "proxyUrl": args.proxy_url,
        "controlPlaneUrl": args.control_plane_url or base,
        "proxyEgressCidrs": args.proxy_egress_cidr,
        "namespace": args.namespace,
        "podSelector": selector,
        "caMountPath": args.ca_mount_path,
        "nonce": nonce,
        "ttlSeconds": args.ttl_seconds,
    }
    request = urllib.request.Request(
        f"{base}/api/agents/enrollment",
        data=(canonical_json(payload) + "\n").encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Admin-Token": args.admin_token,
            "Authorization": f"Bearer {args.admin_token}",
        },
        method="POST",
    )
    response = request_bytes(request, timeout=15, max_bytes=MAX_ENROLLMENT_PACKET_BYTES)
    packet = parse_json_object(
        response.body,
        label="enrollment response",
        max_bytes=MAX_ENROLLMENT_PACKET_BYTES,
    )
    attestation = request_attestation(base, nonce)
    packet["verificationReceipt"] = verify_attestation_for_packet(
        packet,
        attestation,
        nonce,
        args.tee_verify_command,
    )
    emit_packet(packet)


if __name__ == "__main__":
    try:
        main()
    except (OSError, urllib.error.URLError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
