#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from serverware.http_client import request_bytes
from verify_attestation import spki_hash_from_public_key_pem, verify_quote, verify_runtime_digest


MAX_ENROLLMENT_PACKET_BYTES = 8 * 1024 * 1024
MAX_ATTESTATION_BYTES = 8 * 1024 * 1024


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


def parse_json_object(raw: bytes, *, label: str, max_bytes: int) -> dict[str, object]:
    if len(raw) > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def load_enrollment_packet(path: Path) -> dict[str, object]:
    with path.open("rb") as packet_file:
        raw = packet_file.read(MAX_ENROLLMENT_PACKET_BYTES + 1)
    return parse_json_object(raw, label="enrollment packet", max_bytes=MAX_ENROLLMENT_PACKET_BYTES)


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
    with packet_path.open("rb") as packet_file:
        raw_packet = packet_file.read(MAX_ENROLLMENT_PACKET_BYTES + 1)
    actual_packet_sha256 = digest(raw_packet)
    if re.fullmatch(r"sha256:[0-9a-f]{64}", expected_packet_sha256) is None:
        raise ValueError("expected enrollment packet SHA-256 is malformed")
    if actual_packet_sha256 != expected_packet_sha256:
        raise ValueError("downloaded enrollment packet SHA-256 does not match the expected file")
    packet = load_enrollment_packet(packet_path)
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


def emit_packet(packet: dict[str, object]) -> None:
    json.dump(packet, sys.stdout, indent=2, sort_keys=True)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate or verify a Serverware agent enrollment packet.")
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
