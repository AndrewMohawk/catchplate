#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from serverware.http_client import request_bytes
from verify_attestation import request_json, spki_hash_from_public_key_pem, verify_quote, verify_runtime_digest


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_packet(packet: dict[str, object], attestation: dict[str, object], nonce: str) -> dict[str, object]:
    if packet.get("nonce") != nonce or attestation.get("nonce") != nonce:
        raise ValueError("enrollment packet or attestation nonce mismatch")
    now_ms = int(time.time() * 1000)
    issued_at = packet.get("issuedAtEpochMs")
    expires_at = packet.get("expiresAtEpochMs")
    if not isinstance(issued_at, int) or not isinstance(expires_at, int) or not issued_at <= now_ms < expires_at:
        raise ValueError("enrollment packet is not currently valid")
    if expires_at - issued_at > 900_000:
        raise ValueError("enrollment packet lifetime exceeds 900 seconds")
    pinning = packet.get("pinning")
    if not isinstance(pinning, dict):
        raise ValueError("enrollment packet is missing pinning")
    expected_pins = {
        "policyHash": "policy_bundle_digest",
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
    unsigned_packet = json.loads(json.dumps(packet))
    unsigned_packet.pop("authenticity", None)
    unsigned_packet.pop("verificationReceipt", None)
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
    except InvalidSignature as exc:
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a Serverware agent enrollment packet.")
    parser.add_argument("--base", default=os.getenv("SERVERWARE_PUBLIC_URL", "http://localhost:3000"))
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN", "dev-admin-token"))
    parser.add_argument("--principal-id", required=True)
    parser.add_argument("--proxy-url", required=True)
    parser.add_argument("--proxy-egress-cidr", action="append", required=True)
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
    packet = json.loads(request_bytes(request, timeout=15, max_bytes=8 * 1024 * 1024).body)
    attestation = request_json(f"{base}/attestation?nonce={nonce}")
    verify_runtime_digest(attestation)
    verify_quote(attestation, args.tee_verify_command)
    packet["verificationReceipt"] = verify_packet(packet, attestation, nonce)
    json.dump(packet, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
