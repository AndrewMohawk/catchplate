#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def request_json(url: str, admin_token: str | None = None) -> dict[str, Any]:
    headers = {}
    if admin_token:
        headers["X-Serverware-Admin-Token"] = admin_token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def request_bytes(url: str, admin_token: str | None = None) -> bytes:
    headers = {}
    if admin_token:
        headers["X-Serverware-Admin-Token"] = admin_token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read()


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
    for field in (
        "runtime_manifest_digest",
        "policy_bundle_digest",
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Serverware dev attestation before trusting the proxy CA.")
    parser.add_argument("--base", default="http://localhost:3000", help="Serverware control plane base URL")
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN"), help="admin token for protected CA/policy endpoints")
    parser.add_argument("--ca-out", default=".tmp/serverware-verified-ca.pem", help="where to write the verified CA PEM")
    parser.add_argument("--expected-policy-key-hash", help="pin the policy signing public key hash")
    parser.add_argument("--expected-rollback-epoch", type=int, help="minimum rollback epoch to accept")
    parser.add_argument(
        "--tee-verify-command",
        default=os.getenv("SERVERWARE_TEE_QUOTE_VERIFY_COMMAND"),
        help="external TEE quote verifier command for non-dev quote providers",
    )
    args = parser.parse_args()

    if not args.admin_token:
        raise SystemExit("--admin-token or SERVERWARE_ADMIN_TOKEN is required")

    base = args.base.rstrip("/")
    nonce = secrets.token_urlsafe(24)
    attestation = request_json(f"{base}/attestation?nonce={nonce}")
    if attestation.get("nonce") != nonce:
        raise ValueError("attestation nonce mismatch")
    verify_runtime_digest(attestation)
    verify_quote(attestation, args.tee_verify_command)

    public_key_pem = attestation.get("policy_signing_public_key_pem")
    if not isinstance(public_key_pem, str):
        raise ValueError("attestation missing policy signing public key")
    key_hash = spki_hash_from_public_key_pem(public_key_pem)
    if attestation.get("policy_signing_key_id") != key_hash:
        raise ValueError("policy signing key hash does not match public key")
    if args.expected_policy_key_hash and args.expected_policy_key_hash != key_hash:
        raise ValueError("policy signing key hash does not match pinned value")

    if args.expected_rollback_epoch is not None:
        rollback_epoch = attestation.get("rollback_epoch")
        if not isinstance(rollback_epoch, int) or rollback_epoch < args.expected_rollback_epoch:
            raise ValueError("rollback epoch is stale")

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
    if (bundle.get("metadata") or {}).get("signature") != attestation.get("policy_bundle_signature"):
        raise ValueError("attestation policy signature mismatch")

    ca_pem = request_bytes(f"{base}/ca.pem", args.admin_token)
    ca_spki = spki_hash_from_cert_pem(ca_pem)
    if ca_spki != attestation.get("ca_intermediate_spki_sha256"):
        raise ValueError("CA SPKI hash mismatch")

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
                "policy_signing_key_id": key_hash,
                "ca_intermediate_spki_sha256": ca_spki,
                "data_plane_binary_digest": attestation.get("data_plane_binary_digest"),
                "source_tree_digest": attestation.get("source_tree_digest"),
                "response_signing_key_id": attestation.get("response_signing_key_id"),
                "rollback_epoch": attestation.get("rollback_epoch"),
                "ca_out": str(ca_out),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (urllib.error.URLError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
