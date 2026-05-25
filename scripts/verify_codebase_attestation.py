#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


ROOT = Path(__file__).resolve().parents[1]
SOURCE_SUFFIXES = {".py", ".sh", ".json", ".toml", ".lock", ".md", ".yml", ".yaml"}
SOURCE_NAMES = {"Dockerfile", "Makefile", "requirements.txt"}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed(canonical_json(value).encode("utf-8"))


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def source_tree_digest(root: Path) -> str:
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in {".git", ".tmp", "__pycache__", "target"} for part in rel.parts):
            continue
        if path.suffix not in SOURCE_SUFFIXES and path.name not in SOURCE_NAMES and (not rel.parts or rel.parts[0] != "security"):
            continue
        raw = path.read_bytes()
        files.append({"path": str(rel), "bytes": len(raw), "sha256": sha256_prefixed(raw)})
    return sha256_prefixed_json(files)


def request_bytes(url: str, *, headers: dict[str, str] | None = None) -> tuple[bytes, dict[str, str]]:
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read(), {key.lower(): value for key, value in response.headers.items()}


def request_json(url: str, *, headers: dict[str, str] | None = None) -> dict[str, Any]:
    body, _ = request_bytes(url, headers=headers)
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError(f"{url} returned non-object JSON")
    return value


def verify_ed25519(public_key_pem: str, signature: str, payload: bytes, label: str) -> None:
    if not signature.startswith("ed25519:"):
        raise ValueError(f"{label} signature is not ed25519")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    try:
        public_key.verify(b64d(signature.split(":", 1)[1]), payload)
    except InvalidSignature as exc:
        raise ValueError(f"{label} signature verification failed") from exc


def verify_dev_quote(attestation: dict[str, Any]) -> dict[str, Any]:
    quote = attestation.get("quote")
    if not isinstance(quote, dict):
        raise ValueError("attestation missing quote")
    if quote.get("provider") != "dev-signed-quote":
        raise ValueError("non-dev quotes require the deployment TEE verifier before this script can trust them")
    unsigned = dict(quote)
    signature = str(unsigned.pop("signature", ""))
    public_key_pem = quote.get("quote_signing_public_key_pem")
    if not isinstance(public_key_pem, str):
        raise ValueError("quote missing public key")
    verify_ed25519(public_key_pem, signature, canonical_json(unsigned).encode("utf-8"), "quote")
    claims = quote.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("quote missing claims")
    for field in (
        "runtime_manifest_digest",
        "policy_bundle_digest",
        "ca_intermediate_spki_sha256",
        "data_plane_binary_digest",
        "provenance_digest",
        "image_signatures_digest",
        "source_tree_digest",
        "response_signing_key_id",
        "release_channel",
        "rollback_epoch",
    ):
        if claims.get(field) != attestation.get(field):
            raise ValueError(f"quote claim {field} mismatch")
    return claims


def verify_release_provenance(document: dict[str, Any]) -> dict[str, Any]:
    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("release provenance document is missing provenance")
    if document.get("provenance_digest") != sha256_prefixed_json(provenance):
        raise ValueError("release provenance digest mismatch")
    signature = document.get("signature")
    public_key_pem = document.get("release_signing_public_key_pem")
    if not isinstance(signature, str) or not isinstance(public_key_pem, str):
        raise ValueError("release provenance missing signature/public key")
    verify_ed25519(public_key_pem, signature, canonical_json(provenance).encode("utf-8"), "release provenance")
    return provenance


def verify_image_signature_bundle(bundle: dict[str, Any], expected_digest: str) -> None:
    copied = json.loads(json.dumps(bundle))
    actual = copied.pop("image_signature_bundle_digest", None)
    if actual != expected_digest:
        raise ValueError("image signature bundle digest does not match attestation")
    copied.pop("bundle_signature", None)
    metadata = copied.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
        metadata.pop("transparency", None)
        metadata.pop("bundleSigstore", None)
    if expected_digest != sha256_prefixed_json(copied):
        raise ValueError("image signature bundle payload digest mismatch")


def verify_response_signature(attestation: dict[str, Any], body: bytes, headers: dict[str, str], nonce: str) -> None:
    statement_b64 = headers.get("x-serverware-response-statement-b64")
    signature = headers.get("x-serverware-response-signature")
    if not statement_b64 or not signature:
        raise ValueError("response proof headers are missing")
    statement = json.loads(b64d(statement_b64))
    if statement.get("nonce") != nonce:
        raise ValueError("response signature nonce mismatch")
    if statement.get("body_sha256") != sha256_prefixed(body):
        raise ValueError("response signature body digest mismatch")
    if statement.get("response_signing_key_id") != attestation.get("response_signing_key_id"):
        raise ValueError("response signing key id is not attested")
    context = statement.get("context") or {}
    for field in ("runtime_manifest_digest", "policy_bundle_digest", "provenance_digest", "image_signatures_digest", "source_tree_digest"):
        if context.get(field) != attestation.get(field):
            raise ValueError(f"response signature context {field} mismatch")
    public_key_pem = attestation.get("response_signing_public_key_pem")
    if not isinstance(public_key_pem, str):
        raise ValueError("attestation missing response signing public key")
    verify_ed25519(public_key_pem, signature, canonical_json(statement).encode("utf-8"), "response")


def git_commit(root: Path) -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify that a Serverware server is attesting this source tree and signing responses.")
    parser.add_argument("--base", default="http://localhost:3000", help="Serverware control-plane base URL")
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN"), help="admin/auditor token")
    parser.add_argument("--source-root", default=str(ROOT), help="local source tree to compare with release provenance")
    parser.add_argument("--allow-missing-image-signatures", action="store_true")
    args = parser.parse_args()

    if not args.admin_token:
        raise SystemExit("--admin-token or SERVERWARE_ADMIN_TOKEN is required")

    base = args.base.rstrip("/")
    admin_headers = {"X-Serverware-Admin-Token": args.admin_token}
    nonce = secrets.token_urlsafe(24)
    body, proof_headers = request_bytes(f"{base}/attestation?nonce={nonce}", headers={"X-Serverware-Response-Nonce": nonce})
    attestation = json.loads(body)
    if attestation.get("nonce") != nonce:
        raise ValueError("attestation nonce mismatch")
    verify_dev_quote(attestation)
    verify_response_signature(attestation, body, proof_headers, nonce)

    provenance_document = request_json(f"{base}/api/release/provenance", headers=admin_headers)
    provenance = verify_release_provenance(provenance_document)
    if provenance_document.get("provenance_digest") != attestation.get("provenance_digest"):
        raise ValueError("attested provenance digest does not match published provenance")
    published_source_digest = ((provenance.get("source_tree") or {}).get("digest"))
    if published_source_digest != attestation.get("source_tree_digest"):
        raise ValueError("attested source tree digest does not match release provenance")

    local_source_digest = source_tree_digest(Path(args.source_root).resolve())
    if local_source_digest != published_source_digest:
        raise ValueError(f"local source tree digest mismatch: local={local_source_digest} published={published_source_digest}")

    image_signatures_digest = attestation.get("image_signatures_digest")
    if image_signatures_digest:
        bundle = request_json(f"{base}/api/release/image-signatures", headers=admin_headers)
        verify_image_signature_bundle(bundle, image_signatures_digest)
    elif not args.allow_missing_image_signatures:
        raise ValueError("attestation is missing image signature digest")

    print(
        json.dumps(
            {
                "ok": True,
                "source_tree_digest": published_source_digest,
                "local_git_commit": git_commit(Path(args.source_root).resolve()),
                "provenance_digest": attestation.get("provenance_digest"),
                "image_signatures_digest": image_signatures_digest,
                "response_signing_key_id": attestation.get("response_signing_key_id"),
                "data_plane_binary_digest": attestation.get("data_plane_binary_digest"),
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
