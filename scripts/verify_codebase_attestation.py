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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

import serverware_source_tree
from serverware.http_client import request_bytes as bounded_request_bytes


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed(canonical_json(value).encode("utf-8"))


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def require_sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def trusted_ed25519_key(path: Path, label: str) -> tuple[Ed25519PublicKey, str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be an existing regular non-symlink file")
    if path.stat().st_size > 65536:
        raise ValueError(f"{label} exceeds 65536 bytes")
    raw = path.read_bytes()
    try:
        loaded = serialization.load_pem_public_key(raw)
    except ValueError:
        loaded = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError(f"{label} must contain an Ed25519 key")
        loaded = loaded.public_key()
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError(f"{label} must contain an Ed25519 key")
    pem = loaded.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = loaded.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return loaded, pem, sha256_prefixed(der)


def source_tree_digest(root: Path) -> str:
    return serverware_source_tree.source_tree_digest(root)


def request_bytes(url: str, *, headers: dict[str, str] | None = None) -> tuple[bytes, dict[str, str]]:
    request = urllib.request.Request(url, headers=headers or {})
    response = bounded_request_bytes(request, timeout=10, max_bytes=8 * 1024 * 1024)
    return response.body, dict(response.headers)


def request_json(url: str, *, headers: dict[str, str] | None = None) -> dict[str, Any]:
    body, _ = request_bytes(url, headers=headers)
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError(f"{url} returned non-object JSON")
    return value


def verify_ed25519(
    public_key_pem: str,
    signature: str,
    payload: bytes,
    label: str,
    *,
    prefixes: tuple[str, ...] = ("ed25519:",),
) -> None:
    prefix = next((candidate for candidate in prefixes if signature.startswith(candidate)), None)
    if prefix is None:
        raise ValueError(f"{label} signature is not an accepted Ed25519 signature")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError(f"{label} public key is not Ed25519")
    try:
        public_key.verify(b64d(signature[len(prefix) :]), payload)
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
        "policy_sequence",
        "policy_high_water_digest",
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


def verify_release_provenance(
    document: dict[str, Any],
    trusted_public_key_pem: str,
    trusted_key_id: str,
) -> dict[str, Any]:
    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("release provenance document is missing provenance")
    if document.get("provenance_digest") != sha256_prefixed_json(provenance):
        raise ValueError("release provenance digest mismatch")
    signature = document.get("signature")
    public_key_pem = document.get("release_signing_public_key_pem")
    if not isinstance(signature, str) or not isinstance(public_key_pem, str):
        raise ValueError("release provenance missing signature/public key")
    embedded_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(embedded_key, Ed25519PublicKey):
        raise ValueError("release provenance embedded public key is not Ed25519")
    embedded_der = embedded_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if sha256_prefixed(embedded_der) != trusted_key_id:
        raise ValueError("release provenance embedded key does not match the independent trust root")
    if document.get("release_signing_key_id") != trusted_key_id:
        raise ValueError("release provenance signing key ID does not match the independent trust root")
    verify_ed25519(
        trusted_public_key_pem,
        signature,
        canonical_json(provenance).encode("utf-8"),
        "release provenance",
    )
    return provenance


def normalized_image_signature_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(bundle))
    copied.pop("image_signature_bundle_digest", None)
    copied.pop("bundle_signature", None)
    metadata = copied.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
        metadata.pop("transparency", None)
        metadata.pop("bundleSigstore", None)
    return copied


def run_sigstore_verifier(
    command: str,
    *,
    kind: str,
    service: str,
    image_id: str | None,
    statement: dict[str, Any],
    signature_response: dict[str, Any],
    expected_key_id: str,
    label: str,
) -> None:
    statement_digest = sha256_prefixed_json(statement)
    request = {
        "apiVersion": "serverware.sigstoreVerifyRequest/v1",
        "kind": kind,
        "service": service,
        "image_id": image_id,
        "statement": statement,
        "statement_digest": statement_digest,
        "signature_response": signature_response,
    }
    result = subprocess.run(
        shlex.split(command),
        cwd=ROOT,
        input=canonical_json(request).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")[-2000:]
        raise ValueError(f"{label} external Sigstore verification failed: {detail}")
    try:
        response = json.loads(result.stdout)
    except Exception as exc:
        raise ValueError(f"{label} external Sigstore verifier returned invalid JSON") from exc
    if response.get("ok") is not True or response.get("verified_transparency") is not True:
        raise ValueError(f"{label} external Sigstore verifier did not verify transparency")
    if response.get("statement_digest") != statement_digest:
        raise ValueError(f"{label} external Sigstore verifier returned the wrong statement digest")
    key_provider = response.get("key_provider") if isinstance(response.get("key_provider"), dict) else {}
    if key_provider.get("key_id") != expected_key_id:
        raise ValueError(f"{label} external Sigstore verifier returned the wrong key")
    if response.get("transparency") != signature_response.get("transparency"):
        raise ValueError(f"{label} external Sigstore verifier returned different transparency evidence")


def verify_sigstore_statement(
    sigstore: dict[str, Any],
    *,
    statement: dict[str, Any],
    trusted_public_key_pem: str,
    trusted_key_id: str,
    verify_command: str,
    kind: str,
    service: str,
    image_id: str | None,
    label: str,
) -> None:
    statement_digest = sha256_prefixed_json(statement)
    if sigstore.get("ok") is not True or sigstore.get("statement_digest") != statement_digest:
        raise ValueError(f"{label} Sigstore statement binding is invalid")
    key_provider = sigstore.get("key_provider") if isinstance(sigstore.get("key_provider"), dict) else {}
    if key_provider.get("key_id") != trusted_key_id:
        raise ValueError(f"{label} Sigstore key does not match the independent trust root")
    bundle = sigstore.get("bundle") if isinstance(sigstore.get("bundle"), dict) else {}
    message = bundle.get("messageSignature") if isinstance(bundle.get("messageSignature"), dict) else {}
    message_digest = message.get("messageDigest") if isinstance(message.get("messageDigest"), dict) else {}
    if str(message_digest.get("algorithm", "")).lower().replace("-", "") != "sha256":
        raise ValueError(f"{label} Sigstore bundle digest algorithm is invalid")
    if message_digest.get("digest") != statement_digest.split(":", 1)[1]:
        raise ValueError(f"{label} Sigstore bundle digest does not match its statement")
    signature = message.get("signature")
    if not isinstance(signature, str) or signature != sigstore.get("signature"):
        raise ValueError(f"{label} Sigstore signature fields do not agree")
    verification = bundle.get("verificationMaterial") if isinstance(bundle.get("verificationMaterial"), dict) else {}
    embedded_public_key = verification.get("publicKey")
    if not isinstance(embedded_public_key, str):
        raise ValueError(f"{label} Sigstore bundle has no public key")
    embedded = serialization.load_pem_public_key(embedded_public_key.encode("ascii"))
    if not isinstance(embedded, Ed25519PublicKey):
        raise ValueError(f"{label} Sigstore fixture public key is not Ed25519")
    embedded_der = embedded.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if sha256_prefixed(embedded_der) != trusted_key_id:
        raise ValueError(f"{label} Sigstore embedded key does not match the independent trust root")
    verify_ed25519(
        trusted_public_key_pem,
        signature,
        canonical_json(statement).encode("utf-8"),
        label,
        prefixes=("cosign-fixture-ed25519:", "ed25519:"),
    )
    transparency = sigstore.get("transparency") if isinstance(sigstore.get("transparency"), dict) else {}
    proof = transparency.get("inclusion_proof") if isinstance(transparency.get("inclusion_proof"), dict) else {}
    tree_size = proof.get("treeSize")
    log_index = proof.get("logIndex")
    require_sha256(transparency.get("log_id"), f"{label} transparency log ID")
    require_sha256(proof.get("rootHash"), f"{label} transparency root hash")
    if not isinstance(tree_size, int) or tree_size < 1:
        raise ValueError(f"{label} transparency tree size is invalid")
    if not isinstance(log_index, int) or not 0 <= log_index < tree_size:
        raise ValueError(f"{label} transparency log index is invalid")
    if not isinstance(proof.get("hashes"), list):
        raise ValueError(f"{label} transparency proof hashes are invalid")
    entries = verification.get("tlogEntries") if isinstance(verification.get("tlogEntries"), list) else []
    if len(entries) != 1:
        raise ValueError(f"{label} Sigstore bundle must contain exactly one transparency entry")
    entry = entries[0] if isinstance(entries[0], dict) else {}
    entry_log_id = (entry.get("logId") or {}).get("keyId") if isinstance(entry.get("logId"), dict) else None
    if (
        entry_log_id != transparency.get("log_id")
        or entry.get("logIndex") != transparency.get("log_index")
        or entry.get("integratedTime") != transparency.get("integrated_time")
        or entry.get("entryUUID") != transparency.get("entry_uuid")
        or entry.get("inclusionProof") != proof
    ):
        raise ValueError(f"{label} Sigstore transparency fields do not agree")
    run_sigstore_verifier(
        verify_command,
        kind=kind,
        service=service,
        image_id=image_id,
        statement=statement,
        signature_response=sigstore,
        expected_key_id=trusted_key_id,
        label=label,
    )


def verify_image_signature_bundle(
    bundle: dict[str, Any],
    expected_digest: str,
    *,
    provenance: dict[str, Any],
    provenance_digest: str,
    release_signing_key_id: str,
    trusted_public_key_pem: str,
    trusted_key_id: str,
    verify_command: str,
) -> None:
    require_sha256(expected_digest, "attested image signature bundle digest")
    if bundle.get("image_signature_bundle_digest") != expected_digest:
        raise ValueError("image signature bundle digest does not match attestation")
    normalized = normalized_image_signature_payload(bundle)
    if expected_digest != sha256_prefixed_json(normalized):
        raise ValueError("image signature bundle payload digest mismatch")
    if bundle.get("apiVersion") != "serverware.imageSignatures/v1":
        raise ValueError("image signature bundle apiVersion is invalid")
    metadata = bundle.get("metadata") if isinstance(bundle.get("metadata"), dict) else {}
    source_tree = provenance.get("source_tree") if isinstance(provenance.get("source_tree"), dict) else {}
    sbom = provenance.get("sbom") if isinstance(provenance.get("sbom"), dict) else {}
    cyclonedx = sbom.get("cyclonedx") if isinstance(sbom.get("cyclonedx"), dict) else {}
    expected_metadata = {
        "provenanceDigest": provenance_digest,
        "releaseSigningKeyId": release_signing_key_id,
        "imageSigningKeyId": trusted_key_id,
        "sourceTreeDigest": source_tree.get("digest"),
        "composeConfigSha256": provenance.get("compose_config_sha256"),
        "sbomCyclonedxSha256": cyclonedx.get("sha256"),
    }
    for field, expected in expected_metadata.items():
        if metadata.get(field) != expected:
            raise ValueError(f"image signature metadata {field} mismatch")
    if metadata.get("signatureProvider") != "sigstore-command" or metadata.get("sigstoreTransparencyRequired") is not True:
        raise ValueError("image signature metadata does not require Sigstore transparency")
    bundle_sigstore = bundle.get("bundle_signature") if isinstance(bundle.get("bundle_signature"), dict) else {}
    if metadata.get("bundleSigstore") != bundle_sigstore or metadata.get("signature") != bundle_sigstore.get("signature"):
        raise ValueError("image signature bundle proof fields do not agree")
    verify_sigstore_statement(
        bundle_sigstore,
        statement=normalized,
        trusted_public_key_pem=trusted_public_key_pem,
        trusted_key_id=trusted_key_id,
        verify_command=verify_command,
        kind="image-signature-bundle",
        service="__bundle__",
        image_id=None,
        label="image signature bundle",
    )
    provenance_images = provenance.get("images") if isinstance(provenance.get("images"), dict) else {}
    images = bundle.get("images") if isinstance(bundle.get("images"), list) else []
    if not images or len(images) != len(provenance_images):
        raise ValueError("image signature entries do not match the provenance inventory")
    seen: set[str] = set()
    for image in images:
        if not isinstance(image, dict):
            raise ValueError("image signature entry must be an object")
        service = image.get("service")
        if not isinstance(service, str) or service in seen or service not in provenance_images:
            raise ValueError("image signature entry has an unknown or duplicate service")
        seen.add(service)
        inventory = provenance_images[service] if isinstance(provenance_images[service], dict) else {}
        image_id = require_sha256(image.get("image_id"), f"image {service} digest")
        if image_id != inventory.get("image_id"):
            raise ValueError(f"image {service} digest does not match provenance")
        statement = image.get("statement") if isinstance(image.get("statement"), dict) else {}
        statement_digest = sha256_prefixed_json(statement)
        if image.get("statement_digest") != statement_digest:
            raise ValueError(f"image {service} statement digest mismatch")
        subject = statement.get("subject") if isinstance(statement.get("subject"), list) else []
        if not any(
            isinstance(item, dict)
            and item.get("name") == service
            and isinstance(item.get("digest"), dict)
            and item["digest"].get("sha256") == image_id.split(":", 1)[1]
            for item in subject
        ):
            raise ValueError(f"image {service} statement subject mismatch")
        predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
        expected_predicate = {
            "image_id": image_id,
            "provenance_digest": provenance_digest,
            "release_signing_key_id": release_signing_key_id,
            "source_tree_digest": source_tree.get("digest"),
            "compose_config_sha256": provenance.get("compose_config_sha256"),
            "sbom_cyclonedx_sha256": cyclonedx.get("sha256"),
            "sbom_cyclonedx_components": cyclonedx.get("components"),
        }
        for field, expected in expected_predicate.items():
            if predicate.get(field) != expected:
                raise ValueError(f"image {service} statement {field} mismatch")
        if sorted(predicate.get("repo_digests") or []) != sorted(inventory.get("repo_digests") or []):
            raise ValueError(f"image {service} repository digest binding mismatch")
        sigstore = image.get("sigstore") if isinstance(image.get("sigstore"), dict) else {}
        if image.get("signature") != sigstore.get("signature"):
            raise ValueError(f"image {service} signature fields do not agree")
        verify_sigstore_statement(
            sigstore,
            statement=statement,
            trusted_public_key_pem=trusted_public_key_pem,
            trusted_key_id=trusted_key_id,
            verify_command=verify_command,
            kind="oci-image-statement",
            service=service,
            image_id=image_id,
            label=f"image {service}",
        )
    if seen != set(provenance_images):
        raise ValueError("image signature bundle omitted a provenance image")


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
    parser.add_argument(
        "--release-signing-trusted-key",
        default=os.getenv("SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY", ""),
    )
    parser.add_argument(
        "--image-signing-trusted-key",
        default=os.getenv("SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY", ""),
    )
    parser.add_argument(
        "--image-verify-command",
        default=os.getenv("SERVERWARE_IMAGE_VERIFY_COMMAND", "python3 scripts/cosign_sigstore.py verify"),
    )
    parser.add_argument("--allow-missing-image-signatures", action="store_true")
    args = parser.parse_args()

    if not args.admin_token:
        raise SystemExit("--admin-token or SERVERWARE_ADMIN_TOKEN is required")
    if not args.release_signing_trusted_key:
        raise SystemExit("--release-signing-trusted-key is required")
    if not args.image_signing_trusted_key and not args.allow_missing_image_signatures:
        raise SystemExit("--image-signing-trusted-key is required")
    if not args.image_verify_command and not args.allow_missing_image_signatures:
        raise SystemExit("--image-verify-command is required")

    _, release_trusted_pem, release_trusted_key_id = trusted_ed25519_key(
        Path(args.release_signing_trusted_key).resolve(),
        "release signing trust root",
    )

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
    provenance = verify_release_provenance(
        provenance_document,
        release_trusted_pem,
        release_trusted_key_id,
    )
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
        _, image_trusted_pem, image_trusted_key_id = trusted_ed25519_key(
            Path(args.image_signing_trusted_key).resolve(),
            "image signing trust root",
        )
        bundle = request_json(f"{base}/api/release/image-signatures", headers=admin_headers)
        verify_image_signature_bundle(
            bundle,
            image_signatures_digest,
            provenance=provenance,
            provenance_digest=str(provenance_document.get("provenance_digest")),
            release_signing_key_id=release_trusted_key_id,
            trusted_public_key_pem=image_trusted_pem,
            trusted_key_id=image_trusted_key_id,
            verify_command=args.image_verify_command,
        )
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
