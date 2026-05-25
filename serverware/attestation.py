from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import shlex
import subprocess
import time
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import __version__
from serverware.config import (
    EXPECTED_DATA_PLANE_BINARY_DIGEST,
    IMAGE_SIGNATURES_PATH,
    KEY_RELEASE_ALLOW_DEBUG,
    KEY_RELEASE_REQUIRED,
    KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST,
    MITMPROXY_CONF_DIR,
    RELEASE_CHANNEL,
    RELEASE_PROVENANCE_PATH,
    TEE_PLATFORM,
    TEE_QUOTE_COMMAND,
    TEE_QUOTE_PROVIDER,
    TEE_QUOTE_SIGNING_KEY_PATH,
    TEE_QUOTE_VERIFY_COMMAND,
    ensure_data_dirs,
)
from serverware.policy_bundle import get_policy_snapshot, policy_public_key_hash, policy_public_key_pem
from serverware.response_identity import response_public_key_info


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _run_json_command(command: str, payload: dict[str, Any], label: str) -> dict[str, Any]:
    if not command:
        raise ValueError(f"{label} is not configured")
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


def _load_dev_quote_key() -> Ed25519PrivateKey:
    ensure_data_dirs()
    if TEE_QUOTE_SIGNING_KEY_PATH.exists():
        return serialization.load_pem_private_key(TEE_QUOTE_SIGNING_KEY_PATH.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    TEE_QUOTE_SIGNING_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(TEE_QUOTE_SIGNING_KEY_PATH, 0o600)
    return key


def quote_public_key_info() -> dict[str, str]:
    public_key = _load_dev_quote_key().public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"pem": pem, "spki_sha256": sha256_prefixed(der)}


def runtime_manifest() -> dict[str, Any]:
    return {
        "mode": "dev" if TEE_QUOTE_PROVIDER == "dev-signed-quote" else "tee",
        "tee_quote_provider": TEE_QUOTE_PROVIDER,
        "tee_platform": TEE_PLATFORM,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "serverware_version": __version__,
        "policy_signing_key_id": policy_public_key_hash(),
        "release_channel": RELEASE_CHANNEL,
        "key_release_required": KEY_RELEASE_REQUIRED,
        "key_release_require_data_plane_digest": KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST,
        "expected_data_plane_binary_digest": EXPECTED_DATA_PLANE_BINARY_DIGEST,
    }


def runtime_manifest_digest(manifest: dict[str, Any] | None = None) -> str:
    value = runtime_manifest() if manifest is None else manifest
    return sha256_prefixed(repr(sorted(value.items())).encode("utf-8"))


def ca_spki_hash() -> str | None:
    ca_path = MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem"
    if not ca_path.exists():
        return None
    cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_prefixed(der)


def release_provenance_digest() -> str | None:
    if not RELEASE_PROVENANCE_PATH.exists():
        return None
    raw = RELEASE_PROVENANCE_PATH.read_bytes()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return sha256_prefixed(raw)
    digest = data.get("provenance_digest") if isinstance(data, dict) else None
    return digest if isinstance(digest, str) and digest.startswith("sha256:") else sha256_prefixed(raw)


def image_signatures_digest() -> str | None:
    if not IMAGE_SIGNATURES_PATH.exists():
        return None
    raw = IMAGE_SIGNATURES_PATH.read_bytes()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return sha256_prefixed(raw)
    digest = data.get("image_signature_bundle_digest") if isinstance(data, dict) else None
    return digest if isinstance(digest, str) and digest.startswith("sha256:") else sha256_prefixed(raw)


def release_provenance_document() -> dict[str, Any] | None:
    if not RELEASE_PROVENANCE_PATH.exists():
        return None
    try:
        value = json.loads(RELEASE_PROVENANCE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def image_signatures_document() -> dict[str, Any] | None:
    if not IMAGE_SIGNATURES_PATH.exists():
        return None
    try:
        value = json.loads(IMAGE_SIGNATURES_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def source_tree_digest() -> str | None:
    document = release_provenance_document()
    source_tree = ((document or {}).get("provenance") or {}).get("source_tree") or {}
    digest = source_tree.get("digest") if isinstance(source_tree, dict) else None
    return digest if isinstance(digest, str) and digest.startswith("sha256:") else None


def _unsigned_quote(payload: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    copied.pop("signature", None)
    return copied


def sign_quote(claims: dict[str, Any]) -> dict[str, Any]:
    if TEE_QUOTE_PROVIDER != "dev-signed-quote":
        quote = _run_json_command(TEE_QUOTE_COMMAND, {"claims": claims}, "TEE quote command")
        quote.setdefault("version", 1)
        quote.setdefault("provider", TEE_QUOTE_PROVIDER)
        quote.setdefault("tee_platform", TEE_PLATFORM)
        quote_claims = quote.get("claims")
        if not isinstance(quote_claims, dict):
            raise ValueError("TEE quote command must return normalized claims")
        return quote
    key = _load_dev_quote_key()
    key_info = quote_public_key_info()
    quote = {
        "version": 1,
        "provider": "dev-signed-quote",
        "tee_platform": "none-dev",
        "issued_at_ms": int(time.time() * 1000),
        "debug": True,
        "quote_signing_key_id": key_info["spki_sha256"],
        "quote_signing_public_key_pem": key_info["pem"],
        "claims": claims,
    }
    quote["signature"] = "ed25519:" + b64e(key.sign(canonical_json(_unsigned_quote(quote)).encode("utf-8")))
    return quote


def verify_quote_signature(quote: dict[str, Any]) -> None:
    if quote.get("provider") != "dev-signed-quote":
        if not TEE_QUOTE_VERIFY_COMMAND:
            raise ValueError("external TEE quote verification command is not configured")
        return
    signature = quote.get("signature")
    public_key_pem = quote.get("quote_signing_public_key_pem")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ValueError("quote is missing an ed25519 signature")
    if not isinstance(public_key_pem, str):
        raise ValueError("quote is missing public key")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    try:
        public_key.verify(b64d(signature.split(":", 1)[1]), canonical_json(_unsigned_quote(quote)).encode("utf-8"))
    except InvalidSignature as exc:
        raise ValueError("quote signature verification failed") from exc
    key_info_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if quote.get("quote_signing_key_id") != sha256_prefixed(key_info_der):
        raise ValueError("quote signing key id does not match public key")


def verify_attestation_quote(attestation: dict[str, Any]) -> dict[str, Any]:
    quote = attestation.get("quote")
    if not isinstance(quote, dict):
        raise ValueError("attestation quote is missing")
    if quote.get("provider") == "dev-signed-quote":
        verify_quote_signature(quote)
        claims = quote.get("claims")
    else:
        verified = _run_json_command(
            TEE_QUOTE_VERIFY_COMMAND,
            {"attestation": attestation},
            "TEE quote verification command",
        )
        claims = verified.get("claims", verified)
    if not isinstance(claims, dict):
        raise ValueError("attestation quote claims are missing")
    return claims


def attestation_document(nonce: str | None = None) -> dict[str, Any]:
    snapshot = get_policy_snapshot()
    metadata = snapshot.raw.get("metadata") if snapshot else {}
    manifest = runtime_manifest()
    policy_hash = snapshot.hash if snapshot else None
    rollback_epoch = metadata.get("rollbackEpoch") if isinstance(metadata, dict) else None
    ca_hash = ca_spki_hash()
    provenance_digest = release_provenance_digest()
    image_signature_digest = image_signatures_digest()
    source_digest = source_tree_digest()
    response_key_info = response_public_key_info()
    data_plane_digest = EXPECTED_DATA_PLANE_BINARY_DIGEST
    quote_claims = {
        "nonce": nonce,
        "runtime_manifest_digest": runtime_manifest_digest(manifest),
        "policy_bundle_digest": policy_hash,
        "policy_signing_key_id": metadata.get("signingKeyId") if isinstance(metadata, dict) else None,
        "ca_intermediate_spki_sha256": ca_hash,
        "data_plane_binary_digest": data_plane_digest,
        "service_tls_spki_sha256": None,
        "rollback_epoch": rollback_epoch,
        "provenance_digest": provenance_digest,
        "image_signatures_digest": image_signature_digest,
        "source_tree_digest": source_digest,
        "response_signing_key_id": response_key_info["spki_sha256"],
        "release_channel": RELEASE_CHANNEL,
        "debug": TEE_QUOTE_PROVIDER == "dev-signed-quote",
        "key_release_required": KEY_RELEASE_REQUIRED,
        "key_release_allow_debug": KEY_RELEASE_ALLOW_DEBUG,
        "materials": ["broker-kek", "decision-gate-ca"],
        "sealing_public_key_id": quote_public_key_info()["spki_sha256"],
    }
    quote = sign_quote(quote_claims)
    return {
        "tee_platform": quote.get("tee_platform", TEE_PLATFORM),
        "quote": quote,
        "runtime_manifest": manifest,
        "runtime_manifest_digest": quote_claims["runtime_manifest_digest"],
        "policy_bundle_digest": policy_hash,
        "policy_bundle_signature": metadata.get("signature") if isinstance(metadata, dict) else None,
        "policy_signing_key_id": metadata.get("signingKeyId") if isinstance(metadata, dict) else None,
        "policy_signing_public_key_pem": policy_public_key_pem(),
        "ca_intermediate_spki_sha256": ca_hash,
        "data_plane_binary_digest": data_plane_digest,
        "service_tls_spki_sha256": None,
        "rollback_epoch": rollback_epoch,
        "provenance_digest": provenance_digest,
        "image_signatures_digest": image_signature_digest,
        "source_tree_digest": source_digest,
        "response_signing_key_id": response_key_info["spki_sha256"],
        "response_signing_public_key_pem": response_key_info["pem"],
        "release_channel": RELEASE_CHANNEL,
        "nonce": nonce,
        "tls_exporter_binding": None,
    }
