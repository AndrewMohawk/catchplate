#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def recipient_public_key(tee: dict[str, Any]) -> tuple[rsa.RSAPublicKey, bytes, bytes]:
    raw_b64 = tee.get("raw_attestation_document_b64")
    if not isinstance(raw_b64, str) or not raw_b64:
        raise SystemExit("fixture release request is missing the raw attestation document")
    raw = b64d(raw_b64)
    cose = cbor2.loads(raw)
    if isinstance(cose, cbor2.CBORTag):
        cose = cose.value
    if not isinstance(cose, list) or len(cose) != 4 or not isinstance(cose[2], bytes):
        raise SystemExit("fixture release request has an invalid attestation document")
    document = cbor2.loads(cose[2])
    public_key_der = document.get("public_key") if isinstance(document, dict) else None
    if not isinstance(public_key_der, bytes):
        raise SystemExit("fixture release request attestation is missing public_key")
    public_key = serialization.load_der_public_key(public_key_der)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise SystemExit("fixture recipient public key must be RSA")
    return public_key, public_key_der, raw


def read_stdin() -> dict[str, Any]:
    payload = json.loads(sys.stdin.read() or "{}")
    if not isinstance(payload, dict):
        raise SystemExit("stdin must be a JSON object")
    return payload


def key_path() -> Path:
    fixture_dir = os.getenv("SERVERWARE_NITRO_FIXTURE_DIR")
    default_root = Path(fixture_dir) if fixture_dir else Path(os.getenv("SERVERWARE_DATA_DIR", "/data"))
    default = default_root / "nitro-kms-fixture-ed25519.pem"
    return Path(os.getenv("SERVERWARE_NITRO_KMS_FIXTURE_KEY", str(default)))


def load_key() -> Ed25519PrivateKey:
    path = key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)
    return key


def key_info(key: Ed25519PrivateKey) -> dict[str, str]:
    public_key = key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"public_key_pem": pem, "key_id": sha256_prefixed(der)}


def request_without_digest(payload: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    copied.pop("request_digest", None)
    return copied


def release() -> None:
    payload = read_stdin()
    if os.getenv("SERVERWARE_NITRO_KMS_FIXTURE_DENY"):
        print(canonical_json({"ok": False, "provider": "fixture-kms-hsm", "reason": "fixture-deny"}))
        return
    if payload.get("apiVersion") != "serverware.nitroKmsReleaseRequest/v1":
        raise SystemExit("unexpected apiVersion")
    if payload.get("kind") != "NitroKmsMaterialRelease":
        raise SystemExit("unexpected kind")
    material = payload.get("material")
    if not isinstance(material, str) or not material:
        raise SystemExit("missing material")
    claims = payload.get("claims")
    tee = payload.get("tee")
    if not isinstance(claims, dict) or not isinstance(tee, dict) or tee.get("verified") is not True:
        raise SystemExit("release request is not bound to verified Nitro claims")
    expected_digest = sha256_prefixed(canonical_json(request_without_digest(payload)).encode("utf-8"))
    if payload.get("request_digest") != expected_digest:
        raise SystemExit("request digest mismatch")
    key = load_key()
    info = key_info(key)
    public_key, public_key_der, raw_attestation = recipient_public_key(tee)
    fixture_material = (b"fixture-broker-kek-32-byte-key!!" if material == "broker-kek" else b"fixture-decision-gate-ca-key")
    recipient_ciphertext = public_key.encrypt(
        fixture_material,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    handle = sha256_prefixed(recipient_ciphertext)
    response = {
        "ok": True,
        "provider": "fixture-kms-hsm",
        "material": material,
        "request_digest": payload["request_digest"],
        "release_handle": payload.get("release_handle"),
        "material_handle": handle,
        "ciphertext_blob_sha256": sha256_prefixed(f"fixture-kms-ciphertext:{material}".encode("utf-8")),
        "recipient_ciphertext_b64": base64.b64encode(recipient_ciphertext).decode("ascii"),
        "recipient_ciphertext_sha256": handle,
        "recipient_public_key_sha256": sha256_prefixed(public_key_der),
        "recipient_public_key_algorithm": "RSAES_OAEP_SHA_256",
        "recipient_public_key_bits": public_key.key_size,
        "attestation_document_sha256": sha256_prefixed(raw_attestation),
        "key_provider": {
            "type": "fixture-hsm",
            "key_id": info["key_id"],
        },
        "audit": {
            "tee_provider": payload.get("provider"),
            "tee_platform": payload.get("tee_platform"),
            "pcrs": sorted((tee.get("pcrs") or {}).keys()),
        },
    }
    if os.getenv("SERVERWARE_NITRO_KMS_FIXTURE_BAD_DIGEST"):
        response["request_digest"] = "sha256:" + "0" * 64
    if os.getenv("SERVERWARE_NITRO_KMS_FIXTURE_SECRET_RESPONSE"):
        response["plaintext"] = "fixture-secret-that-must-never-be-accepted"
    response["signature"] = "ed25519:" + b64e(key.sign(canonical_json(response).encode("utf-8")))
    response["public_key_pem"] = info["public_key_pem"]
    print(canonical_json(response))


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else "release"
    if command != "release":
        raise SystemExit("usage: nitro_kms_fixture.py release")
    release()


if __name__ == "__main__":
    main()
