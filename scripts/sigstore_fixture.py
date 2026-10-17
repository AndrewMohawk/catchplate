#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent.parent


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def key_path() -> Path:
    return Path(os.getenv("CATCHPLATE_SIGSTORE_FIXTURE_KEY", str(ROOT / ".tmp" / "sigstore-fixture-ed25519.pem")))


def log_path() -> Path:
    return Path(os.getenv("CATCHPLATE_SIGSTORE_FIXTURE_LOG", str(ROOT / ".tmp" / "sigstore-fixture-rekor.jsonl")))


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
    return {"public_key_pem": pem, "key_id": sha256_prefixed_bytes(der)}


def signed_payload(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": request.get("kind"),
        "service": request.get("service"),
        "image_id": request.get("image_id"),
        "statement_digest": request.get("statement_digest"),
        "statement": request.get("statement"),
    }


def append_log(entry: dict[str, Any]) -> dict[str, Any]:
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if path.exists():
        existing = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    log_index = len(existing)
    entry = dict(entry)
    entry["log_index"] = log_index
    entry["entry_uuid"] = str(uuid.uuid5(uuid.NAMESPACE_URL, sha256_prefixed_json(entry)))
    entry["integrated_time"] = datetime.now(timezone.utc).isoformat()
    entry["entry_digest"] = sha256_prefixed_json(entry)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(entry) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    log_id = sha256_prefixed_bytes(str(path).encode("utf-8"))
    return {
        "log_id": log_id,
        "entry_uuid": entry["entry_uuid"],
        "integrated_time": entry["integrated_time"],
        "log_index": log_index,
        "inclusion_proof": {
            "type": "fixture-inclusion-proof",
            "entry_digest": entry["entry_digest"],
            "tree_size": log_index + 1,
        },
    }


def sign() -> dict[str, Any]:
    request = json.loads(sys.stdin.read() or "{}")
    statement_digest = request.get("statement_digest")
    if statement_digest != sha256_prefixed_json(request.get("statement")):
        raise ValueError("statement_digest does not match statement")
    key = load_key()
    info = key_info(key)
    payload = signed_payload(request)
    signature = "sigstore-fixture-ed25519:" + b64e(key.sign(canonical_json(payload).encode("utf-8")))
    transparency = append_log(
        {
            "apiVersion": "catchplate.sigstoreFixtureLog/v1",
            "kind": request.get("kind"),
            "service": request.get("service"),
            "image_id": request.get("image_id"),
            "statement_digest": statement_digest,
            "signature": signature,
            "key_id": info["key_id"],
        }
    )
    return {
        "ok": True,
        "provider": "sigstore-fixture",
        "statement_digest": statement_digest,
        "signature": signature,
        "key_provider": {
            "type": os.getenv("CATCHPLATE_SIGSTORE_FIXTURE_KEY_PROVIDER", "kms"),
            "key_ref": os.getenv("CATCHPLATE_SIGSTORE_FIXTURE_KEY_REF", "kms://fixture/catchplate-release-images"),
            "key_id": info["key_id"],
            "workload_identity": os.getenv("CATCHPLATE_SIGSTORE_FIXTURE_WORKLOAD_IDENTITY", "fixture://github-actions/catchplate-release"),
        },
        "transparency": transparency,
        "bundle": {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {
                "publicKey": info["public_key_pem"],
                "transparencyLog": transparency,
            },
            "messageSignature": {
                "messageDigest": statement_digest,
                "signature": signature,
            },
        },
    }


def verify() -> dict[str, Any]:
    request = json.loads(sys.stdin.read() or "{}")
    signature_response = request.get("signature_response") or {}
    statement_digest = request.get("statement_digest")
    if statement_digest != sha256_prefixed_json(request.get("statement")):
        raise ValueError("statement_digest does not match statement")
    if signature_response.get("statement_digest") != statement_digest:
        raise ValueError("signature response statement_digest mismatch")
    signature = signature_response.get("signature", "")
    if not signature.startswith("sigstore-fixture-ed25519:"):
        raise ValueError("unsupported signature format")
    public_key_pem = ((signature_response.get("bundle") or {}).get("verificationMaterial") or {}).get("publicKey")
    if not isinstance(public_key_pem, str):
        raise ValueError("signature response missing public key")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    public_key.verify(
        b64d(signature.split(":", 1)[1]),
        canonical_json(signed_payload(request)).encode("utf-8"),
    )
    transparency = signature_response.get("transparency") or {}
    for field in ("log_id", "entry_uuid", "integrated_time", "inclusion_proof"):
        if field not in transparency:
            raise ValueError(f"signature response missing transparency.{field}")
    return {
        "ok": True,
        "provider": "sigstore-fixture",
        "statement_digest": statement_digest,
        "verified_transparency": True,
    }


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else "sign"
    if command == "sign":
        response = sign()
    elif command == "verify":
        response = verify()
    else:
        raise SystemExit(f"unknown command: {command}")
    print(canonical_json(response))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"sigstore fixture failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
