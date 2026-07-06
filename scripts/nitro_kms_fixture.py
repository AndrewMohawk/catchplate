#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


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
    handle = sha256_prefixed(canonical_json({"material": material, "claims": claims, "tee": tee}).encode("utf-8"))
    response = {
        "ok": True,
        "provider": "fixture-kms-hsm",
        "material": material,
        "request_digest": payload["request_digest"],
        "release_handle": payload.get("release_handle"),
        "material_handle": handle,
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
