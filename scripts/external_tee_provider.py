#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def key_path() -> Path:
    default = Path(os.getenv("SERVERWARE_DATA_DIR", "/data")) / "external-tee-fixture-ed25519.pem"
    return Path(os.getenv("SERVERWARE_EXTERNAL_TEE_FIXTURE_KEY", str(default)))


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


def public_key_info(key: Ed25519PrivateKey) -> dict[str, str]:
    public_key = key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"pem": pem, "spki_sha256": sha256_prefixed(der)}


def unsigned_quote(quote: dict[str, Any]) -> dict[str, Any]:
    copied = dict(quote)
    copied.pop("signature", None)
    return copied


def read_stdin() -> dict[str, Any]:
    payload = json.loads(sys.stdin.read() or "{}")
    if not isinstance(payload, dict):
        raise SystemExit("stdin must be a JSON object")
    return payload


def quote() -> None:
    payload = read_stdin()
    claims = payload.get("claims")
    if not isinstance(claims, dict):
        raise SystemExit("quote input missing claims")
    key = load_key()
    key_info = public_key_info(key)
    document = {
        "version": 1,
        "provider": "external-command-fixture",
        "tee_platform": "fixture-tee",
        "issued_at_ms": int(time.time() * 1000),
        "debug": False,
        "quote_signing_key_id": key_info["spki_sha256"],
        "quote_signing_public_key_pem": key_info["pem"],
        "claims": claims,
        "raw_quote": "fixture:" + sha256_prefixed(canonical_json(claims).encode("utf-8")),
    }
    document["signature"] = "ed25519:" + b64e(key.sign(canonical_json(unsigned_quote(document)).encode("utf-8")))
    print(canonical_json(document))


def verify() -> None:
    payload = read_stdin()
    quote_doc = (payload.get("attestation") or {}).get("quote") if "attestation" in payload else payload.get("quote")
    if not isinstance(quote_doc, dict):
        raise SystemExit("verify input missing quote")
    signature = quote_doc.get("signature")
    public_key_pem = quote_doc.get("quote_signing_public_key_pem")
    if not isinstance(signature, str) or not signature.startswith("ed25519:") or not isinstance(public_key_pem, str):
        raise SystemExit("quote missing fixture signature")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    try:
        public_key.verify(b64d(signature.split(":", 1)[1]), canonical_json(unsigned_quote(quote_doc)).encode("utf-8"))
    except InvalidSignature:
        raise SystemExit("fixture quote signature invalid")
    claims = quote_doc.get("claims")
    if not isinstance(claims, dict):
        raise SystemExit("quote missing claims")
    print(canonical_json({"ok": True, "provider": quote_doc.get("provider"), "claims": claims}))


def release() -> None:
    payload = read_stdin()
    claims = payload.get("claims") or {}
    expected = payload.get("expected") or {}
    if claims.get("debug") is True:
        raise SystemExit("debug quotes are not accepted by the external release fixture")
    checks = {
        "policy_bundle_digest": "policy_bundle_digest",
        "ca_intermediate_spki_sha256": "ca_intermediate_spki_sha256",
        "rollback_epoch": "rollback_epoch",
        "release_channel": "release_channel",
        "provenance_digest": "provenance_digest",
        "source_tree_digest": "source_tree_digest",
        "response_signing_key_id": "response_signing_key_id",
        "data_plane_binary_digest": "data_plane_binary_digest",
    }
    for expected_key, claim_key in checks.items():
        expected_value = expected.get(expected_key)
        if expected_value is not None and claims.get(claim_key) != expected_value:
            raise SystemExit(f"{claim_key} mismatch")
    material = str(payload.get("material") or "")
    handle = sha256_prefixed(canonical_json({"material": material, "claims": claims}).encode("utf-8"))
    print(canonical_json({"ok": True, "provider": "fixture-kms-hsm", "material": material, "release_handle": handle}))


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"quote", "verify", "release"}:
        raise SystemExit("usage: external_tee_provider.py quote|verify|release")
    {"quote": quote, "verify": verify, "release": release}[sys.argv[1]]()


if __name__ == "__main__":
    main()
