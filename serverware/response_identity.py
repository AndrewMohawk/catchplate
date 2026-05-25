from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware.config import RESPONSE_SIGNING_KEY_PATH, ensure_data_dirs


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _load_response_key() -> Ed25519PrivateKey:
    ensure_data_dirs()
    if RESPONSE_SIGNING_KEY_PATH.exists():
        return serialization.load_pem_private_key(RESPONSE_SIGNING_KEY_PATH.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    RESPONSE_SIGNING_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(RESPONSE_SIGNING_KEY_PATH, 0o600)
    return key


def response_public_key_info() -> dict[str, str]:
    public_key = _load_response_key().public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"pem": pem, "spki_sha256": sha256_prefixed(der)}


def response_statement(
    *,
    method: str,
    path: str,
    query: str,
    status_code: int,
    body: bytes,
    nonce: str | None,
    context: dict[str, Any],
) -> dict[str, Any]:
    key_info = response_public_key_info()
    return {
        "version": "serverware.responseSignature/v1",
        "issued_at_ms": int(time.time() * 1000),
        "request": {
            "method": method.upper(),
            "path": path,
            "query": query,
        },
        "status_code": status_code,
        "body_sha256": sha256_prefixed(body),
        "nonce": nonce,
        "response_signing_key_id": key_info["spki_sha256"],
        "context": context,
    }


def sign_statement(statement: dict[str, Any]) -> str:
    key = _load_response_key()
    return "ed25519:" + b64e(key.sign(canonical_json(statement).encode("utf-8")))


def response_signature_headers(statement: dict[str, Any]) -> dict[str, str]:
    encoded_statement = b64e(canonical_json(statement).encode("utf-8"))
    signature = sign_statement(statement)
    return {
        "X-Serverware-Response-Key-Id": str(statement["response_signing_key_id"]),
        "X-Serverware-Response-Body-SHA256": str(statement["body_sha256"]),
        "X-Serverware-Response-Statement-SHA256": sha256_prefixed(canonical_json(statement).encode("utf-8")),
        "X-Serverware-Response-Statement-B64": encoded_statement,
        "X-Serverware-Response-Signature": signature,
    }
