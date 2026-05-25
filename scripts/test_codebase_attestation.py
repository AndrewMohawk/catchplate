from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("SERVERWARE_DATA_DIR", str(Path(".tmp/test-codebase-attestation/data").resolve()))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization

from serverware.response_identity import canonical_json, response_public_key_info, response_signature_headers, response_statement


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def main() -> None:
    body = b'{"ok":true}'
    context = {
        "runtime_manifest_digest": "sha256:" + "1" * 64,
        "policy_bundle_digest": "sha256:" + "2" * 64,
        "provenance_digest": "sha256:" + "3" * 64,
        "image_signatures_digest": "sha256:" + "4" * 64,
        "source_tree_digest": "sha256:" + "5" * 64,
    }
    statement = response_statement(
        method="GET",
        path="/attestation",
        query="nonce=test",
        status_code=200,
        body=body,
        nonce="client-nonce",
        context=context,
    )
    headers = response_signature_headers(statement)
    assert headers["X-Serverware-Response-Body-SHA256"] == sha256_prefixed(body)
    decoded = json.loads(b64d(headers["X-Serverware-Response-Statement-B64"]))
    assert decoded == statement
    public_key = serialization.load_pem_public_key(response_public_key_info()["pem"].encode("ascii"))
    public_key.verify(
        b64d(headers["X-Serverware-Response-Signature"].split(":", 1)[1]),
        canonical_json(statement).encode("utf-8"),
    )
    print("codebase attestation response signature tests passed")


if __name__ == "__main__":
    main()
