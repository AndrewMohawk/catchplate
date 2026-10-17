#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parent))

from aws_nitro_tee_provider import (  # noqa: E402
    PROVIDER,
    TEE_PLATFORM,
    b64e,
    canonical_json,
    claims_user_data,
    make_fixture_attestation_document,
    sha256_prefixed,
)


def read_stdin() -> dict[str, Any]:
    payload = json.loads(sys.stdin.read() or "{}")
    if not isinstance(payload, dict):
        raise SystemExit("stdin must be a JSON object")
    return payload


def request_without_digest(payload: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    copied.pop("request_digest", None)
    return copied


def attest() -> None:
    payload = read_stdin()
    if payload.get("apiVersion") != "catchplate.nitroAttestationRequest/v1":
        raise SystemExit("unexpected apiVersion")
    if payload.get("kind") != "NitroAttestationDocument":
        raise SystemExit("unexpected kind")
    if payload.get("provider") != PROVIDER or payload.get("tee_platform") != TEE_PLATFORM:
        raise SystemExit("unexpected Nitro provider metadata")
    claims = payload.get("claims")
    if not isinstance(claims, dict):
        raise SystemExit("missing claims")
    expected_user_data = claims_user_data(claims)
    if payload.get("user_data_sha256") != sha256_prefixed(expected_user_data):
        raise SystemExit("user_data_sha256 mismatch")
    expected_request_digest = sha256_prefixed(canonical_json(request_without_digest(payload)).encode("utf-8"))
    if payload.get("request_digest") != expected_request_digest:
        raise SystemExit("request digest mismatch")

    document_claims = json.loads(json.dumps(claims))
    if os.getenv("CATCHPLATE_NITRO_ATTESTATION_FIXTURE_BAD_DOCUMENT"):
        document_claims["nonce"] = f"{document_claims.get('nonce', '')}:tampered"
    response = {
        "ok": True,
        "provider": "aws-nitro-nsm",
        "tee_platform": TEE_PLATFORM,
        "request_digest": payload["request_digest"],
        "attestation_document_b64": b64e(make_fixture_attestation_document(document_claims)),
    }
    if os.getenv("CATCHPLATE_NITRO_ATTESTATION_FIXTURE_BAD_B64"):
        response["attestation_document_b64"] = "not-valid-@@@@"
    if os.getenv("CATCHPLATE_NITRO_ATTESTATION_FIXTURE_BAD_DIGEST"):
        response["request_digest"] = "sha256:" + "0" * 64
    print(canonical_json(response))


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else "attest"
    if command != "attest":
        raise SystemExit("usage: nitro_attestation_fixture.py attest")
    attest()


if __name__ == "__main__":
    main()
