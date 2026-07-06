#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SECRET_FIELD_NAMES = {
    "plaintext",
    "secret",
    "private_key",
    "private_key_pem",
    "raw_material",
    "material_value",
    "unwrapped_key",
    "decrypted_key",
}
AUTHORIZED_MATERIALS = {"broker-kek", "decision-gate-ca"}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64d(value: str, label: str = "base64 value") -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except Exception as exc:
        raise SystemExit(f"{label} is invalid base64") from exc


def b64url_d(value: str, label: str = "base64url value") -> bytes:
    translated = value.replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(translated + "=" * (-len(translated) % 4), validate=True)
    except Exception as exc:
        raise SystemExit(f"{label} is invalid base64url") from exc


def read_stdin() -> dict[str, Any]:
    payload = json.loads(sys.stdin.read() or "{}")
    if not isinstance(payload, dict):
        raise SystemExit("stdin must be a JSON object")
    return payload


def request_without_digest(payload: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    copied.pop("request_digest", None)
    return copied


def reject_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in SECRET_FIELD_NAMES:
                raise SystemExit(f"AWS KMS response contained plaintext material field {path}.{key}")
            reject_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_fields(child, f"{path}[{index}]")


def load_materials(path: str | None) -> dict[str, Any]:
    raw = ""
    if path:
        raw = Path(path).read_text(encoding="utf-8")
    else:
        raw = os.getenv("SERVERWARE_AWS_KMS_MATERIALS_JSON", "")
    if not raw.strip():
        raise SystemExit("--materials-file or SERVERWARE_AWS_KMS_MATERIALS_JSON is required")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise SystemExit("AWS KMS materials config must be a JSON object")
    return parsed


def material_config(materials: dict[str, Any], material: str) -> dict[str, Any]:
    config = materials.get(material)
    if not isinstance(config, dict):
        raise SystemExit(f"AWS KMS materials config missing material {material}")
    key_id = config.get("key_id") or config.get("keyId") or config.get("kms_key_id")
    if not isinstance(key_id, str) or not key_id:
        raise SystemExit(f"AWS KMS material {material} missing key_id")
    has_blob = any(config.get(name) for name in ("ciphertext_blob_b64", "ciphertextBlobB64", "ciphertext_blob_path", "ciphertextBlobPath"))
    if not has_blob:
        raise SystemExit(f"AWS KMS material {material} missing ciphertext blob")
    return config


def ciphertext_blob(config: dict[str, Any]) -> bytes:
    path = config.get("ciphertext_blob_path") or config.get("ciphertextBlobPath")
    if isinstance(path, str) and path:
        return Path(path).read_bytes()
    raw_b64 = config.get("ciphertext_blob_b64") or config.get("ciphertextBlobB64")
    if not isinstance(raw_b64, str) or not raw_b64:
        raise SystemExit("AWS KMS material missing ciphertext blob")
    return b64d(raw_b64, "AWS KMS material ciphertext_blob_b64")


def attestation_document_from_request(payload: dict[str, Any]) -> bytes:
    tee = payload.get("tee")
    claims = payload.get("claims")
    if isinstance(claims, dict) and isinstance(claims.get("tee"), dict):
        tee = claims["tee"]
    if not isinstance(tee, dict):
        raise SystemExit("AWS KMS release request missing verified Nitro tee metadata")
    raw_b64 = tee.get("raw_attestation_document_b64")
    if not isinstance(raw_b64, str) or not raw_b64:
        raise SystemExit("AWS KMS release request missing raw_attestation_document_b64")
    raw = b64url_d(raw_b64, "AWS KMS release request raw_attestation_document_b64")
    expected = tee.get("raw_attestation_document_sha256")
    if expected and expected != sha256_prefixed(raw):
        raise SystemExit("AWS KMS release request attestation document digest mismatch")
    return raw


def validate_request(payload: dict[str, Any]) -> None:
    if payload.get("apiVersion") != "serverware.nitroKmsReleaseRequest/v1":
        raise SystemExit("unexpected apiVersion")
    if payload.get("kind") != "NitroKmsMaterialRelease":
        raise SystemExit("unexpected kind")
    expected_digest = sha256_prefixed(canonical_json(request_without_digest(payload)).encode("utf-8"))
    if payload.get("request_digest") != expected_digest:
        raise SystemExit("request digest mismatch")
    claims = payload.get("claims")
    tee = payload.get("tee")
    if not isinstance(claims, dict) or not isinstance(tee, dict) or tee.get("verified") is not True:
        raise SystemExit("release request is not bound to verified Nitro claims")
    material = payload.get("material")
    if not isinstance(material, str) or not material:
        raise SystemExit("missing material")
    if material not in AUTHORIZED_MATERIALS:
        raise SystemExit(f"unauthorized material: {material}")


def run_aws_kms_decrypt(
    *,
    aws_binary: str,
    key_id: str,
    ciphertext: bytes,
    attestation_document: bytes,
    encryption_context: dict[str, Any] | None,
    region: str | None,
    timeout: float,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        ciphertext_path = tmp / "ciphertext.bin"
        attestation_path = tmp / "attestation.bin"
        ciphertext_path.write_bytes(ciphertext)
        attestation_path.write_bytes(attestation_document)
        command = [
            aws_binary,
            "kms",
            "decrypt",
            "--key-id",
            key_id,
            "--ciphertext-blob",
            f"fileb://{ciphertext_path}",
            "--recipient",
            f"KeyEncryptionAlgorithm=RSAES_OAEP_SHA_256,AttestationDocument=fileb://{attestation_path}",
            "--output",
            "json",
        ]
        if encryption_context:
            command.extend(["--encryption-context", canonical_json(encryption_context)])
        if region:
            command.extend(["--region", region])
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace") or result.stdout.decode("utf-8", errors="replace")
        raise SystemExit(f"aws kms decrypt failed with exit {result.returncode}: {detail.strip()}")
    response = json.loads(result.stdout.decode("utf-8"))
    if not isinstance(response, dict):
        raise SystemExit("aws kms decrypt returned non-object JSON")
    reject_secret_fields(response)
    if not response.get("CiphertextForRecipient"):
        raise SystemExit("aws kms decrypt response missing CiphertextForRecipient")
    return response


def release(args: argparse.Namespace) -> None:
    payload = read_stdin()
    validate_request(payload)
    materials = load_materials(args.materials_file)
    material = str(payload["material"])
    config = material_config(materials, material)
    key_id = str(config.get("key_id") or config.get("keyId") or config.get("kms_key_id"))
    context = config.get("encryption_context") or config.get("encryptionContext")
    if context is not None and not isinstance(context, dict):
        raise SystemExit("AWS KMS encryption_context must be a JSON object")
    ciphertext = ciphertext_blob(config)
    attestation_document = attestation_document_from_request(payload)
    response = run_aws_kms_decrypt(
        aws_binary=args.aws_binary,
        key_id=key_id,
        ciphertext=ciphertext,
        attestation_document=attestation_document,
        encryption_context=context,
        region=args.region,
        timeout=args.timeout,
    )
    recipient_ciphertext = b64d(str(response["CiphertextForRecipient"]), "AWS KMS CiphertextForRecipient")
    tee = payload.get("tee") if isinstance(payload.get("tee"), dict) else {}
    output = {
        "ok": True,
        "provider": "aws-kms-recipient",
        "material": material,
        "request_digest": payload["request_digest"],
        "release_handle": payload.get("release_handle"),
        "ciphertext_blob_sha256": sha256_prefixed(ciphertext),
        "encryption_context_sha256": sha256_prefixed(canonical_json(context or {}).encode("utf-8")),
        "material_handle": sha256_prefixed(recipient_ciphertext),
        "recipient_ciphertext_sha256": sha256_prefixed(recipient_ciphertext),
        "attestation_document_sha256": sha256_prefixed(attestation_document),
        "key_provider": {
            "type": "aws-kms",
            "key_id": response.get("KeyId") or key_id,
        },
        "audit": {
            "tee_provider": payload.get("provider"),
            "tee_platform": payload.get("tee_platform"),
            "pcrs": sorted((tee.get("pcrs") or {}).keys()) if isinstance(tee.get("pcrs"), dict) else [],
            "encryption_context_sha256": sha256_prefixed(canonical_json(context or {}).encode("utf-8")),
            "ciphertext_blob_sha256": sha256_prefixed(ciphertext),
        },
    }
    print(canonical_json(output))


def main() -> None:
    parser = argparse.ArgumentParser(description="AWS KMS Recipient adapter for Nitro enclave-bound material release.")
    subparsers = parser.add_subparsers(dest="command")
    release_parser = subparsers.add_parser("release")
    release_parser.add_argument("--materials-file", default=None)
    release_parser.add_argument("--aws-binary", default=os.getenv("SERVERWARE_AWS_CLI", "aws"))
    release_parser.add_argument("--region", default=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"))
    release_parser.add_argument("--timeout", type=float, default=float(os.getenv("SERVERWARE_AWS_KMS_TIMEOUT_SECONDS", "30")))
    args = parser.parse_args()
    if args.command != "release":
        raise SystemExit("usage: aws_kms_recipient_release.py release [--materials-file path]")
    release(args)


if __name__ == "__main__":
    main()
