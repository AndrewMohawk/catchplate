#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


BROKER_KEK = b"0123456789abcdef0123456789abcdef"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64url_e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def fixture_unseal(argv: list[str]) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--ciphertext", required=True)
    parser.add_argument("--short", action="store_true")
    args = parser.parse_args(argv)
    private_key = serialization.load_pem_private_key(Path(args.private_key).read_bytes(), password=None)
    ciphertext = Path(args.ciphertext).read_bytes()
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    if args.short:
        plaintext = plaintext[:16]
    print(canonical_json({"keyB64": b64url_e(plaintext)}))


def release_receipt(recipient_ciphertext: bytes, recipient_public_key_der: bytes) -> dict[str, Any]:
    release_handle = digest(b"release-handle")
    kms_request_digest = digest(b"kms-request")
    attestation_digest = digest(b"nitro-attestation-document")
    recipient_key_digest = digest(recipient_public_key_der)
    recipient_ciphertext_digest = digest(recipient_ciphertext)
    kms_release = {
        "ok": True,
        "provider": "aws-kms-recipient",
        "material": "broker-kek",
        "request_digest": kms_request_digest,
        "release_handle": release_handle,
        "ciphertext_blob_sha256": digest(b"kms-encrypted-broker-kek"),
        "encryption_context_sha256": digest(b"encryption-context"),
        "material_handle": recipient_ciphertext_digest,
        "recipient_ciphertext_b64": b64e(recipient_ciphertext),
        "recipient_ciphertext_sha256": recipient_ciphertext_digest,
        "recipient_public_key_sha256": recipient_key_digest,
        "recipient_public_key_algorithm": "RSAES_OAEP_SHA_256",
        "recipient_public_key_bits": 2048,
        "attestation_document_sha256": attestation_digest,
        "key_provider": {"type": "aws-kms", "key_id": "arn:aws:kms:us-east-1:111122223333:key/catchplate"},
    }
    return {
        "ok": True,
        "enabled": True,
        "released": True,
        "material": "broker-kek",
        "key_release_provider": "external-command",
        "attestation_document_sha256": attestation_digest,
        "recipient_public_key_sha256": recipient_key_digest,
        "external_release": {
            "ok": True,
            "provider": "aws-nitro-kms-policy",
            "material": "broker-kek",
            "release_handle": release_handle,
            "kms_request_digest": kms_request_digest,
            "kms_release": kms_release,
        },
    }


def unseal_request(release: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "apiVersion": "catchplate.masterKeyUnsealRequest/v1",
        "kind": "MasterKeyUnseal",
        "material": "broker-kek",
        "releaseHandle": release["external_release"]["release_handle"],
        "releaseReceiptDigest": digest(canonical_json(release).encode("utf-8")),
        "releaseReceipt": release,
    }
    payload["requestDigest"] = digest(canonical_json(payload).encode("utf-8"))
    return payload


def refresh_request(payload: dict[str, Any]) -> None:
    payload["releaseReceiptDigest"] = digest(canonical_json(payload["releaseReceipt"]).encode("utf-8"))
    payload.pop("requestDigest", None)
    payload["requestDigest"] = digest(canonical_json(payload).encode("utf-8"))


def run_adapter(
    payload: dict[str, Any],
    command_template: str,
    *,
    allow_fixture: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    command = [
        sys.executable,
        "scripts/aws_nitro_kms_unseal.py",
        "unseal",
        "--command-template",
        command_template,
        "--output-format",
        "json",
    ]
    if allow_fixture:
        command.append("--allow-fixtures-for-test")
    return subprocess.run(
        command,
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")


def expect_failure(
    payload: dict[str, Any],
    command_template: str,
    expected: str,
    *,
    allow_fixture: bool = True,
) -> None:
    result = run_adapter(payload, command_template, allow_fixture=allow_fixture)
    if result.returncode == 0 or expected not in detail(result):
        raise AssertionError(f"Nitro KMS unseal failure mismatch, expected {expected!r}: {detail(result)}")


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--fixture-unseal":
        fixture_unseal(sys.argv[2:])
        return

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_path = tmp / "recipient-key.pem"
        private_key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        os.chmod(private_key_path, 0o600)
        public_key_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        recipient_ciphertext = private_key.public_key().encrypt(
            BROKER_KEK,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        payload = unseal_request(release_receipt(recipient_ciphertext, public_key_der))
        command_template = (
            f"{shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} --fixture-unseal "
            f"--private-key {shlex.quote(str(private_key_path))} --ciphertext {{recipient_ciphertext_path}}"
        )

        result = run_adapter(payload, command_template)
        if result.returncode != 0:
            raise AssertionError(f"Nitro KMS unseal adapter failed: {detail(result)}")
        output = json.loads(result.stdout)
        if output.get("provider") != "aws-nitro-kms-recipient-unseal" or output.get("ok") is not True:
            raise AssertionError(f"Nitro KMS unseal adapter returned invalid output: {output}")
        if base64.urlsafe_b64decode(output["keyB64"] + "=" * (-len(output["keyB64"]) % 4)) != BROKER_KEK:
            raise AssertionError("Nitro KMS unseal adapter returned the wrong broker KEK")
        kms_release = payload["releaseReceipt"]["external_release"]["kms_release"]
        if output.get("recipientCiphertextSha256") != kms_release["recipient_ciphertext_sha256"]:
            raise AssertionError("Nitro KMS unseal adapter omitted the recipient ciphertext binding")
        if output.get("recipientPublicKeySha256") != kms_release["recipient_public_key_sha256"]:
            raise AssertionError("Nitro KMS unseal adapter omitted the recipient key binding")
        from catchplate import crypto

        crypto._validate_nitro_unseal_bindings(payload["releaseReceipt"], output)
        tampered_output = json.loads(json.dumps(output))
        tampered_output["recipientCiphertextSha256"] = "sha256:" + "0" * 64
        try:
            crypto._validate_nitro_unseal_bindings(payload["releaseReceipt"], tampered_output)
        except ValueError as exc:
            if "does not match" not in str(exc):
                raise AssertionError(f"runtime binding validation failed incorrectly: {exc}") from exc
        else:
            raise AssertionError("runtime binding validation accepted a tampered unseal response")

        expect_failure(payload, command_template, "must not use fixture helpers", allow_fixture=False)

        bad_request_digest = json.loads(json.dumps(payload))
        bad_request_digest["requestDigest"] = "sha256:" + "0" * 64
        expect_failure(bad_request_digest, command_template, "request digest mismatch")

        bad_receipt_digest = json.loads(json.dumps(payload))
        bad_receipt_digest["releaseReceiptDigest"] = "sha256:" + "0" * 64
        bad_receipt_digest.pop("requestDigest")
        bad_receipt_digest["requestDigest"] = digest(canonical_json(bad_receipt_digest).encode("utf-8"))
        expect_failure(bad_receipt_digest, command_template, "release receipt digest mismatch")

        tampered_ciphertext = json.loads(json.dumps(payload))
        tampered_ciphertext["releaseReceipt"]["external_release"]["kms_release"]["recipient_ciphertext_b64"] = b64e(
            b"tampered"
        )
        refresh_request(tampered_ciphertext)
        expect_failure(tampered_ciphertext, command_template, "recipient ciphertext digest mismatch")

        wrong_key_binding = json.loads(json.dumps(payload))
        wrong_key_binding["releaseReceipt"]["recipient_public_key_sha256"] = "sha256:" + "0" * 64
        refresh_request(wrong_key_binding)
        expect_failure(wrong_key_binding, command_template, "recipient public key binding mismatch")

        wrong_kms_request = json.loads(json.dumps(payload))
        wrong_kms_request["releaseReceipt"]["external_release"]["kms_request_digest"] = "sha256:" + "0" * 64
        refresh_request(wrong_kms_request)
        expect_failure(wrong_kms_request, command_template, "KMS request digest mismatch")

        short_command = command_template + " --short"
        expect_failure(payload, short_command, "exactly 32 key bytes")

        missing_ciphertext_placeholder = command_template.replace("{recipient_ciphertext_path}", str(tmp / "missing"))
        expect_failure(payload, missing_ciphertext_placeholder, "must use {recipient_ciphertext_path}")

    print(canonical_json({"aws_nitro_kms_unseal": "pass", "ok": True}))


if __name__ == "__main__":
    main()
