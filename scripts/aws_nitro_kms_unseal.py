#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


INPUT_MAX_BYTES = 256 * 1024
OUTPUT_MAX_BYTES = 4096
RECIPIENT_CIPHERTEXT_MAX_BYTES = 6144
SHA256_PREFIXED_LENGTH = 71


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != SHA256_PREFIXED_LENGTH or not value.startswith("sha256:"):
        raise SystemExit(f"{label} must be a SHA-256 digest")
    try:
        bytes.fromhex(value.removeprefix("sha256:"))
    except ValueError as exc:
        raise SystemExit(f"{label} must be a SHA-256 digest") from exc
    return value


def b64d(value: str, label: str) -> bytes:
    translated = value.replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(translated + "=" * (-len(translated) % 4), validate=True)
    except Exception as exc:
        raise SystemExit(f"{label} is invalid base64") from exc


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(INPUT_MAX_BYTES + 1)
    if len(raw) > INPUT_MAX_BYTES:
        raise SystemExit("master-key unseal request exceeds 256 KiB")
    try:
        payload = json.loads(raw or b"{}")
    except json.JSONDecodeError as exc:
        raise SystemExit("master-key unseal request is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise SystemExit("master-key unseal request must be an object")
    return payload


def request_without_digest(payload: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    copied.pop("requestDigest", None)
    return copied


def validate_request(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "apiVersion",
        "kind",
        "material",
        "releaseHandle",
        "releaseReceiptDigest",
        "releaseReceipt",
        "requestDigest",
    }
    if set(payload) != allowed:
        raise SystemExit("master-key unseal request has an invalid object shape")
    if payload.get("apiVersion") != "serverware.masterKeyUnsealRequest/v1":
        raise SystemExit("master-key unseal request has an unexpected apiVersion")
    if payload.get("kind") != "MasterKeyUnseal" or payload.get("material") != "broker-kek":
        raise SystemExit("master-key unseal request is not for broker-kek")
    expected_request_digest = sha256_prefixed(canonical_json(request_without_digest(payload)).encode("utf-8"))
    if payload.get("requestDigest") != expected_request_digest:
        raise SystemExit("master-key unseal request digest mismatch")
    release = payload.get("releaseReceipt")
    if not isinstance(release, dict):
        raise SystemExit("master-key unseal request is missing its release receipt")
    expected_receipt_digest = sha256_prefixed(canonical_json(release).encode("utf-8"))
    if payload.get("releaseReceiptDigest") != expected_receipt_digest:
        raise SystemExit("master-key unseal release receipt digest mismatch")
    if release.get("material") != "broker-kek" or release.get("key_release_provider") != "external-command":
        raise SystemExit("master-key unseal release receipt is not an external broker-kek release")
    external = release.get("external_release")
    if not isinstance(external, dict) or external.get("provider") != "aws-nitro-kms-policy":
        raise SystemExit("master-key unseal release receipt is not backed by the Nitro KMS policy")
    release_handle = payload.get("releaseHandle")
    if not isinstance(release_handle, str) or external.get("release_handle") != release_handle:
        raise SystemExit("master-key unseal release handle mismatch")
    kms_release = external.get("kms_release")
    if not isinstance(kms_release, dict) or kms_release.get("provider") != "aws-kms-recipient":
        raise SystemExit("master-key unseal receipt is missing an AWS KMS Recipient release")
    if kms_release.get("ok") is not True or kms_release.get("material") != "broker-kek":
        raise SystemExit("master-key unseal KMS release is not authorized for broker-kek")
    if kms_release.get("release_handle") != release_handle:
        raise SystemExit("master-key unseal KMS release handle mismatch")
    if external.get("kms_request_digest") != kms_release.get("request_digest"):
        raise SystemExit("master-key unseal KMS request digest mismatch")

    attestation_digest = require_digest(kms_release.get("attestation_document_sha256"), "attestation document digest")
    recipient_key_digest = require_digest(kms_release.get("recipient_public_key_sha256"), "recipient public key digest")
    if release.get("attestation_document_sha256") != attestation_digest:
        raise SystemExit("master-key unseal attestation document binding mismatch")
    if release.get("recipient_public_key_sha256") != recipient_key_digest:
        raise SystemExit("master-key unseal recipient public key binding mismatch")
    if kms_release.get("recipient_public_key_algorithm") != "RSAES_OAEP_SHA_256":
        raise SystemExit("master-key unseal recipient algorithm mismatch")
    if kms_release.get("recipient_public_key_bits") not in {2048, 3072, 4096}:
        raise SystemExit("master-key unseal recipient key size is not supported")

    raw_ciphertext = kms_release.get("recipient_ciphertext_b64")
    if not isinstance(raw_ciphertext, str) or not raw_ciphertext:
        raise SystemExit("master-key unseal KMS release is missing recipient ciphertext")
    recipient_ciphertext = b64d(raw_ciphertext, "KMS recipient ciphertext")
    if not 1 <= len(recipient_ciphertext) <= RECIPIENT_CIPHERTEXT_MAX_BYTES:
        raise SystemExit("master-key unseal KMS recipient ciphertext has an invalid size")
    recipient_ciphertext_digest = sha256_prefixed(recipient_ciphertext)
    if kms_release.get("recipient_ciphertext_sha256") != recipient_ciphertext_digest:
        raise SystemExit("master-key unseal KMS recipient ciphertext digest mismatch")
    if kms_release.get("material_handle") != recipient_ciphertext_digest:
        raise SystemExit("master-key unseal KMS material handle mismatch")
    key_provider = kms_release.get("key_provider")
    if not isinstance(key_provider, dict) or not isinstance(key_provider.get("key_id"), str) or not key_provider["key_id"]:
        raise SystemExit("master-key unseal KMS key identity is missing")
    ciphertext_blob_digest = require_digest(kms_release.get("ciphertext_blob_sha256"), "KMS ciphertext blob digest")
    return {
        "recipient_ciphertext": recipient_ciphertext,
        "recipient_ciphertext_sha256": recipient_ciphertext_digest,
        "recipient_public_key_sha256": recipient_key_digest,
        "attestation_document_sha256": attestation_digest,
        "kms_key_id": key_provider["key_id"],
        "ciphertext_blob_sha256": ciphertext_blob_digest,
    }


def command_mentions(raw: str, *needles: str) -> bool:
    try:
        lowered = " ".join(shlex.split(raw)).lower()
    except ValueError:
        lowered = raw.lower()
    return any(needle.lower() in lowered for needle in needles)


def command_environment() -> dict[str, str]:
    allowed = {"PATH", "HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"}
    return {name: value for name, value in os.environ.items() if name in allowed}


def run_unseal_command(
    *,
    template: str,
    bindings: dict[str, Any],
    request_digest: str,
    release_handle: str,
    timeout: float,
    allow_fixtures_for_test: bool,
) -> bytes:
    if not template.strip():
        raise SystemExit("--command-template or SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE is required")
    if not allow_fixtures_for_test and command_mentions(template, "fixture", "test_aws_nitro_kms_unseal.py"):
        raise SystemExit("Nitro NSM unseal adapter must not use fixture helpers")
    if "{recipient_ciphertext_path}" not in template:
        raise SystemExit("Nitro NSM unseal command template must use {recipient_ciphertext_path}")

    with tempfile.TemporaryDirectory() as tmp_raw:
        ciphertext_path = Path(tmp_raw) / "ciphertext-for-recipient.bin"
        ciphertext_path.write_bytes(bindings["recipient_ciphertext"])
        os.chmod(ciphertext_path, 0o600)
        values = {
            "recipient_ciphertext_path": str(ciphertext_path),
            "recipient_ciphertext_sha256": bindings["recipient_ciphertext_sha256"],
            "recipient_public_key_sha256": bindings["recipient_public_key_sha256"],
            "attestation_document_sha256": bindings["attestation_document_sha256"],
            "kms_key_id": bindings["kms_key_id"],
            "ciphertext_blob_sha256": bindings["ciphertext_blob_sha256"],
            "request_digest": request_digest,
            "release_handle": release_handle,
        }
        try:
            command = shlex.split(template.format(**values))
        except KeyError as exc:
            raise SystemExit(f"unknown Nitro NSM unseal command-template placeholder: {exc}") from exc
        except ValueError as exc:
            raise SystemExit(f"invalid Nitro NSM unseal command template: {exc}") from exc
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=command_environment(),
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise SystemExit("Nitro NSM unseal command timed out") from exc
    if process.returncode != 0:
        detail = stderr[:2048].decode("utf-8", errors="replace").strip()
        raise SystemExit(f"Nitro NSM unseal command failed with exit {process.returncode}: {detail}")
    if len(stdout) > OUTPUT_MAX_BYTES:
        raise SystemExit("Nitro NSM unseal command output exceeds 4 KiB")
    return stdout


def decoded_key(stdout: bytes, output_format: str) -> bytes:
    stripped = stdout.strip()
    if output_format in {"json", "auto"}:
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, UnicodeDecodeError):
            parsed = None
        if parsed is not None:
            if not isinstance(parsed, dict) or set(parsed) != {"keyB64"} or not isinstance(parsed["keyB64"], str):
                raise SystemExit("Nitro NSM unseal JSON output must contain only keyB64")
            return b64d(parsed["keyB64"], "Nitro NSM unsealed key")
        if output_format == "json":
            raise SystemExit("Nitro NSM unseal command returned invalid JSON")
    if output_format in {"b64", "auto"}:
        try:
            decoded = b64d(stripped.decode("ascii"), "Nitro NSM unsealed key")
        except (SystemExit, UnicodeDecodeError):
            if output_format == "b64":
                raise
        else:
            if len(decoded) == 32:
                return decoded
            if output_format == "b64":
                return decoded
    if output_format in {"raw", "auto"}:
        return stdout
    raise SystemExit("Nitro NSM unseal command output could not be decoded")


def unseal(args: argparse.Namespace) -> None:
    if not 0 < args.timeout <= 60:
        raise SystemExit("Nitro NSM unseal timeout must be between 0 and 60 seconds")
    request = read_request()
    bindings = validate_request(request)
    template = args.command_template or os.getenv("SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE", "")
    raw_key = decoded_key(
        run_unseal_command(
            template=template,
            bindings=bindings,
            request_digest=request["requestDigest"],
            release_handle=request["releaseHandle"],
            timeout=args.timeout,
            allow_fixtures_for_test=args.allow_fixtures_for_test,
        ),
        args.output_format,
    )
    if len(raw_key) != 32:
        raise SystemExit("Nitro NSM unseal command must return exactly 32 key bytes")
    print(
        canonical_json(
            {
                "apiVersion": "serverware.unsealedMaterial/v1",
                "kind": "UnsealedMaterial",
                "ok": True,
                "material": "broker-kek",
                "requestDigest": request["requestDigest"],
                "releaseHandle": request["releaseHandle"],
                "keyB64": b64e(raw_key),
                "provider": "aws-nitro-kms-recipient-unseal",
                "attestationDocumentSha256": bindings["attestation_document_sha256"],
                "recipientPublicKeySha256": bindings["recipient_public_key_sha256"],
                "kmsKeyId": bindings["kms_key_id"],
                "ciphertextBlobSha256": bindings["ciphertext_blob_sha256"],
                "recipientCiphertextSha256": bindings["recipient_ciphertext_sha256"],
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate a Nitro/KMS release receipt and unwrap CiphertextForRecipient inside the enclave."
    )
    subparsers = parser.add_subparsers(dest="command")
    unseal_parser = subparsers.add_parser("unseal")
    unseal_parser.add_argument("--command-template", default=None)
    unseal_parser.add_argument(
        "--output-format",
        choices=("auto", "raw", "b64", "json"),
        default=os.getenv("SERVERWARE_NITRO_NSM_UNSEAL_OUTPUT_FORMAT", "auto"),
    )
    unseal_parser.add_argument(
        "--timeout", type=float, default=float(os.getenv("SERVERWARE_NITRO_NSM_UNSEAL_TIMEOUT_SECONDS", "10"))
    )
    unseal_parser.add_argument("--allow-fixtures-for-test", action="store_true")
    args = parser.parse_args()
    if args.command != "unseal":
        raise SystemExit("usage: aws_nitro_kms_unseal.py unseal --command-template '...'")
    unseal(args)


if __name__ == "__main__":
    main()
