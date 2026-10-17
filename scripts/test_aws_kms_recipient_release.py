#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64url_e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def request_without_digest(payload: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    copied.pop("request_digest", None)
    return copied


def kms_request() -> dict[str, Any]:
    recipient_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    recipient_public_key_der = recipient_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw_attestation = cbor2.dumps(
        cbor2.CBORTag(18, [b"", {}, cbor2.dumps({"public_key": recipient_public_key_der}), b""])
    )
    tee = {
        "provider": "aws-nitro-enclaves",
        "tee_platform": "aws-nitro",
        "verified": True,
        "debug": False,
        "module_id": "nitro-prod-module",
        "pcrs": {"0": "11" * 48, "1": "22" * 48},
        "raw_attestation_document_b64": b64url_e(raw_attestation),
        "raw_attestation_document_sha256": sha256_prefixed(raw_attestation),
        "recipient_public_key_sha256": sha256_prefixed(recipient_public_key_der),
        "recipient_public_key_algorithm": "RSAES_OAEP_SHA_256",
        "recipient_public_key_bits": 2048,
    }
    claims = {
        "nonce": "kms-recipient-test",
        "policy_bundle_digest": "sha256:" + "a" * 64,
        "ca_intermediate_spki_sha256": "sha256:" + "b" * 64,
        "rollback_epoch": 7,
        "release_channel": "prod",
        "provenance_digest": "sha256:" + "c" * 64,
        "source_tree_digest": "sha256:" + "d" * 64,
        "response_signing_key_id": "sha256:" + "e" * 64,
        "data_plane_binary_digest": "sha256:" + "f" * 64,
        "materials": ["broker-kek", "decision-gate-ca"],
        "tee": tee,
    }
    payload = {
        "apiVersion": "catchplate.nitroKmsReleaseRequest/v1",
        "kind": "NitroKmsMaterialRelease",
        "provider": "aws-nitro-enclaves",
        "tee_platform": "aws-nitro",
        "material": "decision-gate-ca",
        "claims": claims,
        "expected": {
            "policy_bundle_digest": claims["policy_bundle_digest"],
            "ca_intermediate_spki_sha256": claims["ca_intermediate_spki_sha256"],
            "rollback_epoch": claims["rollback_epoch"],
            "release_channel": claims["release_channel"],
            "provenance_digest": claims["provenance_digest"],
            "source_tree_digest": claims["source_tree_digest"],
            "response_signing_key_id": claims["response_signing_key_id"],
            "data_plane_binary_digest": claims["data_plane_binary_digest"],
        },
        "tee": tee,
        "release_handle": "sha256:" + "9" * 64,
    }
    payload["request_digest"] = sha256_prefixed(canonical_json(payload).encode("utf-8"))
    return payload


def fake_aws(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys

if "--recipient" not in sys.argv or "--ciphertext-blob" not in sys.argv:
    raise SystemExit("missing recipient or ciphertext blob")
response = {
    "KeyId": "arn:aws:kms:us-east-1:111122223333:key/catchplate",
    "CiphertextForRecipient": "cmVjaXBpZW50LWNpcGhlcnRleHQ=",
}
if os.getenv("CATCHPLATE_FAKE_AWS_PLAINTEXT"):
    response["Plaintext"] = "must-not-be-accepted"
print(json.dumps(response, sort_keys=True))
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def run_adapter(payload: dict[str, Any], materials_file: Path, aws_binary: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    run_env = os.environ.copy()
    run_env.pop("CATCHPLATE_FAKE_AWS_PLAINTEXT", None)
    if env:
        run_env.update(env)
    return subprocess.run(
        [
            sys.executable,
            "scripts/aws_kms_recipient_release.py",
            "release",
            "--materials-file",
            str(materials_file),
            "--aws-binary",
            f"{sys.executable} {aws_binary}",
            "--region",
            "us-east-1",
        ],
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=run_env,
        check=False,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")


def expect_failure(payload: dict[str, Any], materials_file: Path, aws_binary: Path, expected: str, env: dict[str, str] | None = None) -> None:
    result = run_adapter(payload, materials_file, aws_binary, env)
    if result.returncode == 0:
        raise AssertionError(f"AWS KMS adapter unexpectedly succeeded: {detail(result)}")
    if expected not in detail(result):
        raise AssertionError(f"AWS KMS adapter failed with wrong error, expected {expected!r}: {detail(result)}")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        aws = tmp / "aws"
        fake_aws(aws)
        materials_file = tmp / "materials.json"
        materials_file.write_text(
            canonical_json(
                {
                    "decision-gate-ca": {
                        "key_id": "arn:aws:kms:us-east-1:111122223333:key/catchplate",
                        "ciphertext_blob_b64": b64e(b"kms-encrypted-dek"),
                        "encryption_context": {"service": "catchplate", "material": "decision-gate-ca"},
                    }
                }
            ),
            encoding="utf-8",
        )
        payload = kms_request()
        result = run_adapter(payload, materials_file, aws)
        if result.returncode != 0:
            raise AssertionError(f"AWS KMS adapter failed: {detail(result)}")
        output = json.loads(result.stdout.decode("utf-8"))
        if output.get("provider") != "aws-kms-recipient" or output.get("ok") is not True:
            raise AssertionError(f"AWS KMS adapter returned invalid output: {output}")
        if output.get("request_digest") != payload["request_digest"]:
            raise AssertionError(f"AWS KMS adapter did not bind request digest: {output}")
        if not ((output.get("key_provider") or {}).get("key_id")):
            raise AssertionError(f"AWS KMS adapter did not bind key identity: {output}")
        if (
            "recipient_ciphertext_sha256" not in output
            or "recipient_ciphertext_b64" not in output
            or "recipient_public_key_sha256" not in output
            or "ciphertext_blob_sha256" not in output
            or "Plaintext" in canonical_json(output)
        ):
            raise AssertionError(f"AWS KMS adapter leaked or omitted material evidence: {output}")
        if base64.b64decode(output["recipient_ciphertext_b64"], validate=True) != b"recipient-ciphertext":
            raise AssertionError(f"AWS KMS adapter did not retain CiphertextForRecipient: {output}")
        if output.get("recipient_public_key_sha256") != payload["tee"]["recipient_public_key_sha256"]:
            raise AssertionError(f"AWS KMS adapter did not bind the attested recipient key: {output}")
        if output.get("ciphertext_blob_sha256") != sha256_prefixed(b"kms-encrypted-dek"):
            raise AssertionError(f"AWS KMS adapter did not bind the input ciphertext digest: {output}")
        if output.get("encryption_context_sha256") != sha256_prefixed(canonical_json({"material": "decision-gate-ca", "service": "catchplate"}).encode("utf-8")):
            raise AssertionError(f"AWS KMS adapter did not bind the encryption context digest: {output}")

        invalid_materials = tmp / "invalid-materials.json"
        invalid_materials.write_text(
            canonical_json(
                {
                    "decision-gate-ca": {
                        "key_id": "arn:aws:kms:us-east-1:111122223333:key/catchplate",
                        "ciphertext_blob_b64": "not-valid-@@@@",
                        "encryption_context": {"service": "catchplate", "material": "decision-gate-ca"},
                    }
                }
            ),
            encoding="utf-8",
        )
        expect_failure(payload, invalid_materials, aws, "ciphertext_blob_b64 is invalid base64")

        bad_digest = json.loads(json.dumps(payload))
        bad_digest["request_digest"] = "sha256:" + "0" * 64
        expect_failure(bad_digest, materials_file, aws, "request digest mismatch")

        unauthorized = json.loads(json.dumps(payload))
        unauthorized["material"] = "debug-material"
        unauthorized["request_digest"] = sha256_prefixed(canonical_json(request_without_digest(unauthorized)).encode("utf-8"))
        expect_failure(unauthorized, materials_file, aws, "unauthorized material")

        missing_doc = json.loads(json.dumps(payload))
        missing_doc["tee"].pop("raw_attestation_document_b64", None)
        missing_doc["claims"]["tee"].pop("raw_attestation_document_b64", None)
        missing_doc["request_digest"] = sha256_prefixed(canonical_json(request_without_digest(missing_doc)).encode("utf-8"))
        expect_failure(missing_doc, materials_file, aws, "raw_attestation_document_b64")

        wrong_recipient = json.loads(json.dumps(payload))
        wrong_recipient["tee"]["recipient_public_key_sha256"] = "sha256:" + "0" * 64
        wrong_recipient["claims"]["tee"]["recipient_public_key_sha256"] = "sha256:" + "0" * 64
        wrong_recipient["request_digest"] = sha256_prefixed(
            canonical_json(request_without_digest(wrong_recipient)).encode("utf-8")
        )
        expect_failure(wrong_recipient, materials_file, aws, "recipient public key digest mismatch")

        expect_failure(payload, materials_file, aws, "plaintext material", {"CATCHPLATE_FAKE_AWS_PLAINTEXT": "1"})

    print(canonical_json({"aws_kms_recipient_release": "pass", "ok": True}))


if __name__ == "__main__":
    main()
