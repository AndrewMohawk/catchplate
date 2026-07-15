from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("SERVERWARE_DATA_DIR", str(Path(".tmp/test-codebase-attestation/data").resolve()))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware.response_identity import canonical_json, response_public_key_info, response_signature_headers, response_statement

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_codebase_attestation as verifier  # noqa: E402


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def fixture_sigstore(
    key: Ed25519PrivateKey,
    key_id: str,
    public_key_pem: str,
    statement: dict[str, object],
) -> dict[str, object]:
    statement_digest = verifier.sha256_prefixed_json(statement)
    signature = "cosign-fixture-ed25519:" + b64e(
        key.sign(verifier.canonical_json(statement).encode("utf-8"))
    )
    proof = {
        "treeSize": 1,
        "logIndex": 0,
        "rootHash": "sha256:" + "d" * 64,
        "hashes": [],
    }
    transparency = {
        "log_id": "sha256:" + "e" * 64,
        "log_index": 0,
        "integrated_time": 1_789_000_000,
        "entry_uuid": "entry-test",
        "inclusion_proof": proof,
    }
    return {
        "ok": True,
        "provider": "cosign",
        "statement_digest": statement_digest,
        "signature": signature,
        "key_provider": {"type": "test", "key_id": key_id},
        "transparency": transparency,
        "bundle": {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "sha256",
                    "digest": statement_digest.split(":", 1)[1],
                },
                "signature": signature,
            },
            "verificationMaterial": {
                "publicKey": public_key_pem,
                "tlogEntries": [
                    {
                        "entryUUID": "entry-test",
                        "inclusionProof": proof,
                        "integratedTime": 1_789_000_000,
                        "logId": {"keyId": "sha256:" + "e" * 64},
                        "logIndex": 0,
                    }
                ],
            },
        },
    }


def signed_bundle_fixture(
    key: Ed25519PrivateKey,
    key_id: str,
    public_key_pem: str,
    provenance: dict[str, object],
    provenance_digest: str,
    release_key_id: str,
) -> dict[str, object]:
    image_id = "sha256:" + "6" * 64
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://serverware.local/attestations/oci-image/v1",
        "subject": [{"name": "serverware", "digest": {"sha256": "6" * 64}}],
        "predicate": {
            "image_id": image_id,
            "repo_digests": [],
            "provenance_digest": provenance_digest,
            "release_signing_key_id": release_key_id,
            "source_tree_digest": provenance["source_tree"]["digest"],
            "compose_config_sha256": provenance["compose_config_sha256"],
            "sbom_cyclonedx_sha256": provenance["sbom"]["cyclonedx"]["sha256"],
            "sbom_cyclonedx_components": provenance["sbom"]["cyclonedx"]["components"],
        },
    }
    image_sigstore = fixture_sigstore(key, key_id, public_key_pem, statement)
    bundle: dict[str, object] = {
        "apiVersion": "serverware.imageSignatures/v1",
        "kind": "ImageSignatureBundle",
        "metadata": {
            "provenanceDigest": provenance_digest,
            "releaseSigningKeyId": release_key_id,
            "imageSigningKeyId": key_id,
            "sourceTreeDigest": provenance["source_tree"]["digest"],
            "composeConfigSha256": provenance["compose_config_sha256"],
            "sbomCyclonedxSha256": provenance["sbom"]["cyclonedx"]["sha256"],
            "signatureProvider": "sigstore-command",
            "sigstoreTransparencyRequired": True,
        },
        "images": [
            {
                "service": "serverware",
                "image_id": image_id,
                "statement": statement,
                "statement_digest": verifier.sha256_prefixed_json(statement),
                "signature": image_sigstore["signature"],
                "sigstore": image_sigstore,
            }
        ],
    }
    normalized = verifier.normalized_image_signature_payload(bundle)
    bundle_sigstore = fixture_sigstore(key, key_id, public_key_pem, normalized)
    bundle["metadata"]["bundleSigstore"] = bundle_sigstore
    bundle["metadata"]["signature"] = bundle_sigstore["signature"]
    bundle["bundle_signature"] = bundle_sigstore
    bundle["image_signature_bundle_digest"] = verifier.sha256_prefixed_json(normalized)
    return bundle


def exercise_bundle_verification() -> None:
    release_key = Ed25519PrivateKey.generate()
    image_key = Ed25519PrivateKey.generate()
    release_public_pem = release_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    image_public_pem = image_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    release_key_id = sha256_prefixed(
        release_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    image_key_id = sha256_prefixed(
        image_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    provenance: dict[str, object] = {
        "source_tree": {"digest": "sha256:" + "5" * 64},
        "compose_config_sha256": "sha256:" + "7" * 64,
        "sbom": {
            "cyclonedx": {"sha256": "sha256:" + "8" * 64, "components": 2}
        },
        "images": {
            "serverware": {"image_id": "sha256:" + "6" * 64, "repo_digests": []}
        },
    }
    provenance_digest = verifier.sha256_prefixed_json(provenance)
    provenance_document = {
        "provenance": provenance,
        "provenance_digest": provenance_digest,
        "release_signing_key_id": release_key_id,
        "release_signing_public_key_pem": release_public_pem,
        "signature": "ed25519:"
        + b64e(release_key.sign(verifier.canonical_json(provenance).encode("utf-8"))),
    }
    verifier.verify_release_provenance(
        provenance_document,
        release_public_pem,
        release_key_id,
    )
    bundle = signed_bundle_fixture(
        image_key,
        image_key_id,
        image_public_pem,
        provenance,
        provenance_digest,
        release_key_id,
    )
    original_external = verifier.run_sigstore_verifier
    verifier.run_sigstore_verifier = lambda *_args, **_kwargs: None  # type: ignore[assignment]
    try:
        verifier.verify_image_signature_bundle(
            bundle,
            bundle["image_signature_bundle_digest"],
            provenance=provenance,
            provenance_digest=provenance_digest,
            release_signing_key_id=release_key_id,
            trusted_public_key_pem=image_public_pem,
            trusted_key_id=image_key_id,
            verify_command="test-verifier",
        )
        unsigned = json.loads(json.dumps(bundle))
        unsigned.pop("bundle_signature")
        try:
            verifier.verify_image_signature_bundle(
                unsigned,
                bundle["image_signature_bundle_digest"],
                provenance=provenance,
                provenance_digest=provenance_digest,
                release_signing_key_id=release_key_id,
                trusted_public_key_pem=image_public_pem,
                trusted_key_id=image_key_id,
                verify_command="test-verifier",
            )
        except ValueError:
            pass
        else:
            raise AssertionError("unsigned image signature bundle was accepted")

        wrong_key = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        try:
            verifier.verify_image_signature_bundle(
                bundle,
                bundle["image_signature_bundle_digest"],
                provenance=provenance,
                provenance_digest=provenance_digest,
                release_signing_key_id=release_key_id,
                trusted_public_key_pem=wrong_key,
                trusted_key_id="sha256:" + "9" * 64,
                verify_command="test-verifier",
            )
        except ValueError:
            pass
        else:
            raise AssertionError("image signature bundle accepted the wrong trust root")

        rebound = json.loads(json.dumps(bundle))
        rebound["metadata"]["provenanceDigest"] = "sha256:" + "0" * 64
        normalized = verifier.normalized_image_signature_payload(rebound)
        bundle_sigstore = fixture_sigstore(image_key, image_key_id, image_public_pem, normalized)
        rebound["metadata"]["bundleSigstore"] = bundle_sigstore
        rebound["metadata"]["signature"] = bundle_sigstore["signature"]
        rebound["bundle_signature"] = bundle_sigstore
        rebound["image_signature_bundle_digest"] = verifier.sha256_prefixed_json(normalized)
        try:
            verifier.verify_image_signature_bundle(
                rebound,
                rebound["image_signature_bundle_digest"],
                provenance=provenance,
                provenance_digest=provenance_digest,
                release_signing_key_id=release_key_id,
                trusted_public_key_pem=image_public_pem,
                trusted_key_id=image_key_id,
                verify_command="test-verifier",
            )
        except ValueError as exc:
            if "provenanceDigest mismatch" not in str(exc):
                raise AssertionError(f"cross-binding failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("image signature bundle accepted another provenance digest")
    finally:
        verifier.run_sigstore_verifier = original_external  # type: ignore[assignment]

    with tempfile.TemporaryDirectory() as tmp_raw:
        private_path = Path(tmp_raw) / "trusted.pem"
        private_path.write_bytes(
            image_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        _key, _pem, loaded_id = verifier.trusted_ed25519_key(
            private_path, "test trust root"
        )
        if loaded_id != image_key_id:
            raise AssertionError("trusted key loader changed the SPKI identity")


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
    exercise_bundle_verification()
    print("codebase attestation response signature tests passed")


if __name__ == "__main__":
    main()
