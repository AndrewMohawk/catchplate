#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import sign_release_images as signer  # noqa: E402
import verify_release_completion as release_verifier  # noqa: E402


def exercise_external_verify_contract() -> None:
    statement = {"predicate": {"source": "verify-contract"}}
    statement_digest = signer.sha256_prefixed_json(statement)
    signed_response = {
        "ok": True,
        "statement_digest": statement_digest,
        "signature": "sigstore:test",
        "key_provider": {"type": "sigstore-keyless", "key_id": "sha256:" + "1" * 64},
        "transparency": {
            "log_id": "sha256:" + "2" * 64,
            "entry_uuid": "entry",
            "integrated_time": 1779830000,
            "log_index": 7,
            "inclusion_proof": {"treeSize": 8},
        },
    }
    calls: list[str] = []

    def run_json_command(command: str, payload: dict[str, object], timeout: float = 120.0) -> dict[str, object]:
        calls.append(command)
        if command == "sign":
            return signed_response
        if command == "verify":
            return {
                "ok": True,
                "statement_digest": statement_digest,
                "verified_transparency": True,
                "key_provider": signed_response["key_provider"],
                "transparency": signed_response["transparency"],
            }
        raise AssertionError(f"unexpected command: {command}")

    original = signer.run_json_command
    signer.run_json_command = run_json_command  # type: ignore[assignment]
    try:
        result = signer.external_sign_statement(
            command="sign",
            verify_command="verify",
            require_transparency=True,
            kind="test",
            service="serverware",
            image_id=None,
            statement=statement,
        )
        if result != signed_response or calls != ["sign", "verify"]:
            raise AssertionError("external signer did not run the expected sign/verify contract")

        def weak_verify(command: str, payload: dict[str, object], timeout: float = 120.0) -> dict[str, object]:
            if command == "sign":
                return signed_response
            return {
                "ok": True,
                "statement_digest": statement_digest,
                "verified_transparency": False,
                "key_provider": signed_response["key_provider"],
                "transparency": signed_response["transparency"],
            }

        signer.run_json_command = weak_verify  # type: ignore[assignment]
        try:
            signer.external_sign_statement(
                command="sign",
                verify_command="verify",
                require_transparency=True,
                kind="test",
                service="serverware",
                image_id=None,
                statement=statement,
            )
        except RuntimeError as exc:
            if "did not prove transparency" not in str(exc):
                raise AssertionError(f"weak verify failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("external signer accepted a verifier that did not prove transparency")

        def wrong_key_verify(command: str, payload: dict[str, object], timeout: float = 120.0) -> dict[str, object]:
            if command == "sign":
                return signed_response
            return {
                "ok": True,
                "statement_digest": statement_digest,
                "verified_transparency": True,
                "key_provider": {"type": "sigstore-keyless", "key_id": "sha256:" + "3" * 64},
                "transparency": signed_response["transparency"],
            }

        signer.run_json_command = wrong_key_verify  # type: ignore[assignment]
        try:
            signer.external_sign_statement(
                command="sign",
                verify_command="verify",
                require_transparency=True,
                kind="test",
                service="serverware",
                image_id=None,
                statement=statement,
            )
        except RuntimeError as exc:
            if "different key provider" not in str(exc):
                raise AssertionError(f"wrong-key verify failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("external signer accepted a verifier that returned another key provider")
    finally:
        signer.run_json_command = original  # type: ignore[assignment]


def exercise_env_file_preload() -> None:
    managed_keys = {
        "SERVERWARE_IMAGE_SIGNATURE_PROVIDER",
        "SERVERWARE_IMAGE_SIGN_COMMAND",
        "SERVERWARE_IMAGE_VERIFY_COMMAND",
        "SERVERWARE_COSIGN_BINARY",
        "SERVERWARE_COSIGN_KEY",
        "SERVERWARE_COSIGN_KEY_ID",
        "SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID",
        "SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY",
        "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY",
        "SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER",
        "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID",
    }
    original = {key: os.environ.get(key) for key in managed_keys}
    with tempfile.TemporaryDirectory() as tmp_raw:
        env_file = Path(tmp_raw) / "production-readiness.env"
        env_file.write_text(
            "\n".join(
                [
                    "SERVERWARE_IMAGE_SIGNATURE_PROVIDER=sigstore-command",
                    "SERVERWARE_IMAGE_SIGN_COMMAND='python3 scripts/cosign_sigstore.py sign'",
                    "SERVERWARE_IMAGE_VERIFY_COMMAND='python3 scripts/cosign_sigstore.py verify'",
                    "SERVERWARE_COSIGN_BINARY=/usr/local/bin/cosign",
                    "SERVERWARE_COSIGN_KEY=awskms://arn:aws:kms:us-east-1:111122223333:key/serverware-signing",
                    "SERVERWARE_COSIGN_KEY_ID=sha256:" + "1" * 64,
                    "SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID=sha256:" + "2" * 64,
                    "SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY=1",
                    "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY=/etc/serverware/release-trust/release-provenance.pem",
                    "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY=/etc/serverware/release-trust/external-checkpoint.pem",
                    "SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER=managed-release-log",
                    "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID=sha256:" + "3" * 64,
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        try:
            for key in managed_keys:
                os.environ.pop(key, None)
            os.environ["SERVERWARE_IMAGE_SIGN_COMMAND"] = "explicit-sign-command"
            signer.preload_env_file(["--env-file", str(env_file)])
            if os.environ["SERVERWARE_IMAGE_SIGN_COMMAND"] != "explicit-sign-command":
                raise AssertionError("env preload overwrote an explicit signer command")
            if os.environ.get("SERVERWARE_IMAGE_VERIFY_COMMAND") != "python3 scripts/cosign_sigstore.py verify":
                raise AssertionError("env preload did not load the verifier command")
            if os.environ.get("SERVERWARE_COSIGN_BINARY") != "/usr/local/bin/cosign":
                raise AssertionError("env preload did not load the production cosign binary")
            if os.environ.get("SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY") != "1":
                raise AssertionError("env preload did not load the transparency requirement")
            if os.environ.get("SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY") != "/etc/serverware/release-trust/release-provenance.pem":
                raise AssertionError("env preload did not load the release provenance trust root")
            if os.environ.get("SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY") != "/etc/serverware/release-trust/external-checkpoint.pem":
                raise AssertionError("env preload did not load the external checkpoint trust root")
            if os.environ.get("SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER") != "managed-release-log":
                raise AssertionError("env preload did not load the external checkpoint provider")
        finally:
            for key, value in original.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def exercise_stale_provenance_rejection() -> None:
    digest = "sha256:" + "a" * 64
    original = signer.serverware_source_tree.source_tree_digest
    signer.serverware_source_tree.source_tree_digest = lambda _root: digest  # type: ignore[assignment]
    try:
        if signer.verify_current_source_tree({"source_tree": {"digest": digest}}) != digest:
            raise AssertionError("current source tree binding was not returned")
        try:
            signer.verify_current_source_tree(
                {"source_tree": {"digest": "sha256:" + "b" * 64}}
            )
        except ValueError as exc:
            if "source tree is stale" not in str(exc):
                raise AssertionError(
                    f"stale provenance failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError("image signing accepted stale release provenance")
    finally:
        signer.serverware_source_tree.source_tree_digest = original  # type: ignore[assignment]


def exercise_independent_provenance_trust() -> None:
    release_key = Ed25519PrivateKey.generate()
    public_key = release_key.public_key()
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    provenance = {
        "version": 2,
        "source": "serverware-digest-pinned-production-release",
        "source_tree": {"digest": "sha256:" + "a" * 64},
    }
    provenance_digest = signer.sha256_prefixed_json(provenance)
    signature = "ed25519:" + signer.b64e(
        release_key.sign(signer.canonical_json(provenance).encode("utf-8"))
    )
    key_id = signer.sha256_prefixed_bytes(public_der)
    record = {
        "type": "release.provenance.v2",
        "provenance_digest": provenance_digest,
        "release_signing_key_id": key_id,
        "signature": signature,
    }
    record_digest = signer.sha256_prefixed_json(record)
    anchor_key = Ed25519PrivateKey.generate()
    anchor_public_pem = anchor_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    anchor_key_id = release_verifier.release_public_key_id(anchor_public_pem)
    external_key = Ed25519PrivateKey.generate()
    external_public_pem = external_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    external_log_id = release_verifier.release_public_key_id(external_public_pem)
    external_provider = "managed-release-log-test"
    item = {
        "anchor_id": "anchor-test",
        "sequence": 7,
        "received_at": "2026-07-15T00:00:00+00:00",
        "record": record,
        "record_digest": record_digest,
    }
    leaf_hash = release_verifier.transparency_leaf_hash(item)
    tree_head_hash = leaf_hash
    signed_tree_head_payload = {
        "version": "serverware.transparencyLog/v1",
        "created_at": "2026-07-15T00:00:01+00:00",
        "log_id": anchor_key_id,
        "tree_head_hash": tree_head_hash,
        "tree_size": 1,
    }
    signed_tree_head = {
        **signed_tree_head_payload,
        "public_key_pem": anchor_public_pem,
        "signature": "ed25519:"
        + signer.b64e(
            anchor_key.sign(signer.canonical_json(signed_tree_head_payload).encode("utf-8"))
        ),
    }
    checkpoint_payload = {
        "provider": external_provider,
        "log_id": external_log_id,
        "record_digest": record_digest,
        "leaf_hash": leaf_hash,
        "tree_head_hash": tree_head_hash,
        "tree_size": 1,
    }
    checkpoint = {
        "ok": True,
        "provider": external_provider,
        "log_id": external_log_id,
        "receipt": {
            "kind": "ed25519-signed-checkpoint",
            "payload": checkpoint_payload,
            "public_key_pem": external_public_pem,
            "signature": "ed25519:"
            + signer.b64e(
                external_key.sign(signer.canonical_json(checkpoint_payload).encode("utf-8"))
            ),
        },
    }
    item.update(
        {
            "leaf_hash": leaf_hash,
            "signed_tree_head": signed_tree_head,
            "external_checkpoint": checkpoint,
        }
    )
    document = {
        "provenance": provenance,
        "provenance_digest": provenance_digest,
        "release_signing_key_id": key_id,
        "release_signing_public_key_pem": public_pem,
        "signature": signature,
        "transparency": {
            "anchor_response": {
                "ok": True,
                "anchors": [
                    {
                        "record_digest": record_digest,
                        "leaf_hash": leaf_hash,
                        "tree_head_hash": tree_head_hash,
                        "tree_size": 1,
                        "signed_tree_head": signed_tree_head,
                        "external_checkpoint": checkpoint,
                    }
                ],
            },
            "record": record,
            "inclusion_proof": {
                "ok": True,
                "verified": True,
                "record_digest": record_digest,
                "sequence": 7,
                "item": item,
                "leaf_hash": leaf_hash,
                "tree_size": 1,
                "tree_head_hash": tree_head_hash,
                "proof": [],
                "signed_tree_head": signed_tree_head,
            },
        },
    }
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        trusted = tmp / "trusted.pem"
        trusted.write_text(public_pem, encoding="ascii")
        external_trusted = tmp / "external-trusted.pem"
        external_trusted.write_text(external_public_pem, encoding="ascii")

        def verify(candidate: dict[str, object], *, release_trust: Path = trusted) -> None:
            signer.verify_release_provenance(
                candidate,
                trusted_public_key_path=release_trust,
                require_transparency=True,
                external_checkpoint_trusted_key_path=external_trusted,
                expected_external_checkpoint_provider=external_provider,
                expected_external_checkpoint_log_id=external_log_id,
            )

        signer.verify_release_provenance(
            document,
            trusted_public_key_path=trusted,
            require_transparency=True,
            external_checkpoint_trusted_key_path=external_trusted,
            expected_external_checkpoint_provider=external_provider,
            expected_external_checkpoint_log_id=external_log_id,
        )
        legacy_document = json.loads(json.dumps(document))
        legacy_document["provenance"]["version"] = 1
        try:
            verify(legacy_document)
        except ValueError as exc:
            if "must use version 2" not in str(exc):
                raise AssertionError(
                    f"legacy production provenance failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError("production image signing accepted provenance version 1")

        wrong_key = Ed25519PrivateKey.generate().public_key()
        wrong_trust = tmp / "wrong.pem"
        wrong_trust.write_bytes(
            wrong_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        try:
            verify(document, release_trust=wrong_trust)
        except ValueError as exc:
            if "independent trust root" not in str(exc):
                raise AssertionError(f"wrong provenance trust root failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("production image signing accepted an untrusted provenance signer")

        without_transparency = dict(document)
        without_transparency.pop("transparency")
        try:
            verify(without_transparency)
        except ValueError as exc:
            if "transparency evidence" not in str(exc):
                raise AssertionError(f"missing provenance transparency failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("production image signing accepted unanchored provenance")

        forged_flags = json.loads(json.dumps(document))
        forged_flags["transparency"] = {
            "anchor_response": {"ok": True},
            "record": record,
            "inclusion_proof": {"ok": True, "verified": True},
        }
        try:
            verify(forged_flags)
        except ValueError:
            pass
        else:
            raise AssertionError("production image signing trusted unauthenticated transparency flags")

        forged_checkpoint = json.loads(json.dumps(document))
        forged_checkpoint["transparency"]["inclusion_proof"]["item"]["external_checkpoint"]["receipt"][
            "signature"
        ] = "ed25519:" + signer.b64e(b"0" * 64)
        forged_checkpoint["transparency"]["anchor_response"]["anchors"][0]["external_checkpoint"] = (
            forged_checkpoint["transparency"]["inclusion_proof"]["item"]["external_checkpoint"]
        )
        try:
            verify(forged_checkpoint)
        except ValueError as exc:
            if "signature verification failed" not in str(exc):
                raise AssertionError(f"forged checkpoint failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("production image signing accepted a forged checkpoint receipt")

        tampered_proof = json.loads(json.dumps(document))
        tampered_proof["transparency"]["inclusion_proof"]["proof"] = [
            {"side": "left", "hash": "sha256:" + "0" * 64}
        ]
        try:
            verify(tampered_proof)
        except ValueError as exc:
            if "Merkle inclusion proof" not in str(exc):
                raise AssertionError(f"tampered Merkle proof failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("production image signing accepted a tampered Merkle inclusion proof")


def main() -> None:
    control_ref = "registry.prod.serverware.dev/serverware/control@sha256:" + "a" * 64
    gate_ref = "registry.prod.serverware.dev/serverware/decision-gate@sha256:" + "b" * 64
    inventory = signer.production_image_inventory([control_ref, gate_ref])
    if set(inventory) != {"control", "decision-gate"}:
        raise AssertionError(f"production image services were not derived from refs: {inventory}")
    if inventory["control"]["image_id"] != "sha256:" + "a" * 64:
        raise AssertionError(f"control image digest mismatch: {inventory}")
    if inventory["decision-gate"]["repo_digests"] != [gate_ref]:
        raise AssertionError(f"decision-gate repo digest was not preserved: {inventory}")
    try:
        signer.production_image_inventory(["registry.prod.serverware.dev/serverware/control:latest"])
    except ValueError as exc:
        if "digest-pinned" not in str(exc):
            raise AssertionError(f"mutable ref failed for the wrong reason: {exc}") from exc
    else:
        raise AssertionError("mutable production image ref was accepted")

    production_metadata = signer.cosign_compatible_statement_metadata(production=True)
    if "keyless" in production_metadata.lower():
        raise AssertionError(
            f"production image-signature metadata still recommends keyless signing: {production_metadata}"
        )
    if "pinned KMS/HSM key" not in production_metadata:
        raise AssertionError(
            f"production image-signature metadata omits the supported pinned key path: {production_metadata}"
        )
    if signer.cosign_compatible_statement_metadata(production=False) != "in-toto Statement v1 per image":
        raise AssertionError("development image-signature metadata contains a production signing recommendation")

    signer.validate_production_sigstore_configuration(
        production_refs=True,
        signature_provider="sigstore-command",
        image_sign_command="python3 scripts/cosign_sigstore.py sign",
        image_verify_command="python3 scripts/cosign_sigstore.py verify",
        require_transparency=True,
        cosign_binary="cosign",
    )
    for kwargs, expected in [
        (
            {
                "signature_provider": "dev-ed25519",
                "image_sign_command": "",
                "image_verify_command": "",
                "require_transparency": False,
                "cosign_binary": "cosign",
            },
            "sigstore-command",
        ),
        (
            {
                "signature_provider": "sigstore-command",
                "image_sign_command": "python3 scripts/cosign_sigstore.py sign",
                "image_verify_command": "",
                "require_transparency": True,
                "cosign_binary": "cosign",
            },
            "VERIFY_COMMAND",
        ),
        (
            {
                "signature_provider": "sigstore-command",
                "image_sign_command": "python3 scripts/cosign_sigstore.py sign",
                "image_verify_command": "python3 scripts/cosign_sigstore.py verify",
                "require_transparency": False,
                "cosign_binary": "cosign",
            },
            "TRANSPARENCY",
        ),
        (
            {
                "signature_provider": "sigstore-command",
                "image_sign_command": "python3 scripts/cosign_sigstore.py sign",
                "image_verify_command": "python3 scripts/cosign_sigstore.py verify",
                "require_transparency": True,
                "cosign_binary": "python3 scripts/cosign_fixture.py",
            },
            "fixture",
        ),
    ]:
        try:
            signer.validate_production_sigstore_configuration(production_refs=True, **kwargs)
        except ValueError as exc:
            if expected.lower() not in str(exc).lower():
                raise AssertionError(f"production signer guard failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError(f"production signer guard accepted invalid settings: {kwargs}")

    provenance = {
        "source_tree": {"digest": "sha256:" + "c" * 64},
        "compose_config_sha256": "sha256:" + "d" * 64,
        "sbom": {"cyclonedx": {"sha256": "sha256:" + "e" * 64, "components": 10}},
    }
    statement = signer.statement_for_image(
        service="control",
        image=inventory["control"],
        provenance=provenance,
        provenance_digest="sha256:" + "f" * 64,
        release_signing_key_id="sha256:" + "9" * 64,
    )
    subject = statement["subject"][0]
    if subject["digest"]["sha256"] != "a" * 64:
        raise AssertionError(f"statement subject did not bind production image digest: {statement}")
    if statement["predicate"]["repo_digests"] != [control_ref]:
        raise AssertionError(f"statement omitted production repo digest: {statement}")
    if statement["predicate"]["release_signing_key_id"] != "sha256:" + "9" * 64:
        raise AssertionError(f"statement omitted release signing key binding: {statement}")
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        images_env = tmp / "production-images.env"
        images_env.write_text("SERVERWARE_PRODUCTION_IMAGES=" + ",".join([control_ref, gate_ref]) + "\n", encoding="utf-8")
        if signer.image_refs_from_env_file(images_env) != [control_ref, gate_ref]:
            raise AssertionError("production image refs were not loaded from the env fragment")
        extra_env = tmp / "extra.env"
        extra_env.write_text(
            "SERVERWARE_PRODUCTION_IMAGES=" + control_ref + "\nSERVERWARE_ADMIN_TOKEN=secret\n",
            encoding="utf-8",
        )
        try:
            signer.image_refs_from_env_file(extra_env)
        except ValueError as exc:
            if "must contain only SERVERWARE_PRODUCTION_IMAGES" not in str(exc):
                raise AssertionError(f"extra key failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("production image signing accepted an env fragment with extra keys")
    exercise_external_verify_contract()
    exercise_env_file_preload()
    exercise_stale_provenance_rejection()
    exercise_independent_provenance_trust()
    print(json.dumps({"ok": True, "sign_release_images": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
