#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import build_production_images
import generate_release_provenance
import production_host_preflight as production_host_preflight_module
import production_release_input_preflight
import launch_authorization
import run_production_readiness
import test_production_policy_identity
import test_production_release_input_preflight
import verify_release_completion
import verify_production_policy_identity

ROOT = Path(__file__).resolve().parent.parent
SOURCE_TREE_DIGEST = build_production_images.source_tree_digest()
IMAGE_SIGNATURES_DIGEST = ""
FIXTURE_LAUNCH_AUTHORITY_KEY_ID = "sha256:" + "1" * 64
FIXTURE_LAUNCH_AUTHORITY_ROOT_SHA256 = "sha256:" + "2" * 64


def clean_subprocess_env() -> dict[str, str]:
    allowed = {
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
    }
    return {name: value for name, value in os.environ.items() if name in allowed}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed_json(value: Any) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_prefixed_bytes(value: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha384(value: str) -> str:
    return "sha384:" + value * 96


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_cosign_ecdsa_signature_compatibility() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    payload = canonical_json({"cosign": "canonical-statement"}).encode("utf-8")
    signature = base64.b64encode(private_key.sign(payload, ec.ECDSA(hashes.SHA256()))).decode("ascii")
    verify_release_completion.verify_public_key_signature(
        public_key_pem,
        signature,
        payload,
        "Cosign ECDSA fixture",
    )
    try:
        verify_release_completion.verify_public_key_signature(
            public_key_pem,
            signature,
            payload + b"-tampered",
            "Cosign ECDSA fixture",
        )
    except ValueError:
        return
    raise AssertionError("completion verifier accepted an ECDSA signature over a different statement")


def verify_ed25519_signature_canonicalization() -> None:
    key_info = hardware_verifier_key_info()
    payload = canonical_json({"signed": "statement"}).encode("utf-8")
    encoded = b64e(key_info["key"].sign(payload))
    signature = "ed25519:" + encoded
    verify_release_completion.verify_ed25519(
        key_info["public_key_pem"],
        signature,
        payload,
        "canonical Ed25519 fixture",
    )
    verify_release_completion.verify_public_key_signature(
        key_info["public_key_pem"],
        encoded,
        payload,
        "canonical Ed25519 generic fixture",
    )

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    final_index = alphabet.index(encoded[-1])
    alias_index = final_index + 1 if final_index % 16 != 15 else final_index - 1
    noncanonical_alias = encoded[:-1] + alphabet[alias_index]
    if base64.urlsafe_b64decode(noncanonical_alias + "==") != key_info["key"].sign(payload):
        raise AssertionError("Ed25519 fixture did not construct an equivalent non-canonical encoding")
    for rejected in (signature + "=", "ed25519:" + noncanonical_alias):
        try:
            verify_release_completion.verify_ed25519(
                key_info["public_key_pem"],
                rejected,
                payload,
                "non-canonical Ed25519 fixture",
            )
        except ValueError as exc:
            if "canonical unpadded base64url" not in str(exc):
                raise AssertionError(
                    f"non-canonical Ed25519 signature failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError("completion verifier accepted a non-canonical Ed25519 signature")


def test_final_file_snapshots() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        document_path = tmp / "hardware-assurance.json"
        trusted_key_path = tmp / "hardware-verifier.pub.pem"
        original_document = b'{"version":"original"}\n'
        replacement_document = b'{"version":"replacement"}\n'
        original_key = hardware_verifier_key_info()["public_key_pem"].encode("ascii")
        replacement_key = final_challenge_authority_key_info()["public_key_pem"].encode("ascii")
        document_path.write_bytes(original_document)
        trusted_key_path.write_bytes(original_key)
        snapshots = verify_release_completion.snapshot_final_verification_files(
            {
                "hardware_assurance": document_path,
                "hardware_assurance_trusted_public_key": trusted_key_path,
            },
            include_hardware_assurance=True,
            include_final_receipt=False,
        )
        document_path.write_bytes(replacement_document)
        trusted_key_path.write_bytes(replacement_key)
        if (
            verify_release_completion.load_json_snapshot(
                snapshots["hardware_assurance"],
                "hardware assurance",
            ).get("version")
            != "original"
            or snapshots["hardware_assurance"].sha256
            != sha256_prefixed_bytes(original_document)
            or verify_release_completion.release_public_key_id(
                verify_release_completion.snapshot_text(
                    snapshots["hardware_assurance_trusted_public_key"],
                    "hardware assurance trust root",
                    encoding="ascii",
                )
            )
            != hardware_verifier_key_info()["key_id"]
        ):
            raise AssertionError("final verification snapshots reopened a swapped input path")

        symlink_path = tmp / "symlinked-hardware-assurance.json"
        symlink_path.symlink_to(document_path)
        try:
            verify_release_completion.snapshot_regular_file(
                symlink_path,
                "hardware assurance",
                max_bytes=verify_release_completion.FINAL_EVIDENCE_MAX_BYTES,
            )
        except ValueError as exc:
            if "must not be a symlink" not in str(exc):
                raise AssertionError(
                    f"symlinked final input failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError("final verification accepted a symlinked input")

        proxy_snapshot_paths = {
            "proxy_response_proof": tmp / "proxy-response-proof.json",
            "proxy_collector_public_key": tmp / "proxy-collector.pub.pem",
            "proxy_proof_verifier_public_key": tmp / "proxy-verifier.pub.pem",
            "control_plane_response_signing_public_key": tmp
            / "control-plane-response-signing.pub.pem",
            "policy_bundle": tmp / "policy-bundle.json",
            "policy_trusted_public_key": tmp / "policy-signing.pub.pem",
        }
        proxy_snapshot_original = {
            "proxy_response_proof": b'{"proof":"original"}\n',
            "proxy_collector_public_key": proxy_collector_key_info()[
                "public_key_pem"
            ].encode("ascii"),
            "proxy_proof_verifier_public_key": proxy_vendor_verifier_key_info()[
                "public_key_pem"
            ].encode("ascii"),
            "control_plane_response_signing_public_key": control_plane_response_signing_key_info()[
                "public_key_pem"
            ].encode("ascii"),
            "policy_bundle": b'{"policy":"original"}\n',
            "policy_trusted_public_key": release_key_info()["public_key_pem"].encode(
                "ascii"
            ),
        }
        for name, path in proxy_snapshot_paths.items():
            path.write_bytes(proxy_snapshot_original[name])
        proxy_snapshots = verify_release_completion.snapshot_final_verification_files(
            proxy_snapshot_paths,
            include_hardware_assurance=False,
            include_final_receipt=False,
            include_proxy_security=True,
            include_policy=True,
        )
        for path in proxy_snapshot_paths.values():
            path.write_bytes(b"replacement")
        for name, original in proxy_snapshot_original.items():
            if proxy_snapshots[name].data != original:
                raise AssertionError(f"final verification reopened swapped {name} input")

        for symlinked_name, path in proxy_snapshot_paths.items():
            path.unlink()
            path.symlink_to(document_path)
            for other_name, other_path in proxy_snapshot_paths.items():
                if other_name != symlinked_name:
                    other_path.unlink(missing_ok=True)
                    other_path.write_bytes(proxy_snapshot_original[other_name])
            try:
                verify_release_completion.snapshot_final_verification_files(
                    proxy_snapshot_paths,
                    include_hardware_assurance=False,
                    include_final_receipt=False,
                    include_proxy_security=True,
                    include_policy=True,
                )
            except ValueError as exc:
                if "must not be a symlink" not in str(exc):
                    raise AssertionError(
                        f"symlinked {symlinked_name} failed for the wrong reason: {exc}"
                    ) from exc
            else:
                raise AssertionError(
                    f"final verification accepted symlinked {symlinked_name} input"
                )

        raced_path = tmp / "raced-input.json"
        replacement_path = tmp / "raced-input-replacement.json"
        raced_original = b'{"generation":"original"}\n'
        raced_replacement = b'{"generation":"replacement"}\n'
        raced_path.write_bytes(raced_original)
        replacement_path.write_bytes(raced_replacement)
        original_os_read = verify_release_completion.os.read
        replaced = False

        def replace_path_after_open(descriptor: int, size: int) -> bytes:
            nonlocal replaced
            if not replaced:
                replaced = True
                os.replace(replacement_path, raced_path)
            return original_os_read(descriptor, size)

        verify_release_completion.os.read = replace_path_after_open
        try:
            try:
                verify_release_completion.snapshot_regular_file(
                    raced_path,
                    "raced completion input",
                    max_bytes=1024,
                )
            except ValueError as exc:
                if "changed while" not in str(exc):
                    raise
            else:
                raise AssertionError("completion input snapshot accepted a path replacement race")
        finally:
            verify_release_completion.os.read = original_os_read
        if raced_path.read_bytes() != raced_replacement:
            raise AssertionError("completion input race fixture did not replace the source path")

        oversized_path = tmp / "oversized-final-receipt.json"
        oversized_path.write_bytes(b"x" * 65)
        try:
            verify_release_completion.snapshot_regular_file(
                oversized_path,
                "final challenge receipt",
                max_bytes=64,
            )
        except ValueError as exc:
            if "size limit" not in str(exc):
                raise AssertionError(f"oversized final input failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("final verification accepted an oversized input")


def test_release_provenance_input_snapshot() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        input_path = tmp / "release-input.json"
        original_bytes = b'{"identity":"original"}\n'
        replacement_bytes = b'{"identity":"replacement"}\n'
        input_path.write_bytes(original_bytes)

        original_reader = generate_release_provenance.read_bounded_regular_file
        read_count = 0

        def swap_path_after_snapshot(
            path: Path,
            label: str,
            *,
            max_bytes: int,
        ) -> bytes:
            nonlocal read_count
            read_count += 1
            snapshot = original_reader(path, label, max_bytes=max_bytes)
            path.write_bytes(replacement_bytes)
            return snapshot

        generate_release_provenance.read_bounded_regular_file = (
            swap_path_after_snapshot
        )
        try:
            parsed, snapshot = generate_release_provenance.load_json_snapshot(
                input_path,
                "release input",
            )
        finally:
            generate_release_provenance.read_bounded_regular_file = original_reader
        if (
            read_count != 1
            or parsed != {"identity": "original"}
            or snapshot != original_bytes
            or sha256_prefixed_bytes(snapshot)
            != sha256_prefixed_bytes(original_bytes)
            or input_path.read_bytes() != replacement_bytes
        ):
            raise AssertionError(
                "release provenance parse and digest did not share one immutable byte snapshot"
            )

        input_path.write_bytes(b'{"duplicate":1,"duplicate":2}\n')
        try:
            generate_release_provenance.load_json_snapshot(
                input_path,
                "release input",
            )
        except ValueError as exc:
            if "duplicate JSON object key" not in str(exc.__cause__):
                raise AssertionError(
                    f"duplicate release JSON failed ambiguously: {exc}"
                ) from exc
        else:
            raise AssertionError("release provenance accepted duplicate JSON keys")

        target_path = tmp / "release-target.json"
        target_path.write_bytes(original_bytes)
        symlink_path = tmp / "release-symlink.json"
        symlink_path.symlink_to(target_path)
        try:
            generate_release_provenance.load_json_snapshot(
                symlink_path,
                "release input",
            )
        except ValueError:
            pass
        else:
            raise AssertionError("release provenance accepted a symlinked input")


def test_measured_preflight_module_replacement_race() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        scripts_dir = tmp / "scripts"
        scripts_dir.mkdir()
        verifier_path = scripts_dir / "verify_release_completion.py"
        verifier_path.write_text("# fixture verifier location\n", encoding="ascii")
        preflight_path = scripts_dir / "production_host_preflight.py"
        replacement_path = scripts_dir / "replacement-production_host_preflight.py"
        preflight_path.write_text("MARKER = 'measured'\n", encoding="ascii")
        replacement_path.write_text("MARKER = 'replacement'\n", encoding="ascii")
        expected_digest = sha256_file(preflight_path)

        def replace_after_open(_measured: run_production_readiness.MeasuredScript) -> None:
            os.replace(replacement_path, preflight_path)

        original_file = verify_release_completion.__file__
        original_module = verify_release_completion._MEASURED_PREFLIGHT_MODULE
        original_digest = verify_release_completion._MEASURED_PREFLIGHT_MODULE_SHA256
        original_sys_module = sys.modules.get(
            "_serverware_measured_production_host_preflight"
        )
        try:
            verify_release_completion.__file__ = str(verifier_path)
            verify_release_completion._MEASURED_PREFLIGHT_MODULE = None
            verify_release_completion._MEASURED_PREFLIGHT_MODULE_SHA256 = None
            try:
                module = verify_release_completion.load_production_host_preflight_module(
                    {
                        run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV: (
                            expected_digest
                        )
                    },
                    final=True,
                    after_open=replace_after_open,
                )
            except ValueError as exc:
                if "changed while being read" not in str(exc):
                    raise
            else:
                if module.MARKER != "measured":
                    raise AssertionError(
                        "completion loaded replacement production host preflight bytes after measurement"
                    )
        finally:
            verify_release_completion.__file__ = original_file
            verify_release_completion._MEASURED_PREFLIGHT_MODULE = original_module
            verify_release_completion._MEASURED_PREFLIGHT_MODULE_SHA256 = original_digest
            if original_sys_module is None:
                sys.modules.pop("_serverware_measured_production_host_preflight", None)
            else:
                sys.modules[
                    "_serverware_measured_production_host_preflight"
                ] = original_sys_module


HARDWARE_ASSURANCE_CHALLENGE_BYTES = b"hardware-assurance-fixture-nonce"
HARDWARE_ASSURANCE_CHALLENGE_NONCE = b64e(HARDWARE_ASSURANCE_CHALLENGE_BYTES)
HARDWARE_ASSURANCE_CHALLENGE_SHA256 = sha256_prefixed_bytes(HARDWARE_ASSURANCE_CHALLENGE_BYTES)


KMS_MATERIAL_FIXTURES: dict[str, dict[str, Any]] = {
    "broker-kek": {
        "key_id": "arn:aws:kms:us-east-1:111122223333:key/1",
        "ciphertext": b"broker-ciphertext",
        "encryption_context": {"material": "broker-kek", "service": "serverware"},
    },
    "decision-gate-ca": {
        "key_id": "arn:aws:kms:us-east-1:111122223333:key/2",
        "ciphertext": b"ca-ciphertext",
        "encryption_context": {"material": "decision-gate-ca", "service": "serverware"},
    },
}


def kms_materials_document() -> dict[str, Any]:
    return {
        material: {
            "key_id": str(config["key_id"]),
            "ciphertext_blob_b64": base64.b64encode(config["ciphertext"]).decode("ascii"),
            "encryption_context": config["encryption_context"],
        }
        for material, config in KMS_MATERIAL_FIXTURES.items()
    }


def kms_material_binding(material: str) -> dict[str, str]:
    config = KMS_MATERIAL_FIXTURES[material]
    return {
        "key_id_sha256": sha256_prefixed_bytes(str(config["key_id"]).encode("utf-8")),
        "ciphertext_blob_sha256": sha256_prefixed_bytes(config["ciphertext"]),
        "encryption_context_sha256": sha256_prefixed_json(config["encryption_context"]),
    }


def release_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x09" * 32)
    return ed25519_key_info(key)


def transparency_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
    return ed25519_key_info(key)


def external_receipt_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x06" * 32)
    return ed25519_key_info(key)


def hardware_verifier_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
    return ed25519_key_info(key)


def sigstore_signing_key_info() -> dict[str, Any]:
    return public_key_info(ec.derive_private_key(4, ec.SECP256R1()))


def rekor_key_info() -> dict[str, Any]:
    return public_key_info(ec.derive_private_key(3, ec.SECP256R1()))


def final_challenge_authority_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x0b" * 32)
    return ed25519_key_info(key)


def control_plane_response_signing_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x0c" * 32)
    return ed25519_key_info(key)


def alternate_control_plane_response_signing_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x0d" * 32)
    return ed25519_key_info(key)


def preflight_signing_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x0e" * 32)
    return ed25519_key_info(key)


def policy_activation_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x10" * 32)
    return ed25519_key_info(key)


def reproducible_build_key_info() -> dict[str, Any]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
    return ed25519_key_info(key)


def reproducible_builder_left_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x24" * 32))


def reproducible_builder_right_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x25" * 32))


def ed25519_key_info(key: Ed25519PrivateKey) -> dict[str, Any]:
    return public_key_info(key)


def public_key_info(key: Any) -> dict[str, Any]:
    public_key = key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"key": key, "public_key_pem": pem, "key_id": sha256_prefixed_bytes(der)}


def image_signature_bundle_digest(document: dict[str, Any]) -> str:
    copied = json.loads(json.dumps(document))
    copied.pop("image_signature_bundle_digest", None)
    copied.pop("bundle_signature", None)
    metadata = copied.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
        metadata.pop("transparency", None)
        metadata.pop("bundleSigstore", None)
    return sha256_prefixed_json(copied)


def refresh_sigstore_bundle_digest(sigstore: dict[str, Any], statement: dict[str, Any]) -> None:
    refreshed = sigstore_proof(statement=statement)
    sigstore.clear()
    sigstore.update(refreshed)


def refresh_image_signature_bundle(summary: dict[str, Any], document: dict[str, Any]) -> None:
    bundle_digest = image_signature_bundle_digest(document)
    document["image_signature_bundle_digest"] = bundle_digest
    bundle_sigstore = document.get("bundle_signature")
    if isinstance(bundle_sigstore, dict):
        bundle_sigstore["statement_digest"] = bundle_digest
        refresh_sigstore_bundle_digest(
            bundle_sigstore,
            verify_release_completion.normalized_image_signature_payload(document),
        )
        metadata = document.get("metadata")
        if isinstance(metadata, dict):
            metadata["bundleSigstore"] = bundle_sigstore
            metadata["signature"] = bundle_sigstore["signature"]
    summary["image_signature_bundle_digest"] = bundle_digest
    refresh_image_transparency_record(document)


def refresh_image_statements_and_bundle(summary: dict[str, Any], document: dict[str, Any]) -> None:
    for image in document.get("images") or []:
        if not isinstance(image, dict):
            continue
        statement = image.get("statement")
        if not isinstance(statement, dict):
            continue
        statement_digest = sha256_prefixed_json(statement)
        image["statement_digest"] = statement_digest
        sigstore = image.get("sigstore")
        if isinstance(sigstore, dict):
            sigstore["statement_digest"] = statement_digest
            refresh_sigstore_bundle_digest(sigstore, statement)
            image["signature"] = sigstore["signature"]
    refresh_image_signature_bundle(summary, document)


def refresh_release_provenance(summary: dict[str, Any], document: dict[str, Any]) -> None:
    key_info = release_key_info()
    provenance = document["provenance"]
    provenance_digest = sha256_prefixed_json(provenance)
    signature = "ed25519:" + b64e(key_info["key"].sign(canonical_json(provenance).encode("utf-8")))
    document["provenance_digest"] = provenance_digest
    document["signature"] = signature
    document["release_signing_key_id"] = key_info["key_id"]
    document["release_signing_public_key_pem"] = key_info["public_key_pem"]
    document["transparency"] = transparency_for_record(
        {
            "type": "release.provenance.v2",
            "provenance_digest": provenance_digest,
            "signature": signature,
            "release_signing_key_id": key_info["key_id"],
            "production_launcher_binary_digest": provenance["images"][
                "serverware-decision-gate"
            ]["launcher_binary_digest"],
            "launch_authority_key_id": provenance["launch_authority"][
                "launch_authority_key_id"
            ],
            "launch_authority_root_sha256": provenance["launch_authority"][
                "launch_authority_root_sha256"
            ],
            "reproducible_build_verification_sha256": provenance[
                "reproducible_build"
            ]["verification_sha256"],
        }
    )
    summary["provenance_digest"] = provenance_digest
    summary["release_signing_key_id"] = key_info["key_id"]
    summary["production_launcher_binary_digest"] = provenance["images"][
        "serverware-decision-gate"
    ]["launcher_binary_digest"]
    summary.update(provenance["launch_authority"])
    summary["reproducible_build_verification_sha256"] = provenance[
        "reproducible_build"
    ]["verification_sha256"]


def sha256_file(path: Path) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def digest(char: str) -> str:
    return "sha256:" + char * 64


def bootstrap_receipt_fixture(
    *,
    deployment_identity_sha256: str = "sha256:" + "a" * 64,
    release_sequence: int = 42,
    rollback_epoch: int = 7,
) -> dict[str, Any]:
    def metadata(*, mode: int = 0o100400, link_count: int = 1) -> dict[str, int]:
        return {
            "device": 1,
            "inode": 2,
            "mode": mode,
            "ownerUid": 0,
            "ownerGid": 0,
            "linkCount": link_count,
            "size": 128,
            "modifiedUnixNanos": 1,
            "changedUnixNanos": 1,
        }

    def file_record(path: str, character: str) -> dict[str, Any]:
        return {"path": path, "sha256": digest(character), "metadata": metadata()}

    launcher_digest = digest("3")
    receipt = {
        "apiVersion": "serverware.bootstrapReceipt/v2",
        "kind": "ProductionBootstrapReceipt",
        "launchId": "1" * 64,
        "bootIdSha256": digest("2"),
        "launcher": file_record(
            "/opt/serverware/launchers/sha256-"
            + launcher_digest.removeprefix("sha256:")
            + "/serverware-production-launcher",
            "3",
        ),
        "manifest": file_record("/etc/serverware/production-release-launch.json", "4"),
        "sourceTreeDigest": SOURCE_TREE_DIGEST,
        "productionEnv": file_record("/etc/serverware/production-readiness.env", "5"),
        "python": {
            **file_record("/opt/serverware/releases/fixture/runtime/python/bin/python3", "6"),
            "importRoots": [
                {
                    "path": "/opt/serverware/releases/fixture",
                    "sha256": digest("7"),
                    "metadata": metadata(mode=0o40555, link_count=2),
                }
            ],
        },
        "scripts": {
            "preflight": file_record(
                "/opt/serverware/releases/fixture/scripts/production_host_preflight.py", "8"
            ),
            "runner": file_record(
                "/opt/serverware/releases/fixture/scripts/run_production_readiness.py", "9"
            ),
        },
        "composeFile": file_record(
            "/opt/serverware/releases/fixture/docker-compose.production.yml", "a"
        ),
        "inputs": {
            name: file_record(f"/opt/serverware/releases/fixture/evidence/{name}.json", "b")
            for name in sorted(run_production_readiness.BOOTSTRAP_RECEIPT_INPUT_NAMES)
        },
        "argv": {"preflightSha256": digest("c"), "readinessSha256": digest("d")},
        "environment": {
            "names": run_production_readiness.BOOTSTRAP_RECEIPT_COMMITTED_ENV_NAMES,
            "sha256": digest("e"),
        },
    }
    authority_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("33" * 32))
    request = {
        "apiVersion": launch_authorization.REQUEST_API_VERSION,
        "kind": launch_authorization.REQUEST_KIND,
        "launcherNonce": receipt["launchId"],
        "bootIdSha256": receipt["bootIdSha256"],
        "launcherSha256": receipt["launcher"]["sha256"],
        "manifestSha256": receipt["manifest"]["sha256"],
        "releaseProvenanceSha256": receipt["inputs"]["releaseProvenance"]["sha256"],
        "provenanceDigest": digest("0"),
        "reproducibleBuildVerificationSha256": receipt["inputs"][
            "reproducibleBuildVerification"
        ]["sha256"],
        "sourceTreeDigest": receipt["sourceTreeDigest"],
        "deploymentAudience": "production.us-east-1:primary",
        "deploymentIdentitySha256": deployment_identity_sha256,
        "releaseSequence": release_sequence,
        "rollbackEpoch": rollback_epoch,
    }
    envelope = launch_authorization.sign_launch_authorization(
        request,
        private_key=authority_key,
        authorization_id="2" * 64,
        issued_at_unix_seconds=100,
        expires_at_unix_seconds=120,
    )
    receipt["launchAuthorization"] = {
        "request": request,
        "requestSha256": launch_authorization.launch_authorization_request_sha256(
            request
        ),
        "envelope": envelope,
        "authorizationSha256": sha256_prefixed_bytes(
            launch_authorization.canonical_json_bytes(envelope)
        ),
        "verifiedAtUnixSeconds": 101,
    }
    return receipt


def bootstrap_receipt_summary(receipt: dict[str, Any]) -> dict[str, Any]:
    authority_public_raw = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("33" * 32)
    ).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "apiVersion": receipt["apiVersion"],
        "kind": receipt["kind"],
        "launchId": receipt["launchId"],
        "sha256": digest("f"),
        "bootIdSha256": receipt["bootIdSha256"],
        "sourceTreeDigest": receipt["sourceTreeDigest"],
        "launchAuthorization": receipt["launchAuthorization"],
        "launchAuthorityKeyId": receipt["launchAuthorization"]["envelope"][
            "statement"
        ]["authorityKeyId"],
        "launchAuthorityRootSha256": sha256_prefixed_bytes(
            authority_public_raw.hex().encode("ascii") + b"\n"
        ),
        "launcher": receipt["launcher"],
        "manifest": receipt["manifest"],
        "argv": receipt["argv"],
        "environment": receipt["environment"],
        "sealed": True,
        "sealMask": run_production_readiness.REQUIRED_BOOTSTRAP_RECEIPT_SEALS,
    }


def verify_release_proof_schemas() -> tuple[Any, dict[str, Any]]:
    from jsonschema import Draft202012Validator

    receipt_schema = json.loads((ROOT / "schemas/bootstrap-receipt.v2.schema.json").read_text(encoding="utf-8"))
    completion_schema = json.loads((ROOT / "schemas/completion-proof.v5.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(receipt_schema)
    Draft202012Validator.check_schema(completion_schema)
    receipt = bootstrap_receipt_fixture()
    Draft202012Validator(receipt_schema).validate(receipt)
    open_receipt = json.loads(json.dumps(receipt))
    open_receipt["launcher"]["metadata"]["unexpected"] = True
    if not list(Draft202012Validator(receipt_schema).iter_errors(open_receipt)):
        raise AssertionError("bootstrap receipt schema accepted an open nested metadata object")
    open_authorization = clone_document(receipt)
    open_authorization["launchAuthorization"]["request"]["unexpected"] = True
    if not list(Draft202012Validator(receipt_schema).iter_errors(open_authorization)):
        raise AssertionError("bootstrap receipt schema accepted an open authorization request")
    old_receipt = clone_document(receipt)
    old_receipt["apiVersion"] = "serverware.bootstrapReceipt/v1"
    if not list(Draft202012Validator(receipt_schema).iter_errors(old_receipt)):
        raise AssertionError("bootstrap receipt v2 schema accepted a v1 receipt")
    return Draft202012Validator(completion_schema), receipt


def verify_launcher_three_way_binding() -> None:
    receipt = bootstrap_receipt_summary(bootstrap_receipt_fixture())
    launcher_digest = receipt["launcher"]["sha256"]
    verified = verify_release_completion.verify_bootstrap_launcher_authorization(
        receipt,
        signed_provenance_digest=launcher_digest,
        independently_reproduced_digest=launcher_digest,
    )
    if not all(
        verified.get(field) is True
        for field in (
            "signed_provenance_bound",
            "independent_build_bound",
            "content_addressed_path_bound",
        )
    ):
        raise AssertionError(f"launcher authorization omitted a required binding: {verified}")
    for label, provenance_digest, reproduced_digest in (
        ("provenance", digest("0"), launcher_digest),
        ("independent build", launcher_digest, digest("0")),
    ):
        try:
            verify_release_completion.verify_bootstrap_launcher_authorization(
                receipt,
                signed_provenance_digest=provenance_digest,
                independently_reproduced_digest=reproduced_digest,
            )
        except ValueError as exc:
            if "does not match signed provenance and independent-build evidence" not in str(exc):
                raise AssertionError(f"{label} mismatch failed ambiguously: {exc}") from exc
        else:
            raise AssertionError(f"launcher authorization accepted a {label} digest mismatch")
    wrong_path = json.loads(json.dumps(receipt))
    wrong_path["launcher"]["path"] = "/opt/serverware/launchers/unbound/serverware-production-launcher"
    try:
        verify_release_completion.verify_bootstrap_launcher_authorization(
            wrong_path,
            signed_provenance_digest=launcher_digest,
            independently_reproduced_digest=launcher_digest,
        )
    except ValueError as exc:
        if "not content-addressed" not in str(exc):
            raise AssertionError(f"launcher path mismatch failed ambiguously: {exc}") from exc
    else:
        raise AssertionError("launcher authorization accepted a non-content-addressed path")

    launch_identity = verify_release_completion.verify_bootstrap_launch_authorization_bindings(
        receipt,
        signed_provenance_digest=digest("0"),
        signed_source_tree_digest=receipt["sourceTreeDigest"],
        release_provenance_sha256=receipt["launchAuthorization"]["request"][
            "releaseProvenanceSha256"
        ],
        reproducible_build_verification_sha256=receipt["launchAuthorization"][
            "request"
        ]["reproducibleBuildVerificationSha256"],
        current_host_identity_sha256=receipt["launchAuthorization"]["request"][
            "deploymentIdentitySha256"
        ],
        release_artifact_launch_authority={
            "launch_authority_key_id": receipt["launchAuthorityKeyId"],
            "launch_authority_root_sha256": receipt[
                "launchAuthorityRootSha256"
            ],
        },
    )
    if not all(
        launch_identity.get(field) is True
        for field in (
            "canonical_request_digest_verified",
            "canonical_envelope_digest_verified",
            "authority_signature_verified_at_launch",
            "signed_provenance_bound",
            "signed_source_tree_bound",
            "measured_release_provenance_bound",
            "independent_build_report_bound",
            "current_host_deployment_identity_bound",
            "release_artifact_authority_bound",
        )
    ):
        raise AssertionError(
            f"completion launch authorization omitted required bindings: {launch_identity}"
        )
    separated_roles = {
        role: sha256_prefixed_bytes(f"fixture-role:{role}".encode("ascii"))
        for role in verify_release_completion.SECURITY_ROLE_NAMES
    }
    role_separation = (
        verify_release_completion.verify_launch_authority_key_role_separation(
            receipt["launchAuthorityKeyId"],
            separated_roles,
        )
    )
    if (
        role_separation.get("verified") is not True
        or set(role_separation.get("roles") or {})
        != {"launch_authority_signer", *separated_roles}
        or role_separation.get("sha256")
        != sha256_prefixed_json(
            {
                "apiVersion": verify_release_completion.SECURITY_ROLE_MAP_API_VERSION,
                "roles": role_separation["roles"],
            }
        )
    ):
        raise AssertionError(
            f"launch authority role separation omitted verified roles: {role_separation}"
        )
    ordered_roles = list(verify_release_completion.SECURITY_ROLE_NAMES)
    for index, role in enumerate(ordered_roles):
        reused_role = dict(separated_roles)
        reused_from = ordered_roles[index - 1]
        reused_role[role] = reused_role[reused_from]
        try:
            verify_release_completion.verify_launch_authority_key_role_separation(
                receipt["launchAuthorityKeyId"],
                reused_role,
            )
        except ValueError as exc:
            if (
                role not in str(exc)
                or reused_from not in str(exc)
                or "pairwise-distinct" not in str(exc)
            ):
                raise AssertionError(
                    f"security role reuse for {role} failed ambiguously: {exc}"
                ) from exc
        else:
            raise AssertionError(
                f"security role {role} reused the {reused_from} key"
            )
    try:
        verify_release_completion.verify_launch_authority_key_role_separation(
            separated_roles[ordered_roles[0]],
            separated_roles,
        )
    except ValueError as exc:
        if (
            "launch_authority_signer" not in str(exc)
            or ordered_roles[0] not in str(exc)
            or "pairwise-distinct" not in str(exc)
        ):
            raise AssertionError(
                f"launch authority role reuse failed ambiguously: {exc}"
            ) from exc
    else:
        raise AssertionError("launch authority reused another security role key")
    for label, overrides in (
        ("provenance", {"signed_provenance_digest": digest("9")}),
        ("source", {"signed_source_tree_digest": digest("9")}),
        ("release provenance file", {"release_provenance_sha256": digest("9")}),
        (
            "reproducible-build file",
            {"reproducible_build_verification_sha256": digest("9")},
        ),
        ("deployment", {"current_host_identity_sha256": digest("9")}),
        (
            "authority key",
            {
                "release_artifact_launch_authority": {
                    "launch_authority_key_id": digest("9"),
                    "launch_authority_root_sha256": receipt[
                        "launchAuthorityRootSha256"
                    ],
                }
            },
        ),
        (
            "authority root",
            {
                "release_artifact_launch_authority": {
                    "launch_authority_key_id": receipt["launchAuthorityKeyId"],
                    "launch_authority_root_sha256": digest("9"),
                }
            },
        ),
    ):
        arguments = {
            "signed_provenance_digest": digest("0"),
            "signed_source_tree_digest": receipt["sourceTreeDigest"],
            "release_provenance_sha256": receipt["launchAuthorization"]["request"][
                "releaseProvenanceSha256"
            ],
            "reproducible_build_verification_sha256": receipt[
                "launchAuthorization"
            ]["request"]["reproducibleBuildVerificationSha256"],
            "current_host_identity_sha256": receipt["launchAuthorization"]["request"][
                "deploymentIdentitySha256"
            ],
            "release_artifact_launch_authority": {
                "launch_authority_key_id": receipt["launchAuthorityKeyId"],
                "launch_authority_root_sha256": receipt[
                    "launchAuthorityRootSha256"
                ],
            },
            **overrides,
        }
        try:
            verify_release_completion.verify_bootstrap_launch_authorization_bindings(
                receipt,
                **arguments,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"completion launch authorization accepted {label} cross-wiring"
            )


PINNED_EXECUTABLE_NAMES = {
    "SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE": "nsm-attest",
    "SERVERWARE_NITRO_NSM_UNSEAL_COMMAND_TEMPLATE": "nsm-unseal",
    "SERVERWARE_DATA_PLANE_RECIPIENT_ATTESTATION_COMMAND": "lease-recipient-attest",
    "SERVERWARE_DATA_PLANE_RESPONSE_PROOF_ATTESTATION_COMMAND": "response-proof-attest",
    "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND": "lease-recipient-verify",
    "SERVERWARE_CONTROL_PLANE_ATTESTATION_VERIFY_COMMAND": "control-plane-attestation-verify",
    "SERVERWARE_PROXY_PROOF_COLLECTOR_COMMAND": "serverware-proof-client",
    "SERVERWARE_PRODUCTION_PYTHON_EXECUTABLE": "production-python",
    "SERVERWARE_DOCKER_EXECUTABLE": "production-docker",
}


def fixture_executable_bytes(setting: str) -> bytes:
    return f"#!/bin/sh\n# {setting}\nexit 0\n".encode("ascii")


def fixture_executable_digest_manifest() -> dict[str, str]:
    return {
        setting: sha256_prefixed_bytes(fixture_executable_bytes(setting))
        for setting in sorted(PINNED_EXECUTABLE_NAMES)
    }


POLICY_DIGEST = digest("8")


PROXY_PRINCIPAL_ID = "agent:payments"
ALTERNATE_PROXY_PRINCIPAL_ID = "agent:billing"
PROXY_CLIENT_NONCE = b64e(b"n" * 32)
PROXY_TLS_CHANNEL_BINDING = b64e(b"t" * 32)
PROXY_CLIENT_REQUEST_DIGEST = sha256_prefixed_json(
    {
        "apiVersion": "serverware.clientProofRequest/v1",
        "method": "GET",
        "scheme": "https",
        "authority": "demo-upstream:8443",
        "path": "/echo",
        "query": [],
        "headers": {"accept": "application/json"},
        "body_sha256": sha256_prefixed_bytes(b""),
    }
)
PROXY_STREAM_CLIENT_REQUEST_DIGEST = sha256_prefixed_json(
    {
        "apiVersion": "serverware.streamingClientProofRequest/v1",
        "method": "GET",
        "scheme": "https",
        "authority": "demo-upstream:8443",
        "path": "/echo",
        "query": [],
        "headers": {"accept": "application/json"},
        "body_sha256": sha256_prefixed_bytes(b""),
    }
)
PROXY_REQUEST_DIGEST = digest("1")
PROXY_OPERATION_DIGEST = digest("2")
PROXY_OPERATION_CONTEXT = {"operation": "demo.echo"}
PROXY_OPERATION_CONTEXT_DIGEST = sha256_prefixed_json(PROXY_OPERATION_CONTEXT)
PROXY_SERVER_INSTANCE_ID = "spiffe://prod.serverware.dev/decision-gate/instance-01"
PROXY_TLS_PEER_LEAF_CERTIFICATE_DIGEST = digest("a")
FIXTURE_HOST_A_MACHINE_ID = "0123456789abcdef0123456789abcdef"
FIXTURE_HOST_A_PRODUCT_UUID = "11111111-2222-4333-8444-555555555555"
FIXTURE_HOST_A_BOOT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
FIXTURE_HOST_B_MACHINE_ID = "fedcba9876543210fedcba9876543210"
FIXTURE_HOST_B_PRODUCT_UUID = "99999999-8888-4777-8666-555555555555"
FIXTURE_HOST_B_BOOT_ID = "11111111-aaaa-4bbb-8ccc-222222222222"


def fixture_current_host_identity(*, host_b: bool = False) -> dict[str, str]:
    if host_b:
        return verify_release_completion.current_host_identity_from_values(
            machine_id=FIXTURE_HOST_B_MACHINE_ID,
            product_uuid=FIXTURE_HOST_B_PRODUCT_UUID,
            boot_id=FIXTURE_HOST_B_BOOT_ID,
        )
    return verify_release_completion.current_host_identity_from_values(
        machine_id=FIXTURE_HOST_A_MACHINE_ID,
        product_uuid=FIXTURE_HOST_A_PRODUCT_UUID,
        boot_id=FIXTURE_HOST_A_BOOT_ID,
    )


def fixture_current_host_summary(*, host_b: bool = False) -> dict[str, Any]:
    return {
        "system": "Linux",
        "machine": "x86_64",
        "linux": True,
        "nitro_nsm_device": True,
        "apparmor_sysfs": True,
        "skipped": False,
        "preflight_bound": True,
        "identity_recomputed": True,
        "identity": fixture_current_host_identity(host_b=host_b),
    }


def proxy_response_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x20" * 32))


def proxy_collector_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x21" * 32))


def alternate_proxy_collector_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x26" * 32))


def proxy_vendor_verifier_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x22" * 32))


def alternate_proxy_vendor_verifier_key_info() -> dict[str, Any]:
    return ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x27" * 32))


def sign_proxy_vendor_verifier_statement(
    document: dict[str, Any],
    verifier_key_info: dict[str, Any] | None = None,
) -> None:
    key_info = verifier_key_info or proxy_vendor_verifier_key_info()
    trusted_verifier = document["vendor_tee"]["trusted_verifier"]
    statement = trusted_verifier["statement"]
    statement["verifier_key_id"] = key_info["key_id"]
    trusted_verifier["signature"] = "ed25519:" + b64e(
        key_info["key"].sign(canonical_json(statement).encode("utf-8"))
    )


def sign_proxy_external_capture(
    document: dict[str, Any],
    collector_key_info: dict[str, Any] | None = None,
) -> None:
    key_info = collector_key_info or proxy_collector_key_info()
    external_capture = document["external_capture"]
    document["collector_signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_info["key_id"],
        "public_key_pem": key_info["public_key_pem"],
        "signature": "ed25519:"
        + b64e(key_info["key"].sign(canonical_json(external_capture).encode("utf-8"))),
    }


def resign_proxy_response_proof(
    document: dict[str, Any],
    *,
    verifier_key_info: dict[str, Any] | None = None,
    sync_attested_claims: bool = True,
) -> None:
    response_key = proxy_response_key_info()
    server_statement = document["server_statement"]
    server_statement_digest = sha256_prefixed_json(server_statement)
    document["external_capture"]["server_statement_sha256"] = server_statement_digest
    sign_proxy_external_capture(document)
    document["server_signature"] = {
        "algorithm": "Ed25519",
        "key_id": response_key["key_id"],
        "public_key_pem": response_key["public_key_pem"],
        "signature": "ed25519:"
        + b64e(response_key["key"].sign(canonical_json(server_statement).encode("utf-8"))),
    }

    vendor_tee = document["vendor_tee"]
    vendor_tee["quote_sha256"] = sha256_prefixed_json(vendor_tee["quote"])
    statement = vendor_tee["trusted_verifier"]["statement"]
    statement.pop("proof_evidence_sha256", None)
    statement.update(
        {
            "tee_platform": vendor_tee["platform"],
            "quote_provider": vendor_tee["provider"],
            "vendor_quote_sha256": vendor_tee["quote_sha256"],
            "server_statement_sha256": server_statement_digest,
            "response_signing_key_id": response_key["key_id"],
        }
    )
    if sync_attested_claims:
        response = server_statement["response"]
        tls_channel_binding = server_statement["tls_channel_binding"]
        server_instance = server_statement["server_instance"]
        statement["attested_claims"] = {
            "server_statement_sha256": server_statement_digest,
            "server_statement_api_version": server_statement["apiVersion"],
            "issued_at_unix": server_statement["issued_at_unix"],
            "client_nonce_sha256": sha256_prefixed_bytes(b64d(server_statement["client_nonce"])),
            "client_request_digest": server_statement["client_request_digest"],
            "request_digest": server_statement["request_digest"],
            "operation_digest": server_statement["operation_digest"],
            "principal_id": server_statement["principal_id"],
            "route_id": server_statement["route_id"],
            "release_authority": server_statement["release_authority"],
            "control_plane_authorization_receipt_sha256": sha256_prefixed_json(
                server_statement["control_plane_authorization_receipt"]
            ),
            "upstream_response": server_statement["upstream_response"],
            "response_status": response["status"],
            "selected_response_headers_digest": response["selected_headers_digest"],
            "response_body_digest": response["body_digest"],
            "policy_digest": server_statement["policy_digest"],
            "runtime_manifest_digest": server_statement["runtime_manifest_digest"],
            "data_plane_binary_digest": server_statement["data_plane_binary_digest"],
            "release_digest": server_statement["release_digest"],
            "server_instance_id": server_instance["id"],
            "server_instance_identity_digest": server_instance["identity_digest"],
            "tls_channel_binding_type": tls_channel_binding["type"],
            "tls_channel_binding_sha256": sha256_prefixed_json(tls_channel_binding),
            "response_signing_key_id": response_key["key_id"],
        }
    sign_proxy_vendor_verifier_statement(document, verifier_key_info)


def proxy_response_proof(
    provenance_digest: str,
    *,
    now: int | None = None,
    shared_quotas: list[dict[str, Any]] | None = None,
    dispatch_quotas: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    captured_at = int(time.time()) if now is None else now
    body = b'{"ok":true,"source":"production-proxy"}'
    body_digest = sha256_prefixed_bytes(body)
    client_request_digest = PROXY_CLIENT_REQUEST_DIGEST
    selected_headers = {
        "content-length": str(len(body)),
        "content-type": "application/json",
        "x-serverware-client-request-digest": client_request_digest,
        "x-serverware-policy-hash": POLICY_DIGEST,
        "x-serverware-request-digest": PROXY_REQUEST_DIGEST,
        "x-serverware-operation-digest": PROXY_OPERATION_DIGEST,
        "x-serverware-response-body-sha256": body_digest,
    }
    response = {
        "status": 200,
        "selected_headers": selected_headers,
        "selected_headers_digest": sha256_prefixed_json(selected_headers),
        "body_digest": body_digest,
    }
    upstream_response = {
        "status": 200,
        "selected_raw_policy_headers_b64": {
            "content-encoding": [],
            "content-length": [b64e(str(len(body)).encode("ascii"))],
            "content-type": [b64e(b"application/json")],
        },
        "body_digest": body_digest,
    }
    upstream_response["canonical_digest"] = sha256_prefixed_json(upstream_response)
    tls_channel_binding = {
        "type": "tls-exporter",
        "value": PROXY_TLS_CHANNEL_BINDING,
    }
    attempt_id = digest("a")
    authorization_binding = {
        "attempt_id": attempt_id,
        "flow_id": attempt_id,
        "principal_id": PROXY_PRINCIPAL_ID,
        "route_id": "demo.echo",
        "credential_id": "credential:response-proof",
        "credential_version": 7,
        "policy_hash": POLICY_DIGEST,
        "request_digest": PROXY_REQUEST_DIGEST,
        "operation_digest": PROXY_OPERATION_DIGEST,
        "operation_context": PROXY_OPERATION_CONTEXT,
        "require_jit_grant": True,
        "shared_quotas": clone_document(shared_quotas or []),
    }
    release_authority = {
        "authority_mode": "atomic",
        "grant_id": "grant:response-proof",
        "approval_id": "approval:response-proof",
        "credential_ref": "credential:response-proof",
        "credential_version": 7,
        "request_digest": PROXY_REQUEST_DIGEST,
        "operation_digest": PROXY_OPERATION_DIGEST,
        "attempt_id": attempt_id,
        "consumption_identity_digest": sha256_prefixed_json(
            authorization_binding
        ),
        "authorization_state_at_upstream_dispatch": "dispatching",
        "authorization_state_observed_at_epoch_ms": captured_at * 1000,
        "reservation_expires_at_epoch_ms": captured_at * 1000 + 300_000,
        "dispatch_expires_at_epoch_ms": captured_at * 1000 + 300_000,
    }
    document = {
        "apiVersion": "serverware.proxyResponseProof/v3",
        "kind": "ServerwareProxyResponseProof",
        "external_capture": {
            "apiVersion": "serverware.proxyResponseCapture/v2",
            "environment": "production",
            "collection_mode": "external-client-capture",
            "captured_at_unix": captured_at,
            "client_nonce": PROXY_CLIENT_NONCE,
            "client_request_digest": client_request_digest,
            "principal_id": PROXY_PRINCIPAL_ID,
            "route_id": "demo.echo",
            "request_digest": PROXY_REQUEST_DIGEST,
            "operation_digest": PROXY_OPERATION_DIGEST,
            "release_authority": json.loads(json.dumps(release_authority)),
            "control_plane_authorization_receipt": {},
            "upstream_response": json.loads(json.dumps(upstream_response)),
            "response": json.loads(json.dumps(response)),
            "tls_channel_binding": json.loads(json.dumps(tls_channel_binding)),
            "tls_peer": {
                "spiffe_id": PROXY_SERVER_INSTANCE_ID,
                "leaf_certificate_sha256": PROXY_TLS_PEER_LEAF_CERTIFICATE_DIGEST,
            },
            "server_statement_sha256": digest("0"),
        },
        "collector_signature": {},
        "server_statement": {
            "apiVersion": "serverware.proxyResponseStatement/v2",
            "issued_at_unix": captured_at,
            "client_nonce": PROXY_CLIENT_NONCE,
            "client_request_digest": client_request_digest,
            "principal_id": PROXY_PRINCIPAL_ID,
            "route_id": "demo.echo",
            "request_digest": PROXY_REQUEST_DIGEST,
            "operation_digest": PROXY_OPERATION_DIGEST,
            "release_authority": json.loads(json.dumps(release_authority)),
            "control_plane_authorization_receipt": {},
            "upstream_response": json.loads(json.dumps(upstream_response)),
            "response": json.loads(json.dumps(response)),
            "tls_channel_binding": json.loads(json.dumps(tls_channel_binding)),
            "policy_digest": POLICY_DIGEST,
            "runtime_manifest_digest": digest("7"),
            "data_plane_binary_digest": digest("9"),
            "release_digest": provenance_digest,
            "server_instance": {
                "id": PROXY_SERVER_INSTANCE_ID,
                "identity_digest": sha256_prefixed_bytes(PROXY_SERVER_INSTANCE_ID.encode("utf-8")),
            },
        },
        "server_signature": {},
        "vendor_tee": {
            "platform": "aws-nitro",
            "provider": "aws-nitro-enclaves",
            "quote": {
                "format": "aws-nitro-attestation-document",
                "body_b64": b64e(b"test-only opaque vendor quote bytes " * 4),
            },
            "trusted_verifier": {
                "apiVersion": "serverware.vendorTeeVerification/v1",
                "kind": "ServerwareVendorTeeVerification",
                "statement": {
                    "outcome": "verified",
                    "environment": "production",
                    "trust_basis": "vendor-root-certificate-chain",
                    "vendor_quote_verified": True,
                    "certificate_chain_verified": True,
                    "revocation_checked": True,
                    "debug": False,
                    "verified_at_unix": captured_at,
                    "expires_at_unix": captured_at + 300,
                },
            },
        },
    }
    receipt = control_plane_authorization_receipt(
        document,
        quotas=dispatch_quotas,
    )
    document["external_capture"]["control_plane_authorization_receipt"] = clone_document(
        receipt
    )
    document["server_statement"]["control_plane_authorization_receipt"] = receipt
    resign_proxy_response_proof(document)
    return document


def streaming_attested_claims(
    document: dict[str, Any],
    statement_digest: str,
    response_signing_key_id: str,
) -> dict[str, Any]:
    statement = document["streaming_response_statement"]
    upstream = statement["upstream_response"]
    released = statement["released_response"]
    tls_channel_binding = statement["tls_channel_binding"]
    server_instance = statement["server_instance"]
    authorization_validation = statement["authorization_binding_validation"]
    return {
        "streaming_response_statement_api_version": statement["apiVersion"],
        "streaming_response_statement_sha256": statement_digest,
        "issued_at_unix": statement["issued_at_unix"],
        "client_nonce_sha256": sha256_prefixed_bytes(b64d(statement["client_nonce"])),
        "client_request_digest": statement["client_request_digest"],
        "principal_id": statement["principal_id"],
        "route_id": statement["route_id"],
        "request_digest": statement["request_digest"],
        "operation_digest": statement["operation_digest"],
        "release_authority": statement["release_authority"],
        "authorization_binding_digest": authorization_validation["binding_digest"],
        "control_plane_authorization_receipt_sha256": statement[
            "control_plane_authorization_receipt_sha256"
        ],
        "upstream_status": upstream["status"],
        "upstream_selected_raw_policy_headers_digest": sha256_prefixed_json(
            upstream["selected_raw_policy_headers_b64"]
        ),
        "upstream_body_digest": upstream["body_digest"],
        "upstream_body_bytes": upstream["body_bytes"],
        "upstream_canonical_digest": upstream["canonical_digest"],
        "released_response_status": released["status"],
        "released_response_content_type": released["content_type"],
        "selected_response_wire_headers_digest": released[
            "selected_wire_headers_digest"
        ],
        "released_response_body_digest": released["body_digest"],
        "released_response_body_bytes": released["body_bytes"],
        "response_framing": released["framing"],
        "response_completion": released["completion"],
        "response_trailer_names": released["trailer_names"],
        "policy_digest": statement["policy_digest"],
        "runtime_manifest_digest": statement["runtime_manifest_digest"],
        "data_plane_binary_digest": statement["data_plane_binary_digest"],
        "release_digest": statement["release_digest"],
        "server_instance_id": server_instance["id"],
        "server_instance_identity_digest": server_instance["identity_digest"],
        "tls_channel_binding_type": tls_channel_binding["type"],
        "tls_exporter_label": tls_channel_binding["exporter_label"],
        "tls_channel_binding_sha256": sha256_prefixed_json(tls_channel_binding),
        "response_signing_key_id": response_signing_key_id,
    }


def resign_streaming_response_proof(
    document: dict[str, Any],
    *,
    verifier_key_info: dict[str, Any] | None = None,
    sync_attested_claims: bool = True,
) -> None:
    response_key = proxy_response_key_info()
    statement = document["streaming_response_statement"]
    statement_digest = sha256_prefixed_json(statement)
    document["server_signature"] = {
        "algorithm": "Ed25519",
        "key_id": response_key["key_id"],
        "public_key_pem": response_key["public_key_pem"],
        "signature": "ed25519:"
        + b64e(response_key["key"].sign(canonical_json(statement).encode("utf-8"))),
    }
    vendor_tee = document["vendor_tee"]
    vendor_tee["quote_sha256"] = sha256_prefixed_json(vendor_tee["quote"])
    verifier_statement = vendor_tee["trusted_verifier"]["statement"]
    verifier_statement.update(
        {
            "tee_platform": vendor_tee["platform"],
            "quote_provider": vendor_tee["provider"],
            "vendor_quote_sha256": vendor_tee["quote_sha256"],
            "streaming_response_statement_sha256": statement_digest,
            "response_signing_key_id": response_key["key_id"],
        }
    )
    if sync_attested_claims:
        verifier_statement["attested_claims"] = streaming_attested_claims(
            document,
            statement_digest,
            response_key["key_id"],
        )
    sign_proxy_vendor_verifier_statement(document, verifier_key_info)
    runtime_proof = {
        "apiVersion": "serverware.streamingResponseRuntimeProof/v1",
        "kind": "ServerwareStreamingResponseRuntimeProof",
        "streaming_response_statement": statement,
        "streaming_response_statement_sha256": statement_digest,
        "server_signature": document["server_signature"],
        "vendor_tee": vendor_tee,
    }
    document["external_capture"][
        "streaming_response_statement_sha256"
    ] = statement_digest
    document["external_capture"]["runtime_proof_sha256"] = sha256_prefixed_json(
        runtime_proof
    )
    sign_proxy_external_capture(document)


def streaming_response_proof(
    provenance_digest: str,
    *,
    body: bytes | None = None,
    now: int | None = None,
) -> tuple[dict[str, Any], bytes]:
    captured_at = int(time.time()) if now is None else now
    released_body = body or b'{"ok":true,"source":"production-stream"}'
    released_body_digest = sha256_prefixed_bytes(released_body)
    buffered = proxy_response_proof(provenance_digest, now=captured_at)
    release_authority = clone_document(buffered["server_statement"]["release_authority"])
    receipt = clone_document(buffered["server_statement"]["control_plane_authorization_receipt"])
    raw_headers = clone_document(
        buffered["server_statement"]["upstream_response"][
            "selected_raw_policy_headers_b64"
        ]
    )
    raw_headers["content-length"] = [b64e(str(len(released_body)).encode("ascii"))]
    upstream_response = {
        "status": 200,
        "selected_raw_policy_headers_b64": raw_headers,
        "body_digest": released_body_digest,
        "body_bytes": len(released_body),
    }
    upstream_response["canonical_digest"] = sha256_prefixed_json(upstream_response)
    content_type = "application/json"
    wire_headers = {
        "connection": "close",
        "content-type": content_type,
        "trailer": "X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256",
        "transfer-encoding": "chunked",
    }
    released_response = {
        "status": 200,
        "content_type": content_type,
        "selected_wire_headers": wire_headers,
        "selected_wire_headers_digest": sha256_prefixed_json(wire_headers),
        "body_digest": released_body_digest,
        "body_bytes": len(released_body),
        "framing": "http1.1-chunked-trailers",
        "completion": "normal-eof",
        "trailer_names": [
            "X-Serverware-Stream-Proof-B64",
            "X-Serverware-Stream-Proof-SHA256",
        ],
    }
    binding_commitment = {
        "attempt_id": release_authority["attempt_id"],
        "flow_id": release_authority["attempt_id"],
        "principal_id": PROXY_PRINCIPAL_ID,
        "route_id": "demo.echo",
        "credential_id": release_authority["credential_ref"],
        "credential_version": release_authority["credential_version"],
        "policy_hash": POLICY_DIGEST,
        "request_digest": PROXY_REQUEST_DIGEST,
        "operation_digest": PROXY_OPERATION_DIGEST,
        "operation_context_digest": PROXY_OPERATION_CONTEXT_DIGEST,
        "require_jit_grant": True,
        "shared_quotas": [],
    }
    receipt_digest = sha256_prefixed_json(receipt)
    tls_channel_binding = {
        "type": "tls-exporter",
        "exporter_label": verify_release_completion.STREAMING_TLS_EXPORTER_LABEL,
        "value": PROXY_TLS_CHANNEL_BINDING,
    }
    statement = {
        "apiVersion": "serverware.streamingResponseStatement/v1",
        "issued_at_unix": captured_at,
        "client_nonce": PROXY_CLIENT_NONCE,
        "client_request_digest": PROXY_STREAM_CLIENT_REQUEST_DIGEST,
        "principal_id": PROXY_PRINCIPAL_ID,
        "route_id": "demo.echo",
        "request_digest": PROXY_REQUEST_DIGEST,
        "operation_digest": PROXY_OPERATION_DIGEST,
        "release_authority": clone_document(release_authority),
        "authorization_binding_validation": {
            "status": "validated",
            "binding_commitment": clone_document(binding_commitment),
            "binding_digest": release_authority["consumption_identity_digest"],
        },
        "control_plane_authorization_receipt": clone_document(receipt),
        "control_plane_authorization_receipt_sha256": receipt_digest,
        "upstream_response": clone_document(upstream_response),
        "released_response": clone_document(released_response),
        "policy_digest": POLICY_DIGEST,
        "runtime_manifest_digest": digest("7"),
        "data_plane_binary_digest": digest("9"),
        "release_digest": provenance_digest,
        "server_instance": {
            "id": PROXY_SERVER_INSTANCE_ID,
            "identity_digest": sha256_prefixed_bytes(
                PROXY_SERVER_INSTANCE_ID.encode("utf-8")
            ),
        },
        "tls_channel_binding": clone_document(tls_channel_binding),
    }
    verifier_statement = clone_document(
        buffered["vendor_tee"]["trusted_verifier"]["statement"]
    )
    verifier_statement.pop("server_statement_sha256", None)
    verifier_statement.pop("attested_claims", None)
    document = {
        "apiVersion": "serverware.streamingProxyResponseProof/v1",
        "kind": "ServerwareStreamingProxyResponseProof",
        "external_capture": {
            "apiVersion": "serverware.streamingProxyResponseCapture/v1",
            "environment": "production",
            "collection_mode": "strict-incremental-stream-capture",
            "classification": "verified-complete-stream",
            "captured_at_unix": captured_at,
            "client_nonce": PROXY_CLIENT_NONCE,
            "client_request_digest": PROXY_STREAM_CLIENT_REQUEST_DIGEST,
            "principal_id": PROXY_PRINCIPAL_ID,
            "route_id": "demo.echo",
            "request_digest": PROXY_REQUEST_DIGEST,
            "operation_digest": PROXY_OPERATION_DIGEST,
            "release_authority": clone_document(release_authority),
            "authorization_binding_commitment": clone_document(binding_commitment),
            "control_plane_authorization_receipt": clone_document(receipt),
            "control_plane_authorization_receipt_sha256": receipt_digest,
            "upstream_response": clone_document(upstream_response),
            "released_response": clone_document(released_response),
            "tls_channel_binding": clone_document(tls_channel_binding),
            "tls_peer": {
                "spiffe_id": PROXY_SERVER_INSTANCE_ID,
                "leaf_certificate_sha256": PROXY_TLS_PEER_LEAF_CERTIFICATE_DIGEST,
            },
            "streaming_response_statement_sha256": digest("0"),
            "runtime_proof_sha256": digest("0"),
        },
        "collector_signature": {},
        "streaming_response_statement": statement,
        "server_signature": {},
        "vendor_tee": {
            "platform": buffered["vendor_tee"]["platform"],
            "provider": buffered["vendor_tee"]["provider"],
            "quote_sha256": buffered["vendor_tee"]["quote_sha256"],
            "quote": clone_document(buffered["vendor_tee"]["quote"]),
            "trusted_verifier": {
                "apiVersion": "serverware.vendorTeeVerification/v1",
                "kind": "ServerwareVendorTeeVerification",
                "statement": verifier_statement,
                "signature": "",
            },
        },
    }
    resign_streaming_response_proof(document)
    return document, released_body


def resign_control_plane_authorization_receipt(
    document: dict[str, Any],
    key_info: dict[str, Any] | None = None,
) -> None:
    signer = key_info or control_plane_response_signing_key_info()
    response = document["response"]
    statement = json.loads(b64d(response["statement_b64"]).decode("utf-8"))
    response["response_signing_key_id"] = signer["key_id"]
    statement["response_signing_key_id"] = signer["key_id"]
    statement_bytes = canonical_json(statement).encode("utf-8")
    response["statement_b64"] = b64e(statement_bytes)
    response["statement_sha256"] = sha256_prefixed_bytes(statement_bytes)
    response["signature"] = "ed25519:" + b64e(
        signer["key"].sign(statement_bytes)
    )


def replace_control_plane_receipt_response_body(
    document: dict[str, Any],
    body: dict[str, Any],
    *,
    issued_at_ms: int | None = None,
    key_info: dict[str, Any] | None = None,
) -> None:
    response = document["response"]
    body_bytes = canonical_json(body).encode("utf-8")
    body_digest = sha256_prefixed_bytes(body_bytes)
    response["body_b64"] = b64e(body_bytes)
    response["body_sha256"] = body_digest
    statement = json.loads(b64d(response["statement_b64"]).decode("utf-8"))
    statement["body_sha256"] = body_digest
    if issued_at_ms is not None:
        statement["issued_at_ms"] = issued_at_ms
    statement_bytes = canonical_json(statement).encode("utf-8")
    response["statement_b64"] = b64e(statement_bytes)
    resign_control_plane_authorization_receipt(document, key_info)


def control_plane_authorization_receipt(
    proxy_proof: dict[str, Any],
    *,
    quotas: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    release_authority = proxy_proof["server_statement"]["release_authority"]
    observed_at_epoch_ms = release_authority[
        "authorization_state_observed_at_epoch_ms"
    ]
    request_body = {
        "apiVersion": "serverware.releaseAuthorizationDispatch/v1",
        "attemptId": release_authority["attempt_id"],
        "bindingDigest": release_authority["consumption_identity_digest"],
    }
    request_body_bytes = canonical_json(request_body).encode("utf-8")
    response_body = {
        "apiVersion": "serverware.releaseAuthorization/v1",
        "ok": True,
        "authorized": True,
        "state": "dispatching",
        "reason": "dispatching",
        "attemptId": release_authority["attempt_id"],
        "bindingDigest": release_authority["consumption_identity_digest"],
        "idempotentReplay": False,
        "grantId": release_authority["grant_id"],
        "approvalRequestId": release_authority["approval_id"],
        "reservationExpiresAtEpochMs": release_authority[
            "reservation_expires_at_epoch_ms"
        ],
        "dispatchStartedAtEpochMs": observed_at_epoch_ms,
        "dispatchExpiresAtEpochMs": release_authority[
            "dispatch_expires_at_epoch_ms"
        ],
        "completionOutcome": None,
        "retryAfterSeconds": 0,
        "quotas": clone_document(quotas or []),
        "store": {"backend": "postgres", "ha": True},
    }
    response_body_bytes = canonical_json(response_body).encode("utf-8")
    response_body_digest = sha256_prefixed_bytes(response_body_bytes)
    nonce = b64e(b"c" * 32)
    signer = control_plane_response_signing_key_info()
    response_statement = {
        "version": verify_release_completion.CONTROL_PLANE_RESPONSE_SIGNATURE_API_VERSION,
        "issued_at_ms": observed_at_epoch_ms,
        "request": {
            "method": "POST",
            "path": verify_release_completion.CONTROL_PLANE_DISPATCH_PATH,
            "query_sha256": sha256_prefixed_bytes(b""),
        },
        "status_code": 200,
        "body_sha256": response_body_digest,
        "nonce": nonce,
        "response_signing_key_id": signer["key_id"],
        "context": {
            "runtime_manifest_digest": proxy_proof["server_statement"][
                "runtime_manifest_digest"
            ],
            "policy_bundle_digest": POLICY_DIGEST,
            "provenance_digest": proxy_proof["server_statement"]["release_digest"],
            "image_signatures_digest": IMAGE_SIGNATURES_DIGEST,
            "source_tree_digest": SOURCE_TREE_DIGEST,
        },
    }
    response_statement_bytes = canonical_json(response_statement).encode("utf-8")
    document = {
        "apiVersion": (
            verify_release_completion.CONTROL_PLANE_AUTHORIZATION_RECEIPT_API_VERSION
        ),
        "kind": "ControlPlaneAuthorizationReceipt",
        "principal_id": proxy_proof["server_statement"]["principal_id"],
        "route_id": proxy_proof["server_statement"]["route_id"],
        "release_authority": clone_document(release_authority),
        "request": {
            "method": "POST",
            "path": verify_release_completion.CONTROL_PLANE_DISPATCH_PATH,
            "query": "",
            "nonce": nonce,
            "body_b64": b64e(request_body_bytes),
            "body_sha256": sha256_prefixed_bytes(request_body_bytes),
        },
        "response": {
            "status": 200,
            "body_b64": b64e(response_body_bytes),
            "body_sha256": response_body_digest,
            "response_signing_key_id": signer["key_id"],
            "statement_b64": b64e(response_statement_bytes),
            "statement_sha256": sha256_prefixed_bytes(response_statement_bytes),
            "signature": "",
        },
    }
    resign_control_plane_authorization_receipt(document)
    return document


def clone_document(value: Any) -> Any:
    return json.loads(json.dumps(value))


def replace_embedded_control_plane_receipt(
    proxy_proof: dict[str, Any],
    receipt: dict[str, Any],
) -> None:
    proxy_proof["external_capture"]["control_plane_authorization_receipt"] = clone_document(
        receipt
    )
    proxy_proof["server_statement"]["control_plane_authorization_receipt"] = clone_document(
        receipt
    )
    resign_proxy_response_proof(proxy_proof)


def benchmark_document(*, p99_ms: float = 9.0) -> dict[str, Any]:
    return {
        "candidate": "rust-decision-gate",
        "requests": 1000,
        "warmup": 100,
        "p50_ms": 1.0,
        "p95_ms": 5.0,
        "p99_ms": p99_ms,
        "data_plane_binary_digest": digest("9"),
        "policy_hash": POLICY_DIGEST,
        "runtime_manifest_digest": digest("7"),
        "attestation_nonce_before": "benchmark-nonce-before",
        "attestation_nonce_after": "benchmark-nonce-after",
    }


def production_image_refs(control_digest: str = digest("6"), gate_digest: str = digest("7")) -> list[str]:
    return [
        "registry.prod.serverware.dev/serverware/control@" + control_digest,
        "registry.prod.serverware.dev/serverware/decision-gate@" + gate_digest,
    ]


def production_images_env_value(control_digest: str = digest("6"), gate_digest: str = digest("7")) -> str:
    return ",".join(production_image_refs(control_digest, gate_digest))


def write_production_env_files(
    tmp: Path,
    *,
    readiness_value: str | None = None,
    images_value: str | None = None,
    proxy_proof_contract: str = "buffered-v3",
    proxy_client_request_digest: str = PROXY_CLIENT_REQUEST_DIGEST,
    proxy_stream_body: Path | None = None,
    proxy_max_stream_bytes: int | None = None,
) -> None:
    selected_images_value = images_value or production_images_env_value()
    selected_readiness_value = readiness_value or selected_images_value
    executable_digest_manifest = canonical_json(fixture_executable_digest_manifest())
    policy_key_path = tmp / "policy-signing.pub.pem"
    activation_key_path = tmp / "policy-activation-verification.pub.pem"
    reproducible_key_path = tmp / "reproducible-build-verification.pub.pem"
    policy_key_id = (
        verify_release_completion.release_public_key_id(
            policy_key_path.read_text(encoding="ascii")
        )
        if policy_key_path.is_file()
        else release_key_info()["key_id"]
    )
    activation_key_id = (
        verify_release_completion.release_public_key_id(
            activation_key_path.read_text(encoding="ascii")
        )
        if activation_key_path.is_file()
        else policy_activation_key_info()["key_id"]
    )
    reproducible_key_id = (
        verify_release_completion.release_public_key_id(
            reproducible_key_path.read_text(encoding="ascii")
        )
        if reproducible_key_path.is_file()
        else reproducible_build_key_info()["key_id"]
    )
    helper_dir = tmp.resolve() / "attestation-helpers"
    helper_dir.mkdir(mode=0o755, exist_ok=True)
    production_python = tmp.resolve() / PINNED_EXECUTABLE_NAMES[
        production_host_preflight_module.PRODUCTION_PYTHON_EXECUTABLE_SETTING
    ]
    production_docker = tmp.resolve() / PINNED_EXECUTABLE_NAMES[
        production_host_preflight_module.PRODUCTION_DOCKER_EXECUTABLE_SETTING
    ]
    production_compose_plugin = tmp.resolve() / "production-docker-compose"
    for setting, name in PINNED_EXECUTABLE_NAMES.items():
        executable = (
            production_python
            if setting == production_host_preflight_module.PRODUCTION_PYTHON_EXECUTABLE_SETTING
            else production_docker
            if setting == production_host_preflight_module.PRODUCTION_DOCKER_EXECUTABLE_SETTING
            else helper_dir / name
        )
        executable.write_bytes(fixture_executable_bytes(setting))
        executable.chmod(0o755)
    production_compose_plugin.write_bytes(b"#!/bin/sh\n# pinned Compose fixture\nexit 0\n")
    production_compose_plugin.chmod(0o755)
    (tmp / "production-images.env").write_text(
        f"SERVERWARE_PRODUCTION_IMAGES={selected_images_value}\n",
        encoding="utf-8",
    )
    executable_commands = "".join(
        f"{setting}=/opt/serverware/bin/{name}\n"
        for setting, name in PINNED_EXECUTABLE_NAMES.items()
        if setting
        not in {
            production_host_preflight_module.PRODUCTION_PYTHON_EXECUTABLE_SETTING,
            production_host_preflight_module.PRODUCTION_DOCKER_EXECUTABLE_SETTING,
        }
    )
    stream_settings = ""
    if proxy_proof_contract == "streaming-v1":
        if proxy_stream_body is None or proxy_max_stream_bytes is None:
            raise AssertionError("streaming fixture env requires a body path and byte limit")
        stream_settings = (
            f"{verify_release_completion.PROXY_STREAM_BODY_ENV_KEY}={proxy_stream_body}\n"
            f"{verify_release_completion.PROXY_STREAM_MAX_BYTES_ENV_KEY}={proxy_max_stream_bytes}\n"
            f"{verify_release_completion.PROXY_STREAM_OPERATION_CONTEXT_DIGEST_ENV_KEY}="
            f"{PROXY_OPERATION_CONTEXT_DIGEST}\n"
        )
    (tmp / "production.env").write_text(
        f"SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST={digest('9')}\n"
        f"SERVERWARE_DATA_PLANE_INSTANCE_ID={PROXY_SERVER_INSTANCE_ID}\n"
        f"{verify_release_completion.PROXY_PRINCIPAL_ENV_KEY}={PROXY_PRINCIPAL_ID}\n"
        f"SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID={proxy_collector_key_info()['key_id']}\n"
        f"SERVERWARE_PROXY_PROOF_VERIFIER_KEY_ID={proxy_vendor_verifier_key_info()['key_id']}\n"
        f"SERVERWARE_PROXY_EXPECTED_CLIENT_REQUEST_DIGEST={proxy_client_request_digest}\n"
        f"SERVERWARE_PROXY_EXPECTED_REQUEST_DIGEST={PROXY_REQUEST_DIGEST}\n"
        f"SERVERWARE_PROXY_EXPECTED_OPERATION_DIGEST={PROXY_OPERATION_DIGEST}\n"
        f"SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS=300\n"
        f"{verify_release_completion.PROXY_PROOF_CONTRACT_ENV_KEY}={proxy_proof_contract}\n"
        f"{stream_settings}"
        f"SERVERWARE_COMPLETION_P99_LIMIT_MS=20.0\n"
        f"{run_production_readiness.FINAL_LAUNCHER_CONTRACT_ENV}={run_production_readiness.FINAL_LAUNCHER_CONTRACT}\n"
        f"SERVERWARE_ATTESTATION_HELPER_DIR={helper_dir}\n"
        f"SERVERWARE_PRODUCTION_PYTHON_EXECUTABLE={production_python}\n"
        f"SERVERWARE_DOCKER_EXECUTABLE={production_docker}\n"
        f"{run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV}={production_compose_plugin}\n"
        f"{run_production_readiness.DOCKER_COMPOSE_PLUGIN_SHA256_ENV}={sha256_file(production_compose_plugin)}\n"
        f"{run_production_readiness.DOCKER_UNIX_SOCKET_ENV}=/run/docker.sock\n"
        f"{run_production_readiness.DOCKER_DAEMON_ID_ENV}=fixture-daemon-id\n"
        f"{run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV}=serverware-production\n"
        f"{run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV}={sha256_file(ROOT / 'scripts' / 'production_host_preflight.py')}\n"
        f"{run_production_readiness.VERIFY_PRODUCTION_READINESS_SCRIPT_SHA256_ENV}={sha256_file(ROOT / 'scripts' / 'verify_production_readiness.py')}\n"
        f"{run_production_readiness.VERIFY_RELEASE_COMPLETION_SCRIPT_SHA256_ENV}={sha256_file(ROOT / 'scripts' / 'verify_release_completion.py')}\n"
        f"{run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_PRIVATE_KEY_ENV}={tmp / 'preflight-signing.key.pem'}\n"
        f"{run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV}={tmp / 'preflight-signing.pub.pem'}\n"
        f"{run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV}={preflight_signing_key_info()['key_id']}\n"
        f"{run_production_readiness.PRODUCTION_HOST_PREFLIGHT_MAX_AGE_ENV}=300\n"
        f"{executable_commands}"
        f"{production_host_preflight_module.ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV}='{executable_digest_manifest}'\n"
        f"{verify_release_completion.RELEASE_PROVENANCE_TRUST_ROOT_ENV_KEY}={tmp / 'release-signing.pub.pem'}\n"
        f"{verify_release_completion.SIGSTORE_TRUST_ROOT_ENV_KEY}={tmp / 'sigstore-signing.pub.pem'}\n"
        f"{verify_release_completion.REKOR_TRUST_ROOT_ENV_KEY}={tmp / 'rekor.pub.pem'}\n"
        f"{verify_release_completion.EXTERNAL_CHECKPOINT_TRUST_ROOT_ENV_KEY}={tmp / 'external-checkpoint.pub.pem'}\n"
        f"{verify_release_completion.EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY}=managed-prod-log\n"
        f"{verify_release_completion.CONTROL_PLANE_RESPONSE_SIGNING_KEY_ENV_KEY}={tmp / 'control-plane-response-signing.pub.pem'}\n"
        f"{verify_release_completion.CONTROL_PLANE_RESPONSE_SIGNING_KEY_ID_ENV_KEY}={control_plane_response_signing_key_info()['key_id']}\n"
        f"{run_production_readiness.POLICY_TRUST_ROOT_ENV}={tmp / 'policy-signing.pub.pem'}\n"
        f"{run_production_readiness.POLICY_TRUST_ROOT_ID_ENV}={policy_key_id}\n"
        f"{run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV}={tmp / 'policy-activation-verification.pub.pem'}\n"
        f"{run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV}={activation_key_id}\n"
        f"{run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV}={tmp / 'reproducible-build-verification.pub.pem'}\n"
        f"{run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV}={reproducible_key_id}\n"
        f"SERVERWARE_PRODUCTION_IMAGES={selected_readiness_value}\n",
        encoding="utf-8",
    )
    (tmp / "production.env").chmod(0o600)
    write_production_config_files(tmp)


def write_final_production_env_file(
    tmp: Path,
    *,
    overrides: dict[str, str] | None = None,
    omitted: set[str] | None = None,
) -> dict[str, str]:
    write_production_env_files(tmp)
    configured = run_production_readiness.load_env_file(tmp / "production.env")
    configured.update(
        {
            verify_release_completion.FINAL_MODE_ENV_KEY: "final",
            verify_release_completion.FINAL_HARDWARE_ASSURANCE_ENV_KEY: str(tmp / "hardware-assurance.json"),
            verify_release_completion.FINAL_HARDWARE_TRUST_ROOT_ENV_KEY: str(
                tmp / "hardware-assurance-verifier.pub.pem"
            ),
            verify_release_completion.FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY: (
                hardware_verifier_key_info()["key_id"]
            ),
            verify_release_completion.FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY: HARDWARE_ASSURANCE_CHALLENGE_NONCE,
            verify_release_completion.FINAL_CHALLENGE_RECEIPT_ENV_KEY: str(tmp / "final-challenge-receipt.json"),
            verify_release_completion.FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ENV_KEY: str(
                tmp / "final-challenge-authority.pub.pem"
            ),
            verify_release_completion.FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY: (
                final_challenge_authority_key_info()["key_id"]
            ),
            verify_release_completion.FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY: (
                "fixture-off-host-challenge-authority"
            ),
        }
    )
    configured.update(overrides or {})
    for name in omitted or set():
        configured.pop(name, None)
    (tmp / "production.env").write_text(
        "".join(f"{name}={shlex.quote(value)}\n" for name, value in configured.items()),
        encoding="utf-8",
    )
    (tmp / "production.env").chmod(0o600)
    write_production_config_files(tmp)
    return configured


def final_env_binding_summaries(
    tmp: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    configured = run_production_readiness.load_env_file(tmp / "production.env")
    refs = production_image_refs()
    environment = {
        "production_readiness_env_sha256": sha256_file(tmp / "production.env"),
        "production_images_env_sha256": sha256_file(tmp / "production-images.env"),
    }
    readiness_summary = {
        "production_images": refs,
        "production_image_digests": [ref.rsplit("@", 1)[1] for ref in refs],
        "environment": environment,
    }
    preflight_summary = {
        "production_image_refs": refs,
        "production_env_keys": sorted(configured),
        "benchmark_binary_digest": digest("9"),
        "production_compose_renderer": {
            "path": configured[
                run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV
            ],
            "sha256": configured[
                run_production_readiness.DOCKER_COMPOSE_PLUGIN_SHA256_ENV
            ],
        },
        "production_compose_project_name": configured[
            run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV
        ],
        "release_security_evidence": {
            "trust_roots": {
                "policy_identity": {
                    "path": str(tmp / "policy-signing.pub.pem"),
                    "sha256": sha256_file(tmp / "policy-signing.pub.pem"),
                    "spki_sha256": configured[
                        run_production_readiness.POLICY_TRUST_ROOT_ID_ENV
                    ],
                },
                "policy_activation": {
                    "path": str(tmp / "policy-activation-verification.pub.pem"),
                    "sha256": sha256_file(
                        tmp / "policy-activation-verification.pub.pem"
                    ),
                    "spki_sha256": configured[
                        run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV
                    ],
                },
                "reproducible_build": {
                    "path": str(tmp / "reproducible-build-verification.pub.pem"),
                    "sha256": sha256_file(
                        tmp / "reproducible-build-verification.pub.pem"
                    ),
                    "spki_sha256": configured[
                        run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV
                    ],
                },
            }
        },
        "runtime_trust_materials": {
            "proof_collector_key_id": proxy_collector_key_info()["key_id"],
            "proof_verifier_key_id": proxy_vendor_verifier_key_info()["key_id"],
            "executable_digests": fixture_executable_digest_manifest(),
            "python_script_digests": {
                setting: configured[setting]
                for setting in run_production_readiness.PINNED_PYTHON_SCRIPTS.values()
            },
        },
        **environment,
    }
    config_summary = {"environment": environment}
    return readiness_summary, preflight_summary, config_summary


def test_final_production_env_binding() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        (tmp / "release-signing.pub.pem").write_text(release_key_info()["public_key_pem"], encoding="ascii")
        (tmp / "sigstore-signing.pub.pem").write_text(
            sigstore_signing_key_info()["public_key_pem"],
            encoding="ascii",
        )
        (tmp / "rekor.pub.pem").write_text(rekor_key_info()["public_key_pem"], encoding="ascii")
        (tmp / "external-checkpoint.pub.pem").write_text(
            external_receipt_key_info()["public_key_pem"],
            encoding="ascii",
        )
        (tmp / "hardware-assurance-verifier.pub.pem").write_text(
            hardware_verifier_key_info()["public_key_pem"],
            encoding="ascii",
        )
        (tmp / "final-challenge-authority.pub.pem").write_text(
            final_challenge_authority_key_info()["public_key_pem"],
            encoding="ascii",
        )
        (tmp / "control-plane-response-signing.pub.pem").write_text(
            control_plane_response_signing_key_info()["public_key_pem"],
            encoding="ascii",
        )
        (tmp / "preflight-signing.pub.pem").write_text(
            preflight_signing_key_info()["public_key_pem"],
            encoding="ascii",
        )
        (tmp / "policy-signing.pub.pem").write_text(
            release_key_info()["public_key_pem"], encoding="ascii"
        )
        (tmp / "policy-activation-verification.pub.pem").write_text(
            policy_activation_key_info()["public_key_pem"], encoding="ascii"
        )
        (tmp / "reproducible-build-verification.pub.pem").write_text(
            reproducible_build_key_info()["public_key_pem"], encoding="ascii"
        )

        configured = write_final_production_env_file(tmp)
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        recorded_summaries = (readiness_summary, preflight_summary, config_summary)
        paths = {
            "production_readiness_env": tmp / "production.env",
            "production_images_env": tmp / "production-images.env",
        }
        final_input_names = (
            verify_release_completion.FINAL_HARDWARE_ASSURANCE_ENV_KEY,
            verify_release_completion.FINAL_HARDWARE_TRUST_ROOT_ENV_KEY,
            verify_release_completion.FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY,
            verify_release_completion.FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY,
            verify_release_completion.FINAL_HARDWARE_CHALLENGE_DIGEST_ENV_KEY,
            verify_release_completion.FINAL_CHALLENGE_RECEIPT_ENV_KEY,
            verify_release_completion.FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ENV_KEY,
            verify_release_completion.FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY,
            verify_release_completion.FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY,
        )
        release_trust_input_names = (
            verify_release_completion.RELEASE_PROVENANCE_TRUST_ROOT_ENV_KEY,
            verify_release_completion.SIGSTORE_TRUST_ROOT_ENV_KEY,
            verify_release_completion.REKOR_TRUST_ROOT_ENV_KEY,
            verify_release_completion.EXTERNAL_CHECKPOINT_TRUST_ROOT_ENV_KEY,
            verify_release_completion.EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY,
            verify_release_completion.CONTROL_PLANE_RESPONSE_SIGNING_KEY_ENV_KEY,
            verify_release_completion.CONTROL_PLANE_RESPONSE_SIGNING_KEY_ID_ENV_KEY,
            run_production_readiness.POLICY_TRUST_ROOT_ENV,
            run_production_readiness.POLICY_TRUST_ROOT_ID_ENV,
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV,
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV,
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
        )
        final_inputs = {name: configured.get(name) for name in final_input_names}
        release_trust_inputs = {name: configured.get(name) for name in release_trust_input_names}

        def verify_binding(
            selected: dict[str, str | None] | None = None,
            selected_release_trust: dict[str, str | None] | None = None,
            selected_proxy_digests: dict[str, str | None] | None = None,
            selected_launcher_trust: dict[str, str | None] | None = None,
            selected_proxy_max_age: int = 300,
            selected_p99_limit: float = 20.0,
            selected_docker_executable: str | None = None,
            selected_compose_plugin: str | None = None,
            selected_docker_socket: str | None = None,
            selected_daemon_id: str | None = None,
            remeasure_runtime: bool = False,
            snapshots_override: dict[
                str, verify_release_completion.FileSnapshot
            ]
            | None = None,
        ) -> dict[str, Any]:
            snapshot_registry = verify_release_completion.InputSnapshots()
            snapshot_paths = {
                "production_readiness_env": tmp / "production.env",
                "production_images_env": tmp / "production-images.env",
                "release_provenance_trusted_public_key": tmp / "release-signing.pub.pem",
                "sigstore_trusted_public_key": tmp / "sigstore-signing.pub.pem",
                "rekor_trusted_public_key": tmp / "rekor.pub.pem",
                "external_checkpoint_trusted_public_key": tmp / "external-checkpoint.pub.pem",
                "hardware_assurance_trusted_public_key": tmp / "hardware-assurance-verifier.pub.pem",
                "final_challenge_authority_public_key": tmp / "final-challenge-authority.pub.pem",
                "control_plane_response_signing_public_key": tmp / "control-plane-response-signing.pub.pem",
                "production_host_preflight_signing_public_key": tmp / "preflight-signing.pub.pem",
                "policy_trusted_public_key": tmp / "policy-signing.pub.pem",
                "policy_activation_trusted_public_key": tmp
                / "policy-activation-verification.pub.pem",
                "reproducible_build_trusted_public_key": tmp
                / "reproducible-build-verification.pub.pem",
            }
            for key, path in snapshot_paths.items():
                snapshot_registry.capture(
                    key,
                    path,
                    key.replace("_", " "),
                    max_bytes=(
                        verify_release_completion.ENV_INPUT_MAX_BYTES
                        if key in {"production_readiness_env", "production_images_env"}
                        else verify_release_completion.FINAL_TRUST_ROOT_MAX_BYTES
                    ),
                )
            for key, snapshot in (snapshots_override or {}).items():
                snapshot_registry.by_key[key] = snapshot
            final_file_snapshots = snapshot_registry.by_key
            return verify_release_completion.verify_current_production_env_binding(
                paths,
                snapshot_registry,
                readiness_summary,
                preflight_summary,
                config_summary,
                verification_mode="final",
                release_trust_inputs=selected_release_trust or release_trust_inputs,
                final_inputs=selected or final_inputs,
                final_file_snapshots=final_file_snapshots,
                proxy_digest_inputs={
                    "proxy_client_request_digest": PROXY_CLIENT_REQUEST_DIGEST,
                    "proxy_request_digest": PROXY_REQUEST_DIGEST,
                    "proxy_operation_digest": PROXY_OPERATION_DIGEST,
                }
                if selected_proxy_digests is None
                else selected_proxy_digests,
                launcher_trust_inputs=selected_launcher_trust
                or {
                    run_production_readiness.LAUNCHER_TRUSTED_ENV_PATH_INPUT: str(
                        tmp / "production.env"
                    ),
                    run_production_readiness.LAUNCHER_TRUSTED_ENV_SHA256_INPUT: sha256_file(
                        tmp / "production.env"
                    ),
                },
                proxy_proof_max_age_seconds=selected_proxy_max_age,
                proxy_proof_contract="buffered-v3",
                p99_limit_ms=selected_p99_limit,
                docker_executable=selected_docker_executable
                or configured[
                    production_host_preflight_module.PRODUCTION_DOCKER_EXECUTABLE_SETTING
                ],
                docker_compose_plugin_executable=selected_compose_plugin
                or configured[run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV],
                docker_unix_socket=selected_docker_socket
                or configured[run_production_readiness.DOCKER_UNIX_SOCKET_ENV],
                docker_daemon_id=selected_daemon_id
                or configured[run_production_readiness.DOCKER_DAEMON_ID_ENV],
                preflight_signing_public_key=configured[
                    run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV
                ],
                preflight_signing_key_id=configured[
                    run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV
                ],
                preflight_max_age_seconds=300,
                remeasure_runtime_trust=remeasure_runtime,
            )

        def expect_failure(
            expected: str,
            selected: dict[str, str | None] | None = None,
            selected_release_trust: dict[str, str | None] | None = None,
        ) -> None:
            try:
                verify_binding(selected, selected_release_trust)
            except ValueError as exc:
                if expected not in str(exc):
                    raise AssertionError(f"final env binding failed for the wrong reason: {exc}") from exc
            else:
                raise AssertionError(f"final env binding accepted invalid input: {expected}")

        binding = verify_binding()
        if (
            binding.get("final_trust_roots_env_bound") is not True
            or binding.get("release_trust_roots_env_bound") is not True
            or binding.get("release_provenance_trusted_public_key_id") != release_key_info()["key_id"]
            or binding.get("sigstore_trusted_public_key_id") != sigstore_signing_key_info()["key_id"]
            or binding.get("rekor_trusted_public_key_id") != rekor_key_info()["key_id"]
            or binding.get("external_checkpoint_trusted_public_key_id")
            != external_receipt_key_info()["key_id"]
            or binding.get("control_plane_response_signing_public_key_id")
            != control_plane_response_signing_key_info()["key_id"]
            or binding.get("policy_trusted_public_key_id")
            != release_key_info()["key_id"]
            or binding.get("policy_activation_trusted_public_key_id")
            != policy_activation_key_info()["key_id"]
            or binding.get("reproducible_build_trusted_public_key_id")
            != reproducible_build_key_info()["key_id"]
            or binding.get("expected_proxy_principal_id") != PROXY_PRINCIPAL_ID
            or binding.get("hardware_assurance_trusted_public_key_id")
            != hardware_verifier_key_info()["key_id"]
            or binding.get("final_challenge_authority_public_key_id")
            != final_challenge_authority_key_info()["key_id"]
            or binding.get("hardware_assurance_expected_challenge_selector") != "nonce"
            or binding.get("SERVERWARE_PROXY_EXPECTED_CLIENT_REQUEST_DIGEST")
            != PROXY_CLIENT_REQUEST_DIGEST
            or binding.get("SERVERWARE_PROXY_EXPECTED_REQUEST_DIGEST")
            != PROXY_REQUEST_DIGEST
            or binding.get("SERVERWARE_PROXY_EXPECTED_OPERATION_DIGEST")
            != PROXY_OPERATION_DIGEST
            or (binding.get("launcher_trust") or {}).get("path")
            != str(tmp / "production.env")
            or binding.get("proxy_proof_max_age_seconds") != 300
            or binding.get("p99_limit_ms") != 20.0
            or binding.get("docker_executable")
            != configured[production_host_preflight_module.PRODUCTION_DOCKER_EXECUTABLE_SETTING]
            or binding.get("docker_compose_project_name")
            != "serverware-production"
        ):
            raise AssertionError(f"valid final env binding omitted trust-root identities: {binding}")

        if sys.platform.startswith("linux"):
            current_python = Path(sys.executable).resolve()
            current_python_digest = sha256_file(current_python)
            interpreter_binding = verify_release_completion.verify_current_interpreter_binding(
                {
                    run_production_readiness.PRODUCTION_PYTHON_EXECUTABLE_ENV: str(
                        current_python
                    )
                },
                {
                    run_production_readiness.PRODUCTION_PYTHON_EXECUTABLE_ENV: current_python_digest
                },
            )
            if interpreter_binding.get("matches_pinned_path_inode") is not True:
                raise AssertionError(
                    f"direct final verifier did not bind its executing interpreter: {interpreter_binding}"
                )
            copied_python = tmp / "same-bytes-different-python-inode"
            copied_python.write_bytes(current_python.read_bytes())
            copied_python.chmod(0o700)
            try:
                verify_release_completion.verify_current_interpreter_binding(
                    {
                        run_production_readiness.PRODUCTION_PYTHON_EXECUTABLE_ENV: str(
                            copied_python
                        )
                    },
                    {
                        run_production_readiness.PRODUCTION_PYTHON_EXECUTABLE_ENV: current_python_digest
                    },
                )
            except ValueError as exc:
                if "inode does not match" not in str(exc):
                    raise
            else:
                raise AssertionError(
                    "direct final verifier accepted matching bytes from a different interpreter inode"
                )

        for attribute in verify_release_completion.PROXY_EXPECTED_DIGEST_ENV_KEYS:
            mismatched = {
                "proxy_client_request_digest": PROXY_CLIENT_REQUEST_DIGEST,
                "proxy_request_digest": PROXY_REQUEST_DIGEST,
                "proxy_operation_digest": PROXY_OPERATION_DIGEST,
            }
            mismatched[attribute] = digest("f")
            try:
                verify_binding(selected_proxy_digests=mismatched)
            except ValueError as exc:
                if "does not exactly match" not in str(exc):
                    raise
            else:
                raise AssertionError(f"direct final verifier accepted mismatched {attribute}")

        for label, kwargs in (
            ("proxy proof max age", {"selected_proxy_max_age": 299}),
            ("p99 limit", {"selected_p99_limit": 19.0}),
            (
                "Docker executable",
                {"selected_docker_executable": str(tmp / "caller-selected-docker")},
            ),
            (
                "Compose plugin",
                {"selected_compose_plugin": str(tmp / "caller-selected-compose")},
            ),
            ("Docker socket", {"selected_docker_socket": "/run/caller.sock"}),
            ("Docker daemon", {"selected_daemon_id": "caller-daemon"}),
        ):
            try:
                verify_binding(**kwargs)
            except ValueError as exc:
                if "does not exactly match" not in str(exc):
                    raise
            else:
                raise AssertionError(f"direct final verifier accepted mismatched {label}")

        try:
            verify_binding(
                selected_launcher_trust={
                    run_production_readiness.LAUNCHER_TRUSTED_ENV_PATH_INPUT: str(
                        tmp / "alternate-production.env"
                    ),
                    run_production_readiness.LAUNCHER_TRUSTED_ENV_SHA256_INPUT: sha256_file(
                        tmp / "production.env"
                    ),
                }
            )
        except ValueError as exc:
            if "out-of-band launcher trust path" not in str(exc):
                raise
        else:
            raise AssertionError("direct final verifier accepted an alternate launcher env path")

        changed_helper = tmp.resolve() / "attestation-helpers" / "serverware-proof-client"
        original_helper = changed_helper.read_bytes()
        changed_helper.write_bytes(b"#!/bin/sh\nexit 9\n")
        changed_helper.chmod(0o755)
        try:
            verify_binding()
        except ValueError as exc:
            if "current pinned executable remeasurement failed" not in str(exc):
                raise
        else:
            raise AssertionError("direct final verifier accepted collector replacement after preflight")
        changed_helper.write_bytes(original_helper)
        changed_helper.chmod(0o755)

        changed_compose_plugin = Path(
            configured[run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV]
        )
        original_compose_plugin = changed_compose_plugin.read_bytes()
        changed_compose_plugin.write_bytes(b"replaced Compose plugin\n")
        changed_compose_plugin.chmod(0o755)
        try:
            verify_binding()
        except ValueError as exc:
            if "executable pin" not in str(exc):
                raise
        else:
            raise AssertionError("direct final verifier accepted Compose plugin replacement")
        changed_compose_plugin.write_bytes(original_compose_plugin)
        changed_compose_plugin.chmod(0o755)

        preflight_runtime = preflight_summary["runtime_trust_materials"]
        preflight_runtime["material_digests"] = {
            "control_plane_certificate": {"sha256": digest("1")}
        }
        preflight_runtime["docker_toolchain"] = {"ok": True, "daemon": {"daemon_id": "fixture-daemon-id"}}
        measured_preflight_module = (
            verify_release_completion.load_production_host_preflight_module(
                configured,
                final=True,
            )
        )
        original_runtime_check = measured_preflight_module.runtime_trust_materials_check
        measured_preflight_module.runtime_trust_materials_check = lambda *_args, **_kwargs: (
            {
                "ok": True,
                "material_digests": {
                    "control_plane_certificate": {"sha256": digest("2")}
                },
                "proof_collector_key_id": preflight_runtime["proof_collector_key_id"],
                "proof_verifier_key_id": preflight_runtime["proof_verifier_key_id"],
                "docker_toolchain": preflight_runtime["docker_toolchain"],
            },
            [],
        )
        try:
            try:
                verify_binding(remeasure_runtime=True)
            except ValueError as exc:
                if "current TLS/audit/proof material bytes differ" not in str(exc):
                    raise
            else:
                raise AssertionError(
                    "direct final verifier accepted runtime TLS material changed after preflight"
                )
        finally:
            measured_preflight_module.runtime_trust_materials_check = original_runtime_check
            preflight_runtime.pop("material_digests", None)
            preflight_runtime.pop("docker_toolchain", None)

        frozen_key_snapshots = {
            "hardware_assurance_trusted_public_key": verify_release_completion.snapshot_regular_file(
                tmp / "hardware-assurance-verifier.pub.pem",
                "hardware assurance trust root",
                max_bytes=verify_release_completion.FINAL_TRUST_ROOT_MAX_BYTES,
            ),
            "final_challenge_authority_public_key": verify_release_completion.snapshot_regular_file(
                tmp / "final-challenge-authority.pub.pem",
                "final challenge authority trust root",
                max_bytes=verify_release_completion.FINAL_TRUST_ROOT_MAX_BYTES,
            ),
            "control_plane_response_signing_public_key": verify_release_completion.snapshot_regular_file(
                tmp / "control-plane-response-signing.pub.pem",
                "control-plane response signing trust root",
                max_bytes=verify_release_completion.FINAL_TRUST_ROOT_MAX_BYTES,
            ),
        }
        (tmp / "hardware-assurance-verifier.pub.pem").write_text(
            final_challenge_authority_key_info()["public_key_pem"],
            encoding="ascii",
        )
        swapped_binding = verify_binding(snapshots_override=frozen_key_snapshots)
        if (
            swapped_binding.get("hardware_assurance_trusted_public_key_id")
            != hardware_verifier_key_info()["key_id"]
        ):
            raise AssertionError(
                "final env binding reopened a hardware trust-root path after snapshot capture"
            )
        (tmp / "hardware-assurance-verifier.pub.pem").write_text(
            hardware_verifier_key_info()["public_key_pem"],
            encoding="ascii",
        )

        wrong_id_configured = write_final_production_env_file(
            tmp,
            overrides={
                verify_release_completion.FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY: digest("0")
            },
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        wrong_id_inputs = {
            name: wrong_id_configured.get(name) for name in final_input_names
        }
        expect_failure(
            "hardware assurance verifier key bytes do not match the independently configured SPKI identity",
            wrong_id_inputs,
        )

        (tmp / "final-challenge-authority.pub.pem").write_text(
            hardware_verifier_key_info()["public_key_pem"],
            encoding="ascii",
        )
        same_key_configured = write_final_production_env_file(
            tmp,
            overrides={
                verify_release_completion.FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY: (
                    hardware_verifier_key_info()["key_id"]
                )
            },
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        same_key_inputs = {
            name: same_key_configured.get(name) for name in final_input_names
        }
        expect_failure(
            "hardware assurance verifier and final challenge authority must use different public keys",
            same_key_inputs,
        )
        (tmp / "final-challenge-authority.pub.pem").write_text(
            final_challenge_authority_key_info()["public_key_pem"],
            encoding="ascii",
        )

        (tmp / "hardware-assurance-verifier.pub.pem").write_text(
            release_key_info()["public_key_pem"],
            encoding="ascii",
        )
        reused_release_hardware_configured = write_final_production_env_file(
            tmp,
            overrides={
                verify_release_completion.FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY: (
                    release_key_info()["key_id"]
                )
            },
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        reused_release_hardware_inputs = {
            name: reused_release_hardware_configured.get(name)
            for name in final_input_names
        }
        expect_failure(
            "hardware assurance verifier must not reuse a release trust public key",
            reused_release_hardware_inputs,
        )
        (tmp / "hardware-assurance-verifier.pub.pem").write_text(
            hardware_verifier_key_info()["public_key_pem"],
            encoding="ascii",
        )

        (tmp / "final-challenge-authority.pub.pem").write_text(
            external_receipt_key_info()["public_key_pem"],
            encoding="ascii",
        )
        reused_release_authority_configured = write_final_production_env_file(
            tmp,
            overrides={
                verify_release_completion.FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY: (
                    external_receipt_key_info()["key_id"]
                )
            },
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        reused_release_authority_inputs = {
            name: reused_release_authority_configured.get(name)
            for name in final_input_names
        }
        expect_failure(
            "final challenge authority must not reuse a release trust public key",
            reused_release_authority_inputs,
        )
        (tmp / "final-challenge-authority.pub.pem").write_text(
            final_challenge_authority_key_info()["public_key_pem"],
            encoding="ascii",
        )

        configured = write_final_production_env_file(tmp)
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        final_inputs = {name: configured.get(name) for name in final_input_names}

        substituted_release_trust = dict(release_trust_inputs)
        substituted_release_trust[verify_release_completion.RELEASE_PROVENANCE_TRUST_ROOT_ENV_KEY] = str(
            tmp / "caller-selected-release-key.pub.pem"
        )
        expect_failure(
            "release provenance trust root does not exactly match",
            selected_release_trust=substituted_release_trust,
        )

        substituted_checkpoint_provider = dict(release_trust_inputs)
        substituted_checkpoint_provider[
            verify_release_completion.EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY
        ] = "caller-selected-transparency-log"
        expect_failure(
            "external checkpoint provider does not exactly match",
            selected_release_trust=substituted_checkpoint_provider,
        )

        substituted_policy_trust = dict(release_trust_inputs)
        substituted_policy_trust[
            run_production_readiness.POLICY_TRUST_ROOT_ENV
        ] = str(tmp / "caller-selected-policy-key.pub.pem")
        expect_failure(
            "policy identity trust root does not exactly match",
            selected_release_trust=substituted_policy_trust,
        )

        substituted_policy_id = dict(release_trust_inputs)
        substituted_policy_id[
            run_production_readiness.POLICY_TRUST_ROOT_ID_ENV
        ] = digest("0")
        expect_failure(
            "policy identity expected SPKI identity does not exactly match",
            selected_release_trust=substituted_policy_id,
        )

        wrong_policy_id_configured = write_final_production_env_file(
            tmp,
            overrides={
                run_production_readiness.POLICY_TRUST_ROOT_ID_ENV: digest("0")
            },
        )
        readiness_summary, preflight_summary, config_summary = (
            final_env_binding_summaries(tmp)
        )
        wrong_policy_release_inputs = {
            name: wrong_policy_id_configured.get(name)
            for name in release_trust_input_names
        }
        expect_failure(
            "policy_identity trust-root bytes do not match the hashed production env SPKI pin",
            selected_release_trust=wrong_policy_release_inputs,
        )
        configured = write_final_production_env_file(tmp)
        readiness_summary, preflight_summary, config_summary = (
            final_env_binding_summaries(tmp)
        )
        release_trust_inputs = {
            name: configured.get(name) for name in release_trust_input_names
        }

        rogue_hardware_key = ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x14" * 32))
        rogue_hardware_path = tmp / "rogue-hardware-verifier.pub.pem"
        rogue_hardware_path.write_text(rogue_hardware_key["public_key_pem"], encoding="ascii")
        substituted_hardware = dict(final_inputs)
        substituted_hardware[verify_release_completion.FINAL_HARDWARE_TRUST_ROOT_ENV_KEY] = str(
            rogue_hardware_path
        )
        expect_failure("hardware assurance trust root does not exactly match", substituted_hardware)

        rogue_authority_key = ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x15" * 32))
        rogue_authority_path = tmp / "rogue-final-authority.pub.pem"
        rogue_authority_path.write_text(rogue_authority_key["public_key_pem"], encoding="ascii")
        substituted_authority = dict(final_inputs)
        substituted_authority[
            verify_release_completion.FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ENV_KEY
        ] = str(rogue_authority_path)
        expect_failure("final challenge authority trust root does not exactly match", substituted_authority)

        substituted_provider = dict(final_inputs)
        substituted_provider[
            verify_release_completion.FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY
        ] = "caller-selected-authority"
        expect_failure("final challenge authority provider does not exactly match", substituted_provider)

        substituted_challenge = dict(final_inputs)
        substituted_challenge[
            verify_release_completion.FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY
        ] = b64e(b"caller-selected-hardware-challenge")
        expect_failure("hardware assurance expected challenge does not exactly match", substituted_challenge)

        substituted_receipt = dict(final_inputs)
        substituted_receipt[verify_release_completion.FINAL_CHALLENGE_RECEIPT_ENV_KEY] = str(
            tmp / "caller-selected-final-receipt.json"
        )
        expect_failure("final challenge receipt does not exactly match", substituted_receipt)

        write_final_production_env_file(
            tmp,
            omitted={verify_release_completion.RELEASE_PROVENANCE_TRUST_ROOT_ENV_KEY},
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        expect_failure("release provenance trust root does not exactly match")

        write_final_production_env_file(
            tmp,
            omitted={verify_release_completion.FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ENV_KEY},
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        expect_failure("final challenge authority trust root does not exactly match")

        write_final_production_env_file(
            tmp,
            omitted={verify_release_completion.FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY},
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        expect_failure("hardware assurance expected SPKI identity does not exactly match")

        write_final_production_env_file(
            tmp,
            omitted={
                verify_release_completion.FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY
            },
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        expect_failure("final challenge authority expected SPKI identity does not exactly match")

        write_final_production_env_file(
            tmp,
            omitted={verify_release_completion.FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY},
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        expect_failure("must pin exactly one hardware assurance expected challenge")

        write_final_production_env_file(
            tmp,
            omitted={verify_release_completion.FINAL_MODE_ENV_KEY},
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        expect_failure("must set SERVERWARE_COMPLETION_VERIFICATION_MODE=final")

        write_final_production_env_file(
            tmp,
            omitted={verify_release_completion.PROXY_PRINCIPAL_ENV_KEY},
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        expect_failure("production readiness expected proxy principal ID is invalid")

        digest_configured = write_final_production_env_file(
            tmp,
            overrides={
                verify_release_completion.FINAL_HARDWARE_CHALLENGE_DIGEST_ENV_KEY: (
                    HARDWARE_ASSURANCE_CHALLENGE_SHA256
                )
            },
            omitted={verify_release_completion.FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY},
        )
        readiness_summary, preflight_summary, config_summary = final_env_binding_summaries(tmp)
        digest_inputs = {name: digest_configured.get(name) for name in final_input_names}
        digest_binding = verify_binding(digest_inputs)
        if digest_binding.get("hardware_assurance_expected_challenge_selector") != "nonce_sha256":
            raise AssertionError(f"final env digest challenge was not bound: {digest_binding}")

        readiness_summary, preflight_summary, config_summary = recorded_summaries
        rewritten = write_final_production_env_file(
            tmp,
            overrides={
                verify_release_completion.FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY: (
                    "rewritten-authority"
                )
            },
        )
        rewritten_inputs = {name: rewritten.get(name) for name in final_input_names}
        expect_failure(
            "current production readiness env digest does not match production host preflight",
            rewritten_inputs,
        )


def test_preflight_authenticity_and_freshness() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        key_info = preflight_signing_key_info()
        private_path = tmp / "preflight-signing.key.pem"
        public_path = tmp / "preflight-signing.pub.pem"
        private_path.write_bytes(
            key_info["key"].private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        private_path.chmod(0o600)
        public_path.write_text(key_info["public_key_pem"], encoding="ascii")
        public_path.chmod(0o600)
        signing_env = {
            run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_PRIVATE_KEY_ENV: str(
                private_path
            ),
            run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY_ENV: str(
                public_path
            ),
            run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID_ENV: key_info[
                "key_id"
            ],
        }

        def signed(generated_at: int) -> dict[str, Any]:
            document: dict[str, Any] = {
                "apiVersion": "serverware.productionHostPreflight/v1",
                "kind": "ProductionHostPreflight",
                "ok": True,
                "generated_at_unix": generated_at,
                "checks": {},
                "failures": [],
                "next_command": "fixture",
                "secret_values_redacted": True,
            }
            document["authenticity"] = production_host_preflight_module.sign_final_preflight(
                document,
                signing_env,
            )
            return document

        snapshot = verify_release_completion.snapshot_regular_file(
            public_path,
            "preflight signing public key",
            max_bytes=verify_release_completion.FINAL_TRUST_ROOT_MAX_BYTES,
        )
        current = signed(int(time.time()))
        verified = verify_release_completion.verify_preflight_authenticity(
            current,
            trusted_public_key=snapshot,
            expected_key_id=key_info["key_id"],
            max_age_seconds=300,
        )
        if verified.get("verified") is not True:
            raise AssertionError(f"valid signed preflight was rejected: {verified}")
        fabricated = json.loads(json.dumps(current))
        fabricated["checks"]["fabricated"] = True
        try:
            verify_release_completion.verify_preflight_authenticity(
                fabricated,
                trusted_public_key=snapshot,
                expected_key_id=key_info["key_id"],
                max_age_seconds=300,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("fabricated signed preflight payload was accepted")
        stale = signed(int(time.time()) - 301)
        try:
            verify_release_completion.verify_preflight_authenticity(
                stale,
                trusted_public_key=snapshot,
                expected_key_id=key_info["key_id"],
                max_age_seconds=300,
            )
        except ValueError as exc:
            if "stale" not in str(exc):
                raise
        else:
            raise AssertionError("stale signed production host preflight was accepted")


def redacted_environment_summary(tmp: Path) -> dict[str, Any]:
    return {
        "env_keys": sorted(run_production_readiness.load_env_file(tmp / "production.env")),
        "production_readiness_env_path": str(tmp / "production.env"),
        "production_readiness_env_sha256": sha256_file(tmp / "production.env"),
        "production_images_env_path": str(tmp / "production-images.env"),
        "production_images_env_sha256": sha256_file(tmp / "production-images.env"),
        "secret_values_redacted": True,
    }


def production_config_document(path: Path) -> dict[str, Any]:
    tmp = path.parent
    return {
        "ok": True,
        "production_readiness": "pass",
        "mode": "config",
        "checks": [
            "no-dev-fixtures",
            "control-plane-auth",
            "nitro",
            "attested-credential-delivery",
            "cosign-sigstore",
            "external-transparency",
            "apparmor",
            "shared-stores",
            "agent-egress",
            "production-images-no-shell",
        ],
        "environment": redacted_environment_summary(tmp),
        "live": None,
        "result_path": str(path),
    }


def production_config_semantic_sha256(path: Path) -> str:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    parsed.pop("result_path", None)
    parsed.pop("result_sha256", None)
    return sha256_prefixed_json(parsed)


def write_production_config_files(tmp: Path) -> None:
    for name in ("production-readiness-config.json", "production-host-preflight-config.json"):
        path = tmp / name
        write(path, production_config_document(path))


def hash_to_bytes(value: str) -> bytes:
    return bytes.fromhex(value.split(":", 1)[1])


def node_hash(left: str, right: str) -> str:
    return sha256_prefixed_bytes(b"\x01" + hash_to_bytes(left) + hash_to_bytes(right))


def transparency_leaf_payload(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "anchor_id": item.get("anchor_id"),
        "sequence": item.get("sequence"),
        "received_at": item.get("received_at"),
        "record": item.get("record"),
        "record_digest": item.get("record_digest"),
    }


def transparency_leaf_hash(item: dict[str, Any]) -> str:
    return sha256_prefixed_bytes(b"\x00" + canonical_json(transparency_leaf_payload(item)).encode("utf-8"))


def signed_tree_head(*, tree_size: int, tree_head_hash: str) -> dict[str, Any]:
    key_info = transparency_key_info()
    payload = {
        "version": "serverware.transparencyLog/v1",
        "tree_size": tree_size,
        "tree_head_hash": tree_head_hash,
        "created_at": "2026-05-26T00:00:00+00:00",
        "log_id": key_info["key_id"],
    }
    payload["signature"] = "ed25519:" + b64e(key_info["key"].sign(canonical_json(payload).encode("utf-8")))
    payload["public_key_pem"] = key_info["public_key_pem"]
    return payload


def signed_external_receipt(payload: dict[str, Any]) -> dict[str, Any]:
    key_info = external_receipt_key_info()
    return {
        "kind": "ed25519-signed-checkpoint",
        "payload": payload,
        "signature": "ed25519:" + b64e(key_info["key"].sign(canonical_json(payload).encode("utf-8"))),
        "public_key_pem": key_info["public_key_pem"],
    }


def external_checkpoint(*, provider: str = "managed-prod-log", log_id: str | None = None) -> dict[str, Any]:
    selected_log_id = log_id or str(external_receipt_key_info()["key_id"])
    receipt_payload = {"provider": provider, "log_id": selected_log_id}
    return {
        "accepted": 1,
        "mode": "external-managed-transparency-log",
        "anchors": [
            {
                "external_checkpoint": {
                    "ok": True,
                    "provider": provider,
                    "log_id": selected_log_id,
                    "external_sequence": 42,
                    "receipt": signed_external_receipt(receipt_payload),
                }
            }
        ],
    }


def transparency_for_record(
    record: dict[str, Any],
    *,
    provider: str = "managed-prod-log",
    log_id: str | None = None,
    anchor_key: str = "anchor_response",
    inclusion_key: str = "inclusion_proof",
) -> dict[str, Any]:
    selected_log_id = log_id or str(external_receipt_key_info()["key_id"])
    record_digest = sha256_prefixed_json(record)
    item = {
        "anchor_id": "fixture-anchor",
        "sequence": 1,
        "received_at": "2026-05-26T00:00:00+00:00",
        "record": record,
        "record_digest": record_digest,
    }
    leaf_hash = transparency_leaf_hash(item)
    tree_size = 1
    tree_head_hash = leaf_hash
    sth = signed_tree_head(tree_size=tree_size, tree_head_hash=tree_head_hash)
    checkpoint = {
        "ok": True,
        "provider": provider,
        "log_id": selected_log_id,
        "external_sequence": 42,
    }
    checkpoint["receipt"] = signed_external_receipt(
        {
            "provider": provider,
            "log_id": selected_log_id,
            "record_digest": record_digest,
            "leaf_hash": leaf_hash,
            "tree_head_hash": tree_head_hash,
            "tree_size": tree_size,
        }
    )
    checkpoint["signature"] = checkpoint["receipt"]["signature"]
    anchor_response = {
        "accepted": 1,
        "mode": "external-managed-transparency-log",
        "anchors": [
            {
                "sequence": 1,
                "record_digest": record_digest,
                "leaf_hash": leaf_hash,
                "tree_head_hash": tree_head_hash,
                "tree_size": tree_size,
                "signed_tree_head": sth,
                "external_checkpoint": checkpoint,
            }
        ],
    }
    inclusion = {
        "verified": True,
        "sequence": 1,
        "record_digest": record_digest,
        "leaf_hash": leaf_hash,
        "tree_size": tree_size,
        "tree_head_hash": tree_head_hash,
        "signed_tree_head": sth,
        "proof": [],
        "item": {
            **item,
            "leaf_hash": leaf_hash,
            "tree_size": tree_size,
            "tree_head_hash": tree_head_hash,
            "signed_tree_head": sth,
            "external_checkpoint": checkpoint,
        },
    }
    return {"record": record, anchor_key: anchor_response, inclusion_key: inclusion}


def sigstore_bundle(
    *,
    statement: dict[str, Any],
    signing_key_info: dict[str, Any] | None = None,
    rekor_signer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    signer = signing_key_info or sigstore_signing_key_info()
    rekor = rekor_signer or rekor_key_info()
    statement_digest = sha256_prefixed_json(statement)
    signature = base64.b64encode(
        signer["key"].sign(
            canonical_json(statement).encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
    ).decode("ascii")
    raw_log_id = base64.b64encode(bytes.fromhex(rekor["key_id"].split(":", 1)[1])).decode("ascii")
    body = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": statement_digest.split(":", 1)[1]}},
            "signature": {
                "content": signature,
                "publicKey": {
                    "content": base64.b64encode(signer["public_key_pem"].encode("ascii")).decode("ascii")
                },
            },
        },
    }
    canonicalized_body_bytes = canonical_json(body).encode("utf-8")
    canonicalized_body = base64.b64encode(canonicalized_body_bytes).decode("ascii")
    integrated_time = 1779830000
    log_index = 0
    set_payload = {
        "body": canonicalized_body,
        "integratedTime": integrated_time,
        "logID": rekor["key_id"].split(":", 1)[1],
        "logIndex": log_index,
    }
    signed_entry_timestamp = base64.b64encode(
        rekor["key"].sign(
            canonical_json(set_payload).encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
    ).decode("ascii")
    leaf_hash = hashlib.sha256(b"\x00" + canonicalized_body_bytes).digest()
    checkpoint_text = (
        "rekor.fixture.test - 1\n"
        "1\n"
        + base64.b64encode(leaf_hash).decode("ascii")
        + "\n"
    )
    checkpoint_signature = rekor["key"].sign(
        checkpoint_text.encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )
    checkpoint_envelope = (
        checkpoint_text
        + "\n\u2014 rekor.fixture.test "
        + base64.b64encode(bytes.fromhex(rekor["key_id"].split(":", 1)[1])[:4] + checkpoint_signature).decode(
            "ascii"
        )
        + "\n"
    )
    inclusion_proof = {
        "treeSize": "1",
        "logIndex": "0",
        "rootHash": base64.b64encode(leaf_hash).decode("ascii"),
        "hashes": [],
        "checkpoint": {"envelope": checkpoint_envelope},
    }
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(bytes.fromhex(statement_digest.split(":", 1)[1])).decode("ascii"),
            },
            "signature": signature,
        },
        "verificationMaterial": {
            "publicKey": {
                "hint": base64.b64encode(
                    bytes.fromhex(signer["key_id"].split(":", 1)[1])
                ).decode("ascii")
            },
            "tlogEntries": [
                {
                    "entryUUID": "fixture-rekor-entry",
                    "integratedTime": str(integrated_time),
                    "logId": {"keyId": raw_log_id},
                    "logIndex": str(log_index),
                    "canonicalizedBody": canonicalized_body,
                    "inclusionPromise": {"signedEntryTimestamp": signed_entry_timestamp},
                    "inclusionProof": inclusion_proof,
                }
            ],
        },
    }


def sigstore_proof(
    *,
    statement: dict[str, Any],
    signing_key_info: dict[str, Any] | None = None,
    rekor_signer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    signer = signing_key_info or sigstore_signing_key_info()
    rekor = rekor_signer or rekor_key_info()
    statement_digest = sha256_prefixed_json(statement)
    bundle = sigstore_bundle(
        statement=statement,
        signing_key_info=signer,
        rekor_signer=rekor,
    )
    signature = bundle["messageSignature"]["signature"]
    entry = bundle["verificationMaterial"]["tlogEntries"][0]
    return {
        "ok": True,
        "provider": "cosign",
        "signature": signature,
        "statement_digest": statement_digest,
        "key_provider": {"type": "sigstore-key", "key_id": signer["key_id"]},
        "transparency": {
            "log_id": rekor["key_id"],
            "entry_uuid": entry["entryUUID"],
            "integrated_time": entry["integratedTime"],
            "log_index": entry["logIndex"],
            "inclusion_proof": entry["inclusionProof"],
        },
        "bundle": bundle,
    }


def refresh_image_transparency_record(document: dict[str, Any]) -> None:
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        return
    record = {
        "type": "release.image_signatures.v1",
        "provenance_digest": metadata.get("provenanceDigest"),
        "image_signature_bundle_digest": document.get("image_signature_bundle_digest"),
        "image_signing_key_id": metadata.get("imageSigningKeyId") or sigstore_signing_key_info()["key_id"],
        "image_signature_provider": metadata.get("signatureProvider"),
        "release_signing_key_id": metadata.get("releaseSigningKeyId"),
        "signature": metadata.get("signature"),
        "images": {
            item["service"]: item["image_id"]
            for item in document.get("images") or []
            if isinstance(item, dict) and item.get("service") and item.get("image_id")
        },
    }
    metadata["transparency"] = transparency_for_record(
        record,
        anchor_key="anchorResponse",
        inclusion_key="inclusionProof",
    )


def nitro_evidence(provenance_digest: str) -> dict[str, Any]:
    releases = []
    for material in ("broker-kek", "decision-gate-ca"):
        config = KMS_MATERIAL_FIXTURES[material]
        binding = kms_material_binding(material)
        releases.append(
            {
                "ok": True,
                "provider": "aws-nitro-kms-policy",
                "material": material,
                "release_handle": digest("a"),
                "kms_command_required": True,
                "kms_request_digest": digest("b"),
                "kms_release": {
                    "ok": True,
                    "provider": "aws-kms-recipient",
                    "material": material,
                    "request_digest": digest("b"),
                    "release_handle": digest("a"),
                    "ciphertext_blob_sha256": binding["ciphertext_blob_sha256"],
                    "encryption_context_sha256": binding["encryption_context_sha256"],
                    "material_handle": digest("c"),
                    "recipient_ciphertext_sha256": digest("c"),
                    "attestation_document_sha256": digest("e"),
                    "key_provider": {"type": "aws-kms", "key_id": str(config["key_id"])},
                    "audit": {
                        "ciphertext_blob_sha256": binding["ciphertext_blob_sha256"],
                        "encryption_context_sha256": binding["encryption_context_sha256"],
                    },
                },
            }
        )
    return {
        "apiVersion": "serverware.nitroKmsEvidence/v1",
        "kind": "NitroKmsEvidence",
        "ok": True,
        "provider": "aws-nitro-enclaves",
        "tee_platform": "aws-nitro",
        "claims": {
            "sha256": digest("d"),
            "fields": {
                "materials": ["broker-kek", "decision-gate-ca"],
                "debug": False,
                "release_channel": "prod",
                "policy_bundle_digest": POLICY_DIGEST,
                "policy_sequence": 12,
                "policy_high_water_digest": digest("6"),
                "runtime_manifest_digest": digest("7"),
                "data_plane_binary_digest": digest("9"),
                "provenance_digest": provenance_digest,
                "source_tree_digest": SOURCE_TREE_DIGEST,
                "response_signing_key_id": proxy_response_key_info()["key_id"],
            },
        },
        "quote": {"provider": "aws-nitro-enclaves", "tee_platform": "aws-nitro", "debug": False},
        "nitro": {
            "provider": "aws-nitro-enclaves",
            "tee_platform": "aws-nitro",
            "verified": True,
            "debug": False,
            "raw_attestation_document_sha256": digest("e"),
        },
        "release_materials": releases,
        "config": {
            "kms_command_required": True,
            "fixtures_allowed_for_test": False,
            "attestation_command_sha256": digest("f"),
            "kms_release_command_sha256": digest("0"),
        },
        "redaction": {"raw_attestation_document_b64": "omitted", "plaintext_material": "rejected"},
    }


def sign_hardware_assurance(
    document: dict[str, Any],
    key_info: dict[str, Any] | None = None,
) -> None:
    signer = key_info or hardware_verifier_key_info()
    document["signing_key_id"] = signer["key_id"]
    document["signature"] = "ed25519:" + b64e(
        signer["key"].sign(canonical_json(document["statement"]).encode("utf-8"))
    )


def final_challenge_receipt(
    *,
    challenge_nonce_sha256: str,
    completion_identity_sha256: str,
    release_identity_sha256: str,
    hardware_verifier_key_id: str,
    current_host_identity_sha256: str,
    proxy_server_statement_sha256: str,
    issued_at_unix: int,
    signer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    key_info = signer or final_challenge_authority_key_info()
    statement = {
        "authority_provider": "fixture-off-host-challenge-authority",
        "consumption_id": "fixture-consumption-0001",
        "status": "consumed",
        "issued_at_unix": issued_at_unix,
        "expires_at_unix": issued_at_unix + 300,
        "challenge_nonce_sha256": challenge_nonce_sha256,
        "completion_identity_sha256": completion_identity_sha256,
        "release_identity_sha256": release_identity_sha256,
        "hardware_verifier_key_id": hardware_verifier_key_id,
        "current_host_identity_sha256": current_host_identity_sha256,
        "proxy_server_statement_sha256": proxy_server_statement_sha256,
    }
    return {
        "apiVersion": verify_release_completion.FINAL_CHALLENGE_RECEIPT_API_VERSION,
        "kind": "FinalChallengeConsumption",
        "statement": statement,
        "signing_key_id": key_info["key_id"],
        "signature": "ed25519:"
        + b64e(key_info["key"].sign(canonical_json(statement).encode("utf-8"))),
    }


def fixture_release_identity(nitro: dict[str, Any], tmp: Path) -> dict[str, Any]:
    nitro_summary = verify_release_completion.verify_nitro_evidence(
        nitro,
        "hardware assurance fixture Nitro evidence",
    )
    readiness = json.loads((tmp / "production-readiness.json").read_text(encoding="utf-8"))
    image_signatures_document = json.loads((tmp / "image-signatures.json").read_text(encoding="utf-8"))
    image_refs = readiness["live"]["production_images_no_shell"]["images"]
    return verify_release_completion.validate_release_identity(
        {
            "source_tree_digest": nitro_summary["attested_runtime"]["source_tree_digest"],
            "provenance_digest": nitro_summary["attested_runtime"]["provenance_digest"],
            "runtime_manifest_digest": nitro_summary["attested_runtime"]["runtime_manifest_digest"],
            "data_plane_binary_digest": nitro_summary["attested_runtime"]["data_plane_binary_digest"],
            "production_image_digests": [item.split("@", 1)[1] for item in image_refs],
            "production_image_refs": image_refs,
            "production_images_build_sha256": sha256_file(tmp / "production-images-build.json"),
            "production_images_published_sha256": sha256_file(tmp / "production-images-published.json"),
            "image_signature_bundle_digest": image_signatures_document["image_signature_bundle_digest"],
        },
        "fixture release identity",
    )


def hardware_assurance_document(nitro: dict[str, Any], tmp: Path) -> dict[str, Any]:
    nitro_summary = verify_release_completion.verify_nitro_evidence(nitro, "hardware assurance fixture Nitro evidence")
    release_identity = fixture_release_identity(nitro, tmp)
    pcrs = {"PCR0": sha384("a"), "PCR1": sha384("b"), "PCR2": sha384("c")}
    build_manifest = {
        "apiVersion": verify_release_completion.EIF_BUILD_MANIFEST_API_VERSION,
        "release_identity": release_identity,
        "release_identity_sha256": sha256_prefixed_json(release_identity),
        "eif_image_sha384": sha384("a"),
        "pcrs": pcrs,
    }
    issued_at = int(time.time())
    document = {
        "apiVersion": "serverware.hardwareAssurance/v1",
        "kind": "ServerwareHardwareAssurance",
        "statement": {
            "verifier": {
                "name": "fixture-independent-verifier",
                "organization": "Serverware test assurance lab",
                "independent": True,
            },
            "issued_at_unix": issued_at,
            "expires_at_unix": issued_at + 300,
            "challenge_nonce": HARDWARE_ASSURANCE_CHALLENGE_NONCE,
            "current_host_identity": verify_release_completion.current_host_identity_claim(
                fixture_current_host_identity(),
                observed_at_unix=issued_at,
            ),
            "attestation_document_sha256": nitro_summary["raw_attestation_document_sha256"],
            "eif": {
                "image_sha384": sha384("a"),
                "build_manifest": build_manifest,
                "build_manifest_sha256": sha256_prefixed_json(build_manifest),
                "signature_verified": True,
                "evidence_sha256": digest("2"),
            },
            "pcrs": pcrs,
            "enclave": {
                "cid": 16,
                "parent_cid": 3,
                "vsock_port": 5000,
                "cid_evidence_sha256": digest("3"),
                "vsock_evidence_sha256": digest("4"),
                "vsock_handshake_verified": True,
            },
            "key_custody": {
                "recipient_key_generated_in_enclave": True,
                "kms_recipient_bound": True,
                "plaintext_key_exported": False,
                "parent_process_key_access": False,
                "kms_recipient_bindings_sha256": sha256_prefixed_json(nitro_summary["material_release_receipts"]),
                "evidence_sha256": digest("5"),
            },
            "no_parent_key": {
                "verified": True,
                "parent_key_material_absent": True,
                "evidence_sha256": digest("6"),
            },
            "release_bindings": nitro_summary["attested_runtime"],
            "artifact_bindings": {
                "nitro_evidence_sha256": sha256_prefixed_bytes((tmp / "nitro-kms-evidence.json").read_bytes()),
                "production_host_preflight_sha256": sha256_prefixed_bytes(
                    (tmp / "production-host-preflight.json").read_bytes()
                ),
            },
        },
        "signing_key_id": "",
        "signature": "",
    }
    sign_hardware_assurance(document)
    return document


def production_readiness(nitro: dict[str, Any], tmp: Path) -> dict[str, Any]:
    checks = [
        "no-dev-fixtures",
        "control-plane-auth",
        "nitro",
        "attested-credential-delivery",
        "cosign-sigstore",
        "external-transparency",
        "apparmor",
        "shared-stores",
        "agent-egress",
        "production-images-no-shell",
    ]
    return {
        "ok": True,
        "production_readiness": "pass",
        "mode": "live",
        "checks": checks,
        "environment": redacted_environment_summary(tmp),
        "live": {
            "sigstore": {
                "ok": True,
                "key_id": sigstore_signing_key_info()["key_id"],
                "transparency_log_id": rekor_key_info()["key_id"],
                "entry_uuid": "entry",
            },
            "external_transparency": {
                "ok": True,
                "provider": "managed-prod-log",
                "log_id": external_receipt_key_info()["key_id"],
                "external_sequence": 10,
            },
            "shared_stores": {
                "ok": True,
                "stores": {
                    "metadata": {"ok": True, "tables": ["credentials"]},
                    "grant": {"ok": True, "tables": ["approval_grants"]},
                    "audit": {"ok": True, "tables": ["serverware_audit_events"]},
                },
            },
            "nitro": nitro,
            "production_images_no_shell": {
                "ok": True,
                "images": [
                    "registry.prod.serverware.dev/serverware/control@sha256:" + "6" * 64,
                    "registry.prod.serverware.dev/serverware/decision-gate@sha256:" + "7" * 64,
                ],
            },
            "apparmor": {"ok": True},
        },
    }


def release_provenance(
    reproducible_build_verification_sha256: str = digest("f"),
) -> tuple[dict[str, Any], dict[str, Any]]:
    key_info = release_key_info()
    launch_authority = {
        "launch_authority_key_id": FIXTURE_LAUNCH_AUTHORITY_KEY_ID,
        "launch_authority_root_sha256": FIXTURE_LAUNCH_AUTHORITY_ROOT_SHA256,
    }
    provenance = {
        "version": 2,
        "source": "serverware-digest-pinned-production-release",
        "source_tree": {"digest": SOURCE_TREE_DIGEST},
        "compose_config_sha256": digest("4"),
        "compose": {"file": "docker-compose.production.yml", "sha256": digest("4")},
        "sbom": {"cyclonedx": {"sha256": digest("5"), "components": 204}},
        "images": {
            "serverware-control": {
                "image_id": digest("6"),
                "config_id": digest("a"),
                "local_build_image_id": digest("a"),
                "remote_image_id": digest("a"),
            },
            "serverware-decision-gate": {
                "image_id": digest("7"),
                "config_id": digest("b"),
                "local_build_image_id": digest("b"),
                "remote_image_id": digest("b"),
                "binary_digest": digest("9"),
                "launcher_binary_digest": digest("e"),
                **launch_authority,
            },
        },
        "launch_authority": launch_authority,
        "reproducible_build": {
            "apiVersion": "serverware.reproducibleBuildVerification/v3",
            "kind": "ReproducibleBuildVerification",
            "verification_sha256": reproducible_build_verification_sha256,
            "builders": [
                {
                    "builder_id": "fixture-builder-left",
                    "key_id": reproducible_builder_left_key_info()["key_id"],
                },
                {
                    "builder_id": "fixture-builder-right",
                    "key_id": reproducible_builder_right_key_info()["key_id"],
                },
            ],
            **launch_authority,
        },
        "anchor_chain": {"ok": True, "mode": "signed-merkle-transparency-log"},
    }
    provenance_digest = sha256_prefixed_json(provenance)
    signature = "ed25519:" + b64e(key_info["key"].sign(canonical_json(provenance).encode("utf-8")))
    record = {
        "type": "release.provenance.v2",
        "provenance_digest": provenance_digest,
        "signature": signature,
        "release_signing_key_id": key_info["key_id"],
        "production_launcher_binary_digest": digest("e"),
        **launch_authority,
        "reproducible_build_verification_sha256": (
            reproducible_build_verification_sha256
        ),
    }
    document = {
        "provenance": provenance,
        "provenance_digest": provenance_digest,
        "signature": signature,
        "release_signing_key_id": key_info["key_id"],
        "production_launcher_binary_digest": digest("e"),
        "release_signing_public_key_pem": key_info["public_key_pem"],
        "transparency": transparency_for_record(record),
    }
    summary = {
        "ok": True,
        "release_provenance": "pass",
        "anchored": True,
        "inclusion_verified": True,
        "provenance_digest": provenance_digest,
        "release_signing_key_id": key_info["key_id"],
        "production_launcher_binary_digest": digest("e"),
        "transparency_mode": "signed-merkle-transparency-log",
        **launch_authority,
        "reproducible_build_verification_sha256": (
            reproducible_build_verification_sha256
        ),
    }
    return summary, document


def image_signatures(
    provenance_digest: str,
    release_signing_key_id: str | None = None,
    source_tree_digest: str = SOURCE_TREE_DIGEST,
) -> tuple[dict[str, Any], dict[str, Any]]:
    selected_release_key_id = release_signing_key_id or release_key_info()["key_id"]
    control_ref = "registry.prod.serverware.dev/serverware/control@sha256:" + "6" * 64
    gate_ref = "registry.prod.serverware.dev/serverware/decision-gate@sha256:" + "7" * 64
    base_predicate = {
        "provenance_digest": provenance_digest,
        "release_signing_key_id": selected_release_key_id,
        "source_tree_digest": source_tree_digest,
        "compose_config_sha256": digest("4"),
        "sbom_cyclonedx_sha256": digest("5"),
        "sbom_cyclonedx_components": 204,
    }
    payload = {
        "apiVersion": "serverware.imageSignatures/v1",
        "kind": "ImageSignatures",
        "metadata": {
            "provenanceDigest": provenance_digest,
            "releaseSigningKeyId": selected_release_key_id,
            "signatureProvider": "sigstore-command",
            "sigstoreTransparencyRequired": True,
            "sourceTreeDigest": source_tree_digest,
            "composeConfigSha256": digest("4"),
            "sbomCyclonedxSha256": digest("5"),
        },
        "images": [
            {
                "service": "serverware",
                "image_id": digest("6"),
                "statement": {
                    "subject": [{"name": "serverware", "digest": {"sha256": "6" * 64}}],
                    "predicate": {**base_predicate, "image_id": digest("6"), "repo_digests": [control_ref]},
                },
                "sigstore": {
                },
            },
            {
                "service": "decision-gate",
                "image_id": digest("7"),
                "statement": {
                    "subject": [{"name": "decision-gate", "digest": {"sha256": "7" * 64}}],
                    "predicate": {**base_predicate, "image_id": digest("7"), "repo_digests": [gate_ref]},
                },
                "sigstore": {
                },
            }
        ],
    }
    for index, image in enumerate(payload["images"], start=1):
        statement_digest = sha256_prefixed_json(image["statement"])
        image["statement_digest"] = statement_digest
        image["sigstore"] = sigstore_proof(statement=image["statement"])
        image["signature"] = image["sigstore"]["signature"]
    bundle_digest = sha256_prefixed_json(payload)
    bundle_sigstore = sigstore_proof(statement=payload)
    document = dict(payload)
    document["image_signature_bundle_digest"] = bundle_digest
    document["bundle_signature"] = bundle_sigstore
    document["metadata"] = dict(document["metadata"])
    document["metadata"]["signature"] = bundle_sigstore["signature"]
    document["metadata"]["bundleSigstore"] = bundle_sigstore
    image_record = {
        "type": "release.image_signatures.v1",
        "provenance_digest": provenance_digest,
        "image_signature_bundle_digest": bundle_digest,
        "image_signing_key_id": sigstore_signing_key_info()["key_id"],
        "image_signature_provider": "sigstore-command",
        "release_signing_key_id": selected_release_key_id,
        "signature": bundle_sigstore["signature"],
        "images": {item["service"]: item["image_id"] for item in document["images"]},
    }
    document["metadata"]["transparency"] = transparency_for_record(
        image_record,
        anchor_key="anchorResponse",
        inclusion_key="inclusionProof",
    )
    summary = {
        "ok": True,
        "image_signatures": "pass",
        "image_signature_provider": "sigstore-command",
        "inclusion_verified": True,
        "provenance_digest": provenance_digest,
        "release_signing_key_id": selected_release_key_id,
        "image_signature_bundle_digest": bundle_digest,
        "image_signing_key_id": sigstore_signing_key_info()["key_id"],
        "images": 2,
    }
    return summary, document


def write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def authorize_alternate_proxy_principal(tmp: Path) -> str:
    fixture = test_production_policy_identity.ProductionPolicyIdentityVerifierTests(
        methodName="runTest"
    )
    fixture.setUp()
    fixture.now_ms = int(time.time() * 1000)
    bundle_path = tmp / "policy-bundle.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["principals"].append(
        fixture.principal(
            principal_id=ALTERNATE_PROXY_PRINCIPAL_ID,
            token_id="billing-agent-01",
            token=b"test-only-high-entropy-bearer-material-02",
            source_cidrs=["10.42.7.20/32"],
        )
    )
    bundle["routes"][0]["principals"].append(ALTERNATE_PROXY_PRINCIPAL_ID)
    bundle = fixture.sign(bundle)
    write(bundle_path, bundle)

    identity_result = fixture.verify(bundle)
    if identity_result.get("ok") is not True:
        raise AssertionError(
            f"two-principal policy fixture failed identity verification: {identity_result}"
        )
    policy_key_path = tmp / "policy-signing.pub.pem"
    verify_production_policy_identity.write_private(
        tmp / "production-policy-identity-verification.json",
        verify_production_policy_identity.persisted_report(
            identity_result,
            bundle_path=bundle_path,
            trusted_public_key_path=policy_key_path,
            trusted_public_key_hash=fixture.public_key_hash,
        ),
    )
    policy_hash = identity_result["policy"]["hash"]
    activation_report_path = tmp / "policy-activation-verification.json"
    activation_report = json.loads(
        activation_report_path.read_text(encoding="utf-8")
    )
    activation_report["candidate_policy_hash"] = policy_hash
    test_production_release_input_preflight.signed_report(
        tmp,
        name="policy-activation-verification",
        purpose=production_release_input_preflight.ACTIVATION_PURPOSE,
        report=activation_report,
    )
    return policy_hash


def add_reproducible_builder_fixture(tmp: Path) -> None:
    report_path = tmp / "reproducible-build-verification.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["inputs"] = {
        "left": {
            "attestation": {
                "builder_id": "fixture-builder-left",
                "key_id": reproducible_builder_left_key_info()["key_id"],
                "signature_verified": True,
                "operator_trusted": True,
            }
        },
        "right": {
            "attestation": {
                "builder_id": "fixture-builder-right",
                "key_id": reproducible_builder_right_key_info()["key_id"],
                "signature_verified": True,
                "operator_trusted": True,
            }
        },
    }
    test_production_release_input_preflight.signed_report(
        tmp,
        name="reproducible-build-verification",
        purpose=production_release_input_preflight.REPRODUCIBILITY_PURPOSE,
        report=report,
    )


def production_images_build() -> dict[str, Any]:
    return {
        "apiVersion": "serverware.productionImagesBuild/v2",
        "kind": "ProductionImagesBuild",
        "ok": True,
        "metadata": {
            "source_tree_digest": SOURCE_TREE_DIGEST,
            "launch_authority_key_id": FIXTURE_LAUNCH_AUTHORITY_KEY_ID,
            "launch_authority_root_sha256": FIXTURE_LAUNCH_AUTHORITY_ROOT_SHA256,
        },
        "no_shell": {"ok": True},
        "images": [
            {"service": "serverware-control", "dockerfile": "Dockerfile.production", "image_id": digest("a")},
            {
                "service": "serverware-decision-gate",
                "dockerfile": "data-plane/decision-gate-rs/Dockerfile.production",
                "image_id": digest("b"),
                "binary_digest": digest("9"),
                "launcher_binary_digest": digest("e"),
                "launch_authority_key_id": FIXTURE_LAUNCH_AUTHORITY_KEY_ID,
                "launch_authority_root_sha256": FIXTURE_LAUNCH_AUTHORITY_ROOT_SHA256,
            },
        ],
    }


def production_images_published() -> dict[str, Any]:
    control_ref = "registry.prod.serverware.dev/serverware/control@sha256:" + "6" * 64
    gate_ref = "registry.prod.serverware.dev/serverware/decision-gate@sha256:" + "7" * 64
    return {
        "apiVersion": "serverware.productionImagesPublished/v2",
        "kind": "ProductionImagesPublished",
        "ok": True,
        "source_build_file": ".tmp/production-images-build.json",
        "images": [
            {
                "service": "serverware-control",
                "local_image_id": digest("a"),
                "config_id": digest("a"),
                "tag": "registry.prod.serverware.dev/serverware/control:production-candidate",
                "repo_digest": control_ref,
                "remote_image_id": digest("a"),
            },
            {
                "service": "serverware-decision-gate",
                "local_image_id": digest("b"),
                "config_id": digest("b"),
                "tag": "registry.prod.serverware.dev/serverware/decision-gate:production-candidate",
                "repo_digest": gate_ref,
                "remote_image_id": digest("b"),
                "binary_digest": digest("9"),
                "launcher_binary_digest": digest("e"),
                "launch_authority_key_id": FIXTURE_LAUNCH_AUTHORITY_KEY_ID,
                "launch_authority_root_sha256": FIXTURE_LAUNCH_AUTHORITY_ROOT_SHA256,
            },
        ],
        "remote_no_shell": {"ok": True},
        "env": {"SERVERWARE_PRODUCTION_IMAGES": ",".join([control_ref, gate_ref])},
    }


def file_summary(path: Path, label: str) -> dict[str, Any]:
    return {
        "label": label,
        "path": str(path),
        "exists": True,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def production_host_preflight(tmp: Path, source_tree_digest: str = SOURCE_TREE_DIGEST) -> dict[str, Any]:
    control_ref = "registry.prod.serverware.dev/serverware/control@sha256:" + "6" * 64
    gate_ref = "registry.prod.serverware.dev/serverware/decision-gate@sha256:" + "7" * 64
    configured = run_production_readiness.load_env_file(tmp / "production.env")
    policy_identity = verify_production_policy_identity.verify_persisted_report(
        bundle_path=tmp / "policy-bundle.json",
        trusted_public_key_path=tmp / "policy-signing.pub.pem",
        report_path=tmp / "production-policy-identity-verification.json",
    )
    activation = production_release_input_preflight.verify_externally_signed_report(
        report_path=tmp / "policy-activation-verification.json",
        signature_path=tmp / "policy-activation-verification.signature.json",
        trusted_public_key_path=tmp / "policy-activation-verification.pub.pem",
        purpose=production_release_input_preflight.ACTIVATION_PURPOSE,
        api_version=production_release_input_preflight.ACTIVATION_API_VERSION,
        kind=production_release_input_preflight.ACTIVATION_KIND,
    )
    reproducibility = production_release_input_preflight.verify_externally_signed_report(
        report_path=tmp / "reproducible-build-verification.json",
        signature_path=tmp / "reproducible-build-verification.signature.json",
        trusted_public_key_path=tmp / "reproducible-build-verification.pub.pem",
        purpose=production_release_input_preflight.REPRODUCIBILITY_PURPOSE,
        api_version=verify_release_completion.REPRODUCIBLE_BUILD_VERIFICATION_API_VERSION,
        kind=production_release_input_preflight.REPRODUCIBILITY_KIND,
    )
    return {
        "apiVersion": "serverware.productionHostPreflight/v1",
        "kind": "ProductionHostPreflight",
        "ok": True,
        "checks": {
            "host": {
                "ok": True,
                "skipped": False,
                "system": "Linux",
                "machine": "x86_64",
                "linux": True,
                "nitro_nsm_device": True,
                "apparmor_sysfs": True,
            },
            "runtime_trust_materials": {
                "ok": True,
                "skipped": False,
                "tls_files": ["ca.pem", "serverware.crt", "serverware.key"],
                "anchor_tls_files": ["audit-anchor.crt", "audit-anchor.key"],
                "helper_files": [
                    "control-plane-attestation-verify",
                    "lease-recipient-attest",
                    "lease-recipient-verify",
                    "nsm-attest",
                    "nsm-unseal",
                    "response-proof-attest",
                ],
                "proof_files": [
                    "proof-collector.key.pem",
                    "proof-collector.pub.pem",
                    "proxy-ca.pem",
                    "proxy-proof-verifier.pub.pem",
                ],
                "proof_collector_files": ["serverware-proof-client"],
                "executable_digests": [
                    {
                        "setting": setting,
                        "executable": (
                            str(tmp.resolve() / PINNED_EXECUTABLE_NAMES[setting])
                            if setting == production_host_preflight_module.PRODUCTION_PYTHON_EXECUTABLE_SETTING
                            else f"/opt/serverware/bin/{PINNED_EXECUTABLE_NAMES[setting]}"
                        ),
                        "host_path": (
                            str(tmp.resolve() / PINNED_EXECUTABLE_NAMES[setting])
                            if setting == production_host_preflight_module.PRODUCTION_PYTHON_EXECUTABLE_SETTING
                            else str(tmp.resolve() / "attestation-helpers" / PINNED_EXECUTABLE_NAMES[setting])
                        ),
                        "sha256": fixture_executable_digest_manifest()[setting],
                        "verified": True,
                    }
                    for setting in sorted(PINNED_EXECUTABLE_NAMES)
                ],
                "python_script_digests": [
                    {
                        "setting": setting,
                        "path": str((ROOT / "scripts" / script_name).resolve()),
                        "sha256": configured[setting],
                        "verified": True,
                    }
                    for script_name, setting in sorted(
                        run_production_readiness.PINNED_PYTHON_SCRIPTS.items()
                    )
                ],
                "proof_collector_private_key_mode": "0o600",
                "proof_collector_key_id": proxy_collector_key_info()["key_id"],
                "proof_verifier_key_id": proxy_vendor_verifier_key_info()["key_id"],
                "private_key_mode": "0o600",
                "certificate_not_after": "2035-01-01T00:00:00+00:00",
                "secret_values_redacted": True,
            },
            "production_env": {
                "ok": True,
                "path": str(tmp / "production.env"),
                "file": file_summary(tmp / "production.env", "production-readiness-env"),
                "env_keys": sorted(configured),
                "executing_script": {
                    "path": str((ROOT / "scripts" / "production_host_preflight.py").resolve()),
                    "sha256": configured[
                        run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV
                    ],
                    "device": (ROOT / "scripts" / "production_host_preflight.py").stat().st_dev,
                    "inode": (ROOT / "scripts" / "production_host_preflight.py").stat().st_ino,
                    "measured_from": "/proc/self/fd/fixture",
                    "matches_pinned_path_inode": True,
                },
                "config_gate": {
                    "ok": True,
                    "out": str(tmp / "production-host-preflight-config.json"),
                    "file": file_summary(tmp / "production-host-preflight-config.json", "production-readiness-config"),
                    "result_sha256": sha256_file(tmp / "production-host-preflight-config.json"),
                    "semantic_sha256": production_config_semantic_sha256(tmp / "production-host-preflight-config.json"),
                    "secret_values_redacted": True,
                },
                "secret_values_redacted": True,
            },
            "production_images_env": {
                "ok": True,
                "path": str(tmp / "production-images.env"),
                "file": file_summary(tmp / "production-images.env", "production-images-env"),
                "status": "valid",
                "images": [
                    {"ref": control_ref, "repository": "registry.prod.serverware.dev/serverware/control", "name": "control", "digest": digest("6")},
                    {
                        "ref": gate_ref,
                        "repository": "registry.prod.serverware.dev/serverware/decision-gate",
                        "name": "decision-gate",
                        "digest": digest("7"),
                    },
                ],
                "image_digests": [digest("6"), digest("7")],
                "secret_values_redacted": True,
            },
            "production_images_env_merge": {
                "ok": True,
                "key": "SERVERWARE_PRODUCTION_IMAGES",
                "production_env_has_key": True,
                "matches_images_env": True,
                "secret_values_redacted": True,
            },
            "production_compose": {
                "ok": True,
                "skipped": False,
                "file": "docker-compose.production.yml",
                "sha256": digest("4"),
                "secret_values_redacted": True,
            },
            "release_security_evidence": {
                "ok": True,
                "secret_values_redacted": True,
                "policy_identity": policy_identity,
                "policy_activation": {key: value for key, value in activation.items() if key != "report"},
                "reproducible_builds": {
                    **{key: value for key, value in reproducibility.items() if key != "report"},
                    "scope": reproducibility["report"]["scope"],
                    "sourceTreeDigest": reproducibility["report"]["source_tree_digest"],
                    "productionBuildBound": True,
                },
                "benchmarkPolicyBound": True,
            },
            "release_artifact_mounts": {
                "ok": True,
                "artifacts": [
                    {
                        "label": "release-provenance",
                        "matches_approved_artifact": True,
                        "sha256": sha256_file(tmp / "release-provenance.json"),
                    },
                    {
                        "label": "image-signatures",
                        "matches_approved_artifact": True,
                        "sha256": sha256_file(tmp / "image-signatures.json"),
                    },
                ],
                "secret_values_redacted": True,
            },
            "release_artifacts": {
                "ok": True,
                "production_images": {
                    "file": file_summary(tmp / "production-images-build.json", "production-images-build"),
                    "source_tree_digest": source_tree_digest,
                    "images": [
                        {"service": "serverware-control", "image_id": digest("a")},
                        {"service": "serverware-decision-gate", "image_id": digest("b")},
                    ],
                    "no_shell": "pass",
                },
                "production_images_published": {
                    "ok": True,
                    "file": file_summary(tmp / "production-images-published.json", "production-images-published"),
                    "repo_digests": [control_ref, gate_ref],
                    "image_digests": [digest("6"), digest("7")],
                },
                "release_provenance": {
                    "digest": json.loads((tmp / "release-provenance-summary.json").read_text(encoding="utf-8"))["provenance_digest"],
                    "file": file_summary(tmp / "release-provenance-summary.json", "release-provenance-summary"),
                },
                "release_provenance_document": {
                    **file_summary(tmp / "release-provenance.json", "release-provenance"),
                    "provenance_digest": json.loads((tmp / "release-provenance-summary.json").read_text(encoding="utf-8"))["provenance_digest"],
                    "source_tree_digest": source_tree_digest,
                },
                "image_signatures_summary": {
                    "digest": json.loads((tmp / "image-signatures-summary.json").read_text(encoding="utf-8"))["image_signature_bundle_digest"],
                    "file": file_summary(tmp / "image-signatures-summary.json", "image-signatures-summary"),
                },
                "image_signatures": {
                    "file": file_summary(tmp / "image-signatures.json", "image-signatures"),
                    "covers_published_production_images": True,
                    "covers_published_production_image_refs": True,
                    "signed_image_ids": [digest("6"), digest("7")],
                    "signed_repo_digests": [control_ref, gate_ref],
                },
                "bench": {
                    "file": file_summary(tmp / "decision-gate-rs-bench.json", "decision-gate-bench"),
                    "candidate": "rust-decision-gate",
                    "requests": 1000,
                    "p99_ms": json.loads((tmp / "decision-gate-rs-bench.json").read_text(encoding="utf-8"))["p99_ms"],
                    "data_plane_binary_digest": json.loads(
                        (tmp / "decision-gate-rs-bench.json").read_text(encoding="utf-8")
                    )["data_plane_binary_digest"],
                    "target_p99_ms": 20.0,
                },
            },
            "kms_materials": {
                "ok": True,
                "path": str(tmp / "kms-materials.json"),
                "exists": True,
                "mode": "0o600",
                "file": file_summary(tmp / "kms-materials.json", "kms-materials"),
                "materials": [
                    {
                        "material": "broker-kek",
                        **kms_material_binding("broker-kek"),
                    },
                    {
                        "material": "decision-gate-ca",
                        **kms_material_binding("decision-gate-ca"),
                    },
                ],
                "secret_values_redacted": True,
            },
        },
        "failures": [],
        "next_command": "make run-production-readiness PRODUCTION_READINESS_ENV=ops/production-readiness.env",
        "secret_values_redacted": True,
    }


def run_verifier(
    tmp: Path,
    *extra: str,
    allow_host_bypass: bool = True,
    include_proxy_proof: bool = True,
    include_control_plane_response_signing_trust_root: bool = True,
    include_hardware_assurance: bool = False,
    hardware_expected_challenge_mode: str | None = "nonce",
    proxy_proof_contract: str = "buffered-v3",
    proxy_stream_body: Path | None = None,
    proxy_max_stream_bytes: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    env = clean_subprocess_env()
    if allow_host_bypass:
        env["SERVERWARE_TEST_ONLY_ALLOW_PREFLIGHT_BYPASS"] = "1"
    proxy_proof_args = []
    if include_proxy_proof:
        proxy_proof_args = [
            "--proxy-response-proof",
            str(tmp / "proxy-response-proof.json"),
            "--proxy-proof-contract",
            proxy_proof_contract,
            "--proxy-proof-verifier-public-key",
            str(tmp / "proxy-vendor-verifier-public-key.pem"),
            "--proxy-collector-public-key",
            str(tmp / "proxy-collector-public-key.pem"),
            "--proxy-server-instance-id",
            PROXY_SERVER_INSTANCE_ID,
            "--proxy-client-nonce",
            PROXY_CLIENT_NONCE,
            "--proxy-client-request-digest",
            (
                PROXY_STREAM_CLIENT_REQUEST_DIGEST
                if proxy_proof_contract == "streaming-v1"
                else PROXY_CLIENT_REQUEST_DIGEST
            ),
            "--proxy-request-digest",
            PROXY_REQUEST_DIGEST,
            "--proxy-operation-digest",
            PROXY_OPERATION_DIGEST,
            "--proxy-tls-channel-binding",
            PROXY_TLS_CHANNEL_BINDING,
        ]
        if proxy_proof_contract == "streaming-v1":
            if proxy_stream_body is None or proxy_max_stream_bytes is None:
                raise AssertionError("streaming verifier fixture requires body path and byte limit")
            proxy_proof_args.extend(
                [
                    "--proxy-stream-body",
                    str(proxy_stream_body),
                    "--proxy-max-stream-bytes",
                    str(proxy_max_stream_bytes),
                    "--proxy-operation-context-digest",
                    PROXY_OPERATION_CONTEXT_DIGEST,
                ]
            )
    hardware_expected_challenge_args: list[str] = []
    if hardware_expected_challenge_mode == "nonce":
        hardware_expected_challenge_args = [
            "--hardware-assurance-expected-challenge-nonce",
            HARDWARE_ASSURANCE_CHALLENGE_NONCE,
        ]
    elif hardware_expected_challenge_mode == "sha256":
        hardware_expected_challenge_args = [
            "--hardware-assurance-expected-challenge-nonce-sha256",
            HARDWARE_ASSURANCE_CHALLENGE_SHA256,
        ]
    elif hardware_expected_challenge_mode is not None:
        raise AssertionError(f"unknown hardware expected challenge mode: {hardware_expected_challenge_mode}")
    hardware_assurance_args = []
    if include_hardware_assurance:
        hardware_assurance_args = [
            "--hardware-assurance",
            str(tmp / "hardware-assurance.json"),
            "--hardware-assurance-trusted-public-key",
            str(tmp / "hardware-assurance-verifier.pub.pem"),
            *hardware_expected_challenge_args,
        ]
    control_plane_response_signing_args: list[str] = []
    if include_control_plane_response_signing_trust_root:
        control_plane_response_signing_args.extend(
            [
                "--control-plane-response-signing-public-key",
                str(tmp / "control-plane-response-signing.pub.pem"),
                "--control-plane-response-signing-public-key-id",
                control_plane_response_signing_key_info()["key_id"],
            ]
        )
    return subprocess.run(
        [
            sys.executable,
            "scripts/verify_release_completion.py",
            *(["--skip-current-host-check"] if allow_host_bypass else []),
            "--production-readiness",
            str(tmp / "production-readiness.json"),
            "--production-readiness-config",
            str(tmp / "production-readiness-config.json"),
            "--production-readiness-env",
            str(tmp / "production.env"),
            "--production-host-preflight",
            str(tmp / "production-host-preflight.json"),
            "--nitro-evidence",
            str(tmp / "nitro-kms-evidence.json"),
            "--production-images-build",
            str(tmp / "production-images-build.json"),
            "--production-images-env",
            str(tmp / "production-images.env"),
            "--production-images-published",
            str(tmp / "production-images-published.json"),
            "--release-provenance-summary",
            str(tmp / "release-provenance-summary.json"),
            "--release-provenance",
            str(tmp / "release-provenance.json"),
            "--release-provenance-trusted-public-key",
            str(tmp / "release-signing.pub.pem"),
            "--image-signatures-summary",
            str(tmp / "image-signatures-summary.json"),
            "--image-signatures",
            str(tmp / "image-signatures.json"),
            "--sigstore-trusted-public-key",
            str(tmp / "sigstore-signing.pub.pem"),
            "--rekor-trusted-public-key",
            str(tmp / "rekor.pub.pem"),
            "--external-checkpoint-provider",
            "managed-prod-log",
            "--external-checkpoint-trusted-public-key",
            str(tmp / "external-checkpoint.pub.pem"),
            "--bench",
            str(tmp / "decision-gate-rs-bench.json"),
            "--policy-bundle",
            str(tmp / "policy-bundle.json"),
            "--policy-trusted-public-key",
            str(tmp / "policy-signing.pub.pem"),
            "--policy-trusted-public-key-id",
            verify_release_completion.release_public_key_id(
                (tmp / "policy-signing.pub.pem").read_text(encoding="ascii")
            ),
            "--policy-identity-verification",
            str(tmp / "production-policy-identity-verification.json"),
            "--policy-activation-verification",
            str(tmp / "policy-activation-verification.json"),
            "--policy-activation-signature",
            str(tmp / "policy-activation-verification.signature.json"),
            "--policy-activation-trusted-public-key",
            str(tmp / "policy-activation-verification.pub.pem"),
            "--policy-activation-trusted-public-key-id",
            verify_release_completion.release_public_key_id(
                (tmp / "policy-activation-verification.pub.pem").read_text(
                    encoding="ascii"
                )
            ),
            "--reproducible-build-verification",
            str(tmp / "reproducible-build-verification.json"),
            "--reproducible-build-signature",
            str(tmp / "reproducible-build-verification.signature.json"),
            "--reproducible-build-trusted-public-key",
            str(tmp / "reproducible-build-verification.pub.pem"),
            "--reproducible-build-trusted-public-key-id",
            verify_release_completion.release_public_key_id(
                (tmp / "reproducible-build-verification.pub.pem").read_text(
                    encoding="ascii"
                )
            ),
            "--kms-materials",
            str(tmp / "kms-materials.json"),
            *control_plane_response_signing_args,
            *proxy_proof_args,
            *hardware_assurance_args,
            *extra,
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace")


def expect_hardware_assurance_failure(
    tmp: Path,
    document: dict[str, Any],
    expected_error: str,
    label: str,
) -> None:
    write(tmp / "hardware-assurance.json", document)
    rejected = run_verifier(tmp, include_hardware_assurance=True)
    if rejected.returncode == 0 or expected_error not in detail(rejected):
        raise AssertionError(f"completion verifier accepted {label}: {detail(rejected)}")


def verify_hardware_assurance_fixture(
    tmp: Path,
    document: dict[str, Any],
    current_host: dict[str, Any],
    *,
    expected_challenge_nonce: str | None = HARDWARE_ASSURANCE_CHALLENGE_NONCE,
    expected_challenge_nonce_sha256: str | None = None,
) -> dict[str, Any]:
    nitro = json.loads((tmp / "nitro-kms-evidence.json").read_text(encoding="utf-8"))
    nitro_summary = verify_release_completion.verify_nitro_evidence(
        nitro,
        "hardware assurance fixture Nitro evidence",
    )
    return verify_release_completion.verify_hardware_assurance(
        document,
        trusted_public_key_pem=hardware_verifier_key_info()["public_key_pem"],
        expected_trusted_public_key_id=hardware_verifier_key_info()["key_id"],
        hardware_assurance_document_sha256=sha256_file(tmp / "hardware-assurance.json"),
        nitro_summary=nitro_summary,
        nitro_evidence_sha256=sha256_file(tmp / "nitro-kms-evidence.json"),
        production_host_preflight_sha256=sha256_file(tmp / "production-host-preflight.json"),
        current_host=current_host,
        expected_release_identity=fixture_release_identity(nitro, tmp),
        expected_challenge_nonce=expected_challenge_nonce,
        expected_challenge_nonce_sha256=expected_challenge_nonce_sha256,
    )


def expect_proxy_proof_failure(
    tmp: Path,
    document: dict[str, Any],
    expected_error: str,
    label: str,
    *extra: str,
) -> None:
    write(tmp / "proxy-response-proof.json", document)
    rejected = run_verifier(tmp, *extra)
    if rejected.returncode == 0 or expected_error not in detail(rejected):
        raise AssertionError(f"completion verifier accepted {label}: {detail(rejected)}")


def verify_streaming_proxy_fixture(
    tmp: Path,
    document: dict[str, Any],
    body: bytes,
    *,
    proof_contract: str = "streaming-v1",
) -> dict[str, Any]:
    body_path = tmp / "proxy-stream-body.bin"
    body_path.write_bytes(body)
    body_snapshot = verify_release_completion.snapshot_regular_file(
        body_path,
        "streaming fixture body",
        max_bytes=verify_release_completion.MAX_PROXY_STREAM_BODY_BYTES,
    )
    policy_snapshot = verify_release_completion.verify_and_compile_policy_snapshot(
        verify_release_completion.snapshot_regular_file(
            tmp / "policy-bundle.json",
            "streaming fixture policy bundle",
            max_bytes=verify_release_completion.POLICY_BUNDLE_MAX_BYTES,
        ),
        verify_release_completion.snapshot_regular_file(
            tmp / "policy-signing.pub.pem",
            "streaming fixture policy trust root",
            max_bytes=verify_release_completion.FINAL_TRUST_ROOT_MAX_BYTES,
        ),
        expected_policy_digest=POLICY_DIGEST,
    )
    return verify_release_completion.verify_production_proxy_response_proof(
        document,
        proof_contract=proof_contract,
        streamed_body_snapshot=body_snapshot if proof_contract == "streaming-v1" else None,
        expected_operation_context_digest=(
            PROXY_OPERATION_CONTEXT_DIGEST
            if proof_contract == "streaming-v1"
            else None
        ),
        trusted_verifier_public_key_pem=proxy_vendor_verifier_key_info()[
            "public_key_pem"
        ],
        trusted_collector_public_key_pem=proxy_collector_key_info()[
            "public_key_pem"
        ],
        trusted_control_plane_response_signing_public_key_pem=(
            control_plane_response_signing_key_info()["public_key_pem"]
        ),
        expected_control_plane_response_signing_public_key_id=(
            control_plane_response_signing_key_info()["key_id"]
        ),
        policy_snapshot=policy_snapshot,
        expected_principal_id=PROXY_PRINCIPAL_ID,
        expected_server_instance_id=PROXY_SERVER_INSTANCE_ID,
        expected_client_nonce=PROXY_CLIENT_NONCE,
        expected_client_request_digest=(
            PROXY_STREAM_CLIENT_REQUEST_DIGEST
            if proof_contract == "streaming-v1"
            else PROXY_CLIENT_REQUEST_DIGEST
        ),
        expected_request_digest=PROXY_REQUEST_DIGEST,
        expected_operation_digest=PROXY_OPERATION_DIGEST,
        expected_tls_channel_binding=PROXY_TLS_CHANNEL_BINDING,
        expected_policy_digest=POLICY_DIGEST,
        expected_runtime_manifest_digest=digest("7"),
        expected_binary_digest=digest("9"),
        expected_release_digest=document[
            "streaming_response_statement"
            if "streaming_response_statement" in document
            else "server_statement"
        ]["release_digest"],
        expected_image_signatures_digest=IMAGE_SIGNATURES_DIGEST,
        expected_source_tree_digest=SOURCE_TREE_DIGEST,
        expected_response_signing_key_id=proxy_response_key_info()["key_id"],
        expected_tee_platform="aws-nitro",
        expected_quote_provider="aws-nitro-enclaves",
        max_age_seconds=300,
    )


def test_streaming_proxy_response_proof_requirements(
    tmp: Path,
    provenance_digest: str,
) -> None:
    valid_document, body = streaming_response_proof(provenance_digest)
    summary = verify_streaming_proxy_fixture(tmp, valid_document, body)
    if (
        summary.get("proof_contract") != "streaming-v1"
        or summary.get("emitted_body_digest") != sha256_prefixed_bytes(body)
        or summary.get("emitted_body_bytes") != len(body)
        or summary.get("released_body_artifact_bound") is not True
    ):
        raise AssertionError(f"streaming completion summary is incomplete: {summary}")

    def reject_streaming(label: str, document: dict[str, Any], candidate_body: bytes, expected: str) -> None:
        try:
            verify_streaming_proxy_fixture(tmp, document, candidate_body)
        except ValueError as exc:
            if expected not in str(exc):
                raise AssertionError(f"streaming rejection for {label} was imprecise: {exc}") from exc
        else:
            raise AssertionError(f"streaming verifier accepted {label}")

    reject_streaming("mutated published body", valid_document, body + b"!", "body digest")
    swapped_body = b"x" * len(body)
    reject_streaming("same-length swapped body", valid_document, swapped_body, "body digest")
    reject_streaming("truncated published body", valid_document, body[:-1], "body digest")

    body_path = tmp / "oversize-stream-body.bin"
    body_path.write_bytes(body)
    try:
        verify_release_completion.snapshot_regular_file(
            body_path,
            "oversize streaming fixture body",
            max_bytes=len(body) - 1,
        )
    except ValueError as exc:
        if "exceeds" not in str(exc):
            raise
    else:
        raise AssertionError("streaming body snapshot accepted bytes above its independent limit")
    symlink_path = tmp / "symlink-stream-body.bin"
    symlink_path.unlink(missing_ok=True)
    symlink_path.symlink_to(body_path)
    try:
        verify_release_completion.snapshot_regular_file(
            symlink_path,
            "symlink streaming fixture body",
            max_bytes=verify_release_completion.MAX_PROXY_STREAM_BODY_BYTES,
        )
    except ValueError as exc:
        if "symlink" not in str(exc) and "without following" not in str(exc):
            raise
    else:
        raise AssertionError("streaming body snapshot followed a substituted symlink")

    try:
        verify_streaming_proxy_fixture(tmp, valid_document, body, proof_contract="buffered-v3")
    except ValueError as exc:
        if "wrong apiVersion" not in str(exc):
            raise
    else:
        raise AssertionError("buffered-v3 contract accepted a streaming-v1 proof downgrade")

    stale_document, stale_body = streaming_response_proof(
        provenance_digest,
        now=int(time.time()) - 600,
    )
    reject_streaming("stale capture", stale_document, stale_body, "stale")

    wrong_identity = clone_document(valid_document)
    wrong_identity["streaming_response_statement"]["server_instance"]["id"] = (
        "spiffe://prod.serverware.dev/decision-gate/substituted"
    )
    wrong_identity["streaming_response_statement"]["server_instance"][
        "identity_digest"
    ] = sha256_prefixed_bytes(
        wrong_identity["streaming_response_statement"]["server_instance"]["id"].encode("utf-8")
    )
    wrong_identity["external_capture"]["tls_peer"]["spiffe_id"] = wrong_identity[
        "streaming_response_statement"
    ]["server_instance"]["id"]
    resign_streaming_response_proof(wrong_identity)
    reject_streaming("server identity substitution", wrong_identity, body, "SPIFFE ID mismatch")

    bad_signature = clone_document(valid_document)
    bad_signature["server_signature"]["signature"] = "ed25519:" + b64e(b"s" * 64)
    bad_signature["external_capture"]["runtime_proof_sha256"] = sha256_prefixed_json(
        {
            "apiVersion": "serverware.streamingResponseRuntimeProof/v1",
            "kind": "ServerwareStreamingResponseRuntimeProof",
            "streaming_response_statement": bad_signature[
                "streaming_response_statement"
            ],
            "streaming_response_statement_sha256": bad_signature[
                "external_capture"
            ]["streaming_response_statement_sha256"],
            "server_signature": bad_signature["server_signature"],
            "vendor_tee": bad_signature["vendor_tee"],
        }
    )
    sign_proxy_external_capture(bad_signature)
    reject_streaming(
        "server signature substitution",
        bad_signature,
        body,
        "signature verification failed",
    )

    for field, replacement, expected_error in (
        ("flow_id", digest("f"), "flow_id claim substitution"),
        (
            "operation_context_digest",
            digest("e"),
            "operation_context_digest claim substitution",
        ),
    ):
        substituted = clone_document(valid_document)
        commitment = substituted["streaming_response_statement"][
            "authorization_binding_validation"
        ]["binding_commitment"]
        commitment[field] = replacement
        substituted["external_capture"]["authorization_binding_commitment"][
            field
        ] = replacement
        resign_streaming_response_proof(substituted)
        reject_streaming(f"authorization binding {field}", substituted, body, expected_error)

    forged_claim = clone_document(valid_document)
    forged_claim["vendor_tee"]["trusted_verifier"]["statement"]["attested_claims"][
        "released_response_body_bytes"
    ] += 1
    sign_proxy_vendor_verifier_statement(forged_claim)
    forged_claim["external_capture"]["runtime_proof_sha256"] = sha256_prefixed_json(
        {
            "apiVersion": "serverware.streamingResponseRuntimeProof/v1",
            "kind": "ServerwareStreamingResponseRuntimeProof",
            "streaming_response_statement": forged_claim[
                "streaming_response_statement"
            ],
            "streaming_response_statement_sha256": forged_claim["external_capture"][
                "streaming_response_statement_sha256"
            ],
            "server_signature": forged_claim["server_signature"],
            "vendor_tee": forged_claim["vendor_tee"],
        }
    )
    sign_proxy_external_capture(forged_claim)
    reject_streaming("vendor attested body binding", forged_claim, body, "attested claims")


def test_streaming_release_completion_cli(
    tmp: Path,
    nitro: dict[str, Any],
    provenance_digest: str,
    buffered_document: dict[str, Any],
) -> None:
    streaming_document, body = streaming_response_proof(provenance_digest)
    body_path = tmp / "proxy-stream-body.bin"
    body_path.write_bytes(body)
    write(tmp / "proxy-response-proof.json", streaming_document)
    write_production_env_files(
        tmp,
        proxy_proof_contract="streaming-v1",
        proxy_client_request_digest=PROXY_STREAM_CLIENT_REQUEST_DIGEST,
        proxy_stream_body=body_path,
        proxy_max_stream_bytes=len(body),
    )
    write_production_config_files(tmp)
    write(tmp / "production-readiness.json", production_readiness(nitro, tmp))
    write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
    accepted = run_verifier(
        tmp,
        proxy_proof_contract="streaming-v1",
        proxy_stream_body=body_path,
        proxy_max_stream_bytes=len(body),
    )
    if accepted.returncode != 0:
        raise AssertionError(
            f"release completion rejected a valid pinned streaming proof: {detail(accepted)}"
        )
    completion = json.loads(accepted.stdout.decode("utf-8"))
    proxy_summary = completion.get("production_proxy_response_proof") or {}
    body_artifact = (completion.get("artifacts") or {}).get("proxy_stream_body") or {}
    if (
        proxy_summary.get("proof_contract") != "streaming-v1"
        or proxy_summary.get("streamed_body_artifact_sha256") != sha256_file(body_path)
        or body_artifact.get("path") != str(body_path)
        or body_artifact.get("sha256") != sha256_file(body_path)
        or completion.get("production_env_binding", {}).get("proxy_proof_contract")
        != "streaming-v1"
    ):
        raise AssertionError(
            f"release completion omitted streaming proof/body/env bindings: {completion}"
        )

    downgraded = run_verifier(tmp)
    if downgraded.returncode == 0 or "proxy proof contract" not in detail(downgraded):
        raise AssertionError(
            "release completion accepted a buffered-v3 CLI downgrade against a streaming-v1 env: "
            + detail(downgraded)
        )
    body_path.write_bytes(body + b"tampered")
    mutated_body = run_verifier(
        tmp,
        proxy_proof_contract="streaming-v1",
        proxy_stream_body=body_path,
        proxy_max_stream_bytes=len(body),
    )
    if mutated_body.returncode == 0 or not any(
        marker in detail(mutated_body) for marker in ("exceeds", "body digest")
    ):
        raise AssertionError(
            "release completion accepted a mutated separately published stream body: "
            + detail(mutated_body)
        )

    write_production_env_files(tmp)
    write_production_config_files(tmp)
    write(tmp / "production-readiness.json", production_readiness(nitro, tmp))
    write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
    write(tmp / "proxy-response-proof.json", buffered_document)


def test_proxy_response_proof_requirements(
    tmp: Path,
    valid_document: dict[str, Any],
    provenance_digest: str,
) -> None:
    missing = run_verifier(tmp, include_proxy_proof=False)
    if missing.returncode == 0 or "production completion requires --proxy-response-proof" not in detail(missing):
        raise AssertionError(f"completion verifier accepted absent proxy proof evidence: {detail(missing)}")

    retired_receipt_cli = run_verifier(
        tmp,
        "--control-plane-authorization-receipt",
        str(tmp / "retired-detached-receipt.json"),
    )
    if (
        retired_receipt_cli.returncode == 0
        or "unrecognized arguments: --control-plane-authorization-receipt"
        not in detail(retired_receipt_cli)
    ):
        raise AssertionError(
            "completion verifier still exposes a detached control-plane authorization receipt CLI: "
            + detail(retired_receipt_cli)
        )

    missing_response_signing_trust = run_verifier(
        tmp, include_control_plane_response_signing_trust_root=False
    )
    if (
        missing_response_signing_trust.returncode == 0
        or "requires --control-plane-response-signing-public-key"
        not in detail(missing_response_signing_trust)
    ):
        raise AssertionError(
            "completion verifier accepted an embedded receipt without its independent response trust root: "
            + detail(missing_response_signing_trust)
        )

    valid_document = proxy_response_proof(provenance_digest)
    valid_receipt = clone_document(
        valid_document["server_statement"]["control_plane_authorization_receipt"]
    )
    quota_window_start = (int(time.time()) // 3600) * 3_600_000
    shared_quota = {
        "counter_key": digest("c"),
        "constraint_id": "quota:test",
        "operation": "demo.echo",
        "window_kind": "fixed",
        "window_seconds": 3600,
        "max_count": 5,
    }
    dispatch_quota = {
        "counterKey": shared_quota["counter_key"],
        "constraintId": shared_quota["constraint_id"],
        "operation": shared_quota["operation"],
        "windowStartEpochMs": quota_window_start,
        "windowSeconds": shared_quota["window_seconds"],
        "max": shared_quota["max_count"],
        "count": 1,
        "remaining": 4,
        "reservationState": "reserved",
    }
    current_dispatch_quota = {
        **dispatch_quota,
        "windowKind": "fixed",
        "windowEndEpochMs": quota_window_start + 3_600_000,
    }
    for quota_label, quota in (
        ("legacy fixed", dispatch_quota),
        ("current fixed", current_dispatch_quota),
    ):
        quota_document = proxy_response_proof(
            provenance_digest,
            shared_quotas=[shared_quota],
            dispatch_quotas=[quota],
        )
        write(tmp / "proxy-response-proof.json", quota_document)
        accepted_quota = run_verifier(tmp)
        if accepted_quota.returncode != 0:
            raise AssertionError(
                f"completion verifier rejected a valid {quota_label} quota receipt: "
                + detail(accepted_quota)
            )

    forged_receipt = clone_document(valid_receipt)
    forged_receipt["response"]["signature"] = "ed25519:" + b64e(b"x" * 64)
    forged_receipt_proof = clone_document(valid_document)
    replace_embedded_control_plane_receipt(forged_receipt_proof, forged_receipt)
    expect_proxy_proof_failure(
        tmp,
        forged_receipt_proof,
        "control-plane authorization receipt signature verification failed",
        "an embedded receipt with a forged control-plane response signature",
    )
    unexpected_receipt_field = clone_document(valid_receipt)
    unexpected_receipt_field["request"]["completion_outcome"] = "forwarded"
    unexpected_receipt_proof = clone_document(valid_document)
    replace_embedded_control_plane_receipt(
        unexpected_receipt_proof,
        unexpected_receipt_field,
    )
    expect_proxy_proof_failure(
        tmp,
        unexpected_receipt_proof,
        "control-plane authorization receipt request fields do not match the contract",
        "an embedded receipt with an unexpected nested request field",
    )

    substituted_request_body_receipt = clone_document(valid_receipt)
    substituted_request_body = {
        "apiVersion": "serverware.releaseAuthorizationDispatch/v1",
        "attemptId": digest("0"),
        "bindingDigest": substituted_request_body_receipt["release_authority"][
            "consumption_identity_digest"
        ],
    }
    substituted_request_body_bytes = canonical_json(substituted_request_body).encode(
        "utf-8"
    )
    substituted_request_body_receipt["request"]["body_b64"] = b64e(
        substituted_request_body_bytes
    )
    substituted_request_body_receipt["request"]["body_sha256"] = sha256_prefixed_bytes(
        substituted_request_body_bytes
    )
    substituted_request_body_proof = clone_document(valid_document)
    replace_embedded_control_plane_receipt(
        substituted_request_body_proof,
        substituted_request_body_receipt,
    )
    expect_proxy_proof_failure(
        tmp,
        substituted_request_body_proof,
        "control-plane authorization receipt dispatch request body mismatch",
        "an embedded receipt with a substituted exact dispatch request body",
    )

    substituted_context_receipt = clone_document(valid_receipt)
    substituted_context_statement = json.loads(
        b64d(substituted_context_receipt["response"]["statement_b64"]).decode(
            "utf-8"
        )
    )
    substituted_context_statement["context"]["policy_bundle_digest"] = digest("0")
    substituted_context_receipt["response"]["statement_b64"] = b64e(
        canonical_json(substituted_context_statement).encode("utf-8")
    )
    resign_control_plane_authorization_receipt(substituted_context_receipt)
    substituted_context_proof = clone_document(valid_document)
    replace_embedded_control_plane_receipt(
        substituted_context_proof,
        substituted_context_receipt,
    )
    expect_proxy_proof_failure(
        tmp,
        substituted_context_proof,
        "control-plane authorization receipt signed response attested context mismatch",
        "an independently re-signed receipt with substituted attested context",
    )

    substituted_key_receipt = clone_document(valid_receipt)
    resign_control_plane_authorization_receipt(
        substituted_key_receipt,
        alternate_control_plane_response_signing_key_info(),
    )
    substituted_key_proof = clone_document(valid_document)
    replace_embedded_control_plane_receipt(
        substituted_key_proof,
        substituted_key_receipt,
    )
    expect_proxy_proof_failure(
        tmp,
        substituted_key_proof,
        "not signed by the independently trusted control-plane response key",
        "an embedded receipt signed by a substituted response key",
    )

    historical_receipt_proof = clone_document(valid_document)
    historical_start_ms = (int(time.time()) - 120) * 1000
    historical_dispatch_expiry_ms = historical_start_ms + 10_000
    historical_reservation_expiry_ms = historical_start_ms + 20_000
    for authority in (
        historical_receipt_proof["external_capture"]["release_authority"],
        historical_receipt_proof["server_statement"]["release_authority"],
    ):
        authority["authorization_state_observed_at_epoch_ms"] = historical_start_ms
        authority["dispatch_expires_at_epoch_ms"] = historical_dispatch_expiry_ms
        authority["reservation_expires_at_epoch_ms"] = historical_reservation_expiry_ms
    historical_receipt = clone_document(valid_receipt)
    historical_receipt["release_authority"] = clone_document(
        historical_receipt_proof["server_statement"]["release_authority"]
    )
    historical_response_body = json.loads(
        b64d(historical_receipt["response"]["body_b64"]).decode("utf-8")
    )
    historical_response_body["dispatchStartedAtEpochMs"] = historical_start_ms
    historical_response_body["dispatchExpiresAtEpochMs"] = historical_dispatch_expiry_ms
    historical_response_body[
        "reservationExpiresAtEpochMs"
    ] = historical_reservation_expiry_ms
    replace_control_plane_receipt_response_body(
        historical_receipt,
        historical_response_body,
        issued_at_ms=historical_start_ms + 1,
    )
    replace_embedded_control_plane_receipt(
        historical_receipt_proof,
        historical_receipt,
    )
    write(tmp / "proxy-response-proof.json", historical_receipt_proof)
    historical_result = run_verifier(tmp)
    if historical_result.returncode != 0:
        raise AssertionError(
            "completion verifier rejected a historically valid expired dispatch window: "
            + detail(historical_result)
        )

    for body_field, authority_field, expected_error in (
        (
            "dispatchExpiresAtEpochMs",
            "dispatch_expires_at_epoch_ms",
            "signed response was issued at or after dispatch expiry",
        ),
        (
            "reservationExpiresAtEpochMs",
            "reservation_expires_at_epoch_ms",
            "signed response was issued at or after reservation expiry",
        ),
    ):
        exact_expiry_proof = clone_document(valid_document)
        exact_expiry_receipt = clone_document(valid_receipt)
        exact_expiry_body = json.loads(
            b64d(exact_expiry_receipt["response"]["body_b64"]).decode("utf-8")
        )
        exact_issue_ms = exact_expiry_body["dispatchStartedAtEpochMs"] + 1
        exact_expiry_body[body_field] = exact_issue_ms
        for authority in (
            exact_expiry_proof["external_capture"]["release_authority"],
            exact_expiry_proof["server_statement"]["release_authority"],
        ):
            authority[authority_field] = exact_issue_ms
        exact_expiry_receipt["release_authority"] = clone_document(
            exact_expiry_proof["server_statement"]["release_authority"]
        )
        replace_control_plane_receipt_response_body(
            exact_expiry_receipt,
            exact_expiry_body,
            issued_at_ms=exact_issue_ms,
        )
        replace_embedded_control_plane_receipt(
            exact_expiry_proof,
            exact_expiry_receipt,
        )
        expect_proxy_proof_failure(
            tmp,
            exact_expiry_proof,
            expected_error,
            f"a signed response issued exactly at {body_field}",
        )

    valid_document = proxy_response_proof(provenance_digest)

    wrong_version = clone_document(valid_document)
    wrong_version["apiVersion"] = "serverware.proxyResponseProof/v2"
    expect_proxy_proof_failure(
        tmp,
        wrong_version,
        "proxy response proof has wrong apiVersion",
        "a legacy v2 proxy proof without mandatory release authority",
    )

    wrong_capture_version = clone_document(valid_document)
    wrong_capture_version["external_capture"]["apiVersion"] = "serverware.proxyResponseCapture/v1"
    expect_proxy_proof_failure(
        tmp,
        wrong_capture_version,
        "external capture has wrong apiVersion",
        "a proxy proof with a legacy external capture",
    )

    tampered_client_request = clone_document(valid_document)
    tampered_client_request["external_capture"]["client_request_digest"] = digest("0")
    sign_proxy_external_capture(tampered_client_request)
    expect_proxy_proof_failure(
        tmp,
        tampered_client_request,
        "does not match the independently supplied client commitment",
        "a collector-signed capture with a tampered client request digest",
    )

    substituted_route = clone_document(valid_document)
    substituted_route["external_capture"]["route_id"] = "demo.echo.substituted"
    sign_proxy_external_capture(substituted_route)
    expect_proxy_proof_failure(
        tmp,
        substituted_route,
        "route identity is absent or ambiguous in the signed policy",
        "a collector-signed route ID substitution",
    )

    cross_principal = clone_document(valid_document)
    for proof_section in (
        cross_principal["external_capture"],
        cross_principal["server_statement"],
    ):
        proof_section["principal_id"] = ALTERNATE_PROXY_PRINCIPAL_ID
        proof_section["control_plane_authorization_receipt"][
            "principal_id"
        ] = ALTERNATE_PROXY_PRINCIPAL_ID
    resign_proxy_response_proof(cross_principal)
    expect_proxy_proof_failure(
        tmp,
        cross_principal,
        "external capture principal ID does not match the independently configured expected proxy principal",
        "a collector-signed proof for a different policy-authorized principal",
    )

    wrong_statement_version = clone_document(valid_document)
    wrong_statement_version["server_statement"]["apiVersion"] = "serverware.proxyResponseStatement/v1"
    resign_proxy_response_proof(wrong_statement_version)
    expect_proxy_proof_failure(
        tmp,
        wrong_statement_version,
        "server statement has wrong apiVersion",
        "a proxy proof with a legacy server statement",
    )

    development = clone_document(valid_document)
    development["external_capture"]["environment"] = "development"
    expect_proxy_proof_failure(tmp, development, "is not production evidence", "development proxy capture")

    self_reported = clone_document(valid_document)
    self_reported["external_capture"]["collection_mode"] = "rust-self-report"
    expect_proxy_proof_failure(tmp, self_reported, "absent, dev, or self-reported", "Rust self-reported proxy capture")

    self_reported_statement = clone_document(valid_document)
    self_reported_statement["server_statement"]["collection_mode"] = "server-self-reported"
    resign_proxy_response_proof(self_reported_statement)
    expect_proxy_proof_failure(
        tmp,
        self_reported_statement,
        "server statement fields do not match the contract",
        "a self-reported field smuggled into the server statement",
    )

    valid_document = proxy_response_proof(provenance_digest)

    missing_server_signature = clone_document(valid_document)
    missing_server_signature["server_signature"] = {}
    expect_proxy_proof_failure(
        tmp,
        missing_server_signature,
        "server signature fields do not match the contract",
        "a proxy statement without a server signature",
    )

    untrusted_collector = clone_document(valid_document)
    sign_proxy_external_capture(untrusted_collector, alternate_proxy_collector_key_info())
    expect_proxy_proof_failure(
        tmp,
        untrusted_collector,
        "collector signing key does not match the configured trust root",
        "an external capture signed by an untrusted collector",
    )

    tampered_signed_capture = clone_document(valid_document)
    tampered_signed_capture["external_capture"]["tls_peer"]["leaf_certificate_sha256"] = digest("b")
    expect_proxy_proof_failure(
        tmp,
        tampered_signed_capture,
        "external capture collector signature verification failed",
        "an external capture changed after collector signing",
    )

    unsigned_headers = clone_document(valid_document)
    unsigned_headers["external_capture"]["response"]["selected_headers"]["x-serverware-request-id"] = "tampered"
    expect_proxy_proof_failure(
        tmp,
        unsigned_headers,
        "selected response headers digest mismatch",
        "tampered external capture headers",
    )

    missing_selected_header = clone_document(valid_document)
    missing_headers = missing_selected_header["external_capture"]["response"]["selected_headers"]
    del missing_headers["content-length"]
    missing_selected_header["external_capture"]["response"]["selected_headers_digest"] = sha256_prefixed_json(
        missing_headers
    )
    sign_proxy_external_capture(missing_selected_header)
    expect_proxy_proof_failure(
        tmp,
        missing_selected_header,
        "missing required selected response headers",
        "a collector-signed capture missing content-length",
    )

    extra_selected_header = clone_document(valid_document)
    extra_headers = extra_selected_header["external_capture"]["response"]["selected_headers"]
    extra_headers["x-serverware-request-id"] = "unexpected"
    extra_selected_header["external_capture"]["response"]["selected_headers_digest"] = sha256_prefixed_json(
        extra_headers
    )
    sign_proxy_external_capture(extra_selected_header)
    expect_proxy_proof_failure(
        tmp,
        extra_selected_header,
        "unexpected selected response headers",
        "a collector-signed capture with an extra selected header",
    )

    capture_body_mismatch = clone_document(valid_document)
    capture_body_mismatch["external_capture"]["response"]["body_digest"] = digest("0")
    capture_body_headers = capture_body_mismatch["external_capture"]["response"]["selected_headers"]
    capture_body_headers["x-serverware-response-body-sha256"] = digest("0")
    capture_body_mismatch["external_capture"]["response"]["selected_headers_digest"] = sha256_prefixed_json(
        capture_body_headers
    )
    sign_proxy_external_capture(capture_body_mismatch)
    expect_proxy_proof_failure(
        tmp,
        capture_body_mismatch,
        "external capture response does not match server statement",
        "an external response body that differs from the server statement",
    )

    capture_statement_digest_mismatch = clone_document(valid_document)
    capture_statement_digest_mismatch["external_capture"]["server_statement_sha256"] = digest("0")
    sign_proxy_external_capture(capture_statement_digest_mismatch)
    expect_proxy_proof_failure(
        tmp,
        capture_statement_digest_mismatch,
        "external capture server statement digest mismatch",
        "an external capture bound to another server statement",
    )

    invalid_tls_peer_leaf_digest = clone_document(valid_document)
    invalid_tls_peer_leaf_digest["external_capture"]["tls_peer"]["leaf_certificate_sha256"] = "invalid"
    sign_proxy_external_capture(invalid_tls_peer_leaf_digest)
    expect_proxy_proof_failure(
        tmp,
        invalid_tls_peer_leaf_digest,
        "TLS peer leaf certificate digest must be a sha256-prefixed digest",
        "an external capture with an invalid TLS peer certificate digest",
    )

    mismatched_tls_peer = clone_document(valid_document)
    mismatched_tls_peer["external_capture"]["tls_peer"]["spiffe_id"] = (
        "spiffe://prod.serverware.dev/decision-gate/instance-02"
    )
    sign_proxy_external_capture(mismatched_tls_peer)
    expect_proxy_proof_failure(
        tmp,
        mismatched_tls_peer,
        "TLS peer SPIFFE ID does not match expected server instance",
        "a collector-signed capture from another TLS peer",
    )

    forged_server_signature = clone_document(valid_document)
    forged_server_signature["server_signature"]["signature"] = "ed25519:AAAA"
    expect_proxy_proof_failure(
        tmp,
        forged_server_signature,
        "server statement signature must decode to exactly 64 bytes",
        "a forged proxy server statement signature",
    )

    mismatched_server_key_id = clone_document(valid_document)
    mismatched_server_key_id["server_signature"]["key_id"] = digest("0")
    expect_proxy_proof_failure(
        tmp,
        mismatched_server_key_id,
        "server statement signing key id mismatch",
        "a server signature with an unrelated key id",
    )

    stale = proxy_response_proof(provenance_digest, now=int(time.time()) - 600)
    expect_proxy_proof_failure(tmp, stale, "external capture is stale", "a stale external proxy capture")

    stale_statement = clone_document(valid_document)
    stale_statement["server_statement"]["issued_at_unix"] = int(time.time()) - 600
    resign_proxy_response_proof(stale_statement)
    expect_proxy_proof_failure(tmp, stale_statement, "server statement is stale", "a stale server statement")

    # This suite runs the full verifier for every case. Refresh the valid base
    # between groups so unrelated negative cases do not age past the 300s gate.
    valid_document = proxy_response_proof(provenance_digest)

    unsuccessful = clone_document(valid_document)
    unsuccessful["external_capture"]["response"]["status"] = 503
    unsuccessful["server_statement"]["response"]["status"] = 503
    resign_proxy_response_proof(unsuccessful)
    expect_proxy_proof_failure(tmp, unsuccessful, "successful production response status", "a failed proxy response")

    bad_header_digest = clone_document(valid_document)
    bad_header_digest["external_capture"]["response"]["selected_headers_digest"] = digest("0")
    bad_header_digest["server_statement"]["response"]["selected_headers_digest"] = digest("0")
    resign_proxy_response_proof(bad_header_digest)
    expect_proxy_proof_failure(
        tmp,
        bad_header_digest,
        "selected response headers digest mismatch",
        "a signed but incorrect selected response headers digest",
    )

    for field, expected_error in (
        ("policy_digest", "proxy response server statement policy digest mismatch"),
        ("runtime_manifest_digest", "proxy response server statement runtime manifest digest mismatch"),
        ("data_plane_binary_digest", "proxy response server statement data plane binary digest mismatch"),
        ("release_digest", "proxy response server statement release digest mismatch"),
    ):
        mismatched = clone_document(valid_document)
        mismatched["server_statement"][field] = digest("0")
        resign_proxy_response_proof(mismatched)
        expect_proxy_proof_failure(tmp, mismatched, expected_error, f"a proxy proof with a mismatched {field}")

    bad_instance = clone_document(valid_document)
    bad_instance["server_statement"]["server_instance"]["identity_digest"] = digest("0")
    resign_proxy_response_proof(bad_instance)
    expect_proxy_proof_failure(
        tmp,
        bad_instance,
        "server instance identity digest mismatch",
        "a mismatched server instance identity",
    )

    mismatched_nonce = clone_document(valid_document)
    mismatched_nonce["server_statement"]["client_nonce"] = b64e(b"s" * 32)
    resign_proxy_response_proof(mismatched_nonce)
    expect_proxy_proof_failure(
        tmp,
        mismatched_nonce,
        "external capture client_nonce does not match server statement",
        "a client nonce mismatch between capture and statement",
    )

    mismatched_request = clone_document(valid_document)
    mismatched_request["server_statement"]["request_digest"] = digest("0")
    resign_proxy_response_proof(mismatched_request)
    expect_proxy_proof_failure(
        tmp,
        mismatched_request,
        "external capture request_digest does not match server statement",
        "a request digest mismatch between capture and statement",
    )

    mismatched_operation = clone_document(valid_document)
    mismatched_operation["server_statement"]["operation_digest"] = digest("0")
    resign_proxy_response_proof(mismatched_operation)
    expect_proxy_proof_failure(
        tmp,
        mismatched_operation,
        "external capture operation_digest does not match server statement",
        "an operation digest mismatch between capture and statement",
    )

    missing_release_authority = clone_document(valid_document)
    del missing_release_authority["server_statement"]["release_authority"]
    resign_proxy_response_proof(
        missing_release_authority,
        sync_attested_claims=False,
    )
    expect_proxy_proof_failure(
        tmp,
        missing_release_authority,
        "server statement fields do not match the contract",
        "a signed v3 statement without release authority",
    )

    cross_wired_authority = clone_document(valid_document)
    cross_wired_authority["server_statement"]["release_authority"]["grant_id"] = "grant:other"
    resign_proxy_response_proof(cross_wired_authority)
    expect_proxy_proof_failure(
        tmp,
        cross_wired_authority,
        "external capture release authority does not match server statement",
        "a grant identity cross-wired between the collector and server statement",
    )

    double_substitution = clone_document(valid_document)
    for authority in (
        double_substitution["external_capture"]["release_authority"],
        double_substitution["server_statement"]["release_authority"],
    ):
        authority["grant_id"] = "grant:substituted"
    resign_proxy_response_proof(double_substitution)
    expect_proxy_proof_failure(
        tmp,
        double_substitution,
        "control-plane authorization receipt release authority mismatch",
        "a double substitution with both capture and statement changed and every internal proof signature refreshed",
    )

    for field, replacement, expected_error in (
        ("request_digest", digest("0"), "release authority request digest mismatch"),
        ("operation_digest", digest("0"), "release authority operation digest mismatch"),
        ("attempt_id", "not-a-digest", "attempt ID must be a sha256-prefixed digest"),
        (
            "consumption_identity_digest",
            "not-a-digest",
            "consumption identity digest must be a sha256-prefixed digest",
        ),
        (
            "authorization_state_at_upstream_dispatch",
            "forwarded",
            "does not prove historical dispatch authorization",
        ),
    ):
        invalid_authority = clone_document(valid_document)
        invalid_authority["server_statement"]["release_authority"][field] = replacement
        invalid_authority["external_capture"]["release_authority"][field] = replacement
        resign_proxy_response_proof(invalid_authority)
        expect_proxy_proof_failure(
            tmp,
            invalid_authority,
            expected_error,
            f"a v3 proof with invalid release authority {field}",
        )

    premature_completion_claim = clone_document(valid_document)
    for authority in (
        premature_completion_claim["server_statement"]["release_authority"],
        premature_completion_claim["external_capture"]["release_authority"],
    ):
        authority["completion_outcome"] = "forwarded"
    resign_proxy_response_proof(premature_completion_claim)
    expect_proxy_proof_failure(
        tmp,
        premature_completion_claim,
        "release authority fields do not match the contract",
        "an inline proof that overclaims downstream response completion",
    )

    future_dispatch_observation = clone_document(valid_document)
    future_observed_at = (int(time.time()) + 60) * 1000
    for authority in (
        future_dispatch_observation["server_statement"]["release_authority"],
        future_dispatch_observation["external_capture"]["release_authority"],
    ):
        authority["authorization_state_observed_at_epoch_ms"] = future_observed_at
        authority["reservation_expires_at_epoch_ms"] = future_observed_at + 15_000
        authority["dispatch_expires_at_epoch_ms"] = future_observed_at + 15_000
    resign_proxy_response_proof(future_dispatch_observation)
    expect_proxy_proof_failure(
        tmp,
        future_dispatch_observation,
        "dispatch observation postdates the enclosing proof event",
        "a historical dispatch observation recorded after proof issuance",
    )

    head_request = clone_document(valid_document)
    head_request["external_capture"]["client_request"] = {
        "method": "HEAD",
        "authorization": "must-not-be-persisted",
    }
    resign_proxy_response_proof(head_request)
    expect_proxy_proof_failure(
        tmp,
        head_request,
        "proxy response external capture fields do not match the contract",
        "a proof artifact that persists raw client request material",
    )

    inconsistent_grant = clone_document(valid_document)
    inconsistent_grant["server_statement"]["release_authority"]["approval_id"] = None
    inconsistent_grant["external_capture"]["release_authority"]["approval_id"] = None
    resign_proxy_response_proof(inconsistent_grant)
    expect_proxy_proof_failure(
        tmp,
        inconsistent_grant,
        "grant and approval identities are inconsistent",
        "a grant-backed proof without its approval identity",
    )

    credential_version_mismatch = clone_document(valid_document)
    credential_version_mismatch["server_statement"]["release_authority"]["credential_version"] = 0
    credential_version_mismatch["external_capture"]["release_authority"]["credential_version"] = 0
    resign_proxy_response_proof(credential_version_mismatch)
    expect_proxy_proof_failure(
        tmp,
        credential_version_mismatch,
        "credential identity and version are inconsistent",
        "a credential-backed proof without a positive credential version",
    )

    valid_document = proxy_response_proof(provenance_digest)

    cross_wired_upstream = clone_document(valid_document)
    cross_wired_server_response = cross_wired_upstream["server_statement"][
        "upstream_response"
    ]
    cross_wired_server_response["body_digest"] = digest("0")
    cross_wired_server_response["canonical_digest"] = sha256_prefixed_json(
        {
            "status": cross_wired_server_response["status"],
            "selected_raw_policy_headers_b64": cross_wired_server_response[
                "selected_raw_policy_headers_b64"
            ],
            "body_digest": cross_wired_server_response["body_digest"],
        }
    )
    resign_proxy_response_proof(cross_wired_upstream)
    expect_proxy_proof_failure(
        tmp,
        cross_wired_upstream,
        "external capture upstream response does not match server statement",
        "an upstream body digest cross-wired between the collector and server statement",
    )

    tampered_raw_upstream_header = clone_document(valid_document)
    for upstream in (
        tampered_raw_upstream_header["server_statement"]["upstream_response"],
        tampered_raw_upstream_header["external_capture"]["upstream_response"],
    ):
        upstream["selected_raw_policy_headers_b64"]["content-type"] = [
            b64e(b"text/plain")
        ]
    resign_proxy_response_proof(tampered_raw_upstream_header)
    expect_proxy_proof_failure(
        tmp,
        tampered_raw_upstream_header,
        "upstream response canonical digest mismatch",
        "raw upstream policy headers changed without the canonical binding",
    )

    omitted_raw_upstream_header = clone_document(valid_document)
    for upstream in (
        omitted_raw_upstream_header["server_statement"]["upstream_response"],
        omitted_raw_upstream_header["external_capture"]["upstream_response"],
    ):
        del upstream["selected_raw_policy_headers_b64"]["content-encoding"]
        upstream["canonical_digest"] = sha256_prefixed_json(
            {
                "status": upstream["status"],
                "selected_raw_policy_headers_b64": upstream[
                    "selected_raw_policy_headers_b64"
                ],
                "body_digest": upstream["body_digest"],
            }
        )
    resign_proxy_response_proof(omitted_raw_upstream_header)
    expect_proxy_proof_failure(
        tmp,
        omitted_raw_upstream_header,
        "raw policy header names do not exactly match the signed route success profile",
        "a fully re-signed proof omitting a mandatory raw response header",
    )

    wrong_upstream_status = clone_document(valid_document)
    wrong_upstream_status["server_statement"]["upstream_response"]["status"] = 503
    wrong_upstream_status["external_capture"]["upstream_response"]["status"] = 503
    resign_proxy_response_proof(wrong_upstream_status)
    expect_proxy_proof_failure(
        tmp,
        wrong_upstream_status,
        "upstream response status mismatch",
        "a proof whose upstream status differs from the released response",
    )

    mismatched_response = clone_document(valid_document)
    mismatched_response["server_statement"]["response"]["body_digest"] = digest("0")
    resign_proxy_response_proof(mismatched_response)
    expect_proxy_proof_failure(
        tmp,
        mismatched_response,
        "external capture response does not match server statement",
        "a response mismatch between capture and statement",
    )

    mismatched_tls = clone_document(valid_document)
    mismatched_tls["server_statement"]["tls_channel_binding"]["value"] = b64e(b"s" * 32)
    resign_proxy_response_proof(mismatched_tls)
    expect_proxy_proof_failure(
        tmp,
        mismatched_tls,
        "external capture tls_channel_binding does not match server statement",
        "a TLS channel mismatch between capture and statement",
    )

    valid_document = proxy_response_proof(provenance_digest)

    missing_quote = clone_document(valid_document)
    missing_quote["vendor_tee"]["quote"] = None
    expect_proxy_proof_failure(tmp, missing_quote, "missing a non-null vendor TEE quote", "a null vendor TEE quote")

    tampered_quote = clone_document(valid_document)
    tampered_quote["vendor_tee"]["quote"]["body_b64"] = b64e(b"tampered opaque vendor quote bytes " * 4)
    expect_proxy_proof_failure(tmp, tampered_quote, "vendor quote digest mismatch", "an unsigned vendor quote")

    development_quote = clone_document(valid_document)
    development_quote["vendor_tee"]["provider"] = "dev-self-reported"
    resign_proxy_response_proof(development_quote)
    expect_proxy_proof_failure(tmp, development_quote, "not a production identifier", "a development TEE provider")

    missing_verifier = clone_document(valid_document)
    missing_verifier["vendor_tee"]["trusted_verifier"] = {}
    expect_proxy_proof_failure(
        tmp,
        missing_verifier,
        "vendor verifier result has wrong apiVersion",
        "a vendor quote without a trusted verifier outcome",
    )

    rejected_outcome = clone_document(valid_document)
    rejected_outcome["vendor_tee"]["trusted_verifier"]["statement"]["outcome"] = "rejected"
    sign_proxy_vendor_verifier_statement(rejected_outcome)
    expect_proxy_proof_failure(tmp, rejected_outcome, "outcome is not verified", "a rejected vendor verifier outcome")

    unverified_quote = clone_document(valid_document)
    unverified_quote["vendor_tee"]["trusted_verifier"]["statement"]["vendor_quote_verified"] = False
    sign_proxy_vendor_verifier_statement(unverified_quote)
    expect_proxy_proof_failure(tmp, unverified_quote, "vendor quote was not verified", "an unverified vendor quote")

    unchecked_revocation = clone_document(valid_document)
    unchecked_revocation["vendor_tee"]["trusted_verifier"]["statement"]["revocation_checked"] = False
    sign_proxy_vendor_verifier_statement(unchecked_revocation)
    expect_proxy_proof_failure(
        tmp,
        unchecked_revocation,
        "revocation status was not checked",
        "a vendor receipt without revocation checking",
    )

    debug_quote = clone_document(valid_document)
    debug_quote["vendor_tee"]["trusted_verifier"]["statement"]["debug"] = True
    sign_proxy_vendor_verifier_statement(debug_quote)
    expect_proxy_proof_failure(tmp, debug_quote, "accepted debug mode", "a debug-mode vendor quote")

    forged_verifier = clone_document(valid_document)
    forged_verifier["vendor_tee"]["trusted_verifier"]["signature"] = "ed25519:AAAA"
    expect_proxy_proof_failure(
        tmp,
        forged_verifier,
        "trusted vendor verifier signature must decode to exactly 64 bytes",
        "a forged vendor verifier receipt",
    )

    untrusted_verifier = clone_document(valid_document)
    resign_proxy_response_proof(
        untrusted_verifier,
        verifier_key_info=alternate_proxy_vendor_verifier_key_info(),
    )
    expect_proxy_proof_failure(
        tmp,
        untrusted_verifier,
        "verifier key is not the configured trust root",
        "a verifier receipt signed by an untrusted key",
    )

    legacy_verifier_binding = clone_document(valid_document)
    legacy_verifier_statement = legacy_verifier_binding["vendor_tee"]["trusted_verifier"]["statement"]
    legacy_verifier_statement["proof_evidence_sha256"] = legacy_verifier_statement.pop("server_statement_sha256")
    sign_proxy_vendor_verifier_statement(legacy_verifier_binding)
    expect_proxy_proof_failure(
        tmp,
        legacy_verifier_binding,
        "legacy proof evidence digest binding",
        "a vendor verifier receipt using the v1 evidence binding",
    )

    mismatched_response_key = clone_document(valid_document)
    mismatched_response_key["vendor_tee"]["trusted_verifier"]["statement"]["response_signing_key_id"] = digest("0")
    sign_proxy_vendor_verifier_statement(mismatched_response_key)
    expect_proxy_proof_failure(
        tmp,
        mismatched_response_key,
        "did not bind the response signing key",
        "a vendor receipt bound to another response signing key",
    )

    mismatched_claim = clone_document(valid_document)
    mismatched_claim["vendor_tee"]["trusted_verifier"]["statement"]["attested_claims"]["request_digest"] = digest("0")
    sign_proxy_vendor_verifier_statement(mismatched_claim)
    expect_proxy_proof_failure(
        tmp,
        mismatched_claim,
        "attested claim request_digest mismatch",
        "a vendor quote that did not attest the request digest",
    )

    missing_claim = clone_document(valid_document)
    del missing_claim["vendor_tee"]["trusted_verifier"]["statement"]["attested_claims"]["issued_at_unix"]
    sign_proxy_vendor_verifier_statement(missing_claim)
    expect_proxy_proof_failure(
        tmp,
        missing_claim,
        "attested claim issued_at_unix mismatch",
        "a vendor receipt missing a server statement claim",
    )

    extra_claim = clone_document(valid_document)
    extra_claim["vendor_tee"]["trusted_verifier"]["statement"]["attested_claims"]["self_reported"] = True
    sign_proxy_vendor_verifier_statement(extra_claim)
    expect_proxy_proof_failure(
        tmp,
        extra_claim,
        "attested claims do not exactly match the server statement",
        "a vendor receipt with an unbound self-reported claim",
    )

    expired_verifier = clone_document(valid_document)
    expired_verifier["vendor_tee"]["trusted_verifier"]["statement"]["verified_at_unix"] = int(time.time()) - 100
    expired_verifier["vendor_tee"]["trusted_verifier"]["statement"]["expires_at_unix"] = int(time.time()) - 1
    sign_proxy_vendor_verifier_statement(expired_verifier)
    expect_proxy_proof_failure(
        tmp,
        expired_verifier,
        "trusted vendor verifier receipt is expired",
        "an expired vendor verifier receipt",
    )

    write(tmp / "proxy-response-proof.json", valid_document)
    wrong_nonce = b64e(b"x" * 32)
    rejected_nonce = run_verifier(tmp, "--proxy-client-nonce", wrong_nonce)
    if rejected_nonce.returncode == 0 or "client nonce mismatch" not in detail(rejected_nonce):
        raise AssertionError(f"completion verifier accepted a proof for another client nonce: {detail(rejected_nonce)}")
    rejected_request = run_verifier(tmp, "--proxy-request-digest", digest("0"))
    if rejected_request.returncode == 0 or "canonical request digest mismatch" not in detail(rejected_request):
        raise AssertionError(f"completion verifier accepted a proof for another request: {detail(rejected_request)}")
    rejected_operation = run_verifier(tmp, "--proxy-operation-digest", digest("0"))
    if rejected_operation.returncode == 0 or "operation digest mismatch" not in detail(rejected_operation):
        raise AssertionError(f"completion verifier accepted a proof for another operation: {detail(rejected_operation)}")
    rejected_tls = run_verifier(tmp, "--proxy-tls-channel-binding", b64e(b"z" * 32))
    if rejected_tls.returncode == 0 or "TLS channel binding mismatch" not in detail(rejected_tls):
        raise AssertionError(f"completion verifier accepted a proof from another TLS channel: {detail(rejected_tls)}")

    prefix_only_spiffe = "spiffe://prod.serverware.dev/decision-gate"
    rejected_instance = run_verifier(tmp, "--proxy-server-instance-id", prefix_only_spiffe)
    instance_error = detail(rejected_instance)
    if rejected_instance.returncode == 0 or not any(
        message in instance_error
        for message in (
            "proxy response expected server instance does not match the signed production environment",
            "TLS peer SPIFFE ID does not match expected server instance",
        )
    ):
        raise AssertionError(
            f"completion verifier accepted a prefix-only expected server SPIFFE ID: {instance_error}"
        )

    duplicate_json = json.dumps(valid_document, sort_keys=True)
    api_version_field = '"apiVersion": "serverware.proxyResponseProof/v3"'
    if api_version_field not in duplicate_json:
        raise AssertionError("proxy proof fixture did not contain its expected apiVersion field")
    (tmp / "proxy-response-proof.json").write_text(
        duplicate_json.replace(api_version_field, f"{api_version_field}, {api_version_field}", 1),
        encoding="utf-8",
    )
    rejected_duplicate = run_verifier(tmp)
    if rejected_duplicate.returncode == 0 or "duplicate JSON object key: apiVersion" not in detail(rejected_duplicate):
        raise AssertionError(f"completion verifier accepted duplicate JSON object keys: {detail(rejected_duplicate)}")

    write(tmp / "proxy-response-proof.json", valid_document)


def test_live_runtime_projection_and_container_artifact_binding() -> None:
    project_name = "serverware-production"
    project_directory = ROOT
    value_hash = lambda value: sha256_prefixed_bytes(value.encode("utf-8"))
    service_model = {
        "image": "registry.example/control@" + digest("6"),
        "compose_user": "",
        "required_runtime_user": "nonroot:nonroot",
        "entrypoint": None,
        "command": ["serve"],
        "working_dir": "",
        "environment": [{"name": "MODE", "value_sha256": value_hash("approved")}],
        "devices": [
            {"source": "/dev/nsm", "target": "/dev/nsm", "permissions": "rwm"}
        ],
        "networks": ["default"],
        "mounts": [
            {
                "type": "bind",
                "source": "/approved/release.json",
                "target": "/run/release.json",
                "read_only": True,
                "bind": {},
                "volume": {},
                "tmpfs": {},
                "consistency": "",
            },
            {
                "type": "volume",
                "source": "data",
                "target": "/data",
                "read_only": False,
                "bind": {},
                "volume": {},
                "tmpfs": {},
                "consistency": "",
            },
        ],
        "tmpfs": [],
        "ports": [
            {
                "target": 3000,
                "published": "3000",
                "host_ip": "127.0.0.1",
                "protocol": "tcp",
                "mode": "ingress",
            }
        ],
        "links": [],
        "external_links": [],
        "host_config": {
            "read_only": True,
            "privileged": False,
            "cap_add": [],
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "pids_limit": 128,
            "memory": 268435456,
            "init": True,
            "group_add": [],
            "volumes_from": [],
            "dns": [],
            "dns_search": [],
            "dns_opt": [],
            "extra_hosts": [],
            "pid": "",
            "ipc": "",
            "uts": "",
            "network_mode": "",
            "userns_mode": "",
            "ulimits": {},
        },
    }
    runtime_model = {
        "services": {"audit-anchor": service_model},
        "networks": {
            "default": {
                "name": "",
                "external": False,
                "driver": "",
                "driver_opts": {},
            }
        },
        "volumes": {
            "data": {
                "name": "",
                "external": False,
                "driver": "",
                "driver_opts": {},
            }
        },
    }
    image_config = {
        "User": "nonroot:nonroot",
        "Entrypoint": ["/entry"],
        "Cmd": ["image-default"],
        "WorkingDir": "/app",
        "Env": ["PATH=/bin", "MODE=image"],
        "ExposedPorts": {},
        "Volumes": {},
    }
    container = {
        "Config": {
            "User": "nonroot:nonroot",
            "Entrypoint": ["/entry"],
            "Cmd": ["serve"],
            "WorkingDir": "/app",
            "Env": ["PATH=/bin", "MODE=approved"],
            "ExposedPorts": {"3000/tcp": {}},
        },
        "HostConfig": {
            "Devices": [
                {
                    "PathOnHost": "/dev/nsm",
                    "PathInContainer": "/dev/nsm",
                    "CgroupPermissions": "rwm",
                }
            ],
            "ReadonlyRootfs": True,
            "Privileged": False,
            "PublishAllPorts": False,
            "CapAdd": [],
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 128,
            "Memory": 268435456,
            "Init": True,
            "GroupAdd": [],
            "VolumesFrom": [],
            "Dns": [],
            "DnsSearch": [],
            "DnsOptions": [],
            "ExtraHosts": [],
            "PidMode": "",
            "IpcMode": "",
            "UTSMode": "",
            "NetworkMode": "serverware-production_default",
            "UsernsMode": "",
            "Ulimits": [],
            "Tmpfs": {},
            "PortBindings": {
                "3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3000"}]
            },
            "Links": [],
        },
        "NetworkSettings": {
            "Networks": {"serverware-production_default": {"IPAddress": "10.0.0.2"}}
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": "serverware-production_data",
                "Destination": "/data",
                "RW": True,
                "Propagation": "",
            },
            {
                "Type": "bind",
                "Source": "/approved/release.json",
                "Destination": "/run/release.json",
                "RW": False,
                "Propagation": "rprivate",
            },
        ],
    }
    expected = verify_release_completion.expected_runtime_projection(
        "audit-anchor",
        service_model,
        runtime_model,
        image_config,
        project_name=project_name,
        project_directory=project_directory,
    )
    observed = verify_release_completion.observed_runtime_projection(
        "audit-anchor", container, project_directory=project_directory
    )
    verify_release_completion.verify_runtime_projection(
        "audit-anchor", expected, observed
    )

    approved_config_ids = {
        "serverware-control": digest("a"),
        "serverware-decision-gate": digest("b"),
    }
    observed_config_ids = {
        "serverware": digest("a"),
        "audit-anchor": digest("a"),
        "decision-gate-rs": digest("b"),
    }
    verified_config_ids = (
        verify_release_completion.verify_running_image_config_ids(
            observed_config_ids,
            approved_config_ids,
        )
    )
    if verified_config_ids != observed_config_ids:
        raise AssertionError(
            "running image config identity verification omitted an approved service"
        )
    for service in observed_config_ids:
        mismatched = dict(observed_config_ids)
        mismatched[service] = digest("c")
        try:
            verify_release_completion.verify_running_image_config_ids(
                mismatched,
                approved_config_ids,
            )
        except ValueError as exc:
            if service not in str(exc) or "approved reproduced config identity" not in str(exc):
                raise AssertionError(
                    f"running config mismatch for {service} failed ambiguously: {exc}"
                ) from exc
        else:
            raise AssertionError(
                f"running service {service} accepted an unapproved image config identity"
            )

    mutations = {
        "root user": ("Config", "User", "0:0"),
        "arbitrary command": ("Config", "Cmd", ["/bin/sh"]),
        "extra environment": (
            "Config",
            "Env",
            ["PATH=/bin", "MODE=approved", "INJECTED=1"],
        ),
        "device substitution": ("HostConfig", "Devices", []),
        "network substitution": (
            "NetworkSettings",
            "Networks",
            {"attacker_default": {}},
        ),
        "mount substitution": (
            "Mounts",
            None,
            [
                {
                    "Type": "bind",
                    "Source": "/attacker/release.json",
                    "Destination": "/run/release.json",
                    "RW": False,
                    "Propagation": "rprivate",
                }
            ],
        ),
        "privileged container": ("HostConfig", "Privileged", True),
    }
    for label, (section, key, replacement) in mutations.items():
        mutated = json.loads(canonical_json(container))
        if key is None:
            mutated[section] = replacement
        else:
            mutated[section][key] = replacement
        try:
            candidate = verify_release_completion.observed_runtime_projection(
                "audit-anchor", mutated, project_directory=project_directory
            )
            verify_release_completion.verify_runtime_projection(
                "audit-anchor", expected, candidate
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"runtime projection accepted {label}")

    generation = {
        "audit-anchor": {
            "container_id": "a" * 64,
            "started_at": "2026-01-01T00:00:00Z",
            "image_id": digest("6"),
            "runtime_projection": observed,
        }
    }
    verify_release_completion.require_stable_container_generation(
        generation, json.loads(canonical_json(generation))
    )
    for field, replacement in (
        ("container_id", "b" * 64),
        ("started_at", "2026-01-01T00:00:01Z"),
    ):
        changed = json.loads(canonical_json(generation))
        changed["audit-anchor"][field] = replacement
        try:
            verify_release_completion.require_stable_container_generation(
                generation, changed
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"container generation accepted changed {field}")

    artifact = b'{"approved":true}\n'
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
        member = tarfile.TarInfo("release.json")
        member.size = len(artifact)
        archive.addfile(member, io.BytesIO(artifact))
    verified = verify_release_completion.parse_container_copy_archive(
        archive_buffer.getvalue(),
        expected_sha256=sha256_prefixed_bytes(artifact),
        expected_bytes=len(artifact),
        label="container-visible artifact",
    )
    if verified.get("container_namespace_verified") is not True:
        raise AssertionError("container artifact was not marked namespace-verified")
    for label, expected_digest, expected_length in (
        ("digest tampering", digest("0"), len(artifact)),
        ("length tampering", sha256_prefixed_bytes(artifact), len(artifact) + 1),
    ):
        try:
            verify_release_completion.parse_container_copy_archive(
                archive_buffer.getvalue(),
                expected_sha256=expected_digest,
                expected_bytes=expected_length,
                label=label,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"container artifact accepted {label}")
    linked_buffer = io.BytesIO()
    with tarfile.open(fileobj=linked_buffer, mode="w") as archive:
        member = tarfile.TarInfo("release.json")
        member.type = tarfile.SYMTYPE
        member.linkname = "/attacker/release.json"
        archive.addfile(member)
    try:
        verify_release_completion.parse_container_copy_archive(
            linked_buffer.getvalue(),
            expected_sha256=sha256_prefixed_bytes(artifact),
            expected_bytes=len(artifact),
            label="symlink archive",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("container artifact accepted a symlink tar member")
    multiple_buffer = io.BytesIO()
    with tarfile.open(fileobj=multiple_buffer, mode="w") as archive:
        for name in ("release.json", "extra.json"):
            member = tarfile.TarInfo(name)
            member.size = len(artifact)
            archive.addfile(member, io.BytesIO(artifact))
    try:
        verify_release_completion.parse_container_copy_archive(
            multiple_buffer.getvalue(),
            expected_sha256=sha256_prefixed_bytes(artifact),
            expected_bytes=len(artifact),
            label="multiple-member archive",
        )
    except ValueError:
        pass
    else:
        raise AssertionError("container artifact accepted multiple tar members")


def verify_release_artifact_authority_contracts() -> None:
    def reject(label: str, operation: Any) -> None:
        try:
            operation()
        except ValueError:
            return
        raise AssertionError(f"completion verifier accepted {label}")

    build = production_images_build()
    build_summary = verify_release_completion.verify_production_image_build(
        build,
        SOURCE_TREE_DIGEST,
    )
    if build_summary["launch_authority"] != {
        "launch_authority_key_id": FIXTURE_LAUNCH_AUTHORITY_KEY_ID,
        "launch_authority_root_sha256": FIXTURE_LAUNCH_AUTHORITY_ROOT_SHA256,
    }:
        raise AssertionError("production image build lost its launch-authority binding")

    old_build = json.loads(json.dumps(build))
    old_build["apiVersion"] = "serverware.productionImagesBuild/v1"
    reject(
        "a productionImagesBuild/v1 artifact",
        lambda: verify_release_completion.verify_production_image_build(
            old_build,
            SOURCE_TREE_DIGEST,
        ),
    )
    mismatched_build = json.loads(json.dumps(build))
    mismatched_build["images"][1]["launch_authority_key_id"] = digest("9")
    reject(
        "a cross-wired production build launch-authority key",
        lambda: verify_release_completion.verify_production_image_build(
            mismatched_build,
            SOURCE_TREE_DIGEST,
        ),
    )

    published = production_images_published()
    readiness_refs = [item["repo_digest"] for item in published["images"]]
    verify_release_completion.verify_published_images(
        published,
        build_summary,
        readiness_refs,
    )
    old_published = json.loads(json.dumps(published))
    old_published["apiVersion"] = "serverware.productionImagesPublished/v1"
    reject(
        "a productionImagesPublished/v1 artifact",
        lambda: verify_release_completion.verify_published_images(
            old_published,
            build_summary,
            readiness_refs,
        ),
    )
    mismatched_published = json.loads(json.dumps(published))
    mismatched_published["images"][1]["launch_authority_root_sha256"] = digest("9")
    reject(
        "a cross-wired published launch-authority root",
        lambda: verify_release_completion.verify_published_images(
            mismatched_published,
            build_summary,
            readiness_refs,
        ),
    )
    for field in ("remote_image_id", "config_id"):
        mismatched_config = json.loads(json.dumps(published))
        mismatched_config["images"][0][field] = digest("c")
        reject(
            f"a published image with mismatched {field}",
            lambda value=mismatched_config: verify_release_completion.verify_published_images(
                value,
                build_summary,
                readiness_refs,
            ),
        )

    provenance_summary, provenance_document = release_provenance()
    verified_provenance = verify_release_completion.verify_release_provenance(
        provenance_summary,
        provenance_document,
        "managed-prod-log",
        external_receipt_key_info()["key_id"],
        release_key_info()["public_key_pem"],
        external_receipt_key_info()["public_key_pem"],
    )
    if verified_provenance["launch_authority"] != build_summary["launch_authority"]:
        raise AssertionError("release provenance launch authority does not bind the production build")
    mismatched_provenance = json.loads(json.dumps(provenance_document))
    mismatched_provenance["provenance"]["reproducible_build"][
        "launch_authority_key_id"
    ] = digest("9")
    reject(
        "cross-wired reproducible provenance launch-authority evidence",
        lambda: verify_release_completion.verify_release_provenance(
            provenance_summary,
            mismatched_provenance,
            "managed-prod-log",
            external_receipt_key_info()["key_id"],
            release_key_info()["public_key_pem"],
            external_receipt_key_info()["public_key_pem"],
        ),
    )
    mismatched_provenance_config = json.loads(json.dumps(provenance_document))
    mismatched_provenance_config["provenance"]["images"][
        "serverware-control"
    ]["remote_image_id"] = digest("c")
    mismatched_provenance_summary = json.loads(json.dumps(provenance_summary))
    refresh_release_provenance(
        mismatched_provenance_summary,
        mismatched_provenance_config,
    )
    reject(
        "release provenance with mismatched local and remote config IDs",
        lambda: verify_release_completion.verify_release_provenance(
            mismatched_provenance_summary,
            mismatched_provenance_config,
            "managed-prod-log",
            external_receipt_key_info()["key_id"],
            release_key_info()["public_key_pem"],
            external_receipt_key_info()["public_key_pem"],
        ),
    )


def main() -> None:
    completion_schema_validator, receipt_schema_fixture = verify_release_proof_schemas()
    verify_launcher_three_way_binding()
    verify_release_artifact_authority_contracts()
    verify_cosign_ecdsa_signature_compatibility()
    verify_ed25519_signature_canonicalization()
    test_final_file_snapshots()
    test_release_provenance_input_snapshot()
    test_measured_preflight_module_replacement_race()
    test_final_production_env_binding()
    test_preflight_authenticity_and_freshness()
    test_live_runtime_projection_and_container_artifact_binding()
    global IMAGE_SIGNATURES_DIGEST, POLICY_DIGEST
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw).resolve()
        production_build = production_images_build()
        reproduced_images = []
        for image in production_build["images"]:
            item = {"service": image["service"], "image_id": image["image_id"]}
            if image["service"] == "serverware-decision-gate":
                item["rust_binary_sha256"] = image["binary_digest"]
                item["launcher_binary_sha256"] = image["launcher_binary_digest"]
                item["launch_authority_key_id"] = image[
                    "launch_authority_key_id"
                ]
                item["launch_authority_root_sha256"] = image[
                    "launch_authority_root_sha256"
                ]
            reproduced_images.append(item)
        test_production_release_input_preflight.release_security_fixture(
            tmp,
            source_tree_digest=SOURCE_TREE_DIGEST,
            images=reproduced_images,
        )
        add_reproducible_builder_fixture(tmp)
        POLICY_DIGEST = authorize_alternate_proxy_principal(tmp)
        provenance_summary, provenance_document = release_provenance(
            sha256_file(tmp / "reproducible-build-verification.json")
        )
        nitro = nitro_evidence(provenance_summary["provenance_digest"])
        image_summary, image_document = image_signatures(provenance_summary["provenance_digest"])
        IMAGE_SIGNATURES_DIGEST = image_summary["image_signature_bundle_digest"]
        write_production_env_files(tmp)
        write(tmp / "production-readiness.json", production_readiness(nitro, tmp))
        write(tmp / "nitro-kms-evidence.json", nitro)
        write(tmp / "production-images-build.json", production_build)
        write(tmp / "production-images-published.json", production_images_published())
        write(tmp / "release-provenance-summary.json", provenance_summary)
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        (tmp / "release-signing.pub.pem").write_text(release_key_info()["public_key_pem"], encoding="ascii")
        (tmp / "sigstore-signing.pub.pem").write_text(
            sigstore_signing_key_info()["public_key_pem"],
            encoding="ascii",
        )
        (tmp / "rekor.pub.pem").write_text(rekor_key_info()["public_key_pem"], encoding="ascii")
        (tmp / "external-checkpoint.pub.pem").write_text(
            external_receipt_key_info()["public_key_pem"],
            encoding="ascii",
        )
        write(tmp / "kms-materials.json", kms_materials_document())
        write(
            tmp / "decision-gate-rs-bench.json",
            benchmark_document(),
        )
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        valid_hardware_assurance = hardware_assurance_document(nitro, tmp)
        write(tmp / "hardware-assurance.json", valid_hardware_assurance)
        (tmp / "hardware-assurance-verifier.pub.pem").write_text(
            hardware_verifier_key_info()["public_key_pem"],
            encoding="ascii",
        )
        valid_proxy_response_proof = proxy_response_proof(provenance_summary["provenance_digest"])
        write(tmp / "proxy-response-proof.json", valid_proxy_response_proof)
        (tmp / "control-plane-response-signing.pub.pem").write_text(
            control_plane_response_signing_key_info()["public_key_pem"],
            encoding="ascii",
        )
        (tmp / "proxy-vendor-verifier-public-key.pem").write_text(
            proxy_vendor_verifier_key_info()["public_key_pem"],
            encoding="ascii",
        )
        (tmp / "proxy-collector-public-key.pem").write_text(
            proxy_collector_key_info()["public_key_pem"],
            encoding="ascii",
        )
        test_streaming_proxy_response_proof_requirements(
            tmp,
            provenance_summary["provenance_digest"],
        )
        test_streaming_release_completion_cli(
            tmp,
            nitro,
            provenance_summary["provenance_digest"],
            valid_proxy_response_proof,
        )
        out_path = tmp / "completion-proof.json"
        result = run_verifier(tmp, "--out", str(out_path))
        if result.returncode != 0:
            raise AssertionError(f"completion verifier failed: {detail(result)}")
        proof = json.loads(result.stdout.decode("utf-8"))
        persisted_proof = json.loads(out_path.read_text(encoding="utf-8"))
        generation = (persisted_proof.get("integrity_metadata") or {}).get("generation")
        detached_digest_path = run_production_readiness.completion_proof_digest_path(
            out_path,
            generation,
        )
        runner_expected = SimpleNamespace(
            verification_mode="readiness",
            runner_started_at_unix=persisted_proof["generated_at_unix"],
            pre_run_completion_proof_state={"exists": False},
            proxy_client_request_digest=PROXY_CLIENT_REQUEST_DIGEST,
            proxy_request_digest=PROXY_REQUEST_DIGEST,
            proxy_operation_digest=PROXY_OPERATION_DIGEST,
            proxy_server_instance_id=PROXY_SERVER_INSTANCE_ID,
            proxy_principal_id=PROXY_PRINCIPAL_ID,
            proxy_client_nonce=PROXY_CLIENT_NONCE,
            proxy_tls_channel_binding=PROXY_TLS_CHANNEL_BINDING,
            proxy_proof_max_age_seconds=300,
            p99_limit_ms=20.0,
            docker_executable=str(tmp / "production-docker"),
            collected_proxy_proof_sha256=sha256_file(tmp / "proxy-response-proof.json"),
            launcher_env_binding=None,
            production_readiness_env_sha256=sha256_file(tmp / "production.env"),
            readiness_out=str(tmp / "production-readiness.json"),
            config_out=str(tmp / "production-readiness-config.json"),
            env_file=str(tmp / "production.env"),
            production_host_preflight=str(tmp / "production-host-preflight.json"),
            nitro_evidence_out=str(tmp / "nitro-kms-evidence.json"),
            production_images_build=str(tmp / "production-images-build.json"),
            production_images_env=str(tmp / "production-images.env"),
            production_images_published=str(tmp / "production-images-published.json"),
            release_provenance_summary=str(tmp / "release-provenance-summary.json"),
            release_provenance=str(tmp / "release-provenance.json"),
            release_provenance_trusted_public_key=str(tmp / "release-signing.pub.pem"),
            image_signatures_summary=str(tmp / "image-signatures-summary.json"),
            image_signatures=str(tmp / "image-signatures.json"),
            sigstore_trusted_public_key=str(tmp / "sigstore-signing.pub.pem"),
            rekor_trusted_public_key=str(tmp / "rekor.pub.pem"),
            external_checkpoint_trusted_public_key=str(tmp / "external-checkpoint.pub.pem"),
            bench=str(tmp / "decision-gate-rs-bench.json"),
            policy_bundle=str(tmp / "policy-bundle.json"),
            policy_trusted_public_key=str(tmp / "policy-signing.pub.pem"),
            policy_identity_verification=str(tmp / "production-policy-identity-verification.json"),
            policy_activation_verification=str(tmp / "policy-activation-verification.json"),
            policy_activation_signature=str(tmp / "policy-activation-verification.signature.json"),
            policy_activation_trusted_public_key=str(tmp / "policy-activation-verification.pub.pem"),
            reproducible_build_verification=str(tmp / "reproducible-build-verification.json"),
            reproducible_build_signature=str(tmp / "reproducible-build-verification.signature.json"),
            reproducible_build_trusted_public_key=str(tmp / "reproducible-build-verification.pub.pem"),
            kms_materials=str(tmp / "kms-materials.json"),
            control_plane_response_signing_public_key=str(tmp / "control-plane-response-signing.pub.pem"),
            proxy_response_proof=str(tmp / "proxy-response-proof.json"),
            proxy_proof_verifier_public_key=str(tmp / "proxy-vendor-verifier-public-key.pem"),
            proxy_collector_public_key=str(tmp / "proxy-collector-public-key.pem"),
            compose_file="docker-compose.production.yml",
            hardware_assurance=None,
            hardware_assurance_trusted_public_key=None,
            final_challenge_receipt=None,
            final_challenge_authority_public_key=None,
        )
        verified_output_digest = run_production_readiness.verify_completion_output(
            out_path,
            runner_expected,
        )
        runner_expected.pre_run_completion_proof_state = {
            "exists": True,
            "sha256": verified_output_digest,
            "device": out_path.stat().st_dev,
            "inode": out_path.stat().st_ino,
            "generation": generation,
        }
        try:
            run_production_readiness.verify_completion_output(out_path, runner_expected)
        except ValueError as exc:
            if "not changed" not in str(exc) and "generation was reused" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a zero-return substitute that left the old proof in place")
        runner_expected.pre_run_completion_proof_state = {"exists": False}
        if (
            proof.get("ok") is not True
            or not out_path.exists()
            or not detached_digest_path.exists()
            or proof.get("proof_sha256") != verified_output_digest
            or proof.get("proof_sha256_path") != str(detached_digest_path)
            or detached_digest_path.read_text(encoding="ascii") != f"{verified_output_digest}\n"
            or (persisted_proof.get("integrity_metadata") or {}).get("scope") != "checksum-only"
            or (persisted_proof.get("integrity_metadata") or {}).get("independently_authenticated") is not False
            or (persisted_proof.get("integrity_metadata") or {}).get(
                "authenticity_requires_external_signature_or_checkpoint"
            )
            is not True
            or (out_path.stat().st_mode & 0o777) != 0o600
            or (detached_digest_path.stat().st_mode & 0o777) != 0o600
        ):
            raise AssertionError(f"completion verifier did not write a valid proof: {proof}")
        original_detached_digest = detached_digest_path.read_bytes()
        detached_digest_path.write_text(f"{digest('f')}\n", encoding="ascii")
        detached_digest_path.chmod(0o600)
        try:
            run_production_readiness.verify_completion_output(out_path)
        except ValueError as exc:
            if "does not match the completion proof bytes" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a tampered detached completion proof digest")
        detached_digest_path.write_bytes(original_detached_digest)
        detached_digest_path.chmod(0o600)
        if run_production_readiness.verify_completion_output(out_path) != verified_output_digest:
            raise AssertionError("runner did not accept the restored detached completion proof digest")
        mutated_contract_path = tmp / "mutated-completion-proof.json"
        mutated_contract = clone_document(persisted_proof)
        mutated_contract["proof_path"] = str(mutated_contract_path)
        mutated_contract["production_proxy_response_proof"]["principal_id"] = "agent:mutated"
        mutated_generation = "c" * 32
        mutated_contract_digest_path = run_production_readiness.completion_proof_digest_path(
            mutated_contract_path,
            mutated_generation,
        )
        mutated_contract["integrity_metadata"] = {
            **mutated_contract["integrity_metadata"],
            "generation": mutated_generation,
            "detached_sha256_path": str(mutated_contract_digest_path),
        }
        verify_release_completion.write_output(mutated_contract_path, mutated_contract)
        try:
            run_production_readiness.verify_completion_output(
                mutated_contract_path,
                runner_expected,
            )
        except ValueError as exc:
            if "proxy principal mismatch" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a checksum-valid mutated persisted proof contract")
        unknown_mode_path = tmp / "unknown-mode-completion-proof.json"
        unknown_mode_contract = clone_document(persisted_proof)
        unknown_mode_contract["verification_mode"] = "audit"
        unknown_mode_contract["proof_path"] = str(unknown_mode_path)
        unknown_mode_generation = "a" * 32
        unknown_mode_digest_path = run_production_readiness.completion_proof_digest_path(
            unknown_mode_path,
            unknown_mode_generation,
        )
        unknown_mode_contract["integrity_metadata"] = {
            **unknown_mode_contract["integrity_metadata"],
            "generation": unknown_mode_generation,
            "detached_sha256_path": str(unknown_mode_digest_path),
        }
        verify_release_completion.write_output(
            unknown_mode_path,
            unknown_mode_contract,
        )
        try:
            run_production_readiness.verify_completion_output(unknown_mode_path)
        except ValueError as exc:
            if "verification mode must be exactly readiness or final" not in str(exc):
                raise
        else:
            raise AssertionError(
                "runner treated an unknown persisted proof mode as readiness"
            )
        stale_contract_path = tmp / "stale-completion-proof.json"
        stale_contract = clone_document(persisted_proof)
        stale_contract["proof_path"] = str(stale_contract_path)
        stale_contract["generated_at_unix"] = runner_expected.runner_started_at_unix - 1
        stale_generation = "b" * 32
        stale_digest_path = run_production_readiness.completion_proof_digest_path(
            stale_contract_path,
            stale_generation,
        )
        stale_contract["integrity_metadata"] = {
            **stale_contract["integrity_metadata"],
            "generation": stale_generation,
            "detached_sha256_path": str(stale_digest_path),
        }
        verify_release_completion.write_output(stale_contract_path, stale_contract)
        try:
            run_production_readiness.verify_completion_output(
                stale_contract_path,
                runner_expected,
            )
        except ValueError as exc:
            if "predates the current readiness runner invocation" not in str(exc):
                raise
        else:
            raise AssertionError("runner accepted a fresh-checksum proof forged with a stale timestamp")
        committed_proof_bytes = out_path.read_bytes()
        interrupted_proof = clone_document(persisted_proof)
        interrupted_generation = "e" * 32
        interrupted_digest_path = run_production_readiness.completion_proof_digest_path(
            out_path,
            interrupted_generation,
        )
        interrupted_proof["integrity_metadata"] = {
            **interrupted_proof["integrity_metadata"],
            "generation": interrupted_generation,
            "detached_sha256_path": str(interrupted_digest_path),
        }
        try:
            verify_release_completion.write_output(
                out_path,
                interrupted_proof,
                fail_after_checksum_publish=True,
            )
        except RuntimeError as exc:
            if "injected failure" not in str(exc):
                raise
        else:
            raise AssertionError("completion output crash injection did not interrupt publication")
        if (
            out_path.read_bytes() != committed_proof_bytes
            or not detached_digest_path.is_file()
            or not interrupted_digest_path.is_file()
            or run_production_readiness.verify_completion_output(out_path) != verified_output_digest
        ):
            raise AssertionError("interrupted checksum publication invalidated the prior committed proof")

        for index in range(5):
            stale_path = run_production_readiness.completion_proof_digest_path(
                out_path,
                f"{index:032x}",
            )
            stale_path.write_text(f"{digest('0')}\n", encoding="ascii")
            stale_path.chmod(0o600)
        replacement_proof = clone_document(persisted_proof)
        replacement_generation = "d" * 32
        replacement_digest_path = run_production_readiness.completion_proof_digest_path(
            out_path,
            replacement_generation,
        )
        replacement_proof["integrity_metadata"] = {
            **replacement_proof["integrity_metadata"],
            "generation": replacement_generation,
            "detached_sha256_path": str(replacement_digest_path),
        }
        replacement_digest = verify_release_completion.write_output(
            out_path,
            replacement_proof,
        )
        retained_checksums = list(out_path.parent.glob(f"{out_path.name}.sha256.*"))
        if (
            len(retained_checksums) > 3
            or replacement_digest_path not in retained_checksums
            or run_production_readiness.verify_completion_output(out_path) != replacement_digest
        ):
            raise AssertionError("completion checksum generation cleanup violated the committed proof contract")

        concurrent_template_path = tmp / "concurrent-proof-template.json"
        concurrent_template_path.write_text(
            json.dumps(persisted_proof, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        writer_code = (
            "import json,sys; from pathlib import Path; "
            "sys.path.insert(0, 'scripts'); import verify_release_completion as v; "
            "template=Path(sys.argv[1]); out=Path(sys.argv[2]); generation=sys.argv[3]; "
            "proof=json.loads(template.read_text(encoding='utf-8')); "
            "proof['proof_path']=str(out); "
            "sidecar=v.completion_proof_digest_path(out,generation); "
            "proof['integrity_metadata']={**proof['integrity_metadata'],'generation':generation,"
            "'detached_sha256_path':str(sidecar)}; v.write_output(out,proof)"
        )
        writers = [
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    writer_code,
                    str(concurrent_template_path),
                    str(out_path),
                    f"{index + 16:032x}",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for index in range(4)
        ]
        writer_failures = []
        for writer in writers:
            stdout, stderr = writer.communicate(timeout=30)
            if writer.returncode != 0:
                writer_failures.append((writer.returncode, stdout, stderr))
        if writer_failures:
            raise AssertionError(f"concurrent completion writers failed: {writer_failures}")
        concurrent_proof = json.loads(out_path.read_text(encoding="utf-8"))
        concurrent_generation = concurrent_proof["integrity_metadata"]["generation"]
        concurrent_sidecar = run_production_readiness.completion_proof_digest_path(
            out_path,
            concurrent_generation,
        )
        if not concurrent_sidecar.is_file():
            raise AssertionError("a concurrently committed completion proof lost its checksum generation")
        run_production_readiness.verify_completion_output(out_path)
        completion_schema_validator.validate(proof)
        final_schema_fixture = json.loads(json.dumps(persisted_proof))
        final_schema_fixture.update(
            {
                "kind": "ServerwareCompletionProof",
                "verification_mode": "final",
                "result_scope": "final-completion",
                "readiness_only": False,
                "completion_status": "hardware-backed-release-completion",
                "release_completion": "pass",
                "final_completion": True,
                "hardware_proof": True,
                "bootstrap_launcher": bootstrap_receipt_summary(receipt_schema_fixture),
                "assurance_ceiling": {
                    "final_completion": True,
                    "hardware_proof": True,
                    "hardware_evidence_verified": True,
                },
                "hardware_assurance_evidence": {"verified": True},
            }
        )
        final_schema_fixture["final_challenge_consumption"] = {
            "consumed": True,
            "completion_identity": {
                "apiVersion": "serverware.finalCompletionIdentity/v1",
                "release_identity_sha256": digest("1"),
                "current_host_identity_sha256": digest("2"),
                "launch_authorization": (
                    run_production_readiness.bootstrap_launch_authorization_identity(
                        final_schema_fixture["bootstrap_launcher"]
                    )
                ),
                "hardware_verifier_key_id": digest("3"),
                "hardware_assurance_document_sha256": digest("4"),
                "hardware_assurance_signed_statement_sha256": digest("5"),
                "challenge_nonce_sha256": digest("6"),
                "proxy_server_statement_sha256": digest("7"),
                "security_role_map_sha256": digest("8"),
            },
        }
        completion_schema_validator.validate(final_schema_fixture)
        final_round_trip_path = tmp / "completion-proof-final-round-trip.json"
        final_round_trip = json.loads(json.dumps(final_schema_fixture))
        final_round_trip["proof_path"] = str(final_round_trip_path)
        final_generation = "f" * 32
        final_round_trip["integrity_metadata"] = {
            "generation": final_generation,
            "detached_sha256_path": str(
                verify_release_completion.completion_proof_digest_path(
                    final_round_trip_path,
                    final_generation,
                )
            ),
            "scope": "checksum-only",
            "independently_authenticated": False,
            "authenticity_requires_external_signature_or_checkpoint": True,
        }
        verify_release_completion.write_output(
            final_round_trip_path,
            final_round_trip,
        )
        try:
            run_production_readiness.verify_completion_output(final_round_trip_path)
        except ValueError as exc:
            if "requires caller-authenticated expected context" not in str(exc):
                raise AssertionError(
                    f"standalone final proof failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError(
                "standalone verifier accepted a self-checksummed final-looking proof"
            )
        readiness_shaped_final = json.loads(json.dumps(final_schema_fixture))
        readiness_shaped_final["final_challenge_consumption"] = {
            "required": False,
            "consumed": False,
        }
        if not list(completion_schema_validator.iter_errors(readiness_shaped_final)):
            raise AssertionError(
                "completion v5 schema accepted readiness-shaped final challenge evidence"
            )
        if (
            proof.get("apiVersion") != "serverware.completionProof/v5"
            or proof.get("kind") != "ServerwarePreEnclaveReadiness"
            or proof.get("verification_mode") != "readiness"
            or proof.get("result_scope") != "readiness-only"
            or proof.get("readiness_only") is not True
            or proof.get("verification_passed") is not True
            or proof.get("completion_status") != "pre-enclave-readiness"
            or proof.get("release_completion") != "not-final"
            or proof.get("final_completion") is not False
            or proof.get("hardware_proof") is not False
            or (proof.get("nitro_kms_evidence") or {}).get("hardware_proof") is not False
        ):
            raise AssertionError(f"ordinary Docker/dev/NSM fixture exceeded the pre-enclave assurance ceiling: {proof}")
        proxy_summary = proof.get("production_proxy_response_proof") or {}
        if not all(
            proxy_summary.get(field) is True
            for field in (
                "vendor_quote_verified",
                "collector_signature_verified",
                "server_statement_signature_verified",
                "fresh_client_nonce_bound",
                "authenticated_external_client_capture_bound",
                "release_authority_bound",
                "embedded_control_plane_authorization_receipt_bound",
                "upstream_response_bound",
                "release_artifacts_bound",
            )
        ):
            raise AssertionError(f"completion verifier omitted verified production proxy proof bindings: {proof}")

        missing_hardware_trust = run_verifier(
            tmp,
            "--hardware-assurance",
            str(tmp / "hardware-assurance.json"),
        )
        if (
            missing_hardware_trust.returncode == 0
            or "requires both --hardware-assurance and --hardware-assurance-trusted-public-key"
            not in detail(missing_hardware_trust)
        ):
            raise AssertionError(f"completion verifier accepted hardware evidence without a separate trust root: {detail(missing_hardware_trust)}")

        missing_hardware_challenge = run_verifier(
            tmp,
            include_hardware_assurance=True,
            hardware_expected_challenge_mode=None,
        )
        if (
            missing_hardware_challenge.returncode == 0
            or "hardware-backed completion requires exactly one --hardware-assurance-expected-challenge-nonce"
            not in detail(missing_hardware_challenge)
        ):
            raise AssertionError(
                "completion verifier accepted hardware evidence without an externally supplied expected challenge: "
                f"{detail(missing_hardware_challenge)}"
            )

        both_hardware_challenges = run_verifier(
            tmp,
            "--hardware-assurance-expected-challenge-nonce-sha256",
            HARDWARE_ASSURANCE_CHALLENGE_SHA256,
            include_hardware_assurance=True,
        )
        if (
            both_hardware_challenges.returncode == 0
            or "hardware-backed completion requires exactly one --hardware-assurance-expected-challenge-nonce"
            not in detail(both_hardware_challenges)
        ):
            raise AssertionError(
                f"completion verifier accepted both expected challenge forms: {detail(both_hardware_challenges)}"
            )

        malformed_hardware_challenge = run_verifier(
            tmp,
            "--hardware-assurance-expected-challenge-nonce",
            "not+unpadded/base64url",
            include_hardware_assurance=True,
            hardware_expected_challenge_mode=None,
        )
        if (
            malformed_hardware_challenge.returncode == 0
            or "expected hardware assurance challenge nonce is invalid" not in detail(malformed_hardware_challenge)
        ):
            raise AssertionError(
                f"completion verifier accepted a malformed expected challenge nonce: {detail(malformed_hardware_challenge)}"
            )

        malformed_hardware_challenge_digest = run_verifier(
            tmp,
            "--hardware-assurance-expected-challenge-nonce-sha256",
            "sha256:not-a-digest",
            include_hardware_assurance=True,
            hardware_expected_challenge_mode=None,
        )
        if (
            malformed_hardware_challenge_digest.returncode == 0
            or "expected hardware assurance challenge nonce digest must be a sha256-prefixed digest"
            not in detail(malformed_hardware_challenge_digest)
        ):
            raise AssertionError(
                "completion verifier accepted a malformed expected challenge digest: "
                f"{detail(malformed_hardware_challenge_digest)}"
            )

        replayed_hardware_assurance = run_verifier(
            tmp,
            "--hardware-assurance-expected-challenge-nonce",
            b64e(b"different-hardware-challenge-nonce"),
            include_hardware_assurance=True,
            hardware_expected_challenge_mode=None,
        )
        if (
            replayed_hardware_assurance.returncode == 0
            or "hardware assurance challenge nonce does not match the caller-expected challenge"
            not in detail(replayed_hardware_assurance)
        ):
            raise AssertionError(
                "completion verifier accepted a signed hardware assurance replayed for another challenge: "
                f"{detail(replayed_hardware_assurance)}"
            )

        hardware_digest_result = run_verifier(
            tmp,
            include_hardware_assurance=True,
            hardware_expected_challenge_mode="sha256",
        )
        if hardware_digest_result.returncode != 0:
            raise AssertionError(
                "completion verifier rejected a valid caller-expected challenge digest: "
                f"{detail(hardware_digest_result)}"
            )
        hardware_digest_summary = (
            json.loads(hardware_digest_result.stdout.decode("utf-8")).get("hardware_assurance_evidence") or {}
        )
        if (
            hardware_digest_summary.get("expected_challenge_bound") is not True
            or hardware_digest_summary.get("challenge_nonce_sha256") != HARDWARE_ASSURANCE_CHALLENGE_SHA256
        ):
            raise AssertionError(
                f"completion verifier omitted the expected challenge digest binding: {hardware_digest_summary}"
            )

        hardware_result = run_verifier(tmp, include_hardware_assurance=True)
        if hardware_result.returncode != 0:
            raise AssertionError(f"completion verifier rejected valid signed hardware assurance evidence: {detail(hardware_result)}")
        hardware_limited_proof = json.loads(hardware_result.stdout.decode("utf-8"))
        hardware_summary = hardware_limited_proof.get("hardware_assurance_evidence") or {}
        if (
            hardware_summary.get("verified") is not True
            or hardware_summary.get("expected_challenge_bound") is not True
            or hardware_summary.get("challenge_nonce_sha256") != HARDWARE_ASSURANCE_CHALLENGE_SHA256
            or hardware_summary.get("current_host_identity_bound") is not False
            or hardware_limited_proof.get("final_completion") is not False
            or hardware_limited_proof.get("hardware_proof") is not False
            or (hardware_limited_proof.get("assurance_ceiling") or {}).get("hardware_evidence_verified") is not True
        ):
            raise AssertionError(f"test-only host bypass escaped the hardware assurance ceiling: {hardware_limited_proof}")

        exact_host_summary = fixture_current_host_summary()
        exact_host_hardware_summary = verify_hardware_assurance_fixture(
            tmp,
            valid_hardware_assurance,
            exact_host_summary,
        )
        if exact_host_hardware_summary.get("current_host_identity_bound") is not True:
            raise AssertionError(
                f"exact-host fixture did not bind signed hardware assurance: {exact_host_hardware_summary}"
            )
        final_assurance = verify_release_completion.completion_assurance(
            exact_host_hardware_summary,
            exact_host_summary,
        )
        if final_assurance.get("final_completion") is not True or final_assurance.get("hardware_proof") is not True:
            raise AssertionError(f"fully verified hardware and current-host evidence did not enable final completion: {final_assurance}")

        proxy_server_statement_sha256 = sha256_prefixed_json(
            valid_proxy_response_proof["server_statement"]
        )
        final_bootstrap_receipt = bootstrap_receipt_summary(
            bootstrap_receipt_fixture(
                deployment_identity_sha256=exact_host_summary["identity"][
                    "identity_sha256"
                ]
            )
        )
        fixture_security_role_map_sha256 = digest("d")
        final_completion_identity = verify_release_completion.final_completion_identity(
            exact_host_hardware_summary,
            bootstrap_receipt=final_bootstrap_receipt,
            current_host_identity_sha256=exact_host_summary["identity"][
                "identity_sha256"
            ],
            proxy_server_statement_sha256=proxy_server_statement_sha256,
            security_role_map_sha256=fixture_security_role_map_sha256,
        )
        final_completion_identity_sha256 = sha256_prefixed_json(
            final_completion_identity
        )
        if (
            final_completion_identity.get("apiVersion")
            != verify_release_completion.FINAL_COMPLETION_IDENTITY_API_VERSION
            or final_completion_identity.get("hardware_assurance_document_sha256")
            != sha256_file(tmp / "hardware-assurance.json")
            or final_completion_identity.get(
                "hardware_assurance_signed_statement_sha256"
            )
            != sha256_prefixed_json(valid_hardware_assurance["statement"])
            or final_completion_identity.get("launch_authorization")
            != run_production_readiness.bootstrap_launch_authorization_identity(
                final_bootstrap_receipt
            )
            or final_completion_identity.get("security_role_map_sha256")
            != fixture_security_role_map_sha256
        ):
            raise AssertionError(
                "final completion identity omitted exact hardware or launch authorization identity"
            )
        for field in (
            "hardware_assurance_document_sha256",
            "hardware_assurance_signed_statement_sha256",
        ):
            changed_hardware_summary = clone_document(exact_host_hardware_summary)
            changed_hardware_summary[field] = digest("0")
            changed_identity_sha256 = sha256_prefixed_json(
                verify_release_completion.final_completion_identity(
                    changed_hardware_summary,
                    bootstrap_receipt=final_bootstrap_receipt,
                    current_host_identity_sha256=exact_host_summary["identity"][
                        "identity_sha256"
                    ],
                    proxy_server_statement_sha256=proxy_server_statement_sha256,
                    security_role_map_sha256=fixture_security_role_map_sha256,
                )
            )
            if changed_identity_sha256 == final_completion_identity_sha256:
                raise AssertionError(
                    f"final completion identity did not bind {field}"
                )
        changed_launch_identity_sha256 = sha256_prefixed_json(
            verify_release_completion.final_completion_identity(
                exact_host_hardware_summary,
                bootstrap_receipt=bootstrap_receipt_summary(
                    bootstrap_receipt_fixture(
                        deployment_identity_sha256=exact_host_summary["identity"][
                            "identity_sha256"
                        ],
                        release_sequence=43,
                    )
                ),
                current_host_identity_sha256=exact_host_summary["identity"][
                    "identity_sha256"
                ],
                proxy_server_statement_sha256=proxy_server_statement_sha256,
                security_role_map_sha256=fixture_security_role_map_sha256,
            )
        )
        if changed_launch_identity_sha256 == final_completion_identity_sha256:
            raise AssertionError(
                "final completion identity did not bind launch authorization sequence"
            )
        changed_role_map_identity_sha256 = sha256_prefixed_json(
            verify_release_completion.final_completion_identity(
                exact_host_hardware_summary,
                bootstrap_receipt=final_bootstrap_receipt,
                current_host_identity_sha256=exact_host_summary["identity"][
                    "identity_sha256"
                ],
                proxy_server_statement_sha256=proxy_server_statement_sha256,
                security_role_map_sha256=digest("0"),
            )
        )
        if changed_role_map_identity_sha256 == final_completion_identity_sha256:
            raise AssertionError(
                "final completion identity did not bind the canonical security role map"
            )
        try:
            verify_release_completion.final_completion_identity(
                exact_host_hardware_summary,
                bootstrap_receipt=bootstrap_receipt_summary(
                    bootstrap_receipt_fixture(
                        deployment_identity_sha256=digest("0")
                    )
                ),
                current_host_identity_sha256=exact_host_summary["identity"][
                    "identity_sha256"
                ],
                proxy_server_statement_sha256=proxy_server_statement_sha256,
                security_role_map_sha256=fixture_security_role_map_sha256,
            )
        except ValueError as exc:
            if "does not match the current completion host" not in str(exc):
                raise
        else:
            raise AssertionError(
                "final completion identity accepted another deployment identity"
            )
        receipt = final_challenge_receipt(
            challenge_nonce_sha256=HARDWARE_ASSURANCE_CHALLENGE_SHA256,
            completion_identity_sha256=final_completion_identity_sha256,
            release_identity_sha256=exact_host_hardware_summary[
                "release_identity_sha256"
            ],
            hardware_verifier_key_id=exact_host_hardware_summary[
                "trusted_verifier_key_id"
            ],
            current_host_identity_sha256=exact_host_summary["identity"][
                "identity_sha256"
            ],
            proxy_server_statement_sha256=proxy_server_statement_sha256,
            issued_at_unix=exact_host_hardware_summary["issued_at_unix"],
        )
        receipt_summary = verify_release_completion.verify_final_challenge_receipt(
            receipt,
            trusted_public_key_pem=final_challenge_authority_key_info()[
                "public_key_pem"
            ],
            expected_trusted_public_key_id=final_challenge_authority_key_info()[
                "key_id"
            ],
            final_challenge_receipt_sha256=sha256_prefixed_json(receipt),
            expected_provider="fixture-off-host-challenge-authority",
            expected_challenge_nonce_sha256=HARDWARE_ASSURANCE_CHALLENGE_SHA256,
            expected_completion_identity_sha256=final_completion_identity_sha256,
            expected_release_identity_sha256=exact_host_hardware_summary[
                "release_identity_sha256"
            ],
            expected_hardware_verifier_key_id=exact_host_hardware_summary[
                "trusted_verifier_key_id"
            ],
            expected_current_host_identity_sha256=exact_host_summary["identity"][
                "identity_sha256"
            ],
            expected_proxy_server_statement_sha256=proxy_server_statement_sha256,
            hardware_assurance_issued_at_unix=exact_host_hardware_summary[
                "issued_at_unix"
            ],
            now_unix=exact_host_hardware_summary["issued_at_unix"],
        )
        if (
            receipt_summary.get("consumed") is not True
            or receipt_summary.get("receipt_sha256")
            != sha256_prefixed_json(receipt)
            or receipt_summary.get("receipt_signed_statement_sha256")
            != sha256_prefixed_json(receipt["statement"])
        ):
            raise AssertionError(
                f"off-host challenge authority receipt did not authorize final completion: {receipt_summary}"
            )
        try:
            verify_release_completion.verify_final_challenge_receipt(
                receipt,
                trusted_public_key_pem=final_challenge_authority_key_info()[
                    "public_key_pem"
                ],
                expected_trusted_public_key_id=hardware_verifier_key_info()[
                    "key_id"
                ],
                final_challenge_receipt_sha256=sha256_prefixed_json(receipt),
                expected_provider="fixture-off-host-challenge-authority",
                expected_challenge_nonce_sha256=HARDWARE_ASSURANCE_CHALLENGE_SHA256,
                expected_completion_identity_sha256=final_completion_identity_sha256,
                expected_release_identity_sha256=exact_host_hardware_summary[
                    "release_identity_sha256"
                ],
                expected_hardware_verifier_key_id=exact_host_hardware_summary[
                    "trusted_verifier_key_id"
                ],
                expected_current_host_identity_sha256=exact_host_summary[
                    "identity"
                ]["identity_sha256"],
                expected_proxy_server_statement_sha256=proxy_server_statement_sha256,
                hardware_assurance_issued_at_unix=exact_host_hardware_summary[
                    "issued_at_unix"
                ],
                now_unix=exact_host_hardware_summary["issued_at_unix"],
            )
        except ValueError as exc:
            if "key bytes do not match the independently configured SPKI identity" not in str(
                exc
            ):
                raise AssertionError(
                    f"wrong expected authority SPKI ID failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError(
                "final challenge receipt accepted authority key bytes under another expected SPKI ID"
            )
        forged_receipt = final_challenge_receipt(
            challenge_nonce_sha256=HARDWARE_ASSURANCE_CHALLENGE_SHA256,
            completion_identity_sha256=digest("0"),
            release_identity_sha256=exact_host_hardware_summary[
                "release_identity_sha256"
            ],
            hardware_verifier_key_id=exact_host_hardware_summary[
                "trusted_verifier_key_id"
            ],
            current_host_identity_sha256=exact_host_summary["identity"][
                "identity_sha256"
            ],
            proxy_server_statement_sha256=proxy_server_statement_sha256,
            issued_at_unix=exact_host_hardware_summary["issued_at_unix"],
        )
        try:
            verify_release_completion.verify_final_challenge_receipt(
                forged_receipt,
                trusted_public_key_pem=final_challenge_authority_key_info()[
                    "public_key_pem"
                ],
                expected_trusted_public_key_id=final_challenge_authority_key_info()[
                    "key_id"
                ],
                final_challenge_receipt_sha256=sha256_prefixed_json(
                    forged_receipt
                ),
                expected_provider="fixture-off-host-challenge-authority",
                expected_challenge_nonce_sha256=HARDWARE_ASSURANCE_CHALLENGE_SHA256,
                expected_completion_identity_sha256=final_completion_identity_sha256,
                expected_release_identity_sha256=exact_host_hardware_summary[
                    "release_identity_sha256"
                ],
                expected_hardware_verifier_key_id=exact_host_hardware_summary[
                    "trusted_verifier_key_id"
                ],
                expected_current_host_identity_sha256=exact_host_summary["identity"][
                    "identity_sha256"
                ],
                expected_proxy_server_statement_sha256=proxy_server_statement_sha256,
                hardware_assurance_issued_at_unix=exact_host_hardware_summary[
                    "issued_at_unix"
                ],
                now_unix=exact_host_hardware_summary["issued_at_unix"],
            )
        except ValueError as exc:
            if "completion_identity_sha256 mismatch" not in str(exc):
                raise AssertionError(
                    f"wrong-completion receipt failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError(
                "off-host challenge receipt authorized a different completion identity"
            )

        challenge_ledger = tmp / "final-challenge-ledger.json"
        first_consumption = verify_release_completion.consume_final_challenge_once(
            challenge_ledger,
            challenge_nonce_sha256=HARDWARE_ASSURANCE_CHALLENGE_SHA256,
            completion_identity_sha256=sha256_prefixed_json({"release": exact_host_hardware_summary["release_identity_sha256"]}),
        )
        if first_consumption.get("consumed") is not True or first_consumption.get("ledger_entries") != 1:
            raise AssertionError(f"final challenge was not atomically consumed: {first_consumption}")
        try:
            verify_release_completion.consume_final_challenge_once(
                challenge_ledger,
                challenge_nonce_sha256=HARDWARE_ASSURANCE_CHALLENGE_SHA256,
                completion_identity_sha256=digest("0"),
            )
        except ValueError as exc:
            if "final completion challenge was already consumed" not in str(exc):
                raise AssertionError(f"same-challenge replay failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("final completion accepted reuse of the same expected challenge")

        # Earlier direct hardware-verifier checks are intentionally extensive.
        # Start the subprocess-backed negative group with fresh signed evidence.
        valid_hardware_assurance = hardware_assurance_document(nitro, tmp)
        arbitrary_source_binding = clone_document(valid_hardware_assurance)
        forged_manifest = arbitrary_source_binding["statement"]["eif"]["build_manifest"]
        forged_manifest["release_identity"]["source_tree_digest"] = digest("0")
        forged_manifest["release_identity_sha256"] = sha256_prefixed_json(forged_manifest["release_identity"])
        arbitrary_source_binding["statement"]["eif"]["build_manifest_sha256"] = sha256_prefixed_json(forged_manifest)
        sign_hardware_assurance(arbitrary_source_binding)
        expect_hardware_assurance_failure(
            tmp,
            arbitrary_source_binding,
            "does not match the independently verified source/build/release identity",
            "trusted-signer arbitrary source-to-EIF binding",
        )
        write(tmp / "hardware-assurance.json", valid_hardware_assurance)

        unbound_legacy_hardware_summary = clone_document(exact_host_hardware_summary)
        unbound_legacy_hardware_summary.pop("expected_challenge_bound")
        try:
            verify_release_completion.completion_assurance(
                unbound_legacy_hardware_summary,
                exact_host_summary,
            )
        except ValueError as exc:
            if "not bound to an externally supplied expected challenge" not in str(exc):
                raise AssertionError(f"unbound hardware summary failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("completion assurance accepted a hardware summary without an expected challenge binding")

        try:
            verify_hardware_assurance_fixture(
                tmp,
                valid_hardware_assurance,
                exact_host_summary,
                expected_challenge_nonce=None,
            )
        except ValueError as exc:
            if "requires exactly one caller-expected challenge nonce or nonce SHA-256" not in str(exc):
                raise AssertionError(f"missing direct verifier challenge failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("hardware assurance verifier accepted evidence without an expected challenge")

        try:
            verify_hardware_assurance_fixture(
                tmp,
                valid_hardware_assurance,
                fixture_current_host_summary(host_b=True),
            )
        except ValueError as exc:
            if "does not match current completion host" not in str(exc):
                raise AssertionError(f"copied host-A evidence failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError("completion verifier accepted copied host-A hardware evidence on host B")

        unsigned_pcr_tamper = clone_document(valid_hardware_assurance)
        unsigned_pcr_tamper["statement"]["pcrs"]["PCR2"] = sha384("d")
        expect_hardware_assurance_failure(
            tmp,
            unsigned_pcr_tamper,
            "hardware assurance signature verification failed",
            "unsigned PCR tampering",
        )

        missing_host_identity = clone_document(valid_hardware_assurance)
        missing_host_identity["statement"].pop("current_host_identity")
        sign_hardware_assurance(missing_host_identity)
        expect_hardware_assurance_failure(
            tmp,
            missing_host_identity,
            "missing required fields",
            "signed hardware evidence without a current-host identity",
        )

        stale_host_identity = clone_document(valid_hardware_assurance)
        stale_host_identity["statement"]["current_host_identity"] = (
            verify_release_completion.current_host_identity_claim(
                fixture_current_host_identity(),
                observed_at_unix=stale_host_identity["statement"]["issued_at_unix"]
                - verify_release_completion.CURRENT_HOST_IDENTITY_MAX_OBSERVATION_AGE_SECONDS
                - 1,
            )
        )
        sign_hardware_assurance(stale_host_identity)
        expect_hardware_assurance_failure(
            tmp,
            stale_host_identity,
            "current-host identity observation is stale relative to assurance issuance",
            "signed hardware evidence with a stale current-host identity observation",
        )

        missing_pcr = clone_document(valid_hardware_assurance)
        missing_pcr["statement"]["pcrs"].pop("PCR2")
        sign_hardware_assurance(missing_pcr)
        expect_hardware_assurance_failure(tmp, missing_pcr, "missing required fields", "signed hardware evidence with a missing PCR")

        unverified_vsock = clone_document(valid_hardware_assurance)
        unverified_vsock["statement"]["enclave"]["vsock_handshake_verified"] = False
        sign_hardware_assurance(unverified_vsock)
        expect_hardware_assurance_failure(tmp, unverified_vsock, "did not verify a vsock handshake", "unverified vsock evidence")

        parent_key_access = clone_document(valid_hardware_assurance)
        parent_key_access["statement"]["key_custody"]["parent_process_key_access"] = True
        sign_hardware_assurance(parent_key_access)
        expect_hardware_assurance_failure(tmp, parent_key_access, "permits parent-process key access", "parent key access")

        absent_no_parent_proof = clone_document(valid_hardware_assurance)
        absent_no_parent_proof["statement"]["no_parent_key"]["parent_key_material_absent"] = False
        sign_hardware_assurance(absent_no_parent_proof)
        expect_hardware_assurance_failure(
            tmp,
            absent_no_parent_proof,
            "found key material in a parent process",
            "failed no-parent-key evidence",
        )

        mismatched_eif = clone_document(valid_hardware_assurance)
        mismatched_eif["statement"]["eif"]["image_sha384"] = sha384("d")
        sign_hardware_assurance(mismatched_eif)
        expect_hardware_assurance_failure(tmp, mismatched_eif, "does not match PCR0", "EIF/PCR mismatch")

        mismatched_release = clone_document(valid_hardware_assurance)
        mismatched_release["statement"]["release_bindings"]["source_tree_digest"] = digest("0")
        sign_hardware_assurance(mismatched_release)
        expect_hardware_assurance_failure(
            tmp,
            mismatched_release,
            "do not exactly match the Nitro-attested runtime",
            "hardware evidence for another release",
        )

        mismatched_artifact = clone_document(valid_hardware_assurance)
        mismatched_artifact["statement"]["artifact_bindings"]["nitro_evidence_sha256"] = digest("0")
        sign_hardware_assurance(mismatched_artifact)
        expect_hardware_assurance_failure(
            tmp,
            mismatched_artifact,
            "does not bind the current Nitro evidence artifact",
            "hardware evidence for another Nitro artifact",
        )

        reused_evidence = clone_document(valid_hardware_assurance)
        reused_evidence["statement"]["no_parent_key"]["evidence_sha256"] = reused_evidence["statement"]["eif"][
            "evidence_sha256"
        ]
        sign_hardware_assurance(reused_evidence)
        expect_hardware_assurance_failure(
            tmp,
            reused_evidence,
            "reused one evidence artifact",
            "one placeholder artifact reused for distinct hardware claims",
        )

        rogue_signer = clone_document(valid_hardware_assurance)
        rogue_key = ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x04" * 32))
        sign_hardware_assurance(rogue_signer, rogue_key)
        expect_hardware_assurance_failure(
            tmp,
            rogue_signer,
            "does not match the separately trusted verifier key",
            "self-selected hardware assurance signer",
        )

        stale_hardware = clone_document(valid_hardware_assurance)
        stale_hardware["statement"]["issued_at_unix"] = int(time.time()) - 1000
        stale_hardware["statement"]["expires_at_unix"] = int(time.time()) + 100
        sign_hardware_assurance(stale_hardware)
        expect_hardware_assurance_failure(tmp, stale_hardware, "hardware assurance is stale", "stale hardware evidence")
        write(tmp / "hardware-assurance.json", valid_hardware_assurance)

        test_proxy_response_proof_requirements(
            tmp,
            valid_proxy_response_proof,
            provenance_summary["provenance_digest"],
        )

        rejected_host_bypass = run_verifier(tmp, "--skip-current-host-check", allow_host_bypass=False)
        if rejected_host_bypass.returncode == 0 or "--skip-current-host-check is test-only" not in detail(rejected_host_bypass):
            raise AssertionError(f"completion verifier accepted host bypass without test-only opt-in: {detail(rejected_host_bypass)}")

        stale_config_preflight = production_host_preflight(tmp)
        write(tmp / "production-host-preflight.json", stale_config_preflight)
        write(tmp / "production-readiness-config.json", {**production_config_document(tmp / "production-readiness-config.json"), "checks": ["nitro"]})
        rejected_config = run_verifier(tmp)
        if rejected_config.returncode == 0 or "production config gate artifact omitted required checks" not in detail(rejected_config):
            raise AssertionError(f"completion verifier accepted a weak config gate artifact: {detail(rejected_config)}")
        write_production_config_files(tmp)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        forged_preflight_config = production_host_preflight(tmp)
        forged_preflight_config["checks"]["production_env"]["config_gate"]["semantic_sha256"] = digest("9")
        write(tmp / "production-host-preflight.json", forged_preflight_config)
        rejected_forged_config = run_verifier(tmp)
        if rejected_forged_config.returncode == 0 or "config gate semantic digest mismatch" not in detail(rejected_forged_config):
            raise AssertionError(f"completion verifier accepted forged preflight config digest: {detail(rejected_forged_config)}")
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        mismatched_readiness_env = production_readiness(nitro, tmp)
        mismatched_readiness_env["environment"]["production_readiness_env_sha256"] = digest("9")
        write(tmp / "production-readiness.json", mismatched_readiness_env)
        rejected_readiness_env = run_verifier(tmp)
        if rejected_readiness_env.returncode == 0 or "production readiness env digest does not match current production readiness env" not in detail(rejected_readiness_env):
            raise AssertionError(f"completion verifier accepted readiness from another env: {detail(rejected_readiness_env)}")
        write(tmp / "production-readiness.json", production_readiness(nitro, tmp))
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        mismatched_config_env = production_config_document(tmp / "production-readiness-config.json")
        mismatched_config_env["environment"]["production_images_env_sha256"] = digest("9")
        write(tmp / "production-readiness-config.json", mismatched_config_env)
        rejected_config_env = run_verifier(tmp)
        if rejected_config_env.returncode == 0 or "production config gate image env digest does not match production host preflight" not in detail(rejected_config_env):
            raise AssertionError(f"completion verifier accepted config gate from another image env: {detail(rejected_config_env)}")
        write_production_config_files(tmp)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        same_value = production_images_env_value()
        (tmp / "production.env").write_text(f"# semantic equivalent rewrite\nSERVERWARE_PRODUCTION_IMAGES='{same_value}'\n", encoding="utf-8")
        rejected_stale_env_preflight = run_verifier(tmp)
        if (
            rejected_stale_env_preflight.returncode == 0
            or "production host preflight production env digest does not match current production readiness env"
            not in detail(rejected_stale_env_preflight)
        ):
            raise AssertionError(f"completion verifier accepted stale production env preflight evidence: {detail(rejected_stale_env_preflight)}")
        write_production_env_files(tmp)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        (tmp / "production-images.env").write_text(f"# semantic equivalent rewrite\nSERVERWARE_PRODUCTION_IMAGES='{same_value}'\n", encoding="utf-8")
        rejected_stale_images_env_preflight = run_verifier(tmp)
        if (
            rejected_stale_images_env_preflight.returncode == 0
            or "production host preflight production images env digest does not match current production images env"
            not in detail(rejected_stale_images_env_preflight)
        ):
            raise AssertionError(f"completion verifier accepted stale production images env preflight evidence: {detail(rejected_stale_images_env_preflight)}")
        write_production_env_files(tmp)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        write_production_env_files(tmp, readiness_value=production_image_refs()[0])
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_env_merge = run_verifier(tmp)
        if (
            rejected_env_merge.returncode == 0
            or "production readiness env SERVERWARE_PRODUCTION_IMAGES does not match production images env"
            not in detail(rejected_env_merge)
        ):
            raise AssertionError(f"completion verifier accepted mismatched production env files: {detail(rejected_env_merge)}")
        write_production_env_files(tmp)

        stale_images_value = production_images_env_value(control_digest=digest("8"), gate_digest=digest("7"))
        write_production_env_files(tmp, images_value=stale_images_value)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_current_images = run_verifier(tmp)
        if rejected_current_images.returncode == 0 or "current production images env refs do not match readiness" not in detail(rejected_current_images):
            raise AssertionError(f"completion verifier accepted stale current production image env: {detail(rejected_current_images)}")
        write_production_env_files(tmp)

        stale_source_tree = digest("9")
        stale_provenance_summary, stale_provenance_document = release_provenance(
            sha256_file(tmp / "reproducible-build-verification.json")
        )
        stale_provenance_document["provenance"]["source_tree"]["digest"] = stale_source_tree
        refresh_release_provenance(stale_provenance_summary, stale_provenance_document)
        stale_image_summary, stale_image_document = image_signatures(
            stale_provenance_summary["provenance_digest"],
            source_tree_digest=stale_source_tree,
        )
        stale_build = production_images_build()
        stale_build["metadata"]["source_tree_digest"] = stale_source_tree
        write(tmp / "production-images-build.json", stale_build)
        write(tmp / "release-provenance-summary.json", stale_provenance_summary)
        write(tmp / "release-provenance.json", stale_provenance_document)
        write(tmp / "image-signatures-summary.json", stale_image_summary)
        write(tmp / "image-signatures.json", stale_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp, source_tree_digest=stale_source_tree))
        rejected_stale_source = run_verifier(tmp)
        if rejected_stale_source.returncode == 0 or "source tree digest does not match current source tree" not in detail(rejected_stale_source):
            raise AssertionError(f"completion verifier accepted stale source-tree artifacts: {detail(rejected_stale_source)}")
        write(tmp / "production-images-build.json", production_images_build())
        write(tmp / "release-provenance-summary.json", provenance_summary)
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_provenance_document = json.loads(json.dumps(provenance_document))
        bad_provenance_document["signature"] = "ed25519:" + b64e(b"\x00" * 64)
        write(tmp / "release-provenance.json", bad_provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_provenance_signature = run_verifier(tmp)
        if rejected_provenance_signature.returncode == 0 or "release provenance signature verification failed" not in detail(rejected_provenance_signature):
            raise AssertionError(f"completion verifier accepted forged release provenance: {detail(rejected_provenance_signature)}")
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        unauthorized_release_key = ed25519_key_info(Ed25519PrivateKey.from_private_bytes(b"\x02" * 32))
        unauthorized_provenance_summary = json.loads(json.dumps(provenance_summary))
        unauthorized_provenance_document = json.loads(json.dumps(provenance_document))
        unauthorized_signature = "ed25519:" + b64e(
            unauthorized_release_key["key"].sign(
                canonical_json(unauthorized_provenance_document["provenance"]).encode("utf-8")
            )
        )
        unauthorized_provenance_document["signature"] = unauthorized_signature
        unauthorized_provenance_document["release_signing_key_id"] = unauthorized_release_key["key_id"]
        unauthorized_provenance_document["release_signing_public_key_pem"] = unauthorized_release_key["public_key_pem"]
        unauthorized_provenance_document["transparency"] = transparency_for_record(
            {
                "type": "release.provenance.v2",
                "provenance_digest": unauthorized_provenance_document["provenance_digest"],
                "signature": unauthorized_signature,
                "release_signing_key_id": unauthorized_release_key["key_id"],
                "production_launcher_binary_digest": unauthorized_provenance_document[
                    "provenance"
                ]["images"]["serverware-decision-gate"][
                    "launcher_binary_digest"
                ],
                **unauthorized_provenance_document["provenance"]["launch_authority"],
            }
        )
        unauthorized_provenance_summary["release_signing_key_id"] = unauthorized_release_key["key_id"]
        write(tmp / "release-provenance-summary.json", unauthorized_provenance_summary)
        write(tmp / "release-provenance.json", unauthorized_provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_unauthorized_signer = run_verifier(tmp)
        if (
            rejected_unauthorized_signer.returncode == 0
            or "release provenance signer does not match the independently trusted release key"
            not in detail(rejected_unauthorized_signer)
        ):
            raise AssertionError(
                f"completion verifier accepted an unauthorized release signer: {detail(rejected_unauthorized_signer)}"
            )
        write(tmp / "release-provenance-summary.json", provenance_summary)
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_provenance_document = json.loads(json.dumps(provenance_document))
        release_checkpoint = bad_provenance_document["transparency"]["anchor_response"]["anchors"][0]["external_checkpoint"]
        release_checkpoint["log_id"] = digest("a")
        release_checkpoint["receipt"]["payload"]["log_id"] = digest("a")
        bad_provenance_document["transparency"]["inclusion_proof"]["item"]["external_checkpoint"] = json.loads(
            json.dumps(release_checkpoint)
        )
        write(tmp / "release-provenance.json", bad_provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_release_log = run_verifier(tmp)
        rejected_release_log_detail = detail(rejected_release_log)
        if rejected_release_log.returncode == 0 or not (
            "release provenance external transparency log does not match live readiness" in rejected_release_log_detail
            or "release provenance external transparency receipt public key does not match log id" in rejected_release_log_detail
            or "release provenance external transparency log is not the trusted log" in rejected_release_log_detail
        ):
            raise AssertionError(f"completion verifier accepted release provenance from another external log: {detail(rejected_release_log)}")
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_provenance_document = json.loads(json.dumps(provenance_document))
        release_checkpoint = bad_provenance_document["transparency"]["anchor_response"]["anchors"][0]["external_checkpoint"]
        release_checkpoint["receipt"]["signature"] = "ed25519:" + b64e(
            b"\x00" * 64
        )
        bad_provenance_document["transparency"]["inclusion_proof"]["item"]["external_checkpoint"] = json.loads(
            json.dumps(release_checkpoint)
        )
        write(tmp / "release-provenance.json", bad_provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_release_receipt = run_verifier(tmp)
        if rejected_release_receipt.returncode == 0 or "release provenance external transparency receipt signature verification failed" not in detail(rejected_release_receipt):
            raise AssertionError(f"completion verifier accepted release provenance with a forged external receipt: {detail(rejected_release_receipt)}")
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        split_checkpoint_document = json.loads(json.dumps(provenance_document))
        split_checkpoint = split_checkpoint_document["transparency"]["inclusion_proof"]["item"][
            "external_checkpoint"
        ]
        split_checkpoint["provider"] = "untrusted-split-log"
        split_checkpoint["log_id"] = digest("0")
        write(tmp / "release-provenance.json", split_checkpoint_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_split_checkpoint = run_verifier(tmp)
        if (
            rejected_split_checkpoint.returncode == 0
            or "transparency inclusion and anchor response used different external checkpoints"
            not in detail(rejected_split_checkpoint)
        ):
            raise AssertionError(
                f"completion verifier accepted split external checkpoints: {detail(rejected_split_checkpoint)}"
            )
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_provenance_document = json.loads(json.dumps(provenance_document))
        bad_provenance_document["transparency"]["record"]["provenance_digest"] = digest("0")
        write(tmp / "release-provenance.json", bad_provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_release_record = run_verifier(tmp)
        if rejected_release_record.returncode == 0 or "release provenance transparency record provenance_digest mismatch" not in detail(rejected_release_record):
            raise AssertionError(f"completion verifier accepted release provenance with a swapped transparency record: {detail(rejected_release_record)}")
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_provenance_document = json.loads(json.dumps(provenance_document))
        bad_provenance_document["transparency"]["inclusion_proof"]["proof"] = [{"side": "right", "hash": digest("0")}]
        write(tmp / "release-provenance.json", bad_provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_release_merkle = run_verifier(tmp)
        if rejected_release_merkle.returncode == 0 or "release provenance transparency Merkle inclusion proof did not verify" not in detail(rejected_release_merkle):
            raise AssertionError(f"completion verifier accepted release provenance with a bad Merkle proof: {detail(rejected_release_merkle)}")
        write(tmp / "release-provenance.json", provenance_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        image_checkpoint = bad_image_document["metadata"]["transparency"]["anchorResponse"]["anchors"][0]["external_checkpoint"]
        image_checkpoint["log_id"] = digest("a")
        image_checkpoint["receipt"]["payload"]["log_id"] = digest("a")
        bad_image_document["metadata"]["transparency"]["inclusionProof"]["item"]["external_checkpoint"] = json.loads(
            json.dumps(image_checkpoint)
        )
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_image_log = run_verifier(tmp)
        rejected_image_log_detail = detail(rejected_image_log)
        if rejected_image_log.returncode == 0 or not (
            "image signature bundle external transparency log does not match live readiness" in rejected_image_log_detail
            or "image signature bundle external transparency receipt public key does not match log id" in rejected_image_log_detail
            or "image signature bundle external transparency log is not the trusted log" in rejected_image_log_detail
        ):
            raise AssertionError(f"completion verifier accepted image signatures from another external log: {detail(rejected_image_log)}")
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        image_checkpoint = bad_image_document["metadata"]["transparency"]["anchorResponse"]["anchors"][0]["external_checkpoint"]
        image_checkpoint["receipt"]["signature"] = "ed25519:" + b64e(
            b"\x00" * 64
        )
        bad_image_document["metadata"]["transparency"]["inclusionProof"]["item"]["external_checkpoint"] = json.loads(
            json.dumps(image_checkpoint)
        )
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_image_receipt = run_verifier(tmp)
        if rejected_image_receipt.returncode == 0 or "image signature bundle external transparency receipt signature verification failed" not in detail(rejected_image_receipt):
            raise AssertionError(f"completion verifier accepted image signatures with a forged external receipt: {detail(rejected_image_receipt)}")
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["sigstore"]["bundle"]["messageSignature"]["messageDigest"]["digest"] = "0" * 64
        refresh_image_signature_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_image_bundle_digest = run_verifier(tmp)
        if rejected_image_bundle_digest.returncode == 0 or "image serverware Sigstore bundle digest mismatch" not in detail(rejected_image_bundle_digest):
            raise AssertionError(f"completion verifier accepted image signatures with a forged Sigstore bundle digest: {detail(rejected_image_bundle_digest)}")
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        forged_sigstore_summary, forged_sigstore_document = image_signatures(
            provenance_summary["provenance_digest"]
        )
        forged_sigstore = forged_sigstore_document["images"][0]["sigstore"]
        forged_signature = "ed25519:" + b64e(b"\x00" * 64)
        forged_sigstore["signature"] = forged_signature
        forged_sigstore["bundle"]["messageSignature"]["signature"] = forged_signature
        forged_sigstore_document["images"][0]["signature"] = forged_signature
        refresh_image_signature_bundle(forged_sigstore_summary, forged_sigstore_document)
        write(tmp / "image-signatures-summary.json", forged_sigstore_summary)
        write(tmp / "image-signatures.json", forged_sigstore_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_forged_sigstore = run_verifier(tmp)
        if (
            rejected_forged_sigstore.returncode == 0
            or "image serverware Sigstore message signature verification failed"
            not in detail(rejected_forged_sigstore)
        ):
            raise AssertionError(
                f"completion verifier accepted forged Sigstore evidence: {detail(rejected_forged_sigstore)}"
            )
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["metadata"]["transparency"]["record"]["image_signature_bundle_digest"] = digest("0")
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_image_record = run_verifier(tmp)
        if rejected_image_record.returncode == 0 or "image signature bundle transparency record image_signature_bundle_digest mismatch" not in detail(rejected_image_record):
            raise AssertionError(f"completion verifier accepted image signatures with a swapped transparency record: {detail(rejected_image_record)}")
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["metadata"]["transparency"]["inclusionProof"][
            "signed_tree_head"
        ]["signature"] = "ed25519:" + b64e(b"\x00" * 64)
        bad_image_document["metadata"]["transparency"]["anchorResponse"]["anchors"][0]["signed_tree_head"] = bad_image_document["metadata"]["transparency"]["inclusionProof"]["signed_tree_head"]
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_image_sth = run_verifier(tmp)
        if rejected_image_sth.returncode == 0 or "image signature bundle signed tree head signature verification failed" not in detail(rejected_image_sth):
            raise AssertionError(f"completion verifier accepted image signatures with a forged signed tree head: {detail(rejected_image_sth)}")
        write(tmp / "image-signatures-summary.json", image_summary)
        write(tmp / "image-signatures.json", image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        mismatched_nitro = nitro_evidence(provenance_summary["provenance_digest"])
        mismatched_nitro["nitro"]["raw_attestation_document_sha256"] = digest("9")
        for release in mismatched_nitro["release_materials"]:
            release["kms_release"]["attestation_document_sha256"] = digest("9")
        write(tmp / "nitro-kms-evidence.json", mismatched_nitro)
        rejected_nitro = run_verifier(tmp)
        if rejected_nitro.returncode == 0 or "does not match live readiness attestation" not in detail(rejected_nitro):
            raise AssertionError(f"completion verifier accepted mismatched Nitro evidence: {detail(rejected_nitro)}")
        write(tmp / "nitro-kms-evidence.json", nitro)

        mismatched_command = nitro_evidence(provenance_summary["provenance_digest"])
        mismatched_command["config"]["kms_release_command_sha256"] = digest("9")
        write(tmp / "nitro-kms-evidence.json", mismatched_command)
        rejected_command = run_verifier(tmp)
        if rejected_command.returncode == 0 or "command hashes do not match live readiness" not in detail(rejected_command):
            raise AssertionError(f"completion verifier accepted mismatched Nitro/KMS commands: {detail(rejected_command)}")
        write(tmp / "nitro-kms-evidence.json", nitro)

        mismatched_request_digest = nitro_evidence(provenance_summary["provenance_digest"])
        mismatched_request_digest["release_materials"][0]["kms_release"]["request_digest"] = digest("9")
        write(tmp / "nitro-kms-evidence.json", mismatched_request_digest)
        rejected_request_digest = run_verifier(tmp)
        if rejected_request_digest.returncode == 0 or "KMS request digest mismatch" not in detail(rejected_request_digest):
            raise AssertionError(f"completion verifier accepted mismatched KMS request digest: {detail(rejected_request_digest)}")
        write(tmp / "nitro-kms-evidence.json", nitro)

        mismatched_recipient_handle = nitro_evidence(provenance_summary["provenance_digest"])
        mismatched_recipient_handle["release_materials"][0]["kms_release"]["material_handle"] = digest("9")
        write(tmp / "nitro-kms-evidence.json", mismatched_recipient_handle)
        rejected_recipient_handle = run_verifier(tmp)
        if rejected_recipient_handle.returncode == 0 or "material handle does not match recipient ciphertext digest" not in detail(rejected_recipient_handle):
            raise AssertionError(f"completion verifier accepted mismatched recipient ciphertext handle: {detail(rejected_recipient_handle)}")
        write(tmp / "nitro-kms-evidence.json", nitro)

        mismatched_recipient_attestation = nitro_evidence(provenance_summary["provenance_digest"])
        mismatched_recipient_attestation["release_materials"][0]["kms_release"]["attestation_document_sha256"] = digest("9")
        write(tmp / "nitro-kms-evidence.json", mismatched_recipient_attestation)
        rejected_recipient_attestation = run_verifier(tmp)
        if rejected_recipient_attestation.returncode == 0 or "KMS release attestation digest does not match Nitro evidence" not in detail(rejected_recipient_attestation):
            raise AssertionError(f"completion verifier accepted mismatched KMS Recipient attestation: {detail(rejected_recipient_attestation)}")
        write(tmp / "nitro-kms-evidence.json", nitro)

        mismatched_kms_preflight = production_host_preflight(tmp)
        mismatched_kms_preflight["checks"]["kms_materials"]["materials"][0]["key_id_sha256"] = digest("9")
        write(tmp / "production-host-preflight.json", mismatched_kms_preflight)
        rejected_kms = run_verifier(tmp)
        if rejected_kms.returncode == 0 or "KMS material bindings" not in detail(rejected_kms):
            raise AssertionError(f"completion verifier accepted mismatched KMS material bindings: {detail(rejected_kms)}")
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        mismatched_kms_ciphertext = production_host_preflight(tmp)
        mismatched_kms_ciphertext["checks"]["kms_materials"]["materials"][0]["ciphertext_blob_sha256"] = digest("9")
        write(tmp / "production-host-preflight.json", mismatched_kms_ciphertext)
        rejected_kms_ciphertext = run_verifier(tmp)
        if rejected_kms_ciphertext.returncode == 0 or "KMS material bindings" not in detail(rejected_kms_ciphertext):
            raise AssertionError(f"completion verifier accepted mismatched KMS ciphertext binding: {detail(rejected_kms_ciphertext)}")
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        stale_kms_preflight = production_host_preflight(tmp)
        write(tmp / "production-host-preflight.json", stale_kms_preflight)
        changed_materials = kms_materials_document()
        changed_materials["broker-kek"]["ciphertext_blob_b64"] = base64.b64encode(b"same-key-different-ciphertext").decode("ascii")
        write(tmp / "kms-materials.json", changed_materials)
        rejected_kms_file = run_verifier(tmp)
        if rejected_kms_file.returncode == 0 or "KMS materials digest does not match current KMS materials file" not in detail(rejected_kms_file):
            raise AssertionError(f"completion verifier accepted stale KMS materials file evidence: {detail(rejected_kms_file)}")
        write(tmp / "kms-materials.json", kms_materials_document())
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        forged_kms_preflight = production_host_preflight(tmp)
        changed_materials = kms_materials_document()
        changed_materials["broker-kek"]["ciphertext_blob_b64"] = base64.b64encode(b"same-key-forged-preflight-ciphertext").decode("ascii")
        write(tmp / "kms-materials.json", changed_materials)
        forged_kms_preflight["checks"]["kms_materials"]["file"] = file_summary(tmp / "kms-materials.json", "kms-materials")
        write(tmp / "production-host-preflight.json", forged_kms_preflight)
        rejected_forged_kms_preflight = run_verifier(tmp)
        if rejected_forged_kms_preflight.returncode == 0 or "KMS material bindings do not match current KMS materials file" not in detail(rejected_forged_kms_preflight):
            raise AssertionError(f"completion verifier accepted forged KMS preflight material bindings: {detail(rejected_forged_kms_preflight)}")
        write(tmp / "kms-materials.json", kms_materials_document())
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        malformed_kms_materials = kms_materials_document()
        malformed_kms_materials["broker-kek"]["ciphertext_blob_b64"] = "not-valid-@@@@"
        write(tmp / "kms-materials.json", malformed_kms_materials)
        malformed_kms_preflight = production_host_preflight(tmp)
        malformed_kms_preflight["checks"]["kms_materials"]["file"] = file_summary(tmp / "kms-materials.json", "kms-materials")
        write(tmp / "production-host-preflight.json", malformed_kms_preflight)
        rejected_malformed_kms = run_verifier(tmp)
        if rejected_malformed_kms.returncode == 0 or "ciphertext blob is invalid base64" not in detail(rejected_malformed_kms):
            raise AssertionError(f"completion verifier accepted malformed KMS ciphertext base64: {detail(rejected_malformed_kms)}")
        write(tmp / "kms-materials.json", kms_materials_document())
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        unauthorized_kms_materials = kms_materials_document()
        unauthorized_kms_materials["debug-material"] = {
            "key_id": "arn:aws:kms:us-east-1:111122223333:key/debug",
            "ciphertext_blob_b64": base64.b64encode(b"debug-ciphertext").decode("ascii"),
            "encryption_context": {"material": "debug-material", "service": "serverware"},
        }
        write(tmp / "kms-materials.json", unauthorized_kms_materials)
        unauthorized_kms_preflight = production_host_preflight(tmp)
        unauthorized_kms_preflight["checks"]["kms_materials"]["file"] = file_summary(tmp / "kms-materials.json", "kms-materials")
        write(tmp / "production-host-preflight.json", unauthorized_kms_preflight)
        rejected_unauthorized_kms = run_verifier(tmp)
        if rejected_unauthorized_kms.returncode == 0 or "unauthorized materials" not in detail(rejected_unauthorized_kms):
            raise AssertionError(f"completion verifier accepted unauthorized KMS materials: {detail(rejected_unauthorized_kms)}")
        write(tmp / "kms-materials.json", kms_materials_document())
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))

        slow_bench = benchmark_document(p99_ms=21.0)
        write(tmp / "decision-gate-rs-bench.json", slow_bench)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected = run_verifier(tmp)
        if rejected.returncode == 0 or "p99" not in detail(rejected):
            raise AssertionError(f"completion verifier accepted a slow benchmark: {detail(rejected)}")

        write(
            tmp / "decision-gate-rs-bench.json",
            benchmark_document(),
        )
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        stale_preflight_bench = benchmark_document(p99_ms=10.0)
        write(tmp / "decision-gate-rs-bench.json", stale_preflight_bench)
        rejected_stale = run_verifier(tmp)
        if rejected_stale.returncode == 0 or "preflight bench digest" not in detail(rejected_stale):
            raise AssertionError(f"completion verifier accepted stale preflight evidence: {detail(rejected_stale)}")
        write(
            tmp / "decision-gate-rs-bench.json",
            benchmark_document(),
        )
        skipped_config_preflight = production_host_preflight(tmp)
        skipped_config_preflight["checks"]["production_env"]["config_gate"]["skipped"] = True
        write(tmp / "production-host-preflight.json", skipped_config_preflight)
        rejected_skipped_config = run_verifier(tmp)
        if rejected_skipped_config.returncode == 0 or "skipped the config gate" not in detail(rejected_skipped_config):
            raise AssertionError(f"completion verifier accepted a skipped preflight config gate: {detail(rejected_skipped_config)}")

        mismatched_publish = production_images_published()
        mismatched_publish["images"][0]["local_image_id"] = digest("c")
        write(tmp / "production-images-published.json", mismatched_publish)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_publish = run_verifier(tmp)
        if rejected_publish.returncode == 0 or "published production images do not match current no-shell build" not in detail(rejected_publish):
            raise AssertionError(f"completion verifier accepted a publish manifest from another build: {detail(rejected_publish)}")

        write(tmp / "production-images-published.json", production_images_published())
        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_summary["image_signing_key_id"] = digest("d")
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_signing_key = run_verifier(tmp)
        if rejected_signing_key.returncode == 0 or "image signing key does not match live Sigstore key" not in detail(rejected_signing_key):
            raise AssertionError(f"completion verifier accepted image signatures from another signing key: {detail(rejected_signing_key)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["sigstore"]["transparency"]["log_id"] = digest("c")
        refresh_image_signature_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_rekor = run_verifier(tmp)
        if rejected_rekor.returncode == 0 or "transparency log does not match live Rekor log" not in detail(rejected_rekor):
            raise AssertionError(f"completion verifier accepted image signatures from another Rekor log: {detail(rejected_rekor)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["statement"]["predicate"]["repo_digests"] = []
        refresh_image_statements_and_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_refs = run_verifier(tmp)
        if rejected_refs.returncode == 0 or "published production image refs" not in detail(rejected_refs):
            raise AssertionError(f"completion verifier accepted image signatures without published refs: {detail(rejected_refs)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["sigstore"]["statement_digest"] = digest("0")
        refresh_image_signature_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_statement_digest = run_verifier(tmp)
        if rejected_statement_digest.returncode == 0 or "Sigstore statement digest mismatch" not in detail(rejected_statement_digest):
            raise AssertionError(f"completion verifier accepted a Sigstore proof for another statement: {detail(rejected_statement_digest)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["sigstore"]["key_provider"]["key_id"] = digest("0")
        refresh_image_signature_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_sigstore_key = run_verifier(tmp)
        if rejected_sigstore_key.returncode == 0 or "Sigstore signing key mismatch" not in detail(rejected_sigstore_key):
            raise AssertionError(f"completion verifier accepted a per-image Sigstore proof from another key: {detail(rejected_sigstore_key)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["signature"] = "sigstore:test:other"
        refresh_image_signature_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_sigstore_signature = run_verifier(tmp)
        if rejected_sigstore_signature.returncode == 0 or "Sigstore signature mismatch" not in detail(rejected_sigstore_signature):
            raise AssertionError(f"completion verifier accepted a mismatched per-image signature: {detail(rejected_sigstore_signature)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["metadata"]["signature"] = "sigstore:test:other"
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_bundle_signature = run_verifier(tmp)
        if rejected_bundle_signature.returncode == 0 or "metadata signature mismatch" not in detail(rejected_bundle_signature):
            raise AssertionError(f"completion verifier accepted a mismatched bundle signature: {detail(rejected_bundle_signature)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["bundle_signature"]["statement_digest"] = digest("0")
        bad_image_document["metadata"]["bundleSigstore"] = bad_image_document["bundle_signature"]
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_bundle_digest = run_verifier(tmp)
        if rejected_bundle_digest.returncode == 0 or "bundle Sigstore statement digest mismatch" not in detail(rejected_bundle_digest):
            raise AssertionError(f"completion verifier accepted a bundle Sigstore proof for another payload: {detail(rejected_bundle_digest)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["statement"]["predicate"]["release_signing_key_id"] = digest("0")
        refresh_image_statements_and_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_release_key = run_verifier(tmp)
        if rejected_release_key.returncode == 0 or "statement release signing key mismatch" not in detail(rejected_release_key):
            raise AssertionError(f"completion verifier accepted image signatures from another release key: {detail(rejected_release_key)}")

        bad_image_summary, bad_image_document = image_signatures(provenance_summary["provenance_digest"])
        bad_image_document["images"][0]["statement"]["predicate"]["source_tree_digest"] = digest("0")
        refresh_image_statements_and_bundle(bad_image_summary, bad_image_document)
        write(tmp / "image-signatures-summary.json", bad_image_summary)
        write(tmp / "image-signatures.json", bad_image_document)
        write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
        rejected_source = run_verifier(tmp)
        if rejected_source.returncode == 0 or "source tree digest mismatch" not in detail(rejected_source):
            raise AssertionError(f"completion verifier accepted image signatures with wrong source binding: {detail(rejected_source)}")

    print(canonical_json({"ok": True, "attestation_assurance_ceiling": "pass"}))


if __name__ == "__main__":
    main()
