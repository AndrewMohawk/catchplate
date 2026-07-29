#!/usr/bin/env python3
from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import os
import shlex
import stat
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
import test_run_production_readiness as readiness_runner_test
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


def refresh_readiness_v6_proof_core(proof: dict[str, Any]) -> None:
    proof["proof_core_sha256"] = sha256_prefixed_json(
        verify_release_completion.host_readiness_completion_proof_v6_core(
            proof
        )
    )


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

        fifo_path = tmp / "blocking-final-input.fifo"
        os.mkfifo(fifo_path)
        fifo_probe_code = "\n".join(
            (
                "import sys",
                "from pathlib import Path",
                "sys.path.insert(0, 'scripts')",
                "import verify_release_completion as verifier",
                "try:",
                "    verifier.snapshot_regular_file(Path(sys.argv[1]), 'FIFO completion input', max_bytes=1024)",
                "except ValueError as exc:",
                "    if 'must be a regular file' not in str(exc):",
                "        raise",
                "else:",
                "    raise AssertionError('snapshot_regular_file accepted a FIFO')",
            )
        )
        try:
            fifo_probe = subprocess.run(
                [sys.executable, "-c", fifo_probe_code, str(fifo_path)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=5,
                env=clean_subprocess_env(),
            )
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(
                "snapshot_regular_file blocked while rejecting a FIFO"
            ) from exc
        if fifo_probe.returncode != 0:
            raise AssertionError(
                "snapshot_regular_file failed to reject a FIFO promptly: "
                + detail(fifo_probe)
            )

        hardlink_source = tmp / "hardlink-source.json"
        hardlink_alias = tmp / "hardlink-alias.json"
        hardlink_source.write_bytes(b'{"artifact":"shared-inode"}\n')
        os.link(hardlink_source, hardlink_alias)
        try:
            verify_release_completion.snapshot_regular_file(
                hardlink_source,
                "hardlinked completion artifact",
                max_bytes=1024,
            )
        except ValueError as exc:
            if "hardlink aliases" not in str(exc):
                raise AssertionError(
                    f"hardlinked final inputs failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError("snapshot_regular_file accepted a hardlinked input")

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


def test_final_mode_observation_signing_key_dereference() -> None:
    source_tree = ast.parse(
        (ROOT / "scripts/verify_release_completion.py").read_text(encoding="utf-8")
    )
    role_values: list[ast.expr] = []
    for node in ast.walk(source_tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if (
                isinstance(key, ast.Constant)
                and key.value == "control_plane_response_signer"
            ):
                role_values.append(value)
    if len(role_values) != 1:
        raise AssertionError(
            "final mode must define exactly one control-plane response signer role"
        )
    role_value = role_values[0]
    if not (
        isinstance(role_value, ast.Subscript)
        and isinstance(role_value.value, ast.Name)
        and role_value.value.id == "proxy_response_summary"
        and isinstance(role_value.slice, ast.Constant)
        and role_value.slice.value == "control_plane_response_signing_key_id"
    ):
        raise AssertionError(
            "final mode must use the stable observation summary signing key ID "
            "without dereferencing the optional authorization receipt"
        )


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


def nonce_rollback_contract_fixture() -> tuple[dict[str, Any], bytes, str, str]:
    evidence_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("41" * 32))
    verifier_state_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("42" * 32)
    )
    verifier_state_store_attestation_key = (
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex("43" * 32))
    )
    evidence_spki = evidence_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier_state_spki = verifier_state_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier_state_store_attestation_spki = (
        verifier_state_store_attestation_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assurance = {
        "apiVersion": "serverware.nonceAuthorityAssurance/v1",
        "administrativeDomainSha256": digest("a"),
        "assuranceEvidenceSha256": digest("b"),
        "assuranceEvidenceType": "linearizableCasOperatorAttestation",
        "assuranceLevel": "productionRollbackProtected",
        "authorityEpoch": 1,
        "authorityGeneration": 2,
        "authorityIdentitySha256": digest("c"),
        "backendClass": "independentlyAdministeredLinearizableCas",
        "productionEligible": True,
        "rollbackProtection": {
            "administrativeRollbackResistance": True,
            "backendAttestationRequired": True,
            "exactSuccessorRequired": True,
            "freshVerifierChallengeRequired": True,
            "keyProtection": "nonExportableKmsHsm",
            "mechanism": "linearizableCasWithRollbackProtectedStorage",
            "stateCommitment": "hashChainedLinearizableCommitment",
            "verifierStateStoreClass": "independentlyAdministeredLinearizableCas",
        },
    }
    assurance_sha256 = sha256_prefixed_json(assurance)
    contract = {
        "apiVersion": (
            run_production_readiness.NONCE_ROLLBACK_ASSURANCE_PINS_API_VERSION
        ),
        "independentVerifierPins": {
            "expectedNonceAuthorityAssuranceIssuerSpkiSha256": (
                sha256_prefixed_bytes(evidence_spki)
            ),
            "expectedNonceAuthorityAssuranceSha256": assurance_sha256,
        },
        "publicConfigPins": {
            "nonceAuthorityAssurance": assurance,
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url": (
                b64e(evidence_spki)
            ),
            "nonceAuthorityAssuranceSha256": assurance_sha256,
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url": (
                b64e(verifier_state_spki)
            ),
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256": (
                digest("d")
            ),
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256": (
                digest("f")
            ),
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url": (
                b64e(verifier_state_store_attestation_spki)
            ),
            "nonceAuthorityVerifierStateStoreIdentitySha256": digest("e"),
        },
    }
    canonical = canonical_json(contract).encode("ascii")
    pins_bytes = canonical + b"\n"
    return (
        contract,
        pins_bytes,
        sha256_prefixed_bytes(pins_bytes),
        sha256_prefixed_bytes(canonical),
    )


def launch_authorization_security_fixture() -> dict[str, Any]:
    authority_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("33" * 32)
    )
    witness_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("35" * 32)
    )
    witness_store_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("36" * 32)
    )
    witness_tls_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("37" * 32)
    )
    policy_activation_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("38" * 32)
    )
    policy_identity_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("39" * 32)
    )
    reproducible_build_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("3a" * 32)
    )

    def spki(private_key: Ed25519PrivateKey) -> bytes:
        return private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    authority_key_id = launch_authorization.spki_key_id(spki(authority_key))
    witness_key_id = launch_authorization.spki_key_id(spki(witness_key))
    witness_store_key_id = launch_authorization.spki_key_id(
        spki(witness_store_key)
    )
    witness_identity_sha256 = sha256_prefixed_bytes(
        b"fixture-launch-authority-witness-identity"
    )
    witness_administrative_domain_sha256 = sha256_prefixed_bytes(
        b"fixture-launch-authority-witness-administrative-domain"
    )
    witness_store_statement = {
        "assuranceIssuerKeyId": witness_store_key_id,
        "witnessKeyId": witness_key_id,
        "witnessIdentitySha256": witness_identity_sha256,
        "witnessAdministrativeDomainSha256": (
            witness_administrative_domain_sha256
        ),
        "storeIdentitySha256": sha256_prefixed_bytes(
            b"fixture-launch-authority-witness-store"
        ),
        "storeAdministrativeDomainSha256": sha256_prefixed_bytes(
            b"fixture-launch-authority-witness-store-administrative-domain"
        ),
        "storeClass": "independentlyAdministeredLinearizableCas",
        "rollbackResistance": "externally-witnessed-monotonic",
        "independentAdministration": True,
    }
    witness_store_unsigned = {
        "apiVersion": "serverware.launchAuthorityWitnessStoreAssurance/v1",
        "kind": "LaunchAuthorityWitnessStoreAssurance",
        "statement": witness_store_statement,
    }
    witness_store_assurance = {
        **witness_store_unsigned,
        "signature": b64e(
            witness_store_key.sign(
                b"serverware.launchAuthorityWitnessStoreAssurance/v1\0"
                + launch_authorization.canonical_json_bytes(
                    witness_store_unsigned
                )
            )
        ),
    }
    nonce_contract, _pins_bytes, _pins_sha256, _contract_sha256 = (
        nonce_rollback_contract_fixture()
    )
    nonce_public = nonce_contract["publicConfigPins"]
    roles = {
        "launchAuthority": authority_key_id,
        "launchAuthorityWitness": witness_key_id,
        "launchAuthorityWitnessStoreAssurance": witness_store_key_id,
        "launchAuthorityWitnessTls": launch_authorization.spki_key_id(
            spki(witness_tls_key)
        ),
        "nonceAuthorityAssuranceEvidence": sha256_prefixed_bytes(
            b64d(
                nonce_public[
                    "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
                ]
            )
        ),
        "nonceAuthorityVerifierState": sha256_prefixed_bytes(
            b64d(
                nonce_public[
                    "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
                ]
            )
        ),
        "nonceAuthorityVerifierStateStoreAttestation": sha256_prefixed_bytes(
            b64d(
                nonce_public[
                    "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
                ]
            )
        ),
        "policyActivation": launch_authorization.spki_key_id(
            spki(policy_activation_key)
        ),
        "policyIdentity": launch_authorization.spki_key_id(
            spki(policy_identity_key)
        ),
        "reproducibleBuild": launch_authorization.spki_key_id(
            spki(reproducible_build_key)
        ),
    }
    global_role_registry = (
        launch_authorization.build_launch_global_role_registry(roles)
    )
    return {
        "authorityKey": authority_key,
        "authorityKeyId": authority_key_id,
        "witnessKey": witness_key,
        "witnessKeyId": witness_key_id,
        "witnessPublicKeySpkiDerBase64url": b64e(spki(witness_key)),
        "witnessIdentitySha256": witness_identity_sha256,
        "witnessAdministrativeDomainSha256": (
            witness_administrative_domain_sha256
        ),
        "witnessStoreAssurance": witness_store_assurance,
        "witnessStoreAssuranceIssuerKeyId": witness_store_key_id,
        "witnessStoreAssuranceIssuerPublicKeySpkiDerBase64url": b64e(
            spki(witness_store_key)
        ),
        "witnessStoreAssuranceSha256": sha256_prefixed_bytes(
            launch_authorization.canonical_json_bytes(
                witness_store_assurance
            )
        ),
        "globalRoleRegistry": global_role_registry,
        "globalRoleRegistrySha256": (
            launch_authorization.launch_global_role_registry_sha256(
                global_role_registry
            )
        ),
        "globalRoleRegistryPinsSha256": sha256_prefixed_bytes(
            launch_authorization.canonical_json_bytes(
                global_role_registry
            )
            + b"\n"
        ),
    }


def bootstrap_receipt_fixture(
    *,
    deployment_identity_sha256: str = "sha256:" + "a" * 64,
    release_sequence: int = 42,
    rollback_epoch: int = 7,
    legacy_v2: bool = False,
    manifest_sha256: str | None = None,
) -> dict[str, Any]:
    if legacy_v2:
        receipt = bootstrap_receipt_fixture(
            deployment_identity_sha256=deployment_identity_sha256,
            release_sequence=release_sequence,
            rollback_epoch=rollback_epoch,
            manifest_sha256=manifest_sha256,
        )
        receipt["apiVersion"] = "serverware.bootstrapReceipt/v2"
        return receipt

    def metadata(*, mode: int = 0o400, link_count: int = 1) -> dict[str, int]:
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

    (
        nonce_contract,
        _nonce_pins_bytes,
        nonce_pins_sha256,
        nonce_contract_sha256,
    ) = nonce_rollback_contract_fixture()
    launcher_digest = digest("3")
    receipt = {
        "apiVersion": (
            "serverware.bootstrapReceipt/v2"
            if legacy_v2
            else run_production_readiness.BOOTSTRAP_RECEIPT_API_VERSION
        ),
        "kind": "ProductionBootstrapReceipt",
        "launchId": "1" * 64,
        "bootIdSha256": digest("2"),
        "launcher": file_record(
            "/opt/serverware/launchers/sha256-"
            + launcher_digest.removeprefix("sha256:")
            + "/serverware-production-launcher",
            "3",
        ),
        "manifest": {
            **file_record(
                "/etc/serverware/production-release-launch.json",
                "4",
            ),
            "sha256": manifest_sha256 or digest("4"),
        },
        "sourceTreeDigest": SOURCE_TREE_DIGEST,
        "productionEnv": file_record("/etc/serverware/production-readiness.env", "5"),
        "python": {
            **file_record("/opt/serverware/releases/fixture/runtime/python/bin/python3", "6"),
            "importRoots": [
                {
                    "path": "/opt/serverware/releases/fixture",
                    "sha256": digest("7"),
                    "metadata": metadata(mode=0o555, link_count=2),
                },
                {
                    "path": "/opt/serverware/releases/fixture/runtime/python/lib/python3.11",
                    "sha256": digest("6"),
                    "metadata": metadata(mode=0o555, link_count=2),
                },
                {
                    "path": "/opt/serverware/releases/fixture/runtime/python/lib/python3.11/lib-dynload",
                    "sha256": digest("5"),
                    "metadata": metadata(mode=0o555, link_count=2),
                },
                {
                    "path": "/opt/serverware/releases/fixture/vendor",
                    "sha256": digest("4"),
                    "metadata": metadata(mode=0o555, link_count=2),
                },
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
    if not legacy_v2:
        receipt["nonceRollbackAssurance"] = {
            "apiVersion": (
                run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
            ),
            "contractSha256": nonce_contract_sha256,
            "pinsFile": {
                **file_record(
                    "/etc/serverware/nonce-rollback-assurance-pins.json",
                    "0",
                ),
                "sha256": nonce_pins_sha256,
            },
            "retainedSnapshotFd": 199,
            "retainedSnapshotSha256": nonce_pins_sha256,
            "verifierStateService": {
                "signingPublicKeySpkiDerBase64url": nonce_contract[
                    "publicConfigPins"
                ][
                    "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
                ],
                "storeAdministrativeDomainSha256": digest("d"),
                "storeAssuranceEvidenceSha256": digest("f"),
                "storeAttestationPublicKeySpkiDerBase64url": nonce_contract[
                    "publicConfigPins"
                ][
                    "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
                ],
                "storeIdentitySha256": digest("e"),
            },
        }
    security = launch_authorization_security_fixture()
    request = {
        "apiVersion": launch_authorization.REQUEST_API_VERSION,
        "kind": launch_authorization.REQUEST_KIND,
        "launcherNonce": receipt["launchId"],
        "bootIdSha256": receipt["bootIdSha256"],
        "launcherSha256": receipt["launcher"]["sha256"],
        "manifestSha256": receipt["manifest"]["sha256"],
        "nonceRollbackAssuranceContractSha256": receipt[
            "nonceRollbackAssurance"
        ]["contractSha256"],
        "nonceRollbackAssurancePinsSha256": receipt[
            "nonceRollbackAssurance"
        ]["retainedSnapshotSha256"],
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
        "authorizationScope": launch_authorization.AUTHORIZATION_SCOPE,
        "freshnessAuthority": launch_authorization.FRESHNESS_AUTHORITY,
        "launchAuthorityWitnessChallenge": "3" * 64,
        "launchAuthorityWitnessKeyId": security["witnessKeyId"],
        "launchAuthorityWitnessIdentitySha256": security[
            "witnessIdentitySha256"
        ],
        "launchAuthorityWitnessAdministrativeDomainSha256": security[
            "witnessAdministrativeDomainSha256"
        ],
        "launchAuthorityWitnessStoreAssuranceSha256": security[
            "witnessStoreAssuranceSha256"
        ],
        "globalRoleRegistry": security["globalRoleRegistry"],
        "globalRoleRegistrySha256": security[
            "globalRoleRegistrySha256"
        ],
        "globalRoleRegistryPinsSha256": security[
            "globalRoleRegistryPinsSha256"
        ],
        "launchAttemptJournalDomain": (
            launch_authorization.LAUNCH_ATTEMPT_JOURNAL_DOMAIN
        ),
    }
    request["launchAttemptRecoveryIdentitySha256"] = (
        launch_authorization.launch_attempt_recovery_identity_sha256(
            request
        )
    )
    request_sha256 = (
        launch_authorization.launch_authorization_request_sha256(request)
    )
    witness_statement = {
        "operation": launch_authorization.WITNESS_OPERATION,
        "operationId": request["launcherNonce"],
        "authorizationId": "2" * 64,
        "requestSha256": request_sha256,
        "challenge": request["launchAuthorityWitnessChallenge"],
        "issuedAtUnixSeconds": 100,
        "expiresAtUnixSeconds": 120,
        "authorityKeyId": security["authorityKeyId"],
        "witnessKeyId": security["witnessKeyId"],
        "witnessIdentitySha256": security["witnessIdentitySha256"],
        "witnessAdministrativeDomainSha256": security[
            "witnessAdministrativeDomainSha256"
        ],
        "storeAssuranceSha256": security[
            "witnessStoreAssuranceSha256"
        ],
        "registryGeneration": 4,
        "registrySha256": digest("3"),
        "predecessorStateSha256": digest("1"),
        "successorStateSha256": digest("2"),
        "deploymentAudience": request["deploymentAudience"],
        "deploymentIdentitySha256": request[
            "deploymentIdentitySha256"
        ],
        "releaseSequence": request["releaseSequence"],
        "rollbackEpoch": request["rollbackEpoch"],
        "authorizationScope": request["authorizationScope"],
        "stateTransitionCommitted": True,
        "checkpointSequence": 9,
    }
    monotonic_witness = {
        "apiVersion": launch_authorization.WITNESS_API_VERSION,
        "kind": launch_authorization.WITNESS_KIND,
        "statement": witness_statement,
        "signature": b64e(
            security["witnessKey"].sign(
                launch_authorization.launch_authority_witness_signing_bytes(
                    witness_statement
                )
            )
        ),
    }
    envelope = launch_authorization.sign_launch_authorization(
        request,
        private_key=security["authorityKey"],
        authorization_id="2" * 64,
        issued_at_unix_seconds=100,
        expires_at_unix_seconds=120,
        monotonic_witness=monotonic_witness,
    )
    receipt["launchAuthorization"] = {
        "request": request,
        "requestSha256": request_sha256,
        "envelope": envelope,
        "authorizationSha256": sha256_prefixed_bytes(
            launch_authorization.canonical_json_bytes(envelope)
        ),
        "witnessPublicKeySpkiDerBase64url": security[
            "witnessPublicKeySpkiDerBase64url"
        ],
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
    summary = {
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
    if "nonceRollbackAssurance" in receipt:
        summary["nonceRollbackAssurance"] = receipt[
            "nonceRollbackAssurance"
        ]
    return summary


def _obsolete_verify_release_proof_schemas() -> tuple[Any, dict[str, Any]]:
    raise AssertionError(
        "obsolete final-shaped completionProof/v6 schema test is unreachable"
    )
    from jsonschema import Draft202012Validator

    receipt_schema = json.loads(
        (ROOT / "schemas/bootstrap-receipt.v3.schema.json").read_text(
            encoding="utf-8"
        )
    )
    completion_schema = json.loads(
        (ROOT / "schemas/completion-proof.v6.schema.json").read_text(
            encoding="utf-8"
        )
    )
    final_result_schema = json.loads(
        (
            ROOT
            / "schemas/release-completion-verification.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(receipt_schema)
    Draft202012Validator.check_schema(completion_schema)
    Draft202012Validator.check_schema(final_result_schema)
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
    legacy_receipt = bootstrap_receipt_fixture(legacy_v2=True)
    if not list(
        Draft202012Validator(receipt_schema).iter_errors(legacy_receipt)
    ):
        raise AssertionError("bootstrap receipt v3 schema accepted a v2 receipt")
    final_result_validator = Draft202012Validator(final_result_schema)
    final_result = (
        readiness_runner_test.release_completion_result_v1_fixture()
    )
    final_result_validator.validate(final_result)
    if (
        verify_release_completion.validate_release_completion_verification_v1(
            final_result,
            **readiness_runner_test.release_completion_fixture_validation_kwargs(),
        )
        != final_result
    ):
        raise AssertionError(
            "native final verifier rejected its current releaseCompletionVerification/v1 output shape"
        )

    def refresh_result_digest(value: dict[str, Any]) -> None:
        payload = clone_document(value)
        payload.pop("resultSha256", None)
        value["resultSha256"] = sha256_prefixed_json(payload)

    def refresh_production_identity_digest(value: dict[str, Any]) -> None:
        identity = value["productionReleaseIdentity"]
        payload = clone_document(identity)
        payload.pop("identitySha256", None)
        identity["identitySha256"] = sha256_prefixed_json(payload)
        refresh_result_digest(value)

    def refresh_boundary_digest(value: dict[str, Any]) -> None:
        boundary = value["hostBootstrapBoundary"]
        payload = clone_document(boundary)
        payload.pop("boundarySha256", None)
        boundary["boundarySha256"] = sha256_prefixed_json(payload)
        refresh_result_digest(value)

    final_result_negatives = []
    missing_redemption = clone_document(final_result)
    missing_redemption["publicVerifierResult"].pop(
        "currentHeadRedemptionReceiptIdentity"
    )
    final_result_negatives.append(
        ("missing public redemption identity", missing_redemption)
    )
    extra_checkpoint_authority = clone_document(final_result)
    extra_checkpoint_authority["productionReleaseIdentity"][
        "protectedPriorClientState"
    ]["legacyCheckpointAuthority"] = digest("d")
    final_result_negatives.append(
        ("extra checkpoint authority", extra_checkpoint_authority)
    )
    substituted_identity_version = clone_document(final_result)
    substituted_identity_version["aggregateAuthentication"][
        "completionIdentity"
    ]["apiVersion"] = "serverware.finalCompletionIdentity/v1"
    final_result_negatives.append(
        ("aggregate identity v1 substitution", substituted_identity_version)
    )
    substituted_public_version = clone_document(final_result)
    substituted_public_version["publicVerifierResult"]["apiVersion"] = (
        "serverware.publicNitroVerificationResult/v1"
    )
    final_result_negatives.append(
        ("public result version substitution", substituted_public_version)
    )
    missing_boundary = clone_document(final_result)
    missing_boundary.pop("hostBootstrapBoundary")
    final_result_negatives.append(
        ("missing host bootstrap boundary", missing_boundary)
    )
    incomplete_boundary = clone_document(final_result)
    incomplete_boundary["hostBootstrapBoundary"].pop(
        "launchAuthorizationRequestApiVersion"
    )
    final_result_negatives.append(
        (
            "missing host bootstrap authorization request version",
            incomplete_boundary,
        )
    )
    missing_boundary_digest = clone_document(final_result)
    missing_boundary_digest["aggregateAuthentication"].pop(
        "hostBootstrapBoundarySha256"
    )
    final_result_negatives.append(
        ("missing aggregate host bootstrap digest", missing_boundary_digest)
    )
    missing_production_boundary_digest = clone_document(final_result)
    missing_production_boundary_digest["productionReleaseIdentity"].pop(
        "hostBootstrapBoundarySha256"
    )
    final_result_negatives.append(
        (
            "missing production identity host bootstrap digest",
            missing_production_boundary_digest,
        )
    )
    obsolete_final_alias = clone_document(final_result)
    obsolete_final_alias["final_completion"] = True
    final_result_negatives.append(
        ("obsolete final_completion alias", obsolete_final_alias)
    )
    obsolete_result_version = clone_document(final_result)
    obsolete_result_version["apiVersion"] = (
        "serverware.releaseCompletionVerification/v0"
    )
    final_result_negatives.append(
        ("obsolete final result version", obsolete_result_version)
    )
    readiness_envelope = {
        "apiVersion": "serverware.completionProof/v6",
        "kind": "ServerwarePreEnclaveReadiness",
        "verificationOk": True,
        "finalCompletionVerified": False,
        "verification_mode": "readiness",
    }
    final_result_negatives.append(
        ("readiness-envelope confusion", readiness_envelope)
    )
    v6_as_final = {
        **readiness_envelope,
        "kind": "ServerwareCompletionProof",
        "finalCompletionVerified": True,
        "verification_mode": "final",
        "result_scope": "final-completion",
        "readiness_only": False,
    }
    final_result_negatives.append(
        ("completionProof/v6 as final", v6_as_final)
    )
    for label, invalid_document in final_result_negatives:
        if not list(final_result_validator.iter_errors(invalid_document)):
            raise AssertionError(
                f"release completion result schema accepted {label}"
            )
        try:
            verify_release_completion.validate_release_completion_verification_v1(
                invalid_document,
                **readiness_runner_test.release_completion_fixture_validation_kwargs(),
            )
        except ValueError:
            continue
        raise AssertionError(
            f"native final verifier accepted {label}"
        )

    runtime_negatives: list[tuple[str, dict[str, Any]]] = []
    boundary_digest_substitution = clone_document(final_result)
    boundary_digest_substitution["hostBootstrapBoundary"][
        "boundarySha256"
    ] = digest("e")
    refresh_result_digest(boundary_digest_substitution)
    runtime_negatives.append(
        ("host bootstrap boundary digest substitution", boundary_digest_substitution)
    )
    boundary_request_version_substitution = clone_document(final_result)
    boundary_request_version_substitution["hostBootstrapBoundary"][
        "launchAuthorizationRequestApiVersion"
    ] = "serverware.launchAuthorizationRequest/v1"
    refresh_boundary_digest(boundary_request_version_substitution)
    runtime_negatives.append(
        (
            "host bootstrap authorization request version substitution",
            boundary_request_version_substitution,
        )
    )
    tampered_boundary = clone_document(final_result)
    tampered_boundary["hostBootstrapBoundary"][
        "authoritativeForFinalCompletion"
    ] = True
    refresh_boundary_digest(tampered_boundary)
    runtime_negatives.append(
        ("authoritative host bootstrap substitution", tampered_boundary)
    )
    cross_wired_boundary = clone_document(final_result)
    cross_wired_boundary["hostBootstrapBoundary"][
        "completionIdentitySha256"
    ] = digest("e")
    refresh_boundary_digest(cross_wired_boundary)
    runtime_negatives.append(
        ("cross-wired host bootstrap identity", cross_wired_boundary)
    )
    aggregate_boundary_substitution = clone_document(final_result)
    aggregate_boundary_substitution["aggregateAuthentication"][
        "hostBootstrapBoundarySha256"
    ] = digest("e")
    refresh_result_digest(aggregate_boundary_substitution)
    runtime_negatives.append(
        (
            "aggregate host bootstrap digest substitution",
            aggregate_boundary_substitution,
        )
    )
    production_boundary_substitution = clone_document(final_result)
    production_boundary_substitution["productionReleaseIdentity"][
        "hostBootstrapBoundarySha256"
    ] = digest("e")
    refresh_production_identity_digest(production_boundary_substitution)
    runtime_negatives.append(
        (
            "production identity host bootstrap substitution",
            production_boundary_substitution,
        )
    )
    completion_identity_mismatch = clone_document(final_result)
    completion_identity_mismatch["aggregateAuthentication"][
        "completionIdentity"
    ]["releaseGeneration"] += 1
    refresh_result_digest(completion_identity_mismatch)
    runtime_negatives.append(
        ("completion identity cross-wire", completion_identity_mismatch)
    )
    completion_digest_substitution = clone_document(final_result)
    completion_digest_substitution["completionIdentitySha256"] = digest("e")
    refresh_result_digest(completion_digest_substitution)
    runtime_negatives.append(
        ("completion identity digest substitution", completion_digest_substitution)
    )
    artifact_digest_substitution = clone_document(final_result)
    artifact_digest_substitution["releaseArtifactBindings"][
        "artifactBindingsSha256"
    ] = digest("e")
    refresh_result_digest(artifact_digest_substitution)
    runtime_negatives.append(
        ("artifact binding digest substitution", artifact_digest_substitution)
    )
    result_digest_substitution = clone_document(final_result)
    result_digest_substitution["resultSha256"] = digest("e")
    runtime_negatives.append(
        ("final result digest substitution", result_digest_substitution)
    )
    for label, invalid_document in runtime_negatives:
        try:
            verify_release_completion.validate_release_completion_verification_v1(
                invalid_document,
                **readiness_runner_test.release_completion_fixture_validation_kwargs(),
            )
        except ValueError:
            continue
        raise AssertionError(
            f"native final verifier accepted {label}"
        )
    return Draft202012Validator(completion_schema), receipt


def verify_final_result_signer_file_handoff(
    *,
    final_core: dict[str, Any],
    signing_response: dict[str, Any],
    final_result: dict[str, Any],
    validation_kwargs: dict[str, str],
) -> None:
    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        request_path = tmp / "release-completion-signing-request.json"
        response_path = tmp / "release-completion-signing-response.json"
        result_path = tmp / "release-completion-verification.json"
        base_args = {
            "expected_release_completion_result_provider": validation_kwargs[
                "expected_result_provider"
            ],
            "expected_release_completion_result_key_id": validation_kwargs[
                "expected_result_key_id"
            ],
            "expected_release_completion_result_spki_sha256": validation_kwargs[
                "expected_result_spki_sha256"
            ],
            "expected_public_nitro_verification_result_provider": (
                validation_kwargs["expected_public_nitro_result_provider"]
            ),
            "expected_public_nitro_verification_result_key_id": (
                validation_kwargs["expected_public_nitro_result_key_id"]
            ),
            "expected_public_nitro_verification_result_spki_sha256": (
                validation_kwargs["expected_public_nitro_result_spki_sha256"]
            ),
            "expected_final_role_registry_sha256": validation_kwargs[
                "expected_final_role_registry_sha256"
            ],
        }

        def invoke(args: SimpleNamespace) -> tuple[dict[str, Any], bytes]:
            captured = io.BytesIO()
            original_stdout = sys.stdout
            sys.stdout = SimpleNamespace(buffer=captured)
            try:
                document = (
                    verify_release_completion
                    .emit_release_completion_result_signer_phase(
                        args,
                        final_core,
                        trusted_result_public_key_pem=validation_kwargs[
                            "trusted_result_public_key_pem"
                        ],
                        trusted_public_nitro_result_public_key_pem=(
                            validation_kwargs[
                                "trusted_public_nitro_result_public_key_pem"
                            ]
                        ),
                    )
                )
            finally:
                sys.stdout = original_stdout
            return document, captured.getvalue()

        prepare_args = SimpleNamespace(
            **base_args,
            final_result_phase="prepare",
            release_completion_result_signing_request=None,
            release_completion_result_signature=None,
            out=str(request_path),
        )
        prepared, prepare_stdout = invoke(prepare_args)
        expected_request = (
            verify_release_completion.build_release_completion_result_signing_request(
                final_core,
                provider=validation_kwargs["expected_result_provider"],
                signing_key_id=validation_kwargs["expected_result_key_id"],
                signing_key_spki_sha256=validation_kwargs[
                    "expected_result_spki_sha256"
                ],
                global_role_registry_sha256=validation_kwargs[
                    "expected_final_role_registry_sha256"
                ],
            )
        )
        expected_request_bytes = (
            canonical_json(expected_request).encode("ascii") + b"\n"
        )
        if (
            prepared != expected_request
            or request_path.read_bytes() != expected_request_bytes
            or prepare_stdout != expected_request_bytes
        ):
            raise AssertionError(
                "prepare phase did not emit the exact deterministic signer request"
            )
        try:
            invoke(
                SimpleNamespace(
                    **base_args,
                    final_result_phase="prepare",
                    release_completion_result_signing_request=None,
                    release_completion_result_signature=str(response_path),
                    out=str(request_path),
                )
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "prepare phase accepted a preexisting signer response"
            )
        try:
            invoke(
                SimpleNamespace(
                    **base_args,
                    final_result_phase="prepare",
                    release_completion_result_signing_request=str(
                        request_path
                    ),
                    release_completion_result_signature=None,
                    out=str(result_path),
                )
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "prepare phase accepted a preexisting prepared request"
            )
        try:
            invoke(
                SimpleNamespace(
                    **base_args,
                    final_result_phase="finalize",
                    release_completion_result_signing_request=str(
                        request_path
                    ),
                    release_completion_result_signature=None,
                    out=str(result_path),
                )
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "finalize phase accepted a missing signer response"
            )
        try:
            invoke(
                SimpleNamespace(
                    **base_args,
                    final_result_phase="finalize",
                    release_completion_result_signing_request=None,
                    release_completion_result_signature=str(response_path),
                    out=str(result_path),
                )
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "finalize phase accepted a missing retained signer request"
            )

        response_path.write_bytes(
            canonical_json(signing_response).encode("ascii") + b"\n"
        )
        finalize_args = SimpleNamespace(
            **base_args,
            final_result_phase="finalize",
            release_completion_result_signing_request=str(request_path),
            release_completion_result_signature=str(response_path),
            out=str(result_path),
        )
        expected_result_bytes = (
            canonical_json(final_result).encode("ascii") + b"\n"
        )
        for attempt in range(2):
            finalized, finalize_stdout = invoke(finalize_args)
            if (
                finalized != final_result
                or result_path.read_bytes() != expected_result_bytes
                or finalize_stdout != expected_result_bytes
            ):
                raise AssertionError(
                    "finalize phase changed the exact signed result during "
                    f"{'initial delivery' if attempt == 0 else 'lost-response retry'}"
                )

        crossed_request = clone_document(expected_request)
        crossed_request["requestSha256"] = digest("e")
        request_path.write_bytes(
            canonical_json(crossed_request).encode("ascii") + b"\n"
        )
        try:
            invoke(finalize_args)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "finalize phase accepted a tampered retained signer request"
            )
        crossed_core = clone_document(final_core)
        crossed_core["verifiedAtUnix"] += 1
        crossed_retained_request = (
            verify_release_completion
            .build_release_completion_result_signing_request(
                crossed_core,
                provider=validation_kwargs["expected_result_provider"],
                signing_key_id=validation_kwargs[
                    "expected_result_key_id"
                ],
                signing_key_spki_sha256=validation_kwargs[
                    "expected_result_spki_sha256"
                ],
                global_role_registry_sha256=validation_kwargs[
                    "expected_final_role_registry_sha256"
                ],
            )
        )
        request_path.write_bytes(
            canonical_json(crossed_retained_request).encode("ascii")
            + b"\n"
        )
        try:
            invoke(finalize_args)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "finalize phase accepted a deterministic request for a different final core"
            )
        request_path.write_bytes(expected_request_bytes)

        try:
            invoke(
                SimpleNamespace(
                    **base_args,
                    final_result_phase="prepare",
                    release_completion_result_signing_request=None,
                    release_completion_result_signature=None,
                    out=None,
                )
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "prepare phase accepted a non-durable missing output"
            )

        protocol_path_attributes = (
            "public_nitro_evidence_bundle",
            "public_nitro_expectations",
            "public_nitro_trust_roots",
            "public_nitro_verification_result",
            "public_nitro_verification_result_public_key",
            "host_readiness_completion_proof",
            "release_completion_result_public_key",
            "release_completion_result_signature",
            "release_completion_result_signing_request",
        )
        for attribute in protocol_path_attributes:
            collision_path = tmp / f"{attribute}.json"
            collision_path.write_bytes(b"collision\n")
            collision_args = SimpleNamespace(
                out=str(collision_path),
                **{attribute: str(collision_path)},
            )
            try:
                verify_release_completion.reject_final_protocol_output_collisions(
                    collision_args
                )
            except ValueError:
                continue
            raise AssertionError(
                f"final protocol output collided with {attribute}"
            )

        hardlink_input = tmp / "hardlink-input.json"
        hardlink_output = tmp / "hardlink-output.json"
        hardlink_input.write_bytes(b"hardlink\n")
        os.link(hardlink_input, hardlink_output)
        try:
            verify_release_completion.reject_final_protocol_output_collisions(
                SimpleNamespace(
                    out=str(hardlink_output),
                    public_nitro_expectations=str(hardlink_input),
                )
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "final protocol output accepted a hardlink input collision"
            )

        aliased_input = tmp / "aliased-input.json"
        aliased_input.write_bytes(b"alias\n")
        aliased_output = str(
            tmp / "nonexistent-component" / ".." / aliased_input.name
        )
        try:
            verify_release_completion.reject_final_protocol_output_collisions(
                SimpleNamespace(
                    out=aliased_output,
                    public_nitro_evidence_bundle=str(aliased_input),
                )
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "final protocol output accepted a normalized path alias collision"
            )


def verify_release_proof_schemas() -> tuple[Any, dict[str, Any]]:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    receipt_schema = json.loads(
        (ROOT / "schemas/bootstrap-receipt.v3.schema.json").read_text(
            encoding="utf-8"
        )
    )
    completion_schema = json.loads(
        (ROOT / "schemas/completion-proof.v6.schema.json").read_text(
            encoding="utf-8"
        )
    )
    final_schema = json.loads(
        (
            ROOT
            / "schemas/release-completion-verification.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    signing_request_schema = json.loads(
        (
            ROOT
            / "schemas/release-completion-result-signing-request.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    signing_response_schema = json.loads(
        (
            ROOT
            / "schemas/release-completion-result-signing-response.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    expected_public_nitro_provider_definition = {
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    }
    if (
        final_schema["$defs"].get("publicNitroProvider")
        != expected_public_nitro_provider_definition
    ):
        raise AssertionError(
            "releaseCompletionVerification/v1 public Nitro provider "
            "definition diverged from the runtime contract"
        )
    provider_references = {
        definition: final_schema["$defs"][definition][
            "properties"
        ]["provider"]
        for definition in (
            "clientState",
            "publicNitroEnvelope",
            "resultAuthenticity",
        )
    }
    if provider_references != {
        "clientState": {"$ref": "#/$defs/identifier"},
        "publicNitroEnvelope": {
            "$ref": "#/$defs/publicNitroProvider"
        },
        "resultAuthenticity": {"$ref": "#/$defs/identifier"},
    }:
        raise AssertionError(
            "releaseCompletionVerification/v1 narrowed an unrelated "
            "provider or left the public Nitro provider generic"
        )
    Draft202012Validator.check_schema(receipt_schema)
    Draft202012Validator.check_schema(completion_schema)
    Draft202012Validator.check_schema(final_schema)
    Draft202012Validator.check_schema(signing_request_schema)
    Draft202012Validator.check_schema(signing_response_schema)
    receipt = bootstrap_receipt_fixture()
    Draft202012Validator(receipt_schema).validate(receipt)
    completion_registry = Registry().with_resource(
        completion_schema["$id"],
        Resource.from_contents(completion_schema),
    )
    native_launch_manifest_validator = Draft202012Validator(
        {
            "$ref": (
                completion_schema["$id"]
                + "#/$defs/nativeLaunchManifest"
            )
        },
        registry=completion_registry,
    )
    receipt_summary = bootstrap_receipt_summary(receipt)
    native_nonce_assurance = {
        "contractSha256": receipt_summary["nonceRollbackAssurance"][
            "contractSha256"
        ],
        "retainedSnapshotSha256": receipt_summary[
            "nonceRollbackAssurance"
        ]["retainedSnapshotSha256"],
        "verifierStateService": receipt_summary[
            "nonceRollbackAssurance"
        ]["verifierStateService"],
        "verified": True,
    }
    native_launch_manifest = launch_manifest_v3_verification_fixture(
        receipt_summary,
        native_nonce_assurance,
    )
    native_launch_manifest_validator.validate(native_launch_manifest)
    open_native_launch_manifest = clone_document(native_launch_manifest)
    open_native_launch_manifest["launchAuthorityIssuanceSaga"][
        "unexpected"
    ] = True
    if not list(
        native_launch_manifest_validator.iter_errors(
            open_native_launch_manifest
        )
    ):
        raise AssertionError(
            "completionProof/v6 schema accepted an open launcher v7 saga"
        )

    schema_registry = Registry().with_resource(
        final_schema["$id"],
        Resource.from_contents(final_schema),
    )
    public_nitro_provider_validator = Draft202012Validator(
        {
            "$ref": (
                final_schema["$id"]
                + "#/$defs/publicNitroProvider"
            )
        },
        registry=schema_registry,
    )
    for provider in ("a", "fixture.signer-1", "a" * 128):
        public_nitro_provider_validator.validate(provider)
    for provider in ("", ".provider", "kms:primary", "a" * 129):
        if not list(
            public_nitro_provider_validator.iter_errors(provider)
        ):
            raise AssertionError(
                "releaseCompletionVerification/v1 accepted an invalid "
                "public Nitro provider"
            )
    final_validator = Draft202012Validator(
        final_schema,
        registry=schema_registry,
    )
    signing_request_validator = Draft202012Validator(
        signing_request_schema,
        registry=schema_registry,
    )
    signing_response_validator = Draft202012Validator(
        signing_response_schema,
        registry=schema_registry,
    )
    final_result = (
        readiness_runner_test.release_completion_result_v1_fixture()
    )
    validation_kwargs = (
        readiness_runner_test.release_completion_fixture_validation_kwargs()
    )
    canonical_signed_max = (
        verify_release_completion.CANONICAL_JSON_SIGNED_MAX
    )
    signed_max_result = clone_document(final_result)
    signed_max_result["verifiedAtUnix"] = canonical_signed_max
    final_validator.validate(signed_max_result)
    verify_release_completion.validate_canonical_json_profile(
        {"verifiedAtUnix": canonical_signed_max},
        label="signed-64 maximum fixture",
    )
    above_signed_max_result = clone_document(final_result)
    above_signed_max_result["verifiedAtUnix"] = canonical_signed_max + 1
    if not list(
        final_validator.iter_errors(above_signed_max_result)
    ):
        raise AssertionError(
            "releaseCompletionVerification/v1 schema accepted an integer "
            "above the canonical signed-64 maximum"
        )
    try:
        verify_release_completion.validate_canonical_json_profile(
            {"verifiedAtUnix": canonical_signed_max + 1},
            label="above signed-64 maximum fixture",
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "canonical final-v1 profile accepted an integer above signed-64"
        )
    try:
        verify_release_completion.validate_release_completion_verification_v1(
            above_signed_max_result,
            **validation_kwargs,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "native final-v1 validator accepted an integer above signed-64"
        )
    if not (
        canonical_signed_max
        == verify_release_completion
        .PUBLIC_NITRO_CANONICAL_INTEGER_MAX
        == verify_release_completion
        .verify_nitro_tee
        .PUBLIC_NITRO_CANONICAL_INTEGER_MAX
    ):
        raise AssertionError(
            "final-v1 and native public Nitro integer domains diverged"
        )
    public_result_at_maximum = clone_document(
        final_result["publicNitroVerification"]["envelope"]["result"]
    )
    public_result_at_maximum["verifiedAtUnix"] = canonical_signed_max
    verify_release_completion._validate_public_nitro_live_result(
        public_result_at_maximum
    )
    public_result_above_maximum = clone_document(
        public_result_at_maximum
    )
    public_result_above_maximum["verifiedAtUnix"] = (
        canonical_signed_max + 1
    )
    try:
        verify_release_completion._validate_public_nitro_live_result(
            public_result_above_maximum
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "final-v1 accepted a public Nitro integer above signed-64"
        )
    expected_public_domain = (
        b"serverware.publicNitroLiveVerificationResultEnvelope/v1"
        b"\x00signatureAlgorithm=Ed25519\x00"
    )
    if (
        verify_release_completion
        .PUBLIC_NITRO_LIVE_RESULT_SIGNATURE_DOMAIN
        != expected_public_domain
        or verify_release_completion
        .verify_nitro_tee
        .PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN
        != expected_public_domain
    ):
        raise AssertionError(
            "native and final-v1 public Nitro signature domains diverged"
        )
    public_envelope = final_result[
        "publicNitroVerification"
    ]["envelope"]
    if (
        verify_release_completion
        .verify_signed_public_nitro_result_envelope(
            public_envelope,
            trusted_public_key_pem=validation_kwargs[
                "trusted_public_nitro_result_public_key_pem"
            ],
            expected_provider=validation_kwargs[
                "expected_public_nitro_result_provider"
            ],
            expected_key_id=validation_kwargs[
                "expected_public_nitro_result_key_id"
            ],
            expected_spki_sha256=validation_kwargs[
                "expected_public_nitro_result_spki_sha256"
            ],
        )
        != public_envelope["result"]
    ):
        raise AssertionError(
            "final-v1 did not consume the production/native envelope"
        )
    final_validator.validate(final_result)
    if (
        verify_release_completion.validate_release_completion_verification_v1(
            final_result,
            **validation_kwargs,
        )
        != final_result
    ):
        raise AssertionError(
            "native final validator rejected the positive producer fixture"
        )
    final_core = clone_document(final_result)
    final_core.pop("resultSha256")
    final_core.pop("authenticity")
    signing_request = (
        verify_release_completion.build_release_completion_result_signing_request(
            final_core,
            provider=validation_kwargs["expected_result_provider"],
            signing_key_id=validation_kwargs["expected_result_key_id"],
            signing_key_spki_sha256=validation_kwargs[
                "expected_result_spki_sha256"
            ],
            global_role_registry_sha256=validation_kwargs[
                "expected_final_role_registry_sha256"
            ],
        )
    )
    if (
        verify_release_completion.build_release_completion_result_signing_request(
            final_core,
            provider=validation_kwargs["expected_result_provider"],
            signing_key_id=validation_kwargs["expected_result_key_id"],
            signing_key_spki_sha256=validation_kwargs[
                "expected_result_spki_sha256"
            ],
            global_role_registry_sha256=validation_kwargs[
                "expected_final_role_registry_sha256"
            ],
        )
        != signing_request
    ):
        raise AssertionError(
            "release-completion signing request is not deterministic"
        )
    signing_request_validator.validate(signing_request)
    verify_release_completion.validate_release_completion_result_signing_request(
        signing_request,
        expected_result_core=final_core,
        expected_provider=validation_kwargs["expected_result_provider"],
        expected_signing_key_id=validation_kwargs[
            "expected_result_key_id"
        ],
        expected_signing_key_spki_sha256=validation_kwargs[
            "expected_result_spki_sha256"
        ],
        expected_global_role_registry_sha256=validation_kwargs[
            "expected_final_role_registry_sha256"
        ],
    )
    result_signing_private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(
            b"serverware-fixture:release-completion-result"
        ).digest()
    )
    signing_bytes = b64d(signing_request["signingBytesBase64url"])
    signing_response = {
        "apiVersion": (
            verify_release_completion
            .FINAL_RESULT_SIGNING_RESPONSE_API_VERSION
        ),
        "kind": (
            verify_release_completion
            .FINAL_RESULT_SIGNING_RESPONSE_KIND
        ),
        "operation": (
            verify_release_completion.FINAL_RESULT_SIGNING_OPERATION
        ),
        "status": "signed",
        "requestSha256": signing_request["requestSha256"],
        "idempotencyKey": signing_request["idempotencyKey"],
        "provider": signing_request["provider"],
        "signingKeyId": signing_request["signingKeyId"],
        "signingKeySpkiSha256": signing_request[
            "signingKeySpkiSha256"
        ],
        "globalRoleRegistrySha256": signing_request[
            "globalRoleRegistrySha256"
        ],
        "resultSha256": signing_request["resultSha256"],
        "signingBytesSha256": signing_request["signingBytesSha256"],
        "signature": "ed25519:"
        + b64e(result_signing_private_key.sign(signing_bytes)),
    }
    signing_response_validator.validate(signing_response)
    finalized = (
        verify_release_completion.finalize_release_completion_verification_v1(
            final_core,
            signing_response,
            **validation_kwargs,
        )
    )
    if finalized != final_result:
        raise AssertionError(
            "two-phase external signer handoff changed the final-v1 result"
        )
    verify_final_result_signer_file_handoff(
        final_core=final_core,
        signing_response=signing_response,
        final_result=final_result,
        validation_kwargs=validation_kwargs,
    )

    signing_request_structural_negatives: list[
        tuple[str, dict[str, Any]]
    ] = []
    missing_request_digest = clone_document(signing_request)
    missing_request_digest.pop("requestSha256")
    signing_request_structural_negatives.append(
        ("omitted signing request digest", missing_request_digest)
    )
    extra_request_field = clone_document(signing_request)
    extra_request_field["unexpected"] = True
    signing_request_structural_negatives.append(
        ("extra signing request field", extra_request_field)
    )
    obsolete_request_version = clone_document(signing_request)
    obsolete_request_version["apiVersion"] = (
        "serverware.releaseCompletionResultSigningRequest/v0"
    )
    signing_request_structural_negatives.append(
        ("obsolete signing request version", obsolete_request_version)
    )
    invalid_request_provider = clone_document(signing_request)
    invalid_request_provider["provider"] = "invalid/provider"
    signing_request_structural_negatives.append(
        ("invalid signing request provider", invalid_request_provider)
    )
    invalid_request_digest = clone_document(signing_request)
    invalid_request_digest["requestSha256"] = "sha256:" + "A" * 64
    signing_request_structural_negatives.append(
        ("invalid signing request digest", invalid_request_digest)
    )
    invalid_signing_bytes = clone_document(signing_request)
    invalid_signing_bytes["signingBytesBase64url"] = "A"
    signing_request_structural_negatives.append(
        ("invalid canonical signing bytes", invalid_signing_bytes)
    )
    for terminator_name, terminator in (
        ("LF", "\n"),
        ("CR", "\r"),
        ("Unicode line separator", "\u2028"),
        ("Unicode paragraph separator", "\u2029"),
    ):
        for field in (
            "provider",
            "requestSha256",
            "signingBytesBase64url",
        ):
            trailing = clone_document(signing_request)
            trailing[field] += terminator
            signing_request_structural_negatives.append(
                (
                    f"{terminator_name} after signing request {field}",
                    trailing,
                )
            )
    for label, invalid in signing_request_structural_negatives:
        if not list(signing_request_validator.iter_errors(invalid)):
            raise AssertionError(
                f"signing request schema accepted {label}"
            )
        try:
            verify_release_completion.validate_release_completion_result_signing_request(
                invalid,
                expected_result_core=final_core,
                expected_provider=validation_kwargs[
                    "expected_result_provider"
                ],
                expected_signing_key_id=validation_kwargs[
                    "expected_result_key_id"
                ],
                expected_signing_key_spki_sha256=validation_kwargs[
                    "expected_result_spki_sha256"
                ],
                expected_global_role_registry_sha256=validation_kwargs[
                    "expected_final_role_registry_sha256"
                ],
            )
        except ValueError:
            continue
        raise AssertionError(
            f"native signing request validator accepted {label}"
        )

    signing_request_identity_negatives: list[
        tuple[str, dict[str, Any]]
    ] = []
    tampered_signing_bytes = clone_document(signing_request)
    tampered_signing_bytes["signingBytesSha256"] = digest("e")
    signing_request_identity_negatives.append(
        ("tampered signing bytes digest", tampered_signing_bytes)
    )
    crossed_request_provider = clone_document(signing_request)
    crossed_request_provider["provider"] = "crossed-provider"
    signing_request_identity_negatives.append(
        ("cross-wired signing request provider", crossed_request_provider)
    )
    crossed_request_registry = clone_document(signing_request)
    crossed_request_registry["globalRoleRegistrySha256"] = digest("e")
    signing_request_identity_negatives.append(
        (
            "cross-wired signing request role registry",
            crossed_request_registry,
        )
    )
    crossed_request_identity = clone_document(signing_request)
    crossed_request_identity["requestSha256"] = digest("e")
    signing_request_identity_negatives.append(
        ("cross-wired deterministic request identity", crossed_request_identity)
    )
    crossed_idempotency = clone_document(signing_request)
    crossed_idempotency["idempotencyKey"] = digest("e")
    signing_request_identity_negatives.append(
        ("cross-wired idempotency identity", crossed_idempotency)
    )
    for label, invalid in signing_request_identity_negatives:
        if list(signing_request_validator.iter_errors(invalid)):
            raise AssertionError(
                "signing request schema performed native deterministic "
                f"identity validation for {label}"
            )
        try:
            verify_release_completion.validate_release_completion_result_signing_request(
                invalid,
                expected_result_core=final_core,
                expected_provider=validation_kwargs[
                    "expected_result_provider"
                ],
                expected_signing_key_id=validation_kwargs[
                    "expected_result_key_id"
                ],
                expected_signing_key_spki_sha256=validation_kwargs[
                    "expected_result_spki_sha256"
                ],
                expected_global_role_registry_sha256=validation_kwargs[
                    "expected_final_role_registry_sha256"
                ],
            )
        except ValueError:
            continue
        raise AssertionError(
            f"external signer request accepted {label}"
        )

    response_structural_negatives: list[
        tuple[str, dict[str, Any]]
    ] = []
    missing_response_binding = clone_document(signing_response)
    missing_response_binding.pop("idempotencyKey")
    response_structural_negatives.append(
        ("omitted response idempotency key", missing_response_binding)
    )
    extra_response_field = clone_document(signing_response)
    extra_response_field["unexpected"] = True
    response_structural_negatives.append(
        ("extra signing response field", extra_response_field)
    )
    wrong_response_status = clone_document(signing_response)
    wrong_response_status["status"] = "pending"
    response_structural_negatives.append(
        ("wrong signing response status", wrong_response_status)
    )
    invalid_response_provider = clone_document(signing_response)
    invalid_response_provider["provider"] = "invalid/provider"
    response_structural_negatives.append(
        ("invalid signing response provider", invalid_response_provider)
    )
    invalid_response_digest = clone_document(signing_response)
    invalid_response_digest["requestSha256"] = "sha256:" + "A" * 64
    response_structural_negatives.append(
        ("invalid signing response digest", invalid_response_digest)
    )
    noncanonical_response_signature = clone_document(signing_response)
    noncanonical_response_signature["signature"] = (
        "ed25519:" + "A" * 85 + "B"
    )
    response_structural_negatives.append(
        (
            "non-canonical signing response signature",
            noncanonical_response_signature,
        )
    )
    for terminator_name, terminator in (
        ("LF", "\n"),
        ("CR", "\r"),
        ("Unicode line separator", "\u2028"),
        ("Unicode paragraph separator", "\u2029"),
    ):
        for field in ("provider", "requestSha256", "signature"):
            trailing = clone_document(signing_response)
            trailing[field] += terminator
            response_structural_negatives.append(
                (
                    f"{terminator_name} after signing response {field}",
                    trailing,
                )
            )
    response_validation_kwargs = {
        "signing_request": signing_request,
        "trusted_public_key_pem": validation_kwargs[
            "trusted_result_public_key_pem"
        ],
        "expected_provider": validation_kwargs[
            "expected_result_provider"
        ],
        "expected_signing_key_id": validation_kwargs[
            "expected_result_key_id"
        ],
        "expected_signing_key_spki_sha256": validation_kwargs[
            "expected_result_spki_sha256"
        ],
        "expected_global_role_registry_sha256": validation_kwargs[
            "expected_final_role_registry_sha256"
        ],
    }
    for label, invalid in response_structural_negatives:
        if not list(signing_response_validator.iter_errors(invalid)):
            raise AssertionError(
                f"signing response schema accepted {label}"
            )
        try:
            verify_release_completion.verify_release_completion_result_signing_response(
                invalid,
                **response_validation_kwargs,
            )
        except ValueError:
            continue
        raise AssertionError(
            f"native signing response validator accepted {label}"
        )

    response_identity_negatives: list[tuple[str, dict[str, Any]]] = []
    for label, field, replacement in (
        ("tampered request digest", "requestSha256", digest("e")),
        ("cross-wired provider", "provider", "crossed-provider"),
        ("cross-wired key", "signingKeyId", digest("e")),
        ("cross-wired SPKI", "signingKeySpkiSha256", digest("e")),
        (
            "cross-wired role registry",
            "globalRoleRegistrySha256",
            digest("e"),
        ),
        ("tampered result digest", "resultSha256", digest("e")),
        ("tampered signing digest", "signingBytesSha256", digest("e")),
        ("tampered signature", "signature", "ed25519:" + "A" * 86),
    ):
        invalid = clone_document(signing_response)
        invalid[field] = replacement
        response_identity_negatives.append((label, invalid))
    for label, invalid in response_identity_negatives:
        if list(signing_response_validator.iter_errors(invalid)):
            raise AssertionError(
                "signing response schema performed native request/signature "
                f"identity validation for {label}"
            )
        try:
            verify_release_completion.verify_release_completion_result_signing_response(
                invalid,
                **response_validation_kwargs,
            )
        except ValueError:
            continue
        raise AssertionError(
            f"external signer response accepted {label}"
        )
    recovered_response = (
        verify_release_completion.verify_release_completion_result_signing_response(
            signing_response,
            **response_validation_kwargs,
        )
    )
    if recovered_response != (
        verify_release_completion.verify_release_completion_result_signing_response(
            signing_response,
            **response_validation_kwargs,
        )
    ):
        raise AssertionError(
            "byte-identical lost-response retry did not recover an identical result"
        )
    replay_core = clone_document(final_core)
    replay_core["verifiedAtUnix"] += 1
    replay_request = (
        verify_release_completion.build_release_completion_result_signing_request(
            replay_core,
            provider=validation_kwargs["expected_result_provider"],
            signing_key_id=validation_kwargs["expected_result_key_id"],
            signing_key_spki_sha256=validation_kwargs[
                "expected_result_spki_sha256"
            ],
            global_role_registry_sha256=validation_kwargs[
                "expected_final_role_registry_sha256"
            ],
        )
    )
    try:
        verify_release_completion.verify_release_completion_result_signing_response(
            signing_response,
            **{
                **response_validation_kwargs,
                "signing_request": replay_request,
            },
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "external signer response replayed across a different final core"
        )
    for label, invalid_identifier in (
        ("empty", ""),
        ("invalid character", "invalid/provider"),
        ("oversized", "a" * 257),
    ):
        try:
            verify_release_completion.require_final_v1_identifier(
                invalid_identifier,
                "fixture final-v1 identifier",
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"native final-v1 lexical validator accepted {label} identifier"
            )
    for provider in ("a", "fixture.signer-1", "a" * 128):
        if (
            verify_release_completion.require_public_nitro_provider(
                provider,
                "fixture public Nitro provider",
            )
            != provider
        ):
            raise AssertionError(
                "final-v1 changed a valid public Nitro provider"
            )
    for label, invalid_provider in (
        ("empty", ""),
        ("leading punctuation", ".provider"),
        ("colon", "kms:primary"),
        ("oversized", "a" * 129),
    ):
        try:
            verify_release_completion.require_public_nitro_provider(
                invalid_provider,
                "fixture public Nitro provider",
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "final-v1 accepted "
                f"{label} public Nitro signing provider"
            )
    state_commit_roles = final_result["publicNitroVerification"][
        "envelope"
    ]["result"]["roleKeyIds"]
    for field in (
        "commitId",
        "storeId",
        "currentHeadAuthorizationId",
        "currentHeadReservationId",
        "currentHeadRedemptionId",
    ):
        invalid_state_commit = clone_document(final_result["stateCommit"])
        invalid_state_commit[field] = "invalid/value"
        try:
            verify_release_completion._validate_final_state_commit(
                invalid_state_commit,
                role_key_ids=state_commit_roles,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"native final-v1 validator accepted invalid {field}"
            )
    for label, boundary in (
        ("empty", ""),
        ("oversized", "x" * 4097),
    ):
        invalid_state_commit = clone_document(final_result["stateCommit"])
        invalid_state_commit["rollbackResistanceBoundary"] = boundary
        try:
            verify_release_completion._validate_final_state_commit(
                invalid_state_commit,
                role_key_ids=state_commit_roles,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "native final-v1 validator accepted "
                f"{label} rollback boundary"
            )

    def assert_final_schema_and_native_reject(
        label: str,
        invalid: dict[str, Any],
    ) -> None:
        if not list(final_validator.iter_errors(invalid)):
            raise AssertionError(f"final schema accepted {label}")
        try:
            verify_release_completion.validate_release_completion_verification_v1(
                invalid,
                **validation_kwargs,
            )
        except ValueError:
            return
        raise AssertionError(f"native final validator accepted {label}")

    for terminator_name, terminator in (
        ("LF", "\n"),
        ("CR", "\r"),
        ("Unicode line separator", "\u2028"),
        ("Unicode paragraph separator", "\u2029"),
    ):
        lexical_cases: list[tuple[str, dict[str, Any]]] = []
        trailing_provider = clone_document(final_result)
        trailing_provider["authenticity"]["provider"] += terminator
        lexical_cases.append(("identifier", trailing_provider))
        trailing_digest = clone_document(final_result)
        trailing_digest["resultSha256"] += terminator
        lexical_cases.append(("SHA-256 digest", trailing_digest))
        trailing_sha384 = clone_document(final_result)
        trailing_sha384["publicNitroVerification"]["envelope"]["result"][
            "eifSha384"
        ] += terminator
        lexical_cases.append(("SHA-384 digest", trailing_sha384))
        trailing_signature = clone_document(final_result)
        trailing_signature["authenticity"]["signature"] += terminator
        lexical_cases.append(("Ed25519 signature", trailing_signature))
        trailing_commit_id = clone_document(final_result)
        trailing_commit_id["stateCommit"]["commitId"] += terminator
        lexical_cases.append(("state commit identifier", trailing_commit_id))
        trailing_boundary = clone_document(final_result)
        trailing_boundary["stateCommit"][
            "rollbackResistanceBoundary"
        ] += terminator
        lexical_cases.append(("boundary string", trailing_boundary))
        for lexical_label, invalid in lexical_cases:
            assert_final_schema_and_native_reject(
                f"{terminator_name} after final-v1 {lexical_label}",
                invalid,
            )

    public_result_fixture = final_result["publicNitroVerification"][
        "envelope"
    ]["result"]
    maximum_kms_audit = {
        f"audit-{index:02d}": digest(f"{index % 16:x}")
        for index in range(64)
    }
    maximum_kms_result = clone_document(final_result)
    maximum_kms_result["publicNitroVerification"]["envelope"]["result"][
        "kmsAuditProofSha256s"
    ] = maximum_kms_audit
    final_validator.validate(maximum_kms_result)
    maximum_native_public_result = clone_document(public_result_fixture)
    maximum_native_public_result["kmsAuditProofSha256s"] = maximum_kms_audit
    verify_release_completion._validate_public_nitro_live_result(
        maximum_native_public_result
    )

    kms_audit_negatives: list[tuple[str, dict[str, str]]] = [
        ("empty KMS audit digest map", {}),
        (
            "65-entry KMS audit digest map",
            {
                f"audit-{index:02d}": digest(f"{index % 16:x}")
                for index in range(65)
            },
        ),
        ("invalid KMS audit key", {"invalid/key": digest("a")}),
        ("invalid KMS audit key prefix", {"_audit": digest("a")}),
        ("oversized KMS audit key", {"a" * 129: digest("a")}),
        (
            "invalid KMS audit digest",
            {"audit": "sha256:" + "A" * 64},
        ),
    ]
    for terminator_name, terminator in (
        ("LF", "\n"),
        ("CR", "\r"),
        ("Unicode line separator", "\u2028"),
        ("Unicode paragraph separator", "\u2029"),
    ):
        kms_audit_negatives.extend(
            (
                (
                    f"{terminator_name} after KMS audit key",
                    {f"audit{terminator}": digest("a")},
                ),
                (
                    f"{terminator_name} after KMS audit digest",
                    {"audit": digest("a") + terminator},
                ),
            )
        )
    for label, invalid_map in kms_audit_negatives:
        invalid_final = clone_document(final_result)
        invalid_final["publicNitroVerification"]["envelope"]["result"][
            "kmsAuditProofSha256s"
        ] = invalid_map
        if not list(final_validator.iter_errors(invalid_final)):
            raise AssertionError(f"final schema accepted {label}")
        invalid_public_result = clone_document(public_result_fixture)
        invalid_public_result["kmsAuditProofSha256s"] = invalid_map
        try:
            verify_release_completion._validate_public_nitro_live_result(
                invalid_public_result
            )
        except ValueError:
            continue
        raise AssertionError(
            f"native public-Nitro result validator accepted {label}"
        )

    structural_negatives: list[tuple[str, dict[str, Any]]] = []
    missing_boundary = clone_document(final_result)
    missing_boundary.pop("hostBootstrapBoundary")
    structural_negatives.append(("missing host boundary", missing_boundary))

    missing_authenticity = clone_document(final_result)
    missing_authenticity.pop("authenticity")
    structural_negatives.append(
        ("unsigned final result", missing_authenticity)
    )

    obsolete_field = clone_document(final_result)
    obsolete_field["final_completion"] = True
    structural_negatives.append(("obsolete final alias", obsolete_field))

    obsolete_version = clone_document(final_result)
    obsolete_version["apiVersion"] = (
        "serverware.releaseCompletionVerification/v0"
    )
    structural_negatives.append(("obsolete final version", obsolete_version))

    missing_role = clone_document(final_result)
    missing_role["globalRoleRegistry"]["roles"].pop("witnessStore")
    structural_negatives.append(("missing witness-store role", missing_role))

    missing_state_store_role = clone_document(final_result)
    missing_state_store_role["globalRoleRegistry"]["roles"].pop("stateStore")
    structural_negatives.append(
        ("missing state-store role", missing_state_store_role)
    )

    bridge_injection = clone_document(final_result)
    bridge_injection["publicNitroVerification"]["envelope"]["result"][
        "public_verifier_bridge"
    ] = {"forged": True}
    structural_negatives.append(
        ("public verifier bridge injection", bridge_injection)
    )

    readiness_as_final = {
        "apiVersion": "serverware.completionProof/v6",
        "kind": "ServerwarePreEnclaveReadiness",
        "verificationOk": True,
        "finalCompletionVerified": False,
        "verification_mode": "readiness",
        "result_scope": "readiness-only",
        "readiness_only": True,
    }
    structural_negatives.append(
        ("readiness result as final", readiness_as_final)
    )
    final_shaped_v6 = {
        **readiness_as_final,
        "kind": "ServerwareCompletionProof",
        "finalCompletionVerified": True,
        "verification_mode": "final",
        "result_scope": "final-completion",
        "readiness_only": False,
        "public_verifier_bridge": {"forged": True},
    }
    structural_negatives.append(
        ("final-shaped completionProof/v6", final_shaped_v6)
    )

    for label, invalid in structural_negatives:
        if not list(final_validator.iter_errors(invalid)):
            raise AssertionError(f"final schema accepted {label}")
        try:
            verify_release_completion.validate_release_completion_verification_v1(
                invalid,
                **validation_kwargs,
            )
        except ValueError:
            continue
        raise AssertionError(f"native final validator accepted {label}")

    runtime_negatives: list[tuple[str, dict[str, Any]]] = []
    boundary_digest = clone_document(final_result)
    boundary_digest["hostBootstrapBoundary"]["boundarySha256"] = digest("e")
    runtime_negatives.append(
        ("host boundary digest substitution", boundary_digest)
    )

    boundary_authority = clone_document(final_result)
    boundary_authority["hostBootstrapBoundary"][
        "authoritativeForFinalCompletion"
    ] = True
    runtime_negatives.append(
        ("host boundary authority escalation", boundary_authority)
    )

    boundary_cross_wire = clone_document(final_result)
    boundary_cross_wire["hostBootstrapBoundary"][
        "completionIdentitySha256"
    ] = digest("e")
    runtime_negatives.append(
        ("host boundary completion cross-wire", boundary_cross_wire)
    )

    readiness_proof_cross_wire = clone_document(final_result)
    readiness_proof_cross_wire["hostBootstrapBoundary"][
        "hostReadinessCompletionProofFileSha256"
    ] = digest("e")
    runtime_negatives.append(
        (
            "host boundary readiness-proof cross-wire",
            readiness_proof_cross_wire,
        )
    )

    launch_authority_cross_wire = clone_document(final_result)
    launch_authority_cross_wire["hostBootstrapBoundary"][
        "launchAuthorityKeyId"
    ] = digest("e")
    runtime_negatives.append(
        (
            "host boundary launch-authority cross-wire",
            launch_authority_cross_wire,
        )
    )

    completion_mismatch = clone_document(final_result)
    completion_mismatch["completionIdentity"]["releaseGeneration"] += 1
    runtime_negatives.append(
        ("completion identity mismatch", completion_mismatch)
    )

    completion_digest = clone_document(final_result)
    completion_digest["completionIdentitySha256"] = digest("e")
    runtime_negatives.append(
        ("completion identity digest substitution", completion_digest)
    )

    public_result_digest = clone_document(final_result)
    public_result_digest["publicNitroVerification"]["resultSha256"] = digest(
        "e"
    )
    runtime_negatives.append(
        ("public result digest substitution", public_result_digest)
    )

    state_digest = clone_document(final_result)
    state_digest["aggregateAuthentication"][
        "stateCommitReceiptSha256"
    ] = digest("e")
    runtime_negatives.append(
        ("state receipt digest substitution", state_digest)
    )

    result_digest = clone_document(final_result)
    result_digest["resultSha256"] = digest("e")
    runtime_negatives.append(
        ("final result digest substitution", result_digest)
    )

    duplicate_role = clone_document(final_result)
    duplicate_role["globalRoleRegistry"]["roles"]["witnessStore"] = (
        duplicate_role["globalRoleRegistry"]["roles"]["witness"]
    )
    runtime_negatives.append(("duplicate global role", duplicate_role))

    tampered_public_signature = clone_document(final_result)
    tampered_public_signature["publicNitroVerification"]["envelope"][
        "signature"
    ] = "ed25519:" + "A" * 86
    runtime_negatives.append(
        ("tampered public result signature", tampered_public_signature)
    )

    tampered_result_signature = clone_document(final_result)
    tampered_result_signature["authenticity"]["signature"] = (
        "ed25519:" + "A" * 86
    )
    runtime_negatives.append(
        ("tampered final result signature", tampered_result_signature)
    )

    for label, invalid in runtime_negatives:
        try:
            verify_release_completion.validate_release_completion_verification_v1(
                invalid,
                **validation_kwargs,
            )
        except ValueError:
            continue
        raise AssertionError(f"native final validator accepted {label}")

    crossed_pins = dict(validation_kwargs)
    crossed_pins["expected_result_provider"] = "cross-wired-provider"
    try:
        verify_release_completion.validate_release_completion_verification_v1(
            final_result,
            **crossed_pins,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "native final validator accepted a cross-wired result provider pin"
        )
    crossed_public_pins = dict(validation_kwargs)
    crossed_public_pins[
        "expected_public_nitro_result_provider"
    ] = "cross-wired-public-provider"
    try:
        verify_release_completion.validate_release_completion_verification_v1(
            final_result,
            **crossed_public_pins,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "native final validator accepted a cross-wired public result provider"
        )
    return Draft202012Validator(completion_schema), receipt


def final_completion_identity_v3_fixture() -> dict[str, Any]:
    core_names = (
        "builderA",
        "builderB",
        "continuity",
        "custody",
        "eif",
        "hardware",
        "promotion",
        "release",
        "response",
        "runtime",
        "source",
        "trust",
        "witness",
    )
    return {
        "apiVersion": verify_release_completion.FINAL_COMPLETION_IDENTITY_API_VERSION,
        "challengeNonceSha256": digest("1"),
        "coreDigests": {
            name: digest(format(index + 2, "x"))
            for index, name in enumerate(core_names)
        },
        "pipeline": "manifest-v6-promoted-oci-nitro-eif",
        "releaseGeneration": 42,
        "rollbackEpoch": 7,
    }


def launch_manifest_v3_verification_fixture(
    receipt: dict[str, Any],
    nonce_assurance: dict[str, Any],
) -> dict[str, Any]:
    request = receipt["launchAuthorization"]["request"]
    statement = receipt["launchAuthorization"]["envelope"]["statement"]
    witness = statement["monotonicWitness"]
    witness_statement = witness["statement"]
    return {
        "apiVersion": "serverware.productionReadinessLaunch/v3",
        "manifestSha256": receipt["manifest"]["sha256"],
        "authorizationScope": request["authorizationScope"],
        "freshnessAuthority": request["freshnessAuthority"],
        "capabilitySemantics": statement["capabilitySemantics"],
        "launchAttemptJournal": {
            "apiVersion": request["launchAttemptJournalDomain"],
            "path": (
                "/var/lib/serverware/production-proof/"
                "launch-authorization-attempt.v1.json"
            ),
            "lockPath": (
                "/var/lib/serverware/production-proof/"
                "launch-authorization-attempt.v1.lock"
            ),
            "domain": request["launchAttemptJournalDomain"],
            "maxBytes": 64 * 1024,
            "consistencyScope": (
                "trusted-host-readiness-availability-and-consistency-only"
            ),
            "rollbackAuthority": "external-monotonic-witness",
        },
        "launchAttemptRecoveryIdentitySha256": request[
            "launchAttemptRecoveryIdentitySha256"
        ],
        "globalRoleRegistry": request["globalRoleRegistry"],
        "globalRoleRegistrySha256": request[
            "globalRoleRegistrySha256"
        ],
        "globalRoleRegistryPinsFile": {
            "path": (
                "/etc/serverware/"
                "production-launch-global-role-registry.json"
            ),
            "sha256": request["globalRoleRegistryPinsSha256"],
        },
        "monotonicWitness": {
            "sha256": sha256_prefixed_json(witness),
            "signingKeyId": witness_statement["witnessKeyId"],
            "identitySha256": witness_statement[
                "witnessIdentitySha256"
            ],
            "administrativeDomainSha256": witness_statement[
                "witnessAdministrativeDomainSha256"
            ],
            "storeAssuranceSha256": witness_statement[
                "storeAssuranceSha256"
            ],
            "storeAssuranceIssuerKeyId": request[
                "globalRoleRegistry"
            ]["roles"]["launchAuthorityWitnessStoreAssurance"],
            "registryGeneration": witness_statement[
                "registryGeneration"
            ],
            "registrySha256": witness_statement["registrySha256"],
            "predecessorStateSha256": witness_statement[
                "predecessorStateSha256"
            ],
            "successorStateSha256": witness_statement[
                "successorStateSha256"
            ],
            "checkpointSequence": witness_statement[
                "checkpointSequence"
            ],
            "stateTransitionCommitted": True,
        },
        "launchAuthorityIssuanceSaga": {
            "ledgerSchemaVersion": 7,
            "requestSha256": receipt["launchAuthorization"][
                "requestSha256"
            ],
            "authorizationId": statement["authorizationId"],
            "recoveryIdentitySha256": request[
                "launchAttemptRecoveryIdentitySha256"
            ],
            "registryGeneration": witness_statement[
                "registryGeneration"
            ],
            "registrySha256": witness_statement["registrySha256"],
            "predecessorStateSha256": witness_statement[
                "predecessorStateSha256"
            ],
            "successorStateSha256": witness_statement[
                "successorStateSha256"
            ],
            "checkpointSequence": witness_statement[
                "checkpointSequence"
            ],
            "witnessTransitionSha256": sha256_prefixed_json(witness),
            "stateTransitionCommitted": True,
        },
        "contractSha256": nonce_assurance["contractSha256"],
        "pinsFile": {
            "path": receipt["nonceRollbackAssurance"]["pinsFile"]["path"],
            "sha256": nonce_assurance["retainedSnapshotSha256"],
        },
        "verifierStateService": nonce_assurance["verifierStateService"],
        "purpose": "readiness-only",
        "verified": True,
    }


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

    nonce_assurance = {
        "contractSha256": receipt["nonceRollbackAssurance"][
            "contractSha256"
        ],
        "retainedSnapshotSha256": receipt["nonceRollbackAssurance"][
            "retainedSnapshotSha256"
        ],
        "verifierStateService": receipt["nonceRollbackAssurance"][
            "verifierStateService"
        ],
        "verified": True,
    }
    launch_manifest_v3 = launch_manifest_v3_verification_fixture(
        receipt,
        nonce_assurance,
    )
    binding_arguments = {
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
        "nonce_rollback_assurance": nonce_assurance,
        "launch_manifest_v3": launch_manifest_v3,
    }
    launch_identity = (
        verify_release_completion.verify_bootstrap_launch_authorization_bindings(
            receipt,
            **binding_arguments,
        )
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
            "nonce_rollback_assurance_bound",
            "launch_manifest_v3_bound",
            "launch_attempt_journal_bound",
            "global_role_registry_bound",
            "trusted_host_scope_and_freshness_bound",
            "monotonic_witness_bound",
            "launch_authority_v7_saga_bound",
        )
    ):
        raise AssertionError(
            f"completion launch authorization omitted required bindings: {launch_identity}"
        )
    receipt_with_extra = clone_document(receipt)
    receipt_with_extra["unexpected"] = True
    receipt_without_nonce = clone_document(receipt)
    receipt_without_nonce.pop("nonceRollbackAssurance")
    request_with_extra = clone_document(receipt)
    request_with_extra["launchAuthorization"]["request"]["unexpected"] = True
    request_without_registry_pins = clone_document(receipt)
    request_without_registry_pins["launchAuthorization"]["request"].pop(
        "globalRoleRegistryPinsSha256"
    )
    authorization_with_extra = clone_document(receipt)
    authorization_with_extra["launchAuthorization"]["unexpected"] = True
    cross_wired_statement = clone_document(receipt)
    cross_wired_statement["launchAuthorization"]["envelope"]["statement"][
        "globalRoleRegistrySha256"
    ] = digest("9")
    for label, invalid_receipt in (
        ("receipt with an added field", receipt_with_extra),
        ("receipt with an omitted nonce binding", receipt_without_nonce),
        ("request with an added field", request_with_extra),
        (
            "request with an omitted registry-pins digest",
            request_without_registry_pins,
        ),
        ("authorization wrapper with an added field", authorization_with_extra),
        ("cross-wired authorization statement", cross_wired_statement),
    ):
        try:
            verify_release_completion.verify_bootstrap_launch_authorization_bindings(
                invalid_receipt,
                **binding_arguments,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "completion launch authorization accepted exact-field violation: "
                + label
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
    cross_wired_journal = clone_document(launch_manifest_v3)
    cross_wired_journal["launchAttemptRecoveryIdentitySha256"] = digest("9")
    cross_wired_registry = clone_document(launch_manifest_v3)
    cross_wired_registry["globalRoleRegistrySha256"] = digest("9")
    cross_wired_witness = clone_document(launch_manifest_v3)
    cross_wired_witness["monotonicWitness"]["successorStateSha256"] = digest("9")
    cross_wired_scope = clone_document(launch_manifest_v3)
    cross_wired_scope["authorizationScope"] = "cross-wired-scope"
    cross_wired_freshness = clone_document(launch_manifest_v3)
    cross_wired_freshness["freshnessAuthority"] = "cross-wired-freshness"
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
        (
            "nonce contract",
            {
                "nonce_rollback_assurance": {
                    **nonce_assurance,
                    "contractSha256": digest("9"),
                }
            },
        ),
        (
            "launch manifest",
            {
                "launch_manifest_v3": {
                    **launch_manifest_v3,
                    "manifestSha256": digest("9"),
                }
            },
        ),
        (
            "verifier-state service",
            {
                "nonce_rollback_assurance": {
                    **nonce_assurance,
                    "verifierStateService": {
                        **nonce_assurance["verifierStateService"],
                        "storeIdentitySha256": digest("9"),
                    },
                },
            },
        ),
        (
            "launch-attempt journal",
            {"launch_manifest_v3": cross_wired_journal},
        ),
        (
            "global role registry",
            {"launch_manifest_v3": cross_wired_registry},
        ),
        (
            "monotonic witness",
            {"launch_manifest_v3": cross_wired_witness},
        ),
        (
            "readiness scope",
            {"launch_manifest_v3": cross_wired_scope},
        ),
        (
            "freshness authority",
            {"launch_manifest_v3": cross_wired_freshness},
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
            "nonce_rollback_assurance": nonce_assurance,
            "launch_manifest_v3": launch_manifest_v3,
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


def verify_launcher_nonce_manifest_v3_binding() -> None:
    contract, _pins_bytes, pins_sha256, contract_sha256 = (
        nonce_rollback_contract_fixture()
    )
    security = launch_authorization_security_fixture()

    def manifest_document(api_version: str, *, extra: bool = False) -> dict[str, Any]:
        value = {
            "apiVersion": api_version,
            "kind": "ProductionReadinessLaunch",
            "releaseRoot": "/opt/serverware/releases/fixture",
            "stateDirectory": "/var/lib/serverware/production-proof",
            "sourceTreeDigest": SOURCE_TREE_DIGEST,
            "authorization": {
                "authorizationScope": launch_authorization.AUTHORIZATION_SCOPE,
                "deploymentAudience": "production.us-east-1:primary",
                "deploymentIdentitySha256": digest("a"),
                "freshnessAuthority": launch_authorization.FRESHNESS_AUTHORITY,
                "monotonicWitness": {
                    "administrativeDomainSha256": security[
                        "witnessAdministrativeDomainSha256"
                    ],
                    "identitySha256": security[
                        "witnessIdentitySha256"
                    ],
                    "signingKeyId": security["witnessKeyId"],
                    "signingPublicKeySpkiDerBase64url": security[
                        "witnessPublicKeySpkiDerBase64url"
                    ],
                    "storeAssurance": security[
                        "witnessStoreAssurance"
                    ],
                    "storeAssuranceIssuerKeyId": security[
                        "witnessStoreAssuranceIssuerKeyId"
                    ],
                    "storeAssuranceIssuerPublicKeySpkiDerBase64url": security[
                        "witnessStoreAssuranceIssuerPublicKeySpkiDerBase64url"
                    ],
                    "storeAssuranceSha256": security[
                        "witnessStoreAssuranceSha256"
                    ],
                },
                "releaseSequence": 42,
                "rollbackEpoch": 7,
            },
            "launchAttemptJournal": {
                "apiVersion": (
                    launch_authorization.LAUNCH_ATTEMPT_JOURNAL_DOMAIN
                ),
                "path": (
                    "/var/lib/serverware/production-proof/"
                    "launch-authorization-attempt.v1.json"
                ),
                "lockPath": (
                    "/var/lib/serverware/production-proof/"
                    "launch-authorization-attempt.v1.lock"
                ),
                "domain": (
                    launch_authorization.LAUNCH_ATTEMPT_JOURNAL_DOMAIN
                ),
                "maxBytes": 64 * 1024,
                "consistencyScope": (
                    "trusted-host-readiness-availability-and-consistency-only"
                ),
                "rollbackAuthority": "external-monotonic-witness",
            },
            "globalRoleRegistry": {
                "apiVersion": (
                    "serverware.productionLaunchGlobalRoleRegistryBinding/v1"
                ),
                "canonicalProfile": (
                    "serverware.canonicalJson/"
                    "integer-string-bool-null-array-object-nfc-v1"
                ),
                "claimScope": (
                    launch_authorization.GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE
                ),
                "registry": security["globalRoleRegistry"],
                "registrySha256": security[
                    "globalRoleRegistrySha256"
                ],
                "pinsFile": {
                    "path": (
                        "/etc/serverware/"
                        "production-launch-global-role-registry.json"
                    ),
                    "sha256": security[
                        "globalRoleRegistryPinsSha256"
                    ],
                },
            },
            "nonceRollbackAssurance": {
                "apiVersion": (
                    run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
                ),
                "canonicalProfile": (
                    "serverware.canonicalJson/integer-string-bool-null-array-object-nfc-v1"
                ),
                "contract": clone_document(contract),
                "contractSha256": contract_sha256,
                "enforcement": "native-launcher-measured",
                "pinsFile": {
                    "path": "/etc/serverware/nonce-rollback-assurance-pins.json",
                    "sha256": pins_sha256,
                },
                "purpose": "readiness-only",
            },
            "productionEnv": {},
            "python": {},
            "scripts": {},
            "composeFile": {},
            "inputs": {},
            "outputs": {},
        }
        if extra:
            value["unexpected"] = True
        return value

    original_reader = run_production_readiness.read_regular_file_once
    try:
        for label, manifest, accepted in (
            (
                "valid v3",
                manifest_document(
                    "serverware.productionReadinessLaunch/v3"
                ),
                True,
            ),
            (
                "v2 downgrade",
                manifest_document(
                    "serverware.productionReadinessLaunch/v2"
                ),
                False,
            ),
            (
                "unknown field",
                manifest_document(
                    "serverware.productionReadinessLaunch/v3",
                    extra=True,
                ),
                False,
            ),
        ):
            manifest_bytes = canonical_json(manifest).encode("ascii") + b"\n"
            receipt = bootstrap_receipt_summary(
                bootstrap_receipt_fixture(
                    manifest_sha256=sha256_prefixed_bytes(manifest_bytes)
                )
            )
            retained = {
                "contractSha256": contract_sha256,
                "enforcement": "native-launcher-measured-retained-snapshot",
                "retainedSnapshotSha256": pins_sha256,
                "verifierStateService": receipt[
                    "nonceRollbackAssurance"
                ]["verifierStateService"],
                "verified": True,
            }
            run_production_readiness.read_regular_file_once = (
                lambda _path, _label, **_kwargs: (
                    manifest_bytes,
                    SimpleNamespace(
                        st_uid=0,
                        st_mode=stat.S_IFREG | 0o400,
                    ),
                )
            )
            try:
                verified = (
                    verify_release_completion.verify_launcher_nonce_rollback_manifest_v3(
                        receipt,
                        retained,
                    )
                )
            except ValueError:
                if accepted:
                    raise
            else:
                if (
                    not accepted
                    or verified.get("verified") is not True
                    or verified.get("verifierStateService")
                    != retained["verifierStateService"]
                ):
                    raise AssertionError(
                        f"launcher manifest unexpectedly accepted {label}: {verified}"
                    )

        rejected_manifests: list[tuple[str, dict[str, Any]]] = []

        omitted_journal = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        del omitted_journal["launchAttemptJournal"]
        rejected_manifests.append(("omitted launch-attempt journal", omitted_journal))

        tampered_journal = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        tampered_journal["launchAttemptJournal"]["path"] = (
            "/var/lib/serverware/production-proof/cross-wired.json"
        )
        rejected_manifests.append(("tampered launch-attempt journal", tampered_journal))

        omitted_registry = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        del omitted_registry["globalRoleRegistry"]
        rejected_manifests.append(("omitted global role registry", omitted_registry))

        cross_wired_registry = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        cross_wired_registry["globalRoleRegistry"]["registrySha256"] = digest("9")
        rejected_manifests.append(
            ("cross-wired global role registry", cross_wired_registry)
        )

        omitted_scope = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        del omitted_scope["authorization"]["authorizationScope"]
        rejected_manifests.append(("omitted readiness scope", omitted_scope))

        cross_wired_scope = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        cross_wired_scope["authorization"]["authorizationScope"] = (
            "cross-wired-scope"
        )
        rejected_manifests.append(("cross-wired readiness scope", cross_wired_scope))

        omitted_freshness = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        del omitted_freshness["authorization"]["freshnessAuthority"]
        rejected_manifests.append(
            ("omitted freshness authority", omitted_freshness)
        )

        cross_wired_freshness = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        cross_wired_freshness["authorization"]["freshnessAuthority"] = (
            "cross-wired-freshness"
        )
        rejected_manifests.append(
            ("cross-wired freshness authority", cross_wired_freshness)
        )

        omitted_witness_assurance = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        del omitted_witness_assurance["authorization"]["monotonicWitness"][
            "storeAssurance"
        ]
        rejected_manifests.append(
            ("omitted witness-store assurance", omitted_witness_assurance)
        )

        tampered_witness_assurance = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        tampered_witness_assurance["authorization"]["monotonicWitness"][
            "storeAssuranceSha256"
        ] = digest("9")
        rejected_manifests.append(
            ("tampered witness-store assurance", tampered_witness_assurance)
        )

        cross_wired_witness = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        cross_wired_witness["authorization"]["monotonicWitness"][
            "identitySha256"
        ] = digest("9")
        rejected_manifests.append(
            ("cross-wired monotonic witness", cross_wired_witness)
        )

        obsolete_use_limit = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        obsolete_use_limit["authorization"]["useLimit"] = 1
        rejected_manifests.append(("obsolete useLimit", obsolete_use_limit))

        for label, rejected_manifest in rejected_manifests:
            rejected_bytes = (
                canonical_json(rejected_manifest).encode("ascii") + b"\n"
            )
            rejected_receipt = bootstrap_receipt_summary(
                bootstrap_receipt_fixture(
                    manifest_sha256=sha256_prefixed_bytes(rejected_bytes)
                )
            )
            rejected_retained = {
                "contractSha256": contract_sha256,
                "enforcement": "native-launcher-measured-retained-snapshot",
                "retainedSnapshotSha256": pins_sha256,
                "verifierStateService": rejected_receipt[
                    "nonceRollbackAssurance"
                ]["verifierStateService"],
                "verified": True,
            }
            run_production_readiness.read_regular_file_once = (
                lambda _path, _label, **_kwargs: (
                    rejected_bytes,
                    SimpleNamespace(
                        st_uid=0,
                        st_mode=stat.S_IFREG | 0o400,
                    ),
                )
            )
            try:
                verify_release_completion.verify_launcher_nonce_rollback_manifest_v3(
                    rejected_receipt,
                    rejected_retained,
                )
            except ValueError:
                pass
            else:
                raise AssertionError(f"launcher manifest accepted {label}")

        substituted = manifest_document(
            "serverware.productionReadinessLaunch/v3"
        )
        substituted["nonceRollbackAssurance"]["contract"][
            "publicConfigPins"
        ]["nonceAuthorityVerifierStateStoreIdentitySha256"] = digest("f")
        substituted_bytes = (
            canonical_json(substituted).encode("ascii") + b"\n"
        )
        substituted_receipt = bootstrap_receipt_summary(
            bootstrap_receipt_fixture(
                manifest_sha256=sha256_prefixed_bytes(substituted_bytes)
            )
        )
        run_production_readiness.read_regular_file_once = (
            lambda _path, _label, **_kwargs: (
                substituted_bytes,
                SimpleNamespace(
                    st_uid=0,
                    st_mode=stat.S_IFREG | 0o400,
                ),
            )
        )
        try:
            verify_release_completion.verify_launcher_nonce_rollback_manifest_v3(
                substituted_receipt,
                {
                    "contractSha256": contract_sha256,
                    "enforcement": "native-launcher-measured-retained-snapshot",
                    "retainedSnapshotSha256": pins_sha256,
                    "verifierStateService": substituted_receipt[
                        "nonceRollbackAssurance"
                    ]["verifierStateService"],
                    "verified": True,
                },
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "launcher manifest accepted contract substitution behind the same path"
            )
    finally:
        run_production_readiness.read_regular_file_once = original_reader


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
OBSERVATION_RESPONSE_BODY = b'{"accepted":true}'
OBSERVATION_REQUEST_COMMITMENT = {
    "method": "POST",
    "target_digest": sha256_prefixed_bytes(b"/v1/messages?limit=1"),
    "query_present": True,
    "query_digest": sha256_prefixed_bytes(b"limit=1"),
    "headers_digest": sha256_prefixed_bytes(
        b"host: api.example\r\ncontent-type: application/json\r\n"
    ),
    "header_count": 2,
    "body_digest": sha256_prefixed_bytes(b'{"ok":1}'),
    "body_bytes": len(b'{"ok":1}'),
    "body_observation": "complete-buffered",
}
OBSERVATION_CLIENT_REQUEST_DIGEST = sha256_prefixed_json(
    OBSERVATION_REQUEST_COMMITMENT
)
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


def release_authorization_durable_policy_fixture(
    receipt_version: str,
    *,
    attempt_id: str,
    durable_policy: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if receipt_version == "v1":
        if durable_policy is not None:
            raise ValueError("v1 release authorization fixtures cannot carry durable policy")
        return None
    if receipt_version != "v2":
        raise ValueError("release authorization fixture version is unsupported")
    if durable_policy is not None:
        return clone_document(durable_policy)
    claims = [
        {
            "constraintId": "durable:fixture",
            "type": "traversalBudget",
            "attemptId": attempt_id,
        }
    ]
    return {
        "actorId": "spiffe://prod.serverware.dev/decision-gate/durable-fixture",
        "claimDigest": sha256_prefixed_json(claims),
        "claims": claims,
    }


def release_authorization_binding_fixture(
    *,
    receipt_version: str,
    attempt_id: str,
    principal_id: str,
    route_id: str,
    credential_id: str,
    credential_version: int,
    request_digest: str,
    operation_digest: str,
    operation_context: dict[str, Any],
    require_jit_grant: bool,
    shared_quotas: list[dict[str, Any]] | None = None,
    durable_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    binding = {
        "attempt_id": attempt_id,
        "flow_id": attempt_id,
        "principal_id": principal_id,
        "route_id": route_id,
        "credential_id": credential_id,
        "credential_version": credential_version,
        "policy_hash": POLICY_DIGEST,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "operation_context": clone_document(operation_context),
        "require_jit_grant": require_jit_grant,
        "shared_quotas": clone_document(shared_quotas or []),
    }
    if receipt_version == "v2":
        if durable_policy is None:
            raise ValueError("v2 release authorization fixtures require durable policy")
        binding["api_version"] = verify_release_completion.RELEASE_AUTHORIZATION_BINDING_V2
        binding["durable_policy"] = clone_document(durable_policy)
    elif receipt_version != "v1":
        raise ValueError("release authorization fixture version is unsupported")
    return binding


def proxy_response_proof(
    provenance_digest: str,
    *,
    now: int | None = None,
    shared_quotas: list[dict[str, Any]] | None = None,
    dispatch_quotas: list[dict[str, Any]] | None = None,
    receipt_version: str = "v1",
    durable_policy: dict[str, Any] | None = None,
    response_nonce: str | None = None,
    attempt_id: str = "sha256:" + "a" * 64,
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
    durable_policy = release_authorization_durable_policy_fixture(
        receipt_version,
        attempt_id=attempt_id,
        durable_policy=durable_policy,
    )
    authorization_binding = release_authorization_binding_fixture(
        receipt_version=receipt_version,
        attempt_id=attempt_id,
        principal_id=PROXY_PRINCIPAL_ID,
        route_id="demo.echo",
        credential_id="cred-demo-bearer",
        credential_version=7,
        request_digest=PROXY_REQUEST_DIGEST,
        operation_digest=PROXY_OPERATION_DIGEST,
        operation_context=PROXY_OPERATION_CONTEXT,
        require_jit_grant=False,
        shared_quotas=shared_quotas,
        durable_policy=durable_policy,
    )
    release_authority = {
        "authority_mode": "atomic",
        "grant_id": None,
        "approval_id": None,
        "credential_ref": "cred-demo-bearer",
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
        receipt_version=receipt_version,
        durable_policy=durable_policy,
        response_nonce=response_nonce,
    )
    document["external_capture"]["control_plane_authorization_receipt"] = clone_document(
        receipt
    )
    document["server_statement"]["control_plane_authorization_receipt"] = receipt
    resign_proxy_response_proof(document)
    return document


def observation_attested_claims(document: dict[str, Any]) -> dict[str, Any]:
    statement = document["runtime_proof"]["server_statement"]
    statement_digest = sha256_prefixed_json(statement)
    upstream = statement["upstream_observation"]
    return {
        "server_statement_sha256": statement_digest,
        "server_statement_api_version": "serverware.responseObservationStatement/v1",
        "issued_at_unix": statement["issued_at_unix"],
        "observation_id": statement["observation_id"],
        "client_nonce_sha256": sha256_prefixed_bytes(b64d(statement["client_nonce"])),
        "request_aggregate_digest": statement["request"]["aggregate_digest"],
        "response_path": statement["response_path"],
        "upstream_attempt": statement["upstream_attempt"],
        "upstream_observation_digest": (
            upstream["aggregate_digest"] if upstream is not None else None
        ),
        "emitted_response_digest": statement["emitted_response"]["aggregate_digest"],
        "policy_digest": statement["policy"]["digest"],
        "runtime_manifest_digest": statement["runtime_manifest_digest"],
        "data_plane_binary_digest": statement["data_plane_binary_digest"],
        "release_digest": statement["release_digest"],
        "server_instance_id": statement["server_instance"]["id"],
        "server_instance_identity_digest": statement["server_instance"]["identity_digest"],
        "tls_exporter_label": "EXPORTER-Serverware-Response-Observation-v1",
        "tls_channel_binding_sha256": sha256_prefixed_bytes(
            statement["tls_channel_binding"]["value"].encode("utf-8")
        ),
        "response_signing_key_id": proxy_response_key_info()["key_id"],
        "observation_source": "gate-authored",
    }


def sign_observation_collector(document: dict[str, Any]) -> None:
    capture = {field: value for field, value in document.items() if field != "collector"}
    key_info = proxy_collector_key_info()
    document["collector"] = {
        "algorithm": "Ed25519",
        "key_id": key_info["key_id"],
        "public_key_pem": key_info["public_key_pem"],
        "signature": "ed25519:"
        + b64e(key_info["key"].sign(canonical_json(capture).encode("utf-8"))),
        "capture_digest": sha256_prefixed_json(capture),
    }


def resign_observation_proof(document: dict[str, Any]) -> None:
    runtime = document["runtime_proof"]
    statement = runtime["server_statement"]
    statement_digest = sha256_prefixed_json(statement)
    response_key = proxy_response_key_info()
    runtime["server_statement_sha256"] = statement_digest
    runtime["server_signature"] = {
        "algorithm": "Ed25519",
        "key_id": response_key["key_id"],
        "public_key_pem": response_key["public_key_pem"],
        "signature": "ed25519:"
        + b64e(response_key["key"].sign(canonical_json(statement).encode("utf-8"))),
    }
    vendor = runtime["vendor_tee"]
    vendor["quote_sha256"] = sha256_prefixed_json(vendor["quote"])
    verifier_key = proxy_vendor_verifier_key_info()
    verifier_statement = vendor["trusted_verifier"]["statement"]
    verifier_statement.update(
        {
            "verifier_key_id": verifier_key["key_id"],
            "tee_platform": vendor["platform"],
            "quote_provider": vendor["provider"],
            "vendor_quote_sha256": vendor["quote_sha256"],
            "server_statement_sha256": statement_digest,
            "response_signing_key_id": response_key["key_id"],
            "attested_claims": observation_attested_claims(document),
        }
    )
    vendor["trusted_verifier"]["signature"] = "ed25519:" + b64e(
        verifier_key["key"].sign(canonical_json(verifier_statement).encode("utf-8"))
    )
    sign_observation_collector(document)


def response_observation_proof(
    provenance_digest: str,
    *,
    now: int | None = None,
    receipt_version: str = "v1",
    durable_policy: dict[str, Any] | None = None,
    response_nonce: str | None = None,
    observation_nonce: str | None = None,
) -> dict[str, Any]:
    captured_at = int(time.time()) if now is None else now
    observation_nonce = observation_nonce or b64e(
        (captured_at + 300).to_bytes(4, "big") + b"n" * 28
    )
    request = clone_document(OBSERVATION_REQUEST_COMMITMENT)
    request["aggregate_digest"] = OBSERVATION_CLIENT_REQUEST_DIGEST
    emitted = {
        "status": 200,
        "headers_digest": sha256_prefixed_json(
            {
                "connection": "close",
                "content-type": "application/json",
                "trailer": "X-Serverware-Observation-Proof-B64, X-Serverware-Observation-Proof-SHA256",
                "transfer-encoding": "chunked",
            }
        ),
        "header_count": 4,
        "body_digest": sha256_prefixed_bytes(OBSERVATION_RESPONSE_BODY),
        "body_bytes": len(OBSERVATION_RESPONSE_BODY),
    }
    emitted["aggregate_digest"] = sha256_prefixed_json(emitted)
    upstream = {
        "status": 429,
        "headers_digest": sha256_prefixed_json(
            {"content-type": ["application/json"], "retry-after": ["60"]}
        ),
        "header_count": 2,
        "body_state": "complete",
        "body_digest": sha256_prefixed_bytes(b'{"error":"rate-limit"}'),
        "body_bytes": len(b'{"error":"rate-limit"}'),
    }
    upstream["aggregate_digest"] = sha256_prefixed_json(upstream)
    attempt_id = digest("a")
    durable_policy = release_authorization_durable_policy_fixture(
        receipt_version,
        attempt_id=attempt_id,
        durable_policy=durable_policy,
    )
    authorization_binding = release_authorization_binding_fixture(
        receipt_version=receipt_version,
        attempt_id=attempt_id,
        principal_id=PROXY_PRINCIPAL_ID,
        route_id="demo.echo",
        credential_id="cred-demo-bearer",
        credential_version=7,
        request_digest=PROXY_REQUEST_DIGEST,
        operation_digest=PROXY_OPERATION_DIGEST,
        operation_context=PROXY_OPERATION_CONTEXT,
        require_jit_grant=False,
        durable_policy=durable_policy,
    )
    binding_digest = sha256_prefixed_json(authorization_binding)
    release_authority = {
        "authority_mode": "atomic",
        "grant_id": None,
        "approval_id": None,
        "credential_ref": "cred-demo-bearer",
        "credential_version": 7,
        "request_digest": PROXY_REQUEST_DIGEST,
        "operation_digest": PROXY_OPERATION_DIGEST,
        "attempt_id": attempt_id,
        "consumption_identity_digest": binding_digest,
        "authorization_state_at_upstream_dispatch": "dispatching",
        "authorization_state_observed_at_epoch_ms": captured_at * 1000,
        "reservation_expires_at_epoch_ms": captured_at * 1000 + 300_000,
        "dispatch_expires_at_epoch_ms": captured_at * 1000 + 300_000,
    }
    statement = {
        "apiVersion": "serverware.responseObservationStatement/v1",
        "issued_at_unix": captured_at,
        "observation_id": sha256_prefixed_json(
            {
                "client_nonce": observation_nonce,
                "contract": "serverware.responseObservationStatement/v1",
            }
        ),
        "client_nonce": observation_nonce,
        "request": request,
        "policy": {
            "digest": POLICY_DIGEST,
            "snapshot_epoch": 7,
            "decision_state": "allowed",
            "completion_state": "same-active",
        },
        "principal_id": PROXY_PRINCIPAL_ID,
        "route_id": "demo.echo",
        "request_digest": PROXY_REQUEST_DIGEST,
        "operation_digest": PROXY_OPERATION_DIGEST,
        "credential": {
            "state": "injected",
            "binding_digest": sha256_prefixed_json(
                {"credential_ref": "cred-demo-bearer", "credential_version": 7}
            ),
        },
        "authorization": {
            "state": "completed-forwarded",
            "binding_digest": binding_digest,
            "release_authority": release_authority,
            "control_plane_authorization_receipt": {},
            "control_plane_authorization_receipt_sha256": digest("0"),
        },
        "response_path": "complete-upstream-response-released",
        "upstream_attempt": "complete",
        "upstream_observation": upstream,
        "emitted_response": emitted,
        "runtime_manifest_digest": digest("7"),
        "data_plane_binary_digest": digest("9"),
        "release_digest": provenance_digest,
        "server_instance": {
            "id": PROXY_SERVER_INSTANCE_ID,
            "identity_digest": sha256_prefixed_bytes(PROXY_SERVER_INSTANCE_ID.encode("utf-8")),
        },
        "tls_channel_binding": {
            "type": "tls-exporter",
            "label": "EXPORTER-Serverware-Response-Observation-v1",
            "value": PROXY_TLS_CHANNEL_BINDING,
        },
        "observation_authority": {
            "source": "gate-authored",
            "upstream_truth": "not-independently-observed",
            "downstream_delivery": "not-claimed",
        },
    }
    receipt_source = {"server_statement": clone_document(statement)}
    receipt_source["server_statement"]["release_authority"] = release_authority
    receipt = control_plane_authorization_receipt(
        receipt_source,
        receipt_version=receipt_version,
        durable_policy=durable_policy,
        response_nonce=response_nonce,
    )
    statement["authorization"]["control_plane_authorization_receipt"] = receipt
    statement["authorization"]["control_plane_authorization_receipt_sha256"] = (
        sha256_prefixed_json(receipt)
    )
    quote = {
        "format": "aws-nitro-attestation-document",
        "body_b64": b64e(b"test-only opaque observation quote bytes " * 4),
    }
    document = {
        "apiVersion": "serverware.responseObservationProof/v1",
        "kind": "ServerwareResponseObservationProof",
        "captured_at_unix": captured_at,
        "request": {field: value for field, value in request.items() if field != "body_observation"},
        "response": clone_document(emitted),
        "runtime_proof": {
            "apiVersion": "serverware.responseObservationRuntimeProof/v1",
            "kind": "ServerwareResponseObservationRuntimeProof",
            "server_statement": statement,
            "server_statement_sha256": digest("0"),
            "server_signature": {},
            "vendor_tee": {
                "platform": "aws-nitro",
                "provider": "aws-nitro-enclaves",
                "quote_sha256": sha256_prefixed_json(quote),
                "quote": quote,
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
                    "signature": "",
                },
            },
        },
        "collector": {},
    }
    resign_observation_proof(document)
    return document


def credentialless_response_observation_proof(
    provenance_digest: str,
    *,
    now: int | None = None,
    observation_nonce: str | None = None,
) -> dict[str, Any]:
    document = response_observation_proof(
        provenance_digest,
        now=now,
        observation_nonce=observation_nonce,
    )
    statement = document["runtime_proof"]["server_statement"]
    statement["credential"] = {"state": "not-required", "binding_digest": None}
    statement["authorization"] = {
        "state": "not-evaluated",
        "binding_digest": None,
        "release_authority": None,
        "control_plane_authorization_receipt": None,
        "control_plane_authorization_receipt_sha256": None,
    }
    resign_observation_proof(document)
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
            "classification": "runtime-verified-complete-stream",
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


def release_authorization_dispatch_quotas_fixture(
    quotas: list[dict[str, Any]] | None,
    receipt_version: str,
) -> list[dict[str, Any]]:
    normalized = clone_document(quotas or [])
    if receipt_version == "v1":
        return normalized
    if receipt_version != "v2":
        raise ValueError("release authorization fixture version is unsupported")
    for quota in normalized:
        window_kind = quota.get("windowKind", "fixed")
        quota["windowKind"] = window_kind
        if window_kind == "fixed":
            quota["windowEndEpochMs"] = (
                quota["windowStartEpochMs"] + quota["windowSeconds"] * 1000
            )
        else:
            quota["calendarWindow"] = window_kind
            if "windowEndEpochMs" not in quota:
                raise ValueError(
                    "calendar quota fixtures require an explicit window end"
                )
    return normalized


def signed_release_authorization_http_mock_response(
    request_headers: dict[str, str],
    *,
    request_method: str,
    request_path: str,
    request_query: str,
    status: int,
    body: dict[str, Any],
    response_headers: list[dict[str, str]],
    issued_at_ms: int,
    context: dict[str, str],
    key_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response_nonce = next(
        (
            value
            for name, value in request_headers.items()
            if name.lower() == "x-serverware-response-nonce"
        ),
        None,
    )
    if not isinstance(response_nonce, str) or not response_nonce:
        raise ValueError("release authorization mock request is missing its response nonce")
    response_nonce_bytes = verify_release_completion.require_base64url_bytes(
        response_nonce,
        "release authorization mock response nonce",
        minimum_bytes=32,
    )
    if len(response_nonce_bytes) != 32:
        raise ValueError(
            "release authorization mock response nonce must contain exactly 32 bytes"
        )
    signer = key_info or control_plane_response_signing_key_info()
    body_bytes = canonical_json(body).encode("utf-8")
    body_digest = sha256_prefixed_bytes(body_bytes)
    response_headers_bytes = canonical_json(response_headers).encode("ascii")
    statement = {
        "version": verify_release_completion.CONTROL_PLANE_RESPONSE_SIGNATURE_API_VERSION,
        "issued_at_ms": issued_at_ms,
        "request": {
            "method": request_method,
            "path": request_path,
            "query_sha256": sha256_prefixed_bytes(request_query.encode("utf-8")),
        },
        "status_code": status,
        "body_sha256": body_digest,
        "response_headers_sha256": sha256_prefixed_bytes(response_headers_bytes),
        "response_header_count": len(response_headers),
        "nonce": response_nonce,
        "response_signing_key_id": signer["key_id"],
        "context": clone_document(context),
    }
    statement_bytes = canonical_json(statement).encode("utf-8")
    proof_headers = {
        "X-Serverware-Response-Key-Id": signer["key_id"],
        "X-Serverware-Response-Body-SHA256": body_digest,
        "X-Serverware-Response-Statement-B64": b64e(statement_bytes),
        "X-Serverware-Response-Statement-SHA256": sha256_prefixed_bytes(
            statement_bytes
        ),
        "X-Serverware-Response-Signature": "ed25519:"
        + b64e(signer["key"].sign(statement_bytes)),
    }
    return {
        "status": status,
        "body_bytes": body_bytes,
        "response_headers": clone_document(response_headers),
        "proof_headers": proof_headers,
    }


def replace_control_plane_receipt_request_body(
    document: dict[str, Any],
    body: dict[str, Any],
) -> None:
    body_bytes = canonical_json(body).encode("utf-8")
    document["request"]["body_b64"] = b64e(body_bytes)
    document["request"]["body_sha256"] = sha256_prefixed_bytes(body_bytes)
    resign_control_plane_authorization_receipt(document)


def replace_control_plane_receipt_nonce(
    document: dict[str, Any],
    nonce: str,
) -> None:
    document["request"]["nonce"] = nonce
    response = document["response"]
    statement = json.loads(b64d(response["statement_b64"]).decode("utf-8"))
    statement["nonce"] = nonce
    response["statement_b64"] = b64e(canonical_json(statement).encode("utf-8"))
    resign_control_plane_authorization_receipt(document)


def replace_control_plane_receipt_response_headers(
    document: dict[str, Any],
    response_headers: list[dict[str, str]],
) -> None:
    response = document["response"]
    response["response_headers"] = clone_document(response_headers)
    response_headers_bytes = canonical_json(response_headers).encode("ascii")
    statement = json.loads(b64d(response["statement_b64"]).decode("utf-8"))
    statement["response_headers_sha256"] = sha256_prefixed_bytes(
        response_headers_bytes
    )
    statement["response_header_count"] = len(response_headers)
    response["statement_b64"] = b64e(canonical_json(statement).encode("utf-8"))
    resign_control_plane_authorization_receipt(document)


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
    receipt_version: str = "v1",
    durable_policy: dict[str, Any] | None = None,
    response_nonce: str | None = None,
) -> dict[str, Any]:
    release_authority = proxy_proof["server_statement"]["release_authority"]
    observed_at_epoch_ms = release_authority[
        "authorization_state_observed_at_epoch_ms"
    ]
    durable_policy = release_authorization_durable_policy_fixture(
        receipt_version,
        attempt_id=release_authority["attempt_id"],
        durable_policy=durable_policy,
    )
    request_body = {
        "apiVersion": (
            verify_release_completion.RELEASE_AUTHORIZATION_DISPATCH_V2
            if receipt_version == "v2"
            else verify_release_completion.RELEASE_AUTHORIZATION_DISPATCH_V1
        ),
        "attemptId": release_authority["attempt_id"],
        "bindingDigest": release_authority["consumption_identity_digest"],
    }
    durable_dispatch: dict[str, Any] | None = None
    if durable_policy is not None:
        durable_dispatch = {
            "actorId": durable_policy["actorId"],
            "attemptId": release_authority["attempt_id"],
            "claimDigest": durable_policy["claimDigest"],
            "reservationId": (
                "reservation:fixture:"
                + release_authority["attempt_id"].removeprefix("sha256:")[:32]
            ),
            "dispatchDeadlineAtEpochMs": release_authority[
                "dispatch_expires_at_epoch_ms"
            ],
        }
        request_body["durablePolicy"] = clone_document(durable_dispatch)
    request_body_bytes = canonical_json(request_body).encode("utf-8")
    response_body = {
        "apiVersion": (
            verify_release_completion.RELEASE_AUTHORIZATION_RESPONSE_V2
            if durable_dispatch is not None
            else verify_release_completion.RELEASE_AUTHORIZATION_RESPONSE_V1
        ),
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
        "quotas": release_authorization_dispatch_quotas_fixture(
            quotas,
            receipt_version,
        ),
        "store": {"backend": "postgres", "ha": True},
    }
    if durable_dispatch is not None:
        response_body["durablePolicy"] = {
            "state": "dispatched",
            "attemptId": durable_dispatch["attemptId"],
            "claimDigest": durable_dispatch["claimDigest"],
            "reservationId": durable_dispatch["reservationId"],
            "actorId": durable_dispatch["actorId"],
            "reservationDeadlineAtEpochMs": release_authority[
                "reservation_expires_at_epoch_ms"
            ],
            "dispatchDeadlineAtEpochMs": durable_dispatch[
                "dispatchDeadlineAtEpochMs"
            ],
            "responseEvidenceDigest": None,
            "failureReason": None,
            "responseBodySha256": None,
            "uncertainty": None,
        }
    response_headers = [
        {
            "name": "content-type",
            "value_b64": b64e(b"application/json"),
        }
    ]
    nonce = response_nonce or b64e(os.urandom(32))
    mock_response = signed_release_authorization_http_mock_response(
        {"X-Serverware-Response-Nonce": nonce},
        request_method="POST",
        request_path=verify_release_completion.CONTROL_PLANE_DISPATCH_PATH,
        request_query="",
        status=200,
        body=response_body,
        response_headers=response_headers,
        issued_at_ms=observed_at_epoch_ms,
        context={
            "runtime_manifest_digest": proxy_proof["server_statement"][
                "runtime_manifest_digest"
            ],
            "policy_bundle_digest": POLICY_DIGEST,
            "provenance_digest": proxy_proof["server_statement"]["release_digest"],
            "image_signatures_digest": IMAGE_SIGNATURES_DIGEST,
            "source_tree_digest": SOURCE_TREE_DIGEST,
        },
    )
    proof_headers = mock_response["proof_headers"]
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
            "status": mock_response["status"],
            "body_b64": b64e(mock_response["body_bytes"]),
            "body_sha256": proof_headers[
                "X-Serverware-Response-Body-SHA256"
            ],
            "response_headers": mock_response["response_headers"],
            "response_signing_key_id": proof_headers[
                "X-Serverware-Response-Key-Id"
            ],
            "statement_b64": proof_headers[
                "X-Serverware-Response-Statement-B64"
            ],
            "statement_sha256": proof_headers[
                "X-Serverware-Response-Statement-SHA256"
            ],
            "signature": proof_headers["X-Serverware-Response-Signature"],
        },
    }
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


def replace_observation_control_plane_receipt(
    observation_proof: dict[str, Any],
    receipt: dict[str, Any],
) -> None:
    authorization = observation_proof["runtime_proof"]["server_statement"][
        "authorization"
    ]
    authorization["control_plane_authorization_receipt"] = clone_document(receipt)
    authorization["control_plane_authorization_receipt_sha256"] = (
        sha256_prefixed_json(receipt)
    )
    resign_observation_proof(observation_proof)


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


def test_exact_benchmark_nanosecond_contract() -> None:
    exact = verify_release_completion.ExactJsonDecimal
    for token, expected in (
        ("0", 0),
        ("0.000001", 1),
        ("1.000000", 1_000_000),
        ("9223372036854.775807", 9_223_372_036_854_775_807),
    ):
        actual = verify_release_completion.exact_milliseconds_to_nanoseconds(
            exact(token),
            label="fixture latency",
        )
        if actual != expected:
            raise AssertionError(
                f"exact millisecond conversion changed {token!r}: {actual}"
            )
    for invalid in (
        exact("-1"),
        exact("01"),
        exact("1e0"),
        exact("0.0000001"),
        exact("9223372036854.775808"),
        1.0,
        True,
    ):
        try:
            verify_release_completion.exact_milliseconds_to_nanoseconds(
                invalid,
                label="fixture latency",
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"exact millisecond conversion accepted {invalid!r}"
            )

    for invalid in ("1.000", 1.0, True):
        try:
            verify_release_completion.benchmark_milliseconds_to_nanoseconds(
                invalid,
                label="fixture benchmark latency",
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                f"benchmark latency accepted a non-JSON-number alias: {invalid!r}"
            )

    benchmark = benchmark_document()
    benchmark["p50_ms"] = exact("1.000")
    benchmark["p95_ms"] = exact("5.000")
    benchmark["p99_ms"] = exact("9.000")
    summary = verify_release_completion.verify_benchmark(
        benchmark,
        20_000_000,
        digest("9"),
    )
    integer_fields = ("requests", "p50_ns", "p95_ns", "p99_ns", "limit_ns")
    if (
        summary.get("latency_unit") != "nanoseconds"
        or any(type(summary[field]) is not int for field in integer_fields)
    ):
        raise AssertionError(
            f"benchmark proof summary contains non-integer latency: {summary}"
        )
    verify_release_completion.validate_canonical_json_profile(
        summary,
        label="benchmark proof summary",
    )
    for invalid_requests in (100.0, "100", True, 9_223_372_036_854_775_808):
        invalid_benchmark = {**benchmark, "requests": invalid_requests}
        try:
            verify_release_completion.verify_benchmark(
                invalid_benchmark,
                20_000_000,
                digest("9"),
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "benchmark verifier accepted a non-canonical request count: "
                f"{invalid_requests!r}"
            )

    preflight_with_legacy_decimal_benchmark = {
        "checks": {
            "release_artifacts": {
                "bench": {
                    "p50_ms": 1.0,
                    "p95_ms": 5.125,
                    "p99_ms": 9.000001,
                    "target_p99_ms": 20.0,
                }
            }
        }
    }
    preflight_snapshot = SimpleNamespace(
        data=json.dumps(
            preflight_with_legacy_decimal_benchmark,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"),
        path=Path("/fixture/production-host-preflight.json"),
    )
    loaded_preflight = (
        verify_release_completion.load_production_host_preflight_json_snapshot(
            preflight_snapshot,
            "fixture production host preflight",
        )
    )
    loaded_preflight_benchmark = loaded_preflight["checks"]["release_artifacts"][
        "bench"
    ]
    if (
        loaded_preflight_benchmark["p95_ms"] != 5.125
        or type(loaded_preflight_benchmark["p95_ms"]) is not float
    ):
        raise AssertionError(
            "signed preflight benchmark decimal compatibility changed"
        )
    legacy_preflight_payload = (
        verify_release_completion.canonical_legacy_preflight_signature_json(
            loaded_preflight
        )
    )
    if json.loads(legacy_preflight_payload) != loaded_preflight:
        raise AssertionError(
            "legacy preflight signature canonicalization changed validated input"
        )
    try:
        verify_release_completion.canonical_json(loaded_preflight)
    except ValueError:
        pass
    else:
        raise AssertionError(
            "completion proof canonicalization accepted legacy preflight decimals"
        )
    invalid_preflight = {
        **preflight_with_legacy_decimal_benchmark,
        "unexpected_decimal": 1.5,
    }
    invalid_preflight_snapshot = SimpleNamespace(
        data=json.dumps(
            invalid_preflight,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"),
        path=Path("/fixture/invalid-production-host-preflight.json"),
    )
    try:
        verify_release_completion.load_production_host_preflight_json_snapshot(
            invalid_preflight_snapshot,
            "invalid fixture production host preflight",
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "production host preflight loader accepted a decimal outside the "
            "closed benchmark compatibility path"
        )

    schema = json.loads(
        (ROOT / "schemas/completion-proof.v6.schema.json").read_text(
            encoding="utf-8"
        )
    )
    definitions = schema["$defs"]
    if (
        definitions["unsignedU64"]["maximum"] != 9_223_372_036_854_775_807
        or definitions["positiveU64"]["maximum"]
        != 9_223_372_036_854_775_807
        or definitions["signedI64"]["minimum"]
        != -9_223_372_036_854_775_808
        or definitions["signedI64"]["maximum"]
        != 9_223_372_036_854_775_807
        or "signedI128" in definitions
    ):
        raise AssertionError("v6 schema integer definitions are not signed-64-bit closed")
    benchmark_schema = definitions["benchmarkSummary"]
    env_schema = definitions["productionEnvironmentBindingSummary"]
    metadata_schema = definitions["metadata"]
    native_evidence_numeric_branches = [
        branch
        for branch in definitions["nativeEvidenceValue"]["anyOf"]
        if branch.get("type") in {"integer", "number"}
        or branch.get("$ref") == "#/$defs/signedI64"
    ]
    if (
        set(integer_fields) - set(benchmark_schema["required"])
        or "latency_unit" not in benchmark_schema["required"]
        or benchmark_schema["properties"]["latency_unit"]
        != {"const": "nanoseconds"}
        or any(
            benchmark_schema["properties"][field].get("$ref")
            not in {"#/$defs/unsignedU64", "#/$defs/positiveU64"}
            for field in integer_fields
        )
        or "p99_limit_ns" not in env_schema["required"]
        or env_schema["properties"]["p99_limit_ns"].get("$ref")
        != "#/$defs/positiveU64"
        or metadata_schema["properties"]["modifiedUnixNanos"].get("$ref")
        != "#/$defs/signedI64"
        or metadata_schema["properties"]["changedUnixNanos"].get("$ref")
        != "#/$defs/signedI64"
        or native_evidence_numeric_branches != [{"$ref": "#/$defs/signedI64"}]
    ):
        raise AssertionError(
            "v6 benchmark, metadata, and nested evidence schemas are not signed-64 integer closed"
        )

    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    completion_registry = Registry().with_resource(
        schema["$id"],
        Resource.from_contents(schema),
    )
    metadata_validator = Draft202012Validator(
        {"$ref": schema["$id"] + "#/$defs/metadata"},
        registry=completion_registry,
    )
    metadata_at_signed64_boundary = {
        "device": 0,
        "inode": 0,
        "mode": 0,
        "ownerUid": 0,
        "ownerGid": 0,
        "linkCount": 1,
        "size": 0,
        "modifiedUnixNanos": -9_223_372_036_854_775_808,
        "changedUnixNanos": 9_223_372_036_854_775_807,
    }
    metadata_validator.validate(metadata_at_signed64_boundary)
    metadata_above_signed64 = {
        **metadata_at_signed64_boundary,
        "changedUnixNanos": 9_223_372_036_854_775_808,
    }
    if not list(metadata_validator.iter_errors(metadata_above_signed64)):
        raise AssertionError(
            "completionProof/v6 metadata accepted an integer above signed-64"
        )
    native_evidence_validator = Draft202012Validator(
        {"$ref": schema["$id"] + "#/$defs/nativeEvidenceValue"},
        registry=completion_registry,
    )
    native_evidence_validator.validate(
        {"boundary": 9_223_372_036_854_775_807}
    )
    for invalid_numeric_evidence in (
        {"above": 9_223_372_036_854_775_808},
    ):
        if not list(
            native_evidence_validator.iter_errors(invalid_numeric_evidence)
        ):
            raise AssertionError(
                "completionProof/v6 nested evidence accepted a non-canonical "
                f"numeric value: {invalid_numeric_evidence!r}"
            )
    try:
        verify_release_completion.validate_canonical_json_profile(
            {"float": 1.0},
            label="floating-point completion evidence fixture",
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "completion proof canonicalization accepted floating-point evidence"
        )


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
    proxy_observation_body: Path | None = None,
    proxy_max_observation_body_bytes: int | None = None,
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
    observation_settings = ""
    if proxy_proof_contract == "observation-v1":
        if (
            proxy_observation_body is None
            or proxy_max_observation_body_bytes is None
        ):
            raise AssertionError(
                "observation fixture env requires a body path and byte limit"
            )
        observation_settings = (
            f"{verify_release_completion.PROXY_OBSERVATION_BODY_ENV_KEY}="
            f"{proxy_observation_body}\n"
            f"{verify_release_completion.PROXY_OBSERVATION_MAX_BYTES_ENV_KEY}="
            f"{proxy_max_observation_body_bytes}\n"
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
        f"{observation_settings}"
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
            selected_p99_limit: str = "20",
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
            or binding.get("p99_limit_ns") != 20_000_000
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
            ("p99 limit", {"selected_p99_limit": "19"}),
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
                "verification_mode": "readiness",
                "readiness_only": True,
                "final_nitro_execution_proven": False,
                "ok_for_action": False,
                "authority_boundary": (
                    production_host_preflight_module.readiness_authority_boundary(
                        launcher_evidence_verified=False
                    )
                ),
                "generated_at_unix": generated_at,
                "checks": {},
                "failures": [],
                "next_command": "fixture",
                "secret_values_redacted": True,
            }
            document["authenticity"] = production_host_preflight_module.sign_readiness_preflight(
                document,
                signing_env,
                signed_at_unix=generated_at,
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
        "verification_mode": "readiness",
        "readiness_only": True,
        "final_nitro_execution_proven": False,
        "ok_for_action": False,
        "authority_boundary": (
            production_host_preflight_module.readiness_authority_boundary(
                launcher_evidence_verified=False
            )
        ),
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
    proxy_observation_body: Path | None = None,
    proxy_max_observation_body_bytes: int | None = None,
    proxy_client_request_digest: str | None = None,
    proxy_client_nonce: str | None = None,
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
            proxy_client_nonce or PROXY_CLIENT_NONCE,
            "--proxy-client-request-digest",
            (
                PROXY_STREAM_CLIENT_REQUEST_DIGEST
                if proxy_proof_contract == "streaming-v1"
                else proxy_client_request_digest or PROXY_CLIENT_REQUEST_DIGEST
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
        elif proxy_proof_contract == "observation-v1":
            if (
                proxy_observation_body is None
                or proxy_max_observation_body_bytes is None
            ):
                raise AssertionError(
                    "observation verifier fixture requires body path and byte limit"
                )
            proxy_proof_args.extend(
                [
                    "--proxy-observation-body",
                    str(proxy_observation_body),
                    "--proxy-max-observation-body-bytes",
                    str(proxy_max_observation_body_bytes),
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
    expected_release_digest: str,
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
        expected_release_digest=expected_release_digest,
        expected_image_signatures_digest=IMAGE_SIGNATURES_DIGEST,
        expected_source_tree_digest=SOURCE_TREE_DIGEST,
        expected_response_signing_key_id=proxy_response_key_info()["key_id"],
        expected_tee_platform="aws-nitro",
        expected_quote_provider="aws-nitro-enclaves",
        max_age_seconds=300,
    )


def verify_observation_proxy_fixture(
    tmp: Path,
    document: dict[str, Any],
    *,
    expected_release_digest: str,
    expected_client_request_digest: str,
    expected_client_nonce: str,
    proof_contract: str = "observation-v1",
    observation_body: bytes = OBSERVATION_RESPONSE_BODY,
) -> dict[str, Any]:
    runtime = document.get("runtime_proof")
    runtime = runtime if isinstance(runtime, dict) else {}
    statement = runtime.get("server_statement")
    statement = statement if isinstance(statement, dict) else {}
    policy_snapshot = verify_release_completion.verify_and_compile_policy_snapshot(
        verify_release_completion.snapshot_regular_file(
            tmp / "policy-bundle.json",
            "observation fixture policy bundle",
            max_bytes=verify_release_completion.POLICY_BUNDLE_MAX_BYTES,
        ),
        verify_release_completion.snapshot_regular_file(
            tmp / "policy-signing.pub.pem",
            "observation fixture policy trust root",
            max_bytes=verify_release_completion.FINAL_TRUST_ROOT_MAX_BYTES,
        ),
        expected_policy_digest=POLICY_DIGEST,
    )
    observation_body_path = tmp / "direct-observation-response-body.bin"
    observation_body_path.write_bytes(observation_body)
    observation_body_snapshot = verify_release_completion.snapshot_regular_file(
        observation_body_path,
        "observation fixture response body",
        max_bytes=verify_release_completion.MAX_PROXY_OBSERVATION_BODY_BYTES,
        allow_empty=True,
    )
    return verify_release_completion.verify_production_proxy_response_proof(
        document,
        proof_contract=proof_contract,
        observation_body_snapshot=(
            observation_body_snapshot
            if proof_contract == "observation-v1"
            else None
        ),
        trusted_verifier_public_key_pem=proxy_vendor_verifier_key_info()["public_key_pem"],
        trusted_collector_public_key_pem=proxy_collector_key_info()["public_key_pem"],
        trusted_control_plane_response_signing_public_key_pem=(
            control_plane_response_signing_key_info()["public_key_pem"]
        ),
        expected_control_plane_response_signing_public_key_id=(
            control_plane_response_signing_key_info()["key_id"]
        ),
        policy_snapshot=policy_snapshot,
        expected_principal_id=PROXY_PRINCIPAL_ID,
        expected_server_instance_id=PROXY_SERVER_INSTANCE_ID,
        expected_client_nonce=expected_client_nonce,
        expected_client_request_digest=expected_client_request_digest,
        expected_request_digest=PROXY_REQUEST_DIGEST,
        expected_operation_digest=PROXY_OPERATION_DIGEST,
        expected_tls_channel_binding=PROXY_TLS_CHANNEL_BINDING,
        expected_policy_digest=POLICY_DIGEST,
        expected_runtime_manifest_digest=digest("7"),
        expected_binary_digest=digest("9"),
        expected_release_digest=expected_release_digest,
        expected_image_signatures_digest=IMAGE_SIGNATURES_DIGEST,
        expected_source_tree_digest=SOURCE_TREE_DIGEST,
        expected_response_signing_key_id=proxy_response_key_info()["key_id"],
        expected_tee_platform="aws-nitro",
        expected_quote_provider="aws-nitro-enclaves",
        max_age_seconds=300,
    )


def test_response_observation_proof_requirements(
    tmp: Path,
    provenance_digest: str,
) -> None:
    valid_captured_at = int(time.time())
    valid_nonce = b64e(
        (valid_captured_at + 300).to_bytes(4, "big") + b"v" * 28
    )
    valid = response_observation_proof(
        provenance_digest,
        now=valid_captured_at,
        observation_nonce=valid_nonce,
    )
    summary = verify_observation_proxy_fixture(
        tmp,
        valid,
        expected_release_digest=provenance_digest,
        expected_client_request_digest=OBSERVATION_CLIENT_REQUEST_DIGEST,
        expected_client_nonce=valid_nonce,
    )
    expected_control_plane_key_id = control_plane_response_signing_key_info()[
        "key_id"
    ]
    if (
        summary.get("proof_contract") != "observation-v1"
        or summary.get("terminal_runtime_proof_bound") is not True
        or summary.get("strict_collector_capture_bound") is not True
        or summary.get("upstream_status") != 429
        or summary.get("response_path") != "complete-upstream-response-released"
        or summary.get("compiled_route_authority_verified") is not True
        or summary.get("observation_authority")
        != {
            "source": "gate-authored",
            "upstream_truth": "not-independently-observed",
            "downstream_delivery": "not-claimed",
        }
        or summary.get("control_plane_response_signing_key_id")
        != expected_control_plane_key_id
    ):
        raise AssertionError(f"observation proof summary omitted strict bindings: {summary}")

    durable_nonce = b64e(b"o" * 32)
    durable_observation_nonce = b64e(
        (valid_captured_at + 300).to_bytes(4, "big") + b"d" * 28
    )
    durable = response_observation_proof(
        provenance_digest,
        now=valid_captured_at,
        receipt_version="v2",
        response_nonce=durable_nonce,
        observation_nonce=durable_observation_nonce,
    )
    durable_summary = verify_observation_proxy_fixture(
        tmp,
        durable,
        expected_release_digest=provenance_digest,
        expected_client_request_digest=OBSERVATION_CLIENT_REQUEST_DIGEST,
        expected_client_nonce=durable_observation_nonce,
    )
    durable_receipt_summary = durable_summary.get(
        "control_plane_authorization_receipt"
    ) or {}
    if (
        durable_receipt_summary.get("dispatch_request_api_version")
        != verify_release_completion.RELEASE_AUTHORIZATION_DISPATCH_V2
        or durable_receipt_summary.get("dispatch_response_api_version")
        != verify_release_completion.RELEASE_AUTHORIZATION_RESPONSE_V2
        or durable_receipt_summary.get("durable_policy_verified") is not True
        or (
            durable["runtime_proof"]["server_statement"]["authorization"][
                "control_plane_authorization_receipt"
            ]["request"]["nonce"]
            != durable_nonce
        )
    ):
        raise AssertionError(
            "observation proof omitted its v2 durable dispatch receipt bindings: "
            f"{durable_summary}"
        )

    credentialless = credentialless_response_observation_proof(
        provenance_digest,
        now=valid_captured_at,
        observation_nonce=valid_nonce,
    )
    try:
        verify_observation_proxy_fixture(
            tmp,
            credentialless,
            expected_release_digest=provenance_digest,
            expected_client_request_digest=OBSERVATION_CLIENT_REQUEST_DIGEST,
            expected_client_nonce=valid_nonce,
        )
    except ValueError as exc:
        if "credentialed signed route" not in str(exc) and "atomic credential" not in str(exc):
            raise AssertionError(
                f"credentialless route bypass failed ambiguously: {exc}"
            ) from exc
    else:
        raise AssertionError(
            "observation verifier accepted credentialless evidence for a credentialed route"
        )

    def rejected(
        document: dict[str, Any],
        expected_error: str,
        description: str,
        *,
        contract: str = "observation-v1",
        client_digest: str = OBSERVATION_CLIENT_REQUEST_DIGEST,
        expected_nonce: str = valid_nonce,
        body: bytes = OBSERVATION_RESPONSE_BODY,
    ) -> None:
        try:
            verify_observation_proxy_fixture(
                tmp,
                document,
                expected_release_digest=provenance_digest,
                proof_contract=contract,
                expected_client_request_digest=client_digest,
                expected_client_nonce=expected_nonce,
                observation_body=body,
            )
        except ValueError as exc:
            if expected_error not in str(exc):
                raise AssertionError(
                    f"{description} failed for the wrong reason: {exc}"
                ) from exc
            return
        raise AssertionError(f"observation verifier accepted {description}")

    completed_durable_observation = clone_document(durable)
    completed_durable_receipt = clone_document(
        completed_durable_observation["runtime_proof"]["server_statement"][
            "authorization"
        ]["control_plane_authorization_receipt"]
    )
    completed_durable_body = json.loads(
        b64d(completed_durable_receipt["response"]["body_b64"]).decode("utf-8")
    )
    completed_durable_body["durablePolicy"]["responseEvidenceDigest"] = digest("e")
    replace_control_plane_receipt_response_body(
        completed_durable_receipt,
        completed_durable_body,
    )
    replace_observation_control_plane_receipt(
        completed_durable_observation,
        completed_durable_receipt,
    )
    rejected(
        completed_durable_observation,
        "control-plane authorization receipt durable policy lifecycle mismatch",
        "non-null completion evidence in a dispatched observation receipt",
    )

    rejected(
        valid,
        "wrong apiVersion",
        "observation proof under buffered-v3",
        contract="buffered-v3",
        client_digest=valid["request"]["aggregate_digest"],
    )
    buffered = proxy_response_proof(provenance_digest)
    rejected(
        buffered,
        "fields do not match the contract",
        "buffered proof under observation-v1",
        client_digest=PROXY_CLIENT_REQUEST_DIGEST,
    )
    rejected(
        valid,
        "body digest",
        "same-length substituted observation body",
        body=b"{" + b"x" * (len(OBSERVATION_RESPONSE_BODY) - 2) + b"}",
    )
    malformed_nonce = clone_document(valid)
    malformed_statement = malformed_nonce["runtime_proof"]["server_statement"]
    malformed_statement["client_nonce"] = b64e(
        (malformed_nonce["captured_at_unix"] + 300).to_bytes(4, "big")
        + b"\0" * 28
    )
    malformed_statement["observation_id"] = sha256_prefixed_json(
        {
            "client_nonce": malformed_statement["client_nonce"],
            "contract": "serverware.responseObservationStatement/v1",
        }
    )
    resign_observation_proof(malformed_nonce)
    rejected(
        malformed_nonce,
        "random bytes must not be all zero",
        "structured nonce without random entropy",
        expected_nonce=malformed_statement["client_nonce"],
    )

    for field, replacement in (
        ("target_digest", digest("e")),
        ("headers_digest", digest("d")),
        ("header_count", 3),
        ("body_digest", digest("c")),
        ("body_bytes", 99),
    ):
        mutated = clone_document(valid)
        mutated["request"][field] = replacement
        sign_observation_collector(mutated)
        rejected(
            mutated,
            "collector request aggregate digest mismatch",
            f"collector request {field} mutation",
            client_digest=valid["request"]["aggregate_digest"],
        )

    for field, replacement in (
        ("headers_digest", digest("c")),
        ("header_count", 5),
        ("body_digest", digest("b")),
        ("body_bytes", 101),
    ):
        mutated = clone_document(valid)
        mutated["response"][field] = replacement
        sign_observation_collector(mutated)
        rejected(
            mutated,
            "collector response aggregate digest mismatch",
            f"collector response {field} mutation",
        )

    upstream_mutation = clone_document(valid)
    upstream_mutation["runtime_proof"]["server_statement"]["upstream_observation"]["status"] = 200
    resign_observation_proof(upstream_mutation)
    rejected(
        upstream_mutation,
        "upstream observation aggregate digest mismatch",
        "re-signed upstream status mutation",
    )

    state_mutation = clone_document(valid)
    state_statement = state_mutation["runtime_proof"]["server_statement"]
    state_statement["upstream_attempt"] = "headers-observed-body-incomplete"
    resign_observation_proof(state_mutation)
    rejected(
        state_mutation,
        "requires a complete upstream response observation",
        "re-signed upstream state mutation",
    )

    for forbidden_state in ("denied", "reserved"):
        forbidden = clone_document(credentialless)
        forbidden["runtime_proof"]["server_statement"]["authorization"]["state"] = (
            forbidden_state
        )
        resign_observation_proof(forbidden)
        rejected(
            forbidden,
            "credentialed signed route",
            f"credentialless post-dispatch {forbidden_state} authorization",
        )
    missing_atomic_evidence = clone_document(credentialless)
    missing_atomic_evidence["runtime_proof"]["server_statement"]["authorization"][
        "state"
    ] = "dispatching"
    resign_observation_proof(missing_atomic_evidence)
    rejected(
        missing_atomic_evidence,
        "credentialed signed route",
        "dispatching authorization without full atomic evidence",
    )
    injected_without_authority = clone_document(valid)
    injected_statement = injected_without_authority["runtime_proof"]["server_statement"]
    injected_statement["authorization"] = clone_document(
        credentialless["runtime_proof"]["server_statement"]["authorization"]
    )
    resign_observation_proof(injected_without_authority)
    rejected(
        injected_without_authority,
        "requires atomic",
        "injected credential without atomic authorization evidence",
    )

    missing_terminal = clone_document(valid)
    missing_terminal["runtime_proof"] = None
    sign_observation_collector(missing_terminal)
    rejected(
        missing_terminal,
        "terminal proof evidence is required",
        "capture without terminal runtime proof",
    )
    missing_collector = clone_document(valid)
    missing_collector.pop("collector")
    rejected(
        missing_collector,
        "fields do not match the contract",
        "capture without strict collector evidence",
    )
    bad_capture_digest = clone_document(valid)
    bad_capture_digest["collector"]["capture_digest"] = digest("0")
    rejected(
        bad_capture_digest,
        "collector capture digest mismatch",
        "collector capture digest substitution",
    )
    unknown_top = clone_document(valid)
    unknown_top["terminal_proof"] = True
    rejected(unknown_top, "fields do not match the contract", "unknown top-level field")
    unknown_nested = clone_document(valid)
    unknown_nested["runtime_proof"]["server_statement"]["request"]["raw_body"] = "secret"
    sign_observation_collector(unknown_nested)
    rejected(
        unknown_nested,
        "fields do not match the contract",
        "unknown nested statement field",
    )


def test_route_authorization_evidence_contract() -> None:
    route = SimpleNamespace(
        credential_ref="credential:tweet",
        jit={"required": True},
        constraints=(
            {
                "id": "tweet-daily",
                "type": "rateLimit",
                "store": "shared",
                "phase": "request",
                "max": 1,
                "calendarWindow": "utcDay",
            },
        ),
    )
    authority = {
        "credential_ref": "credential:tweet",
        "grant_id": "grant:tweet",
        "approval_id": "approval:tweet",
    }
    receipt = {
        "quotas": [
            {
                "constraintId": "tweet-daily",
                "max": 1,
                "windowKind": "utcDay",
                "calendarWindow": "utcDay",
            }
        ]
    }
    verify_release_completion.verify_route_authorization_evidence(
        route,
        authority,
        receipt,
        label="route authorization fixture",
    )
    for description, mutated_authority, mutated_receipt, expected in (
        (
            "credential substitution",
            {**authority, "credential_ref": "credential:other"},
            receipt,
            "credential",
        ),
        (
            "missing JIT approval",
            {**authority, "grant_id": None, "approval_id": None},
            receipt,
            "JIT",
        ),
        (
            "quota limit substitution",
            authority,
            {"quotas": [{**receipt["quotas"][0], "max": 2}]},
            "maximum",
        ),
        (
            "missing quota",
            authority,
            {"quotas": []},
            "quota count",
        ),
    ):
        try:
            verify_release_completion.verify_route_authorization_evidence(
                route,
                mutated_authority,
                mutated_receipt,
                label="route authorization fixture",
            )
        except ValueError as exc:
            if expected not in str(exc):
                raise AssertionError(
                    f"{description} failed ambiguously: {exc}"
                ) from exc
        else:
            raise AssertionError(f"route authorization accepted {description}")


def test_streaming_proxy_response_proof_requirements(
    tmp: Path,
    provenance_digest: str,
) -> None:
    valid_document, body = streaming_response_proof(provenance_digest)
    summary = verify_streaming_proxy_fixture(
        tmp,
        valid_document,
        body,
        expected_release_digest=provenance_digest,
    )
    if (
        summary.get("proof_contract") != "streaming-v1"
        or summary.get("emitted_body_digest") != sha256_prefixed_bytes(body)
        or summary.get("emitted_body_bytes") != len(body)
        or summary.get("released_body_artifact_bound") is not True
        or summary.get("compiled_route_authority_verified") is not True
    ):
        raise AssertionError(f"streaming completion summary is incomplete: {summary}")

    def reject_streaming(label: str, document: dict[str, Any], candidate_body: bytes, expected: str) -> None:
        try:
            verify_streaming_proxy_fixture(
                tmp,
                document,
                candidate_body,
                expected_release_digest=provenance_digest,
            )
        except ValueError as exc:
            if expected not in str(exc):
                raise AssertionError(f"streaming rejection for {label} was imprecise: {exc}") from exc
        else:
            raise AssertionError(f"streaming verifier accepted {label}")

    stale_classification = clone_document(valid_document)
    stale_classification["external_capture"]["classification"] = (
        "verified-complete-stream"
    )
    sign_proxy_external_capture(stale_classification)
    reject_streaming(
        "stale stream classification",
        stale_classification,
        body,
        "strict production stream evidence",
    )

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
        verify_streaming_proxy_fixture(
            tmp,
            valid_document,
            body,
            expected_release_digest=provenance_digest,
            proof_contract="buffered-v3",
        )
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


def test_observation_release_completion_cli(
    tmp: Path,
    nitro: dict[str, Any],
    provenance_digest: str,
    buffered_document: dict[str, Any],
) -> None:
    observation = response_observation_proof(provenance_digest)
    client_digest = observation["request"]["aggregate_digest"]
    observation_nonce = observation["runtime_proof"]["server_statement"]["client_nonce"]
    observation_body_path = tmp / "proxy-observation-response-body.bin"
    observation_body_path.write_bytes(OBSERVATION_RESPONSE_BODY)
    observation_body_limit = len(OBSERVATION_RESPONSE_BODY)
    write(tmp / "proxy-response-proof.json", observation)
    write_production_env_files(
        tmp,
        proxy_proof_contract="observation-v1",
        proxy_client_request_digest=client_digest,
        proxy_observation_body=observation_body_path,
        proxy_max_observation_body_bytes=observation_body_limit,
    )
    write_production_config_files(tmp)
    write(tmp / "production-readiness.json", production_readiness(nitro, tmp))
    write(tmp / "production-host-preflight.json", production_host_preflight(tmp))
    accepted = run_verifier(
        tmp,
        proxy_proof_contract="observation-v1",
        proxy_client_request_digest=client_digest,
        proxy_client_nonce=observation_nonce,
        proxy_observation_body=observation_body_path,
        proxy_max_observation_body_bytes=observation_body_limit,
    )
    if accepted.returncode != 0:
        raise AssertionError(
            f"release completion rejected a valid pinned observation proof: {detail(accepted)}"
        )
    completion = json.loads(accepted.stdout.decode("utf-8"))
    proxy_summary = completion.get("production_proxy_response_proof") or {}
    if (
        proxy_summary.get("proof_contract") != "observation-v1"
        or proxy_summary.get("terminal_runtime_proof_bound") is not True
        or proxy_summary.get("strict_collector_capture_bound") is not True
        or proxy_summary.get("credentialless_dispatch_bound") is not False
        or proxy_summary.get("release_authority_bound") is not True
        or proxy_summary.get("embedded_control_plane_authorization_receipt_bound")
        is not True
        or completion.get("production_env_binding", {}).get("proxy_proof_contract")
        != "observation-v1"
        or completion.get("production_env_binding", {}).get(
            "proxy_observation_body"
        )
        != str(observation_body_path)
        or completion.get("production_env_binding", {}).get(
            "proxy_max_observation_body_bytes"
        )
        != observation_body_limit
        or proxy_summary.get("observed_body_artifact")
        != {
            "path": str(observation_body_path),
            "sha256": sha256_file(observation_body_path),
            "bytes": len(OBSERVATION_RESPONSE_BODY),
            "max_bytes": observation_body_limit,
        }
        or proxy_summary.get("observed_body_artifact_bound") is not True
    ):
        raise AssertionError(
            f"release completion omitted observation proof/env bindings: {completion}"
        )
    downgraded = run_verifier(tmp)
    if downgraded.returncode == 0 or "proxy proof contract" not in detail(downgraded):
        raise AssertionError(
            "release completion accepted a buffered-v3 CLI downgrade against an observation-v1 env: "
            + detail(downgraded)
        )

    fresh_observation = response_observation_proof(provenance_digest)
    fresh_client_digest = fresh_observation["request"]["aggregate_digest"]
    fresh_observation_nonce = fresh_observation["runtime_proof"]["server_statement"][
        "client_nonce"
    ]
    if fresh_client_digest != client_digest:
        raise AssertionError(
            "fresh observation proof changed the pinned client request digest"
        )
    write(tmp / "proxy-response-proof.json", fresh_observation)
    observation_body_path.write_bytes(b"{" + b"x" * (len(OBSERVATION_RESPONSE_BODY) - 2) + b"}")
    mutated_body = run_verifier(
        tmp,
        proxy_proof_contract="observation-v1",
        proxy_client_request_digest=client_digest,
        proxy_client_nonce=fresh_observation_nonce,
        proxy_observation_body=observation_body_path,
        proxy_max_observation_body_bytes=observation_body_limit,
    )
    if mutated_body.returncode == 0 or "body digest" not in detail(mutated_body):
        raise AssertionError(
            "release completion accepted a same-length substituted observation body: "
            + detail(mutated_body)
        )
    observation_body_path.write_bytes(OBSERVATION_RESPONSE_BODY + b"!")
    oversized_body = run_verifier(
        tmp,
        proxy_proof_contract="observation-v1",
        proxy_client_request_digest=client_digest,
        proxy_client_nonce=fresh_observation_nonce,
        proxy_observation_body=observation_body_path,
        proxy_max_observation_body_bytes=observation_body_limit,
    )
    if oversized_body.returncode == 0 or "exceeds" not in detail(oversized_body):
        raise AssertionError(
            "release completion accepted an observation body above the configured bound: "
            + detail(oversized_body)
        )
    observation_body_path.unlink()
    missing_body = run_verifier(
        tmp,
        proxy_proof_contract="observation-v1",
        proxy_client_request_digest=client_digest,
        proxy_client_nonce=fresh_observation_nonce,
        proxy_observation_body=observation_body_path,
        proxy_max_observation_body_bytes=observation_body_limit,
    )
    if missing_body.returncode == 0 or "could not be opened" not in detail(
        missing_body
    ):
        raise AssertionError(
            "release completion accepted a missing observation body snapshot: "
            + detail(missing_body)
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

    valid_nonce = b64e(b"v" * 32)
    valid_document = proxy_response_proof(
        provenance_digest,
        receipt_version="v1",
        response_nonce=valid_nonce,
    )
    valid_receipt = clone_document(
        valid_document["server_statement"]["control_plane_authorization_receipt"]
    )
    write(tmp / "proxy-response-proof.json", valid_document)
    valid_result = run_verifier(tmp)
    valid_summary = (
        json.loads(valid_result.stdout.decode("utf-8"))
        if valid_result.returncode == 0
        else {}
    )
    valid_proxy_summary = valid_summary.get("production_proxy_response_proof") or {}
    valid_receipt_summary = valid_proxy_summary.get(
        "control_plane_authorization_receipt"
    ) or {}
    if (
        valid_result.returncode != 0
        or valid_receipt_summary.get("dispatch_request_api_version")
        != verify_release_completion.RELEASE_AUTHORIZATION_DISPATCH_V1
        or valid_receipt_summary.get("dispatch_response_api_version")
        != verify_release_completion.RELEASE_AUTHORIZATION_RESPONSE_V1
        or valid_receipt_summary.get("durable_policy_verified") is not False
        or valid_receipt["request"]["nonce"] != valid_nonce
    ):
        raise AssertionError(
            "completion verifier rejected a valid v1 dispatch receipt: "
            + detail(valid_result)
        )

    control_plane_key = control_plane_response_signing_key_info()
    public_receipt_verification_args = {
        "trusted_public_key_pem": control_plane_key["public_key_pem"],
        "expected_trusted_public_key_id": control_plane_key["key_id"],
        "expected_release_authority": valid_document["server_statement"][
            "release_authority"
        ],
        "expected_principal_id": valid_document["server_statement"][
            "principal_id"
        ],
        "expected_route_id": valid_document["server_statement"]["route_id"],
        "expected_runtime_manifest_digest": valid_document[
            "server_statement"
        ]["runtime_manifest_digest"],
        "expected_policy_digest": POLICY_DIGEST,
        "expected_provenance_digest": provenance_digest,
        "expected_image_signatures_digest": IMAGE_SIGNATURES_DIGEST,
        "expected_source_tree_digest": SOURCE_TREE_DIGEST,
    }
    try:
        verify_release_completion.verify_control_plane_authorization_receipt(
            valid_receipt,
            **public_receipt_verification_args,
        )
    except ValueError as exc:
        if "requires an authenticated custody authorization binding" not in str(
            exc
        ):
            raise
    else:
        raise AssertionError(
            "public receipt verification accepted a receipt without an exact "
            "authorization binding or authenticated custody statement"
        )
    if any(
        hasattr(verify_release_completion, name)
        for name in (
            "_VerifiedCustodyAuthorizationBinding",
            "_VERIFIED_CUSTODY_BINDING_TOKEN",
        )
    ):
        raise AssertionError(
            "completion verifier still exposes caller-forgeable custody capability state"
        )
    custody_envelope = {
        "statement": clone_document(valid_document["server_statement"]),
        "statement_sha256": sha256_prefixed_json(
            valid_document["server_statement"]
        ),
        "signature": clone_document(valid_document["server_signature"]),
    }
    custody_verified = (
        verify_release_completion.verify_control_plane_authorization_receipt(
            valid_receipt,
            **public_receipt_verification_args,
            custody_authorization_envelope=custody_envelope,
            expected_custody_signing_key_id=proxy_response_key_info()["key_id"],
        )
    )
    if (
        custody_verified.get("custody_authorization_envelope_verified")
        is not True
        or custody_verified.get("custody_authorization_signing_key_id")
        != proxy_response_key_info()["key_id"]
    ):
        raise AssertionError(
            "public receipt verification omitted its internally verified custody envelope"
        )
    forged_custody = clone_document(custody_envelope)
    forged_custody["signature"]["signature"] = "ed25519:" + b64e(b"x" * 64)
    try:
        verify_release_completion.verify_control_plane_authorization_receipt(
            valid_receipt,
            **public_receipt_verification_args,
            custody_authorization_envelope=forged_custody,
            expected_custody_signing_key_id=proxy_response_key_info()["key_id"],
        )
    except ValueError as exc:
        if "custody authorization envelope statement signature verification failed" not in str(
            exc
        ):
            raise
    else:
        raise AssertionError(
            "public receipt verification accepted a forged raw custody envelope"
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
        rejected_quota = run_verifier(tmp)
        if (
            rejected_quota.returncode == 0
            or "control-plane receipt quota count does not match the signed route"
            not in detail(rejected_quota)
        ):
            raise AssertionError(
                f"completion verifier accepted a {quota_label} quota not present "
                "in the compiled route: "
                + detail(rejected_quota)
            )

    durable_nonce = b64e(b"d" * 32)
    durable_document = proxy_response_proof(
        provenance_digest,
        receipt_version="v2",
        response_nonce=durable_nonce,
    )
    durable_receipt = clone_document(
        durable_document["server_statement"][
            "control_plane_authorization_receipt"
        ]
    )
    write(tmp / "proxy-response-proof.json", durable_document)
    durable_result = run_verifier(tmp)
    durable_summary = (
        json.loads(durable_result.stdout.decode("utf-8"))
        if durable_result.returncode == 0
        else {}
    )
    durable_proxy_summary = (
        durable_summary.get("production_proxy_response_proof") or {}
    )
    durable_receipt_summary = durable_proxy_summary.get(
        "control_plane_authorization_receipt"
    ) or {}
    durable_response_body = json.loads(
        b64d(durable_receipt["response"]["body_b64"]).decode("utf-8")
    )
    if (
        durable_result.returncode != 0
        or durable_receipt_summary.get("dispatch_request_api_version")
        != verify_release_completion.RELEASE_AUTHORIZATION_DISPATCH_V2
        or durable_receipt_summary.get("dispatch_response_api_version")
        != verify_release_completion.RELEASE_AUTHORIZATION_RESPONSE_V2
        or durable_receipt_summary.get("durable_policy_verified") is not True
        or durable_receipt["request"]["nonce"] != durable_nonce
        or durable_response_body.get("quotas") != []
        or durable_response_body.get("store")
        != {"backend": "postgres", "ha": True}
    ):
        raise AssertionError(
            "completion verifier rejected a valid v2 durable dispatch receipt: "
            + detail(durable_result)
        )

    same_attempt_replay_receipt = clone_document(durable_receipt)
    same_attempt_replay_body = clone_document(durable_response_body)
    same_attempt_replay_body["idempotentReplay"] = True
    replace_control_plane_receipt_response_body(
        same_attempt_replay_receipt,
        same_attempt_replay_body,
    )
    same_attempt_replay_proof = clone_document(durable_document)
    replace_embedded_control_plane_receipt(
        same_attempt_replay_proof,
        same_attempt_replay_receipt,
    )
    write(tmp / "proxy-response-proof.json", same_attempt_replay_proof)
    same_attempt_replay_result = run_verifier(tmp)
    same_attempt_replay_summary = (
        json.loads(same_attempt_replay_result.stdout.decode("utf-8"))
        if same_attempt_replay_result.returncode == 0
        else {}
    )
    if (
        same_attempt_replay_result.returncode != 0
        or (
            same_attempt_replay_summary.get("production_proxy_response_proof")
            or {}
        )
        .get("control_plane_authorization_receipt", {})
        .get("idempotent_replay")
        is not True
    ):
        raise AssertionError(
            "completion verifier rejected an exact same-attempt idempotent "
            "dispatch replay: "
            + detail(same_attempt_replay_result)
        )

    replay_with_completed_lifecycle = clone_document(
        same_attempt_replay_receipt
    )
    replay_with_completed_body = clone_document(same_attempt_replay_body)
    replay_with_completed_body["durablePolicy"]["state"] = "completed"
    replace_control_plane_receipt_response_body(
        replay_with_completed_lifecycle,
        replay_with_completed_body,
    )
    replay_with_completed_proof = clone_document(durable_document)
    replace_embedded_control_plane_receipt(
        replay_with_completed_proof,
        replay_with_completed_lifecycle,
    )
    expect_proxy_proof_failure(
        tmp,
        replay_with_completed_proof,
        "control-plane authorization receipt durable policy lifecycle mismatch",
        "an idempotentReplay=true receipt with a completed lifecycle",
    )

    cross_attempt_document = proxy_response_proof(
        provenance_digest,
        receipt_version="v2",
        response_nonce=b64e(b"r" * 32),
        attempt_id=digest("b"),
    )
    cross_attempt_receipt = clone_document(
        cross_attempt_document["server_statement"][
            "control_plane_authorization_receipt"
        ]
    )
    cross_attempt_replay = clone_document(durable_document)
    replace_embedded_control_plane_receipt(
        cross_attempt_replay,
        cross_attempt_receipt,
    )
    expect_proxy_proof_failure(
        tmp,
        cross_attempt_replay,
        "control-plane authorization receipt release authority mismatch",
        "a control-plane dispatch receipt replayed across attempts",
    )

    calendar_candidates = [
        (
            window_kind,
            *verify_release_completion.streaming_calendar_window_bounds(
                window_kind,
                int(time.time()) * 1000,
            ),
        )
        for window_kind in ("utcDay", "utcIsoWeek", "utcMonth")
    ]
    (
        calendar_window_kind,
        calendar_window_start,
        calendar_window_end,
    ) = max(calendar_candidates, key=lambda candidate: candidate[2])
    calendar_captured_at = min(
        int(time.time()),
        calendar_window_end // 1000 - 300,
    )
    calendar_shared_quota = {
        "counter_key": digest("4"),
        "constraint_id": "quota:calendar",
        "operation": "demo.echo",
        "window_kind": calendar_window_kind,
        "max_count": 3,
    }
    calendar_dispatch_quota = {
        "counterKey": calendar_shared_quota["counter_key"],
        "constraintId": calendar_shared_quota["constraint_id"],
        "operation": calendar_shared_quota["operation"],
        "windowKind": calendar_window_kind,
        "windowStartEpochMs": calendar_window_start,
        "windowEndEpochMs": calendar_window_end,
        "calendarWindow": calendar_window_kind,
        "max": calendar_shared_quota["max_count"],
        "count": 1,
        "remaining": 2,
        "reservationState": "reserved",
    }
    calendar_document = proxy_response_proof(
        provenance_digest,
        now=calendar_captured_at,
        shared_quotas=[calendar_shared_quota],
        dispatch_quotas=[calendar_dispatch_quota],
        receipt_version="v2",
        response_nonce=b64e(b"k" * 32),
    )
    write(tmp / "proxy-response-proof.json", calendar_document)
    calendar_result = run_verifier(tmp)
    if (
        calendar_result.returncode == 0
        or "control-plane receipt quota count does not match the signed route"
        not in detail(calendar_result)
    ):
        raise AssertionError(
            "completion verifier accepted a calendar quota not present in the "
            "compiled route: "
            + detail(calendar_result)
        )
    invalid_calendar_receipt = clone_document(
        calendar_document["server_statement"][
            "control_plane_authorization_receipt"
        ]
    )
    invalid_calendar_body = json.loads(
        b64d(invalid_calendar_receipt["response"]["body_b64"]).decode("utf-8")
    )
    invalid_calendar_body["quotas"][0]["windowEndEpochMs"] += 1000
    replace_control_plane_receipt_response_body(
        invalid_calendar_receipt,
        invalid_calendar_body,
    )
    invalid_calendar_proof = clone_document(calendar_document)
    replace_embedded_control_plane_receipt(
        invalid_calendar_proof,
        invalid_calendar_receipt,
    )
    expect_proxy_proof_failure(
        tmp,
        invalid_calendar_proof,
        "calendar boundaries are not exact",
        "a v2 calendar quota receipt with a substituted window end",
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
    secret_header_receipt = clone_document(valid_receipt)
    secret_headers = [
        {
            "name": "set-cookie",
            "value_b64": b64e(b"session=secret"),
        }
    ]
    replace_control_plane_receipt_response_headers(
        secret_header_receipt,
        secret_headers,
    )
    secret_header_proof = clone_document(valid_document)
    replace_embedded_control_plane_receipt(
        secret_header_proof,
        secret_header_receipt,
    )
    expect_proxy_proof_failure(
        tmp,
        secret_header_proof,
        "control-plane authorization receipt response header 0 name is invalid",
        "a re-signed dispatch receipt carrying a secret-bearing response header",
    )

    def expect_durable_receipt_failure(
        receipt: dict[str, Any],
        expected_error: str,
        description: str,
    ) -> None:
        proof = clone_document(durable_document)
        replace_embedded_control_plane_receipt(proof, receipt)
        expect_proxy_proof_failure(tmp, proof, expected_error, description)

    v2_request_v1_response = clone_document(durable_receipt)
    v1_response_body = clone_document(durable_response_body)
    v1_response_body["apiVersion"] = (
        verify_release_completion.RELEASE_AUTHORIZATION_RESPONSE_V1
    )
    v1_response_body.pop("durablePolicy")
    replace_control_plane_receipt_response_body(
        v2_request_v1_response,
        v1_response_body,
    )
    expect_durable_receipt_failure(
        v2_request_v1_response,
        "control-plane authorization receipt response body fields do not match the contract",
        "a v2 dispatch request paired with a v1 response shape",
    )

    v1_request_v2_response = clone_document(durable_receipt)
    v1_request_body = json.loads(
        b64d(v1_request_v2_response["request"]["body_b64"]).decode("utf-8")
    )
    v1_request_body["apiVersion"] = (
        verify_release_completion.RELEASE_AUTHORIZATION_DISPATCH_V1
    )
    v1_request_body.pop("durablePolicy")
    replace_control_plane_receipt_request_body(
        v1_request_v2_response,
        v1_request_body,
    )
    expect_durable_receipt_failure(
        v1_request_v2_response,
        "control-plane authorization receipt response body fields do not match the contract",
        "a v1 dispatch request paired with a v2 response shape",
    )

    missing_durable_field = clone_document(durable_receipt)
    missing_durable_body = clone_document(durable_response_body)
    missing_durable_body["durablePolicy"].pop("uncertainty")
    replace_control_plane_receipt_response_body(
        missing_durable_field,
        missing_durable_body,
    )
    expect_durable_receipt_failure(
        missing_durable_field,
        "control-plane authorization receipt response durable policy fields do not match the contract",
        "a v2 dispatch response missing a durable lifecycle field",
    )

    durable_request_body = json.loads(
        b64d(durable_receipt["request"]["body_b64"]).decode("utf-8")
    )
    for field, substituted, expected_error, description in (
        (
            "actorId",
            "spiffe://prod.serverware.dev/decision-gate/substituted",
            "control-plane authorization receipt request durable policy binding mismatch",
            "durable request actor substitution",
        ),
        (
            "attemptId",
            digest("1"),
            "control-plane authorization receipt request durable policy binding mismatch",
            "durable request attempt substitution",
        ),
        (
            "claimDigest",
            digest("2"),
            "control-plane authorization receipt request durable policy binding mismatch",
            "durable request claim substitution",
        ),
        (
            "reservationId",
            "reservation:fixture:substituted",
            "control-plane authorization receipt durable policy lifecycle mismatch",
            "durable request reservation substitution",
        ),
        (
            "dispatchDeadlineAtEpochMs",
            durable_response_body["dispatchExpiresAtEpochMs"] - 1,
            "control-plane authorization receipt request durable policy binding mismatch",
            "durable request dispatch deadline substitution",
        ),
    ):
        substituted_receipt = clone_document(durable_receipt)
        substituted_body = clone_document(durable_request_body)
        substituted_body["durablePolicy"][field] = substituted
        replace_control_plane_receipt_request_body(
            substituted_receipt,
            substituted_body,
        )
        expect_durable_receipt_failure(
            substituted_receipt,
            expected_error,
            description,
        )

    missing_request_field = clone_document(durable_receipt)
    missing_request_body = clone_document(durable_request_body)
    missing_request_body["durablePolicy"].pop("reservationId")
    replace_control_plane_receipt_request_body(
        missing_request_field,
        missing_request_body,
    )
    expect_durable_receipt_failure(
        missing_request_field,
        "control-plane authorization receipt request durable policy fields do not match the contract",
        "a v2 dispatch request missing its reservation ID",
    )

    for completion_value, description in (
        (None, "a v2 dispatch request with a null completion-only field"),
        (digest("3"), "a v2 dispatch request with completion evidence"),
    ):
        completion_request_field = clone_document(durable_receipt)
        completion_request_body = clone_document(durable_request_body)
        completion_request_body["durablePolicy"][
            "responseEvidenceDigest"
        ] = completion_value
        replace_control_plane_receipt_request_body(
            completion_request_field,
            completion_request_body,
        )
        expect_durable_receipt_failure(
            completion_request_field,
            "control-plane authorization receipt request durable policy fields do not match the contract",
            description,
        )

    for field, substituted, description in (
        (
            "actorId",
            "spiffe://prod.serverware.dev/decision-gate/substituted",
            "durable actor substitution",
        ),
        ("claimDigest", digest("0"), "durable claim substitution"),
        (
            "reservationId",
            "reservation:fixture:substituted",
            "durable reservation substitution",
        ),
        (
            "dispatchDeadlineAtEpochMs",
            durable_response_body["dispatchExpiresAtEpochMs"] - 1,
            "durable dispatch deadline substitution",
        ),
    ):
        substituted_receipt = clone_document(durable_receipt)
        substituted_body = clone_document(durable_response_body)
        substituted_body["durablePolicy"][field] = substituted
        replace_control_plane_receipt_response_body(
            substituted_receipt,
            substituted_body,
        )
        expect_durable_receipt_failure(
            substituted_receipt,
            "control-plane authorization receipt durable policy lifecycle mismatch",
            description,
        )

    invalid_store_receipt = clone_document(durable_receipt)
    invalid_store_body = clone_document(durable_response_body)
    invalid_store_body["store"]["ha"] = False
    replace_control_plane_receipt_response_body(
        invalid_store_receipt,
        invalid_store_body,
    )
    expect_durable_receipt_failure(
        invalid_store_receipt,
        "does not prove an HA authorization store",
        "a v2 dispatch response carrying non-HA store evidence",
    )

    canonical_nonce = b64e(b"n" * 32)
    base64url_alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    final_nonce_index = base64url_alphabet.index(canonical_nonce[-1])
    alias_nonce_index = (
        final_nonce_index + 1
        if final_nonce_index % 4 != 3
        else final_nonce_index - 1
    )
    noncanonical_nonce = (
        canonical_nonce[:-1] + base64url_alphabet[alias_nonce_index]
    )
    for nonce_label, nonce, expected_error in (
        (
            "short",
            b64e(b"n" * 31),
            "control-plane authorization receipt request nonce must contain at least 32 bytes",
        ),
        (
            "padded",
            canonical_nonce + "=",
            "control-plane authorization receipt request nonce must be unpadded base64url",
        ),
        (
            "noncanonical",
            noncanonical_nonce,
            "control-plane authorization receipt request nonce is not canonical base64url",
        ),
        (
            "overlong",
            b64e(b"n" * 33),
            "control-plane authorization receipt request nonce must contain exactly 32 bytes",
        ),
    ):
        invalid_nonce_receipt = clone_document(durable_receipt)
        replace_control_plane_receipt_nonce(invalid_nonce_receipt, nonce)
        expect_durable_receipt_failure(
            invalid_nonce_receipt,
            expected_error,
            f"a signed v2 dispatch receipt with a {nonce_label} response nonce",
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
    cross_wired_authority["server_statement"]["release_authority"][
        "approval_id"
    ] = "approval:other"
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
        authority["approval_id"] = "approval:substituted"
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
    inconsistent_grant["server_statement"]["release_authority"][
        "grant_id"
    ] = "grant:unexpected"
    inconsistent_grant["external_capture"]["release_authority"][
        "grant_id"
    ] = "grant:unexpected"
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
    overlong_nonce = run_verifier(
        tmp,
        "--proxy-client-nonce",
        b64e(b"x" * 33),
    )
    if (
        overlong_nonce.returncode == 0
        or "expected proxy proof client nonce must contain exactly 32 bytes"
        not in detail(overlong_nonce)
    ):
        raise AssertionError(
            "completion verifier accepted a 33-byte buffered proof nonce: "
            + detail(overlong_nonce)
        )
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
        "custody-runtime": digest("b"),
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
    test_exact_benchmark_nanosecond_contract()
    verify_launcher_three_way_binding()
    verify_launcher_nonce_manifest_v3_binding()
    verify_release_artifact_authority_contracts()
    verify_cosign_ecdsa_signature_compatibility()
    verify_ed25519_signature_canonicalization()
    test_route_authorization_evidence_contract()
    test_final_file_snapshots()
    test_final_mode_observation_signing_key_dereference()
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
        test_response_observation_proof_requirements(
            tmp,
            provenance_summary["provenance_digest"],
        )
        test_observation_release_completion_cli(
            tmp,
            nitro,
            provenance_summary["provenance_digest"],
            valid_proxy_response_proof,
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
        persisted_bytes = out_path.read_bytes()
        persisted_proof = json.loads(persisted_bytes.decode("utf-8"))
        if (
            persisted_bytes
            != canonical_json(persisted_proof).encode("utf-8") + b"\n"
        ):
            raise AssertionError(
                "readiness writer did not persist canonical JSON plus LF"
            )
        host_context = (
            verify_release_completion._load_host_readiness_context(
                str(out_path)
            )
        )
        if (
            host_context["completionProofFileSha256"]
            != sha256_prefixed_bytes(persisted_bytes)
            or host_context["completionProofCoreSha256"]
            != persisted_proof["proof_core_sha256"]
        ):
            raise AssertionError(
                "final-v1 did not consume the exact persisted readiness bytes"
            )
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
            proof.get("verificationOk") is not True
            or proof.get("finalCompletionVerified") is not False
            or proof.get("actionAuthorization") is not None
            or proof.get("okForAction") is not False
            or "ok" in proof
            or "final_completion" in proof
            or not out_path.exists()
            or not detached_digest_path.exists()
            or "proof_sha256" in proof
            or "proof_sha256_path" in proof
            or proof != persisted_proof
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
        refresh_readiness_v6_proof_core(mutated_contract)
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
        refresh_readiness_v6_proof_core(unknown_mode_contract)
        verify_release_completion.write_output(
            unknown_mode_path,
            unknown_mode_contract,
        )
        try:
            run_production_readiness.verify_completion_output(unknown_mode_path)
        except ValueError as exc:
            if "completionProof/v6 is a readiness envelope" not in str(exc):
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
        refresh_readiness_v6_proof_core(stale_contract)
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
        completion_schema_validator.validate(persisted_proof)
        if (
            verify_release_completion
            .validate_host_readiness_completion_proof_v6(persisted_proof)
            != persisted_proof
        ):
            raise AssertionError(
                "native host-context validator changed a valid readiness proof"
            )
        core_mismatch = clone_document(persisted_proof)
        core_mismatch["generated_at_unix"] += 1
        core_mismatch_path = tmp / "readiness-core-mismatch.json"
        core_mismatch_path.write_bytes(
            canonical_json(core_mismatch).encode("utf-8") + b"\n"
        )
        try:
            verify_release_completion._load_host_readiness_context(
                str(core_mismatch_path)
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "final-v1 accepted a readiness proof with a stale core digest"
            )
        open_nested_readiness = clone_document(persisted_proof)
        open_nested_readiness["nonce_rollback_assurance"][
            "launchManifest"
        ]["unexpected"] = True
        refresh_readiness_v6_proof_core(open_nested_readiness)
        open_nested_readiness_path = (
            tmp / "readiness-open-nested-contract.json"
        )
        open_nested_readiness_path.write_bytes(
            canonical_json(open_nested_readiness).encode("utf-8") + b"\n"
        )
        try:
            verify_release_completion._load_host_readiness_context(
                str(open_nested_readiness_path)
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "final-v1 accepted a readiness proof with an open nested "
                "contract"
            )
        noncanonical_readiness_path = tmp / "readiness-pretty.json"
        noncanonical_readiness_path.write_bytes(
            (
                json.dumps(
                    persisted_proof,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=True,
                )
                + "\n"
            ).encode("utf-8")
        )
        try:
            verify_release_completion._load_host_readiness_context(
                str(noncanonical_readiness_path)
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "final-v1 accepted noncanonical persisted readiness bytes"
            )
        for label, invalid_wire in (
            (
                "missing proof_path",
                {
                    key: value
                    for key, value in persisted_proof.items()
                    if key != "proof_path"
                },
            ),
            (
                "missing integrity_metadata",
                {
                    key: value
                    for key, value in persisted_proof.items()
                    if key != "integrity_metadata"
                },
            ),
            (
                "obsolete proof_sha256 alias",
                {
                    **persisted_proof,
                    "proof_sha256": verified_output_digest,
                },
            ),
            (
                "obsolete proof_sha256_path alias",
                {
                    **persisted_proof,
                    "proof_sha256_path": str(detached_digest_path),
                },
            ),
        ):
            if not list(
                completion_schema_validator.iter_errors(invalid_wire)
            ):
                raise AssertionError(
                    f"completionProof/v6 schema accepted {label}"
                )
        action_authority_v6 = clone_document(persisted_proof)
        action_authority_v6["production_host_preflight"][
            "authority_boundary"
        ]["actionAuthority"] = True
        if not list(
            completion_schema_validator.iter_errors(action_authority_v6)
        ):
            raise AssertionError(
                "completionProof/v6 schema accepted host preflight action "
                "authority"
            )
        final_shaped_v6 = clone_document(persisted_proof)
        final_shaped_v6.update(
            {
                "kind": "ServerwareCompletionProof",
                "verification_mode": "final",
                "result_scope": "final-completion",
                "readiness_only": False,
                "finalCompletionVerified": True,
            }
        )
        if not list(
            completion_schema_validator.iter_errors(final_shaped_v6)
        ):
            raise AssertionError(
                "completionProof/v6 schema accepted a final envelope"
            )
        try:
            (
                verify_release_completion
                .validate_host_readiness_completion_proof_v6(
                    final_shaped_v6
                )
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "native host-context validator accepted a final-shaped v6"
            )
        try:
            run_production_readiness.verify_completion_output(
                out_path,
                SimpleNamespace(verification_mode="final"),
            )
        except ValueError as exc:
            if "cannot satisfy a final-mode readiness runner" not in str(exc):
                raise AssertionError(
                    f"readiness output failed for the wrong final-context reason: {exc}"
                ) from exc
        else:
            raise AssertionError(
                "readiness consumer accepted completionProof/v6 as final"
            )
        if (
            proof.get("apiVersion")
            != verify_release_completion.COMPLETION_PROOF_API_VERSION
            or proof.get("kind") != "ServerwarePreEnclaveReadiness"
            or proof.get("verificationOk") is not True
            or proof.get("finalCompletionVerified") is not False
            or proof.get("actionAuthorization") is not None
            or proof.get("okForAction") is not False
            or proof.get("verification_mode") != "readiness"
            or proof.get("result_scope") != "readiness-only"
            or proof.get("readiness_only") is not True
            or proof.get("verification_passed") is not True
            or proof.get("completion_status") != "pre-enclave-readiness"
            or proof.get("release_completion") != "not-final"
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
                "compiled_route_authority_verified",
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
            or hardware_limited_proof.get("finalCompletionVerified") is not False
            or hardware_limited_proof.get("verificationOk") is not True
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
        if (
            final_assurance.get("final_completion") is not False
            or final_assurance.get("hardware_proof") is not False
            or final_assurance.get("hardware_evidence_verified") is not True
            or final_assurance.get("level") != "pre-enclave-readiness"
        ):
            raise AssertionError(
                "legacy hardware and current-host evidence escaped the "
                f"readiness-only ceiling: {final_assurance}"
            )

        proxy_server_statement_sha256 = sha256_prefixed_json(
            valid_proxy_response_proof["server_statement"]
        )
        final_completion_identity = final_completion_identity_v3_fixture()
        final_completion_identity["challengeNonceSha256"] = (
            HARDWARE_ASSURANCE_CHALLENGE_SHA256
        )
        (
            validated_final_completion_identity,
            final_completion_identity_sha256,
        ) = verify_release_completion.validate_final_v6_completion_identity(
            final_completion_identity
        )
        if (
            validated_final_completion_identity
            != final_completion_identity
            or final_completion_identity.get("apiVersion")
            != verify_release_completion.FINAL_COMPLETION_IDENTITY_API_VERSION
            or final_completion_identity_sha256
            != sha256_prefixed_json(final_completion_identity)
        ):
            raise AssertionError(
                "final completion identity v3 did not bind its exact canonical fields"
            )
        changed_identity = clone_document(final_completion_identity)
        changed_identity["coreDigests"]["release"] = digest("0")
        _, changed_identity_sha256 = (
            verify_release_completion.validate_final_v6_completion_identity(
                changed_identity
            )
        )
        if changed_identity_sha256 == final_completion_identity_sha256:
            raise AssertionError(
                "final completion identity v3 did not bind its release core"
            )
        legacy_identity = clone_document(final_completion_identity)
        legacy_identity["apiVersion"] = "serverware.finalCompletionIdentity/v1"
        try:
            verify_release_completion.validate_final_v6_completion_identity(
                legacy_identity
            )
        except ValueError as exc:
            if "version or pipeline" not in str(exc):
                raise
        else:
            raise AssertionError(
                "final verifier accepted final completion identity v1"
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
