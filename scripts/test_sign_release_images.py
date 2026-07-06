#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import sign_release_images as signer  # noqa: E402


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
        finally:
            for key, value in original.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


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
    print(json.dumps({"ok": True, "sign_release_images": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
