#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def run_readiness(env: dict[str, str]) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "scripts/verify_production_readiness.py", "--mode", "config"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
    if result.returncode != 0:
        raise AssertionError(f"production readiness unexpectedly failed: {detail}")
    parsed = json.loads(result.stdout.decode("utf-8"))
    if not isinstance(parsed, dict) or parsed.get("ok") is not True:
        raise AssertionError(f"production readiness returned invalid success: {parsed}")
    return parsed


def expect_failure(env: dict[str, str], expected: str) -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_production_readiness.py", "--mode", "config"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
    if result.returncode == 0:
        raise AssertionError(f"production readiness unexpectedly succeeded: {detail}")
    if expected not in detail:
        raise AssertionError(f"production readiness failed with wrong error, expected {expected!r}: {detail}")


def good_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "SERVERWARE_RELEASE_CHANNEL": "prod",
            "SERVERWARE_PUBLIC_URL": "https://serverware.example",
            "SERVERWARE_TEE_QUOTE_PROVIDER": "aws-nitro-enclaves",
            "SERVERWARE_TEE_PLATFORM": "aws-nitro",
            "SERVERWARE_TEE_QUOTE_COMMAND": "python scripts/aws_nitro_tee_provider.py quote",
            "SERVERWARE_TEE_QUOTE_VERIFY_COMMAND": "python scripts/aws_nitro_tee_provider.py verify",
            "SERVERWARE_KEY_RELEASE_COMMAND": "python scripts/aws_nitro_tee_provider.py release",
            "SERVERWARE_NITRO_ATTESTATION_COMMAND": "/opt/serverware/bin/nitro-nsm-attest",
            "SERVERWARE_NITRO_ROOT_CERT_PEM": "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----",
            "SERVERWARE_NITRO_EXPECTED_PCRS": canonical_json({"0": "11" * 48, "1": "22" * 48, "2": "33" * 48}),
            "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND": "1",
            "SERVERWARE_NITRO_KMS_RELEASE_COMMAND": "/opt/serverware/bin/kms-unseal --key awskms://arn:aws:kms:us-east-1:111122223333:key/serverware",
            "SERVERWARE_NITRO_ALLOWED_MATERIALS": "broker-kek,decision-gate-ca",
            "SERVERWARE_IMAGE_SIGNATURE_PROVIDER": "sigstore-command",
            "SERVERWARE_IMAGE_SIGN_COMMAND": "python3 scripts/cosign_sigstore.py sign",
            "SERVERWARE_IMAGE_VERIFY_COMMAND": "python3 scripts/cosign_sigstore.py verify",
            "SERVERWARE_COSIGN_BINARY": "cosign",
            "SERVERWARE_COSIGN_KEY": "awskms://arn:aws:kms:us-east-1:111122223333:key/serverware-signing",
            "SERVERWARE_COSIGN_KEY_ID": "sha256:" + "c" * 64,
            "SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY": "1",
            "SERVERWARE_TRANSPARENCY_CHECKPOINT_REQUIRED": "1",
            "SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND": "python3 scripts/transparency_checkpoint.py checkpoint",
            "SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE": "http",
            "SERVERWARE_TRANSPARENCY_LOG_URL": "https://transparency.example/checkpoints",
            "SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER": "managed-prod-log",
            "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID": "sha256:" + "d" * 64,
            "SERVERWARE_APPARMOR_EXPECTED_PROFILE": "serverware-docker",
        }
    )
    for name in (
        "SERVERWARE_DEV_AUTHENTICATOR",
        "SERVERWARE_NITRO_FIXTURE",
        "SERVERWARE_NITRO_ALLOW_DEBUG",
        "SERVERWARE_NITRO_ALLOW_DEBUG_RELEASE",
        "SERVERWARE_NITRO_ATTESTATION_DOCUMENT",
        "SERVERWARE_NITRO_ATTESTATION_DOCUMENT_B64",
        "SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP",
    ):
        env.pop(name, None)
    return env


def main() -> None:
    passed = run_readiness(good_env())
    if passed.get("mode") != "config":
        raise AssertionError(f"unexpected readiness mode: {passed}")

    fixture_env = good_env()
    fixture_env["SERVERWARE_NITRO_FIXTURE"] = "1"
    fixture_env["SERVERWARE_NITRO_ATTESTATION_COMMAND"] = "python scripts/nitro_attestation_fixture.py attest"
    fixture_env["SERVERWARE_NITRO_KMS_RELEASE_COMMAND"] = "python scripts/nitro_kms_fixture.py release"
    fixture_env["SERVERWARE_COSIGN_BINARY"] = "python scripts/cosign_fixture.py"
    fixture_env["SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE"] = "fixture"
    expect_failure(fixture_env, "fixture")

    missing_cosign_env = good_env()
    missing_cosign_env.pop("SERVERWARE_COSIGN_KEY", None)
    missing_cosign_env.pop("SERVERWARE_COSIGN_CERT_IDENTITY", None)
    missing_cosign_env.pop("SERVERWARE_COSIGN_CERT_OIDC_ISSUER", None)
    expect_failure(missing_cosign_env, "KMS/HSM key ref or keyless certificate identity")

    insecure_transparency_env = good_env()
    insecure_transparency_env["SERVERWARE_TRANSPARENCY_LOG_URL"] = "http://transparency.example/checkpoints"
    insecure_transparency_env["SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP"] = "1"
    expect_failure(insecure_transparency_env, "https URL")

    print(canonical_json({"ok": True, "production_readiness": "pass", "checks": passed.get("checks")}))


if __name__ == "__main__":
    main()
