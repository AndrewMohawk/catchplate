#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
REQUIRED_MATERIALS = {"broker-kek", "decision-gate-ca"}
KMS_KEY_PREFIXES = (
    "awskms://",
    "gcpkms://",
    "azurekms://",
    "hashivault://",
    "pkcs11:",
    "kms://",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def env_bool(env: dict[str, str], name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_json_object(env: dict[str, str], name: str) -> dict[str, Any] | None:
    raw = env.get(name, "").strip()
    if not raw:
        return None
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError(f"{name} must be a JSON object")
    return parsed


def command_words(raw: str) -> list[str]:
    try:
        return shlex.split(raw)
    except ValueError:
        return []


def command_mentions(raw: str, *needles: str) -> bool:
    lowered = " ".join(command_words(raw)).lower()
    return any(needle.lower() in lowered for needle in needles)


def add(failures: list[str], condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def valid_pcr_policy(raw: str) -> bool:
    try:
        policy = json.loads(raw)
    except json.JSONDecodeError:
        return False
    if not isinstance(policy, dict) or not policy:
        return False
    for key, value in policy.items():
        try:
            int(key)
            decoded = bytes.fromhex(str(value).removeprefix("sha384:"))
        except Exception:
            return False
        if len(decoded) != 48:
            return False
    return True


def check_no_dev_or_fixture(env: dict[str, str], failures: list[str]) -> None:
    add(failures, not env_bool(env, "SERVERWARE_DEV_AUTHENTICATOR"), "SERVERWARE_DEV_AUTHENTICATOR must be disabled")
    release_channel = env.get("SERVERWARE_RELEASE_CHANNEL", "").strip().lower()
    add(failures, release_channel not in {"", "dev", "local", "test"}, "SERVERWARE_RELEASE_CHANNEL must be a production channel")
    public_url = env.get("SERVERWARE_PUBLIC_URL", "").strip()
    if public_url:
        parsed = urllib.parse.urlparse(public_url)
        add(failures, parsed.scheme == "https", "SERVERWARE_PUBLIC_URL must use https in production")
        add(failures, parsed.hostname not in {"localhost", "127.0.0.1", "::1"}, "SERVERWARE_PUBLIC_URL must not be localhost")


def check_nitro(env: dict[str, str], failures: list[str]) -> None:
    add(failures, env.get("SERVERWARE_TEE_QUOTE_PROVIDER") == "aws-nitro-enclaves", "TEE quote provider must be aws-nitro-enclaves")
    add(failures, env.get("SERVERWARE_TEE_PLATFORM") == "aws-nitro", "TEE platform must be aws-nitro")
    add(failures, not env_bool(env, "SERVERWARE_NITRO_FIXTURE"), "SERVERWARE_NITRO_FIXTURE must be disabled")
    add(failures, not env_bool(env, "SERVERWARE_NITRO_ALLOW_DEBUG"), "SERVERWARE_NITRO_ALLOW_DEBUG must be disabled")
    add(failures, not env_bool(env, "SERVERWARE_NITRO_ALLOW_DEBUG_RELEASE"), "SERVERWARE_NITRO_ALLOW_DEBUG_RELEASE must be disabled")
    attestation_command = env.get("SERVERWARE_NITRO_ATTESTATION_COMMAND", "").strip()
    add(failures, bool(attestation_command), "SERVERWARE_NITRO_ATTESTATION_COMMAND must be configured for fresh NSM documents")
    add(
        failures,
        attestation_command and not command_mentions(attestation_command, "fixture", "nitro_attestation_fixture.py"),
        "SERVERWARE_NITRO_ATTESTATION_COMMAND must not use fixture helpers",
    )
    add(
        failures,
        not env.get("SERVERWARE_NITRO_ATTESTATION_DOCUMENT") and not env.get("SERVERWARE_NITRO_ATTESTATION_DOCUMENT_B64"),
        "production Nitro readiness must use a fresh attestation command, not a static document env var",
    )
    add(
        failures,
        bool(env.get("SERVERWARE_NITRO_ROOT_CERT") or env.get("SERVERWARE_NITRO_ROOT_CERT_PEM")),
        "Nitro root certificate must be pinned with SERVERWARE_NITRO_ROOT_CERT[_PEM]",
    )
    add(
        failures,
        valid_pcr_policy(env.get("SERVERWARE_NITRO_EXPECTED_PCRS", "")),
        "SERVERWARE_NITRO_EXPECTED_PCRS must be a non-empty JSON PCR allowlist with 48-byte SHA384 values",
    )
    add(
        failures,
        env_bool(env, "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND"),
        "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND must be enabled",
    )
    kms_command = env.get("SERVERWARE_NITRO_KMS_RELEASE_COMMAND", "").strip()
    add(failures, bool(kms_command), "SERVERWARE_NITRO_KMS_RELEASE_COMMAND must be configured")
    add(
        failures,
        kms_command and not command_mentions(kms_command, "fixture", "nitro_kms_fixture.py"),
        "SERVERWARE_NITRO_KMS_RELEASE_COMMAND must not use fixture helpers",
    )
    materials = {item.strip() for item in env.get("SERVERWARE_NITRO_ALLOWED_MATERIALS", ",".join(REQUIRED_MATERIALS)).split(",") if item.strip()}
    add(failures, REQUIRED_MATERIALS.issubset(materials), "Nitro allowed materials must include broker-kek and decision-gate-ca")


def check_cosign(env: dict[str, str], failures: list[str]) -> None:
    add(failures, env.get("SERVERWARE_IMAGE_SIGNATURE_PROVIDER") == "sigstore-command", "image signature provider must be sigstore-command")
    sign_command = env.get("SERVERWARE_IMAGE_SIGN_COMMAND", "").strip()
    verify_command = env.get("SERVERWARE_IMAGE_VERIFY_COMMAND", "").strip()
    add(failures, bool(sign_command), "SERVERWARE_IMAGE_SIGN_COMMAND must be configured")
    add(failures, bool(verify_command), "SERVERWARE_IMAGE_VERIFY_COMMAND must be configured")
    cosign_binary = env.get("SERVERWARE_COSIGN_BINARY", "cosign").strip()
    add(failures, bool(cosign_binary), "SERVERWARE_COSIGN_BINARY must be configured")
    add(
        failures,
        not command_mentions(cosign_binary, "fixture", "cosign_fixture.py"),
        "SERVERWARE_COSIGN_BINARY must not use fixture helpers",
    )
    add(failures, env_bool(env, "SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY"), "Sigstore transparency evidence must be required")
    key_ref = env.get("SERVERWARE_COSIGN_KEY", "").strip()
    cert_identity = env.get("SERVERWARE_COSIGN_CERT_IDENTITY", "").strip()
    cert_issuer = env.get("SERVERWARE_COSIGN_CERT_OIDC_ISSUER", "").strip()
    keyless_ok = bool(cert_identity and cert_issuer)
    kms_key_ok = key_ref.startswith(KMS_KEY_PREFIXES)
    add(
        failures,
        keyless_ok or kms_key_ok,
        "cosign must use a KMS/HSM key ref or keyless certificate identity plus OIDC issuer",
    )
    if key_ref:
        add(failures, kms_key_ok, f"SERVERWARE_COSIGN_KEY must use a KMS/HSM-backed URI prefix: {', '.join(KMS_KEY_PREFIXES)}")
    add(failures, bool(env.get("SERVERWARE_COSIGN_KEY_ID", "").strip() or keyless_ok), "cosign key provider identity must be stable")


def check_transparency(env: dict[str, str], failures: list[str]) -> None:
    add(
        failures,
        env_bool(env, "SERVERWARE_TRANSPARENCY_CHECKPOINT_REQUIRED"),
        "external transparency checkpoint publication must be required",
    )
    checkpoint_command = env.get("SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND", "").strip()
    add(failures, bool(checkpoint_command), "SERVERWARE_TRANSPARENCY_CHECKPOINT_COMMAND must be configured")
    add(
        failures,
        not command_mentions(checkpoint_command, "external_transparency_log.py"),
        "legacy local external_transparency_log.py fixture must not be used in production",
    )
    mode = env.get("SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE", "").strip()
    add(failures, mode != "fixture", "SERVERWARE_TRANSPARENCY_CHECKPOINT_MODE must not be fixture in production")
    url = env.get("SERVERWARE_TRANSPARENCY_LOG_URL", "").strip()
    parsed = urllib.parse.urlparse(url)
    add(failures, parsed.scheme == "https" and bool(parsed.netloc), "SERVERWARE_TRANSPARENCY_LOG_URL must be an https URL")
    add(
        failures,
        not env_bool(env, "SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP"),
        "SERVERWARE_TRANSPARENCY_ALLOW_INSECURE_HTTP must be disabled",
    )
    add(failures, bool(env.get("SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER", "").strip()), "managed transparency provider must be pinned")
    add(failures, bool(env.get("SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID", "").strip()), "managed transparency log ID must be pinned")
    headers = env_json_object(env, "SERVERWARE_TRANSPARENCY_LOG_HEADERS")
    if headers:
        forbidden = {"authorization", "content-length", "host"}
        bad = sorted(key for key in headers if key.lower() in forbidden)
        add(failures, not bad, f"SERVERWARE_TRANSPARENCY_LOG_HEADERS cannot override {bad}")


def check_apparmor(env: dict[str, str], failures: list[str]) -> None:
    profile = ROOT / "security" / "apparmor" / "serverware-docker"
    override = ROOT / "docker-compose.apparmor.yml"
    add(failures, profile.exists(), "AppArmor profile file must exist")
    add(failures, override.exists(), "AppArmor Compose override must exist")
    expected_profile = env.get("SERVERWARE_APPARMOR_EXPECTED_PROFILE", "serverware-docker").strip()
    add(failures, expected_profile == "serverware-docker", "SERVERWARE_APPARMOR_EXPECTED_PROFILE must pin serverware-docker")


def run_command(command: list[str], *, env: dict[str, str], input_obj: dict[str, Any] | None = None) -> dict[str, Any] | None:
    input_bytes = None
    if input_obj is not None:
        input_bytes = (canonical_json(input_obj) + "\n").encode("utf-8")
    result = subprocess.run(command, cwd=ROOT, env=env, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=180)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace") or result.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(f"{' '.join(command)} failed with exit {result.returncode}: {detail.strip()}")
    if not result.stdout.strip():
        return None
    parsed = json.loads(result.stdout.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{' '.join(command)} returned non-object JSON")
    return parsed


def live_claims(env: dict[str, str], claims_file: str | None) -> dict[str, Any]:
    if claims_file:
        parsed = json.loads(Path(claims_file).read_text(encoding="utf-8"))
    else:
        parsed = env_json_object(env, "SERVERWARE_PRODUCTION_READINESS_CLAIMS_JSON")
    if not isinstance(parsed, dict):
        raise RuntimeError("live mode requires --claims-file or SERVERWARE_PRODUCTION_READINESS_CLAIMS_JSON")
    parsed = json.loads(json.dumps(parsed))
    parsed["nonce"] = f"production-readiness-{int(time.time())}"
    return parsed


def run_live_probes(env: dict[str, str], claims_file: str | None) -> dict[str, Any]:
    probes: dict[str, Any] = {}
    claims = live_claims(env, claims_file)
    quote = run_command([sys.executable, "scripts/aws_nitro_tee_provider.py", "quote"], env=env, input_obj={"claims": claims})
    verified = run_command([sys.executable, "scripts/aws_nitro_tee_provider.py", "verify"], env=env, input_obj={"quote": quote})
    verified_claims = (verified or {}).get("claims") or {}
    tee = verified_claims.get("tee") or {}
    if tee.get("verified") is not True:
        raise RuntimeError(f"Nitro live quote did not verify: {verified}")
    expected = {
        "policy_bundle_digest": claims.get("policy_bundle_digest"),
        "ca_intermediate_spki_sha256": claims.get("ca_intermediate_spki_sha256"),
        "rollback_epoch": claims.get("rollback_epoch"),
        "release_channel": claims.get("release_channel"),
        "provenance_digest": claims.get("provenance_digest"),
        "data_plane_binary_digest": claims.get("data_plane_binary_digest"),
    }
    release = run_command(
        [sys.executable, "scripts/aws_nitro_tee_provider.py", "release"],
        env=env,
        input_obj={"material": "decision-gate-ca", "claims": verified_claims, "expected": expected},
    )
    probes["nitro"] = {
        "ok": True,
        "module_id": tee.get("module_id"),
        "root_sha256": tee.get("root_sha256"),
        "kms_provider": ((release or {}).get("kms_release") or {}).get("provider"),
    }

    if platform.system().lower() != "linux":
        raise RuntimeError("AppArmor live probe requires a Linux Docker host")
    run_command(["./scripts/test_apparmor_runtime.sh"], env=env)
    probes["apparmor"] = {"ok": True}
    return probes


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail-closed production readiness gate for Serverware external trust dependencies.")
    parser.add_argument("--mode", choices=("config", "live"), default="config")
    parser.add_argument("--claims-file", default=None)
    args = parser.parse_args()

    env = dict(os.environ)
    failures: list[str] = []
    for check in (check_no_dev_or_fixture, check_nitro, check_cosign, check_transparency, check_apparmor):
        try:
            check(env, failures)
        except Exception as exc:
            failures.append(str(exc))
    if failures:
        print(canonical_json({"ok": False, "production_readiness": "fail", "failures": failures}))
        raise SystemExit(1)

    live = None
    if args.mode == "live":
        try:
            live = run_live_probes(env, args.claims_file)
        except Exception as exc:
            print(canonical_json({"ok": False, "production_readiness": "fail", "mode": "live", "failures": [str(exc)]}))
            raise SystemExit(1) from exc

    print(
        canonical_json(
            {
                "ok": True,
                "production_readiness": "pass",
                "mode": args.mode,
                "checks": ["no-dev-fixtures", "nitro", "cosign-sigstore", "external-transparency", "apparmor"],
                "live": live,
            }
        )
    )


if __name__ == "__main__":
    main()
