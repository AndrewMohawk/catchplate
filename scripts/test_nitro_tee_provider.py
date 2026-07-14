#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


FIXTURE_PCRS = {
    "0": "11" * 48,
    "1": "22" * 48,
    "2": "33" * 48,
    "8": "88" * 48,
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def run_provider(mode: str, payload: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "scripts/aws_nitro_tee_provider.py", mode],
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"{mode} failed: {result.stderr.decode('utf-8', errors='replace')}")
    data = json.loads(result.stdout.decode("utf-8"))
    if not isinstance(data, dict):
        raise AssertionError(f"{mode} did not return a JSON object")
    return data


def expect_provider_failure(mode: str, payload: dict[str, Any], env: dict[str, str], expected: str) -> None:
    result = subprocess.run(
        [sys.executable, "scripts/aws_nitro_tee_provider.py", mode],
        input=(canonical_json(payload) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
    if result.returncode == 0:
        raise AssertionError(f"{mode} unexpectedly succeeded: {detail}")
    if expected not in detail:
        raise AssertionError(f"{mode} failed with wrong error, expected {expected!r}: {detail}")


def run_serverware_integration(env: dict[str, str]) -> dict[str, Any]:
    code = r'''
import json
import os
from pathlib import Path
from serverware.policy_bundle import write_policy_bundle
from serverware.ca_material import ensure_mitm_ca_material
from serverware.db import get_policy_high_water, init_db

init_db()
policy_source = Path(os.environ["SERVERWARE_POLICY_BUNDLE_SOURCE"])
bundle = json.loads(policy_source.read_text())
high_water = get_policy_high_water()
if high_water:
    bundle["metadata"]["sequence"] = int(high_water["sequence"]) + 1
    bundle["metadata"]["rollbackEpoch"] = max(
        int(bundle["metadata"].get("rollbackEpoch", 0)),
        int(high_water["rollback_epoch"]),
    )
snapshot = write_policy_bundle(bundle, enforce_high_water=True)
ensure_mitm_ca_material()

from serverware.attestation import attestation_document, verify_attestation_quote
from serverware.key_release import release_material

attestation = attestation_document("nitro-integration-test")
claims = verify_attestation_quote(attestation)
tee = claims.get("tee") or {}
if tee.get("verified") is not True:
    raise SystemExit(f"TEE quote was not verified: {tee}")
released = release_material(
    "decision-gate-ca",
    expected_policy_hash=attestation.get("policy_bundle_digest"),
    expected_policy_sequence=attestation.get("policy_sequence"),
    expected_policy_high_water_digest=attestation.get("policy_high_water_digest"),
    expected_ca_spki=attestation.get("ca_intermediate_spki_sha256"),
    expected_rollback_epoch=attestation.get("rollback_epoch"),
    expected_release_channel=attestation.get("release_channel"),
    expected_provenance_digest=attestation.get("provenance_digest"),
    expected_data_plane_binary_digest=attestation.get("data_plane_binary_digest"),
)
if released.get("key_release_provider") != "external-command":
    raise SystemExit(f"unexpected key release provider: {released}")
external_release = released.get("external_release") or {}
kms_release = external_release.get("kms_release") or {}
if kms_release.get("provider") != "fixture-kms-hsm":
    raise SystemExit(f"Nitro key release did not call fixture KMS/HSM command: {released}")
print(json.dumps({
    "ok": True,
    "quote_provider": attestation["quote"]["provider"],
    "tee_platform": attestation["tee_platform"],
    "key_release_provider": released["key_release_provider"],
    "external_release_provider": external_release.get("provider"),
    "kms_release_provider": kms_release.get("provider"),
    "material": released["material"],
}, sort_keys=True))
'''
    result = subprocess.run(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
        raise AssertionError(f"Serverware Nitro integration failed: {detail}")
    data = json.loads(result.stdout.decode("utf-8"))
    if not isinstance(data, dict):
        raise AssertionError("Serverware Nitro integration did not return a JSON object")
    return data


def main() -> None:
    data_dir = Path(os.getenv("SERVERWARE_DATA_DIR", "/data"))
    fixture_dir = data_dir / "nitro-fixture"
    root_cert = fixture_dir / "root.cert.pem"
    base_env = os.environ.copy()
    base_env.update(
        {
            "SERVERWARE_NITRO_FIXTURE": "1",
            "SERVERWARE_NITRO_FIXTURE_DIR": str(fixture_dir),
            "SERVERWARE_NITRO_ROOT_CERT": str(root_cert),
            "SERVERWARE_NITRO_EXPECTED_PCRS": canonical_json(FIXTURE_PCRS),
            "SERVERWARE_NITRO_ALLOW_DEBUG": "0",
            "SERVERWARE_NITRO_ALLOW_DEBUG_RELEASE": "0",
            "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND": "1",
            "SERVERWARE_NITRO_KMS_RELEASE_COMMAND": f"{sys.executable} scripts/nitro_kms_fixture.py release",
        }
    )
    claims = {
        "nonce": "nitro-provider-test",
        "runtime_manifest_digest": "sha256:" + "a" * 64,
        "policy_bundle_digest": "sha256:" + "b" * 64,
        "ca_intermediate_spki_sha256": "sha256:" + "c" * 64,
        "data_plane_binary_digest": "sha256:" + "d" * 64,
        "rollback_epoch": 7,
        "release_channel": "prod",
        "provenance_digest": "sha256:" + "e" * 64,
        "image_signatures_digest": "sha256:" + "f" * 64,
        "source_tree_digest": "sha256:" + "1" * 64,
        "response_signing_key_id": "sha256:" + "2" * 64,
        "materials": ["broker-kek", "decision-gate-ca"],
        "debug": False,
    }

    quote = run_provider("quote", {"claims": claims}, base_env)
    if quote.get("provider") != "aws-nitro-enclaves" or quote.get("debug") is not False:
        raise AssertionError(f"unexpected quote metadata: {quote}")
    verified = run_provider("verify", {"quote": quote}, base_env)
    tee = (verified.get("claims") or {}).get("tee") or {}
    if tee.get("verified") is not True or tee.get("pcrs") != FIXTURE_PCRS:
        raise AssertionError(f"Nitro quote was not verified with expected PCRs: {verified}")
    if not tee.get("raw_attestation_document_b64") or not tee.get("raw_attestation_document_sha256"):
        raise AssertionError(f"Nitro verification did not preserve KMS recipient attestation evidence: {verified}")
    release = run_provider(
        "release",
        {
            "material": "decision-gate-ca",
            "claims": verified["claims"],
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
        },
        base_env,
    )
    if release.get("provider") != "aws-nitro-kms-policy" or release.get("material") != "decision-gate-ca":
        raise AssertionError(f"Nitro release policy did not allow the expected material: {release}")
    kms_release = release.get("kms_release") or {}
    if release.get("kms_command_configured") is not True or release.get("kms_command_required") is not True:
        raise AssertionError(f"Nitro release did not require the configured KMS command: {release}")
    if kms_release.get("provider") != "fixture-kms-hsm":
        raise AssertionError(f"Nitro release did not call the fixture KMS/HSM command: {release}")
    if kms_release.get("request_digest") != release.get("kms_request_digest"):
        raise AssertionError(f"Nitro KMS/HSM response was not bound to the release request: {release}")
    if not ((kms_release.get("key_provider") or {}).get("key_id")):
        raise AssertionError(f"Nitro KMS/HSM response did not bind a key provider: {release}")
    if "raw_attestation_document_b64" in (release.get("tee") or {}):
        raise AssertionError(f"Nitro release response leaked the raw attestation document: {release}")
    unauthorized_claims = json.loads(json.dumps(verified["claims"]))
    unauthorized_claims["materials"] = ["broker-kek"]
    expect_provider_failure(
        "release",
        {
            "material": "decision-gate-ca",
            "claims": unauthorized_claims,
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
        },
        base_env,
        "verified Nitro claims must authorize exactly broker-kek and decision-gate-ca",
    )

    extra_material_claims = json.loads(json.dumps(verified["claims"]))
    extra_material_claims["materials"] = ["broker-kek", "decision-gate-ca", "debug-material"]
    expect_provider_failure(
        "release",
        {
            "material": "decision-gate-ca",
            "claims": extra_material_claims,
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
        },
        base_env,
        "verified Nitro claims must authorize exactly broker-kek and decision-gate-ca",
    )

    extra_allowed_env = dict(base_env)
    extra_allowed_env["SERVERWARE_NITRO_ALLOWED_MATERIALS"] = "broker-kek,decision-gate-ca,debug-material"
    expect_provider_failure(
        "release",
        {
            "material": "decision-gate-ca",
            "claims": verified["claims"],
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
        },
        extra_allowed_env,
        "allowed materials must be exactly broker-kek and decision-gate-ca",
    )

    attestation_command_env = dict(base_env)
    attestation_command_env.pop("SERVERWARE_NITRO_FIXTURE", None)
    attestation_command_env["SERVERWARE_NITRO_ATTESTATION_COMMAND"] = f"{sys.executable} scripts/nitro_attestation_fixture.py attest"
    command_quote = run_provider("quote", {"claims": claims}, attestation_command_env)
    if command_quote.get("provider") != "aws-nitro-enclaves":
        raise AssertionError(f"Nitro attestation command quote had wrong provider: {command_quote}")
    command_verified = run_provider("verify", {"quote": command_quote}, attestation_command_env)
    command_tee = (command_verified.get("claims") or {}).get("tee") or {}
    if command_tee.get("verified") is not True or command_tee.get("pcrs") != FIXTURE_PCRS:
        raise AssertionError(f"Nitro attestation command quote was not verified: {command_verified}")

    integration_data_dir = fixture_dir / "serverware-integration"
    shutil.rmtree(integration_data_dir, ignore_errors=True)
    integration_data_dir.mkdir(parents=True, exist_ok=True)
    integration_env = dict(attestation_command_env)
    integration_env.update(
        {
            "SERVERWARE_DATA_DIR": str(integration_data_dir.resolve()),
            "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
            "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
            "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
            "SERVERWARE_TEE_QUOTE_PROVIDER": "aws-nitro-enclaves",
            "SERVERWARE_TEE_PLATFORM": "aws-nitro",
            "SERVERWARE_TEE_QUOTE_COMMAND": f"{sys.executable} scripts/aws_nitro_tee_provider.py quote",
            "SERVERWARE_TEE_QUOTE_VERIFY_COMMAND": f"{sys.executable} scripts/aws_nitro_tee_provider.py verify",
            "SERVERWARE_KEY_RELEASE_COMMAND": f"{sys.executable} scripts/aws_nitro_tee_provider.py release",
            "SERVERWARE_POLICY_BUNDLE_SOURCE": str(Path("policies/demo.policy.json").resolve()),
            "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST": claims["data_plane_binary_digest"],
        }
    )
    integration = run_serverware_integration(integration_env)
    if integration.get("external_release_provider") != "aws-nitro-kms-policy":
        raise AssertionError(f"Serverware key release did not use Nitro release policy: {integration}")
    if integration.get("kms_release_provider") != "fixture-kms-hsm":
        raise AssertionError(f"Serverware key release did not invoke Nitro KMS/HSM fixture: {integration}")

    bad_attestation_digest_env = dict(attestation_command_env)
    bad_attestation_digest_env["SERVERWARE_NITRO_ATTESTATION_FIXTURE_BAD_DIGEST"] = "1"
    expect_provider_failure(
        "quote",
        {"claims": claims},
        bad_attestation_digest_env,
        "external Nitro attestation command response digest mismatch",
    )

    bad_attestation_doc_env = dict(attestation_command_env)
    bad_attestation_doc_env["SERVERWARE_NITRO_ATTESTATION_FIXTURE_BAD_DOCUMENT"] = "1"
    expect_provider_failure("quote", {"claims": claims}, bad_attestation_doc_env, "user_data does not bind")

    tampered_quote = json.loads(json.dumps(quote))
    tampered_quote["claims"]["policy_bundle_digest"] = "sha256:" + "0" * 64
    expect_provider_failure("verify", {"quote": tampered_quote}, base_env, "user_data does not bind")

    mismatch_env = dict(base_env)
    mismatch_pcrs = dict(FIXTURE_PCRS)
    mismatch_pcrs["0"] = "99" * 48
    mismatch_env["SERVERWARE_NITRO_EXPECTED_PCRS"] = canonical_json(mismatch_pcrs)
    expect_provider_failure("verify", {"quote": quote}, mismatch_env, "PCR0 does not match")

    no_kms_env = dict(base_env)
    no_kms_env.pop("SERVERWARE_NITRO_KMS_RELEASE_COMMAND", None)
    expect_provider_failure(
        "release",
        {
            "material": "decision-gate-ca",
            "claims": verified["claims"],
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
        },
        no_kms_env,
        "SERVERWARE_NITRO_KMS_RELEASE_COMMAND is required",
    )

    denied_kms_env = dict(base_env)
    denied_kms_env["SERVERWARE_NITRO_KMS_FIXTURE_DENY"] = "1"
    expect_provider_failure(
        "release",
        {
            "material": "decision-gate-ca",
            "claims": verified["claims"],
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
        },
        denied_kms_env,
        "denied material release",
    )

    bad_digest_kms_env = dict(base_env)
    bad_digest_kms_env["SERVERWARE_NITRO_KMS_FIXTURE_BAD_DIGEST"] = "1"
    expect_provider_failure(
        "release",
        {
            "material": "decision-gate-ca",
            "claims": verified["claims"],
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
        },
        bad_digest_kms_env,
        "response digest mismatch",
    )

    secret_kms_env = dict(base_env)
    secret_kms_env["SERVERWARE_NITRO_KMS_FIXTURE_SECRET_RESPONSE"] = "1"
    expect_provider_failure(
        "release",
        {
            "material": "decision-gate-ca",
            "claims": verified["claims"],
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
        },
        secret_kms_env,
        "plaintext material field",
    )

    debug_env = dict(base_env)
    debug_env["SERVERWARE_NITRO_FIXTURE_DEBUG"] = "1"
    expect_provider_failure("quote", {"claims": claims}, debug_env, "debug PCRs are not accepted")

    print(
        json.dumps(
            {
                "ok": True,
                "nitro_tee_provider": "pass",
                "provider": quote["provider"],
                "tee_platform": quote["tee_platform"],
                "pcrs": len(FIXTURE_PCRS),
                "root_sha256": tee.get("root_sha256"),
                "release_provider": release.get("provider"),
                "kms_provider": kms_release.get("provider"),
                "serverware_integration": integration.get("quote_provider"),
                "attestation_command": "pass",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit(f"Nitro TEE provider test failed: {exc}") from exc
