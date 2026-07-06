#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
FIXTURE_PCRS = {
    "0": "11" * 48,
    "1": "22" * 48,
    "2": "33" * 48,
    "8": "88" * 48,
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def claims(materials: list[str] | None = None) -> dict[str, Any]:
    return {
        "nonce": "will-be-replaced",
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
        "materials": materials or ["broker-kek", "decision-gate-ca"],
        "debug": False,
    }


def fixture_env(tmp: Path) -> dict[str, str]:
    fixture_dir = tmp / "nitro-fixture"
    env = os.environ.copy()
    env.update(
        {
            "SERVERWARE_NITRO_FIXTURE": "1",
            "SERVERWARE_NITRO_FIXTURE_DIR": str(fixture_dir),
            "SERVERWARE_NITRO_ROOT_CERT": str(fixture_dir / "root.cert.pem"),
            "SERVERWARE_NITRO_EXPECTED_PCRS": canonical_json(FIXTURE_PCRS),
            "SERVERWARE_NITRO_ALLOW_DEBUG": "0",
            "SERVERWARE_NITRO_ALLOW_DEBUG_RELEASE": "0",
            "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND": "1",
            "SERVERWARE_NITRO_ATTESTATION_COMMAND": f"{sys.executable} scripts/nitro_attestation_fixture.py attest",
            "SERVERWARE_NITRO_KMS_RELEASE_COMMAND": f"{sys.executable} scripts/nitro_kms_fixture.py release",
        }
    )
    return env


def run_collector(env: dict[str, str], claims_file: Path, *extra: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            "scripts/collect_nitro_kms_evidence.py",
            "--claims-file",
            str(claims_file),
            "--nonce",
            "evidence-test",
            *extra,
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def output_text(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode("utf-8", errors="replace")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        claims_file = tmp / "claims.json"
        claims_file.write_text(json.dumps(claims(), sort_keys=True), encoding="utf-8")
        env = fixture_env(tmp)

        rejected = run_collector(env, claims_file)
        if rejected.returncode == 0 or "fixture" not in output_text(rejected).lower():
            raise AssertionError(f"collector accepted fixture commands without explicit test opt-in: {output_text(rejected)}")
        rejected_path = tmp / "nitro-evidence-rejected.json"
        rejected_with_out = run_collector(env, claims_file, "--out", str(rejected_path))
        if rejected_with_out.returncode == 0:
            raise AssertionError(f"collector accepted fixture commands with an output path: {output_text(rejected_with_out)}")
        rejected_summary = json.loads(rejected_with_out.stdout.decode("utf-8"))
        if not rejected_path.exists() or not rejected_summary.get("evidence_sha256", "").startswith("sha256:"):
            raise AssertionError(f"collector did not write failure evidence: {rejected_summary}")
        rejected_evidence = json.loads(rejected_path.read_text(encoding="utf-8"))
        if rejected_evidence.get("ok") is not False or "fixture" not in rejected_evidence.get("error", "").lower():
            raise AssertionError(f"collector failure evidence was invalid: {rejected_evidence}")

        evidence_path = tmp / "nitro-evidence.json"
        accepted = run_collector(env, claims_file, "--allow-fixtures-for-test", "--out", str(evidence_path))
        if accepted.returncode != 0:
            raise AssertionError(f"collector failed with fixture opt-in: {output_text(accepted)}")
        summary = json.loads(accepted.stdout.decode("utf-8"))
        if summary.get("ok") is not True or not summary.get("evidence_sha256"):
            raise AssertionError(f"collector summary was invalid: {summary}")
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        if evidence.get("ok") is not True or evidence.get("provider") != "aws-nitro-enclaves":
            raise AssertionError(f"evidence did not prove Nitro provider: {evidence}")
        if (evidence.get("nitro") or {}).get("verified") is not True:
            raise AssertionError(f"evidence did not include verified Nitro metadata: {evidence}")
        if "raw_attestation_document_b64" in (evidence.get("quote") or {}):
            raise AssertionError(f"evidence leaked the raw attestation document: {evidence}")
        materials = {item.get("material") for item in evidence.get("release_materials") or []}
        if materials != {"broker-kek", "decision-gate-ca"}:
            raise AssertionError(f"evidence did not prove both release materials: {evidence}")
        for release in evidence.get("release_materials") or []:
            kms_release = (release.get("kms_release") or {})
            leaked = {"public_key_pem", "signature", "plaintext"} & set(kms_release)
            if leaked:
                raise AssertionError(f"KMS release evidence leaked raw fields {sorted(leaked)}: {release}")
            key_id = (((release.get("kms_release") or {}).get("key_provider") or {}).get("key_id"))
            if not key_id:
                raise AssertionError(f"KMS release evidence did not bind a key id: {release}")
        if ((evidence.get("claims") or {}).get("fields") or {}).get("nonce") != "evidence-test":
            raise AssertionError(f"evidence did not bind the requested nonce: {evidence}")

        missing_material_file = tmp / "claims-missing-material.json"
        missing_material_file.write_text(json.dumps(claims(["broker-kek"]), sort_keys=True), encoding="utf-8")
        missing_material = run_collector(
            env,
            missing_material_file,
            "--allow-fixtures-for-test",
            "--material",
            "decision-gate-ca",
        )
        if missing_material.returncode == 0 or "do not authorize" not in output_text(missing_material):
            raise AssertionError(f"collector accepted a material absent from the quote claims: {output_text(missing_material)}")

        extra_claims_file = tmp / "claims-extra-material.json"
        extra_claims_file.write_text(
            json.dumps(claims(["broker-kek", "decision-gate-ca", "debug-material"]), sort_keys=True),
            encoding="utf-8",
        )
        extra_claims = run_collector(env, extra_claims_file, "--allow-fixtures-for-test")
        if extra_claims.returncode == 0 or "claims authorize unauthorized materials" not in output_text(extra_claims):
            raise AssertionError(f"collector accepted unauthorized claim materials: {output_text(extra_claims)}")

        unauthorized_material = run_collector(
            env,
            claims_file,
            "--allow-fixtures-for-test",
            "--material",
            "debug-material",
        )
        if unauthorized_material.returncode == 0 or "unauthorized requested materials" not in output_text(unauthorized_material):
            raise AssertionError(f"collector accepted an unauthorized requested material: {output_text(unauthorized_material)}")

        bad_b64_env = dict(env)
        bad_b64_env["SERVERWARE_NITRO_ATTESTATION_FIXTURE_BAD_B64"] = "1"
        bad_b64 = run_collector(bad_b64_env, claims_file, "--allow-fixtures-for-test")
        if bad_b64.returncode == 0 or "attestation_document_b64 is invalid base64url" not in output_text(bad_b64):
            raise AssertionError(f"collector accepted malformed Nitro attestation base64: {output_text(bad_b64)}")

        secret_env = dict(env)
        secret_env["SERVERWARE_NITRO_KMS_FIXTURE_SECRET_RESPONSE"] = "1"
        secret_result = run_collector(secret_env, claims_file, "--allow-fixtures-for-test")
        if secret_result.returncode == 0 or "plaintext material" not in output_text(secret_result):
            raise AssertionError(f"collector accepted a plaintext KMS response: {output_text(secret_result)}")

    print(canonical_json({"ok": True, "nitro_kms_evidence": "pass"}))


if __name__ == "__main__":
    main()
