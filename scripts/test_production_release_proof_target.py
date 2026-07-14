#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def target_body(makefile: str, target: str) -> str:
    lines = makefile.splitlines()
    declaration = re.compile(rf"^{re.escape(target)}\s*:")
    for index, line in enumerate(lines):
        if declaration.match(line):
            break
    else:
        raise AssertionError(f"Makefile is missing {target}")

    body = []
    for line in lines[index + 1 :]:
        if line.startswith("\t") or not line.strip():
            body.append(line)
            continue
        break
    return "\n".join(body).strip()


def recursive_make_targets(body: str) -> list[str]:
    invocation = re.compile(r"^\s*\$\(MAKE\)\s+([^\s]+)")
    return [match.group(1) for line in body.splitlines() if (match := invocation.match(line))]


def main() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    body = target_body(makefile, "production-release-proof")
    if "AWS_KMS_MATERIALS_OUT ?= /etc/serverware/kms-materials.json" not in makefile:
        raise AssertionError("production release proof does not default KMS materials to the production /etc path")
    required_order = [
        "verify-credential-policy-contracts",
        "validate-production-policy-identity",
        "validate-policy-activation-evidence",
        "validate-reproducible-builds",
        "production-release-input-preflight",
        "build-production-images",
        "decision-gate-bench-evidence",
        "publish-production-images",
        "merge-production-images-env",
        "production-release-provenance",
        "sign-production-images",
        "prepare-aws-kms-materials",
        "production-host-preflight",
        "deploy-production",
        "run-production-readiness",
    ]
    release_targets = recursive_make_targets(body)
    positions = []
    for item in required_order:
        if item not in release_targets:
            raise AssertionError(f"production-release-proof omits {item}")
        positions.append(release_targets.index(item))
    if positions != sorted(positions):
        raise AssertionError(f"production-release-proof runs steps in the wrong order: {body}")
    if "PRODUCTION_READINESS_PREFLIGHT=0" in body:
        raise AssertionError("production-release-proof disables final preflight")
    if "SERVERWARE_TEST_ONLY_ALLOW_PREFLIGHT_BYPASS" in body:
        raise AssertionError("production-release-proof enables the test-only preflight bypass")
    if release_targets.index("production-host-preflight") > release_targets.index("deploy-production"):
        raise AssertionError("production-release-proof deploys before full host preflight")
    if release_targets.index("validate-production-policy-identity") > release_targets.index("build-production-images"):
        raise AssertionError("production-release-proof builds before validating production principal identity")

    policy_contract_body = target_body(makefile, "verify-credential-policy-contracts")
    for required in (
        "uv run --isolated --python 3.11 --with-requirements requirements.lock",
        "scripts/test_credential_constraints.py",
        "cargo test",
        "--locked",
        "--manifest-path data-plane/decision-gate-rs/Cargo.toml",
    ):
        if required not in policy_contract_body:
            raise AssertionError(f"credential policy verification omits {required}")

    input_preflight_body = target_body(makefile, "production-release-input-preflight")
    for required in (
        "scripts/production_release_input_preflight.py",
        "$(PRODUCTION_READINESS_ENV)",
        "$(AWS_KMS_MATERIALS_SPEC)",
        "$(PRODUCTION_IMAGE_REGISTRY_PREFIX)",
        "$(PRODUCTION_DEPLOY_COMMAND)",
        "$(PRODUCTION_POLICY_IDENTITY_VERIFICATION_OUT)",
        "$(POLICY_ACTIVATION_VERIFICATION_SIGNATURE)",
        "$(POLICY_ACTIVATION_VERIFICATION_TRUSTED_PUBLIC_KEY)",
        "$(REPRODUCIBLE_BUILD_VERIFICATION_SIGNATURE)",
        "$(REPRODUCIBLE_BUILD_VERIFICATION_TRUSTED_PUBLIC_KEY)",
    ):
        if required not in input_preflight_body:
            raise AssertionError(f"production release input preflight omits {required}")

    identity_body = target_body(makefile, "validate-production-policy-identity")
    for required in (
        "scripts/verify_production_policy_identity.py",
        "$(PRODUCTION_POLICY_BUNDLE)",
        "$(PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY)",
        "$(PRODUCTION_POLICY_IDENTITY_VERIFICATION_OUT)",
    ):
        if required not in identity_body:
            raise AssertionError(f"production policy identity validation omits {required}")

    activation_body = target_body(makefile, "validate-policy-activation-evidence")
    for required in (
        "--trusted-policy-public-key",
        "$(POLICY_ACTIVATION_TRUSTED_POLICY_PUBLIC_KEY)",
        "--trusted-audit-checkpoint-public-key",
        "$(POLICY_ACTIVATION_TRUSTED_AUDIT_CHECKPOINT_PUBLIC_KEY)",
        "--expected-data-plane-actor",
        "$(POLICY_ACTIVATION_EXPECTED_DATA_PLANE_ACTOR)",
    ):
        if required not in activation_body:
            raise AssertionError(f"production policy activation validation omits {required}")

    reproducibility_body = target_body(makefile, "validate-reproducible-builds")
    for required in (
        "$(REPRODUCIBLE_BUILD_LEFT)",
        "$(REPRODUCIBLE_BUILD_RIGHT)",
        "--trusted-builder",
        "$(REPRODUCIBLE_BUILD_TRUSTED_BUILDER_LEFT)",
        "$(REPRODUCIBLE_BUILD_TRUSTED_BUILDER_RIGHT)",
    ):
        if required not in reproducibility_body:
            raise AssertionError(f"production reproducibility validation omits {required}")

    deploy_body = target_body(makefile, "deploy-production")
    if "PRODUCTION_DEPLOY_COMMAND" not in deploy_body or "is required" not in deploy_body:
        raise AssertionError("deploy-production does not fail closed without an explicit deployment command")

    bench_body = target_body(makefile, "decision-gate-bench-evidence")
    if "$(DECISION_GATE_BENCH_FILE)" not in bench_body or "bench_decision_gate.py --self-test" not in bench_body:
        raise AssertionError("decision-gate-bench-evidence does not regenerate the configured benchmark evidence")

    release_body = target_body(makefile, "release-provenance")
    if "$(RELEASE_PROVENANCE_SUMMARY_FILE)" not in release_body or "$(RELEASE_PROVENANCE_FILE)" not in release_body:
        raise AssertionError("release-provenance target does not write the configured provenance summary/document")
    if "--production" in release_body:
        raise AssertionError("development release-provenance target must preserve direct requirements.txt inventory")

    production_release_body = target_body(makefile, "production-release-provenance")
    if "--production" not in production_release_body:
        raise AssertionError("production-release-provenance target does not select the locked transitive inventory")

    image_body = target_body(makefile, "image-signatures")
    if "$(IMAGE_SIGNATURES_SUMMARY_FILE)" not in image_body or "$(IMAGE_SIGNATURES_FILE)" not in image_body:
        raise AssertionError("image-signatures target does not write the configured image-signature summary/document")

    sign_body = target_body(makefile, "sign-production-images")
    if "--env-file \"$(PRODUCTION_READINESS_ENV)\"" not in sign_body:
        raise AssertionError("sign-production-images does not load production signing settings from the readiness env")
    if "cosign_fixture.py" in sign_body:
        raise AssertionError("sign-production-images must not default published image signing to the fixture cosign helper")
    if "SERVERWARE_IMAGE_SIGN_COMMAND=" in sign_body or "SERVERWARE_COSIGN_BINARY=" in sign_body:
        raise AssertionError("sign-production-images must let the strict env file or explicit environment select the signer")

    preflight_body = target_body(makefile, "production-host-preflight")
    if "--bench" not in preflight_body or "$(DECISION_GATE_BENCH_FILE)" not in preflight_body:
        raise AssertionError("production-host-preflight does not verify benchmark evidence")
    if "--production-images-published" not in preflight_body or "$(PRODUCTION_IMAGES_PUBLISHED_FILE)" not in preflight_body:
        raise AssertionError("production-host-preflight does not verify the published image manifest")
    for required in (
        "--policy-identity-verification",
        "--policy-activation-signature",
        "--reproducible-build-signature",
    ):
        if required not in preflight_body:
            raise AssertionError(f"production-host-preflight omits release binding {required}")

    run_body = target_body(makefile, "run-production-readiness")
    if "production-host-preflight" not in run_body:
        raise AssertionError("run-production-readiness does not enforce production-host-preflight")
    if "--production-host-preflight" not in run_body:
        raise AssertionError("run-production-readiness does not pass production preflight evidence to completion")
    if "--production-images-build" not in run_body or "--production-images-published" not in run_body:
        raise AssertionError("run-production-readiness does not pass production image build/publish evidence to completion")
    if "--production-images-env" not in run_body:
        raise AssertionError("run-production-readiness does not pass current production image env evidence to completion")
    for required in (
        "--policy-bundle",
        "--policy-identity-verification",
        "--policy-activation-verification",
        "--reproducible-build-verification",
    ):
        if required not in run_body:
            raise AssertionError(f"run-production-readiness omits release binding {required}")
    if "SERVERWARE_TEST_ONLY_ALLOW_PREFLIGHT_BYPASS" in run_body:
        raise AssertionError("run-production-readiness enables the test-only preflight bypass")
    if "--skip-current-host-check" in run_body:
        raise AssertionError("run-production-readiness disables the final current-host check")

    print(json.dumps({"ok": True, "production_release_proof_target": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
