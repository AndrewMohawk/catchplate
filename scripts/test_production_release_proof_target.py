#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import build_production_images

ROOT = Path(__file__).resolve().parent.parent


def build_metadata_fixture() -> dict[str, object]:
    digest = "sha256:" + "0" * 64
    return {
        "source": "https://example.invalid/serverware",
        "revision": "0" * 40,
        "created": "2026-01-01T00:00:00Z",
        "source_date_epoch": "0",
        "source_tree_digest": digest,
        "source_archive_digest": digest,
        "source_archive_path": "production-dependencies/cache/source-contract/source.tar",
        "source_manifest_digest": digest,
        "source_manifest_path": "production-dependencies/cache/source-contract/source.manifest.json",
        "source_file_list_digest": digest,
        "source_file_list_path": "production-dependencies/cache/source-contract/source.files",
        "source_file_hashes_digest": digest,
        "source_file_hashes_path": "production-dependencies/cache/source-contract/source.files.sha256",
        "source_file_modes_digest": digest,
        "source_file_modes_path": "production-dependencies/cache/source-contract/source.files.mode",
        "source_identity_mode": "production-commit",
        "production_release_eligible": True,
        "image_title_suffix": "production test",
    }


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
        "verify-custody-response-proof",
        "verify-control-plane-startup",
        "verify-control-plane-oidc",
        "verify-webauthn-recovery",
        "verify-portal-browser-oauth",
        "verify-onboarding-evidence-tooling",
        "verify-agent-enrollment",
        "build-agent-enrollment-wheel",
        "verify-setup-session-api",
        "validate-production-policy-identity",
        "verify-production-agent-enrollment-evidence",
        "validate-policy-activation-evidence",
        "validate-reproducible-builds",
        "production-release-input-preflight",
        "build-production-images",
        "decision-gate-bench-evidence",
        "publish-production-images",
        "merge-production-images-env",
        "build-production-launcher",
        "production-release-provenance",
        "sign-production-images",
        "prepare-aws-kms-materials",
        "deploy-production",
        "install-production-launcher",
        "generate-production-launch-manifest",
        "run-production-readiness-final",
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
    if "production-host-preflight" in release_targets or "run-production-readiness" in release_targets:
        raise AssertionError("production-release-proof bypasses the closed native launcher path")
    if release_targets.index("validate-production-policy-identity") > release_targets.index("build-production-images"):
        raise AssertionError("production-release-proof builds before validating production principal identity")

    policy_contract_body = target_body(makefile, "verify-credential-policy-contracts")
    for required in (
        "uv run --no-project --isolated --python 3.11 --with-requirements requirements.lock",
        "scripts/test_credential_constraints.py",
        "cargo test",
        "--locked",
        "--manifest-path data-plane/decision-gate-rs/Cargo.toml",
    ):
        if required not in policy_contract_body:
            raise AssertionError(f"credential policy verification omits {required}")

    startup_body = target_body(makefile, "verify-control-plane-startup")
    if "scripts/test_control_plane_startup.py" not in startup_body:
        raise AssertionError("control-plane startup verification omits the shared preflight test")

    custody_body = target_body(makefile, "verify-custody-response-proof")
    if "scripts/test_custody_response_proof.sh" not in custody_body:
        raise AssertionError("production release verification omits the custody proof lifecycle")

    aggregate_declaration = next(
        line for line in makefile.splitlines() if line.startswith("verify-production-release-proof:")
    )
    if "verify-custody-response-proof" not in aggregate_declaration:
        raise AssertionError("verify-production-release-proof omits the custody proof lifecycle")
    for required in (
        "verify-onboarding-evidence-tooling",
        "build-agent-enrollment-wheel",
    ):
        if required not in aggregate_declaration:
            raise AssertionError(
                f"verify-production-release-proof omits {required}"
            )

    oidc_body = target_body(makefile, "verify-control-plane-oidc")
    if "scripts/test_control_plane_oidc.py" not in oidc_body:
        raise AssertionError("control-plane OIDC verification omits its session test")

    recovery_body = target_body(makefile, "verify-webauthn-recovery")
    if "scripts/test_webauthn_recovery.py" not in recovery_body:
        raise AssertionError("WebAuthn recovery verification omits its race and rollback test")

    browser_body = target_body(makefile, "verify-portal-browser-oauth")
    for required in (
        "python -m playwright install chromium",
        "scripts/test_portal_browser_oauth.py",
    ):
        if required not in browser_body:
            raise AssertionError(f"portal browser OAuth verification omits {required}")
    for target in ("bench-gate-rs", "verify-oauth-credentials"):
        if "$(MAKE) verify-portal-browser-oauth" not in target_body(makefile, target):
            raise AssertionError(f"{target} omits the portal browser OAuth proof")

    onboarding_body = target_body(makefile, "verify-onboarding-evidence-tooling")
    for required in (
        "$(TEST_PYTHON_RUN)",
        "-m unittest scripts.test_onboarding_evidence -v",
    ):
        if required not in onboarding_body:
            raise AssertionError(
                f"onboarding evidence verification omits {required}"
            )

    bench_body = target_body(makefile, "bench-gate-rs")
    provenance_step = "scripts/generate_release_provenance.py"
    proof_step = "./scripts/test_response_proof_capture.sh"
    image_signing_step = "scripts/sign_release_images.py"
    if bench_body.count(provenance_step) != 1:
        raise AssertionError("bench-gate-rs must generate release provenance exactly once")
    if not (
        bench_body.index(provenance_step)
        < bench_body.index(proof_step)
        < bench_body.index(image_signing_step)
    ):
        raise AssertionError(
            "bench-gate-rs must publish provenance before response-proof capture and image signing"
        )

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

    enrollment_evidence_body = target_body(
        makefile, "verify-production-agent-enrollment-evidence"
    )
    for required in (
        "scripts/verify_production_agent_enrollment.py",
        "$(PRODUCTION_AGENT_ENROLLMENT_PACKET)",
        "$(PRODUCTION_AGENT_ENROLLMENT_PACKET_FILE_SHA256)",
        "$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT)",
        "$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT_TRUSTED_PUBLIC_KEY)",
        "$(PRODUCTION_AGENT_EGRESS_EVIDENCE)",
        "$(PRODUCTION_AGENT_EGRESS_TRUSTED_PUBLIC_KEY)",
        "$(PRODUCTION_AGENT_ASSIGNMENT_DIGEST)",
        "--expected-enrollment-packet-file-sha256",
        "--expected-assignment-digest",
        "--out",
    ):
        if required not in enrollment_evidence_body:
            raise AssertionError(
                f"production agent enrollment evidence gate omits {required}"
            )
    for forbidden in (
        "development-fixture",
        "generate_agent_enrollment.py",
        "test_agent_enrollment.py",
        "fixture",
    ):
        if forbidden in enrollment_evidence_body:
            raise AssertionError(
                f"production agent enrollment evidence gate synthesizes or accepts {forbidden}"
            )

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

    launcher_build_body = target_body(makefile, "build-production-launcher")
    for required in (
        "--network=none",
        '--platform "$(PRODUCTION_PLATFORM)"',
        "--target production-launcher-artifact",
        "Dockerfile.production",
    ):
        if required not in launcher_build_body:
            raise AssertionError(f"production launcher build omits {required}")

    launcher_install_body = target_body(makefile, "install-production-launcher")
    for required in ("id -u", "sha256sum", "/opt/serverware/launchers/sha256-", "-m 0500"):
        if required not in launcher_install_body:
            raise AssertionError(f"production launcher installation omits {required}")
    if "launcher_binary_digest" not in launcher_install_body or "independently reproducible production image" not in launcher_install_body:
        raise AssertionError("production launcher installation is not bound to independent-build evidence")

    launch_manifest_body = target_body(makefile, "generate-production-launch-manifest")
    for required in (
        "generate_production_launch_manifest.py",
        "--systemd-unit-out",
        "--launcher-path",
        "--source-tree-digest",
        "--nonce-rollback-assurance-pins",
        "--expected-nonce-rollback-assurance-pins-sha256",
        "--pipeline-metadata-out",
        "--python-import-root \"$(PRODUCTION_RELEASE_ROOT)\"",
        "--production-host-preflight",
        "/usr/bin/systemctl daemon-reload",
    ):
        if required not in launch_manifest_body:
            raise AssertionError(f"production launch-manifest generation omits {required}")

    final_launcher_body = target_body(makefile, "run-production-readiness-final")
    for required in ("id -u", "/usr/bin/systemctl start", "--property=Result"):
        if required not in final_launcher_body:
            raise AssertionError(f"final production launcher target omits {required}")
    if "python3" in final_launcher_body or "scripts/run_production_readiness.py" in final_launcher_body:
        raise AssertionError("final production launcher target starts Python outside systemd")

    generator_source = (
        ROOT / "scripts" / "generate_production_launch_manifest.py"
    ).read_text(encoding="utf-8")
    launcher_source = (
        ROOT
        / "data-plane"
        / "decision-gate-rs"
        / "src"
        / "bin"
        / "serverware-production-launcher.rs"
    ).read_text(encoding="utf-8")
    readiness_source = (
        ROOT / "scripts" / "run_production_readiness.py"
    ).read_text(encoding="utf-8")
    preflight_source = (
        ROOT / "scripts" / "production_host_preflight.py"
    ).read_text(encoding="utf-8")
    completion_source = (
        ROOT / "scripts" / "verify_release_completion.py"
    ).read_text(encoding="utf-8")
    adversarial_launcher_source = (
        ROOT / "scripts" / "test_production_launcher_adversarial.py"
    ).read_text(encoding="utf-8")
    for label, source, required in (
        (
            "manifest generator",
            generator_source,
            (
                'API_VERSION = "serverware.productionReadinessLaunch/v3"',
                '"nonceRollbackAssurance"',
                '"native-launcher-measured"',
                '"purpose": "readiness-only"',
                '"nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"',
                '"nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"',
            ),
        ),
        (
            "native launcher",
            launcher_source,
            (
                'serverware.bootstrapReceipt/v3',
                'nonceRollbackAssuranceContractSha256',
                'nonceRollbackAssurancePinsSha256',
                '--launcher-nonce-rollback-assurance-pins',
                'legacy v2 launch manifests are readiness-only',
                'nonce_authority_verifier_state_store_attestation_public_key_spki_der_base64url',
                'nonce_authority_verifier_state_store_assurance_evidence_sha256',
                'let receipt_fd_reservation = reserve_receipt_fd()?;',
                'create_sealed_receipt(&receipt_bytes, receipt_fd_reservation)',
            ),
        ),
        (
            "readiness child",
            readiness_source,
            (
                '--launcher-nonce-rollback-assurance-pins',
                'validate_retained_nonce_rollback_assurance',
                '"readiness"',
                '"nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"',
                '"nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"',
            ),
        ),
        (
            "preflight child",
            preflight_source,
            (
                '--launcher-nonce-rollback-assurance-pins',
                'nonce_rollback_assurance',
                'pass_fds=tuple(sorted({receipt_fd, pins_fd}))',
            ),
        ),
        (
            "offline completion verifier",
            completion_source,
            (
                'verify_launcher_nonce_rollback_manifest_v3',
                '"nonce_rollback_assurance"',
                '"readiness-only"',
                '"nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"',
                '"nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"',
            ),
        ),
        (
            "adversarial launcher test",
            adversarial_launcher_source,
            (
                'CODER_IMAGE_REF = "serverware-production-launcher-adversarial:coder-v3"',
                'IMAGE_REF_ENV = "SERVERWARE_ADVERSARIAL_LAUNCHER_IMAGE"',
                'IMAGE_ID_ENV = "SERVERWARE_ADVERSARIAL_LAUNCHER_IMAGE_ID"',
                '"--prepare-image"',
                '"--test-prebuilt-image"',
                '"--expected-image-id"',
                '"--pull=never"',
            ),
        ),
    ):
        for marker in required:
            if marker not in source:
                raise AssertionError(
                    f"{label} omits nonce rollback assurance source marker: {marker}"
                )

    bench_body = target_body(makefile, "decision-gate-bench-evidence")
    if "$(DECISION_GATE_BENCH_FILE)" not in bench_body or "bench_decision_gate.py --self-test" not in bench_body:
        raise AssertionError("decision-gate-bench-evidence does not regenerate the configured benchmark evidence")
    if "rm -f \"$(DECISION_GATE_BENCH_FILE)\"" not in bench_body:
        raise AssertionError("decision-gate benchmark verification can reuse a stale output artifact")
    if bench_body.index('rm -f "$(DECISION_GATE_BENCH_FILE)"') > bench_body.index(
        "bench_decision_gate.py --self-test"
    ):
        raise AssertionError("decision-gate benchmark output is removed after rather than before regeneration")

    if "override PRODUCTION_PLATFORM := linux/amd64" not in makefile:
        raise AssertionError("production release platform is not pinned to linux/amd64")
    if build_production_images.PRODUCTION_PLATFORM != "linux/amd64":
        raise AssertionError("production image helper platform differs from the release contract")
    try:
        build_production_images.build_command(
            "Dockerfile.production",
            "serverware/control:test",
            platform="linux/arm64",
            metadata=build_metadata_fixture(),
            context=ROOT,
        )
    except RuntimeError as exc:
        if "linux/amd64" not in str(exc):
            raise AssertionError(f"unexpected platform rejection: {exc}") from exc
    else:
        raise AssertionError("production image helper accepted a non-linux/amd64 platform")
    build_images_body = target_body(makefile, "build-production-images")
    if '--platform "$(PRODUCTION_PLATFORM)"' not in build_images_body:
        raise AssertionError("production image target does not pass the pinned platform")
    if "build-production-images: verify-production-dependency-cache" not in makefile:
        raise AssertionError("production image build does not verify its offline dependency cache")
    dry_run_command = build_production_images.build_command(
        "Dockerfile.production",
        "serverware/control:test",
        platform="linux/amd64",
        metadata=build_metadata_fixture(),
        context=ROOT,
    )
    if "--network=none" not in dry_run_command:
        raise AssertionError("production image helper does not disable build-step networking")
    publish_images_body = target_body(makefile, "publish-production-images")
    for required in ("docker image inspect", "{{.Os}}/{{.Architecture}}", "$(PRODUCTION_PLATFORM)"):
        if required not in publish_images_body:
            raise AssertionError(f"production publication does not enforce platform binding: {required}")
    runtime_body = target_body(makefile, "build-production-python-runtime")
    for required in ('--platform "$(PRODUCTION_PLATFORM)"', "--network=none"):
        if required not in runtime_body:
            raise AssertionError(f"production Python runtime omits {required}")
    for target in (
        "build-production-python-runtime",
        "build-production-launcher",
    ):
        if f"{target}: verify-production-dependency-cache" not in makefile:
            raise AssertionError(f"{target} does not verify its offline dependency cache")
    dependency_cache_body = target_body(makefile, "verify-production-dependency-cache")
    if "production-dependencies/prefetch.py verify" not in dependency_cache_body:
        raise AssertionError("production dependency cache target does not fail closed on manifest drift")
    fetch_cache_body = target_body(makefile, "fetch-production-dependency-cache")
    if "production-dependencies/prefetch.py fetch" not in fetch_cache_body:
        raise AssertionError("production cache fetch rewrites pins instead of verifying them")
    prefetch_path = ROOT / "production-dependencies" / "prefetch.py"
    prefetch_spec = importlib.util.spec_from_file_location(
        "serverware_production_dependency_prefetch", prefetch_path
    )
    if prefetch_spec is None or prefetch_spec.loader is None:
        raise AssertionError("could not load production dependency cache verifier")
    prefetch = importlib.util.module_from_spec(prefetch_spec)
    prefetch_spec.loader.exec_module(prefetch)
    (ROOT / ".tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / ".tmp") as temporary_directory:
        temporary_root = Path(temporary_directory)
        first_input = temporary_root / "requirements.lock"
        second_input = temporary_root / "cache.tar.gz"
        first_input.write_bytes(b"locked dependency\n")
        second_input.write_bytes(b"pinned cache archive\n")
        inputs = ("requirements.lock", "cache/archive.tar.gz")
        paths = {
            "requirements.lock": first_input,
            "cache/archive.tar.gz": second_input,
        }
        prefetch.input_path = paths.__getitem__
        valid_manifest = temporary_root / "valid.sha256"
        valid_manifest.write_text(prefetch.manifest_text(inputs), encoding="ascii")
        prefetch.verify_manifest(valid_manifest, inputs)
        substituted_manifest = temporary_root / "substituted.sha256"
        substituted_manifest.write_text(
            "0" * 64 + "  requirements.lock\n", encoding="ascii"
        )
        try:
            prefetch.verify_manifest(substituted_manifest, inputs)
        except RuntimeError as exc:
            if "does not match" not in str(exc):
                raise AssertionError(f"unexpected dependency drift rejection: {exc}") from exc
        else:
            raise AssertionError("production dependency verifier accepted a substituted manifest")

    production_dockerfiles = (
        ROOT / "Dockerfile.production",
        ROOT / "data-plane" / "decision-gate-rs" / "Dockerfile.production",
    )
    for dockerfile in production_dockerfiles:
        contents = dockerfile.read_text(encoding="utf-8")
        run_lines = [line for line in contents.splitlines() if line.startswith("RUN ")]
        if not run_lines or any("--network=none" not in line for line in run_lines):
            raise AssertionError(f"{dockerfile.relative_to(ROOT)} has a network-enabled RUN step")
        for forbidden in ("apt-get ", "apk update", "cargo fetch", "pip download"):
            if forbidden in contents:
                raise AssertionError(
                    f"{dockerfile.relative_to(ROOT)} resolves {forbidden.strip()} during production build"
                )

    wheel_body = target_body(makefile, "build-agent-enrollment-wheel")
    if (
        "AGENT_ENROLLMENT_WHEEL_FILENAME ?= $(shell python3 -c "
        "'from serverware_agent_trust.build_backend import WHEEL_NAME; print(WHEEL_NAME)')"
        not in makefile
    ):
        raise AssertionError("agent enrollment wheel filename is not sourced from build_backend.WHEEL_NAME")
    for required in (
        "AGENT_ENROLLMENT_WHEEL_DIRECTORY must resolve below the repository .tmp directory",
        "pip download",
        "--require-hashes",
        "--only-binary=:all:",
        '--platform "$(AGENT_ENROLLMENT_TARGET_PLATFORM)"',
        "--implementation cp",
        '--python-version "$(AGENT_ENROLLMENT_TARGET_PYTHON)"',
        '--abi "$(AGENT_ENROLLMENT_TARGET_ABI)"',
        "$(AGENT_ENROLLMENT_RUNTIME_LOCK)",
        '"$(AGENT_ENROLLMENT_WHEEL_DIRECTORY)/requirements.lock"',
        "--no-build-isolation",
        "--no-deps",
        "$(AGENT_ENROLLMENT_WHEEL_FILENAME)",
        "generate_offline_artifact_manifest.py",
        "verify_offline_artifact_manifest.py",
        "$(AGENT_ENROLLMENT_WHEEL_MANIFEST)",
        "$(AGENT_ENROLLMENT_WHEEL_CHECKSUMS)",
        "--checksums",
        "SHA256SUMS",
        "shasum -a 256 -c SHA256SUMS",
        "sha256sum -c SHA256SUMS",
        "--python-tag cp311",
        '"$(AGENT_ENROLLMENT_TARGET_PLATFORM)"',
        "--architecture amd64",
    ):
        if required not in wheel_body:
            raise AssertionError(f"clean-room wheel build target omits {required}")
    if wheel_body.index("must resolve below") > wheel_body.index('rm -rf "'):
        raise AssertionError(
            "wheelhouse path guard must execute before recursive cleanup"
        )
    generate_position = wheel_body.index("generate_offline_artifact_manifest.py")
    checksum_position = wheel_body.index("shasum -a 256 -c SHA256SUMS")
    verify_position = wheel_body.index("verify_offline_artifact_manifest.py")
    if not generate_position < checksum_position < verify_position:
        raise AssertionError("wheel build must generate, standard-verify, then Python-verify SHA256SUMS")
    with tempfile.TemporaryDirectory(dir=ROOT / ".tmp") as temporary_directory:
        wheelhouse = Path(temporary_directory)
        package_wheel_name = subprocess.check_output(
            [
                sys.executable,
                "-c",
                "from serverware_agent_trust.build_backend import WHEEL_NAME; print(WHEEL_NAME)",
            ],
            cwd=ROOT,
            text=True,
        ).strip()
        package_wheel = wheelhouse / package_wheel_name
        package_wheel_bytes = b"package wheel bytes"
        package_wheel.write_bytes(package_wheel_bytes)
        cryptography_wheel = wheelhouse / "cryptography-48.0.1-cp311-manylinux2014_x86_64.whl"
        cryptography_wheel_bytes = b"cryptography wheel bytes"
        cryptography_wheel.write_bytes(
            cryptography_wheel_bytes
        )
        (wheelhouse / "cffi-2.1.0-cp311-manylinux2014_x86_64.whl").write_bytes(
            b"cffi wheel bytes"
        )
        (wheelhouse / "pycparser-3.0-py3-none-any.whl").write_bytes(
            b"pycparser wheel bytes"
        )
        (wheelhouse / "requirements.lock").write_bytes(b"locked requirements\n")
        manifest = wheelhouse / "wheelhouse-manifest.json"
        checksums = wheelhouse / "SHA256SUMS"
        common = [
            "--root",
            str(wheelhouse),
            "--label",
            "serverware-enrollment-cpython311-linux-amd64",
            "--python-tag",
            "cp311",
            "--platform-tag",
            "manylinux2014_x86_64",
            "--architecture",
            "amd64",
        ]
        generate = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "generate_offline_artifact_manifest.py"),
                "--output",
                str(manifest),
                "--checksums",
                str(checksums),
                *common,
                "--require",
                package_wheel_name,
                "--require",
                "cryptography-*.whl",
                "--require",
                "cffi-*.whl",
                "--require",
                "pycparser-*.whl",
                "--require",
                "requirements.lock",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if generate.returncode != 0:
            raise AssertionError(f"wheel manifest generation failed: {generate.stderr}")
        first_manifest = manifest.read_bytes()
        first_checksums = checksums.read_bytes()
        regenerated = subprocess.run(
            generate.args,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if regenerated.returncode != 0:
            raise AssertionError(f"wheel manifest regeneration failed: {regenerated.stderr}")
        if manifest.read_bytes() != first_manifest or checksums.read_bytes() != first_checksums:
            raise AssertionError("wheel manifest or SHA256SUMS output is not deterministic")

        checksum_lines = checksums.read_text(encoding="ascii").splitlines()
        expected_checksum_names = sorted(
            path.name for path in wheelhouse.iterdir() if path.name != checksums.name
        )
        actual_checksum_names = []
        for line in checksum_lines:
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,254})", line)
            if match is None:
                raise AssertionError(f"SHA256SUMS contains a non-canonical line: {line!r}")
            digest, name = match.groups()
            actual_checksum_names.append(name)
            if digest != hashlib.sha256((wheelhouse / name).read_bytes()).hexdigest():
                raise AssertionError(f"SHA256SUMS contains the wrong digest for {name}")
        if actual_checksum_names != expected_checksum_names:
            raise AssertionError(
                f"SHA256SUMS coverage differs: {actual_checksum_names} != {expected_checksum_names}"
            )

        if shutil.which("shasum"):
            standard_checksum_command = ["shasum", "-a", "256", "-c", checksums.name]
        elif shutil.which("sha256sum"):
            standard_checksum_command = ["sha256sum", "-c", checksums.name]
        else:
            raise AssertionError("focused wheelhouse test requires shasum or sha256sum")
        standard_verified = subprocess.run(
            standard_checksum_command,
            cwd=wheelhouse,
            text=True,
            capture_output=True,
            check=False,
        )
        if standard_verified.returncode != 0:
            raise AssertionError(
                f"standard SHA256SUMS verification failed: {standard_verified.stderr}"
            )
        verify_command = [
            sys.executable,
            str(ROOT / "scripts" / "verify_offline_artifact_manifest.py"),
            "--manifest",
            str(manifest),
            "--checksums",
            str(checksums),
            *common,
        ]
        verified = subprocess.run(
            verify_command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if verified.returncode != 0:
            raise AssertionError(f"wheel manifest verification failed: {verified.stderr}")
        verification = json.loads(verified.stdout)
        if verification.get("manifest_sha256", "").startswith("sha256:") is not True:
            raise AssertionError("wheel manifest verifier did not emit its manifest digest")
        if verification.get("checksums_sha256", "").startswith("sha256:") is not True:
            raise AssertionError("wheel manifest verifier did not emit the SHA256SUMS digest")

        package_wheel.write_bytes(b"X" * len(package_wheel_bytes))
        standard_substituted = subprocess.run(
            standard_checksum_command,
            cwd=wheelhouse,
            text=True,
            capture_output=True,
            check=False,
        )
        if standard_substituted.returncode == 0:
            raise AssertionError("standard SHA256SUMS verification accepted a substituted wheel")
        substituted = subprocess.run(
            verify_command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if substituted.returncode == 0 or "SHA-256 mismatch" not in substituted.stderr:
            raise AssertionError("wheel manifest verifier accepted a substituted package wheel")
        package_wheel.write_bytes(package_wheel_bytes)

        cryptography_wheel.unlink()
        missing = subprocess.run(
            verify_command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if missing.returncode == 0 or "artifact set differs" not in missing.stderr:
            raise AssertionError("wheel manifest verifier accepted a missing dependency wheel")
        missing_standard = subprocess.run(
            standard_checksum_command,
            cwd=wheelhouse,
            text=True,
            capture_output=True,
            check=False,
        )
        if missing_standard.returncode == 0:
            raise AssertionError("standard SHA256SUMS verification accepted a missing dependency wheel")
        cryptography_wheel.write_bytes(cryptography_wheel_bytes)

        unexpected = wheelhouse / "unexpected.whl"
        unexpected.write_bytes(b"unexpected wheel")
        extra = subprocess.run(
            verify_command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if extra.returncode == 0 or "artifact set differs" not in extra.stderr:
            raise AssertionError("wheel manifest verifier accepted an extra wheelhouse artifact")
        unexpected.unlink()
    agent_enrollment_body = target_body(makefile, "verify-agent-enrollment")
    if "scripts/test_agent_enrollment.py" not in agent_enrollment_body:
        raise AssertionError("agent enrollment gate omits its clean-room and receipt contract test")
    setup_session_body = target_body(makefile, "verify-setup-session-api")
    if "scripts/test_setup_session_api.py" not in setup_session_body:
        raise AssertionError("setup-session gate omits its API test")

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
