#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_production_images  # noqa: E402
import generate_release_provenance  # noqa: E402
import publish_production_images  # noqa: E402
import test_release_completion  # noqa: E402
import verify_reproducible_builds  # noqa: E402


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_json(value: object) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def release_key_info() -> dict[str, object]:
    key = Ed25519PrivateKey.from_private_bytes(b"\x0e" * 32)
    public_key = key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"key": key, "public_key_pem": pem, "key_id": sha256_bytes(der)}


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def write_env(path: Path, env: dict[str, str]) -> None:
    path.write_text(
        "\n".join(f"{key}={shlex.quote(value)}" for key, value in sorted(env.items()))
        + "\n",
        encoding="utf-8",
    )


def digest(char: str) -> str:
    return "sha256:" + char * 64


LAUNCH_AUTHORITY_KEY_ID = digest("1")
LAUNCH_AUTHORITY_ROOT_SHA256 = digest("2")
DEPLOYMENT_AUDIENCE = "serverware.production.us-east-1"
DEPLOYMENT_IDENTITY_SHA256 = digest("6")
RELEASE_SEQUENCE = "42"
ROLLBACK_EPOCH = "3"
LAUNCH_ENV_KEYS = (
    "PRODUCTION_DEPLOYMENT_AUDIENCE",
    "PRODUCTION_DEPLOYMENT_IDENTITY_SHA256",
    "PRODUCTION_RELEASE_SEQUENCE",
    "PRODUCTION_ROLLBACK_EPOCH",
)
VALID_LAUNCH_ARGUMENTS = (
    "--deployment-audience",
    DEPLOYMENT_AUDIENCE,
    "--deployment-identity-sha256",
    DEPLOYMENT_IDENTITY_SHA256,
    "--release-sequence",
    RELEASE_SEQUENCE,
    "--rollback-epoch",
    ROLLBACK_EPOCH,
)


def fixture_release_trust_env(paths: dict[str, Path]) -> dict[str, str]:
    return {
        "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY": str(
            paths["release_trust_root"]
        ),
        "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY": str(paths["sigstore_trust_root"]),
        "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY": str(paths["rekor_trust_root"]),
        "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY": str(
            paths["external_trust_root"]
        ),
        "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER": "managed-prod-log",
        "SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER": "managed-prod-log",
        "SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID": str(
            test_release_completion.external_receipt_key_info()["key_id"]
        ),
        "SERVERWARE_COSIGN_KEY_ID": str(
            test_release_completion.sigstore_signing_key_info()["key_id"]
        ),
        "SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID": str(
            test_release_completion.rekor_key_info()["key_id"]
        ),
    }


def write_fixture_artifacts(tmp: Path, *, p99_ms: float = 6.0) -> dict[str, Path]:
    build = tmp / "production-images-build.json"
    provenance_summary = tmp / "release-provenance-summary.json"
    provenance = tmp / "release-provenance.json"
    image_signatures_summary = tmp / "image-signatures-summary.json"
    image_signatures = tmp / "image-signatures.json"
    published = tmp / "production-images-published.json"
    reproducible = tmp / "reproducible-build-verification.json"
    bench = tmp / "bench.json"
    images_env = tmp / "production-images.env"
    env = tmp / "production.env"
    env_template = tmp / "production.env.example"
    release_trust_root = tmp / "release-signing.pub.pem"
    sigstore_trust_root = tmp / "sigstore-signing.pub.pem"
    rekor_trust_root = tmp / "rekor.pub.pem"
    external_trust_root = tmp / "external-checkpoint.pub.pem"
    source_tree_digest = build_production_images.source_tree_digest()
    control_ref = "registry.prod.serverware.dev/serverware/control@" + digest("a")
    gate_ref = "registry.prod.serverware.dev/serverware/decision-gate@" + digest("b")

    reproducible_document = {
        "apiVersion": verify_reproducible_builds.VERIFICATION_API_VERSION,
        "kind": verify_reproducible_builds.VERIFICATION_KIND,
        "ok": True,
        "reproducible": True,
        "scope": {
            "artifact_reproducibility_only": True,
            "independent_execution_proven": True,
            "hardware_proof": False,
        },
        "inputs": {
            "left": {
                "attestation": {
                    "builder_id": "builder.example/alpha",
                    "key_id": digest("3"),
                    "signature_verified": True,
                    "operator_trusted": True,
                }
            },
            "right": {
                "attestation": {
                    "builder_id": "builder.example/bravo",
                    "key_id": digest("4"),
                    "signature_verified": True,
                    "operator_trusted": True,
                }
            },
        },
        "source_tree_digest": source_tree_digest,
        "comparison_sha256": digest("5"),
        "images": [
            {"service": "serverware-control", "image_id": digest("a")},
            {
                "service": "serverware-decision-gate",
                "image_id": digest("b"),
                "rust_binary_sha256": digest("9"),
                "launcher_binary_sha256": digest("e"),
                "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
                "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
            },
        ],
        "mismatches": [],
    }
    write_json(reproducible, reproducible_document)
    reproducible_sha256 = sha256_bytes(reproducible.read_bytes())
    reproducible_binding = {
        "apiVersion": verify_reproducible_builds.VERIFICATION_API_VERSION,
        "kind": verify_reproducible_builds.VERIFICATION_KIND,
        "verification_sha256": reproducible_sha256,
        "comparison_sha256": digest("5"),
        "source_tree_digest": source_tree_digest,
        "builders": [
            {"builder_id": "builder.example/alpha", "key_id": digest("3")},
            {"builder_id": "builder.example/bravo", "key_id": digest("4")},
        ],
        "launcher_binary_sha256": digest("e"),
        "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
        "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
    }

    write_json(
        build,
        {
            "apiVersion": build_production_images.BUILD_API_VERSION,
            "kind": build_production_images.BUILD_KIND,
            "ok": True,
            "metadata": {
                "source_tree_digest": source_tree_digest,
                "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
                "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
            },
            "images": [
                {
                    "service": "serverware-control",
                    "dockerfile": "Dockerfile.production",
                    "image_id": digest("a"),
                },
                {
                    "service": "serverware-decision-gate",
                    "dockerfile": "data-plane/decision-gate-rs/Dockerfile.production",
                    "image_id": digest("b"),
                    "binary_digest": digest("9"),
                    "launcher_binary_digest": digest("e"),
                    "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
                    "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
                },
            ],
            "no_shell": {"ok": True, "results": [{"ok": True}, {"ok": True}]},
        },
    )
    provenance_payload = {
        "version": generate_release_provenance.PRODUCTION_PROVENANCE_VERSION,
        "source": "serverware-digest-pinned-production-release",
        "source_tree": {"digest": source_tree_digest},
        "compose_config_sha256": digest("c"),
        "compose": {
            "file": "docker-compose.production.yml",
            "sha256": digest("c"),
        },
        "sbom": {"cyclonedx": {"sha256": digest("d"), "components": 204}},
        "images": {
            "serverware-control": {"image_id": digest("a")},
            "serverware-decision-gate": {
                "image_id": digest("b"),
                "binary_digest": digest("9"),
                "launcher_binary_digest": digest("e"),
                "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
                "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
            },
        },
        "launch_authority": {
            "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
            "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
        },
        "reproducible_build": reproducible_binding,
    }
    release_key = release_key_info()
    release_key_id = str(release_key["key_id"])
    release_trust_root.write_text(str(release_key["public_key_pem"]), encoding="ascii")
    sigstore_trust_root.write_text(
        str(test_release_completion.sigstore_signing_key_info()["public_key_pem"]),
        encoding="ascii",
    )
    rekor_trust_root.write_text(
        str(test_release_completion.rekor_key_info()["public_key_pem"]),
        encoding="ascii",
    )
    external_trust_root.write_text(
        str(test_release_completion.external_receipt_key_info()["public_key_pem"]),
        encoding="ascii",
    )
    provenance_digest = sha256_json(provenance_payload)
    provenance_signature = "ed25519:" + b64e(
        release_key["key"].sign(canonical_json(provenance_payload).encode("utf-8"))
    )
    provenance_record = {
        "type": generate_release_provenance.PRODUCTION_PROVENANCE_RECORD_TYPE,
        "provenance_digest": provenance_digest,
        "signature": provenance_signature,
        "release_signing_key_id": release_key_id,
        "production_launcher_binary_digest": digest("e"),
        "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
        "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
        "reproducible_build_verification_sha256": reproducible_sha256,
    }
    write_json(
        provenance_summary,
        {
            "ok": True,
            "release_provenance": "pass",
            "anchored": True,
            "inclusion_verified": True,
            "provenance_digest": provenance_digest,
            "release_signing_key_id": release_key_id,
            "production_launcher_binary_digest": digest("e"),
            "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
            "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
            "reproducible_build_verification_sha256": reproducible_sha256,
            "transparency_mode": "signed-merkle-transparency-log",
        },
    )
    write_json(
        provenance,
        {
            "provenance_digest": provenance_digest,
            "provenance": provenance_payload,
            "release_signing_key_id": release_key_id,
            "release_signing_public_key_pem": str(release_key["public_key_pem"]),
            "signature": provenance_signature,
            "transparency": test_release_completion.transparency_for_record(
                provenance_record
            ),
        },
    )
    image_signature_payload = {
        "apiVersion": "serverware.imageSignatures/v1",
        "images": [
            {
                "service": "serverware-control",
                "image_id": digest("a"),
                "statement": {
                    "predicate": {
                        "image_id": digest("a"),
                        "repo_digests": [control_ref],
                        "release_signing_key_id": release_key_id,
                        "source_tree_digest": source_tree_digest,
                        "compose_config_sha256": digest("c"),
                        "sbom_cyclonedx_sha256": digest("d"),
                        "sbom_cyclonedx_components": 204,
                    }
                },
            },
            {
                "service": "serverware-decision-gate",
                "image_id": digest("b"),
                "statement": {
                    "predicate": {
                        "image_id": digest("b"),
                        "repo_digests": [gate_ref],
                        "release_signing_key_id": release_key_id,
                        "source_tree_digest": source_tree_digest,
                        "compose_config_sha256": digest("c"),
                        "sbom_cyclonedx_sha256": digest("d"),
                        "sbom_cyclonedx_components": 204,
                    }
                },
            },
        ],
        "kind": "ImageSignatures",
        "metadata": {
            "provenanceDigest": provenance_digest,
            "releaseSigningKeyId": release_key_id,
            "imageSigningKeyId": test_release_completion.sigstore_signing_key_info()[
                "key_id"
            ],
            "signatureProvider": "sigstore-command",
            "sigstoreTransparencyRequired": True,
            "sourceTreeDigest": source_tree_digest,
            "composeConfigSha256": digest("c"),
            "sbomCyclonedxSha256": digest("d"),
        },
    }
    for image in image_signature_payload["images"]:
        statement_digest = sha256_json(image["statement"])
        image["statement_digest"] = statement_digest
        image["sigstore"] = test_release_completion.sigstore_proof(
            statement=image["statement"]
        )
        image["signature"] = image["sigstore"]["signature"]
    image_signature_digest = sha256_json(image_signature_payload)
    bundle_sigstore = test_release_completion.sigstore_proof(
        statement=image_signature_payload,
    )
    image_signature_payload["bundle_signature"] = bundle_sigstore
    image_signature_payload["metadata"]["signature"] = bundle_sigstore["signature"]
    image_signature_payload["metadata"]["bundleSigstore"] = bundle_sigstore
    image_signature_payload["image_signature_bundle_digest"] = image_signature_digest
    image_record = {
        "type": "release.image_signatures.v1",
        "provenance_digest": provenance_digest,
        "image_signature_bundle_digest": image_signature_digest,
        "image_signing_key_id": test_release_completion.sigstore_signing_key_info()[
            "key_id"
        ],
        "image_signature_provider": "sigstore-command",
        "release_signing_key_id": release_key_id,
        "signature": bundle_sigstore["signature"],
        "images": {
            item["service"]: item["image_id"]
            for item in image_signature_payload["images"]
        },
    }
    image_signature_payload["metadata"]["transparency"] = (
        test_release_completion.transparency_for_record(
            image_record,
            anchor_key="anchorResponse",
            inclusion_key="inclusionProof",
        )
    )
    write_json(
        image_signatures_summary,
        {
            "ok": True,
            "image_signatures": "pass",
            "image_signature_provider": "sigstore-command",
            "inclusion_verified": True,
            "image_signature_bundle_digest": image_signature_digest,
            "provenance_digest": provenance_digest,
            "release_signing_key_id": release_key_id,
            "image_signing_key_id": digest("3"),
            "images": len(image_signature_payload["images"]),
            "transparency_mode": "signed-merkle-transparency-log",
        },
    )
    write_json(image_signatures, image_signature_payload)
    write_json(
        bench,
        {
            "candidate": "rust-decision-gate",
            "requests": 1000,
            "warmup": 100,
            "p50_ms": 1.0,
            "p95_ms": 2.0,
            "p99_ms": p99_ms,
            "data_plane_binary_digest": digest("9"),
            "policy_hash": digest("8"),
            "runtime_manifest_digest": digest("7"),
            "attestation_nonce_before": "benchmark-nonce-before",
            "attestation_nonce_after": "benchmark-nonce-after",
        },
    )
    images_env.write_text(
        "SERVERWARE_PRODUCTION_IMAGES=" + ",".join([control_ref, gate_ref]) + "\n",
        encoding="utf-8",
    )
    write_json(
        published,
        {
            "apiVersion": publish_production_images.PUBLISHED_API_VERSION,
            "kind": publish_production_images.PUBLISHED_KIND,
            "ok": True,
            "source_build_file": str(build),
            "images": [
                {
                    "service": "serverware-control",
                    "local_image_id": digest("a"),
                    "tag": "registry.prod.serverware.dev/serverware/control:production-candidate",
                    "repo_digest": control_ref,
                    "config_id": digest("a"),
                    "remote_image_id": digest("a"),
                },
                {
                    "service": "serverware-decision-gate",
                    "local_image_id": digest("b"),
                    "tag": "registry.prod.serverware.dev/serverware/decision-gate:production-candidate",
                    "repo_digest": gate_ref,
                    "config_id": digest("b"),
                    "remote_image_id": digest("b"),
                    "binary_digest": digest("9"),
                    "launcher_binary_digest": digest("e"),
                    "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
                    "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
                },
            ],
            "remote_no_shell": {"ok": True},
            "env": {"SERVERWARE_PRODUCTION_IMAGES": ",".join([control_ref, gate_ref])},
        },
    )
    paths = {
        "release_trust_root": release_trust_root,
        "sigstore_trust_root": sigstore_trust_root,
        "rekor_trust_root": rekor_trust_root,
        "external_trust_root": external_trust_root,
    }
    write_env(
        env,
        {
            **fixture_release_trust_env(paths),
            "SERVERWARE_ADMIN_TOKEN": "prod-admin-token-32-byte-secret-value",
            "SERVERWARE_OIDC_JWKS_JSON": canonical_json({"keys": [{"kid": "prod"}]}),
        },
    )
    env_template.write_text("SERVERWARE_ADMIN_TOKEN=<secret>\n", encoding="utf-8")
    return {
        "build": build,
        "provenance_summary": provenance_summary,
        "provenance": provenance,
        "image_signatures_summary": image_signatures_summary,
        "image_signatures": image_signatures,
        "published": published,
        "reproducible": reproducible,
        "bench": bench,
        "images_env": images_env,
        "env": env,
        "env_template": env_template,
        **paths,
    }


def run_handoff(
    paths: dict[str, Path],
    *extra: str,
    check_current_tree: bool = False,
    launch_arguments: tuple[str, ...] = VALID_LAUNCH_ARGUMENTS,
    launch_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    registry_prefix = "registry.prod.serverware.dev/serverware"
    if extra and extra[0] == "--registry-prefix":
        registry_prefix = extra[1]
        extra = extra[2:]
    environment = {
        key: value for key, value in os.environ.items() if key not in LAUNCH_ENV_KEYS
    }
    environment.update(launch_environment or {})
    return subprocess.run(
        [
            sys.executable,
            "scripts/generate_production_handoff.py",
            "--production-images-build",
            str(paths["build"]),
            "--release-provenance-summary",
            str(paths["provenance_summary"]),
            "--release-provenance",
            str(paths["provenance"]),
            "--image-signatures-summary",
            str(paths["image_signatures_summary"]),
            "--image-signatures",
            str(paths["image_signatures"]),
            "--bench",
            str(paths["bench"]),
            "--production-images-env",
            str(paths["images_env"]),
            "--env-file",
            str(paths["env"]),
            "--env-template",
            str(paths["env_template"]),
            "--registry-prefix",
            registry_prefix,
            "--out",
            str(paths["build"].parent / "handoff.json"),
            *launch_arguments,
            *([] if check_current_tree else ["--skip-current-tree-check"]),
            *extra,
        ],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stdout.decode("utf-8", errors="replace") + result.stderr.decode(
        "utf-8", errors="replace"
    )


def expect_value_error(callback: object, expected: str) -> None:
    try:
        callback()
    except ValueError as exc:
        if expected not in str(exc):
            raise AssertionError(
                f"rejection did not mention {expected!r}: {exc}"
            ) from exc
        return
    raise AssertionError(f"invalid release input was accepted; expected {expected!r}")


def assert_release_input_bindings(paths: dict[str, Path]) -> None:
    build = json.loads(paths["build"].read_text(encoding="utf-8"))
    source_tree_digest = build["metadata"]["source_tree_digest"]

    def inventory() -> dict[str, object]:
        return generate_release_provenance.production_image_inventory(
            build_path=paths["build"],
            published_path=paths["published"],
            images_env_path=paths["images_env"],
            expected_source_tree_digest=source_tree_digest,
        )

    production_images = inventory()
    gate = production_images["serverware-decision-gate"]
    for field, expected in (
        ("launch_authority_key_id", LAUNCH_AUTHORITY_KEY_ID),
        ("launch_authority_root_sha256", LAUNCH_AUTHORITY_ROOT_SHA256),
    ):
        if gate.get(field) != expected:
            raise AssertionError(f"release inventory omitted {field}: {gate}")
    reproducible = generate_release_provenance.production_reproducibility_binding(
        paths["reproducible"],
        expected_source_tree_digest=source_tree_digest,
        expected_images=production_images,
    )
    if reproducible.get("verification_sha256") != sha256_bytes(
        paths["reproducible"].read_bytes()
    ):
        raise AssertionError(
            f"release provenance did not bind reproducibility evidence bytes: {reproducible}"
        )

    published = json.loads(paths["published"].read_text(encoding="utf-8"))
    reproducible_document = json.loads(
        paths["reproducible"].read_text(encoding="utf-8")
    )
    try:
        build["images"][1]["launch_authority_key_id"] = digest("8")
        write_json(paths["build"], build)
        expect_value_error(inventory, "does not match build metadata")
    finally:
        build["images"][1]["launch_authority_key_id"] = LAUNCH_AUTHORITY_KEY_ID
        write_json(paths["build"], build)

    try:
        published["images"][1]["launch_authority_root_sha256"] = digest("8")
        write_json(paths["published"], published)
        expect_value_error(inventory, "does not match the measured build")
    finally:
        published["images"][1]["launch_authority_root_sha256"] = (
            LAUNCH_AUTHORITY_ROOT_SHA256
        )
        write_json(paths["published"], published)

    try:
        reproducible_document["images"][1]["launch_authority_key_id"] = digest("8")
        write_json(paths["reproducible"], reproducible_document)
        expect_value_error(
            lambda: generate_release_provenance.production_reproducibility_binding(
                paths["reproducible"],
                expected_source_tree_digest=source_tree_digest,
                expected_images=production_images,
            ),
            "does not match build and publish evidence",
        )
    finally:
        reproducible_document["images"][1]["launch_authority_key_id"] = (
            LAUNCH_AUTHORITY_KEY_ID
        )
        write_json(paths["reproducible"], reproducible_document)


def main() -> None:
    if generate_release_provenance.PRODUCTION_PROVENANCE_VERSION != 2:
        raise AssertionError(
            f"production release provenance payload was not promoted to v2: "
            f"{generate_release_provenance.PRODUCTION_PROVENANCE_VERSION}"
        )
    if (
        generate_release_provenance.PRODUCTION_PROVENANCE_RECORD_TYPE
        != "release.provenance.v2"
    ):
        raise AssertionError(
            "production release provenance transparency record was not promoted to v2"
        )
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        paths = write_fixture_artifacts(tmp)
        assert_release_input_bindings(paths)
        result = run_handoff(paths, check_current_tree=True)
        if result.returncode != 0:
            raise AssertionError(f"handoff generation failed: {detail(result)}")
        output = json.loads(result.stdout.decode("utf-8"))
        if (
            output.get("ok") is not True
            or output.get("completion_state") != "pending-production-host"
        ):
            raise AssertionError(
                f"handoff output did not describe pending production completion: {output}"
            )
        if output.get("production_env", {}).get("status") != "valid":
            raise AssertionError(
                f"handoff did not validate the env file shape: {output}"
            )
        production_images = output.get("local_evidence", {}).get(
            "production_images", {}
        )
        provenance_summary = output.get("local_evidence", {}).get(
            "release_provenance", {}
        )
        provenance_document = output.get("local_evidence", {}).get(
            "release_provenance_document", {}
        )
        for field, expected in (
            ("launch_authority_key_id", LAUNCH_AUTHORITY_KEY_ID),
            ("launch_authority_root_sha256", LAUNCH_AUTHORITY_ROOT_SHA256),
        ):
            if (
                production_images.get(field) != expected
                or provenance_summary.get(field) != expected
                or provenance_document.get(field) != expected
            ):
                raise AssertionError(f"handoff did not preserve {field}: {output}")
        if "prod-admin-token-32-byte-secret-value" in result.stdout.decode("utf-8"):
            raise AssertionError("handoff leaked a production env value")
        publish_plan = output.get("production_commands", {}).get("publish_plan") or []
        if len(publish_plan) != 2 or not publish_plan[0].get("commands"):
            raise AssertionError(
                f"handoff did not include a concrete publish plan: {output}"
            )
        one_shot = output.get("production_commands", {}).get("one_shot_command") or []
        if one_shot[:2] != ["make", "production-release-proof"]:
            raise AssertionError(
                f"handoff did not include the one-shot production proof command: {output}"
            )
        expected_launch_variables = {
            f"PRODUCTION_DEPLOYMENT_AUDIENCE={DEPLOYMENT_AUDIENCE}",
            f"PRODUCTION_DEPLOYMENT_IDENTITY_SHA256={DEPLOYMENT_IDENTITY_SHA256}",
            f"PRODUCTION_RELEASE_SEQUENCE={RELEASE_SEQUENCE}",
            f"PRODUCTION_ROLLBACK_EPOCH={ROLLBACK_EPOCH}",
        }
        if not expected_launch_variables.issubset(one_shot):
            raise AssertionError(
                f"one-shot production proof omitted launch-manifest inputs: {output}"
            )
        if output.get("production_images_env", {}).get("status") != "valid":
            raise AssertionError(
                f"handoff did not validate the production images env fragment: {output}"
            )
        if (
            output.get("local_evidence", {})
            .get("image_signatures", {})
            .get("covers_published_production_images")
            is not True
        ):
            raise AssertionError(
                f"handoff did not verify signatures against published image digest refs: {output}"
            )
        commands = output.get("production_commands", {}).get("commands") or []
        required_order = [
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
        actual_order = [
            command[1]
            for command in commands
            if isinstance(command, list) and len(command) >= 2 and command[0] == "make"
        ]
        positions = [
            actual_order.index(target) if target in actual_order else -1
            for target in required_order
        ]
        if any(position < 0 for position in positions) or positions != sorted(
            positions
        ):
            raise AssertionError(
                f"handoff command list does not match the production proof order: {output}"
            )
        sign_runs = [
            command
            for command in commands
            if command[:2] == ["make", "sign-production-images"]
        ]
        if not sign_runs:
            raise AssertionError(
                f"handoff did not include the checked production image signing target: {output}"
            )
        if not any(
            item.startswith("PRODUCTION_READINESS_ENV=") for item in sign_runs[0]
        ):
            raise AssertionError(
                f"handoff image signing command did not preserve the production env path: {output}"
            )
        if not any(
            command[:2] == ["make", "merge-production-images-env"]
            for command in commands
        ):
            raise AssertionError(
                f"handoff did not include the checked production image env merge target: {output}"
            )
        manifest_runs = [
            command
            for command in commands
            if command[:2] == ["make", "generate-production-launch-manifest"]
        ]
        if (
            not manifest_runs
            or not any(
                item.startswith(
                    "PRODUCTION_RELEASE_ROOT=/opt/serverware/releases/sha256-"
                )
                for item in manifest_runs[0]
            )
            or not any(
                item.startswith("PRODUCTION_SOURCE_TREE_DIGEST=sha256:")
                for item in manifest_runs[0]
            )
            or not expected_launch_variables.issubset(manifest_runs[0])
        ):
            raise AssertionError(
                f"handoff did not bind the installed release tree to the source digest: {output}"
            )
        install_runs = [
            command
            for command in commands
            if command[:2] == ["make", "install-production-launcher"]
        ]
        if not install_runs or not expected_launch_variables.issubset(install_runs[0]):
            raise AssertionError(
                f"handoff launcher install omitted launch-manifest inputs: {output}"
            )
        final_runs = [
            command
            for command in commands
            if command[:2] == ["make", "run-production-readiness-final"]
        ]
        if not final_runs:
            raise AssertionError(
                f"handoff omitted the systemd final readiness command: {output}"
            )

        placeholder = run_handoff(
            paths, "--registry-prefix", "registry.example/serverware"
        )
        if placeholder.returncode == 0 or "placeholder .example registry" not in detail(
            placeholder
        ):
            raise AssertionError(
                f"handoff accepted a placeholder registry prefix: {detail(placeholder)}"
            )

        env_backed = run_handoff(
            paths,
            launch_arguments=(),
            launch_environment={
                "PRODUCTION_DEPLOYMENT_AUDIENCE": DEPLOYMENT_AUDIENCE,
                "PRODUCTION_DEPLOYMENT_IDENTITY_SHA256": DEPLOYMENT_IDENTITY_SHA256,
                "PRODUCTION_RELEASE_SEQUENCE": RELEASE_SEQUENCE,
                "PRODUCTION_ROLLBACK_EPOCH": ROLLBACK_EPOCH,
            },
        )
        if env_backed.returncode != 0:
            raise AssertionError(
                f"handoff rejected valid env-backed launch inputs: {detail(env_backed)}"
            )
        env_output = json.loads(env_backed.stdout.decode("utf-8"))
        env_one_shot = (
            env_output.get("production_commands", {}).get("one_shot_command") or []
        )
        if not expected_launch_variables.issubset(env_one_shot):
            raise AssertionError(
                f"handoff did not propagate env-backed launch inputs: {env_output}"
            )

        missing_launch_inputs = run_handoff(paths, launch_arguments=())
        if (
            missing_launch_inputs.returncode == 0
            or "production deployment audience" not in detail(missing_launch_inputs)
        ):
            raise AssertionError(
                f"handoff accepted missing launch-manifest inputs: {detail(missing_launch_inputs)}"
            )

        invalid_launch_inputs = (
            ("--deployment-audience", "Production", "deployment audience"),
            ("--deployment-identity-sha256", digest("A"), "deployment identity digest"),
            ("--release-sequence", "0", "release sequence"),
            ("--release-sequence", "01", "release sequence"),
            ("--release-sequence", str(9_007_199_254_740_992), "release sequence"),
            ("--rollback-epoch", "-1", "rollback epoch"),
            ("--rollback-epoch", "00", "rollback epoch"),
            ("--rollback-epoch", str(9_007_199_254_740_992), "rollback epoch"),
        )
        for argument, value, expected_error in invalid_launch_inputs:
            invalid = run_handoff(paths, argument, value)
            if invalid.returncode == 0 or expected_error not in detail(invalid):
                raise AssertionError(
                    f"handoff accepted invalid {argument}={value!r}: {detail(invalid)}"
                )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        bad_paths = write_fixture_artifacts(tmp, p99_ms=25.0)
        bad = run_handoff(bad_paths)
        if bad.returncode == 0 or "p99_ms" not in detail(bad):
            raise AssertionError(
                f"handoff accepted a benchmark over target: {detail(bad)}"
            )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        stale_paths = write_fixture_artifacts(tmp)
        build = json.loads(stale_paths["build"].read_text(encoding="utf-8"))
        build["metadata"]["source_tree_digest"] = digest("f")
        write_json(stale_paths["build"], build)
        stale = run_handoff(stale_paths, check_current_tree=True)
        if stale.returncode == 0 or "stale" not in detail(stale):
            raise AssertionError(
                f"handoff accepted stale source-tree evidence: {detail(stale)}"
            )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        authority_paths = write_fixture_artifacts(tmp)
        summary = json.loads(
            authority_paths["provenance_summary"].read_text(encoding="utf-8")
        )
        summary["launch_authority_root_sha256"] = digest("8")
        write_json(authority_paths["provenance_summary"], summary)
        authority_mismatch = run_handoff(authority_paths)
        if (
            authority_mismatch.returncode == 0
            or "launch-authority binding" not in detail(authority_mismatch)
        ):
            raise AssertionError(
                f"handoff accepted a mismatched launch-authority summary: {detail(authority_mismatch)}"
            )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        mismatch_paths = write_fixture_artifacts(tmp)
        provenance = json.loads(
            mismatch_paths["provenance"].read_text(encoding="utf-8")
        )
        provenance["provenance"]["source_tree"]["digest"] = digest("9")
        provenance["provenance_digest"] = sha256_json(provenance["provenance"])
        write_json(mismatch_paths["provenance"], provenance)
        mismatch = run_handoff(mismatch_paths)
        if mismatch.returncode == 0 or "summary digest" not in detail(mismatch):
            raise AssertionError(
                f"handoff accepted mismatched provenance evidence: {detail(mismatch)}"
            )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        forged_paths = write_fixture_artifacts(tmp)
        provenance = json.loads(forged_paths["provenance"].read_text(encoding="utf-8"))
        provenance["signature"] = "ed25519:test"
        write_json(forged_paths["provenance"], provenance)
        forged = run_handoff(forged_paths)
        if (
            forged.returncode == 0
            or "release provenance signature verification failed" not in detail(forged)
        ):
            raise AssertionError(
                f"handoff accepted forged release provenance: {detail(forged)}"
            )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        forged_transparency_paths = write_fixture_artifacts(tmp)
        provenance = json.loads(
            forged_transparency_paths["provenance"].read_text(encoding="utf-8")
        )
        provenance["transparency"]["anchor_response"]["anchors"][0][
            "external_checkpoint"
        ]["receipt"]["signature"] = "ed25519:test"
        provenance["transparency"]["inclusion_proof"]["item"]["external_checkpoint"][
            "receipt"
        ]["signature"] = "ed25519:test"
        write_json(forged_transparency_paths["provenance"], provenance)
        forged_transparency = run_handoff(forged_transparency_paths)
        if (
            forged_transparency.returncode == 0
            or "release provenance external transparency receipt signature"
            not in detail(forged_transparency)
        ):
            raise AssertionError(
                f"handoff accepted forged release transparency receipt: {detail(forged_transparency)}"
            )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        reused_final_key_paths = write_fixture_artifacts(tmp)
        reused_final_key_env = {
            **fixture_release_trust_env(reused_final_key_paths),
            "SERVERWARE_ADMIN_TOKEN": "prod-admin-token-32-byte-secret-value",
            "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY": str(
                reused_final_key_paths["release_trust_root"]
            ),
            "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID": str(
                release_key_info()["key_id"]
            ),
        }
        write_env(reused_final_key_paths["env"], reused_final_key_env)
        reused_final_key = run_handoff(reused_final_key_paths)
        if (
            reused_final_key.returncode == 0
            or "must not reuse a production release trust key"
            not in detail(reused_final_key)
        ):
            raise AssertionError(
                f"handoff accepted a final trust key reused for release provenance: {detail(reused_final_key)}"
            )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        sig_paths = write_fixture_artifacts(tmp)
        summary = json.loads(
            sig_paths["image_signatures_summary"].read_text(encoding="utf-8")
        )
        summary["image_signature_bundle_digest"] = digest("8")
        write_json(sig_paths["image_signatures_summary"], summary)
        sig_mismatch = run_handoff(sig_paths)
        if (
            sig_mismatch.returncode == 0
            or "image signature summary digest" not in detail(sig_mismatch)
        ):
            raise AssertionError(
                f"handoff accepted mismatched image-signature evidence: {detail(sig_mismatch)}"
            )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        release_key_paths = write_fixture_artifacts(tmp)
        image_signatures = json.loads(
            release_key_paths["image_signatures"].read_text(encoding="utf-8")
        )
        image_signatures["images"][0]["statement"]["predicate"][
            "release_signing_key_id"
        ] = digest("9")
        summary = json.loads(
            release_key_paths["image_signatures_summary"].read_text(encoding="utf-8")
        )
        test_release_completion.refresh_image_statements_and_bundle(
            summary, image_signatures
        )
        write_json(release_key_paths["image_signatures"], image_signatures)
        write_json(release_key_paths["image_signatures_summary"], summary)
        release_key_mismatch = run_handoff(release_key_paths)
        if (
            release_key_mismatch.returncode == 0
            or "release_signing_key_id" not in detail(release_key_mismatch)
        ):
            raise AssertionError(
                f"handoff accepted image signatures from another release key: {detail(release_key_mismatch)}"
            )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        image_transparency_paths = write_fixture_artifacts(tmp)
        image_signatures = json.loads(
            image_transparency_paths["image_signatures"].read_text(encoding="utf-8")
        )
        image_signatures["metadata"]["transparency"]["inclusionProof"]["proof"] = [
            {"side": "right", "hash": digest("0")}
        ]
        write_json(image_transparency_paths["image_signatures"], image_signatures)
        image_transparency = run_handoff(image_transparency_paths)
        if (
            image_transparency.returncode == 0
            or "image signature bundle transparency Merkle inclusion proof did not verify"
            not in detail(image_transparency)
        ):
            raise AssertionError(
                f"handoff accepted image signatures with a bad transparency proof: {detail(image_transparency)}"
            )

    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        sigstore_bundle_paths = write_fixture_artifacts(tmp)
        image_signatures = json.loads(
            sigstore_bundle_paths["image_signatures"].read_text(encoding="utf-8")
        )
        image_signatures["bundle_signature"]["bundle"]["messageSignature"][
            "signature"
        ] = "sigstore:test:forged"
        image_signatures["metadata"]["bundleSigstore"] = image_signatures[
            "bundle_signature"
        ]
        write_json(sigstore_bundle_paths["image_signatures"], image_signatures)
        sigstore_bundle = run_handoff(sigstore_bundle_paths)
        if (
            sigstore_bundle.returncode == 0
            or "image signature bundle Sigstore bundle signature mismatch"
            not in detail(sigstore_bundle)
        ):
            raise AssertionError(
                f"handoff accepted a forged Sigstore bundle signature: {detail(sigstore_bundle)}"
            )

    print(canonical_json({"ok": True, "production_handoff": "pass"}))


if __name__ == "__main__":
    main()
