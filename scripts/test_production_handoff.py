#!/usr/bin/env python3
from __future__ import annotations

import json
import base64
import os
import shlex
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

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


@contextmanager
def fixture_image_measurements(*, substituted: dict[str, object] | None = None):
    """Synthetic I/O only; exercise the real inventory/platform/no-shell validators.

    Measurements are fixed independently of the mutable build/publish artifacts.
    Unexpected commands fail closed instead of accessing Docker or the network.
    """
    control = "registry.prod.serverware.dev/serverware/control@" + digest("a")
    gate = "registry.prod.serverware.dev/serverware/decision-gate@" + digest("b")
    image_ids = {control: digest("a"), gate: digest("b")}
    replacements = substituted or {}

    def measured_run(command: list[str]) -> str:
        if command == [
            sys.executable, "scripts/verify_production_images_no_shell.py",
            "--local-image-id", control, "--local-image-id", gate,
        ]:
            return json.dumps(replacements.get("no_shell", {"ok": True}))
        if len(command) == 3 and command[:2] == ["docker", "pull"]:
            if command[2] in image_ids:
                return "synthetic fixture pull; no registry contacted"
        if (
            len(command) == 6
            and command[:4] == ["docker", "image", "inspect", "--format"]
            and command[5] in image_ids
        ):
            image_ref = command[5]
            if command[4] == "{{.Id}}":
                return str(replacements.get("image_id", image_ids[image_ref]))
            if command[4] == "{{.Os}}/{{.Architecture}}":
                return str(replacements.get("platform", "linux/amd64"))
            if command[4] == "{{json .RepoDigests}}":
                return json.dumps(replacements.get("repo_digests", [image_ref]))
        raise AssertionError(f"unexpected fixture measurement command: {command!r}")

    def measured_file(image_ref: str, path: str) -> str:
        if image_ref == gate:
            for field, character in (
                ("binary_digest", "9"), ("launcher_binary_digest", "e")
            ):
                if path == build_production_images.DECISION_GATE_BINARY_PATHS[field]:
                    return str(replacements.get(field, digest(character)))
        raise AssertionError(f"unexpected fixture image file: {image_ref!r} {path!r}")

    with (
        patch.object(generate_release_provenance, "run", measured_run),
        patch.object(build_production_images, "run", measured_run),
        patch.object(build_production_images, "image_file_sha256", measured_file),
    ):
        yield


def sign_fixture_reproducibility_report(paths: dict[str, Path]) -> None:
    """Use real signature verification with a fixture-only external report key."""
    key = Ed25519PrivateKey.from_private_bytes(b"\x19" * 32)
    key_info = generate_release_provenance.public_key_info(key)
    paths["reproducible_trust_root"].write_text(key_info["pem"], encoding="ascii")
    payload = {
        "apiVersion": generate_release_provenance.EXTERNAL_SIGNATURE_API_VERSION,
        "artifactSha256": sha256_bytes(paths["reproducible"].read_bytes()),
        "purpose": generate_release_provenance.REPRODUCIBILITY_SIGNATURE_PURPOSE,
    }
    write_json(paths["reproducible_signature"], {
        **payload,
        "kind": generate_release_provenance.EXTERNAL_SIGNATURE_KIND,
        "algorithm": "Ed25519",
        "signerKeyId": key_info["spki_sha256"],
        "signature": "ed25519:" + b64e(key.sign(canonical_json(payload).encode("utf-8"))),
    })


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
    source_contract = build_production_images.source_contract(
        development_dirty_tree=False
    )
    source_tree_digest = source_contract["digest"]
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
    reproducible_paths = {
        "reproducible": reproducible,
        "reproducible_signature": tmp / "reproducible-build-verification.sig.json",
        "reproducible_trust_root": tmp / "reproducible-build-verification.pub.pem",
    }
    sign_fixture_reproducibility_report(reproducible_paths)
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
                "revision": source_contract["commit"],
                "source_tree_digest": source_tree_digest,
                "source_archive_digest": source_contract["archive"]["sha256"],
                "source_manifest_digest": source_contract["manifest"]["sha256"],
                "source_identity_mode": source_contract["identityMode"],
                "production_release_eligible": source_contract[
                    "productionReleaseEligible"
                ],
                "source_contract": source_contract,
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
        **reproducible_paths,
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
    source_contract = build_production_images.source_contract(
        development_dirty_tree=False
    )

    def inventory(*, substituted: dict[str, object] | None = None) -> dict[str, object]:
        with fixture_image_measurements(substituted=substituted):
            return generate_release_provenance.production_image_inventory(
                build_path=paths["build"],
                published_path=paths["published"],
                images_env_path=paths["images_env"],
                expected_source_tree_digest=source_tree_digest,
                expected_source_contract=source_contract,
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
        signature_path=paths["reproducible_signature"],
        trusted_public_key_path=paths["reproducible_trust_root"],
        expected_source_tree_digest=source_tree_digest,
        expected_images=production_images,
    )
    if reproducible.get("verification_sha256") != sha256_bytes(
        paths["reproducible"].read_bytes()
    ):
        raise AssertionError(
            f"release provenance did not bind reproducibility evidence bytes: {reproducible}"
        )
    signature_document = json.loads(paths["reproducible_signature"].read_text(encoding="utf-8"))
    try:
        write_json(paths["reproducible_signature"], {
            **signature_document, "signature": "ed25519:" + b64e(b"\0" * 64),
        })
        expect_value_error(
            lambda: generate_release_provenance.production_reproducibility_binding(
                paths["reproducible"],
                signature_path=paths["reproducible_signature"],
                trusted_public_key_path=paths["reproducible_trust_root"],
                expected_source_tree_digest=source_tree_digest,
                expected_images=production_images,
            ),
            "detached signature verification failed",
        )
    finally:
        write_json(paths["reproducible_signature"], signature_document)

    for substitutions, error_type, expected in (
        ({"image_id": digest("8")}, ValueError, "does not resolve to the authenticated build config"),
        ({"repo_digests": []}, ValueError, "expected immutable registry digest"),
        ({"binary_digest": digest("8")}, ValueError, "decision-gate executable does not match"),
        ({"launcher_binary_digest": digest("8")}, ValueError, "launcher does not match"),
        ({"platform": "linux/arm64"}, RuntimeError, "platform"),
        ({"no_shell": {"ok": False}}, RuntimeError, "no-shell verification failed"),
    ):
        try:
            inventory(substituted=substitutions)
        except error_type as exc:
            if expected not in str(exc):
                raise AssertionError(f"wrong measurement rejection: {exc}") from exc
        else:
            raise AssertionError(f"substituted measurement was accepted: {substitutions}")

    published = json.loads(paths["published"].read_text(encoding="utf-8"))
    reproducible_document = json.loads(
        paths["reproducible"].read_text(encoding="utf-8")
    )
    for field, substituted in (
        ("revision", "substituted-source-revision"),
        ("source_archive_digest", digest("8")),
        ("source_manifest_digest", digest("8")),
        ("source_identity_mode", "development-dirty-tree"),
        ("production_release_eligible", False),
    ):
        original = build["metadata"][field]
        try:
            build["metadata"][field] = substituted
            write_json(paths["build"], build)
            expect_value_error(
                inventory,
                f"metadata {field} does not match the exact clean source contract",
            )
        finally:
            build["metadata"][field] = original
            write_json(paths["build"], build)

    original_contract = build["metadata"]["source_contract"]
    try:
        build["metadata"]["source_contract"] = {
            **original_contract,
            "productionReleaseEligible": False,
        }
        write_json(paths["build"], build)
        expect_value_error(inventory, "embedded a different source archive contract")
    finally:
        build["metadata"]["source_contract"] = original_contract
        write_json(paths["build"], build)

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
                signature_path=paths["reproducible_signature"],
                trusted_public_key_path=paths["reproducible_trust_root"],
                expected_source_tree_digest=source_tree_digest,
                expected_images=production_images,
            ),
            "detached signature binding is invalid",
        )
        sign_fixture_reproducibility_report(paths)
        expect_value_error(
            lambda: generate_release_provenance.production_reproducibility_binding(
                paths["reproducible"],
                signature_path=paths["reproducible_signature"],
                trusted_public_key_path=paths["reproducible_trust_root"],
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
        sign_fixture_reproducibility_report(paths)


def assert_staged_commands(output: dict[str, object], paths: dict[str, Path]) -> None:
    plan = output.get("production_commands") or {}
    if "one_shot_command" in plan or "commands" in plan:
        raise AssertionError("handoff still exposes a monolithic executable release plan")
    build = plan.get("build_preparation") or {}
    if (
        build.get("command") != ["make", "production-release-build"]
        or build.get("repeat_for_current_build") is not False
        or build.get("current_image_build_verified") is not True
    ):
        raise AssertionError("handoff must keep fresh-workspace build preparation separate from its existing images")
    expected_stages = {
        "publish": ("release-publisher", "production-release-publish"),
        "sign": ("release-signing-owner", "production-release-sign"),
        "deploy": ("production-operator", "production-release-deploy"),
        "prepare-final-request": ("independent-production-verifier", "prepare-production-final-v1"),
        "authorize-final-result": ("independent-final-authority", None),
        "verify-final-result": ("independent-production-verifier", "production-release-proof"),
    }
    stages = plan.get("stages") or []
    if [stage.get("name") for stage in stages] != list(expected_stages):
        raise AssertionError("handoff stages omit or reorder an independent release authority boundary")
    by_name = {stage["name"]: stage for stage in stages}
    for name, (domain, target) in expected_stages.items():
        stage = by_name[name]
        if stage.get("trust_domain") != domain or not stage.get("prerequisites"):
            raise AssertionError(f"handoff stage {name} omits its owner or prerequisites")
        commands = stage.get("commands")
        if target is None:
            if commands != []:
                raise AssertionError("handoff must obtain final signing from the external authority")
        elif len(commands or []) != 1 or commands[0][:2] != ["make", target]:
            raise AssertionError(f"handoff stage {name} has an incorrect operation: {commands}")

    launch_variables = {
        f"PRODUCTION_DEPLOYMENT_AUDIENCE={DEPLOYMENT_AUDIENCE}",
        f"PRODUCTION_DEPLOYMENT_IDENTITY_SHA256={DEPLOYMENT_IDENTITY_SHA256}",
        f"PRODUCTION_RELEASE_SEQUENCE={RELEASE_SEQUENCE}",
        f"PRODUCTION_ROLLBACK_EPOCH={ROLLBACK_EPOCH}",
    }
    source_digest = output["local_evidence"]["production_images"]["source_tree_digest"]
    release_variables = {
        f"PRODUCTION_RELEASE_ROOT=/opt/serverware/releases/{source_digest.replace(':', '-', 1)}",
        f"PRODUCTION_SOURCE_TREE_DIGEST={source_digest}",
    }
    deployment = by_name["deploy"]["commands"][0]
    if not (launch_variables | release_variables).issubset(deployment):
        raise AssertionError("handoff deployment lost its exact source or deployment identity")
    for name in ("publish", "sign", "deploy"):
        command = by_name[name]["commands"][0]
        if not {
            f"PRODUCTION_READINESS_ENV={paths['env']}",
            f"PRODUCTION_IMAGES_BUILD_FILE={paths['build']}",
            f"PRODUCTION_IMAGES_ENV_OUT={paths['images_env']}",
        }.issubset(command):
            raise AssertionError(f"handoff {name} stage replaced explicit input paths with defaults")
    signing = by_name["sign"]["commands"][0]
    if not {
        f"RELEASE_PROVENANCE_FILE={paths['provenance']}",
        f"IMAGE_SIGNATURES_FILE={paths['image_signatures']}",
    }.issubset(signing):
        raise AssertionError("handoff signing stage lost its explicit evidence paths")
    for name in ("prepare-final-request", "verify-final-result"):
        command = by_name[name]["commands"][0]
        if set(command[2:]) != release_variables:
            raise AssertionError("final-v1 plan must consume separately configured verifier inputs, not deployment credentials")
    legacy = plan.get("legacy_readiness") or {}
    if (
        legacy.get("scope") != "trusted-host-readiness-only"
        or legacy.get("production_completion_evidence") is not False
        or legacy.get("commands", [[]])[0][:2] != ["make", "run-production-readiness-final"]
    ):
        raise AssertionError("legacy readiness must remain explicitly separate from production final-v1")
    if any("so systemd produces the final completion proof" in item for item in output.get("remaining", [])):
        raise AssertionError("handoff still describes legacy readiness as final production proof")


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
            or output.get("apiVersion") != "serverware.productionHandoff/v2"
            or output.get("completion_state") != "pending-independent-production-verification"
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
        assert_staged_commands(output, paths)
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
        assert_staged_commands(env_output, paths)

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
