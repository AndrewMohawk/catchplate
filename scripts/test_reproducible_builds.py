#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import io
import json
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

import catchplate_source_tree
import verify_reproducible_builds as verifier
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent.parent


def digest(character: str) -> str:
    return "sha256:" + character * 64


LAUNCH_AUTHORITY_KEY_ID = digest("4")
LAUNCH_AUTHORITY_ROOT_SHA256 = digest("5")
LEFT_BUILD_ENVIRONMENT_ID = digest("1")
RIGHT_BUILD_ENVIRONMENT_ID = digest("2")
LEFT_EXECUTION_NONCE = "1" * 64
RIGHT_EXECUTION_NONCE = "2" * 64
FIXTURE_BUILD_COMMAND = [
    "python3",
    "scripts/build_production_images.py",
    "--out",
    ".tmp/production-images-build.json",
]


def add_directory(archive: tarfile.TarFile, name: str, *, mtime: int) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = 10001
    info.gid = 10001
    info.mtime = mtime
    archive.addfile(info)


def add_file(
    archive: tarfile.TarFile,
    name: str,
    content: bytes,
    *,
    mtime: int,
    mode: int = 0o644,
    xattrs: dict[str, str] | None = None,
) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = mode
    info.uid = 10001
    info.gid = 10001
    info.mtime = mtime
    for key, value in (xattrs or {}).items():
        info.pax_headers["SCHILY.xattr." + key] = value
    archive.addfile(info, io.BytesIO(content))


def add_symlink(archive: tarfile.TarFile, name: str, target: str, *, mtime: int) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    info.mode = 0o777
    info.uid = 10001
    info.gid = 10001
    info.mtime = mtime
    archive.addfile(info)


def add_hardlink(archive: tarfile.TarFile, name: str, target: str, *, mtime: int) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.LNKTYPE
    info.linkname = target
    info.mode = 0o755
    info.uid = 10001
    info.gid = 10001
    info.mtime = mtime
    archive.addfile(info)


def write_rootfs(
    path: Path,
    service: str,
    *,
    binary: bytes,
    launcher: bytes | None,
    mtime: int,
    reverse_order: bool,
    runtime_marker: bytes,
    launcher_kind: str = "file",
    duplicate_launcher: bool = False,
) -> None:
    actions: list[tuple[str, tuple[Any, ...]]] = []
    if service == "catchplate-control":
        actions.extend(
            [
                ("directory", ("app",)),
                ("directory", ("app/catchplate",)),
                ("file", ("app/catchplate/app.py", b"print('catchplate')\n", 0o644, {})),
                ("symlink", ("app/current", "catchplate")),
            ]
        )
    else:
        actions.extend(
            [
                ("directory", ("usr",)),
                ("directory", ("usr/local",)),
                ("directory", ("usr/local/bin",)),
                ("directory", ("usr/local/libexec",)),
                (
                    "file",
                    (
                        verifier.RUST_BINARY_PATH,
                        binary,
                        0o755,
                        {"security.capability": "cap_net_bind_service=ep"},
                    ),
                ),
                ("hardlink", ("usr/local/bin/catchplate-decision-gate-copy", verifier.RUST_BINARY_PATH)),
            ]
        )
        if launcher is not None:
            if launcher_kind == "file":
                actions.append(("file", (verifier.LAUNCHER_BINARY_PATH, launcher, 0o755, {})))
            elif launcher_kind == "symlink":
                actions.append(("symlink", (verifier.LAUNCHER_BINARY_PATH, "/tmp/launcher")))
            else:
                raise AssertionError(f"unknown launcher fixture kind: {launcher_kind}")
            if duplicate_launcher:
                actions.append(("file", (verifier.LAUNCHER_BINARY_PATH, launcher, 0o755, {})))
    actions.extend(
        [
            ("directory", ("etc",)),
            ("file", ("etc/hosts", runtime_marker, 0o644, {})),
            ("file", ("etc/hostname", b"container-specific\n", 0o644, {})),
            ("file", ("etc/resolv.conf", b"nameserver 127.0.0.11\n", 0o644, {})),
            ("file", (".dockerenv", b"", 0o755, {})),
        ]
    )
    if reverse_order:
        actions.reverse()
    with tarfile.open(path, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for kind, values in actions:
            if kind == "directory":
                add_directory(archive, values[0], mtime=mtime)
            elif kind == "file":
                add_file(
                    archive,
                    values[0],
                    values[1],
                    mtime=mtime,
                    mode=values[2],
                    xattrs=values[3],
                )
            elif kind == "symlink":
                add_symlink(archive, values[0], values[1], mtime=mtime)
            elif kind == "hardlink":
                add_hardlink(archive, values[0], values[1], mtime=mtime)
            else:
                raise AssertionError(f"unknown test tar action: {kind}")


def build_artifact(
    *,
    generated_at: int,
    binary_digest: str,
    launcher_digest: str,
    source_digest: str,
    gate_image_id: str = digest("b"),
) -> dict[str, Any]:
    images = [
        {
            "service": "catchplate-control",
            "tag": "catchplate/control:production-local",
            "dockerfile": "Dockerfile.production",
            "image_id": digest("a"),
        },
        {
            "service": "catchplate-decision-gate",
            "tag": "catchplate/decision-gate:production-local",
            "dockerfile": "data-plane/decision-gate-rs/Dockerfile.production",
            "image_id": gate_image_id,
            "binary_digest": binary_digest,
            "launcher_binary_digest": launcher_digest,
            "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
            "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
        },
    ]
    return {
        "apiVersion": verifier.BUILD_API_VERSION,
        "kind": verifier.BUILD_KIND,
        "ok": True,
        "generated_at_unix": generated_at,
        "metadata": {
            "source": "https://github.com/example/private-deployment",
            "revision": "c" * 40,
            "created": "1970-01-01T00:00:00Z",
            "source_date_epoch": "0",
            "source_tree_digest": source_digest,
            "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
            "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
        },
        "images": images,
        "no_shell": {
            "ok": True,
            "production_images_no_shell": "pass",
            "results": [
                {"image": image["image_id"], "ok": True, "forbidden_shell_paths": []}
                for image in images
            ],
            "failures": [],
        },
        "publish_requirement": verifier.PUBLISH_REQUIREMENT,
    }


def encoded(document: dict[str, Any], *, pretty: bool) -> bytes:
    if pretty:
        return (json.dumps(document, indent=2, sort_keys=False) + "\n").encode("utf-8")
    return verifier.canonical_json(document).encode("utf-8")


def write_manifest(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_public_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def refresh_evidence_digest(document: dict[str, Any]) -> None:
    document["evidence_sha256"] = verifier.sha256_json(verifier.manifest_body(document))
    if "attestation" in document:
        document["attestation"]["payload_sha256"] = verifier.sha256_bytes(
            verifier.attestation_payload(document)
        )


def refresh_content_digest(image: dict[str, Any]) -> None:
    image["content"]["entry_count"] = len(image["content"]["entries"])
    image["content"]["entries_sha256"] = verifier.sha256_json(image["content"]["entries"])


def resign_execution_manifest(
    document: dict[str, Any],
    builder_id: str,
    signing_key: Ed25519PrivateKey,
    *,
    execution_nonce: str | None = None,
) -> None:
    previous = document["build_execution"]["statement"]
    verifier.sign_build_execution(
        document,
        builder_id=builder_id,
        signing_key=signing_key,
        build_command=list(previous["recipe"]["argv"]),
        build_environment_id=previous["environment"]["identity"],
        execution_nonce=execution_nonce or previous["execution_nonce"],
        source_clean=True,
    )
    verifier.sign_manifest(document, builder_id, signing_key)


def load_and_compare(
    left: Path,
    right: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
) -> dict[str, Any]:
    with mock.patch.object(verifier, "current_source_tree_digest", return_value=source_digest):
        left_manifest, left_input = verifier.load_evidence(left, trusted_builders)
        right_manifest, right_input = verifier.load_evidence(right, trusted_builders)
    result = verifier.verification_result(left_manifest, right_manifest, left_input, right_input)
    return json.loads(verifier.canonical_json(result))


def assert_success(
    left: Path,
    right: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
) -> None:
    parsed = load_and_compare(left, right, source_digest, trusted_builders)
    if parsed.get("ok") is not True or parsed.get("reproducible") is not True:
        raise AssertionError(f"matching clean-build manifests were rejected: {parsed}")
    if parsed.get("apiVersion") != "catchplate.reproducibleBuildVerification/v3":
        raise AssertionError(f"success result used the wrong verification contract: {parsed.get('apiVersion')}")
    scope = parsed.get("scope") or {}
    if scope.get("hardware_proof") is not False or scope.get("independent_execution_proven") is not True:
        raise AssertionError(f"verifier did not report the verified independent builders accurately: {scope}")
    inputs = parsed.get("inputs") or {}
    for side in ("left", "right"):
        attestation = (inputs.get(side) or {}).get("attestation") or {}
        if attestation.get("signature_verified") is not True or attestation.get("operator_trusted") is not True:
            raise AssertionError(f"success result omitted verified trust state for {side}: {attestation}")
        execution = (inputs.get(side) or {}).get("build_execution") or {}
        if (
            execution.get("signature_verified") is not True
            or execution.get("operator_trusted") is not True
            or execution.get("source_clean") is not True
        ):
            raise AssertionError(
                f"success result omitted verified build execution state for {side}: {execution}"
            )
        if execution.get("builder_id") != attestation.get("builder_id"):
            raise AssertionError(f"success result mixed builder identities for {side}")
    images = parsed.get("images") or []
    if {image.get("service") for image in images} != set(verifier.EXPECTED_SERVICES):
        raise AssertionError(f"success result did not bind both production images: {images}")
    gate = next(image for image in images if image["service"] == "catchplate-decision-gate")
    if gate.get("rust_binary_sha256") != verifier.sha256_bytes(b"same-rust-binary"):
        raise AssertionError(f"success result did not bind the extracted Rust binary: {gate}")
    if gate.get("launcher_binary_sha256") != verifier.sha256_bytes(b"same-static-launcher"):
        raise AssertionError(f"success result did not bind the extracted launcher binary: {gate}")
    expected_authority = {
        "launch_authority_key_id": LAUNCH_AUTHORITY_KEY_ID,
        "launch_authority_root_sha256": LAUNCH_AUTHORITY_ROOT_SHA256,
    }
    for field, expected in expected_authority.items():
        if gate.get(field) != expected:
            raise AssertionError(f"success result did not bind {field}: {gate}")


def assert_forged_content_rejected(
    base: dict[str, Any],
    left: Path,
    output: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
    builder_id: str,
    signing_key: Ed25519PrivateKey,
) -> None:
    forged = copy.deepcopy(base)
    gate = next(image for image in forged["images"] if image["service"] == "catchplate-decision-gate")
    binary_entry = next(entry for entry in gate["content"]["entries"] if entry["path"] == verifier.RUST_BINARY_PATH)
    binary_entry["sha256"] = digest("9")
    gate["declared_rust_binary_sha256"] = digest("9")
    gate["rust_binary"]["sha256"] = digest("9")
    refresh_content_digest(gate)
    resign_execution_manifest(forged, builder_id, signing_key)
    verifier.validate_manifest(forged)
    write_manifest(output, forged)
    parsed = load_and_compare(left, output, source_digest, trusted_builders)
    if parsed.get("reproducible") is not False or not parsed.get("mismatches"):
        raise AssertionError(f"forged rootfs/Rust binary mismatch was accepted: {parsed}")
    fields = {item.get("field") for item in parsed["mismatches"]}
    if not any("rust_binary.sha256" in str(field) for field in fields):
        raise AssertionError(f"forged Rust binary mismatch was not reported: {parsed['mismatches']}")


def assert_forged_launcher_rejected(
    base: dict[str, Any],
    left: Path,
    output: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
    builder_id: str,
    signing_key: Ed25519PrivateKey,
) -> None:
    forged = copy.deepcopy(base)
    gate = next(image for image in forged["images"] if image["service"] == "catchplate-decision-gate")
    launcher_entry = next(
        entry for entry in gate["content"]["entries"] if entry["path"] == verifier.LAUNCHER_BINARY_PATH
    )
    launcher_entry["sha256"] = digest("8")
    gate["declared_launcher_binary_sha256"] = digest("8")
    gate["launcher_binary_sha256"] = digest("8")
    refresh_content_digest(gate)
    resign_execution_manifest(forged, builder_id, signing_key)
    verifier.validate_manifest(forged)
    write_manifest(output, forged)
    parsed = load_and_compare(left, output, source_digest, trusted_builders)
    if parsed.get("reproducible") is not False or not parsed.get("mismatches"):
        raise AssertionError(f"signed forged launcher mismatch was accepted: {parsed}")
    fields = {str(item.get("field")) for item in parsed["mismatches"]}
    if not any("launcher_binary_sha256" in field for field in fields):
        raise AssertionError(f"forged launcher mismatch was not reported: {parsed['mismatches']}")


def assert_forged_launch_authority_rejected(
    base: dict[str, Any],
    left: Path,
    output_dir: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
    builder_id: str,
    signing_key: Ed25519PrivateKey,
) -> None:
    for index, field in enumerate(verifier.LAUNCH_AUTHORITY_FIELDS, start=6):
        forged = copy.deepcopy(base)
        replacement = digest(str(index))
        forged["source"][field] = replacement
        gate = next(
            image for image in forged["images"] if image["service"] == "catchplate-decision-gate"
        )
        gate[field] = replacement
        resign_execution_manifest(forged, builder_id, signing_key)
        verifier.validate_manifest(forged)
        output = output_dir / f"forged-{field}.json"
        write_manifest(output, forged)
        parsed = load_and_compare(left, output, source_digest, trusted_builders)
        if parsed.get("reproducible") is not False:
            raise AssertionError(f"signed forged {field} was accepted: {parsed}")
        fields = {str(item.get("field")) for item in parsed.get("mismatches") or []}
        if not any(field in mismatch_field for mismatch_field in fields):
            raise AssertionError(f"signed forged {field} was not reported: {parsed}")


def assert_capture_rejected(
    build: dict[str, Any],
    archives: dict[str, Path],
    builder_id: str,
    signing_key: Ed25519PrivateKey,
    expected: str,
) -> None:
    try:
        verifier.build_manifest_from_archives(
            build,
            encoded(build, pretty=False),
            archives,
            engine_image_id_verified=True,
            source_labels_verified=True,
            builder_id=builder_id,
            signing_key=signing_key,
            build_command=FIXTURE_BUILD_COMMAND,
            build_environment_id=RIGHT_BUILD_ENVIRONMENT_ID,
            execution_nonce=RIGHT_EXECUTION_NONCE,
            source_clean=True,
        )
    except verifier.VerificationError as exc:
        if expected not in str(exc):
            raise AssertionError(f"launcher capture rejection did not mention {expected!r}: {exc}") from exc
        return
    raise AssertionError(f"invalid launcher capture was accepted; expected {expected!r}")


def assert_forged_image_id_rejected(
    base: dict[str, Any],
    left: Path,
    output: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
    builder_id: str,
    signing_key: Ed25519PrivateKey,
) -> None:
    forged = copy.deepcopy(base)
    gate = next(image for image in forged["images"] if image["service"] == "catchplate-decision-gate")
    gate["image_id"] = digest("8")
    resign_execution_manifest(forged, builder_id, signing_key)
    verifier.validate_manifest(forged)
    write_manifest(output, forged)
    parsed = load_and_compare(left, output, source_digest, trusted_builders)
    if parsed.get("ok") is not False or not any(
        item.get("field", "").endswith(".image_id") for item in parsed.get("mismatches") or []
    ):
        raise AssertionError(f"forged image ID mismatch was accepted or not reported: {parsed}")


def assert_validation_error(document: dict[str, Any], expected: str) -> None:
    try:
        verifier.validate_manifest(document)
    except verifier.VerificationError as exc:
        if expected not in str(exc):
            raise AssertionError(f"validation error did not mention {expected!r}: {exc}") from exc
        return
    raise AssertionError(f"invalid manifest was accepted; expected error containing {expected!r}")


def assert_schema_forgery_rejected(base: dict[str, Any]) -> None:
    missing_statement = copy.deepcopy(base)
    missing_statement["build_execution"].pop("statement")
    refresh_evidence_digest(missing_statement)
    assert_validation_error(missing_statement, "missing=['statement']")

    extra_environment_field = copy.deepcopy(base)
    extra_environment_field["build_execution"]["statement"]["environment"]["host"] = "unbound"
    refresh_evidence_digest(extra_environment_field)
    assert_validation_error(extra_environment_field, "extra=['host']")

    missing = copy.deepcopy(base)
    missing["images"][0]["content"].pop("entry_count")
    refresh_evidence_digest(missing)
    assert_validation_error(missing, "missing=")

    extra = copy.deepcopy(base)
    extra["images"][0]["content"]["unrecognized"] = True
    refresh_evidence_digest(extra)
    assert_validation_error(extra, "extra=")

    missing_launcher = copy.deepcopy(base)
    gate = next(
        image for image in missing_launcher["images"] if image["service"] == "catchplate-decision-gate"
    )
    gate.pop("launcher_binary_sha256")
    refresh_evidence_digest(missing_launcher)
    assert_validation_error(missing_launcher, "launcher_binary_sha256")

    missing_authority = copy.deepcopy(base)
    gate = next(
        image for image in missing_authority["images"] if image["service"] == "catchplate-decision-gate"
    )
    gate.pop("launch_authority_key_id")
    refresh_evidence_digest(missing_authority)
    assert_validation_error(missing_authority, "launch_authority_key_id")

    mismatched_authority = copy.deepcopy(base)
    gate = next(
        image for image in mismatched_authority["images"] if image["service"] == "catchplate-decision-gate"
    )
    gate["launch_authority_root_sha256"] = digest("9")
    refresh_evidence_digest(mismatched_authority)
    assert_validation_error(mismatched_authority, "does not match reproducibility source metadata")


def assert_unbound_and_stale_forgery_rejected(base: dict[str, Any], source_digest: str) -> None:
    unbound = copy.deepcopy(base)
    unbound["images"][0]["image_ref"] = "forged/control:latest"
    assert_validation_error(unbound, "evidence_sha256")

    verifier.validate_manifest(base)
    stale_checkout_digest = digest("7")
    if stale_checkout_digest == source_digest:
        raise AssertionError("stale source fixture unexpectedly matches the current source")
    with mock.patch.object(
        verifier, "current_source_tree_digest", return_value=stale_checkout_digest
    ):
        try:
            verifier.enforce_current_source(base)
        except verifier.VerificationError as exc:
            if "current checkout" not in str(exc):
                raise AssertionError(f"stale-source rejection was ambiguous: {exc}") from exc
        else:
            raise AssertionError("manifest from a different source tree was accepted")


def assert_load_rejected(
    path: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
    expected: str,
) -> None:
    with mock.patch.object(verifier, "current_source_tree_digest", return_value=source_digest):
        try:
            verifier.load_evidence(path, trusted_builders)
        except verifier.VerificationError as exc:
            if expected not in str(exc):
                raise AssertionError(
                    f"attestation rejection did not mention {expected!r}: {exc}"
                ) from exc
            return
    raise AssertionError(f"invalid builder attestation was accepted; expected {expected!r}")


def assert_unsigned_rejected(
    base: dict[str, Any], output: Path, source_digest: str, trusted_builders: dict[str, Any]
) -> None:
    unsigned = copy.deepcopy(base)
    unsigned.pop("attestation")
    write_manifest(output, unsigned)
    assert_load_rejected(output, source_digest, trusted_builders, "missing=['attestation']")


def assert_forged_signature_rejected(
    base: dict[str, Any],
    output: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
    builder_id: str,
    attacker_key: Ed25519PrivateKey,
) -> None:
    forged = copy.deepcopy(base)
    verifier.sign_manifest(forged, builder_id, attacker_key)
    forged["attestation"]["key_id"] = verifier.public_key_id(trusted_builders[builder_id])
    write_manifest(output, forged)
    assert_load_rejected(output, source_digest, trusted_builders, "signature is invalid")


def assert_swapped_signature_rejected(
    base: dict[str, Any],
    other: dict[str, Any],
    output: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
) -> None:
    swapped = copy.deepcopy(base)
    swapped["attestation"]["signature"] = other["attestation"]["signature"]
    write_manifest(output, swapped)
    assert_load_rejected(output, source_digest, trusted_builders, "signature is invalid")


def assert_tampered_capture_rejected(
    base: dict[str, Any], output: Path, source_digest: str, trusted_builders: dict[str, Any]
) -> None:
    tampered = copy.deepcopy(base)
    tampered["images"][0]["image_ref"] = "attacker.invalid/control:latest"
    refresh_evidence_digest(tampered)
    write_manifest(output, tampered)
    assert_load_rejected(output, source_digest, trusted_builders, "does not bind the completed capture")


def assert_same_builder_rejected(
    left_path: Path,
    right: dict[str, Any],
    output: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
    builder_id: str,
    signing_key: Ed25519PrivateKey,
) -> None:
    duplicate_builder = copy.deepcopy(right)
    resign_execution_manifest(duplicate_builder, builder_id, signing_key)
    write_manifest(output, duplicate_builder)
    with mock.patch.object(verifier, "current_source_tree_digest", return_value=source_digest):
        left_manifest, left_input = verifier.load_evidence(left_path, trusted_builders)
        right_manifest, right_input = verifier.load_evidence(output, trusted_builders)
    try:
        verifier.verification_result(left_manifest, right_manifest, left_input, right_input)
    except verifier.VerificationError as exc:
        if "distinct builder identities" not in str(exc):
            raise AssertionError(f"same-builder rejection was ambiguous: {exc}") from exc
    else:
        raise AssertionError("two attestations from the same builder identity were accepted")


def assert_same_key_rejected(
    left: dict[str, Any],
    right: dict[str, Any],
    left_path: Path,
    right_path: Path,
    source_digest: str,
    first_builder: str,
    second_builder: str,
    shared_key: Ed25519PrivateKey,
) -> None:
    same_key_left = copy.deepcopy(left)
    same_key_right = copy.deepcopy(right)
    resign_execution_manifest(same_key_left, first_builder, shared_key)
    resign_execution_manifest(same_key_right, second_builder, shared_key)
    write_manifest(left_path, same_key_left)
    write_manifest(right_path, same_key_right)
    trusted = {
        first_builder: shared_key.public_key(),
        second_builder: shared_key.public_key(),
    }
    with mock.patch.object(verifier, "current_source_tree_digest", return_value=source_digest):
        left_manifest, left_input = verifier.load_evidence(left_path, trusted)
        right_manifest, right_input = verifier.load_evidence(right_path, trusted)
    try:
        verifier.verification_result(left_manifest, right_manifest, left_input, right_input)
    except verifier.VerificationError as exc:
        if "distinct operator-pinned keys" not in str(exc):
            raise AssertionError(f"same-key rejection was ambiguous: {exc}") from exc
    else:
        raise AssertionError("two builder identities sharing one signing key were accepted")


def fresh_execution_capture(
    *,
    temp: Path,
    name: str,
    build: dict[str, Any],
    pretty: bool,
    archives: dict[str, Path],
    source_digest: str,
    builder_id: str,
    signing_key: Ed25519PrivateKey,
    build_environment_id: str,
    execution_nonce: str,
) -> dict[str, Any]:
    fixture_path = temp / f"{name}-build-fixture.json"
    build_path = temp / f"{name}-fresh-build.json"
    fixture_path.write_bytes(encoded(build, pretty=pretty))
    build_path.write_text('{"stale":"preloaded-only"}\n', encoding="utf-8")
    command = [
        sys.executable,
        "-c",
        (
            "from pathlib import Path; import sys; "
            "Path(sys.argv[2]).write_bytes(Path(sys.argv[1]).read_bytes())"
        ),
        str(fixture_path),
        str(build_path),
    ]

    def fake_export(image: dict[str, Any], source: dict[str, Any], destination: Path) -> None:
        if source["tree_sha256"] != source_digest:
            raise AssertionError(f"capture exported an image for the wrong source: {source}")
        destination.write_bytes(archives[str(image["service"])].read_bytes())

    with (
        mock.patch.object(verifier, "require_clean_source_checkout"),
        mock.patch.object(verifier, "current_source_tree_digest", return_value=source_digest),
        mock.patch.object(verifier, "current_source_revision", return_value="c" * 40),
        mock.patch.object(verifier, "export_docker_image", side_effect=fake_export),
    ):
        manifest = verifier.capture_build(
            build_path,
            builder_id=builder_id,
            signing_key=signing_key,
            build_command=command,
            build_environment_id=build_environment_id,
            execution_nonce=execution_nonce,
        )
    statement = manifest["build_execution"]["statement"]
    if statement["recipe"]["argv"] != command:
        raise AssertionError("fresh capture did not bind the exact executed argv")
    if statement["environment"]["identity"] != build_environment_id:
        raise AssertionError("fresh capture did not bind the isolated build environment")
    if statement["execution_nonce"] != execution_nonce:
        raise AssertionError("fresh capture did not bind the execution nonce")
    if statement["result"]["build_artifact_sha256"] != verifier.sha256_file(build_path):
        raise AssertionError("fresh capture did not bind the generated v2 build artifact")
    return manifest


def assert_preloaded_image_signatures_rejected(
    left: dict[str, Any],
    right: dict[str, Any],
    temp: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
    left_builder: str,
    right_builder: str,
    left_key: Ed25519PrivateKey,
    right_key: Ed25519PrivateKey,
) -> None:
    for name, base, builder_id, signing_key in (
        ("left", left, left_builder, left_key),
        ("right", right, right_builder, right_key),
    ):
        old_attack = copy.deepcopy(base)
        old_attack.pop("build_execution")
        verifier.sign_manifest(old_attack, builder_id, signing_key)
        path = temp / f"preloaded-{name}.json"
        write_manifest(path, old_attack)
        assert_load_rejected(path, source_digest, trusted_builders, "build_execution")


def assert_preloaded_artifact_only_capture_rejected(
    *,
    temp: Path,
    build: dict[str, Any],
    source_digest: str,
    builder_id: str,
    signing_key: Ed25519PrivateKey,
) -> None:
    build_path = temp / "preloaded-only-build.json"
    build_path.write_bytes(encoded(build, pretty=False))
    with (
        mock.patch.object(verifier, "require_clean_source_checkout"),
        mock.patch.object(verifier, "current_source_tree_digest", return_value=source_digest),
        mock.patch.object(verifier, "current_source_revision", return_value="c" * 40),
    ):
        try:
            verifier.capture_build(
                build_path,
                builder_id=builder_id,
                signing_key=signing_key,
                build_command=[sys.executable, "-c", "pass"],
                build_environment_id=LEFT_BUILD_ENVIRONMENT_ID,
                execution_nonce="3" * 64,
            )
        except verifier.VerificationError as exc:
            if "fresh production build artifact" not in str(exc):
                raise AssertionError(f"preloaded-only rejection was ambiguous: {exc}") from exc
        else:
            raise AssertionError("a no-op command reused a preloaded build artifact")


def assert_forged_execution_signature_rejected(
    base: dict[str, Any],
    output: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
    builder_id: str,
    signing_key: Ed25519PrivateKey,
    attacker_key: Ed25519PrivateKey,
) -> None:
    forged = copy.deepcopy(base)
    statement = forged["build_execution"]["statement"]
    forged["build_execution"]["attestation"]["signature"] = base64.b64encode(
        attacker_key.sign(verifier.execution_statement_payload(statement))
    ).decode("ascii")
    verifier.sign_manifest(forged, builder_id, signing_key)
    write_manifest(output, forged)
    assert_load_rejected(
        output, source_digest, trusted_builders, "build execution signature is invalid"
    )


def assert_swapped_execution_statement_rejected(
    base: dict[str, Any],
    other: dict[str, Any],
    output: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
    builder_id: str,
    signing_key: Ed25519PrivateKey,
) -> None:
    swapped = copy.deepcopy(base)
    swapped["build_execution"] = copy.deepcopy(other["build_execution"])
    verifier.sign_manifest(swapped, builder_id, signing_key)
    write_manifest(output, swapped)
    assert_load_rejected(output, source_digest, trusted_builders, "does not bind")


def assert_replayed_execution_nonce_rejected(
    left_path: Path,
    right: dict[str, Any],
    output: Path,
    source_digest: str,
    trusted_builders: dict[str, Any],
    builder_id: str,
    signing_key: Ed25519PrivateKey,
) -> None:
    replay = copy.deepcopy(right)
    resign_execution_manifest(
        replay,
        builder_id,
        signing_key,
        execution_nonce=LEFT_EXECUTION_NONCE,
    )
    write_manifest(output, replay)
    with mock.patch.object(verifier, "current_source_tree_digest", return_value=source_digest):
        left_manifest, left_input = verifier.load_evidence(left_path, trusted_builders)
        right_manifest, right_input = verifier.load_evidence(output, trusted_builders)
    try:
        verifier.verification_result(left_manifest, right_manifest, left_input, right_input)
    except verifier.VerificationError as exc:
        if "replay rejected" not in str(exc):
            raise AssertionError(f"execution nonce replay rejection was ambiguous: {exc}") from exc
    else:
        raise AssertionError("replayed build execution nonce was accepted")


def main() -> None:
    expected_versions = {
        "build": "catchplate.productionImagesBuild/v2",
        "manifest": "catchplate.reproducibleBuildManifest/v3",
        "verification": "catchplate.reproducibleBuildVerification/v3",
        "execution": "catchplate.buildExecutionStatement/v1",
    }
    actual_versions = {
        "build": verifier.BUILD_API_VERSION,
        "manifest": verifier.MANIFEST_API_VERSION,
        "verification": verifier.VERIFICATION_API_VERSION,
        "execution": verifier.BUILD_EXECUTION_API_VERSION,
    }
    if actual_versions != expected_versions:
        raise AssertionError(f"reproducibility contracts have incoherent versions: {actual_versions}")
    binary = b"same-rust-binary"
    binary_digest = verifier.sha256_bytes(binary)
    launcher = b"same-static-launcher"
    launcher_digest = verifier.sha256_bytes(launcher)
    source_digest = catchplate_source_tree.source_tree_digest(ROOT)
    left_builder = "builder.example/alpha"
    right_builder = "builder.example/bravo"
    left_key = Ed25519PrivateKey.generate()
    right_key = Ed25519PrivateKey.generate()
    attacker_key = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(prefix="catchplate-reproducibility-test-") as temp_dir:
        temp = Path(temp_dir)
        left_public_key = temp / "left-builder.pub.pem"
        right_public_key = temp / "right-builder.pub.pem"
        write_public_key(left_public_key, left_key)
        write_public_key(right_public_key, right_key)
        trusted_builders = verifier.parse_trusted_builders(
            [
                f"{left_builder}={left_public_key}",
                f"{right_builder}={right_public_key}",
            ]
        )
        left_archives = {
            service: temp / f"left-{service}.tar" for service in verifier.EXPECTED_SERVICES
        }
        right_archives = {
            service: temp / f"right-{service}.tar" for service in verifier.EXPECTED_SERVICES
        }
        for service in verifier.EXPECTED_SERVICES:
            write_rootfs(
                left_archives[service],
                service,
                binary=binary,
                launcher=launcher,
                mtime=10,
                reverse_order=False,
                runtime_marker=b"left-runtime-hosts\n",
            )
            write_rootfs(
                right_archives[service],
                service,
                binary=binary,
                launcher=launcher,
                mtime=999,
                reverse_order=True,
                runtime_marker=b"right-runtime-hosts\n",
            )

        left_build = build_artifact(
            generated_at=100,
            binary_digest=binary_digest,
            launcher_digest=launcher_digest,
            source_digest=source_digest,
        )
        right_build = build_artifact(
            generated_at=200,
            binary_digest=binary_digest,
            launcher_digest=launcher_digest,
            source_digest=source_digest,
        )
        assert_preloaded_artifact_only_capture_rejected(
            temp=temp,
            build=left_build,
            source_digest=source_digest,
            builder_id=left_builder,
            signing_key=left_key,
        )

        for fixture_name, mutate, expected in (
            (
                "missing-metadata-key-id",
                lambda value: value["metadata"].pop("launch_authority_key_id"),
                "launch_authority_key_id",
            ),
            (
                "missing-image-root-digest",
                lambda value: value["images"][1].pop("launch_authority_root_sha256"),
                "launch_authority_root_sha256",
            ),
            (
                "metadata-image-authority-mismatch",
                lambda value: value["images"][1].__setitem__(
                    "launch_authority_key_id", digest("9")
                ),
                "does not match production build metadata",
            ),
        ):
            invalid_build = copy.deepcopy(right_build)
            mutate(invalid_build)
            assert_capture_rejected(
                invalid_build,
                right_archives,
                right_builder,
                right_key,
                expected,
            )

        missing_declaration = copy.deepcopy(right_build)
        missing_declaration["images"][1].pop("launcher_binary_digest")
        assert_capture_rejected(
            missing_declaration,
            right_archives,
            right_builder,
            right_key,
            "launcher_binary_digest",
        )

        mismatched_declaration = copy.deepcopy(right_build)
        mismatched_declaration["images"][1]["launcher_binary_digest"] = digest("9")
        assert_capture_rejected(
            mismatched_declaration,
            right_archives,
            right_builder,
            right_key,
            "launcher binary digest does not match",
        )

        for fixture_name, fixture_launcher, fixture_kind, duplicate, expected in (
            ("missing", None, "file", False, "one regular launcher binary"),
            ("symlink", launcher, "symlink", False, "one regular launcher binary"),
            ("duplicate", launcher, "file", True, "contains duplicate path"),
        ):
            invalid_gate_archive = temp / f"{fixture_name}-launcher-gate.tar"
            write_rootfs(
                invalid_gate_archive,
                "catchplate-decision-gate",
                binary=binary,
                launcher=fixture_launcher,
                launcher_kind=fixture_kind,
                duplicate_launcher=duplicate,
                mtime=999,
                reverse_order=False,
                runtime_marker=b"invalid-runtime-hosts\n",
            )
            invalid_archives = dict(right_archives)
            invalid_archives["catchplate-decision-gate"] = invalid_gate_archive
            assert_capture_rejected(
                right_build,
                invalid_archives,
                right_builder,
                right_key,
                expected,
            )
        left_manifest = fresh_execution_capture(
            temp=temp,
            name="left",
            build=left_build,
            pretty=True,
            archives=left_archives,
            source_digest=source_digest,
            builder_id=left_builder,
            signing_key=left_key,
            build_environment_id=LEFT_BUILD_ENVIRONMENT_ID,
            execution_nonce=LEFT_EXECUTION_NONCE,
        )
        right_manifest = fresh_execution_capture(
            temp=temp,
            name="right",
            build=right_build,
            pretty=False,
            archives=right_archives,
            source_digest=source_digest,
            builder_id=right_builder,
            signing_key=right_key,
            build_environment_id=RIGHT_BUILD_ENVIRONMENT_ID,
            execution_nonce=RIGHT_EXECUTION_NONCE,
        )
        verifier.validate_manifest(left_manifest)
        verifier.validate_manifest(right_manifest)
        for manifest in (left_manifest, right_manifest):
            if manifest.get("apiVersion") != "catchplate.reproducibleBuildManifest/v3":
                raise AssertionError(f"capture manifest used the wrong contract: {manifest.get('apiVersion')}")
            if (
                manifest.get("build_execution", {}).get("statement", {}).get("apiVersion")
                != "catchplate.buildExecutionStatement/v1"
            ):
                raise AssertionError(f"capture manifest omitted the execution statement: {manifest}")
            gate = next(image for image in manifest["images"] if image["service"] == "catchplate-decision-gate")
            if gate.get("launcher_binary_sha256") != launcher_digest:
                raise AssertionError(f"signed capture manifest omitted the launcher binary digest: {gate}")
            for field, expected in (
                ("launch_authority_key_id", LAUNCH_AUTHORITY_KEY_ID),
                ("launch_authority_root_sha256", LAUNCH_AUTHORITY_ROOT_SHA256),
            ):
                if manifest["source"].get(field) != expected or gate.get(field) != expected:
                    raise AssertionError(f"signed capture manifest omitted {field}: {manifest}")
        left_path = temp / "left-manifest.json"
        right_path = temp / "right-manifest.json"
        write_manifest(left_path, left_manifest)
        write_manifest(right_path, right_manifest)

        assert_preloaded_image_signatures_rejected(
            left_manifest,
            right_manifest,
            temp,
            source_digest,
            trusted_builders,
            left_builder,
            right_builder,
            left_key,
            right_key,
        )
        assert_success(left_path, right_path, source_digest, trusted_builders)
        assert_forged_execution_signature_rejected(
            right_manifest,
            temp / "forged-execution-signature.json",
            source_digest,
            trusted_builders,
            right_builder,
            right_key,
            attacker_key,
        )
        assert_swapped_execution_statement_rejected(
            right_manifest,
            left_manifest,
            temp / "swapped-execution.json",
            source_digest,
            trusted_builders,
            right_builder,
            right_key,
        )
        assert_replayed_execution_nonce_rejected(
            left_path,
            right_manifest,
            temp / "replayed-execution-nonce.json",
            source_digest,
            trusted_builders,
            right_builder,
            right_key,
        )
        assert_forged_content_rejected(
            right_manifest,
            left_path,
            temp / "forged-content.json",
            source_digest,
            trusted_builders,
            right_builder,
            right_key,
        )
        assert_forged_launcher_rejected(
            right_manifest,
            left_path,
            temp / "forged-launcher.json",
            source_digest,
            trusted_builders,
            right_builder,
            right_key,
        )
        assert_forged_launch_authority_rejected(
            right_manifest,
            left_path,
            temp,
            source_digest,
            trusted_builders,
            right_builder,
            right_key,
        )
        assert_forged_image_id_rejected(
            right_manifest,
            left_path,
            temp / "forged-image-id.json",
            source_digest,
            trusted_builders,
            right_builder,
            right_key,
        )
        assert_schema_forgery_rejected(right_manifest)
        assert_unbound_and_stale_forgery_rejected(right_manifest, source_digest)
        assert_unsigned_rejected(
            right_manifest,
            temp / "unsigned.json",
            source_digest,
            trusted_builders,
        )
        assert_forged_signature_rejected(
            right_manifest,
            temp / "forged-signature.json",
            source_digest,
            trusted_builders,
            right_builder,
            attacker_key,
        )
        assert_swapped_signature_rejected(
            right_manifest,
            left_manifest,
            temp / "swapped-signature.json",
            source_digest,
            trusted_builders,
        )
        assert_tampered_capture_rejected(
            right_manifest,
            temp / "tampered.json",
            source_digest,
            trusted_builders,
        )
        assert_same_builder_rejected(
            left_path,
            right_manifest,
            temp / "same-builder.json",
            source_digest,
            trusted_builders,
            left_builder,
            left_key,
        )
        assert_same_key_rejected(
            left_manifest,
            right_manifest,
            temp / "same-key-left.json",
            temp / "same-key-right.json",
            source_digest,
            left_builder,
            right_builder,
            left_key,
        )

    print(
        verifier.canonical_json(
            {
                "ok": True,
                "tests": [
                    "fresh-two-execution-normalized-success",
                    "preloaded-artifact-no-op-capture-rejected",
                    "two-signatures-on-preloaded-images-rejected",
                    "forged-execution-signature-rejected",
                    "swapped-execution-statement-rejected",
                    "replayed-execution-nonce-rejected",
                    "forged-rootfs-and-rust-binary-mismatch",
                    "signed-forged-launcher-mismatch",
                    "signed-forged-launch-authority-mismatch",
                    "launcher-missing-nonregular-duplicate-and-declaration-mismatch",
                    "forged-image-id-mismatch",
                    "missing-and-extra-fields",
                    "unbound-mutation-and-stale-source",
                    "unsigned-attestation-rejected",
                    "forged-signature-rejected",
                    "swapped-signature-rejected",
                    "same-builder-rejected",
                    "same-key-rejected",
                    "tampered-capture-rejected",
                ],
            }
        )
    )


if __name__ == "__main__":
    main()
