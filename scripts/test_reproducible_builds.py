#!/usr/bin/env python3
from __future__ import annotations

import copy
import io
import json
import tarfile
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

import serverware_source_tree
import verify_reproducible_builds as verifier
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent.parent


def digest(character: str) -> str:
    return "sha256:" + character * 64


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
    if service == "serverware-control":
        actions.extend(
            [
                ("directory", ("app",)),
                ("directory", ("app/serverware",)),
                ("file", ("app/serverware/app.py", b"print('serverware')\n", 0o644, {})),
                ("symlink", ("app/current", "serverware")),
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
                ("hardlink", ("usr/local/bin/serverware-decision-gate-copy", verifier.RUST_BINARY_PATH)),
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
            "service": "serverware-control",
            "tag": "serverware/control:production-local",
            "dockerfile": "Dockerfile.production",
            "image_id": digest("a"),
        },
        {
            "service": "serverware-decision-gate",
            "tag": "serverware/decision-gate:production-local",
            "dockerfile": "data-plane/decision-gate-rs/Dockerfile.production",
            "image_id": gate_image_id,
            "binary_digest": binary_digest,
            "launcher_binary_digest": launcher_digest,
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
    scope = parsed.get("scope") or {}
    if scope.get("hardware_proof") is not False or scope.get("independent_execution_proven") is not True:
        raise AssertionError(f"verifier did not report the verified independent builders accurately: {scope}")
    inputs = parsed.get("inputs") or {}
    for side in ("left", "right"):
        attestation = (inputs.get(side) or {}).get("attestation") or {}
        if attestation.get("signature_verified") is not True or attestation.get("operator_trusted") is not True:
            raise AssertionError(f"success result omitted verified trust state for {side}: {attestation}")
    images = parsed.get("images") or []
    if {image.get("service") for image in images} != set(verifier.EXPECTED_SERVICES):
        raise AssertionError(f"success result did not bind both production images: {images}")
    gate = next(image for image in images if image["service"] == "serverware-decision-gate")
    if gate.get("rust_binary_sha256") != verifier.sha256_bytes(b"same-rust-binary"):
        raise AssertionError(f"success result did not bind the extracted Rust binary: {gate}")
    if gate.get("launcher_binary_sha256") != verifier.sha256_bytes(b"same-static-launcher"):
        raise AssertionError(f"success result did not bind the extracted launcher binary: {gate}")


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
    gate = next(image for image in forged["images"] if image["service"] == "serverware-decision-gate")
    binary_entry = next(entry for entry in gate["content"]["entries"] if entry["path"] == verifier.RUST_BINARY_PATH)
    binary_entry["sha256"] = digest("9")
    gate["declared_rust_binary_sha256"] = digest("9")
    gate["rust_binary"]["sha256"] = digest("9")
    refresh_content_digest(gate)
    verifier.sign_manifest(forged, builder_id, signing_key)
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
    gate = next(image for image in forged["images"] if image["service"] == "serverware-decision-gate")
    launcher_entry = next(
        entry for entry in gate["content"]["entries"] if entry["path"] == verifier.LAUNCHER_BINARY_PATH
    )
    launcher_entry["sha256"] = digest("8")
    gate["declared_launcher_binary_sha256"] = digest("8")
    gate["launcher_binary_sha256"] = digest("8")
    refresh_content_digest(gate)
    verifier.sign_manifest(forged, builder_id, signing_key)
    verifier.validate_manifest(forged)
    write_manifest(output, forged)
    parsed = load_and_compare(left, output, source_digest, trusted_builders)
    if parsed.get("reproducible") is not False or not parsed.get("mismatches"):
        raise AssertionError(f"signed forged launcher mismatch was accepted: {parsed}")
    fields = {str(item.get("field")) for item in parsed["mismatches"]}
    if not any("launcher_binary_sha256" in field for field in fields):
        raise AssertionError(f"forged launcher mismatch was not reported: {parsed['mismatches']}")


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
    gate = next(image for image in forged["images"] if image["service"] == "serverware-decision-gate")
    gate["image_id"] = digest("8")
    verifier.sign_manifest(forged, builder_id, signing_key)
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
        image for image in missing_launcher["images"] if image["service"] == "serverware-decision-gate"
    )
    gate.pop("launcher_binary_sha256")
    refresh_evidence_digest(missing_launcher)
    assert_validation_error(missing_launcher, "launcher_binary_sha256")


def assert_unbound_and_stale_forgery_rejected(base: dict[str, Any], source_digest: str) -> None:
    unbound = copy.deepcopy(base)
    unbound["images"][0]["image_ref"] = "forged/control:latest"
    assert_validation_error(unbound, "evidence_sha256")

    stale = copy.deepcopy(base)
    stale["source"]["tree_sha256"] = digest("7")
    refresh_evidence_digest(stale)
    verifier.validate_manifest(stale)
    with mock.patch.object(verifier, "current_source_tree_digest", return_value=source_digest):
        try:
            verifier.enforce_current_source(stale)
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
    assert_load_rejected(output, source_digest, trusted_builders, "signature is invalid")


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
    verifier.sign_manifest(duplicate_builder, builder_id, signing_key)
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
    verifier.sign_manifest(same_key_left, first_builder, shared_key)
    verifier.sign_manifest(same_key_right, second_builder, shared_key)
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


def main() -> None:
    binary = b"same-rust-binary"
    binary_digest = verifier.sha256_bytes(binary)
    launcher = b"same-static-launcher"
    launcher_digest = verifier.sha256_bytes(launcher)
    source_digest = serverware_source_tree.source_tree_digest(ROOT)
    left_builder = "builder.example/alpha"
    right_builder = "builder.example/bravo"
    left_key = Ed25519PrivateKey.generate()
    right_key = Ed25519PrivateKey.generate()
    attacker_key = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(prefix="serverware-reproducibility-test-") as temp_dir:
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
                "serverware-decision-gate",
                binary=binary,
                launcher=fixture_launcher,
                launcher_kind=fixture_kind,
                duplicate_launcher=duplicate,
                mtime=999,
                reverse_order=False,
                runtime_marker=b"invalid-runtime-hosts\n",
            )
            invalid_archives = dict(right_archives)
            invalid_archives["serverware-decision-gate"] = invalid_gate_archive
            assert_capture_rejected(
                right_build,
                invalid_archives,
                right_builder,
                right_key,
                expected,
            )
        left_raw = encoded(left_build, pretty=True)
        right_raw = encoded(right_build, pretty=False)
        left_manifest = verifier.build_manifest_from_archives(
            left_build,
            left_raw,
            left_archives,
            engine_image_id_verified=True,
            source_labels_verified=True,
            builder_id=left_builder,
            signing_key=left_key,
        )
        right_manifest = verifier.build_manifest_from_archives(
            right_build,
            right_raw,
            right_archives,
            engine_image_id_verified=True,
            source_labels_verified=True,
            builder_id=right_builder,
            signing_key=right_key,
        )
        verifier.validate_manifest(left_manifest)
        verifier.validate_manifest(right_manifest)
        for manifest in (left_manifest, right_manifest):
            gate = next(image for image in manifest["images"] if image["service"] == "serverware-decision-gate")
            if gate.get("launcher_binary_sha256") != launcher_digest:
                raise AssertionError(f"signed capture manifest omitted the launcher binary digest: {gate}")
        left_path = temp / "left-manifest.json"
        right_path = temp / "right-manifest.json"
        write_manifest(left_path, left_manifest)
        write_manifest(right_path, right_manifest)

        assert_success(left_path, right_path, source_digest, trusted_builders)
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
                    "normalized-success",
                    "forged-rootfs-and-rust-binary-mismatch",
                    "signed-forged-launcher-mismatch",
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
