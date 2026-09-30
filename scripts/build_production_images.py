#!/usr/bin/env python3
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import serverware_source_tree

ROOT = Path(__file__).resolve().parent.parent
BUILD_API_VERSION = "serverware.productionImagesBuild/v2"
BUILD_KIND = "ProductionImagesBuild"
PRODUCTION_PLATFORM = "linux/amd64"
DEFAULT_IMAGES = (
    ("serverware-control", "Dockerfile.production", "serverware/control:production-local"),
    ("serverware-decision-gate", "data-plane/decision-gate-rs/Dockerfile.production", "serverware/decision-gate:production-local"),
)
DECISION_GATE_BINARY_PATHS = {
    "binary_digest": "/usr/local/bin/serverware-decision-gate",
    "launcher_binary_digest": "/usr/local/libexec/serverware-production-launcher",
}
LAUNCH_AUTHORITY_ROOT = ROOT / "data-plane/decision-gate-rs/trust/launch-authority-root.ed25519.hex"
ED25519_SPKI_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
LAUNCH_AUTHORITY_METADATA_FIELDS = (
    "launch_authority_key_id",
    "launch_authority_root_sha256",
)
PRIVATE_CONTEXT_FILES = (
    "Dockerfile.production",
    "data-plane/decision-gate-rs/Dockerfile.production",
    "requirements.lock",
    "production-dependencies/python-linux-amd64.sha256",
    "production-dependencies/cache/python-wheelhouse-linux-amd64.tar.gz",
    "production-dependencies/cache/cargo-vendor.tar.gz",
    "production-dependencies/cache/musl-1.2.5-r12.apk",
    "production-dependencies/cache/musl-dev-1.2.5-r12.apk",
    "production-dependencies/cache/squashfs-tools_4.5.1-1_amd64.deb",
    "production-dependencies/cache/liblzo2-2_2.10-2_amd64.deb",
)
PRODUCTION_ARTIFACT_TARGETS = {
    (
        "data-plane/decision-gate-rs/Dockerfile.production",
        "production-launcher-artifact",
    ),
    (
        "data-plane/decision-gate-rs/Dockerfile.production",
        "native-broker-runtime-artifact",
    ),
    ("data-plane/decision-gate-rs/Dockerfile.production", "native-pilot-artifacts"),
    # Separately installed independent authorities; never part of the claimant
    # bundle. Their fixed Docker stages own their respective runtime closures.
    ("data-plane/decision-gate-rs/Dockerfile.production", "native-setup-hardware-artifact"),
    ("data-plane/decision-gate-rs/Dockerfile.production", "native-setup-proxy-artifact"),
    ("data-plane/decision-gate-rs/Dockerfile.production", "native-setup-final-artifact"),
    ("data-plane/decision-gate-rs/Dockerfile.production", "native-shadow-verifier-supervisor-artifact"),
    ("data-plane/decision-gate-rs/Dockerfile.production", "native-shadow-verifier-transport-artifact"),
    ("data-plane/decision-gate-rs/Dockerfile.production", "native-shadow-verifier-runtime-artifact"),
    ("data-plane/decision-gate-rs/Dockerfile.production", "native-shadow-time-issuer-supervisor-artifact"),
    ("data-plane/decision-gate-rs/Dockerfile.production", "native-shadow-time-issuer-runtime-artifact"),
    ("data-plane/decision-gate-rs/Dockerfile.production", "native-generation-origin-issuer-supervisor-artifact"),
    ("data-plane/decision-gate-rs/Dockerfile.production", "native-generation-origin-issuer-runtime-artifact"),
}
NATIVE_PILOT_TARGET = "native-pilot-artifacts"
PUBLIC_GUEST_FILES = {
    "seccomp.bpf": ("seccompSha256", 32768),
    "runtime.json": ("runtimeConfigurationSha256", 4 * 1024 * 1024),
    "build-recipe.json": ("buildRecipeSha256", 4 * 1024 * 1024),
    "provenance.json": ("provenanceStatementSha256", 4 * 1024 * 1024),
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def run(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed with exit {result.returncode}: {detail}")
    return result.stdout.strip()


def image_id(tag: str) -> str:
    return run(["docker", "image", "inspect", "--format", "{{.Id}}", tag])


def maybe_run(command: list[str]) -> str | None:
    try:
        return run(command)
    except Exception:
        return None


def verify_dependency_cache() -> None:
    run([sys.executable, "production-dependencies/prefetch.py", "verify"])


def source_contract(*, development_dirty_tree: bool) -> dict[str, Any]:
    if development_dirty_tree:
        return serverware_source_tree.development_source_contract(ROOT)
    return serverware_source_tree.production_source_contract(ROOT)


def source_tree_digest(*, development_dirty_tree: bool = False) -> str:
    return source_contract(development_dirty_tree=development_dirty_tree)["digest"]


def _decode_ed25519_point(public_key: bytes) -> tuple[int, int]:
    prime = (1 << 255) - 19
    encoded = int.from_bytes(public_key, "little")
    x_sign = encoded >> 255
    y = encoded & ((1 << 255) - 1)
    if y >= prime:
        raise ValueError("non-canonical point encoding")

    d = (-121665 * pow(121666, prime - 2, prime)) % prime
    y_squared = y * y % prime
    denominator = (d * y_squared + 1) % prime
    if denominator == 0:
        raise ValueError("point is not on the Ed25519 curve")
    x_squared = (y_squared - 1) * pow(denominator, prime - 2, prime) % prime
    x = pow(x_squared, (prime + 3) // 8, prime)
    if x * x % prime != x_squared:
        x = x * pow(2, (prime - 1) // 4, prime) % prime
    if x * x % prime != x_squared:
        raise ValueError("point is not on the Ed25519 curve")
    if x & 1 != x_sign:
        x = prime - x
    if x == 0 and x_sign:
        raise ValueError("non-canonical point encoding")
    return x, y


def _ed25519_point_add(first: tuple[int, int], second: tuple[int, int]) -> tuple[int, int]:
    prime = (1 << 255) - 19
    d = (-121665 * pow(121666, prime - 2, prime)) % prime
    x1, y1 = first
    x2, y2 = second
    product = d * x1 * x2 * y1 * y2 % prime
    x_denominator = (1 + product) % prime
    y_denominator = (1 - product) % prime
    if x_denominator == 0 or y_denominator == 0:
        raise ValueError("invalid Ed25519 point")
    return (
        (x1 * y2 + y1 * x2) * pow(x_denominator, prime - 2, prime) % prime,
        (y1 * y2 + x1 * x2) * pow(y_denominator, prime - 2, prime) % prime,
    )


def _validate_ed25519_public_key(public_key: bytes) -> None:
    if len(public_key) != 32:
        raise ValueError("Ed25519 public keys must contain 32 bytes")
    point = _decode_ed25519_point(public_key)
    multiplied = point
    for _ in range(3):
        multiplied = _ed25519_point_add(multiplied, multiplied)
    if multiplied == (0, 1):
        raise ValueError("weak Ed25519 public key")


def launch_authority_metadata(path: Path = LAUNCH_AUTHORITY_ROOT) -> dict[str, str]:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise RuntimeError(f"could not open launch authority trust root {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != 65:
            raise RuntimeError(f"launch authority trust root is not a regular file: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                raise RuntimeError("launch authority trust root changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        tracked_bytes = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise RuntimeError("launch authority trust root changed during read")
    finally:
        os.close(descriptor)
    if re.fullmatch(rb"[0-9a-f]{64}\n", tracked_bytes) is None:
        raise RuntimeError(
            "launch authority trust root must be exactly 64 lowercase hex characters followed by LF"
        )
    public_key = bytes.fromhex(tracked_bytes[:-1].decode("ascii"))
    try:
        _validate_ed25519_public_key(public_key)
    except ValueError as exc:
        raise RuntimeError(f"launch authority trust root is not a valid Ed25519 public key: {exc}") from exc
    return {
        "launch_authority_key_id": "sha256:"
        + hashlib.sha256(ED25519_SPKI_DER_PREFIX + public_key).hexdigest(),
        "launch_authority_root_sha256": "sha256:" + hashlib.sha256(tracked_bytes).hexdigest(),
    }


def build_metadata(*, development_dirty_tree: bool = False) -> dict[str, Any]:
    contract = source_contract(development_dirty_tree=development_dirty_tree)
    if development_dirty_tree:
        raw_epoch = os.getenv("SOURCE_DATE_EPOCH", "0")
        revision = "development-uncommitted"
        source = "local-development-dirty-tree"
        title_suffix = "development dirty tree"
    else:
        commit = contract.get("commit")
        if not isinstance(commit, str) or not commit:
            raise RuntimeError("production source contract is missing its exact commit")
        raw_epoch = contract.get("commitTimestamp")
        if not isinstance(raw_epoch, str) or not raw_epoch:
            raise RuntimeError("production source contract is missing its authenticated commit timestamp")
        supplied_epoch = os.getenv("SOURCE_DATE_EPOCH")
        if supplied_epoch is not None and supplied_epoch != raw_epoch:
            raise RuntimeError(
                "production SOURCE_DATE_EPOCH must equal the authenticated Git commit timestamp"
            )
        revision = commit
        source = str(contract["repository"])
        title_suffix = "production"
    try:
        source_date_epoch = int(raw_epoch)
    except ValueError as exc:
        raise RuntimeError("SOURCE_DATE_EPOCH must be an integer") from exc
    if source_date_epoch < 0:
        raise RuntimeError("SOURCE_DATE_EPOCH must be non-negative")
    return {
        "source": source,
        "revision": revision,
        "created": datetime.fromtimestamp(source_date_epoch, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source_date_epoch": str(source_date_epoch),
        "source_tree_digest": contract["digest"],
        "source_archive_digest": contract["archive"]["sha256"],
        "source_archive_path": contract["archivePath"],
        "source_manifest_digest": contract["manifest"]["sha256"],
        "source_manifest_path": contract["manifestPath"],
        "source_file_list_digest": contract["verification"]["fileList"]["sha256"],
        "source_file_list_path": contract["verificationPaths"]["fileList"],
        "source_file_hashes_digest": contract["verification"]["fileHashes"]["sha256"],
        "source_file_hashes_path": contract["verificationPaths"]["fileHashes"],
        "source_file_modes_digest": contract["verification"]["fileModes"]["sha256"],
        "source_file_modes_path": contract["verificationPaths"]["fileModes"],
        "source_identity_mode": contract["identityMode"],
        "production_release_eligible": contract["productionReleaseEligible"],
        "image_title_suffix": title_suffix,
        "source_contract": contract,
        **launch_authority_metadata(),
    }


def _copy_context_file(source: Path, destination: Path, expected_sha256: str | None,
                       *, maximum_bytes: int | None = None) -> None:
    try:
        source_descriptor = os.open(source, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise RuntimeError(f"could not open private build-context input {source}: {exc}") from exc
    try:
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode) or (maximum_bytes is not None
                and not 0 < before.st_size <= maximum_bytes):
            raise RuntimeError(f"private build-context input is not a regular file: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        digest = hashlib.sha256()
        copied = 0
        try:
            with os.fdopen(source_descriptor, "rb", closefd=False) as source_handle:
                with os.fdopen(destination_descriptor, "wb", closefd=False) as destination_handle:
                    while True:
                        chunk = source_handle.read(1024 * 1024)
                        if not chunk:
                            break
                        if maximum_bytes is not None and copied + len(chunk) > maximum_bytes:
                            raise RuntimeError("bounded public build original grew during copy")
                        destination_handle.write(chunk)
                        digest.update(chunk)
                        copied += len(chunk)
                    destination_handle.flush()
                    os.fsync(destination_descriptor)
        finally:
            os.close(destination_descriptor)
        after = os.fstat(source_descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ) or copied != after.st_size:
            raise RuntimeError(f"private build-context input changed while copied: {source}")
        actual_sha256 = "sha256:" + digest.hexdigest()
        if expected_sha256 is not None and actual_sha256 != expected_sha256:
            raise RuntimeError(
                f"private build-context input digest mismatch for {source}: "
                f"expected {expected_sha256}, got {actual_sha256}"
            )
    finally:
        os.close(source_descriptor)


def copy_native_pilot_public_inputs(directory: Path, expected_sha256: str,
                                   metadata: dict[str, Any], context: Path) -> None:
    """Copy only the independently pinned public guest closure, never secrets.

    The fixed existing image packager independently rechecks every byte/pin.
    This producer does not sign or author the public policy/provenance inputs.
    """
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_sha256) or expected_sha256 == "sha256:" + "0" * 64:
        raise RuntimeError("an independently supplied public guest input SHA-256 is required")
    if not directory.is_absolute() or directory.resolve() != directory:
        raise RuntimeError("public guest input directory must be absolute and contain no symlink ancestors")
    destination = context / "production-shadow-custody"
    _copy_context_file(directory / "inputs.json", destination / "inputs.json", expected_sha256, maximum_bytes=16384)
    raw = (destination / "inputs.json").read_bytes()
    document = json.loads(raw)
    fields = {"apiVersion", "sourceManifestSha256", *(item[0] for item in PUBLIC_GUEST_FILES.values())}
    if (type(document) is not dict or set(document) != fields
            or document.get("apiVersion") != "serverware.nativeShadowCustodyImageInputs/v1"
            or (canonical_json(document) + "\n").encode("ascii") != raw
            or document["sourceManifestSha256"] != metadata["source_manifest_digest"]):
        raise RuntimeError("public guest manifest must be canonical ASCII plus exactly one LF and pin this exact admitted source")
    for filename, (field, maximum) in PUBLIC_GUEST_FILES.items():
        pin = document[field]
        if type(pin) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", pin) or pin == "sha256:" + "0" * 64:
            raise RuntimeError("invalid independently pinned public guest original")
        _copy_context_file(directory / filename, destination / filename, pin, maximum_bytes=maximum)


def _tracked_file_digests(metadata: dict[str, Any]) -> dict[str, str]:
    files = metadata["source_contract"]["sourceTreeManifest"]["files"]
    return {
        str(item["path"]): str(item["sha256"])
        for item in files
        if item.get("type") == "file"
    }


@contextmanager
def private_build_context(metadata: dict[str, Any]):
    contract_paths = (
        metadata["source_archive_path"],
        metadata["source_manifest_path"],
        metadata["source_file_list_path"],
        metadata["source_file_hashes_path"],
        metadata["source_file_modes_path"],
    )
    expected_contract_digests = {
        metadata["source_archive_path"]: metadata["source_archive_digest"],
        metadata["source_manifest_path"]: metadata["source_manifest_digest"],
        metadata["source_file_list_path"]: metadata["source_file_list_digest"],
        metadata["source_file_hashes_path"]: metadata["source_file_hashes_digest"],
        metadata["source_file_modes_path"]: metadata["source_file_modes_digest"],
    }
    tracked_digests = _tracked_file_digests(metadata)
    with tempfile.TemporaryDirectory(prefix="serverware-private-build-context.",
                                    dir=os.environ.get("TMPDIR") or "/srv/catchplate-fast/tmp") as temporary:
        context = Path(temporary)
        for relative in (*PRIVATE_CONTEXT_FILES, *contract_paths):
            relative_path = Path(relative)
            if relative_path.is_absolute() or any(
                part in {"", ".", ".."} for part in relative_path.parts
            ):
                raise RuntimeError(f"private build-context path escapes the repository: {relative}")
            source = ROOT / relative_path
            resolved_parent = source.parent.resolve()
            if resolved_parent != ROOT and ROOT not in resolved_parent.parents:
                raise RuntimeError(f"private build-context parent escapes the repository: {relative}")
            expected = expected_contract_digests.get(relative) or tracked_digests.get(relative)
            _copy_context_file(source, context / relative_path, expected)
        yield context


def build_command(
    dockerfile: str,
    tag: str,
    *,
    platform: str,
    metadata: dict[str, Any],
    context: Path,
) -> list[str]:
    if platform != PRODUCTION_PLATFORM:
        raise RuntimeError(f"production image platform must be {PRODUCTION_PLATFORM}")
    command = [
        "docker",
        "build",
        "--network=none",
        "-f",
        str(context / dockerfile),
        "-t",
        tag,
        "--platform",
        platform,
    ]
    component = "control plane" if dockerfile == "Dockerfile.production" else "decision gate"
    image_title = f"Serverware {component} {metadata['image_title_suffix']}"
    command.extend(source_build_arguments(metadata, image_title=image_title))
    command.append(str(context))
    return command


def source_build_arguments(
    metadata: dict[str, Any], *, image_title: str | None = None
) -> list[str]:
    values = [
        ("SERVERWARE_IMAGE_SOURCE", metadata["source"]),
        ("SERVERWARE_IMAGE_REVISION", metadata["revision"]),
        ("SERVERWARE_IMAGE_CREATED", metadata["created"]),
        ("SERVERWARE_SOURCE_TREE_DIGEST", metadata["source_tree_digest"]),
        ("SERVERWARE_SOURCE_ARCHIVE", metadata["source_archive_path"]),
        ("SERVERWARE_SOURCE_ARCHIVE_SHA256", metadata["source_archive_digest"]),
        ("SERVERWARE_SOURCE_MANIFEST", metadata["source_manifest_path"]),
        ("SERVERWARE_SOURCE_MANIFEST_SHA256", metadata["source_manifest_digest"]),
        ("SERVERWARE_SOURCE_FILE_LIST", metadata["source_file_list_path"]),
        ("SERVERWARE_SOURCE_FILE_LIST_SHA256", metadata["source_file_list_digest"]),
        ("SERVERWARE_SOURCE_FILE_HASHES", metadata["source_file_hashes_path"]),
        ("SERVERWARE_SOURCE_FILE_HASHES_SHA256", metadata["source_file_hashes_digest"]),
        ("SERVERWARE_SOURCE_FILE_MODES", metadata["source_file_modes_path"]),
        ("SERVERWARE_SOURCE_FILE_MODES_SHA256", metadata["source_file_modes_digest"]),
        ("SERVERWARE_SOURCE_IDENTITY_MODE", metadata["source_identity_mode"]),
        (
            "SERVERWARE_PRODUCTION_RELEASE_ELIGIBLE",
            "true" if metadata["production_release_eligible"] else "false",
        ),
        ("SOURCE_DATE_EPOCH", metadata["source_date_epoch"]),
    ]
    if image_title is not None:
        values.insert(3, ("SERVERWARE_IMAGE_TITLE", image_title))
    arguments: list[str] = []
    for name, value in values:
        arguments.extend(("--build-arg", f"{name}={value}"))
    return arguments


def artifact_build_command(
    dockerfile: str,
    target: str,
    output: str,
    *,
    network: str,
    platform: str,
    metadata: dict[str, Any],
    context: Path,
    public_inputs_sha256: str | None = None,
) -> list[str]:
    if (dockerfile, target) not in PRODUCTION_ARTIFACT_TARGETS:
        raise RuntimeError("unsupported production artifact Dockerfile/target pair")
    if network != "none":
        raise RuntimeError("production artifact builds require network=none")
    if platform != PRODUCTION_PLATFORM:
        raise RuntimeError(f"production artifact platform must be {PRODUCTION_PLATFORM}")
    if not output.startswith("type=local,dest=") or output == "type=local,dest=":
        raise RuntimeError("production artifact output must be a non-empty local destination")
    if target == NATIVE_PILOT_TARGET:
        if not isinstance(public_inputs_sha256, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", public_inputs_sha256):
            raise RuntimeError("native pilot artifact requires its independent public guest input pin")
        extra = ["--build-arg", "SHADOW_CUSTODY_INPUTS_SHA256=" + public_inputs_sha256]
    else:
        if public_inputs_sha256 is not None:
            raise RuntimeError("public guest inputs are forbidden for this artifact target")
        extra = []
    return [
        "docker",
        "buildx",
        "build",
        "--network=none",
        "--platform",
        platform,
        "--target",
        target,
        "--output",
        output,
        "-f",
        str(context / dockerfile),
        *source_build_arguments(metadata),
        *extra,
        str(context),
    ]


def verify_no_shell(image_ids: list[str]) -> dict[str, Any]:
    command = [sys.executable, "scripts/verify_production_images_no_shell.py"]
    for image in image_ids:
        command.extend(["--local-image-id", image])
    raw = run(command)
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError("no-shell verifier returned non-object JSON")
    if parsed.get("ok") is not True:
        raise RuntimeError(f"production image no-shell verification failed: {raw}")
    return parsed


def image_file_sha256(image: str, path: str) -> str:
    container_id = run(["docker", "create", image])
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            ["docker", "export", container_id],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.stdout is None:
            raise RuntimeError("docker export did not provide stdout")
        wanted = path.lstrip("/")
        digest: str | None = None
        with tarfile.open(fileobj=process.stdout, mode="r|*") as archive:
            for member in archive:
                member_path = member.name
                while member_path.startswith("./"):
                    member_path = member_path[2:]
                if member_path != wanted:
                    continue
                if digest is not None:
                    raise RuntimeError(f"production image contains duplicate path: {path}")
                if not member.isfile():
                    raise RuntimeError(f"production image path is not a regular file: {path}")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"production image path is not a regular file: {path}")
                hasher = hashlib.sha256()
                while chunk := extracted.read(1024 * 1024):
                    hasher.update(chunk)
                digest = "sha256:" + hasher.hexdigest()
        _, stderr = process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"docker export failed for {image}: {stderr.decode(errors='replace').strip()}")
        if digest is None:
            raise RuntimeError(f"production image does not contain required file: {path}")
        return digest
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        maybe_run(["docker", "rm", "-f", container_id])


def verify_image_platform(image: str, expected: str) -> None:
    actual = run(["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image])
    if actual != expected:
        raise RuntimeError(f"production image platform mismatch: expected {expected}, got {actual}")


def decision_gate_binary_digests(image: str) -> dict[str, str]:
    return {
        field: image_file_sha256(image, path)
        for field, path in DECISION_GATE_BINARY_PATHS.items()
    }


def image_launch_authority_binding(service: str, metadata: dict[str, str]) -> dict[str, str]:
    if service != "serverware-decision-gate":
        return {}
    return {field: metadata[field] for field in LAUNCH_AUTHORITY_METADATA_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build local shell-free Serverware production image candidates.")
    parser.add_argument("--control-tag")
    parser.add_argument("--decision-gate-tag")
    parser.add_argument("--platform", default=PRODUCTION_PLATFORM, choices=(PRODUCTION_PLATFORM,))
    parser.add_argument("--out")
    parser.add_argument("--dockerfile")
    parser.add_argument("--target")
    parser.add_argument("--output")
    parser.add_argument("--network", choices=("none",))
    parser.add_argument("--shadow-custody-inputs", type=Path)
    parser.add_argument("--shadow-custody-inputs-sha256")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--development-dirty-tree",
        action="store_true",
        help="Build an explicitly non-production image from dirty/untracked filesystem bytes.",
    )
    args = parser.parse_args()

    guest_inputs = (args.shadow_custody_inputs, args.shadow_custody_inputs_sha256)
    if args.target == NATIVE_PILOT_TARGET:
        if not all(guest_inputs):
            parser.error("native-pilot-artifacts requires --shadow-custody-inputs and --shadow-custody-inputs-sha256")
    elif any(guest_inputs):
        parser.error("public guest inputs require the explicit native-pilot-artifacts target")

    artifact_values = (args.dockerfile, args.target, args.output, args.network)
    if any(value is not None for value in artifact_values):
        if not all(value is not None for value in artifact_values):
            parser.error("--dockerfile, --target, --output, and --network are required together")
        if any((args.control_tag, args.decision_gate_tag, args.out, args.development_dirty_tree)):
            parser.error("production artifact mode cannot be combined with image build options")
        metadata = build_metadata()
        placeholder_context = Path("/private/serverware-build-context")
        if args.dry_run:
            print(
                canonical_json(
                    {
                        "ok": True,
                        "argv": artifact_build_command(
                            args.dockerfile,
                            args.target,
                            args.output,
                            network=args.network,
                            platform=args.platform,
                            metadata=metadata,
                            context=placeholder_context,
                            public_inputs_sha256=args.shadow_custody_inputs_sha256,
                        ),
                        "metadata": metadata,
                    }
                )
            )
            return
        verify_dependency_cache()
        with private_build_context(metadata) as context:
            if args.target == NATIVE_PILOT_TARGET:
                copy_native_pilot_public_inputs(args.shadow_custody_inputs, args.shadow_custody_inputs_sha256, metadata, context)
            command = artifact_build_command(
                args.dockerfile,
                args.target,
                args.output,
                network=args.network,
                platform=args.platform,
                metadata=metadata,
                context=context,
                public_inputs_sha256=args.shadow_custody_inputs_sha256,
            )
            run(command)
        print(
            canonical_json(
                {
                    "ok": True,
                    "dockerfile": args.dockerfile,
                    "target": args.target,
                    "output": args.output,
                    "source_tree_digest": metadata["source_tree_digest"],
                }
            )
        )
        return

    if args.development_dirty_tree:
        control_tag = args.control_tag or "serverware/control:development-dirty-tree"
        decision_gate_tag = (
            args.decision_gate_tag
            or "serverware/decision-gate:development-dirty-tree"
        )
        output = args.out or ".tmp/development-dirty-images-build.json"
    else:
        control_tag = args.control_tag or "serverware/control:production-local"
        decision_gate_tag = (
            args.decision_gate_tag or "serverware/decision-gate:production-local"
        )
        output = args.out or ".tmp/production-images-build.json"

    image_specs = [
        ("serverware-control", "Dockerfile.production", control_tag),
        ("serverware-decision-gate", "data-plane/decision-gate-rs/Dockerfile.production", decision_gate_tag),
    ]
    metadata = build_metadata(development_dirty_tree=args.development_dirty_tree)
    if args.dry_run:
        placeholder_context = Path("/private/serverware-build-context")
        commands = [
            {
                "service": service,
                "dockerfile": dockerfile,
                "tag": tag,
                "argv": build_command(
                    dockerfile,
                    tag,
                    platform=args.platform,
                    metadata=metadata,
                    context=placeholder_context,
                ),
            }
            for service, dockerfile, tag in image_specs
        ]
        print(
            canonical_json(
                {
                    "ok": True,
                    "identity_mode": metadata["source_identity_mode"],
                    "production_release_eligible": metadata[
                        "production_release_eligible"
                    ],
                    "commands": commands,
                    "metadata": metadata,
                    "platform": args.platform,
                    "out": output,
                }
            )
        )
        return

    images: list[dict[str, Any]] = []
    verify_dependency_cache()
    with private_build_context(metadata) as context:
        commands = [
            {
                "service": service,
                "dockerfile": dockerfile,
                "tag": tag,
                "argv": build_command(
                    dockerfile,
                    tag,
                    platform=args.platform,
                    metadata=metadata,
                    context=context,
                ),
            }
            for service, dockerfile, tag in image_specs
        ]
        for spec in commands:
            print(f"==> building {spec['service']} with {spec['dockerfile']}", file=sys.stderr)
            run(spec["argv"])
            built_image_id = image_id(spec["tag"])
            verify_image_platform(built_image_id, args.platform)
            binary_digests: dict[str, str] = {}
            if spec["service"] == "serverware-decision-gate":
                binary_digests = decision_gate_binary_digests(built_image_id)
            images.append(
                {
                    "service": spec["service"],
                    "tag": spec["tag"],
                    "dockerfile": spec["dockerfile"],
                    "image_id": built_image_id,
                    **binary_digests,
                    **image_launch_authority_binding(spec["service"], metadata),
                }
            )
    no_shell = verify_no_shell([str(item["image_id"]) for item in images])
    result = {
        "apiVersion": BUILD_API_VERSION,
        "kind": BUILD_KIND,
        "ok": True,
        "identity_mode": metadata["source_identity_mode"],
        "production_release_eligible": metadata["production_release_eligible"],
        "generated_at_unix": int(time.time()),
        "metadata": metadata,
        "images": images,
        "no_shell": no_shell,
        "publish_requirement": "publish these verified linux/amd64 image IDs unchanged, then set SERVERWARE_PRODUCTION_IMAGES to immutable @sha256 digest refs before live readiness",
    }
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(canonical_json(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(canonical_json({"ok": False, "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1) from exc
