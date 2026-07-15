#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Any, Iterable


API_VERSION = "serverware.productionReadinessLaunch/v1"
KIND = "ProductionReadinessLaunch"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SYSTEMD_SAFE_PATH_RE = re.compile(r"/[A-Za-z0-9._/+@:-]+\Z")
PRODUCTION_ENV_ROOT = Path("/etc/serverware")
MAX_MEASURED_FILE_BYTES = 512 * 1024 * 1024

SYSTEMD_UNIT_TEMPLATE = """[Unit]
Description=Serverware closed production release proof
Documentation=https://github.com/example/private-deployment
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service
ConditionFileIsExecutable=/opt/serverware/launchers/sha256-<launcher-sha256>/serverware-production-launcher
ConditionPathIsReadWrite=/var/lib/serverware/production-proof

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/opt/serverware/launchers/sha256-<launcher-sha256>/serverware-production-launcher --manifest /etc/serverware/production-release-launch.json --manifest-sha256 sha256:<manifest-sha256>
StandardInput=null
StandardOutput=journal
StandardError=journal

# The launcher discards the service manager environment and constructs its
# closed child environment. Keep this service free of environment imports,
# preparatory commands, shells, and additional launcher arguments.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictRealtime=yes

# AWS Nitro Secure Module access is the only device exception. Remove both
# NSM lines on non-Nitro hosts; no other device may be added to this unit.
DevicePolicy=closed
DeviceAllow=/dev/nsm rw
BindReadOnlyPaths=-/dev/nsm

# The immutable release and /etc trust material stay read-only. The proof state,
# launch receipts, and the pinned local Docker socket are the only write paths.
ReadWritePaths=/var/lib/serverware/production-proof /run/serverware /run/docker.sock
RuntimeDirectory=serverware
RuntimeDirectoryMode=0700

[Install]
WantedBy=multi-user.target
"""

INPUT_ARGUMENTS = (
    ("productionImagesBuild", "production-images-build"),
    ("productionImagesEnv", "production-images-env"),
    ("productionImagesPublished", "production-images-published"),
    ("releaseProvenanceSummary", "release-provenance-summary"),
    ("releaseProvenance", "release-provenance"),
    ("imageSignaturesSummary", "image-signatures-summary"),
    ("imageSignatures", "image-signatures"),
    ("bench", "bench"),
    ("kmsMaterials", "kms-materials"),
    ("policyBundle", "policy-bundle"),
    ("policyTrustedPublicKey", "policy-trusted-public-key"),
    ("policyIdentityVerification", "policy-identity-verification"),
    ("policyActivationVerification", "policy-activation-verification"),
    ("policyActivationSignature", "policy-activation-signature"),
    ("policyActivationTrustedPublicKey", "policy-activation-trusted-public-key"),
    ("reproducibleBuildVerification", "reproducible-build-verification"),
    ("reproducibleBuildSignature", "reproducible-build-signature"),
    ("reproducibleBuildTrustedPublicKey", "reproducible-build-trusted-public-key"),
)

OUTPUT_ARGUMENTS = (
    ("configOut", "config-out"),
    ("claimsFile", "claims-file"),
    ("nitroEvidenceOut", "nitro-evidence-out"),
    ("readinessOut", "readiness-out"),
    ("completionProofOut", "completion-proof-out"),
    ("proxyProofSummaryOut", "proxy-proof-summary-out"),
    ("productionHostPreflight", "production-host-preflight"),
)


class ManifestError(ValueError):
    pass


def absolute_normalized_path(raw: str, label: str) -> Path:
    if not raw or "\x00" in raw:
        raise ManifestError(f"{label} must be a non-empty path without NUL bytes")
    if not os.path.isabs(raw):
        raise ManifestError(f"{label} must be absolute: {raw!r}")
    if raw.startswith("//"):
        raise ManifestError(f"{label} must use a single leading slash: {raw!r}")
    normalized = os.path.normpath(raw)
    if normalized != raw:
        raise ManifestError(f"{label} must be normalized: {raw!r}")
    return Path(raw)


def systemd_literal_path(raw: str, label: str) -> Path:
    path = absolute_normalized_path(raw, label)
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in raw):
        raise ManifestError(f"{label} must not contain whitespace or control characters: {raw!r}")
    if not SYSTEMD_SAFE_PATH_RE.fullmatch(raw):
        raise ManifestError(f"{label} contains characters unsafe for a literal systemd command: {raw!r}")
    return path


def reject_symlink_components(path: Path, label: str, *, allow_missing_leaf: bool = False) -> None:
    current = Path(path.anchor)
    components = path.parts[1:]
    for index, component in enumerate(components):
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            if allow_missing_leaf and index == len(components) - 1:
                return
            raise ManifestError(f"{label} does not exist: {current}") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise ManifestError(f"{label} contains a symlink component: {current}")


def existing_directory(raw: str, label: str) -> Path:
    path = absolute_normalized_path(raw, label)
    reject_symlink_components(path, label)
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ManifestError(f"{label} must be a directory: {path}")
    return path


def contained_path(path: Path, root: Path, label: str) -> None:
    try:
        common = os.path.commonpath((str(path), str(root)))
    except ValueError:
        common = ""
    if common != str(root) or path == root:
        raise ManifestError(f"{label} must be beneath {root}: {path}")


def contained_or_equal_path(path: Path, root: Path, label: str) -> None:
    try:
        common = os.path.commonpath((str(path), str(root)))
    except ValueError:
        common = ""
    if common != str(root):
        raise ManifestError(f"{label} must be {root} or beneath it: {path}")


def hash_regular_file(raw: str, label: str, root: Path) -> dict[str, str]:
    path = absolute_normalized_path(raw, label)
    contained_path(path, root, label)
    reject_symlink_components(path, label)

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ManifestError(f"cannot open {label} securely: {path}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ManifestError(f"{label} must be a regular file: {path}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise ManifestError(f"{label} changed while it was hashed: {path}")
    current = os.stat(path, follow_symlinks=False)
    if any(getattr(after, field) != getattr(current, field) for field in stable_fields):
        raise ManifestError(f"{label} was replaced while it was hashed: {path}")
    return {"path": str(path), "sha256": f"sha256:{digest.hexdigest()}"}


def stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def hash_import_tree_fd(
    descriptor: int,
    relative: bytes,
    digest: Any,
    label: str,
) -> None:
    before = os.fstat(descriptor)
    if not stat.S_ISDIR(before.st_mode):
        raise ManifestError(f"{label} must contain only directories and regular files")
    names = sorted(os.listdir(descriptor), key=os.fsencode)
    for name in names:
        encoded_name = os.fsencode(name)
        child_relative = encoded_name if not relative else relative + b"/" + encoded_name
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            child = os.open(name, flags, dir_fd=descriptor)
        except OSError as exc:
            raise ManifestError(f"cannot measure {label} securely: {name!r}: {exc}") from exc
        try:
            child_before = os.fstat(child)
            path_length = len(child_relative).to_bytes(8, "big")
            mode = stat.S_IMODE(child_before.st_mode).to_bytes(4, "big")
            if stat.S_ISDIR(child_before.st_mode):
                digest.update(b"directory\x00")
                digest.update(path_length)
                digest.update(child_relative)
                digest.update(mode)
                hash_import_tree_fd(child, child_relative, digest, label)
            elif stat.S_ISREG(child_before.st_mode):
                if child_before.st_size > MAX_MEASURED_FILE_BYTES:
                    raise ManifestError(f"{label} contains an oversized file: {name!r}")
                file_digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = os.read(child, 64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_MEASURED_FILE_BYTES:
                        raise ManifestError(f"{label} contains an oversized file: {name!r}")
                    file_digest.update(chunk)
                digest.update(b"file\x00")
                digest.update(path_length)
                digest.update(child_relative)
                digest.update(mode)
                digest.update(total.to_bytes(8, "big"))
                digest.update(file_digest.digest())
            else:
                raise ManifestError(f"{label} contains an unsupported filesystem entry: {name!r}")
            if stable_identity(child_before) != stable_identity(os.fstat(child)):
                raise ManifestError(f"{label} changed while it was measured")
        finally:
            os.close(child)
    if stable_identity(before) != stable_identity(os.fstat(descriptor)):
        raise ManifestError(f"{label} changed while it was measured")


def hash_import_root(path: Path, label: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ManifestError(f"cannot open {label} securely: {path}: {exc}") from exc
    try:
        digest = hashlib.sha256(b"serverware.importRoot/v1\x00")
        hash_import_tree_fd(descriptor, b"", digest, label)
        return f"sha256:{digest.hexdigest()}"
    finally:
        os.close(descriptor)


def validate_import_roots(values: Iterable[str], release_root: Path) -> list[dict[str, str]]:
    roots: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(values):
        label = f"python import root {index + 1}"
        path = existing_directory(raw, label)
        contained_or_equal_path(path, release_root, label)
        rendered = str(path)
        if rendered in seen:
            raise ManifestError(f"duplicate python import root: {rendered}")
        seen.add(rendered)
        roots.append({"path": rendered, "sha256": hash_import_root(path, label)})
    if not roots:
        raise ManifestError("at least one --python-import-root is required")
    return roots


def validate_output_path(raw: str, label: str, state_directory: Path) -> str:
    path = absolute_normalized_path(raw, label)
    contained_path(path, state_directory, label)
    if path.parent != state_directory:
        raise ManifestError(f"{label} must be a direct child of {state_directory}: {path}")
    reject_symlink_components(path, label, allow_missing_leaf=True)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        metadata = None
    if metadata is not None and not stat.S_ISREG(metadata.st_mode):
        raise ManifestError(f"{label} must be absent or a regular file: {path}")
    return str(path)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def render_systemd_unit(
    launcher_path: Path,
    manifest_path: Path,
    manifest_digest: str,
    state_directory: Path,
) -> bytes:
    if not DIGEST_RE.fullmatch(manifest_digest):
        raise ManifestError("manifest digest is not a canonical SHA-256 digest")
    rendered = SYSTEMD_UNIT_TEMPLATE.replace(
        "/opt/serverware/launchers/sha256-<launcher-sha256>/serverware-production-launcher",
        str(launcher_path),
    ).replace(
        "/etc/serverware/production-release-launch.json",
        str(manifest_path),
    ).replace(
        "sha256:<manifest-sha256>",
        manifest_digest,
    ).replace(
        "/var/lib/serverware/production-proof",
        str(state_directory),
    )
    if re.search(r"<(?:launcher|manifest)-sha256>", rendered):
        raise ManifestError("generated systemd unit still contains a launcher placeholder")
    return rendered.encode("utf-8")


def atomic_write_read_only(path: Path, content: bytes, mode: int) -> None:
    if mode not in (0o400, 0o444):
        raise ManifestError(f"unsupported atomic output mode: {mode:o}")
    parent = path.parent
    reject_symlink_components(parent, "manifest output directory")
    if not stat.S_ISDIR(os.lstat(parent).st_mode):
        raise ManifestError(f"manifest output directory must be a directory: {parent}")
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        raise ManifestError(f"manifest output must not replace a non-regular file: {path}")

    temporary = parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, mode)
        os.fchmod(descriptor, mode)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written == 0:
                raise ManifestError(f"manifest output write made no progress: {path}")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a byte-pinned manifest for the closed native production-readiness launcher."
    )
    parser.add_argument("--output", required=True, help="absolute manifest output path")
    parser.add_argument("--systemd-unit-out", help="absolute output path for a concrete hardened systemd unit")
    parser.add_argument("--launcher-path", help="absolute content-addressed native launcher path")
    parser.add_argument("--release-root", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--source-tree-digest", required=True)
    parser.add_argument("--production-env", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--python-import-root", action="append", required=True)
    parser.add_argument("--preflight-script", required=True)
    parser.add_argument("--runner-script", required=True)
    parser.add_argument("--compose-file", required=True)
    for _manifest_name, argument_name in INPUT_ARGUMENTS:
        parser.add_argument(f"--{argument_name}", required=True)
    for _manifest_name, argument_name in OUTPUT_ARGUMENTS:
        parser.add_argument(f"--{argument_name}", required=True)
    parser.add_argument("--print-sha256", action="store_true")
    return parser


def generate(args: argparse.Namespace) -> tuple[dict[str, Any], bytes]:
    release_root = existing_directory(args.release_root, "release root")
    state_directory = existing_directory(args.state_directory, "state directory")
    if os.path.commonpath((str(release_root), str(state_directory))) in (
        str(release_root),
        str(state_directory),
    ):
        raise ManifestError("release root and state directory must not contain one another")
    if not DIGEST_RE.fullmatch(args.source_tree_digest):
        raise ManifestError("source tree digest must be sha256:<64 lowercase hexadecimal characters>")

    production_env = hash_regular_file(args.production_env, "production env", PRODUCTION_ENV_ROOT)
    python_record: dict[str, Any] = hash_regular_file(args.python, "python", release_root)
    python_record["importRoots"] = validate_import_roots(args.python_import_root, release_root)

    inputs = {
        manifest_name: hash_regular_file(getattr(args, argument_name.replace("-", "_")), manifest_name, release_root)
        for manifest_name, argument_name in INPUT_ARGUMENTS
    }
    outputs = {
        manifest_name: validate_output_path(
            getattr(args, argument_name.replace("-", "_")), manifest_name, state_directory
        )
        for manifest_name, argument_name in OUTPUT_ARGUMENTS
    }
    if len(set(outputs.values())) != len(outputs):
        raise ManifestError("every output must use a distinct path")

    manifest = {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "releaseRoot": str(release_root),
        "stateDirectory": str(state_directory),
        "sourceTreeDigest": args.source_tree_digest,
        "productionEnv": production_env,
        "python": python_record,
        "scripts": {
            "preflight": hash_regular_file(args.preflight_script, "preflight script", release_root),
            "runner": hash_regular_file(args.runner_script, "runner script", release_root),
        },
        "composeFile": hash_regular_file(args.compose_file, "compose file", release_root),
        "inputs": inputs,
        "outputs": outputs,
    }
    return manifest, canonical_json(manifest)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        output_path = systemd_literal_path(args.output, "manifest output")
        if bool(args.systemd_unit_out) != bool(args.launcher_path):
            raise ManifestError("--systemd-unit-out and --launcher-path must be supplied together")
        systemd_unit_path = None
        launcher_path = None
        systemd_state_directory = None
        if args.systemd_unit_out:
            systemd_unit_path = systemd_literal_path(args.systemd_unit_out, "systemd unit output")
            launcher_path = systemd_literal_path(args.launcher_path, "launcher path")
            systemd_state_directory = systemd_literal_path(args.state_directory, "state directory")
        manifest, encoded = generate(args)
        del manifest
        manifest_digest = f"sha256:{hashlib.sha256(encoded).hexdigest()}"
        atomic_write_read_only(output_path, encoded, 0o400)
        if systemd_unit_path is not None and launcher_path is not None and systemd_state_directory is not None:
            unit = render_systemd_unit(launcher_path, output_path, manifest_digest, systemd_state_directory)
            atomic_write_read_only(systemd_unit_path, unit, 0o444)
    except (ManifestError, OSError) as exc:
        parser.error(str(exc))
    if args.print_sha256:
        print(manifest_digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
