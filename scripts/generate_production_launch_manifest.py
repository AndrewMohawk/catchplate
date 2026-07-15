#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import struct
import sys
from pathlib import Path
from typing import Any, Callable, Iterable


API_VERSION = "serverware.productionReadinessLaunch/v2"
KIND = "ProductionReadinessLaunch"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
DEPLOYMENT_AUDIENCE_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z", re.ASCII)
UNSIGNED_INTEGER_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z", re.ASCII)
SYSTEMD_SAFE_PATH_RE = re.compile(r"/[A-Za-z0-9._/+@:-]+\Z")
PYTHON_STDLIB_DIRECTORY_RE = re.compile(r"python3\.(?:0|[1-9][0-9]*)\Z", re.ASCII)
LAUNCHER_PATH_RE = re.compile(
    r"/opt/serverware/launchers/sha256-[0-9a-f]{64}/serverware-production-launcher\Z"
)
PRODUCTION_ENV_ROOT = Path("/etc/serverware")
MAX_MEASURED_FILE_BYTES = 512 * 1024 * 1024
MAX_PYTHON_EXECUTABLE_BYTES = 64 * 1024 * 1024
JSON_SAFE_INTEGER_MAX = 9_007_199_254_740_991
ELF64_HEADER_SIZE = 64
ELF64_PROGRAM_HEADER_SIZE = 56
ELF64_SECTION_HEADER_SIZE = 64
ELF64_SYMBOL_SIZE = 24
ELF64_DYNAMIC_SIZE = 16
ELF_MACHINE_X86_64 = 62
ELF_SECTION_DYNAMIC = 6
ELF_SECTION_DYNSYM = 11
ELF_SECTION_STRTAB = 3
ELF_DYNAMIC_NEEDED = 1

SYSTEMD_UNIT_TEMPLATE = """[Unit]
Description=Serverware closed production release proof
Documentation=https://github.com/example/private-deployment
After=network-online.target docker.service serverware-launch-authority-relay.socket
Wants=network-online.target serverware-launch-authority-relay.socket
Requires=docker.service serverware-launch-authority-relay.socket
ConditionFileIsExecutable=/opt/serverware/launchers/sha256-<launcher-sha256>/serverware-production-launcher
ConditionPathIsReadWrite=/var/lib/serverware/production-proof

[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/opt/serverware/launchers/sha256-<launcher-sha256>/serverware-production-launcher --manifest /etc/serverware/production-release-launch.json
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

# The immutable release, /etc trust material, and relay socket directory stay
# read-only. Proof state, launch receipts, and Docker socket access are the only
# writable paths. The relay socket unit alone owns /run/serverware lifecycle.
ReadOnlyPaths=/run/serverware
ReadWritePaths=/var/lib/serverware/production-proof /run/docker.sock

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


def hash_regular_file(
    raw: str,
    label: str,
    root: Path,
    *,
    content_validator: Callable[[bytes], None] | None = None,
    require_executable: bool = False,
) -> dict[str, str]:
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
        if require_executable and stat.S_IMODE(before.st_mode) & 0o111 == 0:
            raise ManifestError(f"{label} must be executable: {path}")
        digest = hashlib.sha256()
        validated_bytes = bytearray() if content_validator is not None else None
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            if validated_bytes is not None:
                validated_bytes.extend(chunk)
                if len(validated_bytes) > MAX_PYTHON_EXECUTABLE_BYTES:
                    raise ManifestError(f"{label} exceeds the bounded executable parser limit")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        raise ManifestError(f"{label} changed while it was hashed: {path}")
    current = os.stat(path, follow_symlinks=False)
    if any(getattr(after, field) != getattr(current, field) for field in stable_fields):
        raise ManifestError(f"{label} was replaced while it was hashed: {path}")
    if content_validator is not None and validated_bytes is not None:
        content_validator(bytes(validated_bytes))
    return {"path": str(path), "sha256": f"sha256:{digest.hexdigest()}"}


def checked_elf_slice(data: bytes, offset: int, size: int, label: str) -> bytes:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ManifestError(f"python ELF {label} is out of bounds")
    return data[offset : offset + size]


def elf_c_string(table: bytes, offset: int, label: str) -> bytes:
    if offset < 0 or offset >= len(table):
        raise ManifestError(f"python ELF {label} string offset is out of bounds")
    end = table.find(b"\0", offset)
    if end < 0:
        raise ManifestError(f"python ELF {label} string is not NUL-terminated")
    return table[offset:end]


def compatible_libpython_name(value: bytes, python_version: str) -> bool:
    prefix = f"lib{python_version}.so".encode("ascii")
    if value == prefix:
        return True
    if not value.startswith(prefix + b"."):
        return False
    suffix = value[len(prefix) + 1 :]
    return bool(suffix) and all(part and part.isdigit() for part in suffix.split(b"."))


def validate_cpython_elf64(data: bytes, python_version: str) -> None:
    # This is an interpreter identity check, not recursive loader closure. The
    # selected PT_INTERP and non-libpython DT_NEEDED descendants remain host trust.
    if len(data) < ELF64_HEADER_SIZE or data[:4] != b"\x7fELF":
        raise ManifestError("python must be an ELF executable, not a script or arbitrary file")
    if data[4:7] != b"\x02\x01\x01":
        raise ManifestError("python must use the ELF64 little-endian version-1 format")
    (
        _ident,
        elf_type,
        machine,
        version,
        _entry,
        program_offset,
        section_offset,
        _flags,
        header_size,
        program_entry_size,
        program_count,
        section_entry_size,
        section_count,
        section_name_index,
    ) = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if elf_type not in (2, 3) or machine != ELF_MACHINE_X86_64 or version != 1:
        raise ManifestError("python must be a Linux x86-64 ELF executable")
    if header_size != ELF64_HEADER_SIZE:
        raise ManifestError("python ELF header size is invalid")
    if program_count == 0 or program_entry_size != ELF64_PROGRAM_HEADER_SIZE:
        raise ManifestError("python ELF program-header table is invalid")
    checked_elf_slice(
        data,
        program_offset,
        program_count * program_entry_size,
        "program-header table",
    )
    if (
        section_count == 0
        or section_count > 4096
        or section_entry_size != ELF64_SECTION_HEADER_SIZE
        or section_name_index == 0xFFFF
    ):
        raise ManifestError("python ELF section-header table is unsupported or invalid")
    section_table = checked_elf_slice(
        data,
        section_offset,
        section_count * section_entry_size,
        "section-header table",
    )
    sections: list[tuple[int, int, int, int, int]] = []
    for index in range(section_count):
        (
            _name,
            section_type,
            _section_flags,
            _address,
            offset,
            size,
            link,
            _info,
            _alignment,
            entry_size,
        ) = struct.unpack_from(
            "<IIQQQQIIQQ", section_table, index * ELF64_SECTION_HEADER_SIZE
        )
        checked_elf_slice(data, offset, size, f"section {index}")
        sections.append((section_type, offset, size, link, entry_size))

    def linked_string_table(link: int, label: str) -> bytes:
        if link >= len(sections):
            raise ManifestError(f"python ELF {label} has an invalid string-table link")
        section_type, offset, size, _linked, _entry_size = sections[link]
        if section_type != ELF_SECTION_STRTAB:
            raise ManifestError(f"python ELF {label} does not link to a string table")
        return checked_elf_slice(data, offset, size, f"{label} string table")

    has_py_bytes_main = False
    needed_libraries: set[bytes] = set()
    for index, (section_type, offset, size, link, entry_size) in enumerate(sections):
        if section_type == ELF_SECTION_DYNSYM:
            if entry_size != ELF64_SYMBOL_SIZE or size % entry_size != 0:
                raise ManifestError("python ELF dynamic symbol table is malformed")
            strings = linked_string_table(link, f"dynamic symbol section {index}")
            symbols = checked_elf_slice(data, offset, size, "dynamic symbol table")
            for symbol_offset in range(0, len(symbols), ELF64_SYMBOL_SIZE):
                name_offset = struct.unpack_from("<I", symbols, symbol_offset)[0]
                if name_offset and elf_c_string(strings, name_offset, "dynamic symbol") == b"Py_BytesMain":
                    has_py_bytes_main = True
        elif section_type == ELF_SECTION_DYNAMIC:
            if entry_size != ELF64_DYNAMIC_SIZE or size % entry_size != 0:
                raise ManifestError("python ELF dynamic dependency table is malformed")
            strings = linked_string_table(link, f"dynamic section {index}")
            dynamic = checked_elf_slice(data, offset, size, "dynamic dependency table")
            for dynamic_offset in range(0, len(dynamic), ELF64_DYNAMIC_SIZE):
                tag, value = struct.unpack_from("<qQ", dynamic, dynamic_offset)
                if tag == ELF_DYNAMIC_NEEDED:
                    needed_libraries.add(elf_c_string(strings, value, "DT_NEEDED"))
    if not has_py_bytes_main:
        raise ManifestError("python ELF does not import the required Py_BytesMain symbol")
    if not any(compatible_libpython_name(value, python_version) for value in needed_libraries):
        raise ManifestError(
            f"python ELF does not depend on a compatible lib{python_version}.so"
        )


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


def require_cpython_extension_modules(descriptor: int) -> None:
    try:
        names = os.listdir(descriptor)
    except OSError as exc:
        raise ManifestError(f"cannot inspect python lib-dynload root: {exc}") from exc
    for name in names:
        if not name.endswith(".so"):
            continue
        try:
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as exc:
            raise ManifestError(
                f"cannot inspect python lib-dynload extension module: {name!r}: {exc}"
            ) from exc
        if stat.S_ISREG(metadata.st_mode):
            return
    raise ManifestError(
        "python lib-dynload root must contain at least one direct regular .so extension module"
    )


def hash_import_root(
    path: Path, label: str, *, require_extension_modules: bool = False
) -> str:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ManifestError(f"cannot open {label} securely: {path}: {exc}") from exc
    try:
        if require_extension_modules:
            require_cpython_extension_modules(descriptor)
        digest = hashlib.sha256(b"serverware.importRoot/v1\x00")
        hash_import_tree_fd(descriptor, b"", digest, label)
        return f"sha256:{digest.hexdigest()}"
    finally:
        os.close(descriptor)


def validate_import_roots(
    values: Iterable[str], release_root: Path, python_path: Path
) -> tuple[list[dict[str, str]], str]:
    expected_python = release_root / "runtime" / "python" / "bin" / "python3"
    if python_path != expected_python:
        raise ManifestError(f"python must use the exact release runtime executable: {expected_python}")

    raw_values = list(values)
    if len(raw_values) != 4:
        raise ManifestError(
            "python import roots must contain exactly release root, stdlib, lib-dynload, and vendor"
        )

    seen: set[str] = set()
    paths: list[Path] = []
    for index, raw in enumerate(raw_values):
        label = f"python import root {index + 1}"
        path = existing_directory(raw, label)
        contained_or_equal_path(path, release_root, label)
        rendered = str(path)
        if rendered in seen:
            raise ManifestError(f"duplicate python import root: {rendered}")
        seen.add(rendered)
        paths.append(path)

    stdlib = paths[1]
    expected_stdlib_parent = release_root / "runtime" / "python" / "lib"
    if stdlib.parent != expected_stdlib_parent or PYTHON_STDLIB_DIRECTORY_RE.fullmatch(stdlib.name) is None:
        raise ManifestError(
            f"python stdlib import root must be an exact python3.X directory beneath {expected_stdlib_parent}"
        )
    expected_paths = [
        release_root,
        stdlib,
        stdlib / "lib-dynload",
        release_root / "vendor",
    ]
    if paths != expected_paths:
        raise ManifestError(
            "python import roots must be ordered exactly as release root, stdlib, lib-dynload, vendor"
        )
    roots = [
        {
            "path": str(path),
            "sha256": hash_import_root(
                path,
                f"python import root {index + 1}",
                require_extension_modules=index == 2,
            ),
        }
        for index, path in enumerate(paths)
    ]
    return roots, stdlib.name


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


def validate_json_safe_integer(raw: str, label: str, *, allow_zero: bool) -> int:
    if not UNSIGNED_INTEGER_RE.fullmatch(raw):
        raise ManifestError(f"{label} must be a canonical nonnegative decimal integer")
    value = int(raw)
    if value > JSON_SAFE_INTEGER_MAX or (value == 0 and not allow_zero):
        qualifier = "nonnegative" if allow_zero else "positive"
        raise ManifestError(f"{label} must be a {qualifier} JSON-safe integer")
    return value


def render_systemd_unit(
    launcher_path: Path,
    manifest_path: Path,
    state_directory: Path,
) -> bytes:
    rendered = SYSTEMD_UNIT_TEMPLATE.replace(
        "/opt/serverware/launchers/sha256-<launcher-sha256>/serverware-production-launcher",
        str(launcher_path),
    ).replace(
        "/etc/serverware/production-release-launch.json",
        str(manifest_path),
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
        description="Generate an exact-byte-measured manifest for the closed native production-readiness launcher."
    )
    parser.add_argument("--output", required=True, help="absolute manifest output path")
    parser.add_argument("--systemd-unit-out", help="absolute output path for a concrete hardened systemd unit")
    parser.add_argument("--launcher-path", help="absolute content-addressed native launcher path")
    parser.add_argument("--release-root", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--source-tree-digest", required=True)
    parser.add_argument("--deployment-audience", required=True)
    parser.add_argument("--deployment-identity-sha256", required=True)
    parser.add_argument("--release-sequence", required=True)
    parser.add_argument("--rollback-epoch", required=True)
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
    if not DEPLOYMENT_AUDIENCE_RE.fullmatch(args.deployment_audience):
        raise ManifestError(
            "deployment audience must match ASCII [a-z0-9][a-z0-9._:-]{0,127}"
        )
    if not DIGEST_RE.fullmatch(args.deployment_identity_sha256):
        raise ManifestError(
            "deployment identity digest must be sha256:<64 lowercase hexadecimal characters>"
        )
    release_sequence = validate_json_safe_integer(
        args.release_sequence, "release sequence", allow_zero=False
    )
    rollback_epoch = validate_json_safe_integer(
        args.rollback_epoch, "rollback epoch", allow_zero=True
    )

    production_env = hash_regular_file(args.production_env, "production env", PRODUCTION_ENV_ROOT)
    python_path = absolute_normalized_path(args.python, "python")
    import_roots, python_version = validate_import_roots(
        args.python_import_root, release_root, python_path
    )
    python_record: dict[str, Any] = hash_regular_file(
        args.python,
        "python",
        release_root,
        content_validator=lambda data: validate_cpython_elf64(data, python_version),
        require_executable=True,
    )
    python_record["importRoots"] = import_roots

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
        "authorization": {
            "deploymentAudience": args.deployment_audience,
            "deploymentIdentitySha256": args.deployment_identity_sha256,
            "releaseSequence": release_sequence,
            "rollbackEpoch": rollback_epoch,
        },
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
            if not LAUNCHER_PATH_RE.fullmatch(str(launcher_path)):
                raise ManifestError(
                    "launcher path must identify the content-addressed native production launcher"
                )
            systemd_state_directory = systemd_literal_path(args.state_directory, "state directory")
        manifest, encoded = generate(args)
        del manifest
        manifest_digest = f"sha256:{hashlib.sha256(encoded).hexdigest()}"
        atomic_write_read_only(output_path, encoded, 0o400)
        if systemd_unit_path is not None and launcher_path is not None and systemd_state_directory is not None:
            unit = render_systemd_unit(launcher_path, output_path, systemd_state_directory)
            atomic_write_read_only(systemd_unit_path, unit, 0o444)
    except (ManifestError, OSError) as exc:
        parser.error(str(exc))
    if args.print_sha256:
        print(manifest_digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
