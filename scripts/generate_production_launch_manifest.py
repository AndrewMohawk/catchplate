#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
import struct
import sys
import unicodedata
from pathlib import Path
from typing import Any, Callable, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


API_VERSION = "serverware.productionReadinessLaunch/v3"
KIND = "ProductionReadinessLaunch"
PIPELINE = "legacy-docker-dev-nsm-readiness"
INCOMPATIBLE_FINAL_PIPELINE = "manifest-v6-promoted-oci-nitro-eif"
PIPELINE_METADATA_API_VERSION = "serverware.launchPipelineMetadata/v1"
NONCE_ROLLBACK_ASSURANCE_BINDING_VERSION = (
    "serverware.productionNonceRollbackAssuranceBinding/v1"
)
NONCE_ROLLBACK_ASSURANCE_PINS_VERSION = (
    "serverware.productionNonceRollbackAssurancePins/v1"
)
CANONICAL_JSON_PROFILE = (
    "serverware.canonicalJson/integer-string-bool-null-array-object-nfc-v1"
)
WITNESS_STORE_ASSURANCE_API_VERSION = (
    "serverware.launchAuthorityWitnessStoreAssurance/v1"
)
WITNESS_STORE_ASSURANCE_KIND = "LaunchAuthorityWitnessStoreAssurance"
GLOBAL_ROLE_REGISTRY_BINDING_API_VERSION = (
    "serverware.productionLaunchGlobalRoleRegistryBinding/v1"
)
GLOBAL_ROLE_REGISTRY_API_VERSION = (
    "serverware.productionLaunchGlobalRoleRegistry/v1"
)
GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE = "roles-present-in-native-launch-contract"
ATTEMPT_JOURNAL_API_VERSION = (
    "serverware.launchAuthorizationAttemptJournal/v1"
)
ATTEMPT_JOURNAL_DOMAIN = (
    "serverware.launchAuthorizationAttemptJournal/v1"
)
ATTEMPT_JOURNAL_CONSISTENCY_SCOPE = (
    "trusted-host-readiness-availability-and-consistency-only"
)
ATTEMPT_JOURNAL_ROLLBACK_AUTHORITY = "external-monotonic-witness"
ATTEMPT_JOURNAL_FILE_NAME = "launch-authorization-attempt.v1.json"
ATTEMPT_JOURNAL_LOCK_FILE_NAME = "launch-authorization-attempt.v1.lock"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
DEPLOYMENT_AUDIENCE_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z", re.ASCII)
UNSIGNED_INTEGER_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z", re.ASCII)
PRODUCTION_MANIFEST_PATH_PATTERN = (
    r"^/(?:[A-Za-z0-9._+@:-]+/)*[A-Za-z0-9._+@:-]+$"
)
PRODUCTION_MANIFEST_PATH_RE = re.compile(
    PRODUCTION_MANIFEST_PATH_PATTERN,
    re.ASCII,
)
MAX_PRODUCTION_MANIFEST_PATH_BYTES = 4096
SYSTEMD_SAFE_PATH_RE = PRODUCTION_MANIFEST_PATH_RE
PYTHON_STDLIB_DIRECTORY_RE = re.compile(r"python3\.(?:0|[1-9][0-9]*)\Z", re.ASCII)
LAUNCHER_PATH_RE = re.compile(
    r"/opt/serverware/launchers/sha256-[0-9a-f]{64}/serverware-production-launcher\Z"
)
PRODUCTION_ENV_ROOT = Path("/etc/serverware")
PRODUCTION_STATE_DIRECTORY = Path("/var/lib/serverware/production-proof")
MAX_MEASURED_FILE_BYTES = 512 * 1024 * 1024
MAX_PYTHON_EXECUTABLE_BYTES = 64 * 1024 * 1024
MAX_NONCE_ROLLBACK_ASSURANCE_PINS_BYTES = 64 * 1024
MAX_GLOBAL_ROLE_REGISTRY_PINS_BYTES = 64 * 1024
MAX_ATTEMPT_JOURNAL_BYTES = 64 * 1024
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
GLOBAL_ROLE_NAMES = (
    "launchAuthority",
    "launchAuthorityWitness",
    "launchAuthorityWitnessStoreAssurance",
    "launchAuthorityWitnessTls",
    "nonceAuthorityAssuranceEvidence",
    "nonceAuthorityVerifierState",
    "nonceAuthorityVerifierStateStoreAttestation",
    "policyActivation",
    "policyIdentity",
    "reproducibleBuild",
)
GLOBAL_ROLES_OUTSIDE_CLAIM = (
    "actionGate",
    "publicAttestationNonceStore",
    "publicAttestationProducer",
    "publicAttestationWitnessStore",
    "finalVerifier",
    "nonceAuthorityVerifierStateStoreAssurance",
    "release",
    "response",
    "verifierStateTlsClient",
    "verifierStateTlsServer",
)
INDEPENDENT_ADMINISTRATION_BINDINGS = (
    "launchAuthority.signingKeyId",
    "launchAuthorityWitness.signingKeyId",
    "launchAuthorityWitness.identitySha256",
    "launchAuthorityWitness.administrativeDomainSha256",
    "launchAuthorityWitnessStore.identitySha256",
    "launchAuthorityWitnessStore.administrativeDomainSha256",
    "launchAuthorityWitnessStore.assuranceIssuerKeyId",
)

SYSTEMD_UNIT_TEMPLATE = """[Unit]
Description=Serverware legacy Docker NSM production-readiness proof
Documentation=https://github.com/example/private-deployment
After=network-online.target docker.service serverware-launch-authority-relay.socket
Wants=network-online.target serverware-launch-authority-relay.socket
Requires=docker.service serverware-launch-authority-relay.socket

[Service]
Type=oneshot
RemainAfterExit=yes
User=root
Group=root
UMask=0077
ExecStart=/opt/serverware/launchers/sha256-<launcher-sha256>/serverware-production-launcher --manifest /etc/serverware/production-release-launch.json
StandardInput=null
StandardOutput=journal
StandardError=journal

# The launcher discards the service manager environment and constructs its
# closed child environment. Keep this service free of environment imports,
# preparatory commands, shells, skip-capable Condition directives, and
# additional launcher arguments. Missing prerequisites must fail ExecStart.
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

# This legacy readiness pipeline exposes NSM to a host Docker workload. It is
# intentionally incompatible with Manifest v6 final-completion evidence.
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

PRODUCTION_NONCE_ASSURANCE_PROFILES = {
    "productionHardwareMonotonicCounter": {
        "assuranceEvidenceType": "hardwareMonotonicCounterAttestation",
        "backendClass": "hardwareMonotonicCounter",
        "keyProtection": "nonExportableHsm",
        "rollbackMechanism": "hardwareMonotonicCounter",
        "stateCommitment": "monotonicCounterCommitment",
        "verifierStateStoreClass": "hardwareProtectedStateStore",
    },
    "productionIndependentLinearizableCas": {
        "assuranceEvidenceType": "linearizableCasOperatorAttestation",
        "backendClass": "independentlyAdministeredLinearizableCas",
        "keyProtection": "nonExportableKmsHsm",
        "rollbackMechanism": "linearizableCasWithRollbackProtectedStorage",
        "stateCommitment": "hashChainedLinearizableCommitment",
        "verifierStateStoreClass":
        "independentlyAdministeredLinearizableCas",
    },
    "productionAppendOnlyTransparencyLedger": {
        "assuranceEvidenceType": "transparencyLedgerOperatorAttestation",
        "backendClass": "appendOnlyTransparencyLedger",
        "keyProtection": "nonExportableKmsHsm",
        "rollbackMechanism": "appendOnlyWitnessedLedger",
        "stateCommitment": "appendOnlyMerkleCommitment",
        "verifierStateStoreClass":
        "independentlyAdministeredLinearizableCas",
    },
}


class ManifestError(ValueError):
    pass


def absolute_normalized_path(raw: str, label: str) -> Path:
    if not raw or "\x00" in raw:
        raise ManifestError(f"{label} must be a non-empty path without NUL bytes")
    if len(raw) > MAX_PRODUCTION_MANIFEST_PATH_BYTES:
        raise ManifestError(
            f"{label} exceeds the {MAX_PRODUCTION_MANIFEST_PATH_BYTES}-byte "
            "production path limit"
        )
    if PRODUCTION_MANIFEST_PATH_RE.fullmatch(raw) is None:
        raise ManifestError(
            f"{label} must use the safe printable-ASCII production path syntax: "
            f"{raw!r}"
        )
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
    if not SYSTEMD_SAFE_PATH_RE.fullmatch(raw):
        raise ManifestError(f"{label} contains characters unsafe for a literal systemd command: {raw!r}")
    return path


def require_pairwise_distinct_bindings(bindings: dict[str, str]) -> None:
    if tuple(bindings) != INDEPENDENT_ADMINISTRATION_BINDINGS:
        raise ManifestError(
            "independent-administration binding inventory is incomplete or reordered"
        )
    owners: dict[str, str] = {}
    for label, value in bindings.items():
        if DIGEST_RE.fullmatch(value) is None:
            raise ManifestError(
                f"independent-administration binding {label} is not a SHA-256 identity"
            )
        previous = owners.get(value)
        if previous is not None:
            raise ManifestError(
                "independentAdministration requires pairwise-distinct authority, "
                f"witness, and witness-store bindings: {previous} collides with "
                f"{label}"
            )
        owners[value] = label


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


def validate_canonical_json_profile(
    value: Any,
    *,
    label: str,
    depth: int = 0,
) -> None:
    if depth > 64:
        raise ManifestError(f"{label} exceeds the canonical JSON nesting limit")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ManifestError(f"{label} contains a non-string object key")
            validate_canonical_json_string(key, f"{label} object key")
            validate_canonical_json_profile(
                child,
                label=label,
                depth=depth + 1,
            )
        return
    if isinstance(value, list):
        for child in value:
            validate_canonical_json_profile(
                child,
                label=label,
                depth=depth + 1,
            )
        return
    if isinstance(value, str):
        validate_canonical_json_string(value, label)
        return
    if value is None or isinstance(value, bool):
        return
    if type(value) is int:
        if not -JSON_SAFE_INTEGER_MAX <= value <= JSON_SAFE_INTEGER_MAX:
            raise ManifestError(
                f"{label} integer is outside the canonical JSON-safe range"
            )
        return
    raise ManifestError(
        f"{label} contains a value outside {CANONICAL_JSON_PROFILE}"
    )


def validate_canonical_json_string(value: str, label: str) -> None:
    if "\x00" in value:
        raise ManifestError(f"{label} contains NUL")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ManifestError(f"{label} contains a Unicode surrogate")
    if unicodedata.normalize("NFC", value) != value:
        raise ManifestError(f"{label} is not Unicode NFC")


def canonical_json(value: Any) -> bytes:
    validate_canonical_json_profile(value, label="canonical JSON value")
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


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
        description=(
            "Generate the exact-byte-measured legacy Docker /dev/nsm readiness "
            "manifest. This artifact cannot satisfy Manifest v6 final completion."
        )
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
    parser.add_argument("--expected-launch-authority-key-id", required=True)
    parser.add_argument(
        "--global-role-registry",
        required=True,
        help="absolute root-owned canonical role registry below /etc/serverware",
    )
    parser.add_argument(
        "--expected-global-role-registry-pins-sha256",
        required=True,
        help="independent digest of the exact global role registry file",
    )
    parser.add_argument(
        "--launch-authority-witness-signing-public-key-spki-base64url",
        required=True,
    )
    parser.add_argument("--expected-launch-authority-witness-key-id", required=True)
    parser.add_argument("--launch-authority-witness-identity-sha256", required=True)
    parser.add_argument(
        "--launch-authority-witness-administrative-domain-sha256",
        required=True,
    )
    parser.add_argument(
        "--launch-authority-witness-store-assurance-sha256",
        required=True,
    )
    parser.add_argument(
        "--launch-authority-witness-store-assurance",
        required=True,
    )
    parser.add_argument(
        "--launch-authority-witness-store-assurance-issuer-public-key-spki-base64url",
        required=True,
    )
    parser.add_argument(
        "--expected-launch-authority-witness-store-assurance-issuer-key-id",
        required=True,
    )
    parser.add_argument(
        "--nonce-rollback-assurance-pins",
        required=True,
        help=(
            "absolute root-owned canonical pin contract below "
            "/etc/serverware"
        ),
    )
    parser.add_argument(
        "--expected-nonce-rollback-assurance-pins-sha256",
        required=True,
        help="independent digest of the exact pin-contract bytes",
    )
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
    parser.add_argument(
        "--pipeline-metadata-out",
        required=True,
        help=(
            "required informational projection of the rollback binding "
            "already enforced by the consumed launch manifest"
        ),
    )
    return parser


def canonical_json_value(value: Any) -> bytes:
    validate_canonical_json_profile(value, label="canonical JSON value")
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def exact_object_keys(
    value: Any,
    expected: set[str],
    label: str,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise ManifestError(f"{label} does not have the exact required fields")
    return value


def decode_ed25519_spki(value: Any, label: str) -> bytes:
    if type(value) is not str or not value:
        raise ManifestError(f"{label} must be non-empty base64url")
    if "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value, re.ASCII):
        raise ManifestError(f"{label} is not canonical unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise ManifestError(f"{label} is invalid base64url") from exc
    expected_prefix = bytes.fromhex("302a300506032b6570032100")
    if len(decoded) != 44 or not decoded.startswith(expected_prefix):
        raise ManifestError(f"{label} is not an Ed25519 SPKI DER key")
    if (
        base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
        != value
    ):
        raise ManifestError(f"{label} is not canonical base64url")
    return decoded


def decode_ed25519_signature(value: Any, label: str) -> bytes:
    if (
        type(value) is not str
        or "=" in value
        or not re.fullmatch(r"[A-Za-z0-9_-]+", value, re.ASCII)
    ):
        raise ManifestError(f"{label} is not canonical unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise ManifestError(f"{label} is invalid base64url") from exc
    if (
        len(decoded) != 64
        or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
        != value
    ):
        raise ManifestError(f"{label} must encode exactly 64 canonical bytes")
    return decoded


def load_launch_authority_witness_store_assurance(
    args: argparse.Namespace,
    *,
    witness_key_id: str,
) -> tuple[dict[str, Any], str, str]:
    path = absolute_normalized_path(
        args.launch_authority_witness_store_assurance,
        "launch authority witness store assurance",
    )
    reject_symlink_components(path, "launch authority witness store assurance")
    raw = path.read_bytes()
    if not raw or len(raw) > 64 * 1024:
        raise ManifestError(
            "launch authority witness store assurance size is invalid"
        )
    try:
        document = json.loads(
            raw,
            object_pairs_hook=reject_json_pairs,
            parse_float=reject_json_value,
            parse_constant=reject_json_value,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(
            "launch authority witness store assurance is invalid JSON"
        ) from exc
    envelope = exact_object_keys(
        document,
        {"apiVersion", "kind", "statement", "signature"},
        "launch authority witness store assurance",
    )
    if (
        envelope["apiVersion"] != WITNESS_STORE_ASSURANCE_API_VERSION
        or envelope["kind"] != WITNESS_STORE_ASSURANCE_KIND
    ):
        raise ManifestError(
            "launch authority witness store assurance version is invalid"
        )
    statement = exact_object_keys(
        envelope["statement"],
        {
            "assuranceIssuerKeyId",
            "witnessKeyId",
            "witnessIdentitySha256",
            "witnessAdministrativeDomainSha256",
            "storeIdentitySha256",
            "storeAdministrativeDomainSha256",
            "storeClass",
            "rollbackResistance",
            "independentAdministration",
        },
        "launch authority witness store assurance statement",
    )
    if canonical_json_value(envelope) != raw:
        raise ManifestError(
            "launch authority witness store assurance must be canonical JSON"
        )
    issuer_spki_der = decode_ed25519_spki(
        args.launch_authority_witness_store_assurance_issuer_public_key_spki_base64url,
        "launch authority witness store assurance issuer key",
    )
    issuer_key_id = "sha256:" + hashlib.sha256(issuer_spki_der).hexdigest()
    if (
        not DIGEST_RE.fullmatch(
            args.expected_launch_authority_witness_store_assurance_issuer_key_id
        )
        or issuer_key_id
        != args.expected_launch_authority_witness_store_assurance_issuer_key_id
        or statement["assuranceIssuerKeyId"] != issuer_key_id
    ):
        raise ManifestError(
            "launch authority witness store assurance issuer does not match "
            "its independent key pin"
        )
    for field in (
        "witnessKeyId",
        "witnessIdentitySha256",
        "witnessAdministrativeDomainSha256",
        "storeIdentitySha256",
        "storeAdministrativeDomainSha256",
    ):
        if not DIGEST_RE.fullmatch(str(statement[field])):
            raise ManifestError(
                f"launch authority witness store assurance {field} is invalid"
            )
    if (
        statement["witnessKeyId"] != witness_key_id
        or statement["witnessIdentitySha256"]
        != args.launch_authority_witness_identity_sha256
        or statement["witnessAdministrativeDomainSha256"]
        != args.launch_authority_witness_administrative_domain_sha256
        or statement["storeClass"]
        not in {
            "hardwareMonotonicCounter",
            "independentlyAdministeredLinearizableCas",
            "appendOnlyTransparencyLedger",
        }
        or statement["rollbackResistance"]
        != "externally-witnessed-monotonic"
        or statement["independentAdministration"] is not True
    ):
        raise ManifestError(
            "launch authority witness store assurance does not bind an "
            "independently administered rollback-resistant store"
        )
    unsigned = {
        "apiVersion": envelope["apiVersion"],
        "kind": envelope["kind"],
        "statement": statement,
    }
    try:
        public_key = serialization.load_der_public_key(issuer_spki_der)
    except (TypeError, ValueError) as exc:
        raise ManifestError(
            "launch authority witness store assurance issuer key is invalid"
        ) from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ManifestError(
            "launch authority witness store assurance issuer key is not Ed25519"
        )
    signing_bytes = (
        WITNESS_STORE_ASSURANCE_API_VERSION.encode("ascii")
        + b"\0"
        + canonical_json_value(unsigned)
    )
    try:
        public_key.verify(
            decode_ed25519_signature(
                envelope["signature"],
                "launch authority witness store assurance signature",
            ),
            signing_bytes,
        )
    except InvalidSignature as exc:
        raise ManifestError(
            "launch authority witness store assurance signature is invalid"
        ) from exc
    assurance_sha256 = (
        "sha256:" + hashlib.sha256(canonical_json_value(envelope)).hexdigest()
    )
    if (
        args.launch_authority_witness_store_assurance_sha256
        != assurance_sha256
    ):
        raise ManifestError(
            "launch authority witness store assurance does not match its "
            "independent digest pin"
        )
    require_pairwise_distinct_bindings(
        {
            "launchAuthority.signingKeyId": args.expected_launch_authority_key_id,
            "launchAuthorityWitness.signingKeyId": witness_key_id,
            "launchAuthorityWitness.identitySha256": statement[
                "witnessIdentitySha256"
            ],
            "launchAuthorityWitness.administrativeDomainSha256": statement[
                "witnessAdministrativeDomainSha256"
            ],
            "launchAuthorityWitnessStore.identitySha256": statement[
                "storeIdentitySha256"
            ],
            "launchAuthorityWitnessStore.administrativeDomainSha256": statement[
                "storeAdministrativeDomainSha256"
            ],
            "launchAuthorityWitnessStore.assuranceIssuerKeyId": issuer_key_id,
        }
    )
    return envelope, issuer_key_id, assurance_sha256


def reject_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ManifestError(f"duplicate JSON object key: {key!r}")
        document[key] = value
    return document


def reject_json_value(value: str) -> Any:
    raise ManifestError(f"noncanonical JSON numeric value: {value!r}")


def load_nonce_rollback_assurance_pins(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], dict[str, str]]:
    expected_file_sha256 = (
        args.expected_nonce_rollback_assurance_pins_sha256
    )
    if not DIGEST_RE.fullmatch(expected_file_sha256):
        raise ManifestError(
            "expected nonce rollback assurance pins digest must be "
            "sha256:<64 lowercase hexadecimal characters>"
        )
    path = absolute_normalized_path(
        args.nonce_rollback_assurance_pins,
        "nonce rollback assurance pins",
    )
    contained_path(path, PRODUCTION_ENV_ROOT, "nonce rollback assurance pins")
    reject_symlink_components(path, "nonce rollback assurance pins")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in (0o400, 0o440)
        ):
            raise ManifestError(
                "nonce rollback assurance pins must be a root:root-owned, "
                "single-linked regular file with mode exactly 0400 or 0440"
            )
        if not 1 <= before.st_size <= MAX_NONCE_ROLLBACK_ASSURANCE_PINS_BYTES:
            raise ManifestError(
                "nonce rollback assurance pins are empty or exceed 64 KiB"
            )
        chunks: list[bytes] = []
        remaining = MAX_NONCE_ROLLBACK_ASSURANCE_PINS_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if stable_identity(before) != stable_identity(after):
        raise ManifestError(
            "nonce rollback assurance pins changed while being read"
        )
    current = os.stat(path, follow_symlinks=False)
    if stable_identity(after) != stable_identity(current):
        raise ManifestError(
            "nonce rollback assurance pins were replaced while being read"
        )
    if len(raw) > MAX_NONCE_ROLLBACK_ASSURANCE_PINS_BYTES:
        raise ManifestError("nonce rollback assurance pins exceed 64 KiB")
    file_sha256 = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    if file_sha256 != expected_file_sha256:
        raise ManifestError(
            "nonce rollback assurance pins differ from the independent digest"
        )
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_json_pairs,
            parse_float=reject_json_value,
            parse_constant=reject_json_value,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(
            "nonce rollback assurance pins are not strict UTF-8 JSON"
        ) from exc
    if raw != canonical_json_value(document) + b"\n":
        raise ManifestError(
            "nonce rollback assurance pins are not canonical JSON plus LF"
        )
    contract = exact_object_keys(
        document,
        {
            "apiVersion",
            "independentVerifierPins",
            "publicConfigPins",
        },
        "nonce rollback assurance pins",
    )
    if contract["apiVersion"] != NONCE_ROLLBACK_ASSURANCE_PINS_VERSION:
        raise ManifestError("nonce rollback assurance pins version is invalid")
    independent = exact_object_keys(
        contract["independentVerifierPins"],
        {
            "expectedNonceAuthorityAssuranceIssuerSpkiSha256",
            "expectedNonceAuthorityAssuranceSha256",
        },
        "independent nonce rollback verifier pins",
    )
    public = exact_object_keys(
        contract["publicConfigPins"],
        {
            "nonceAuthorityAssurance",
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityAssuranceSha256",
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256",
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256",
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreIdentitySha256",
        },
        "public nonce rollback config pins",
    )
    assurance = exact_object_keys(
        public["nonceAuthorityAssurance"],
        {
            "apiVersion",
            "administrativeDomainSha256",
            "assuranceEvidenceSha256",
            "assuranceEvidenceType",
            "assuranceLevel",
            "authorityEpoch",
            "authorityGeneration",
            "authorityIdentitySha256",
            "backendClass",
            "productionEligible",
            "rollbackProtection",
        },
        "nonce authority assurance",
    )
    rollback = exact_object_keys(
        assurance["rollbackProtection"],
        {
            "administrativeRollbackResistance",
            "backendAttestationRequired",
            "exactSuccessorRequired",
            "freshVerifierChallengeRequired",
            "keyProtection",
            "mechanism",
            "stateCommitment",
            "verifierStateStoreClass",
        },
        "nonce authority rollback protection",
    )
    digest_fields = (
        independent[
            "expectedNonceAuthorityAssuranceIssuerSpkiSha256"
        ],
        independent["expectedNonceAuthorityAssuranceSha256"],
        public["nonceAuthorityAssuranceSha256"],
        public[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ],
        public[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ],
        public["nonceAuthorityVerifierStateStoreIdentitySha256"],
        assurance["administrativeDomainSha256"],
        assurance["assuranceEvidenceSha256"],
        assurance["authorityIdentitySha256"],
    )
    if any(type(value) is not str or not DIGEST_RE.fullmatch(value) for value in digest_fields):
        raise ManifestError("nonce rollback assurance pins contain an invalid digest")
    assurance_sha256 = (
        "sha256:"
        + hashlib.sha256(canonical_json_value(assurance)).hexdigest()
    )
    evidence_der = decode_ed25519_spki(
        public[
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
        ],
        "nonce authority assurance evidence key",
    )
    verifier_state_der = decode_ed25519_spki(
        public[
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
        ],
        "nonce authority verifier-state key",
    )
    verifier_state_store_attestation_der = decode_ed25519_spki(
        public[
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
        ],
        "nonce authority verifier-state store attestation key",
    )
    evidence_key_id = f"sha256:{hashlib.sha256(evidence_der).hexdigest()}"
    verifier_state_key_id = (
        f"sha256:{hashlib.sha256(verifier_state_der).hexdigest()}"
    )
    verifier_state_store_attestation_key_id = (
        "sha256:"
        + hashlib.sha256(verifier_state_store_attestation_der).hexdigest()
    )
    administrative_and_service_identities = {
        assurance["administrativeDomainSha256"],
        assurance["authorityIdentitySha256"],
        public[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ],
        public["nonceAuthorityVerifierStateStoreIdentitySha256"],
    }
    profile = {
        "assuranceEvidenceType": assurance["assuranceEvidenceType"],
        "backendClass": assurance["backendClass"],
        "keyProtection": rollback["keyProtection"],
        "rollbackMechanism": rollback["mechanism"],
        "stateCommitment": rollback["stateCommitment"],
        "verifierStateStoreClass": rollback["verifierStateStoreClass"],
    }
    # Native code stores these values in unsigned integer fields, but this
    # launch contract accepts only JSON-safe integers through 2^53-1.
    if (
        assurance["apiVersion"]
        != "serverware.nonceAuthorityAssurance/v1"
        or assurance["productionEligible"] is not True
        or assurance["assuranceLevel"] != "productionRollbackProtected"
        or type(assurance["authorityEpoch"]) is not int
        or not 1 <= assurance["authorityEpoch"] <= JSON_SAFE_INTEGER_MAX
        or type(assurance["authorityGeneration"]) is not int
        or not 1 <= assurance["authorityGeneration"] <= JSON_SAFE_INTEGER_MAX
        or rollback["administrativeRollbackResistance"] is not True
        or rollback["backendAttestationRequired"] is not True
        or rollback["exactSuccessorRequired"] is not True
        or rollback["freshVerifierChallengeRequired"] is not True
        or profile not in PRODUCTION_NONCE_ASSURANCE_PROFILES.values()
        or public["nonceAuthorityAssuranceSha256"] != assurance_sha256
        or independent["expectedNonceAuthorityAssuranceSha256"]
        != assurance_sha256
        or independent[
            "expectedNonceAuthorityAssuranceIssuerSpkiSha256"
        ]
        != evidence_key_id
        or len(
            {
                evidence_key_id,
                verifier_state_key_id,
                verifier_state_store_attestation_key_id,
            }
        )
        != 3
        or len(administrative_and_service_identities) != 4
        or evidence_key_id in administrative_and_service_identities
        or verifier_state_key_id in administrative_and_service_identities
        or verifier_state_store_attestation_key_id
        in administrative_and_service_identities
        or public[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ]
        == assurance["assuranceEvidenceSha256"]
    ):
        raise ManifestError(
            "nonce rollback assurance pins do not form an independently "
            "pinned production rollback profile"
        )
    return contract, {"path": str(path), "sha256": file_sha256}


def load_canonical_ed25519_public_key_id(raw: str, label: str) -> str:
    path = absolute_normalized_path(raw, label)
    reject_symlink_components(path, label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > 64 * 1024
        ):
            raise ManifestError(
                f"{label} must be a bounded single-linked regular file"
            )
        chunks: list[bytes] = []
        remaining = 64 * 1024 + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw_key = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if stable_identity(before) != stable_identity(after):
        raise ManifestError(f"{label} changed while being read")
    if len(raw_key) > 64 * 1024:
        raise ManifestError(f"{label} exceeds 64 KiB")
    try:
        key = serialization.load_pem_public_key(raw_key)
    except (TypeError, ValueError) as exc:
        raise ManifestError(f"{label} is not a public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ManifestError(f"{label} must contain an Ed25519 public key")
    canonical_pem = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if canonical_pem != raw_key:
        raise ManifestError(f"{label} must be canonical Ed25519 SPKI PEM")
    spki_der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(spki_der).hexdigest()


def load_global_role_registry(
    args: argparse.Namespace,
    *,
    expected_roles: dict[str, str],
) -> tuple[dict[str, Any], str, dict[str, str]]:
    expected_file_sha256 = args.expected_global_role_registry_pins_sha256
    if not DIGEST_RE.fullmatch(expected_file_sha256):
        raise ManifestError(
            "expected global role registry digest must be "
            "sha256:<64 lowercase hexadecimal characters>"
        )
    path = absolute_normalized_path(
        args.global_role_registry,
        "global role registry",
    )
    contained_path(path, PRODUCTION_ENV_ROOT, "global role registry")
    reject_symlink_components(path, "global role registry")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in (0o400, 0o440)
            or not 1 <= before.st_size <= MAX_GLOBAL_ROLE_REGISTRY_PINS_BYTES
        ):
            raise ManifestError(
                "global role registry must be root:root-owned, single-linked, "
                "mode 0400 or 0440, regular, and at most 64 KiB"
            )
        chunks: list[bytes] = []
        remaining = MAX_GLOBAL_ROLE_REGISTRY_PINS_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        stable_identity(before) != stable_identity(after)
        or len(raw) != before.st_size
    ):
        raise ManifestError("global role registry changed while being read")
    file_sha256 = "sha256:" + hashlib.sha256(raw).hexdigest()
    if file_sha256 != expected_file_sha256:
        raise ManifestError(
            "global role registry differs from its independent digest"
        )
    try:
        registry = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_json_pairs,
            parse_float=reject_json_value,
            parse_constant=reject_json_value,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError("global role registry is invalid JSON") from exc
    exact_object_keys(
        registry,
        {"apiVersion", "claimScope", "roles", "rolesOutsideClaim"},
        "global role registry",
    )
    if raw != canonical_json_value(registry) + b"\n":
        raise ManifestError(
            "global role registry must be canonical JSON plus one LF"
        )
    if (
        registry["apiVersion"] != GLOBAL_ROLE_REGISTRY_API_VERSION
        or registry["claimScope"] != GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE
        or registry["rolesOutsideClaim"] != list(GLOBAL_ROLES_OUTSIDE_CLAIM)
    ):
        raise ManifestError(
            "global role registry scope or outside-claim inventory is invalid"
        )
    roles = exact_object_keys(
        registry["roles"],
        set(GLOBAL_ROLE_NAMES),
        "global role registry roles",
    )
    if any(
        type(value) is not str or DIGEST_RE.fullmatch(value) is None
        for value in roles.values()
    ) or len(set(roles.values())) != len(roles):
        raise ManifestError(
            "global role registry SPKI identities must be valid and pairwise distinct"
        )
    for role, key_id in expected_roles.items():
        if roles.get(role) != key_id:
            raise ManifestError(
                f"global role registry {role} does not match its supplied SPKI"
            )
    registry_sha256 = (
        "sha256:" + hashlib.sha256(canonical_json_value(registry)).hexdigest()
    )
    return (
        registry,
        registry_sha256,
        {"path": str(path), "sha256": file_sha256},
    )


def generate(args: argparse.Namespace) -> tuple[dict[str, Any], bytes]:
    (
        nonce_rollback_assurance_pins,
        nonce_rollback_assurance_pins_file,
    ) = load_nonce_rollback_assurance_pins(args)
    nonce_rollback_assurance_contract_sha256 = (
        "sha256:"
        + hashlib.sha256(
            canonical_json_value(nonce_rollback_assurance_pins)
        ).hexdigest()
    )
    release_root = existing_directory(args.release_root, "release root")
    state_directory = existing_directory(args.state_directory, "state directory")
    if state_directory != PRODUCTION_STATE_DIRECTORY:
        raise ManifestError(
            "state directory must be /var/lib/serverware/production-proof"
        )
    if os.path.commonpath((str(release_root), str(state_directory))) in (
        str(release_root),
        str(state_directory),
    ):
        raise ManifestError("release root and state directory must not contain one another")
    attempt_journal_path = state_directory / ATTEMPT_JOURNAL_FILE_NAME
    attempt_journal_lock_path = (
        state_directory / ATTEMPT_JOURNAL_LOCK_FILE_NAME
    )
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
    witness_signing_key_der = decode_ed25519_spki(
        args.launch_authority_witness_signing_public_key_spki_base64url,
        "launch authority witness signing public key",
    )
    witness_key_id = "sha256:" + hashlib.sha256(witness_signing_key_der).hexdigest()
    if not DIGEST_RE.fullmatch(args.expected_launch_authority_key_id):
        raise ManifestError(
            "expected launch authority key ID must be sha256:<64 lowercase hexadecimal characters>"
        )
    if (
        not DIGEST_RE.fullmatch(args.expected_launch_authority_witness_key_id)
        or witness_key_id != args.expected_launch_authority_witness_key_id
    ):
        raise ManifestError(
            "launch authority witness signing key does not match its independent key ID pin"
        )
    for value, label in (
        (
            args.launch_authority_witness_identity_sha256,
            "launch authority witness identity",
        ),
        (
            args.launch_authority_witness_administrative_domain_sha256,
            "launch authority witness administrative domain",
        ),
        (
            args.launch_authority_witness_store_assurance_sha256,
            "launch authority witness store assurance",
        ),
    ):
        if not DIGEST_RE.fullmatch(value):
            raise ManifestError(f"{label} must be sha256:<64 lowercase hexadecimal characters>")
    (
        witness_store_assurance,
        witness_store_assurance_issuer_key_id,
        witness_store_assurance_sha256,
    ) = load_launch_authority_witness_store_assurance(
        args,
        witness_key_id=witness_key_id,
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
    if attempt_journal_path in {Path(value) for value in outputs.values()} or (
        attempt_journal_lock_path
        in {Path(value) for value in outputs.values()}
    ):
        raise ManifestError(
            "launch attempt journal state must not collide with an output"
        )

    nonce_public = nonce_rollback_assurance_pins["publicConfigPins"]
    # launchAuthorityWitnessTls is intentionally not derived here because the
    # native manifest supplies no raw TLS SPKI. The authority cross-binds it.
    expected_global_roles = {
        "launchAuthority": args.expected_launch_authority_key_id,
        "launchAuthorityWitness": witness_key_id,
        "launchAuthorityWitnessStoreAssurance": (
            witness_store_assurance_issuer_key_id
        ),
        "nonceAuthorityAssuranceEvidence": (
            "sha256:"
            + hashlib.sha256(
                decode_ed25519_spki(
                    nonce_public[
                        "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
                    ],
                    "nonce authority assurance evidence role",
                )
            ).hexdigest()
        ),
        "nonceAuthorityVerifierState": (
            "sha256:"
            + hashlib.sha256(
                decode_ed25519_spki(
                    nonce_public[
                        "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
                    ],
                    "nonce authority verifier-state role",
                )
            ).hexdigest()
        ),
        "nonceAuthorityVerifierStateStoreAttestation": (
            "sha256:"
            + hashlib.sha256(
                decode_ed25519_spki(
                    nonce_public[
                        "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
                    ],
                    "nonce authority verifier-state store attestation role",
                )
            ).hexdigest()
        ),
        "policyIdentity": load_canonical_ed25519_public_key_id(
            args.policy_trusted_public_key,
            "policy trusted public key",
        ),
        "policyActivation": load_canonical_ed25519_public_key_id(
            args.policy_activation_trusted_public_key,
            "policy activation trusted public key",
        ),
        "reproducibleBuild": load_canonical_ed25519_public_key_id(
            args.reproducible_build_trusted_public_key,
            "reproducible-build trusted public key",
        ),
    }
    (
        global_role_registry,
        global_role_registry_sha256,
        global_role_registry_pins_file,
    ) = load_global_role_registry(
        args,
        expected_roles=expected_global_roles,
    )

    manifest = {
        "apiVersion": API_VERSION,
        "kind": KIND,
        "releaseRoot": str(release_root),
        "stateDirectory": str(state_directory),
        "sourceTreeDigest": args.source_tree_digest,
        "authorization": {
            "authorizationScope": "trusted-host-readiness",
            "deploymentAudience": args.deployment_audience,
            "deploymentIdentitySha256": args.deployment_identity_sha256,
            "freshnessAuthority": "trusted-host-wall-clock",
            "monotonicWitness": {
                "administrativeDomainSha256": (
                    args.launch_authority_witness_administrative_domain_sha256
                ),
                "identitySha256": args.launch_authority_witness_identity_sha256,
                "signingKeyId": witness_key_id,
                "signingPublicKeySpkiDerBase64url": (
                    args.launch_authority_witness_signing_public_key_spki_base64url
                ),
                "storeAssurance": witness_store_assurance,
                "storeAssuranceIssuerKeyId": (
                    witness_store_assurance_issuer_key_id
                ),
                "storeAssuranceIssuerPublicKeySpkiDerBase64url": (
                    args.launch_authority_witness_store_assurance_issuer_public_key_spki_base64url
                ),
                "storeAssuranceSha256": witness_store_assurance_sha256,
            },
            "releaseSequence": release_sequence,
            "rollbackEpoch": rollback_epoch,
        },
        "launchAttemptJournal": {
            "apiVersion": ATTEMPT_JOURNAL_API_VERSION,
            "path": str(attempt_journal_path),
            "lockPath": str(attempt_journal_lock_path),
            "domain": ATTEMPT_JOURNAL_DOMAIN,
            "maxBytes": MAX_ATTEMPT_JOURNAL_BYTES,
            "consistencyScope": ATTEMPT_JOURNAL_CONSISTENCY_SCOPE,
            "rollbackAuthority": ATTEMPT_JOURNAL_ROLLBACK_AUTHORITY,
        },
        "globalRoleRegistry": {
            "apiVersion": GLOBAL_ROLE_REGISTRY_BINDING_API_VERSION,
            "canonicalProfile": CANONICAL_JSON_PROFILE,
            "claimScope": GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE,
            "registry": global_role_registry,
            "registrySha256": global_role_registry_sha256,
            "pinsFile": global_role_registry_pins_file,
        },
        "nonceRollbackAssurance": {
            "apiVersion": NONCE_ROLLBACK_ASSURANCE_BINDING_VERSION,
            "canonicalProfile": CANONICAL_JSON_PROFILE,
            "contract": nonce_rollback_assurance_pins,
            "contractSha256": nonce_rollback_assurance_contract_sha256,
            "enforcement": "native-launcher-measured",
            "pinsFile": nonce_rollback_assurance_pins_file,
            "purpose": "readiness-only",
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
        pipeline_metadata_path = systemd_literal_path(
            args.pipeline_metadata_out,
            "pipeline metadata output",
        )
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
        manifest_digest = f"sha256:{hashlib.sha256(encoded).hexdigest()}"
        nonce_rollback_assurance = manifest[
            "nonceRollbackAssurance"
        ]
        pipeline_metadata = {
            "apiVersion": PIPELINE_METADATA_API_VERSION,
            "canonicalProfile": CANONICAL_JSON_PROFILE,
            "finalCompletionCompatible": False,
            "incompatibleWith": [INCOMPATIBLE_FINAL_PIPELINE],
            "kind": "ServerwareLaunchPipelineMetadata",
            "manifestApiVersion": manifest["apiVersion"],
            "manifestKind": manifest["kind"],
            "manifestSha256": manifest_digest,
            "nonceRollbackAssurancePins": nonce_rollback_assurance[
                "contract"
            ],
            "nonceRollbackAssurancePinsFile": nonce_rollback_assurance[
                "pinsFile"
            ],
            "nonceRollbackAssurancePinsSha256": nonce_rollback_assurance[
                "pinsFile"
            ]["sha256"],
            "nonceRollbackAssuranceContractSha256": (
                nonce_rollback_assurance["contractSha256"]
            ),
            "projectionOfManifestSha256": manifest_digest,
            "pipeline": PIPELINE,
            "purpose": "readiness-only",
            "authorizationScope": manifest["authorization"][
                "authorizationScope"
            ],
            "freshnessAuthority": manifest["authorization"][
                "freshnessAuthority"
            ],
            "monotonicWitness": manifest["authorization"][
                "monotonicWitness"
            ],
            "launchAttemptJournal": manifest["launchAttemptJournal"],
            "globalRoleRegistry": manifest["globalRoleRegistry"],
            "runtimeBoundary": (
                "legacy host Docker with /dev/nsm; never accepted as "
                "Manifest v6 final completion"
            ),
        }
        reserved_outputs = {
            output_path,
            *(Path(value) for value in manifest["outputs"].values()),
            Path(manifest["productionEnv"]["path"]),
            Path(nonce_rollback_assurance["pinsFile"]["path"]),
            Path(manifest["globalRoleRegistry"]["pinsFile"]["path"]),
            Path(manifest["launchAttemptJournal"]["path"]),
            Path(manifest["launchAttemptJournal"]["lockPath"]),
            Path(manifest["python"]["path"]),
            Path(manifest["scripts"]["preflight"]["path"]),
            Path(manifest["scripts"]["runner"]["path"]),
            Path(manifest["composeFile"]["path"]),
            *(
                Path(record["path"])
                for record in manifest["inputs"].values()
            ),
        }
        if systemd_unit_path is not None:
            reserved_outputs.add(systemd_unit_path)
        if launcher_path is not None:
            reserved_outputs.add(launcher_path)
        if pipeline_metadata_path in reserved_outputs:
            raise ManifestError(
                "pipeline metadata output must differ from manifest and systemd outputs"
            )
        # The launcher consumes only this manifest. It embeds the validated
        # contract and exact pin-file digest, so metadata publication cannot
        # create or repair a security binding.
        atomic_write_read_only(output_path, encoded, 0o400)
        atomic_write_read_only(
            pipeline_metadata_path,
            canonical_json(pipeline_metadata),
            0o400,
        )
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
