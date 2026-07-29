#!/usr/bin/env python3
"""Exercise the sealed clean-room payload already present in its OCI image."""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import email.parser
import email.policy
import hashlib
import io
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import (
    InvalidName,
    InvalidWheelFilename,
    canonicalize_name,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version


SEALED_ROOT = Path("/opt/serverware/clean-room")
WHEELHOUSE = SEALED_ROOT / "wheelhouse"
INSTALLED = SEALED_ROOT / "installed"
PAYLOAD_MANIFEST = SEALED_ROOT / "payload-manifest.json"
WHEELHOUSE_MANIFEST = WHEELHOUSE / "wheelhouse-manifest.json"
CHECKSUMS = WHEELHOUSE / "SHA256SUMS"
PACKAGE_CONTRACT = SEALED_ROOT / "package-install-contract.json"
RESULT_PREFIX = "SERVERWARE_CLEAN_ROOM_RESULT="
PAYLOAD_VERSION = "serverware.cleanRoomPayloadManifest/v1"
WHEELHOUSE_VERSION = "serverware.cleanRoomWheelhouseManifest/v3"
CONTRACT_VERSION = "serverware.cleanRoomInstallContract/v5"
RESULT_VERSION = "serverware.agentTrustCleanRoomResult/v5"
EXPECTED_UID = 65532
EXPECTED_GID = 65532
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_FILES = 20_000
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")
WHEEL_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._+]*-[A-Za-z0-9][A-Za-z0-9._+]*-"
    r"[A-Za-z0-9._]+-[A-Za-z0-9._]+-[A-Za-z0-9._]+\.whl$"
)
EXPECTED_COMMANDS = (
    "/opt/serverware/clean-room/installed/bin/serverware-attestation",
    "/opt/serverware/clean-room/installed/bin/serverware-enrollment",
    "/opt/serverware/clean-room/installed/bin/serverware-evidence",
)
PYTHON_SITE = "lib/python3.11/site-packages"
PYTHON_EXECUTABLE = "/opt/serverware/clean-room/python/bin/python3"
WHEELHOUSE_SCHEMA = {
    "apiVersion": WHEELHOUSE_VERSION,
    "fileFields": ["path", "sha256", "size"],
    "packageFields": [
        "name",
        "normalizedName",
        "providesExtras",
        "requires",
        "sha256",
        "version",
        "wheel",
    ],
    "payloadDigestField": "payloadSha256",
}
MARKER_ENVIRONMENT = {
    "implementation_name": "cpython",
    "implementation_version": "3.11.11",
    "os_name": "posix",
    "platform_machine": "x86_64",
    "platform_python_implementation": "CPython",
    "platform_release": "",
    "platform_system": "Linux",
    "platform_version": "",
    "python_full_version": "3.11.11",
    "python_version": "3.11",
    "sys_platform": "linux",
}
FIXED_SCENARIOS = (
    {
        "argv": [
            EXPECTED_COMMANDS[0],
            "--base",
            "http://127.0.0.1:1",
            "--enrollment-packet",
            str(SEALED_ROOT / "fixtures/rejected-enrollment-packet.json"),
            "--ca-out",
            "/work/attestation-verify-offline/verified-ca.pem",
        ],
        "expectedExitCode": 1,
        "expectedState": [],
        "scenario": "attestation-verify-offline",
    },
    {
        "argv": [
            EXPECTED_COMMANDS[1],
            "--base",
            "http://127.0.0.1:1",
            "--verify-packet",
            str(SEALED_ROOT / "fixtures/rejected-enrollment-packet.json"),
        ],
        "expectedExitCode": 1,
        "expectedState": [],
        "scenario": "enrollment-install-offline",
    },
    {
        "argv": [
            EXPECTED_COMMANDS[2],
            "--root",
            str(SEALED_ROOT / "fixtures"),
            "verify",
            "--manifest",
            "onboarding-evidence.json",
        ],
        "expectedExitCode": 0,
        "expectedState": [],
        "scenario": "evidence-verify-offline",
    },
)


class ValidationError(RuntimeError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    raise ValidationError(f"JSON contains an unsupported number: {value}")


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValidationError("value is not canonical JSON") from exc


def _load_json(raw: bytes, *, label: str) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise ValidationError(f"{label} exceeds its byte limit")
    try:
        return json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_number,
            parse_float=_reject_number,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label} is not strict ASCII JSON") from exc


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _safe_relative(value: str, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValidationError(f"{label} is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValidationError(f"{label} contains an unsafe path")
    return path


def _open_directory(path: Path, *, label: str) -> int:
    if not path.is_absolute():
        raise ValidationError(f"{label} is not absolute")
    descriptor = os.open(
        "/",
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular_at(
    root_fd: int,
    relative: str,
    *,
    label: str,
    max_bytes: int = MAX_FILE_BYTES,
) -> tuple[bytes, os.stat_result]:
    parts = _safe_relative(relative, label=label).parts
    parent = os.dup(root_fd)
    try:
        for component in parts[:-1]:
            child = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | os.O_NOFOLLOW,
                dir_fd=parent,
            )
            os.close(parent)
            parent = child
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    finally:
        os.close(parent)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > max_bytes
        ):
            raise ValidationError(f"{label} is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            raw = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not raw:
                break
            chunks.append(raw)
            total += len(raw)
            if total > max_bytes:
                raise ValidationError(f"{label} exceeds its byte limit")
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_gid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(before) != identity(after):
            raise ValidationError(f"{label} changed while read")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def _scan_tree(
    root: Path,
    *,
    exclude: set[str] | None = None,
) -> list[dict[str, Any]]:
    root_fd = _open_directory(root, label="sealed tree")
    records: list[dict[str, Any]] = []
    aggregate = 0

    def walk(descriptor: int, relative: PurePosixPath) -> None:
        nonlocal aggregate
        for name in sorted(os.listdir(descriptor)):
            if (
                name in {"", ".", ".."}
                or "/" in name
                or "\x00" in name
                or (not relative.parts and exclude and name in exclude)
            ):
                if not relative.parts and exclude and name in exclude:
                    continue
                raise ValidationError("sealed tree contains an unsafe name")
            path = relative / name
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            common = {
                "gid": metadata.st_gid,
                "mode": stat.S_IMODE(metadata.st_mode),
                "path": path.as_posix(),
                "uid": metadata.st_uid,
            }
            if stat.S_ISDIR(metadata.st_mode):
                records.append({**common, "type": "directory"})
                child = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                    | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                try:
                    walk(child, path)
                finally:
                    os.close(child)
                continue
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(name, dir_fd=descriptor)
                if not target or "\x00" in target:
                    raise ValidationError("sealed tree contains an invalid symlink")
                records.append({**common, "target": target, "type": "symlink"})
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValidationError("sealed tree contains a special or hard-linked file")
            raw, stable = _read_regular_at(
                root_fd,
                path.as_posix(),
                label="sealed payload file",
            )
            aggregate += len(raw)
            if aggregate > MAX_TOTAL_BYTES or len(records) >= MAX_FILES:
                raise ValidationError("sealed payload exceeds its closure bound")
            records.append(
                {
                    **common,
                    "mode": stat.S_IMODE(stable.st_mode),
                    "sha256": _sha256(raw),
                    "size": len(raw),
                    "type": "file",
                }
            )

    try:
        walk(root_fd, PurePosixPath())
    finally:
        os.close(root_fd)
    return records


def _verify_payload_manifest() -> dict[str, Any]:
    root_fd = _open_directory(SEALED_ROOT, label="sealed clean-room root")
    try:
        raw, _ = _read_regular_at(
            root_fd,
            PAYLOAD_MANIFEST.name,
            label="clean-room payload manifest",
            max_bytes=MAX_JSON_BYTES,
        )
    finally:
        os.close(root_fd)
    document = _load_json(raw, label="clean-room payload manifest")
    if (
        raw != _canonical_json(document) + b"\n"
        or not isinstance(document, dict)
        or set(document)
        != {
            "apiVersion",
            "closureSha256",
            "entries",
            "excluded",
        }
        or document.get("apiVersion") != PAYLOAD_VERSION
        or document.get("excluded") != [PAYLOAD_MANIFEST.name]
    ):
        raise ValidationError("clean-room payload manifest fields are invalid")
    entries = _scan_tree(SEALED_ROOT, exclude={PAYLOAD_MANIFEST.name})
    if document["entries"] != entries:
        raise ValidationError("sealed clean-room payload differs from its manifest")
    payload = {
        "apiVersion": PAYLOAD_VERSION,
        "entries": entries,
        "excluded": [PAYLOAD_MANIFEST.name],
    }
    if document["closureSha256"] != _sha256(_canonical_json(payload)):
        raise ValidationError("clean-room payload closure digest is invalid")
    return document


def _verify_checksums() -> dict[str, str]:
    root_fd = _open_directory(WHEELHOUSE, label="sealed wheelhouse")
    try:
        raw, _ = _read_regular_at(
            root_fd,
            CHECKSUMS.name,
            label="wheelhouse checksums",
            max_bytes=MAX_JSON_BYTES,
        )
        entries = _scan_tree(WHEELHOUSE)
        file_names = {
            item["path"]
            for item in entries
            if item["type"] == "file" and item["path"] != CHECKSUMS.name
        }
        checksums: dict[str, str] = {}
        text = raw.decode("ascii")
        if not text or not text.endswith("\n") or "\r" in text:
            raise ValidationError(
                "wheelhouse checksums are not canonical LF text"
            )
        for line in text[:-1].split("\n"):
            match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+/-]*)", line)
            if match is None:
                raise ValidationError("wheelhouse checksum line is malformed")
            relative = _safe_relative(match.group(2), label="wheelhouse checksum path")
            name = relative.as_posix()
            if name in checksums:
                raise ValidationError("wheelhouse checksum path is duplicated")
            content, _ = _read_regular_at(
                root_fd,
                name,
                label="checksummed wheelhouse file",
            )
            if hashlib.sha256(content).hexdigest() != match.group(1):
                raise ValidationError("wheelhouse checksum mismatch")
            checksums[name] = "sha256:" + match.group(1)
    finally:
        os.close(root_fd)
    if set(checksums) != file_names:
        raise ValidationError("wheelhouse checksum inventory is not complete")
    if list(checksums) != sorted(checksums):
        raise ValidationError("wheelhouse checksums are not sorted")
    return checksums


def _verify_wheelhouse_manifest(checksums: dict[str, str]) -> dict[str, Any]:
    root_fd = _open_directory(WHEELHOUSE, label="sealed wheelhouse")
    try:
        raw, _ = _read_regular_at(
            root_fd,
            WHEELHOUSE_MANIFEST.name,
            label="wheelhouse manifest",
            max_bytes=MAX_JSON_BYTES,
        )
    finally:
        os.close(root_fd)
    document = _load_json(raw, label="wheelhouse manifest")
    if (
        raw != _canonical_json(document) + b"\n"
        or not isinstance(document, dict)
        or set(document)
        != {
            "apiVersion",
            "files",
            "packages",
            "payloadSha256",
            "schemaSha256",
        }
        or document.get("apiVersion") != WHEELHOUSE_VERSION
        or document.get("schemaSha256")
        != _sha256(_canonical_json(WHEELHOUSE_SCHEMA))
        or not isinstance(document.get("files"), list)
        or not isinstance(document.get("packages"), list)
    ):
        raise ValidationError("wheelhouse manifest fields are not closed")
    payload = dict(document)
    supplied_payload_sha256 = payload.pop("payloadSha256")
    if supplied_payload_sha256 != _sha256(_canonical_json(payload)):
        raise ValidationError("wheelhouse manifest payload digest is invalid")
    observed: dict[str, tuple[str, int]] = {}
    for item in document["files"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256", "size"}
            or not isinstance(item.get("path"), str)
            or SHA256_RE.fullmatch(str(item.get("sha256") or "")) is None
            or type(item.get("size")) is not int
            or item["size"] < 0
            or item["path"] in observed
        ):
            raise ValidationError("wheelhouse manifest file record is invalid")
        observed[item["path"]] = (item["sha256"], item["size"])
    expected = {
        key: (value, (WHEELHOUSE / key).stat().st_size)
        for key, value in checksums.items()
        if key != WHEELHOUSE_MANIFEST.name
    }
    if (
        observed != expected
        or document["files"]
        != sorted(document["files"], key=lambda item: item["path"])
    ):
        raise ValidationError("wheelhouse manifest and checksums differ")
    package_wheels: set[str] = set()
    package_names: set[str] = set()
    for package in document["packages"]:
        if not isinstance(package, dict):
            raise ValidationError("wheelhouse package record is invalid")
        try:
            normalized_name = canonicalize_name(
                package.get("name", ""),
                validate=True,
            )
            normalized_version = str(Version(package.get("version", "")))
        except (InvalidName, InvalidVersion, TypeError, ValueError) as exc:
            raise ValidationError(
                "wheelhouse package name or version is invalid"
            ) from exc
        if (
            set(package)
            != {
                "name",
                "normalizedName",
                "providesExtras",
                "requires",
                "sha256",
                "version",
                "wheel",
            }
            or not isinstance(package.get("name"), str)
            or SAFE_NAME_RE.fullmatch(package["name"]) is None
            or package.get("normalizedName") != normalized_name
            or not isinstance(package.get("version"), str)
            or package["version"] != normalized_version
            or not isinstance(package.get("wheel"), str)
            or WHEEL_RE.fullmatch(package["wheel"]) is None
            or package.get("sha256") != checksums.get(package["wheel"])
            or not isinstance(package.get("requires"), list)
            or any(
                not isinstance(item, str) or not item
                for item in package["requires"]
            )
            or package["requires"] != sorted(set(package["requires"]))
            or not isinstance(package.get("providesExtras"), list)
            or package["providesExtras"]
            != sorted(set(package["providesExtras"]))
            or any(
                not isinstance(item, str)
                or canonicalize_name(item) != item
                for item in package["providesExtras"]
            )
            or package["wheel"] in package_wheels
            or normalized_name in package_names
        ):
            raise ValidationError("wheelhouse package record is invalid")
        package_wheels.add(package["wheel"])
        package_names.add(normalized_name)
    if (
        document["packages"]
        != sorted(
            document["packages"],
            key=lambda item: item["normalizedName"],
        )
        or package_wheels
        != {name for name in observed if name.endswith(".whl")}
    ):
        raise ValidationError("wheelhouse package inventory is incomplete")
    return document


def _wheel_install_path(member_name: str) -> str:
    parts = _safe_relative(member_name, label="wheel install member").parts
    if parts[0].endswith(".data"):
        if len(parts) < 3:
            raise ValidationError("wheel .data member is incomplete")
        category = parts[1]
        remainder = PurePosixPath(*parts[2:]).as_posix()
        if category in {"purelib", "platlib"}:
            return f"{PYTHON_SITE}/{remainder}"
        if category == "scripts":
            return f"bin/{remainder}"
        if category == "data":
            return remainder
        raise ValidationError("wheel uses an unsupported .data installation class")
    return f"{PYTHON_SITE}/{member_name}"


def _console_script_bytes(target: str) -> bytes:
    match = re.fullmatch(
        r"([A-Za-z_][A-Za-z0-9_.]*):([A-Za-z_][A-Za-z0-9_]*)",
        target,
    )
    if match is None:
        raise ValidationError("console-script target is not a closed callable")
    module, callable_name = match.groups()
    return (
        f"#!{PYTHON_EXECUTABLE}\n"
        "import re\n"
        "import sys\n"
        f"from {module} import {callable_name}\n"
        "if __name__ == '__main__':\n"
        "    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])\n"
        f"    sys.exit({callable_name}())\n"
    ).encode("ascii")


def _verify_wheel_record(
    wheel_name: str,
    expected_sha256: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    if WHEEL_RE.fullmatch(wheel_name) is None:
        raise ValidationError("package wheel name is invalid")
    try:
        (
            filename_name,
            filename_version,
            _filename_build,
            filename_tags,
        ) = parse_wheel_filename(wheel_name)
    except InvalidWheelFilename as exc:
        raise ValidationError("package wheel filename is invalid") from exc
    filename_parts = wheel_name.removesuffix(".whl").split("-")
    expected_dist_info = (
        f"{filename_parts[0]}-{filename_parts[1]}.dist-info"
    )
    root_fd = _open_directory(WHEELHOUSE, label="sealed wheelhouse")
    try:
        raw, _ = _read_regular_at(
            root_fd,
            wheel_name,
            label="serverware package wheel",
        )
    finally:
        os.close(root_fd)
    if _sha256(raw) != expected_sha256:
        raise ValidationError("package wheel digest differs from its contract")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw), mode="r")
    except zipfile.BadZipFile as exc:
        raise ValidationError("package wheel is not a valid ZIP") from exc
    with archive:
        members = archive.infolist()
        names = [item.filename for item in members]
        if (
            not members
            or len(members) > MAX_FILES
            or names != sorted(names)
            or len(names) != len(set(names))
        ):
            raise ValidationError("package wheel members are not canonical")
        contents: dict[str, bytes] = {}
        aggregate = 0
        for member in members:
            relative = _safe_relative(member.filename, label="package wheel member")
            canonical_name = relative.as_posix()
            unix_mode = member.external_attr >> 16
            if (
                canonical_name != member.filename
                or member.is_dir()
                or member.flag_bits & 0x1
                or member.file_size < 0
                or member.file_size > MAX_FILE_BYTES
                or (
                    stat.S_IFMT(unix_mode)
                    and not stat.S_ISREG(unix_mode)
                )
                or (
                    relative.parts[0].endswith(".data")
                    and relative.parts[0]
                    != (
                        f"{filename_parts[0]}-"
                        f"{filename_parts[1]}.data"
                    )
                )
            ):
                raise ValidationError("package wheel member metadata is unsafe")
            content = archive.read(member)
            if len(content) != member.file_size:
                raise ValidationError("package wheel member size is invalid")
            aggregate += len(content)
            if aggregate > MAX_TOTAL_BYTES:
                raise ValidationError("package wheel content exceeds its bound")
            contents[canonical_name] = content
        record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
        expected_record_name = f"{expected_dist_info}/RECORD"
        if record_names != [expected_record_name]:
            raise ValidationError("package wheel RECORD is ambiguous")
        try:
            rows = list(
                csv.reader(
                    io.StringIO(contents[record_names[0]].decode("utf-8"))
                )
            )
        except UnicodeError as exc:
            raise ValidationError("package wheel RECORD is not UTF-8") from exc
        record_entries: dict[str, tuple[str, str]] = {}
        for row in rows:
            if len(row) != 3:
                raise ValidationError("package wheel RECORD row is malformed")
            record_path = _safe_relative(
                row[0],
                label="package wheel RECORD path",
            ).as_posix()
            if record_path != row[0] or record_path in record_entries:
                raise ValidationError("package wheel RECORD path is not canonical")
            record_entries[record_path] = (row[1], row[2])
        if set(record_entries) != set(contents):
            raise ValidationError("package wheel RECORD inventory is incomplete")
        for name, content in contents.items():
            encoded_hash, encoded_size = record_entries[name]
            if name == record_names[0]:
                if encoded_hash or encoded_size:
                    raise ValidationError(
                        "package wheel RECORD must leave its own digest empty"
                    )
                continue
            if (
                re.fullmatch(r"sha256=[A-Za-z0-9_-]{43}", encoded_hash)
                is None
                or encoded_size != str(len(content))
            ):
                raise ValidationError("package wheel RECORD metadata is invalid")
            recorded_digest = base64.urlsafe_b64decode(
                encoded_hash.removeprefix("sha256=") + "="
            )
            if recorded_digest != hashlib.sha256(content).digest():
                raise ValidationError("package wheel RECORD digest is invalid")
        if not rows:
            raise ValidationError("package wheel RECORD is empty")
        metadata_names = [
            name for name in names if name.endswith(".dist-info/METADATA")
        ]
        wheel_metadata_names = [
            name for name in names if name.endswith(".dist-info/WHEEL")
        ]
        if (
            metadata_names != [f"{expected_dist_info}/METADATA"]
            or wheel_metadata_names != [f"{expected_dist_info}/WHEEL"]
        ):
            raise ValidationError("package wheel METADATA is ambiguous")
        metadata = email.parser.BytesParser(
            policy=email.policy.default
        ).parsebytes(contents[metadata_names[0]])
        package_name = metadata.get("Name")
        package_version = metadata.get("Version")
        requires = sorted(metadata.get_all("Requires-Dist", []))
        provides_extras_raw = metadata.get_all("Provides-Extra", [])
        try:
            normalized_name = canonicalize_name(
                package_name or "",
                validate=True,
            )
            normalized_version = str(Version(package_version or ""))
            provides_extras = sorted(
                {
                    canonicalize_name(item, validate=True)
                    for item in provides_extras_raw
                }
            )
            parsed_requirements = [Requirement(item) for item in requires]
        except (
            InvalidName,
            InvalidRequirement,
            InvalidVersion,
            TypeError,
            ValueError,
        ) as exc:
            raise ValidationError("package wheel metadata is invalid") from exc
        if (
            not isinstance(package_name, str)
            or SAFE_NAME_RE.fullmatch(package_name) is None
            or not isinstance(package_version, str)
            or package_version != normalized_version
            or normalized_name != str(filename_name)
            or normalized_version != str(filename_version)
            or any(not isinstance(item, str) or not item for item in requires)
            or any(item.url is not None for item in parsed_requirements)
        ):
            raise ValidationError("package wheel metadata is invalid")
        wheel_metadata = email.parser.BytesParser(
            policy=email.policy.default
        ).parsebytes(contents[wheel_metadata_names[0]])
        wheel_versions = wheel_metadata.get_all("Wheel-Version", [])
        purelib_values = wheel_metadata.get_all("Root-Is-Purelib", [])
        declared_tags = sorted(wheel_metadata.get_all("Tag", []))
        expected_tags = sorted(str(item) for item in filename_tags)
        if (
            wheel_versions != ["1.0"]
            or purelib_values != ["true"]
            or declared_tags != expected_tags
            or len(declared_tags) != len(set(declared_tags))
        ):
            raise ValidationError(
                "package wheel WHEEL metadata differs from its filename"
            )
        installed: dict[str, dict[str, Any]] = {}
        for name, content in contents.items():
            destination = _wheel_install_path(name)
            wheel_mode = archive.getinfo(name).external_attr >> 16
            mode = 0o555 if wheel_mode & 0o111 else 0o444
            if destination in installed:
                raise ValidationError("wheel installation path is duplicated")
            installed[destination] = {
                "gid": 0,
                "mode": mode,
                "path": destination,
                "sha256": _sha256(content),
                "size": len(content),
                "source": {"member": name, "wheel": wheel_name},
                "type": "file",
            }
        generated: dict[str, dict[str, Any]] = {}
        entry_point_names = [
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        ]
        if len(entry_point_names) > 1:
            raise ValidationError("package wheel entry points are ambiguous")
        if entry_point_names:
            if entry_point_names != [
                f"{expected_dist_info}/entry_points.txt"
            ]:
                raise ValidationError(
                    "package wheel entry points use the wrong dist-info root"
                )
            parser = configparser.ConfigParser(
                interpolation=None,
                strict=True,
            )
            parser.optionxform = str
            try:
                parser.read_string(
                    contents[entry_point_names[0]].decode("ascii")
                )
            except (UnicodeError, configparser.Error) as exc:
                raise ValidationError(
                    "package wheel entry points are invalid"
                ) from exc
            if set(parser.sections()) - {"console_scripts"}:
                raise ValidationError("wheel contains unsupported entry points")
            console_scripts = (
                parser.items("console_scripts")
                if parser.has_section("console_scripts")
                else []
            )
            for script_name, target in sorted(console_scripts):
                if SAFE_NAME_RE.fullmatch(script_name) is None:
                    raise ValidationError("console-script name is unsafe")
                script = _console_script_bytes(target.strip())
                destination = f"bin/{script_name}"
                if destination in installed or destination in generated:
                    raise ValidationError(
                        "console-script installation path is duplicated"
                    )
                generated[destination] = {
                    "gid": 0,
                    "mode": 0o555,
                    "path": destination,
                    "sha256": _sha256(script),
                    "size": len(script),
                    "source": {
                        "entryPoint": f"{script_name}={target.strip()}",
                        "wheel": wheel_name,
                    },
                    "type": "file",
                }
    record = {
        "memberCount": len(names),
        "name": package_name,
        "normalizedName": normalized_name,
        "providesExtras": provides_extras,
        "recordSha256": _sha256(contents[record_names[0]]),
        "recordPath": record_names[0],
        "requires": requires,
        "sha256": expected_sha256,
        "version": package_version,
        "wheel": wheel_name,
    }
    return record, installed, generated


def _with_directories(
    files: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    directories: set[str] = set()
    for path in files:
        parent = PurePosixPath(path).parent
        while parent.parts:
            directories.add(parent.as_posix())
            parent = parent.parent
    records = [
        {
            "gid": 0,
            "mode": 0o555,
            "path": path,
            "type": "directory",
            "uid": 0,
        }
        for path in sorted(directories)
    ]
    records.extend(
        {
            **{
                key: value
                for key, value in record.items()
                if key != "source"
            },
            "uid": 0,
        }
        for _, record in sorted(files.items())
    )
    return sorted(records, key=lambda item: item["path"])


def _resolve_requirements(
    wheel_records: list[dict[str, Any]],
    requested_extras: Any,
) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
    selected: dict[str, dict[str, Any]] = {}
    for record in wheel_records:
        normalized = record["normalizedName"]
        try:
            expected_name = canonicalize_name(
                record["name"],
                validate=True,
            )
            expected_version = str(Version(record["version"]))
        except (
            InvalidName,
            InvalidVersion,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise ValidationError(
                "selected wheel identity is invalid"
            ) from exc
        if (
            normalized != expected_name
            or record["version"] != expected_version
            or normalized in selected
        ):
            raise ValidationError(
                "selected wheels have a noncanonical or duplicate identity"
            )
        selected[normalized] = record
    if (
        not isinstance(requested_extras, dict)
        or list(requested_extras) != sorted(requested_extras)
    ):
        raise ValidationError("requested extras are not canonical")
    normalized_extras: dict[str, list[str]] = {}
    for package_name, extras in requested_extras.items():
        if (
            package_name not in selected
            or not isinstance(extras, list)
            or not extras
            or extras != sorted(set(extras))
            or any(
                not isinstance(extra, str)
                or canonicalize_name(extra) != extra
                or extra not in selected[package_name]["providesExtras"]
                for extra in extras
            )
        ):
            raise ValidationError("requested extras are unsupported")
        normalized_extras[package_name] = extras
    dependencies: list[dict[str, str]] = []
    resolution: list[dict[str, Any]] = []
    active_targets: set[str] = set()
    active_edges: dict[str, set[str]] = {
        name: set() for name in selected
    }
    allowed_marker_variables = {*MARKER_ENVIRONMENT, "extra"}
    for source_name in sorted(selected):
        source = selected[source_name]
        contexts = ["", *normalized_extras.get(source_name, [])]
        for raw_requirement in source["requires"]:
            try:
                requirement = Requirement(raw_requirement)
            except InvalidRequirement as exc:
                raise ValidationError("Requires-Dist is invalid") from exc
            if requirement.url is not None:
                raise ValidationError("direct-URL Requires-Dist is unsupported")
            target_name = canonicalize_name(requirement.name)
            requested_target_extras = sorted(
                canonicalize_name(extra) for extra in requirement.extras
            )
            marker = str(requirement.marker) if requirement.marker else None
            if marker is not None:
                unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", marker)
                marker_words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", unquoted))
                if marker_words - allowed_marker_variables - {
                    "and",
                    "in",
                    "not",
                    "or",
                }:
                    raise ValidationError("Requires-Dist marker uses an unsupported variable")
            matched_contexts = []
            for extra in contexts:
                environment = {**MARKER_ENVIRONMENT, "extra": extra}
                if requirement.marker is None or requirement.marker.evaluate(
                    environment=environment,
                ):
                    matched_contexts.append(extra)
            applies = bool(matched_contexts)
            target = selected.get(target_name)
            selected_version = target["version"] if target is not None else None
            version_satisfied = (
                target is not None
                and (
                    not requirement.specifier
                    or Version(target["version"]) in requirement.specifier
                )
            )
            extras_satisfied = (
                target is not None
                and set(requested_target_extras).issubset(
                    target["providesExtras"]
                )
                and set(requested_target_extras).issubset(
                    normalized_extras.get(target_name, [])
                )
            )
            satisfied = not applies or (
                version_satisfied and extras_satisfied
            )
            if not satisfied:
                raise ValidationError(
                    "selected wheels do not satisfy an active Requires-Dist"
                )
            if applies:
                active_targets.add(target_name)
                active_edges[source_name].add(target_name)
            dependencies.append(
                {
                    "from": source_name,
                    "requirement": raw_requirement,
                }
            )
            resolution.append(
                {
                    "applies": applies,
                    "from": source_name,
                    "marker": marker,
                    "matchedExtraContexts": matched_contexts,
                    "normalizedName": target_name,
                    "requestedExtras": requested_target_extras,
                    "requirement": raw_requirement,
                    "satisfied": satisfied,
                    "selectedVersion": selected_version,
                    "specifier": str(requirement.specifier),
                }
            )
    dependencies.sort(key=lambda item: (item["from"], item["requirement"]))
    resolution.sort(key=lambda item: (item["from"], item["requirement"]))
    roots = {"serverware-enrollment"}
    reachable = set(roots)
    frontier = list(roots)
    while frontier:
        source_name = frontier.pop()
        for target_name in active_edges.get(source_name, set()):
            if target_name not in reachable:
                reachable.add(target_name)
                frontier.append(target_name)
    if (
        not roots.issubset(selected)
        or set(selected) - roots != active_targets - roots
        or any(target not in selected for target in active_targets)
        or reachable != set(selected)
    ):
        raise ValidationError("selected wheel dependency graph is not closed")
    return dependencies, resolution


def _verify_install_contract(
    checksums: dict[str, str],
    wheelhouse: dict[str, Any],
) -> dict[str, Any]:
    root_fd = _open_directory(SEALED_ROOT, label="sealed clean-room root")
    try:
        raw, _ = _read_regular_at(
            root_fd,
            PACKAGE_CONTRACT.name,
            label="package install contract",
            max_bytes=MAX_JSON_BYTES,
        )
    finally:
        os.close(root_fd)
    document = _load_json(raw, label="package install contract")
    if (
        raw != _canonical_json(document) + b"\n"
        or not isinstance(document, dict)
        or set(document)
        != {
            "apiVersion",
            "contractSha256",
            "dependencies",
            "exerciseScenarios",
            "generatedArtifacts",
            "markerEnvironment",
            "requestedExtras",
            "requirementsResolution",
            "wheels",
        }
        or document.get("apiVersion") != CONTRACT_VERSION
        or not isinstance(document.get("wheels"), list)
        or not isinstance(document.get("dependencies"), list)
        or not isinstance(document.get("requirementsResolution"), list)
        or not isinstance(document.get("generatedArtifacts"), list)
        or not isinstance(document.get("exerciseScenarios"), list)
        or document.get("markerEnvironment") != MARKER_ENVIRONMENT
    ):
        raise ValidationError("package install contract fields are invalid")
    payload = dict(document)
    supplied = payload.pop("contractSha256")
    if supplied != _sha256(_canonical_json(payload)):
        raise ValidationError("package install contract digest is invalid")
    expected_wheels = [
        {"path": item["wheel"], "sha256": item["sha256"]}
        for item in wheelhouse["packages"]
    ]
    if document["wheels"] != expected_wheels:
        raise ValidationError("install contract does not select every sealed wheel")
    installed_files: dict[str, dict[str, Any]] = {}
    generated_files: dict[str, dict[str, Any]] = {}
    wheel_records: list[dict[str, Any]] = []
    for wheel in document["wheels"]:
        if (
            not isinstance(wheel, dict)
            or set(wheel) != {"path", "sha256"}
            or wheel.get("sha256") != checksums.get(wheel.get("path"))
        ):
            raise ValidationError("install contract wheel record is invalid")
        record, wheel_files, wheel_generated = _verify_wheel_record(
            wheel["path"],
            wheel["sha256"],
        )
        package = next(
            item
            for item in wheelhouse["packages"]
            if item["wheel"] == wheel["path"]
        )
        if (
            record["name"] != package["name"]
            or record["normalizedName"] != package["normalizedName"]
            or record["version"] != package["version"]
            or record["providesExtras"] != package["providesExtras"]
            or record["requires"] != package["requires"]
        ):
            raise ValidationError("wheel metadata differs from its manifest")
        for path, item in wheel_files.items():
            if path in installed_files or path in generated_files:
                raise ValidationError("selected wheels collide when installed")
            installed_files[path] = item
        for path, item in wheel_generated.items():
            if path in installed_files or path in generated_files:
                raise ValidationError("selected wheels collide when installed")
            generated_files[path] = item
        wheel_records.append(record)
    dependencies, requirements_resolution = _resolve_requirements(
        wheel_records,
        document["requestedExtras"],
    )
    if (
        document["dependencies"] != dependencies
        or document["requirementsResolution"] != requirements_resolution
    ):
        raise ValidationError("install dependency resolution is not exact")
    expected_generated = [
        {
            "mode": item["mode"],
            "path": item["path"],
            "sha256": item["sha256"],
            "size": item["size"],
            "source": item["source"],
        }
        for _, item in sorted(generated_files.items())
    ]
    if document["generatedArtifacts"] != expected_generated:
        raise ValidationError("generated console-script bytes are not exact")
    expected_installation = _with_directories(
        {**installed_files, **generated_files}
    )
    installed_entries = _scan_tree(INSTALLED)
    if expected_installation != installed_entries:
        raise ValidationError(
            "installed tree is not byte-identical to selected wheel members "
            "and deterministic generated artifacts"
        )
    installed_paths = {item["path"]: item for item in expected_installation}
    for command in EXPECTED_COMMANDS:
        relative = str(Path(command).relative_to(INSTALLED))
        record = installed_paths.get(relative)
        if (
            record is None
            or record["type"] != "file"
            or not record["mode"] & 0o111
        ):
            raise ValidationError(f"installed command is missing: {command}")
    scenario_bindings = [
        {
            "argv": item.get("argv"),
            "expectedExitCode": item.get("expectedExitCode"),
            "expectedState": item.get("expectedState"),
            "scenario": item.get("scenario"),
        }
        for item in document["exerciseScenarios"]
    ]
    if (
        scenario_bindings != list(FIXED_SCENARIOS)
        or any(
            not isinstance(item, dict)
            or set(item)
            != {
                "argv",
                "expectedExitCode",
                "expectedState",
                "scenario",
                "stderrSha256",
                "stdoutSha256",
            }
            or SHA256_RE.fullmatch(str(item.get("stdoutSha256") or "")) is None
            or SHA256_RE.fullmatch(str(item.get("stderrSha256") or "")) is None
            for item in document["exerciseScenarios"]
        )
    ):
        raise ValidationError("clean-room exercise contract is not fixed")
    return {
        "contractSha256": supplied,
        "derivedEntries": expected_installation,
        "derivedInstallationSha256": _sha256(
            _canonical_json(expected_installation)
        ),
        "exerciseScenarios": document["exerciseScenarios"],
        "requirementsResolution": requirements_resolution,
        "requirementsResolutionSha256": _sha256(
            _canonical_json(requirements_resolution)
        ),
        "wheels": wheel_records,
        "wheelRecordsSha256": _sha256(_canonical_json(wheel_records)),
    }


def _mountinfo_unescape(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _verify_sandbox() -> dict[str, Any]:
    if os.getuid() != EXPECTED_UID or os.getgid() != EXPECTED_GID:
        raise ValidationError("clean-room lane is not running as the fixed nonroot user")
    if not os.statvfs("/").f_flag & getattr(os, "ST_RDONLY", 1):
        raise ValidationError("clean-room root filesystem is writable")
    try:
        mount_lines = Path("/proc/self/mountinfo").read_text(
            encoding="ascii"
        ).splitlines()
        status_lines = Path("/proc/self/status").read_text(
            encoding="ascii"
        ).splitlines()
        apparmor = Path("/proc/self/attr/current").read_text(
            encoding="ascii"
        ).strip()
    except (OSError, UnicodeError) as exc:
        raise ValidationError("clean-room sandbox evidence is unavailable") from exc
    allowed_mounts = {
        "/",
        "/dev",
        "/proc",
        "/run/serverware-runtime",
        "/tmp",
        "/work",
    }
    expected_filesystems = {
        "/dev": "tmpfs",
        "/proc": "proc",
        "/run/serverware-runtime": "tmpfs",
        "/tmp": "tmpfs",
        "/work": "tmpfs",
    }
    expected_tmpfs = {
        "/dev": {
            "gid": 0,
            "mode": 0o755,
            "options": {"nosuid", "rw", "strictatime"},
            "sizeBytes": 16 * 1024 * 1024,
            "uid": 0,
        },
        "/run/serverware-runtime": {
            "gid": EXPECTED_GID,
            "mode": 0o700,
            "options": {"nodev", "noexec", "nosuid", "rw", "strictatime"},
            "sizeBytes": 16 * 1024 * 1024,
            "uid": EXPECTED_UID,
        },
        "/tmp": {
            "gid": EXPECTED_GID,
            "mode": 0o700,
            "options": {"nodev", "noexec", "nosuid", "rw", "strictatime"},
            "sizeBytes": 256 * 1024 * 1024,
            "uid": EXPECTED_UID,
        },
        "/work": {
            "gid": EXPECTED_GID,
            "mode": 0o700,
            "options": {"nodev", "nosuid", "rw", "strictatime"},
            "sizeBytes": 256 * 1024 * 1024,
            "uid": EXPECTED_UID,
        },
    }
    unexpected_mounts: list[str] = []
    observed_mounts: list[str] = []
    mount_evidence: dict[str, dict[str, Any]] = {}
    for line in mount_lines:
        before, separator, after = line.partition(" - ")
        fields = before.split()
        trailing = after.split()
        if not separator or len(fields) < 6 or len(trailing) < 3:
            raise ValidationError("clean-room mount table is malformed")
        mountpoint = _mountinfo_unescape(fields[4])
        observed_mounts.append(mountpoint)
        raw_options = set(fields[5].split(",")) | set(trailing[2].split(","))
        options = raw_options.intersection(
            {
                "nodev",
                "noexec",
                "nosuid",
                "ro",
                "rw",
                "strictatime",
            }
        )
        metadata = os.stat(mountpoint, follow_symlinks=False)
        filesystem = os.statvfs(mountpoint)
        mount_evidence[mountpoint] = {
            "filesystem": trailing[0],
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "options": sorted(options),
            "rawOptions": sorted(raw_options),
            "sizeBytes": filesystem.f_blocks * filesystem.f_frsize,
            "uid": metadata.st_uid,
        }
        if (
            mountpoint not in allowed_mounts
            or (
                mountpoint in expected_filesystems
                and trailing[0] != expected_filesystems[mountpoint]
            )
        ):
            unexpected_mounts.append(mountpoint)
    if (
        unexpected_mounts
        or set(observed_mounts) != allowed_mounts
        or len(observed_mounts) != len(allowed_mounts)
    ):
        raise ValidationError(
            "clean-room contains a mount outside its exact OCI contract: "
            + ", ".join(sorted(unexpected_mounts or observed_mounts))
        )
    for mountpoint, expected in expected_tmpfs.items():
        actual = mount_evidence[mountpoint]
        if (
            actual["uid"] != expected["uid"]
            or actual["gid"] != expected["gid"]
            or actual["mode"] != expected["mode"]
            or actual["sizeBytes"] != expected["sizeBytes"]
            or set(actual["options"]) != expected["options"]
        ):
            raise ValidationError(
                f"clean-room tmpfs contract differs at {mountpoint}"
            )
    status: dict[str, str] = {}
    for line in status_lines:
        key, separator, value = line.partition(":")
        if separator:
            status[key] = value.strip()
    if (
        status.get("NoNewPrivs") != "1"
        or status.get("Seccomp") != "2"
        or any(
            int(status.get(name, "1"), 16) != 0
            for name in ("CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm")
        )
        or not apparmor
        or apparmor == "unconfined"
    ):
        raise ValidationError("clean-room security profile is not active")
    namespaces: dict[str, str] = {}
    for name in ("cgroup", "ipc", "mnt", "net", "pid", "user", "uts"):
        try:
            identity = os.readlink(f"/proc/self/ns/{name}")
        except OSError as exc:
            raise ValidationError("clean-room namespace evidence is missing") from exc
        if re.fullmatch(rf"{name}:\[[0-9]+\]", identity) is None:
            raise ValidationError("clean-room namespace identity is malformed")
        namespaces[name] = identity
    try:
        route_lines = Path("/proc/net/route").read_text(
            encoding="ascii"
        ).splitlines()
        interface_lines = Path("/proc/net/dev").read_text(
            encoding="ascii"
        ).splitlines()[2:]
    except (OSError, UnicodeError) as exc:
        raise ValidationError("clean-room network evidence is missing") from exc
    if len(route_lines) != 1:
        raise ValidationError("clean-room network namespace has an IPv4 route")
    interfaces = sorted(
        line.split(":", 1)[0].strip()
        for line in interface_lines
        if ":" in line
    )
    if interfaces != ["lo"]:
        raise ValidationError("clean-room network namespace is not loopback-only")
    work_fd = _open_directory(Path("/work"), label="clean-room work root")
    descriptor = -1
    try:
        descriptor = os.open(
            ".serverware-cwd-probe",
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | os.O_NOFOLLOW,
            0o600,
            dir_fd=work_fd,
        )
        created = os.fstat(descriptor)
        os.close(descriptor)
        descriptor = -1
        current = os.stat(
            ".serverware-cwd-probe",
            dir_fd=work_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino)
            != (created.st_dev, created.st_ino)
        ):
            raise ValidationError("clean-room writability probe was replaced")
        os.unlink(".serverware-cwd-probe", dir_fd=work_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(work_fd)
    return {
        "apparmor": apparmor,
        "capabilitySets": {
            name: status[name]
            for name in ("CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm")
        },
        "interfaces": interfaces,
        "mounts": mount_evidence,
        "namespaces": namespaces,
        "noNewPrivs": status["NoNewPrivs"],
        "routes": [],
        "seccomp": status["Seccomp"],
        "uid": os.getuid(),
        "gid": os.getgid(),
    }


def _terminate(process: subprocess.Popen[bytes]) -> None:
    for sent_signal, timeout in ((signal.SIGTERM, 1), (signal.SIGKILL, 5)):
        try:
            os.killpg(process.pid, sent_signal)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=timeout)
            return
        except subprocess.TimeoutExpired:
            continue
    raise ValidationError("fixed clean-room exercise process did not terminate")


def _run_fixed(scenario: dict[str, Any]) -> dict[str, Any]:
    scenario_name = scenario["scenario"]
    work_dir = Path("/work") / scenario_name
    work_dir.mkdir(mode=0o700)
    argv = scenario["argv"]
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "HOME": "/work/home",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/opt/serverware/clean-room/installed/bin",
            "PYTHONPATH": (
                "/opt/serverware/clean-room/installed/"
                "lib/python3.11/site-packages"
            ),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "TMPDIR": "/work/tmp",
            "XDG_RUNTIME_DIR": "/run/serverware-runtime",
        },
        cwd=work_dir,
        close_fds=True,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        _terminate(process)
        raise ValidationError("fixed clean-room exercise pipes are unavailable")
    selector = selectors.DefaultSelector()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, label)
    deadline = time.monotonic() + 30
    try:
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= deadline:
                raise ValidationError("fixed clean-room exercise timed out")
            for key, _ in selector.select(timeout=0.05):
                try:
                    raw = os.read(key.fd, 64 * 1024)
                except BlockingIOError:
                    continue
                if not raw:
                    selector.unregister(key.fileobj)
                    continue
                output[key.data].extend(raw)
                if len(output[key.data]) > MAX_OUTPUT_BYTES:
                    raise ValidationError("fixed clean-room exercise output is oversized")
        return_code = process.wait()
        if return_code != scenario["expectedExitCode"]:
            raise ValidationError(
                "fixed clean-room exercise returned an unexpected exit code"
            )
    except BaseException:
        _terminate(process)
        raise
    finally:
        selector.close()
    stdout_sha256 = _sha256(bytes(output["stdout"]))
    stderr_sha256 = _sha256(bytes(output["stderr"]))
    state = _scan_tree(work_dir)
    if (
        stdout_sha256 != scenario["stdoutSha256"]
        or stderr_sha256 != scenario["stderrSha256"]
        or state != scenario["expectedState"]
    ):
        raise ValidationError(
            f"{scenario_name} behavior differs from its promoted fixture"
        )
    return {
        "argv": argv,
        "exitCode": return_code,
        "scenario": scenario_name,
        "stateSha256": _sha256(_canonical_json(state)),
        "stderrSha256": stderr_sha256,
        "stdoutSha256": stdout_sha256,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Exercise the fixed sealed clean-room OCI payload.",
        allow_abbrev=False,
    )
    args = parser.parse_args()
    if sys.argv[1:]:
        parser.error("the sealed clean-room exercise accepts no arguments")
    return args


def main() -> None:
    _parse_args()
    try:
        sandbox = _verify_sandbox()
        payload = _verify_payload_manifest()
        checksums = _verify_checksums()
        wheelhouse = _verify_wheelhouse_manifest(checksums)
        installation = _verify_install_contract(checksums, wheelhouse)
        exercises = [
            _run_fixed(scenario)
            for scenario in installation["exerciseScenarios"]
        ]
        result_payload = {
            "apiVersion": RESULT_VERSION,
            "derivedInstallationSha256": installation[
                "derivedInstallationSha256"
            ],
            "exerciseScenarios": exercises,
            "installContractSha256": installation["contractSha256"],
            "payloadClosureSha256": payload["closureSha256"],
            "requirementsResolutionSha256": installation[
                "requirementsResolutionSha256"
            ],
            "sandboxEvidenceSha256": _sha256(_canonical_json(sandbox)),
            "wheelRecordsSha256": installation["wheelRecordsSha256"],
            "wheelhouseManifestPayloadSha256": wheelhouse[
                "payloadSha256"
            ],
        }
        result = {
            **result_payload,
            "resultSha256": _sha256(_canonical_json(result_payload)),
        }
        print(
            RESULT_PREFIX + _canonical_json(result).decode("ascii"),
            flush=True,
        )
    except (OSError, TypeError, UnicodeError, ValidationError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
