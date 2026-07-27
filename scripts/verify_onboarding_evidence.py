#!/usr/bin/env python3
"""Create and verify unsigned, local-integrity-only onboarding evidence."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import platform
import re
import stat
import struct
import sys
import unicodedata
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import NoReturn
from urllib.parse import parse_qsl, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

API_VERSION = "serverware.onboardingEvidence/v3"
ASSURANCE = {
    "classification": "local-integrity-only",
    "unsigned": True,
    "executionAttestation": False,
    "serverAttestation": False,
    "provenanceAttestation": False,
    "teeAttestation": False,
    "statement": (
        "Unsigned local hash-bound consistency over caller-supplied artifacts; "
        "timestamps, origins, identities, and trust anchors are not "
        "authenticated; not execution, server, provenance, or TEE attestation."
    ),
}

MAX_CAPTURE_INTERVAL_SECONDS = 3_600
MAX_EPOCH_SECONDS = 253_402_300_799
MAX_EPOCH_MILLISECONDS = 253_402_300_799_999
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20_000
MAX_JSON_STRING_LENGTH = 4_096
MAX_JSON_STRING_CHARACTERS = 1 * 1024 * 1024
MAX_JSON_CONTAINER_ITEMS = 4_096
MAX_JSON_TOTAL_CONTAINER_ITEMS = 20_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_SCREENSHOT_BYTES = 256 * 1024 * 1024
MAX_TOTAL_DECODED_PNG_BYTES = 512 * 1024 * 1024
MAX_SOURCE_INPUTS = 512
MAX_SCREENSHOTS = 128
READ_CHUNK_BYTES = 1024 * 1024
MAX_HTTP_BYTES = 1024 * 1024
MAX_HTTP_HEAD_BYTES = 64 * 1024
MAX_HTTP_BODY_BYTES = 512 * 1024
MAX_HTTP_HEADERS = 64
MAX_HTTP_LINE_BYTES = 8 * 1024
MAX_WEBAUTHN_COMPONENT_BYTES = 16 * 1024

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_PNG_WIDTH = 8_192
MAX_PNG_HEIGHT = 8_192
MAX_PNG_ROWS = 8_192
MAX_PNG_ROW_BYTES = 64 * 1024
MAX_DECODED_PNG_BYTES = 64 * 1024 * 1024
MAX_PNG_COMPRESSED_BYTES = 32 * 1024 * 1024
MAX_PNG_CHUNK_BYTES = 8 * 1024 * 1024
MAX_PNG_CHUNKS = 64
MAX_PNG_IDAT_CHUNKS = 16
MAX_PNG_PARSER_WORK = 160 * 1024 * 1024


class EvidenceError(ValueError):
    """Raised when evidence is unsafe, malformed, incomplete, or stale."""


@dataclass(frozen=True)
class _Capture:
    path: str
    kind: str
    limit: int
    identity: tuple[int, ...]
    facts: dict[str, object]


@dataclass
class _OutputPublication:
    relative: str
    leaf: str
    directory_parts: tuple[str, ...]
    directory_fds: list[int]
    directory_identities: list[tuple[int, ...]]
    pending_leaf: str | None = None
    pending_fd: int | None = None
    inode_identity: tuple[int, int] | None = None
    pending_exists: bool = False
    final_linked: bool = False

    @property
    def parent_fd(self) -> int:
        return self.directory_fds[-1]


def _fail(message: str) -> NoReturn:
    raise EvidenceError(message)


def _closed_object(
    value: object,
    *,
    name: str,
    fields: set[str],
) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{name} must be an object")
    actual = set(value)
    missing = sorted(fields - actual)
    unknown = sorted(actual - fields)
    if missing:
        _fail(f"{name} is missing fields: {', '.join(missing)}")
    if unknown:
        _fail(f"{name} has unknown fields: {', '.join(unknown)}")
    return value


def _text(value: object, *, name: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        _fail(f"{name} must be a string")
    if not value or value != value.strip() or len(value) > maximum:
        _fail(f"{name} must be a non-empty trimmed string of at most {maximum} characters")
    if unicodedata.normalize("NFC", value) != value:
        _fail(f"{name} must use NFC Unicode normalization")
    if any(unicodedata.category(character).startswith("C") for character in value):
        _fail(f"{name} must not contain control characters")
    return value


def _digest(value: object, *, name: str) -> str:
    digest = _text(value, name=name, maximum=71)
    if len(digest) != 71 or not digest.startswith("sha256:"):
        _fail(f"{name} must be canonical sha256:<64 lowercase hex>")
    if any(character not in "0123456789abcdef" for character in digest[7:]):
        _fail(f"{name} must be canonical sha256:<64 lowercase hex>")
    return digest


def _integer(
    value: object,
    *,
    name: str,
    minimum: int = 0,
    maximum: int = (1 << 63) - 1,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(f"{name} must be an integer from {minimum} through {maximum}")
    return value


def _literal(value: object, expected: object, *, name: str) -> None:
    if type(value) is not type(expected) or value != expected:
        rendered = repr(expected) if isinstance(expected, bytes) else json.dumps(expected)
        _fail(f"{name} must be {rendered}")


def _canonical_relative_path(value: object, *, name: str) -> str:
    path = _text(value, name=name, maximum=1024)
    if "\\" in path or "\x00" in path:
        _fail(f"{name} must be a canonical POSIX relative path")
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or pure.as_posix() != path
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        _fail(f"{name} must be a canonical POSIX relative path without . or ..")
    return path


def _duplicate_rejecting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"JSON contains duplicate object key {key!r}")
        result[key] = value
    return result


def _validate_json_resource_limits(value: object, *, name: str) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    string_characters = 0
    container_items = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            _fail(f"{name} exceeds the {MAX_JSON_NODES}-node JSON limit")
        if depth > MAX_JSON_DEPTH:
            _fail(f"{name} exceeds the {MAX_JSON_DEPTH}-level JSON depth limit")
        if isinstance(current, str):
            if len(current) > MAX_JSON_STRING_LENGTH:
                _fail(
                    f"{name} contains a string longer than "
                    f"{MAX_JSON_STRING_LENGTH} characters"
                )
            string_characters += len(current)
        elif isinstance(current, dict):
            if len(current) > MAX_JSON_CONTAINER_ITEMS:
                _fail(
                    f"{name} contains an object with more than "
                    f"{MAX_JSON_CONTAINER_ITEMS} entries"
                )
            container_items += len(current)
            for key, child in current.items():
                if len(key) > MAX_JSON_STRING_LENGTH:
                    _fail(
                        f"{name} contains an object key longer than "
                        f"{MAX_JSON_STRING_LENGTH} characters"
                    )
                string_characters += len(key)
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            if len(current) > MAX_JSON_CONTAINER_ITEMS:
                _fail(
                    f"{name} contains an array with more than "
                    f"{MAX_JSON_CONTAINER_ITEMS} entries"
                )
            container_items += len(current)
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, float):
            _fail(f"{name} must not contain floating-point numbers")
        elif current is not None and type(current) not in {bool, int}:
            _fail(f"{name} contains an unsupported JSON value")
        if string_characters > MAX_JSON_STRING_CHARACTERS:
            _fail(
                f"{name} exceeds the {MAX_JSON_STRING_CHARACTERS}-character "
                "aggregate JSON string limit"
            )
        if container_items > MAX_JSON_TOTAL_CONTAINER_ITEMS:
            _fail(
                f"{name} exceeds the {MAX_JSON_TOTAL_CONTAINER_ITEMS}-item "
                "aggregate JSON container limit"
            )


def _decode_json(data: bytes, *, name: str) -> object:
    if len(data) > MAX_JSON_BYTES:
        _fail(f"{name} exceeds the {MAX_JSON_BYTES}-byte JSON limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        _fail(f"{name} is not UTF-8: {exc}")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=lambda token: _fail(
                f"{name} contains non-finite number {token}"
            ),
        )
    except EvidenceError:
        raise
    except RecursionError:
        _fail(f"{name} exceeds safe JSON parser nesting")
    except (json.JSONDecodeError, ValueError) as exc:
        _fail(f"{name} is not valid bounded JSON: {exc}")
    _validate_json_resource_limits(value, name=name)
    return value


def _directory_flags() -> int:
    for required in ("O_DIRECTORY", "O_NOFOLLOW"):
        if not hasattr(os, required):
            _fail("this platform cannot provide fail-closed no-follow traversal")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _open_root_fd(root: Path) -> int:
    try:
        descriptor = os.open(os.fspath(root), _directory_flags())
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            os.close(descriptor)
            _fail("root must be a directory")
        return descriptor
    except EvidenceError:
        raise
    except OSError as exc:
        _fail(f"cannot pin root directory safely: {exc}")


def _open_directory(root_fd: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root_fd)
    try:
        for part in parts:
            next_descriptor = os.open(
                part,
                _directory_flags(),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        _fail(f"symlinks and unsafe path components are not allowed: {exc}")


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _open_regular_fd(root_fd: int, relative: str) -> tuple[int, os.stat_result]:
    parts = PurePosixPath(relative).parts
    parent_fd = _open_directory(root_fd, parts[:-1])
    try:
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        os.close(parent_fd)
        _fail(
            f"{relative}: symlinks are not allowed and the file cannot be "
            f"opened safely: {exc}"
        )
    os.close(parent_fd)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            _fail(f"{relative}: must be a regular file")
        if opened.st_nlink != 1:
            _fail(f"{relative}: regular file must have exactly one hard link")
        return descriptor, opened
    except Exception:
        os.close(descriptor)
        raise


def _capture_regular(
    root_fd: int,
    relative: str,
    *,
    limit: int,
    collect: bool = False,
) -> tuple[_Capture, bytes | None]:
    descriptor, before = _open_regular_fd(root_fd, relative)
    chunks: list[bytes] | None = [] if collect else None
    hasher = hashlib.sha256()
    size = 0
    try:
        if before.st_size > limit:
            _fail(f"{relative}: exceeds the {limit}-byte limit")
        while True:
            chunk = os.read(
                descriptor,
                min(READ_CHUNK_BYTES, limit - size + 1),
            )
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                _fail(f"{relative}: grew beyond the {limit}-byte limit while reading")
            hasher.update(chunk)
            if chunks is not None:
                chunks.append(chunk)
        after = os.fstat(descriptor)
    except EvidenceError:
        raise
    except OSError as exc:
        _fail(f"{relative}: cannot read stable input: {exc}")
    finally:
        os.close(descriptor)
    if after.st_nlink != 1:
        _fail(f"{relative}: regular file must have exactly one hard link")
    if _stat_identity(before) != _stat_identity(after) or size != before.st_size:
        _fail(f"{relative}: file changed while reading")
    facts = {
        "path": relative,
        "sha256": f"sha256:{hasher.hexdigest()}",
        "byteSize": size,
    }
    return (
        _Capture(
            path=relative,
            kind="regular",
            limit=limit,
            identity=_stat_identity(before),
            facts=facts,
        ),
        b"".join(chunks) if chunks is not None else None,
    )


def _parse_png(data: bytes, *, relative: str) -> dict[str, int]:
    if len(data) > MAX_FILE_BYTES:
        _fail(f"{relative}: exceeds the {MAX_FILE_BYTES}-byte screenshot limit")
    if not data.startswith(PNG_SIGNATURE):
        _fail(f"{relative}: is not a PNG")
    offset = len(PNG_SIGNATURE)
    chunk_count = 0
    idat_count = 0
    compressed = bytearray()
    width: int | None = None
    height: int | None = None
    decoded_size: int | None = None
    saw_idat = False
    idat_ended = False
    saw_iend = False
    while not saw_iend:
        chunk_count += 1
        if chunk_count > MAX_PNG_CHUNKS:
            _fail(f"{relative}: PNG exceeds the {MAX_PNG_CHUNKS}-chunk limit")
        if offset + 12 > len(data):
            _fail(f"{relative}: truncated PNG")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        offset += 8
        if any(
            not (65 <= character <= 90 or 97 <= character <= 122)
            for character in chunk_type
        ) or chunk_type[2] & 0x20:
            _fail(f"{relative}: PNG chunk type is invalid")
        if length > MAX_PNG_CHUNK_BYTES:
            _fail(f"{relative}: PNG chunk exceeds the {MAX_PNG_CHUNK_BYTES}-byte limit")
        if offset + length + 4 > len(data):
            _fail(f"{relative}: truncated PNG")
        chunk_data = data[offset : offset + length]
        expected_crc = struct.unpack(">I", data[offset + length : offset + length + 4])[0]
        actual_crc = zlib.crc32(chunk_type)
        actual_crc = zlib.crc32(chunk_data, actual_crc) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            _fail(f"{relative}: PNG chunk CRC mismatch")
        offset += length + 4

        if chunk_count == 1 and chunk_type != b"IHDR":
            _fail(f"{relative}: PNG must begin with IHDR")
        if chunk_type == b"IHDR":
            if chunk_count != 1 or length != 13 or width is not None:
                _fail(f"{relative}: PNG IHDR is duplicated or malformed")
            (
                width,
                height,
                bit_depth,
                color_type,
                compression_method,
                filter_method,
                interlace,
            ) = struct.unpack(">IIBBBBB", chunk_data)
            if not 1 <= width <= MAX_PNG_WIDTH:
                _fail(f"{relative}: PNG width exceeds the {MAX_PNG_WIDTH}-pixel limit")
            if not 1 <= height <= MAX_PNG_HEIGHT or height > MAX_PNG_ROWS:
                _fail(f"{relative}: PNG rows exceed the {MAX_PNG_ROWS}-row limit")
            if (
                bit_depth != 8
                or color_type != 6
                or compression_method != 0
                or filter_method != 0
                or interlace != 0
            ):
                _fail(
                    f"{relative}: PNG must use the supported non-interlaced "
                    "8-bit RGBA subset"
                )
            row_bytes = width * 4
            if row_bytes > MAX_PNG_ROW_BYTES:
                _fail(
                    f"{relative}: PNG row exceeds the "
                    f"{MAX_PNG_ROW_BYTES}-byte limit"
                )
            decoded_size = height * (row_bytes + 1)
            if decoded_size > MAX_DECODED_PNG_BYTES:
                _fail(
                    f"{relative}: decoded PNG exceeds the "
                    f"{MAX_DECODED_PNG_BYTES}-byte limit"
                )
        elif chunk_type == b"IDAT":
            if width is None or idat_ended or length == 0:
                _fail(f"{relative}: PNG IDAT is empty, out of order, or nonconsecutive")
            idat_count += 1
            if idat_count > MAX_PNG_IDAT_CHUNKS:
                _fail(
                    f"{relative}: PNG exceeds the "
                    f"{MAX_PNG_IDAT_CHUNKS}-IDAT-chunk limit"
                )
            if len(compressed) + length > MAX_PNG_COMPRESSED_BYTES:
                _fail(
                    f"{relative}: PNG compressed bytes exceed the "
                    f"{MAX_PNG_COMPRESSED_BYTES}-byte limit"
                )
            compressed.extend(chunk_data)
            saw_idat = True
        elif chunk_type == b"IEND":
            if length != 0 or not saw_idat:
                _fail(f"{relative}: PNG IEND is malformed or precedes IDAT")
            saw_iend = True
        elif chunk_type in {b"acTL", b"fcTL", b"fdAT"}:
            _fail(f"{relative}: APNG animation chunks are forbidden")
        elif chunk_type in {b"iCCP", b"zTXt", b"iTXt"}:
            _fail(f"{relative}: compressed ancillary PNG chunks are forbidden")
        else:
            _fail(f"{relative}: unsupported PNG chunk {chunk_type!r}")
        if saw_idat and chunk_type not in {b"IDAT", b"IEND"}:
            idat_ended = True

    if offset != len(data):
        _fail(f"{relative}: PNG has trailing bytes")
    if width is None or height is None or decoded_size is None or not compressed:
        _fail(f"{relative}: PNG is missing required data")
    parser_work = (
        len(data)
        + len(compressed)
        + decoded_size
        + chunk_count * 256
        + height
    )
    if parser_work > MAX_PNG_PARSER_WORK:
        _fail(
            f"{relative}: PNG parser work exceeds the "
            f"{MAX_PNG_PARSER_WORK}-unit limit"
        )
    try:
        decompressor = zlib.decompressobj()
        decoded = decompressor.decompress(bytes(compressed), decoded_size + 1)
        if len(decoded) > decoded_size:
            _fail(f"{relative}: PNG decodes beyond its declared dimensions")
        decoded += decompressor.flush(decoded_size + 1 - len(decoded))
    except zlib.error as exc:
        _fail(f"{relative}: PNG IDAT stream is invalid: {exc}")
    if (
        not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
        or len(decoded) != decoded_size
    ):
        _fail(f"{relative}: PNG IDAT data does not match declared dimensions")
    row_bytes = width * 4
    offset = 0
    for _ in range(height):
        if decoded[offset] > 4:
            _fail(f"{relative}: PNG contains an invalid row filter")
        offset += row_bytes + 1
    if offset != decoded_size:
        _fail(f"{relative}: PNG row layout is inconsistent")
    return {
        "decodedByteSize": decoded_size,
        "width": width,
        "height": height,
    }


def _capture_png(root_fd: int, relative: str) -> _Capture:
    regular, raw = _capture_regular(
        root_fd,
        relative,
        limit=MAX_FILE_BYTES,
        collect=True,
    )
    assert raw is not None
    facts = dict(regular.facts)
    facts.update(_parse_png(raw, relative=relative))
    return _Capture(
        path=relative,
        kind="png",
        limit=regular.limit,
        identity=regular.identity,
        facts=facts,
    )


def _validate_runtime(value: object) -> dict[str, object]:
    runtime = _closed_object(
        value,
        name="captureRuntime",
        fields={"python", "playwright", "chromium"},
    )
    patterns = {
        "python": r"[0-9]+\.[0-9]+\.[0-9]+",
        "playwright": r"[0-9]+\.[0-9]+\.[0-9]+",
        "chromium": r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",
    }
    for field, pattern in patterns.items():
        version = _text(runtime[field], name=f"captureRuntime.{field}", maximum=128)
        if re.fullmatch(pattern, version) is None:
            _fail(f"captureRuntime.{field} is not a canonical version")
    return runtime


def _validate_assurance(value: object) -> dict[str, object]:
    assurance = _closed_object(
        value,
        name="assurance",
        fields=set(ASSURANCE),
    )
    for field, expected in ASSURANCE.items():
        _literal(assurance[field], expected, name=f"assurance.{field}")
    return assurance


def _validate_oauth_approval(
    value: object,
    *,
    name: str,
    requester_id: str,
    reviewer_id: str,
) -> dict[str, object]:
    approval = _closed_object(
        value,
        name=name,
        fields={
            "approvalId",
            "expectedAccountId",
            "observedAccountId",
            "exactAccount",
            "requestedBy",
            "approvedBy",
            "activatedBy",
            "credentialId",
        },
    )
    _text(approval["approvalId"], name=f"{name}.approvalId")
    expected = _text(approval["expectedAccountId"], name=f"{name}.expectedAccountId")
    observed = _text(approval["observedAccountId"], name=f"{name}.observedAccountId")
    if expected != observed:
        _fail(f"{name} expected and observed account IDs must match exactly")
    _literal(approval["exactAccount"], True, name=f"{name}.exactAccount")
    _literal(approval["requestedBy"], requester_id, name=f"{name}.requestedBy")
    _literal(approval["approvedBy"], reviewer_id, name=f"{name}.approvedBy")
    _literal(approval["activatedBy"], requester_id, name=f"{name}.activatedBy")
    _text(approval["credentialId"], name=f"{name}.credentialId")
    return approval


def _validate_activation_challenge(
    value: object,
    *,
    name: str,
    approval_id: object,
    requester_id: str,
) -> None:
    challenge = _closed_object(
        value,
        name=name,
        fields={"status", "approvalId", "actorId"},
    )
    _literal(challenge["status"], 428, name=f"{name}.status")
    _literal(challenge["approvalId"], approval_id, name=f"{name}.approvalId")
    _literal(challenge["actorId"], requester_id, name=f"{name}.actorId")


def _validate_policy(value: object) -> dict[str, object]:
    policy = _closed_object(value, name="policy artifact", fields={"gmail", "x"})
    gmail = _closed_object(
        policy["gmail"],
        name="policy artifact.gmail",
        fields={"maximumAgeDays"},
    )
    _literal(
        gmail["maximumAgeDays"],
        30,
        name="policy artifact.gmail.maximumAgeDays",
    )
    x_policy = _closed_object(
        policy["x"],
        name="policy artifact.x",
        fields={"maximumSearchLookbackDays", "maximumPostsPerUtcDay"},
    )
    _literal(
        x_policy["maximumSearchLookbackDays"],
        7,
        name="policy artifact.x.maximumSearchLookbackDays",
    )
    _literal(
        x_policy["maximumPostsPerUtcDay"],
        1,
        name="policy artifact.x.maximumPostsPerUtcDay",
    )
    return policy


def _validate_artifact_paths(
    value: object,
    *,
    name: str,
    fields: set[str],
) -> dict[str, object]:
    artifact_paths = _closed_object(value, name=name, fields=fields)
    for field in fields:
        _canonical_relative_path(
            artifact_paths[field],
            name=f"{name}.{field}",
        )
    return artifact_paths


def _validate_journey(value: object) -> dict[str, object]:
    journey = _closed_object(
        value,
        name="journey",
        fields={
            "ok",
            "captureInterval",
            "operators",
            "oauthApprovals",
            "oauthActivationChallenges",
            "policy",
            "packet",
            "gmail",
            "x",
            "jitApproval",
            "unknownRoute",
        },
    )
    _literal(journey["ok"], True, name="journey.ok")
    capture_interval = _closed_object(
        journey["captureInterval"],
        name="journey.captureInterval",
        fields={
            "startedAtEpochSeconds",
            "endedAtEpochSeconds",
            "timestampsAuthenticated",
        },
    )
    started_at = _integer(
        capture_interval["startedAtEpochSeconds"],
        name="journey.captureInterval.startedAtEpochSeconds",
        maximum=MAX_EPOCH_SECONDS,
    )
    ended_at = _integer(
        capture_interval["endedAtEpochSeconds"],
        name="journey.captureInterval.endedAtEpochSeconds",
        maximum=MAX_EPOCH_SECONDS,
    )
    _literal(
        capture_interval["timestampsAuthenticated"],
        False,
        name="journey.captureInterval.timestampsAuthenticated",
    )
    if not started_at < ended_at:
        _fail("journey.captureInterval must have a positive duration")
    if ended_at - started_at > MAX_CAPTURE_INTERVAL_SECONDS:
        _fail(
            "journey.captureInterval exceeds the "
            f"{MAX_CAPTURE_INTERVAL_SECONDS}-second limit"
        )
    operators = _closed_object(
        journey["operators"],
        name="journey.operators",
        fields={"requesterId", "reviewerId"},
    )
    requester_id = _text(
        operators["requesterId"],
        name="journey.operators.requesterId",
    )
    reviewer_id = _text(
        operators["reviewerId"],
        name="journey.operators.reviewerId",
    )
    if requester_id == reviewer_id:
        _fail("journey operator IDs must be distinct")

    oauth = _closed_object(
        journey["oauthApprovals"],
        name="journey.oauthApprovals",
        fields={"google", "x"},
    )
    google = _validate_oauth_approval(
        oauth["google"],
        name="journey.oauthApprovals.google",
        requester_id=requester_id,
        reviewer_id=reviewer_id,
    )
    x_approval = _validate_oauth_approval(
        oauth["x"],
        name="journey.oauthApprovals.x",
        requester_id=requester_id,
        reviewer_id=reviewer_id,
    )
    if google["approvalId"] == x_approval["approvalId"]:
        _fail("Google and X OAuth approval IDs must be distinct")
    if google["credentialId"] == x_approval["credentialId"]:
        _fail("Google and X OAuth credential IDs must be distinct")
    challenges = _closed_object(
        journey["oauthActivationChallenges"],
        name="journey.oauthActivationChallenges",
        fields={"google", "x"},
    )
    _validate_activation_challenge(
        challenges["google"],
        name="journey.oauthActivationChallenges.google",
        approval_id=google["approvalId"],
        requester_id=requester_id,
    )
    _validate_activation_challenge(
        challenges["x"],
        name="journey.oauthActivationChallenges.x",
        approval_id=x_approval["approvalId"],
        requester_id=requester_id,
    )

    policy = _closed_object(
        journey["policy"],
        name="journey.policy",
        fields={"artifactPath"},
    )
    _canonical_relative_path(
        policy["artifactPath"],
        name="journey.policy.artifactPath",
    )
    packet = _closed_object(
        journey["packet"],
        name="journey.packet",
        fields={"artifactPath"},
    )
    _canonical_relative_path(
        packet["artifactPath"],
        name="journey.packet.artifactPath",
    )
    _validate_artifact_paths(
        journey["gmail"],
        name="journey.gmail",
        fields={"requestArtifactPath", "responseArtifactPath"},
    )
    x_evidence = _closed_object(
        journey["x"],
        name="journey.x",
        fields={
            "searchRequestArtifactPath",
            "searchResponseArtifactPath",
            "firstPostRequestArtifactPath",
            "firstPostResponseArtifactPath",
            "secondPostRequestArtifactPath",
            "secondPostResponseArtifactPath",
            "postCounterArtifactPath",
            "capturedAtEpochSeconds",
            "captureTimeAuthenticated",
        },
    )
    for field in (
        "searchRequestArtifactPath",
        "searchResponseArtifactPath",
        "firstPostRequestArtifactPath",
        "firstPostResponseArtifactPath",
        "secondPostRequestArtifactPath",
        "secondPostResponseArtifactPath",
        "postCounterArtifactPath",
    ):
        _canonical_relative_path(x_evidence[field], name=f"journey.x.{field}")
    _require_capture_time(
        journey,
        x_evidence["capturedAtEpochSeconds"],
        name="journey.x.capturedAtEpochSeconds",
    )
    _literal(
        x_evidence["captureTimeAuthenticated"],
        False,
        name="journey.x.captureTimeAuthenticated",
    )

    jit = _closed_object(
        journey["jitApproval"],
        name="journey.jitApproval",
        fields={
            "approvedBy",
            "approvalRequestId",
            "challengeRequestArtifactPath",
            "retryRequestArtifactPath",
            "challengeResponseArtifactPath",
            "retryResponseArtifactPath",
            "challengeIssuedAtEpochSeconds",
            "approvedAtEpochSeconds",
            "expiresAtEpochSeconds",
            "retryAtEpochSeconds",
            "webauthn",
        },
    )
    _literal(jit["approvedBy"], reviewer_id, name="journey.jitApproval.approvedBy")
    _text(jit["approvalRequestId"], name="journey.jitApproval.approvalRequestId")
    for field in (
        "challengeRequestArtifactPath",
        "retryRequestArtifactPath",
        "challengeResponseArtifactPath",
        "retryResponseArtifactPath",
    ):
        _canonical_relative_path(jit[field], name=f"journey.jitApproval.{field}")
    issued = _integer(
        jit["challengeIssuedAtEpochSeconds"],
        name="journey.jitApproval.challengeIssuedAtEpochSeconds",
    )
    approved = _integer(
        jit["approvedAtEpochSeconds"],
        name="journey.jitApproval.approvedAtEpochSeconds",
    )
    expires = _integer(
        jit["expiresAtEpochSeconds"],
        name="journey.jitApproval.expiresAtEpochSeconds",
    )
    retry = _integer(
        jit["retryAtEpochSeconds"],
        name="journey.jitApproval.retryAtEpochSeconds",
    )
    if not issued < approved <= retry < expires:
        _fail(
            "journey JIT timestamps must satisfy challenge < approval <= retry < expiry"
        )
    for field, timestamp in (
        ("challengeIssuedAtEpochSeconds", issued),
        ("approvedAtEpochSeconds", approved),
        ("retryAtEpochSeconds", retry),
    ):
        _require_capture_time(
            journey,
            timestamp,
            name=f"journey.jitApproval.{field}",
        )
    if expires - issued > 300:
        _fail("journey JIT approval lifetime must not exceed 300 seconds")
    webauthn = _closed_object(
        jit["webauthn"],
        name="journey.jitApproval.webauthn",
        fields={
            "credentialId",
            "clientDataJSONArtifactPath",
            "authenticatorDataArtifactPath",
            "signatureArtifactPath",
            "publicKeyArtifactPath",
            "expectedOrigin",
            "expectedRpId",
            "expectedSignatureCounter",
        },
    )
    _text(
        webauthn["credentialId"],
        name="journey.jitApproval.webauthn.credentialId",
    )
    for field in (
        "clientDataJSONArtifactPath",
        "authenticatorDataArtifactPath",
        "signatureArtifactPath",
        "publicKeyArtifactPath",
    ):
        _canonical_relative_path(
            webauthn[field],
            name=f"journey.jitApproval.webauthn.{field}",
        )
    origin = _text(
        webauthn["expectedOrigin"],
        name="journey.jitApproval.webauthn.expectedOrigin",
    )
    rp_id = _text(
        webauthn["expectedRpId"],
        name="journey.jitApproval.webauthn.expectedRpId",
    )
    dns_name = (
        r"(?=.{1,253}\Z)"
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
    )
    if re.fullmatch(dns_name, rp_id) is None:
        _fail("journey WebAuthn expectedRpId must be a canonical DNS RP ID")
    if origin != f"https://{rp_id}":
        _fail("journey WebAuthn expectedOrigin must be the HTTPS RP ID origin")
    _integer(
        webauthn["expectedSignatureCounter"],
        name="journey.jitApproval.webauthn.expectedSignatureCounter",
        minimum=1,
        maximum=(1 << 32) - 1,
    )

    unknown = _closed_object(
        journey["unknownRoute"],
        name="journey.unknownRoute",
        fields={"status", "error", "upstreamCalls", "credentialLeaseIssued"},
    )
    _literal(unknown["status"], 403, name="journey.unknownRoute.status")
    _literal(
        unknown["error"],
        "unknown_route_denied",
        name="journey.unknownRoute.error",
    )
    _literal(unknown["upstreamCalls"], 0, name="journey.unknownRoute.upstreamCalls")
    _literal(
        unknown["credentialLeaseIssued"],
        False,
        name="journey.unknownRoute.credentialLeaseIssued",
    )
    return journey


def _file_entry(value: object, *, name: str, screenshot: bool) -> dict[str, object]:
    fields = {"path", "sha256", "byteSize"}
    if screenshot:
        fields |= {"decodedByteSize", "width", "height"}
    entry = _closed_object(value, name=name, fields=fields)
    path = _canonical_relative_path(entry["path"], name=f"{name}.path")
    _digest(entry["sha256"], name=f"{name}.sha256")
    _integer(
        entry["byteSize"],
        name=f"{name}.byteSize",
        minimum=1 if screenshot else 0,
        maximum=MAX_FILE_BYTES,
    )
    if screenshot:
        if not path.lower().endswith(".png"):
            _fail(f"{name}.path must end in .png")
        _integer(
            entry["decodedByteSize"],
            name=f"{name}.decodedByteSize",
            minimum=1,
            maximum=MAX_DECODED_PNG_BYTES,
        )
        _integer(
            entry["width"],
            name=f"{name}.width",
            minimum=1,
            maximum=MAX_PNG_WIDTH,
        )
        _integer(
            entry["height"],
            name=f"{name}.height",
            minimum=1,
            maximum=MAX_PNG_HEIGHT,
        )
    return entry


def _file_entries(
    value: object,
    *,
    name: str,
    screenshot: bool,
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        _fail(f"{name} must be an array")
    limit = MAX_SCREENSHOTS if screenshot else MAX_SOURCE_INPUTS
    if not 1 <= len(value) <= limit:
        _fail(f"{name} must contain from 1 through {limit} entries")
    entries = [
        _file_entry(item, name=f"{name}[{index}]", screenshot=screenshot)
        for index, item in enumerate(value)
    ]
    paths = [entry["path"] for entry in entries]
    if len(set(paths)) != len(paths):
        _fail(f"{name} contains duplicate paths")
    if paths != sorted(paths):
        _fail(f"{name} paths must be sorted lexicographically")
    return entries


def _validate_manifest_shape(value: object) -> dict[str, object]:
    manifest = _closed_object(
        value,
        name="manifest",
        fields={
            "apiVersion",
            "assurance",
            "captureRuntime",
            "journeyArtifact",
            "workflow",
            "sourceInputs",
            "screenshots",
        },
    )
    _literal(manifest["apiVersion"], API_VERSION, name="manifest.apiVersion")
    _validate_assurance(manifest["assurance"])
    _validate_runtime(manifest["captureRuntime"])
    journey_entry = _file_entry(
        manifest["journeyArtifact"],
        name="journeyArtifact",
        screenshot=False,
    )
    if not journey_entry["path"].endswith(".json"):
        _fail("journeyArtifact.path must end in .json")
    _closed_object(
        manifest["workflow"],
        name="workflow",
        fields={
            "captureInterval",
            "operators",
            "oauthApprovals",
            "oauthActivationChallenges",
            "policyArtifact",
            "packetArtifact",
            "gmail",
            "x",
            "jitApproval",
            "unknownRoute",
        },
    )
    _file_entries(manifest["sourceInputs"], name="sourceInputs", screenshot=False)
    _file_entries(manifest["screenshots"], name="screenshots", screenshot=True)
    return manifest


def _validate_path_sets(manifest: dict[str, object], manifest_path: str) -> None:
    journey_path = manifest["journeyArtifact"]["path"]
    source_paths = {entry["path"] for entry in manifest["sourceInputs"]}
    screenshot_paths = {entry["path"] for entry in manifest["screenshots"]}
    sets = [
        {manifest_path},
        {journey_path},
        source_paths,
        screenshot_paths,
    ]
    labels = ["manifest", "journeyArtifact", "sourceInputs", "screenshots"]
    for left in range(len(sets)):
        for right in range(left + 1, len(sets)):
            if sets[left] & sets[right]:
                _fail(f"{labels[left]} paths must not overlap {labels[right]}")


def _facts_match(
    expected: dict[str, object],
    actual: dict[str, object],
    *,
    name: str,
) -> None:
    if expected != actual:
        _fail(
            f"{name} drift for {expected.get('path', '<unknown>')}: "
            f"expected {expected!r}, got {actual!r}"
        )


def _capture_source_inputs(
    root_fd: int,
    paths: list[str],
    *,
    collect_paths: set[str],
    path_limits: dict[str, int] | None = None,
) -> tuple[list[_Capture], dict[str, bytes]]:
    captures: list[_Capture] = []
    collected: dict[str, bytes] = {}
    total = 0
    for path in sorted(paths):
        capture, raw = _capture_regular(
            root_fd,
            path,
            limit=(path_limits or {}).get(path, MAX_FILE_BYTES),
            collect=path in collect_paths,
        )
        total += capture.facts["byteSize"]
        if total > MAX_TOTAL_SOURCE_BYTES:
            _fail(f"sourceInputs exceed the {MAX_TOTAL_SOURCE_BYTES}-byte total limit")
        captures.append(capture)
        if raw is not None:
            collected[path] = raw
    return captures, collected


def _capture_screenshots(root_fd: int, paths: list[str]) -> list[_Capture]:
    captures: list[_Capture] = []
    encoded_total = 0
    decoded_total = 0
    for path in sorted(paths):
        capture = _capture_png(root_fd, path)
        encoded_total += capture.facts["byteSize"]
        decoded_total += capture.facts["decodedByteSize"]
        if encoded_total > MAX_TOTAL_SCREENSHOT_BYTES:
            _fail(
                f"screenshots exceed the {MAX_TOTAL_SCREENSHOT_BYTES}-byte "
                "encoded total limit"
            )
        if decoded_total > MAX_TOTAL_DECODED_PNG_BYTES:
            _fail(
                f"screenshots exceed the {MAX_TOTAL_DECODED_PNG_BYTES}-byte "
                "decoded total limit"
            )
        captures.append(capture)
    return captures


def _reference_paths(journey: dict[str, object]) -> set[str]:
    jit = journey["jitApproval"]
    webauthn = jit["webauthn"]
    gmail = journey["gmail"]
    x_evidence = journey["x"]
    paths = {
        journey["policy"]["artifactPath"],
        journey["packet"]["artifactPath"],
        gmail["requestArtifactPath"],
        gmail["responseArtifactPath"],
        x_evidence["searchRequestArtifactPath"],
        x_evidence["searchResponseArtifactPath"],
        x_evidence["firstPostRequestArtifactPath"],
        x_evidence["firstPostResponseArtifactPath"],
        x_evidence["secondPostRequestArtifactPath"],
        x_evidence["secondPostResponseArtifactPath"],
        x_evidence["postCounterArtifactPath"],
        jit["challengeRequestArtifactPath"],
        jit["retryRequestArtifactPath"],
        jit["challengeResponseArtifactPath"],
        jit["retryResponseArtifactPath"],
        webauthn["clientDataJSONArtifactPath"],
        webauthn["authenticatorDataArtifactPath"],
        webauthn["signatureArtifactPath"],
        webauthn["publicKeyArtifactPath"],
    }
    if len(paths) != 19:
        _fail("all journey-bound evidence artifact paths must be distinct")
    return paths


def _reference_limits(journey: dict[str, object]) -> dict[str, int]:
    jit = journey["jitApproval"]
    webauthn = jit["webauthn"]
    gmail = journey["gmail"]
    x_evidence = journey["x"]
    limits = {
        journey["policy"]["artifactPath"]: MAX_JSON_BYTES,
        journey["packet"]["artifactPath"]: MAX_FILE_BYTES,
        gmail["requestArtifactPath"]: MAX_HTTP_BYTES,
        gmail["responseArtifactPath"]: MAX_HTTP_BYTES,
        x_evidence["searchRequestArtifactPath"]: MAX_HTTP_BYTES,
        x_evidence["searchResponseArtifactPath"]: MAX_HTTP_BYTES,
        x_evidence["firstPostRequestArtifactPath"]: MAX_HTTP_BYTES,
        x_evidence["firstPostResponseArtifactPath"]: MAX_HTTP_BYTES,
        x_evidence["secondPostRequestArtifactPath"]: MAX_HTTP_BYTES,
        x_evidence["secondPostResponseArtifactPath"]: MAX_HTTP_BYTES,
        x_evidence["postCounterArtifactPath"]: MAX_JSON_BYTES,
        jit["challengeRequestArtifactPath"]: MAX_HTTP_BYTES,
        jit["retryRequestArtifactPath"]: MAX_HTTP_BYTES,
        jit["challengeResponseArtifactPath"]: MAX_HTTP_BYTES,
        jit["retryResponseArtifactPath"]: MAX_HTTP_BYTES,
        webauthn["clientDataJSONArtifactPath"]: MAX_WEBAUTHN_COMPONENT_BYTES,
        webauthn["authenticatorDataArtifactPath"]: MAX_WEBAUTHN_COMPONENT_BYTES,
        webauthn["signatureArtifactPath"]: MAX_WEBAUTHN_COMPONENT_BYTES,
        webauthn["publicKeyArtifactPath"]: MAX_WEBAUTHN_COMPONENT_BYTES,
    }
    if set(limits) != _reference_paths(journey):
        _fail("internal evidence reference limit map is incomplete")
    return limits


def _parse_http_head(
    raw: bytes,
    *,
    name: str,
) -> tuple[bytes, dict[str, str], bytes]:
    if not raw or len(raw) > MAX_HTTP_BYTES:
        _fail(f"{name} must contain from 1 through {MAX_HTTP_BYTES} HTTP bytes")
    if b"\x00" in raw:
        _fail(f"{name} contains a NUL byte")
    separator = raw.find(b"\r\n\r\n")
    if separator < 0 or separator > MAX_HTTP_HEAD_BYTES:
        _fail(f"{name} is missing a bounded CRLF HTTP header terminator")
    head = raw[:separator]
    body = raw[separator + 4 :]
    if len(body) > MAX_HTTP_BODY_BYTES:
        _fail(f"{name} exceeds the {MAX_HTTP_BODY_BYTES}-byte HTTP body limit")
    if b"\r" in head.replace(b"\r\n", b"") or b"\n" in head.replace(b"\r\n", b""):
        _fail(f"{name} contains non-CRLF HTTP line endings")
    lines = head.split(b"\r\n")
    if not lines or len(lines[0]) > MAX_HTTP_LINE_BYTES:
        _fail(f"{name} has an invalid HTTP start line")
    if not 1 <= len(lines) - 1 <= MAX_HTTP_HEADERS:
        _fail(f"{name} must contain from 1 through {MAX_HTTP_HEADERS} headers")
    headers: dict[str, str] = {}
    for raw_line in lines[1:]:
        if not raw_line or len(raw_line) > MAX_HTTP_LINE_BYTES or b":" not in raw_line:
            _fail(f"{name} contains a malformed HTTP header line")
        raw_key, raw_value = raw_line.split(b":", 1)
        try:
            key = raw_key.decode("ascii")
            value = raw_value.decode("ascii")
        except UnicodeDecodeError:
            _fail(f"{name} HTTP headers must be ASCII")
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", key) is None:
            _fail(f"{name} HTTP header names must be canonical lowercase tokens")
        if key in headers:
            _fail(f"{name} contains duplicate HTTP header {key}")
        if value != value.strip() or not value:
            _fail(f"{name} HTTP header {key} must be non-empty and trimmed")
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
            _fail(f"{name} HTTP header {key} contains non-visible ASCII")
        headers[key] = value
    if "transfer-encoding" in headers:
        _fail(f"{name} must not use transfer-encoding")
    declared_length = headers.get("content-length")
    if declared_length is None:
        if body:
            _fail(f"{name} body requires content-length")
    elif (
        len(declared_length) > 10
        or re.fullmatch(r"0|[1-9][0-9]*", declared_length) is None
        or int(declared_length) != len(body)
    ):
        _fail(f"{name} content-length does not exactly match its body")
    return lines[0], headers, body


def _parse_http_request(raw: bytes, *, name: str) -> dict[str, object]:
    start_line, headers, body = _parse_http_head(raw, name=name)
    try:
        start = start_line.decode("ascii")
    except UnicodeDecodeError:
        _fail(f"{name} request line must be ASCII")
    parts = start.split(" ")
    if len(parts) != 3 or parts[2] != "HTTP/1.1":
        _fail(f"{name} must use a canonical HTTP/1.1 request line")
    method, target, _ = parts
    if re.fullmatch(r"[A-Z]{3,10}", method) is None:
        _fail(f"{name} has an invalid HTTP method")
    if not target.startswith("/") or len(target) > MAX_HTTP_LINE_BYTES:
        _fail(f"{name} must use a bounded origin-form request target")
    split = urlsplit(target)
    if split.scheme or split.netloc or split.fragment:
        _fail(f"{name} request target must not contain scheme, authority, or fragment")
    if re.search(r"%(?![0-9A-F]{2})", split.query):
        _fail(f"{name} query must use canonical uppercase percent encoding")
    try:
        query_pairs = parse_qsl(
            split.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=32,
            encoding="utf-8",
            errors="strict",
        )
    except (UnicodeDecodeError, ValueError) as exc:
        _fail(f"{name} has an invalid bounded query string: {exc}")
    query: dict[str, str] = {}
    for key, value in query_pairs:
        if key in query:
            _fail(f"{name} contains duplicate query parameter {key}")
        query[key] = value
    authority = headers.get("host")
    if authority is None or re.fullmatch(r"[a-z0-9.-]+", authority) is None:
        _fail(f"{name} requires a canonical lowercase host header")
    return {
        "method": method,
        "authority": authority,
        "path": split.path,
        "query": query,
        "headers": headers,
        "body": body,
    }


def _parse_http_response(raw: bytes, *, name: str) -> dict[str, object]:
    start_line, headers, body = _parse_http_head(raw, name=name)
    try:
        start = start_line.decode("ascii")
    except UnicodeDecodeError:
        _fail(f"{name} status line must be ASCII")
    match = re.fullmatch(r"HTTP/1\.1 ([1-5][0-9]{2}) ([\x20-\x7e]{1,64})", start)
    if match is None:
        _fail(f"{name} must use a canonical HTTP/1.1 status line")
    return {
        "status": int(match.group(1)),
        "headers": headers,
        "body": body,
    }


def _json_http_body(message: dict[str, object], *, name: str) -> object:
    if message["headers"].get("content-type") != "application/json":
        _fail(f"{name} must use content-type application/json")
    return _decode_json(message["body"], name=f"{name} body")


def _require_header_names(
    message: dict[str, object],
    expected: set[str],
    *,
    name: str,
) -> None:
    actual = set(message["headers"])
    if actual != expected:
        _fail(
            f"{name} headers must be exactly {', '.join(sorted(expected))}; "
            f"got {', '.join(sorted(actual))}"
        )


def _require_request_identity(
    request: dict[str, object],
    *,
    principal_id: str,
    credential_id: str,
    name: str,
) -> None:
    headers = request["headers"]
    _literal(
        headers.get("x-serverware-principal"),
        principal_id,
        name=f"{name} x-serverware-principal",
    )
    _literal(
        headers.get("x-serverware-credential-id"),
        credential_id,
        name=f"{name} x-serverware-credential-id",
    )


def _parse_rfc3339_utc(value: object, *, name: str) -> datetime:
    timestamp = _text(value, name=name, maximum=20)
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", timestamp) is None:
        _fail(f"{name} must be canonical second-resolution RFC3339 UTC")
    try:
        return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        _fail(f"{name} is not a valid UTC timestamp: {exc}")


def _epoch_milliseconds(value: object, *, name: str) -> int:
    encoded = _text(value, name=name, maximum=15)
    if re.fullmatch(r"(?:0|[1-9][0-9]{0,14})", encoded) is None:
        _fail(f"{name} must be canonical decimal epoch milliseconds")
    milliseconds = int(encoded)
    if milliseconds > MAX_EPOCH_MILLISECONDS:
        _fail(f"{name} exceeds the supported epoch-millisecond range")
    return milliseconds


def _capture_interval(journey: dict[str, object]) -> tuple[int, int]:
    interval = journey["captureInterval"]
    return interval["startedAtEpochSeconds"], interval["endedAtEpochSeconds"]


def _require_capture_time(
    journey: dict[str, object],
    value: object,
    *,
    name: str,
) -> int:
    captured_at = _integer(value, name=name, maximum=MAX_EPOCH_SECONDS)
    started_at, ended_at = _capture_interval(journey)
    if not started_at <= captured_at <= ended_at:
        _fail(f"{name} must lie within journey.captureInterval")
    return captured_at


def _artifact_facts(
    source_by_path: dict[str, _Capture],
    path: str,
) -> dict[str, object]:
    return source_by_path[path].facts


def _derive_gmail(
    journey: dict[str, object],
    policy: dict[str, object],
    source_by_path: dict[str, _Capture],
    collected: dict[str, bytes],
) -> dict[str, object]:
    gmail = journey["gmail"]
    request_path = gmail["requestArtifactPath"]
    response_path = gmail["responseArtifactPath"]
    request = _parse_http_request(collected[request_path], name=request_path)
    _literal(request["method"], "GET", name="Gmail request method")
    _literal(request["authority"], "gmail.googleapis.com", name="Gmail authority")
    _literal(
        request["path"],
        "/gmail/v1/users/me/messages",
        name="Gmail request path",
    )
    _literal(request["body"], b"", name="Gmail request body")
    _require_header_names(
        request,
        {
            "host",
            "x-serverware-principal",
            "x-serverware-credential-id",
        },
        name="Gmail request",
    )
    _require_request_identity(
        request,
        principal_id=journey["operators"]["requesterId"],
        credential_id=journey["oauthApprovals"]["google"]["credentialId"],
        name="Gmail request",
    )
    query = request["query"]
    if set(query) != {"q", "maxResults"}:
        _fail("Gmail request query must contain exactly q and maxResults")
    match = re.fullmatch(r"newer_than:([1-9][0-9]?)d", query["q"])
    if match is None:
        _fail("Gmail request q must be canonical newer_than:<days>d")
    maximum_age_days = int(match.group(1))
    _literal(
        maximum_age_days,
        policy["gmail"]["maximumAgeDays"],
        name="Gmail request maximum age",
    )
    _literal(query["maxResults"], "100", name="Gmail request maxResults")

    response = _parse_http_response(collected[response_path], name=response_path)
    _literal(response["status"], 200, name="Gmail response status")
    _require_header_names(
        response,
        {"content-type", "content-length"},
        name="Gmail response",
    )
    body = _closed_object(
        _json_http_body(response, name="Gmail response"),
        name="Gmail response body",
        fields={
            "schema",
            "captureTimeAuthenticated",
            "capturedAtEpochSeconds",
            "messages",
        },
    )
    _literal(
        body["schema"],
        "serverware.gatewayNormalizedGmailMessages/v1",
        name="Gmail response schema",
    )
    _literal(
        body["captureTimeAuthenticated"],
        False,
        name="Gmail response captureTimeAuthenticated",
    )
    captured_at = _require_capture_time(
        journey,
        body["capturedAtEpochSeconds"],
        name="Gmail response capturedAtEpochSeconds",
    )
    captured_at_milliseconds = captured_at * 1_000
    messages = body["messages"]
    if not isinstance(messages, list) or not 1 <= len(messages) <= 100:
        _fail("Gmail response messages must contain from 1 through 100 items")
    seen_ids: set[str] = set()
    oldest_milliseconds: int | None = None
    for index, raw_message in enumerate(messages):
        message = _closed_object(
            raw_message,
            name=f"Gmail response messages[{index}]",
            fields={"id", "internalDateEpochMillis"},
        )
        message_id = _text(
            message["id"],
            name=f"Gmail response messages[{index}].id",
        )
        if message_id in seen_ids:
            _fail("Gmail response contains duplicate message IDs")
        seen_ids.add(message_id)
        internal_date_milliseconds = _epoch_milliseconds(
            message["internalDateEpochMillis"],
            name=f"Gmail response messages[{index}].internalDateEpochMillis",
        )
        age_milliseconds = captured_at_milliseconds - internal_date_milliseconds
        if age_milliseconds < 0:
            _fail("Gmail response contains a future message timestamp")
        if age_milliseconds > maximum_age_days * 86_400 * 1_000:
            _fail("Gmail response contains a message older than the allowed window")
        if (
            oldest_milliseconds is None
            or internal_date_milliseconds < oldest_milliseconds
        ):
            oldest_milliseconds = internal_date_milliseconds
    assert oldest_milliseconds is not None
    return {
        "requestArtifact": _artifact_facts(source_by_path, request_path),
        "responseArtifact": _artifact_facts(source_by_path, response_path),
        "method": request["method"],
        "authority": request["authority"],
        "route": "gmail.messages.list",
        "query": query["q"],
        "maximumAgeDays": maximum_age_days,
        "responseFormat": body["schema"],
        "captureTimeAuthenticated": False,
        "capturedAtEpochSeconds": captured_at,
        "messageCount": len(messages),
        "oldestInternalDateEpochMillis": str(oldest_milliseconds),
    }


def _parse_x_post_request(
    raw: bytes,
    *,
    name: str,
    journey: dict[str, object],
) -> dict[str, object]:
    request = _parse_http_request(raw, name=name)
    _literal(request["method"], "POST", name=f"{name} method")
    _literal(request["authority"], "api.x.com", name=f"{name} authority")
    _literal(request["path"], "/2/tweets", name=f"{name} path")
    _literal(request["query"], {}, name=f"{name} query")
    _require_header_names(
        request,
        {
            "host",
            "x-serverware-principal",
            "x-serverware-credential-id",
            "content-type",
            "content-length",
        },
        name=name,
    )
    _require_request_identity(
        request,
        principal_id=journey["operators"]["requesterId"],
        credential_id=journey["oauthApprovals"]["x"]["credentialId"],
        name=name,
    )
    body = _closed_object(
        _json_http_body(request, name=name),
        name=f"{name} body",
        fields={"text"},
    )
    text = _text(body["text"], name=f"{name} body.text", maximum=280)
    return {"request": request, "text": text}


def _derive_x(
    journey: dict[str, object],
    policy: dict[str, object],
    source_by_path: dict[str, _Capture],
    collected: dict[str, bytes],
) -> dict[str, object]:
    x_paths = journey["x"]
    search_request_path = x_paths["searchRequestArtifactPath"]
    search_response_path = x_paths["searchResponseArtifactPath"]
    search_request = _parse_http_request(
        collected[search_request_path],
        name=search_request_path,
    )
    _literal(search_request["method"], "GET", name="X search method")
    _literal(search_request["authority"], "api.x.com", name="X search authority")
    _literal(
        search_request["path"],
        "/2/tweets/search/recent",
        name="X search path",
    )
    _literal(search_request["body"], b"", name="X search body")
    _require_header_names(
        search_request,
        {
            "host",
            "x-serverware-principal",
            "x-serverware-credential-id",
        },
        name="X search request",
    )
    _require_request_identity(
        search_request,
        principal_id=journey["operators"]["requesterId"],
        credential_id=journey["oauthApprovals"]["x"]["credentialId"],
        name="X search request",
    )
    search_query = search_request["query"]
    if set(search_query) != {"query", "start_time", "end_time", "tweet.fields"}:
        _fail(
            "X search query must contain exactly query, start_time, end_time, "
            "and tweet.fields"
        )
    _text(search_query["query"], name="X search query", maximum=512)
    _literal(
        search_query["tweet.fields"],
        "created_at",
        name="X search tweet.fields",
    )
    start = _parse_rfc3339_utc(search_query["start_time"], name="X search start_time")
    end = _parse_rfc3339_utc(search_query["end_time"], name="X search end_time")
    captured_at = _require_capture_time(
        journey,
        x_paths["capturedAtEpochSeconds"],
        name="journey.x.capturedAtEpochSeconds",
    )
    if int(end.timestamp()) > captured_at:
        _fail("X search end_time must not be later than its caller-supplied capture time")
    lookback_seconds = int((end - start).total_seconds())
    if not 0 < lookback_seconds <= policy["x"]["maximumSearchLookbackDays"] * 86_400:
        _fail("X search lookback exceeds the policy window")
    search_response = _parse_http_response(
        collected[search_response_path],
        name=search_response_path,
    )
    _literal(search_response["status"], 200, name="X search response status")
    _require_header_names(
        search_response,
        {"content-type", "content-length"},
        name="X search response",
    )
    search_body = _closed_object(
        _json_http_body(search_response, name="X search response"),
        name="X search response body",
        fields={"data", "meta"},
    )
    data = search_body["data"]
    if not isinstance(data, list) or not 1 <= len(data) <= 100:
        _fail("X search response data must contain from 1 through 100 items")
    seen_ids: set[str] = set()
    for index, raw_item in enumerate(data):
        item = _closed_object(
            raw_item,
            name=f"X search response data[{index}]",
            fields={"id", "created_at"},
        )
        item_id = _text(item["id"], name=f"X search response data[{index}].id")
        if item_id in seen_ids:
            _fail("X search response contains duplicate IDs")
        seen_ids.add(item_id)
        created_at = _parse_rfc3339_utc(
            item["created_at"],
            name=f"X search response data[{index}].created_at",
        )
        if not start <= created_at <= end:
            _fail("X search response item lies outside the requested lookback window")
    meta = _closed_object(
        search_body["meta"],
        name="X search response meta",
        fields={"result_count"},
    )
    _literal(meta["result_count"], len(data), name="X search result_count")

    first_request_path = x_paths["firstPostRequestArtifactPath"]
    first_response_path = x_paths["firstPostResponseArtifactPath"]
    second_request_path = x_paths["secondPostRequestArtifactPath"]
    second_response_path = x_paths["secondPostResponseArtifactPath"]
    first_post = _parse_x_post_request(
        collected[first_request_path],
        name=first_request_path,
        journey=journey,
    )
    second_post = _parse_x_post_request(
        collected[second_request_path],
        name=second_request_path,
        journey=journey,
    )
    first_response = _parse_http_response(
        collected[first_response_path],
        name=first_response_path,
    )
    _literal(first_response["status"], 201, name="first X post response status")
    _require_header_names(
        first_response,
        {"content-type", "content-length"},
        name="first X post response",
    )
    first_body = _closed_object(
        _json_http_body(first_response, name="first X post response"),
        name="first X post response body",
        fields={"data"},
    )
    first_data = _closed_object(
        first_body["data"],
        name="first X post response data",
        fields={"id"},
    )
    _text(first_data["id"], name="first X post response data.id")
    second_response = _parse_http_response(
        collected[second_response_path],
        name=second_response_path,
    )
    _literal(second_response["status"], 429, name="second X post response status")
    _require_header_names(
        second_response,
        {"content-type", "content-length"},
        name="second X post response",
    )
    second_body = _closed_object(
        _json_http_body(second_response, name="second X post response"),
        name="second X post response body",
        fields={"error", "limit", "used", "utcDay"},
    )
    _literal(
        second_body["error"],
        "daily_post_limit",
        name="second X post response error",
    )
    _literal(
        second_body["limit"],
        policy["x"]["maximumPostsPerUtcDay"],
        name="second X post response limit",
    )
    _literal(second_body["used"], 1, name="second X post response used")
    utc_day = _text(second_body["utcDay"], name="second X post response utcDay")
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", utc_day) is None:
        _fail("second X post response utcDay must be canonical")

    counter_path = x_paths["postCounterArtifactPath"]
    if (
        _artifact_facts(source_by_path, first_request_path)["sha256"]
        == _artifact_facts(source_by_path, second_request_path)["sha256"]
    ):
        _fail("X post attempts must be distinct exact request bytes")
    counter = _closed_object(
        _decode_json(collected[counter_path], name=counter_path),
        name="X post counter artifact",
        fields={"utcDay", "limit", "events"},
    )
    _literal(counter["utcDay"], utc_day, name="X post counter utcDay")
    _literal(
        counter["limit"],
        policy["x"]["maximumPostsPerUtcDay"],
        name="X post counter limit",
    )
    events = counter["events"]
    if not isinstance(events, list) or len(events) != 2:
        _fail("X post counter events must contain exactly two events")
    expected = [
        (
            "accepted",
            _artifact_facts(source_by_path, first_request_path)["sha256"],
            _artifact_facts(source_by_path, first_response_path)["sha256"],
        ),
        (
            "denied",
            _artifact_facts(source_by_path, second_request_path)["sha256"],
            _artifact_facts(source_by_path, second_response_path)["sha256"],
        ),
    ]
    event_times: list[datetime] = []
    for index, (raw_event, expected_event) in enumerate(zip(events, expected, strict=True)):
        event = _closed_object(
            raw_event,
            name=f"X post counter events[{index}]",
            fields={"at", "decision", "requestSha256", "responseSha256"},
        )
        decision, request_sha256, response_sha256 = expected_event
        _literal(
            event["decision"],
            decision,
            name=f"X post counter events[{index}].decision",
        )
        _literal(
            event["requestSha256"],
            request_sha256,
            name=f"X post counter events[{index}].requestSha256",
        )
        _literal(
            event["responseSha256"],
            response_sha256,
            name=f"X post counter events[{index}].responseSha256",
        )
        event_time = _parse_rfc3339_utc(
            event["at"],
            name=f"X post counter events[{index}].at",
        )
        if event_time.strftime("%Y-%m-%d") != utc_day:
            _fail("X post counter events must occur within the declared UTC day")
        event_epoch_seconds = int(event_time.timestamp())
        started_at, ended_at = _capture_interval(journey)
        if not started_at <= event_epoch_seconds <= ended_at:
            _fail("X post counter event must lie within journey.captureInterval")
        if event_epoch_seconds > captured_at:
            _fail("X post counter event must not be later than the X capture time")
        event_times.append(event_time)
    if event_times[1] <= event_times[0]:
        _fail("X post counter events must be strictly chronological")
    return {
        "search": {
            "requestArtifact": _artifact_facts(source_by_path, search_request_path),
            "responseArtifact": _artifact_facts(source_by_path, search_response_path),
            "method": search_request["method"],
            "authority": search_request["authority"],
            "route": "x.search.recent",
            "startTime": search_query["start_time"],
            "endTime": search_query["end_time"],
            "tweetFields": search_query["tweet.fields"],
            "capturedAtEpochSeconds": captured_at,
            "captureTimeAuthenticated": False,
            "lookbackSeconds": lookback_seconds,
            "resultCount": len(data),
        },
        "posting": {
            "firstRequestArtifact": _artifact_facts(source_by_path, first_request_path),
            "firstResponseArtifact": _artifact_facts(source_by_path, first_response_path),
            "secondRequestArtifact": _artifact_facts(source_by_path, second_request_path),
            "secondResponseArtifact": _artifact_facts(source_by_path, second_response_path),
            "counterArtifact": _artifact_facts(source_by_path, counter_path),
            "route": "x.posts.create",
            "firstTextSha256": "sha256:"
            + hashlib.sha256(first_post["text"].encode("utf-8")).hexdigest(),
            "secondTextSha256": "sha256:"
            + hashlib.sha256(second_post["text"].encode("utf-8")).hexdigest(),
            "utcDay": utc_day,
            "acceptedCount": 1,
            "deniedCount": 1,
            "limit": policy["x"]["maximumPostsPerUtcDay"],
        },
    }


def _derive_npm_publish(
    request: dict[str, object],
    *,
    journey: dict[str, object],
    name: str,
) -> dict[str, str]:
    _literal(request["method"], "PUT", name=f"{name} method")
    _literal(request["authority"], "registry.npmjs.org", name=f"{name} authority")
    _literal(request["query"], {}, name=f"{name} query")
    _require_request_identity(
        request,
        principal_id=journey["operators"]["requesterId"],
        credential_id="credential:npm",
        name=name,
    )
    _require_header_names(
        request,
        {
            "host",
            "x-serverware-principal",
            "x-serverware-credential-id",
            "content-type",
            "content-length",
        },
        name=name,
    )
    body = _closed_object(
        _json_http_body(request, name=name),
        name=f"{name} body",
        fields={"name", "version"},
    )
    package = _text(body["name"], name=f"{name} package", maximum=214)
    version = _text(body["version"], name=f"{name} version", maximum=64)
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,213}", package) is None:
        _fail(f"{name} package name is not supported by the closed npm grammar")
    if re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)",
        version,
    ) is None:
        _fail(f"{name} version must be canonical major.minor.patch")
    if request["path"] != f"/{package}":
        _fail(f"{name} path must exactly identify the published package")
    return {
        "principalId": journey["operators"]["requesterId"],
        "credentialId": "credential:npm",
        "method": request["method"],
        "authority": request["authority"],
        "path": request["path"],
        "route": "npm.publish",
        "operation": f"npm.publish {package}@{version}",
    }


def _approval_challenge(
    journey: dict[str, object],
    npm: dict[str, str],
    *,
    request_sha256: str,
) -> tuple[bytes, str]:
    jit = journey["jitApproval"]
    binding = {
        "approvalRequestId": jit["approvalRequestId"],
        "approvedBy": jit["approvedBy"],
        "principalId": npm["principalId"],
        "credentialId": npm["credentialId"],
        "routeId": npm["route"],
        "operation": npm["operation"],
        "requestSha256": request_sha256,
        "expiresAtEpochSeconds": jit["expiresAtEpochSeconds"],
        "webauthnCredentialId": jit["webauthn"]["credentialId"],
    }
    encoded = json.dumps(
        binding,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    challenge = hashlib.sha256(encoded).digest()
    return challenge, f"sha256:{challenge.hex()}"


def _base64url_without_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_base64url(value: object, *, name: str) -> bytes:
    encoded = _text(value, name=name, maximum=1024)
    if "=" in encoded or re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None:
        _fail(f"{name} must be canonical unpadded base64url")
    try:
        decoded = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        _fail(f"{name} is invalid base64url: {exc}")
    if _base64url_without_padding(decoded) != encoded:
        _fail(f"{name} is not canonical base64url")
    return decoded


def _verify_webauthn(
    journey: dict[str, object],
    source_by_path: dict[str, _Capture],
    collected: dict[str, bytes],
    *,
    challenge: bytes,
    challenge_sha256: str,
) -> dict[str, object]:
    config = journey["jitApproval"]["webauthn"]
    client_path = config["clientDataJSONArtifactPath"]
    auth_path = config["authenticatorDataArtifactPath"]
    signature_path = config["signatureArtifactPath"]
    public_key_path = config["publicKeyArtifactPath"]
    for path in (client_path, auth_path, signature_path, public_key_path):
        if len(collected[path]) > MAX_WEBAUTHN_COMPONENT_BYTES:
            _fail(f"{path} exceeds the WebAuthn component byte limit")
    client_data = _closed_object(
        _decode_json(collected[client_path], name=client_path),
        name="WebAuthn clientDataJSON",
        fields={"type", "challenge", "origin", "crossOrigin"},
    )
    _literal(client_data["type"], "webauthn.get", name="WebAuthn clientDataJSON.type")
    _literal(
        client_data["origin"],
        config["expectedOrigin"],
        name="WebAuthn clientDataJSON.origin",
    )
    _literal(
        client_data["crossOrigin"],
        False,
        name="WebAuthn clientDataJSON.crossOrigin",
    )
    client_challenge = _decode_base64url(
        client_data["challenge"],
        name="WebAuthn clientDataJSON.challenge",
    )
    if client_challenge != challenge:
        _fail("WebAuthn clientDataJSON challenge does not match the JIT binding")

    authenticator_data = collected[auth_path]
    if len(authenticator_data) != 37:
        _fail("WebAuthn authenticatorData must be exactly 37 bytes")
    expected_rp_hash = hashlib.sha256(
        config["expectedRpId"].encode("utf-8")
    ).digest()
    if authenticator_data[:32] != expected_rp_hash:
        _fail("WebAuthn authenticatorData RP ID hash mismatch")
    flags = authenticator_data[32]
    if flags != 0x05:
        _fail("WebAuthn authenticatorData must set exactly UP and UV flags")
    signature_counter = struct.unpack(">I", authenticator_data[33:37])[0]
    _literal(
        signature_counter,
        config["expectedSignatureCounter"],
        name="WebAuthn signature counter",
    )

    public_key_bytes = collected[public_key_path]
    try:
        public_key = serialization.load_pem_public_key(public_key_bytes)
    except (TypeError, ValueError) as exc:
        _fail(f"WebAuthn public key artifact is not valid PEM: {exc}")
    if (
        not isinstance(public_key, ec.EllipticCurvePublicKey)
        or not isinstance(public_key.curve, ec.SECP256R1)
    ):
        _fail("WebAuthn public key must be an ES256 P-256 key")
    canonical_public_key = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if canonical_public_key != public_key_bytes:
        _fail("WebAuthn public key PEM must be canonical SubjectPublicKeyInfo")
    signed_data = authenticator_data + hashlib.sha256(collected[client_path]).digest()
    signature = collected[signature_path]
    if not 8 <= len(signature) <= 80:
        _fail("WebAuthn ES256 signature has an invalid DER length")
    try:
        public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        _fail("WebAuthn signature verification failed")
    except ValueError as exc:
        _fail(f"WebAuthn signature is malformed: {exc}")
    return {
        "credentialId": config["credentialId"],
        "clientDataJSONArtifact": _artifact_facts(source_by_path, client_path),
        "authenticatorDataArtifact": _artifact_facts(source_by_path, auth_path),
        "signatureArtifact": _artifact_facts(source_by_path, signature_path),
        "publicKeyArtifact": _artifact_facts(source_by_path, public_key_path),
        "type": client_data["type"],
        "challenge": _base64url_without_padding(challenge),
        "challengeSha256": challenge_sha256,
        "origin": client_data["origin"],
        "rpId": config["expectedRpId"],
        "rpIdHash": f"sha256:{expected_rp_hash.hex()}",
        "userPresent": True,
        "userVerified": True,
        "signatureCounter": signature_counter,
        "signatureAlgorithm": "ES256",
        "signatureVerified": True,
        "trustAnchor": "evidence-supplied-public-key",
        "selfAnchored": True,
        "registeredAuthenticatorOwnershipEstablished": False,
    }


def _derive_jit(
    journey: dict[str, object],
    source_by_path: dict[str, _Capture],
    collected: dict[str, bytes],
) -> dict[str, object]:
    jit = journey["jitApproval"]
    challenge_path = jit["challengeRequestArtifactPath"]
    retry_path = jit["retryRequestArtifactPath"]
    challenge_request = _parse_http_request(
        collected[challenge_path],
        name=challenge_path,
    )
    retry_request = _parse_http_request(collected[retry_path], name=retry_path)
    challenge_npm = _derive_npm_publish(
        challenge_request,
        journey=journey,
        name="challenged npm request",
    )
    retry_npm = _derive_npm_publish(
        retry_request,
        journey=journey,
        name="retried npm request",
    )
    challenge_facts = _artifact_facts(source_by_path, challenge_path)
    retry_facts = _artifact_facts(source_by_path, retry_path)
    if challenge_facts["sha256"] != retry_facts["sha256"]:
        _fail("JIT retry raw HTTP request bytes must match the challenged request")
    if challenge_npm != retry_npm:
        _fail("JIT retry npm operation must match the challenged operation")

    challenge_response_path = jit["challengeResponseArtifactPath"]
    challenge_response = _parse_http_response(
        collected[challenge_response_path],
        name=challenge_response_path,
    )
    _literal(challenge_response["status"], 428, name="JIT challenge response status")
    _require_header_names(
        challenge_response,
        {"content-type", "content-length"},
        name="JIT challenge response",
    )
    challenge_body = _closed_object(
        _json_http_body(challenge_response, name="JIT challenge response"),
        name="JIT challenge response body",
        fields={"error", "approvalRequestId", "upstreamCalls"},
    )
    _literal(
        challenge_body["error"],
        "approval_required",
        name="JIT challenge response error",
    )
    _literal(
        challenge_body["approvalRequestId"],
        jit["approvalRequestId"],
        name="JIT challenge response approvalRequestId",
    )
    _literal(
        challenge_body["upstreamCalls"],
        0,
        name="JIT challenge response upstreamCalls",
    )
    retry_response_path = jit["retryResponseArtifactPath"]
    retry_response = _parse_http_response(
        collected[retry_response_path],
        name=retry_response_path,
    )
    if not 200 <= retry_response["status"] <= 299:
        _fail("JIT retry response must be successful")
    _require_header_names(
        retry_response,
        {"content-type", "content-length"},
        name="JIT retry response",
    )
    retry_body = _closed_object(
        _json_http_body(retry_response, name="JIT retry response"),
        name="JIT retry response body",
        fields={"ok", "approvalRequestId", "upstreamCalls"},
    )
    _literal(retry_body["ok"], True, name="JIT retry response ok")
    _literal(
        retry_body["approvalRequestId"],
        jit["approvalRequestId"],
        name="JIT retry response approvalRequestId",
    )
    _literal(
        retry_body["upstreamCalls"],
        1,
        name="JIT retry response upstreamCalls",
    )
    challenge, challenge_sha256 = _approval_challenge(
        journey,
        challenge_npm,
        request_sha256=challenge_facts["sha256"],
    )
    webauthn = _verify_webauthn(
        journey,
        source_by_path,
        collected,
        challenge=challenge,
        challenge_sha256=challenge_sha256,
    )
    return {
        "approvalRequestId": jit["approvalRequestId"],
        "approvedBy": jit["approvedBy"],
        **challenge_npm,
        "operationSha256": "sha256:"
        + hashlib.sha256(challenge_npm["operation"].encode("utf-8")).hexdigest(),
        "challengeRequestArtifact": challenge_facts,
        "retryRequestArtifact": retry_facts,
        "challengeResponseArtifact": _artifact_facts(
            source_by_path,
            challenge_response_path,
        ),
        "retryResponseArtifact": _artifact_facts(
            source_by_path,
            retry_response_path,
        ),
        "challengeStatus": challenge_response["status"],
        "retryStatus": retry_response["status"],
        "challengeIssuedAtEpochSeconds": jit["challengeIssuedAtEpochSeconds"],
        "approvedAtEpochSeconds": jit["approvedAtEpochSeconds"],
        "expiresAtEpochSeconds": jit["expiresAtEpochSeconds"],
        "retryAtEpochSeconds": jit["retryAtEpochSeconds"],
        "upstreamCallsBeforeApproval": challenge_body["upstreamCalls"],
        "upstreamCallsAfterRetry": retry_body["upstreamCalls"],
        "webauthn": webauthn,
    }


def _derive_workflow(
    journey: dict[str, object],
    source_captures: list[_Capture],
    collected: dict[str, bytes],
) -> dict[str, object]:
    source_by_path = {capture.path: capture for capture in source_captures}
    references = _reference_paths(journey)
    missing = sorted(references - set(source_by_path))
    if missing:
        _fail(f"journey references undeclared source artifacts: {', '.join(missing)}")

    policy_path = journey["policy"]["artifactPath"]
    policy = _validate_policy(
        _decode_json(collected[policy_path], name=policy_path)
    )
    policy_capture = source_by_path[policy_path]
    packet_capture = source_by_path[journey["packet"]["artifactPath"]]
    return {
        "captureInterval": journey["captureInterval"],
        "operators": journey["operators"],
        "oauthApprovals": journey["oauthApprovals"],
        "oauthActivationChallenges": journey["oauthActivationChallenges"],
        "policyArtifact": policy_capture.facts,
        "packetArtifact": packet_capture.facts,
        "gmail": _derive_gmail(journey, policy, source_by_path, collected),
        "x": _derive_x(journey, policy, source_by_path, collected),
        "jitApproval": _derive_jit(journey, source_by_path, collected),
        "unknownRoute": journey["unknownRoute"],
    }


def _assert_unique_captures(captures: list[_Capture]) -> None:
    identities: dict[tuple[int, int], str] = {}
    for capture in captures:
        identity = (capture.identity[0], capture.identity[1])
        if identity in identities:
            _fail(
                f"{capture.path}: inode aliases already captured path "
                f"{identities[identity]}"
            )
        identities[identity] = capture.path


def _revalidate_captures(root_fd: int, captures: list[_Capture]) -> None:
    for capture in captures:
        if capture.kind == "png":
            fresh = _capture_png(root_fd, capture.path)
        else:
            fresh, _ = _capture_regular(
                root_fd,
                capture.path,
                limit=capture.limit,
            )
        if fresh.identity != capture.identity or fresh.facts != capture.facts:
            _fail(f"{capture.path}: input changed before finalization")


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
    )


def _validate_output_directory(
    value: os.stat_result,
    *,
    relative: str,
    label: str,
    final_parent: bool,
) -> None:
    if not stat.S_ISDIR(value.st_mode):
        _fail(f"{relative}: output directory {label} is not a directory")
    mode = stat.S_IMODE(value.st_mode)
    if value.st_uid != os.geteuid():
        _fail(
            f"{relative}: output directory {label} must be owned by the effective user"
        )
    if not mode & stat.S_IXUSR:
        _fail(f"{relative}: output directory {label} must be owner-searchable")
    if mode & 0o022:
        _fail(
            f"{relative}: output directory {label} must not be writable by "
            "group or world"
        )
    if final_parent and (mode & 0o077 or (mode & 0o300) != 0o300):
        _fail(
            f"{relative}: output parent must be private, owner-writable, "
            "and inaccessible to group/world"
        )


def _pin_output_publication(root_fd: int, relative: str) -> _OutputPublication:
    parts = PurePosixPath(relative).parts
    directory_parts = parts[:-1]
    directory_fds = [os.dup(root_fd)]
    identities: list[tuple[int, ...]] = []
    try:
        for index, component in enumerate(directory_parts):
            current = os.fstat(directory_fds[-1])
            label = "." if index == 0 else "/".join(directory_parts[:index])
            _validate_output_directory(
                current,
                relative=relative,
                label=label,
                final_parent=False,
            )
            identities.append(_directory_identity(current))
            directory_fds.append(
                os.open(component, _directory_flags(), dir_fd=directory_fds[-1])
            )
        parent = os.fstat(directory_fds[-1])
        label = "." if not directory_parts else "/".join(directory_parts)
        _validate_output_directory(
            parent,
            relative=relative,
            label=label,
            final_parent=True,
        )
        identities.append(_directory_identity(parent))
        publication = _OutputPublication(
            relative=relative,
            leaf=parts[-1],
            directory_parts=directory_parts,
            directory_fds=directory_fds,
            directory_identities=identities,
        )
        _revalidate_output_chain(publication)
        return publication
    except EvidenceError:
        for descriptor in reversed(directory_fds):
            os.close(descriptor)
        raise
    except OSError as exc:
        for descriptor in reversed(directory_fds):
            os.close(descriptor)
        _fail(
            f"{relative}: cannot pin private output directory chain without "
            f"following links: {exc}"
        )


def _revalidate_output_chain(publication: _OutputPublication) -> None:
    for index, descriptor in enumerate(publication.directory_fds):
        current = os.fstat(descriptor)
        label = (
            "."
            if index == 0
            else "/".join(publication.directory_parts[:index])
        )
        _validate_output_directory(
            current,
            relative=publication.relative,
            label=label,
            final_parent=index == len(publication.directory_fds) - 1,
        )
        if _directory_identity(current) != publication.directory_identities[index]:
            _fail(
                f"{publication.relative}: output directory chain changed at {label}"
            )
        if index == 0:
            continue
        child = os.stat(
            publication.directory_parts[index - 1],
            dir_fd=publication.directory_fds[index - 1],
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(child.st_mode)
            or child.st_dev != current.st_dev
            or child.st_ino != current.st_ino
        ):
            _fail(
                f"{publication.relative}: output directory chain was substituted "
                f"at {label}"
            )


def _pending_prefix(leaf: str) -> str:
    leaf_digest = hashlib.sha256(leaf.encode("utf-8")).hexdigest()[:20]
    return f".serverware-onboarding-{leaf_digest}-"


def _pending_entries(publication: _OutputPublication) -> list[str]:
    prefix = _pending_prefix(publication.leaf)
    try:
        return sorted(
            entry
            for entry in os.listdir(publication.parent_fd)
            if entry.startswith(prefix) and entry.endswith(".pending")
        )
    except OSError as exc:
        _fail(
            f"{publication.relative}: cannot inspect output publication state: {exc}"
        )


def _entry_identity(
    publication: _OutputPublication,
    leaf: str,
) -> tuple[int, int] | None:
    try:
        value = os.stat(
            leaf,
            dir_fd=publication.parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        _fail(
            f"{publication.relative}: cannot inspect publication entry {leaf}: {exc}"
        )
    return (value.st_dev, value.st_ino)


def _assert_new_output_state(publication: _OutputPublication) -> None:
    _assert_no_pending_output_state(publication)
    if _entry_identity(publication, publication.leaf) is not None:
        _fail(
            f"{publication.relative}: output already exists; refusing replacement"
        )


def _assert_no_pending_output_state(publication: _OutputPublication) -> None:
    residue = _pending_entries(publication)
    if residue:
        _fail(
            f"{publication.relative}: incomplete fail-closed publication state "
            f"exists: {', '.join(residue)}"
        )


def _close_output_publication(publication: _OutputPublication) -> list[str]:
    errors: list[str] = []
    if publication.pending_fd is not None:
        try:
            os.close(publication.pending_fd)
        except OSError as exc:
            errors.append(f"pending descriptor close failed: {exc}")
        publication.pending_fd = None
    for descriptor in reversed(publication.directory_fds):
        try:
            os.close(descriptor)
        except OSError as exc:
            errors.append(f"output directory descriptor close failed: {exc}")
    publication.directory_fds.clear()
    return errors


def _unlink_owned_publication_entry(
    publication: _OutputPublication,
    leaf: str,
) -> str | None:
    try:
        current = _entry_identity(publication, leaf)
    except EvidenceError as exc:
        return f"cannot inspect {leaf} before cleanup: {exc}"
    if current is None:
        return None
    if current != publication.inode_identity:
        return f"{leaf} changed identity; refusing unlink"
    try:
        os.unlink(leaf, dir_fd=publication.parent_fd)
    except OSError as exc:
        return f"unlink {leaf} failed: {exc}"
    return None


def _cleanup_output_publication(publication: _OutputPublication) -> list[str]:
    errors: list[str] = []
    if publication.final_linked:
        error = _unlink_owned_publication_entry(publication, publication.leaf)
        if error:
            errors.append(error)
        else:
            publication.final_linked = False
    if publication.pending_exists and publication.pending_leaf is not None:
        error = _unlink_owned_publication_entry(
            publication,
            publication.pending_leaf,
        )
        if error:
            errors.append(error)
        else:
            publication.pending_exists = False
    try:
        os.fsync(publication.parent_fd)
    except OSError as exc:
        errors.append(f"parent fsync failed: {exc}")
    return errors


def _stage_output_file(publication: _OutputPublication, data: bytes) -> None:
    _revalidate_output_chain(publication)
    _assert_new_output_state(publication)
    publication.pending_leaf = (
        _pending_prefix(publication.leaf) + os.urandom(16).hex() + ".pending"
    )
    try:
        publication.pending_fd = os.open(
            publication.pending_leaf,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=publication.parent_fd,
        )
        publication.pending_exists = True
        opened = os.fstat(publication.pending_fd)
        publication.inode_identity = (opened.st_dev, opened.st_ino)
        os.fchmod(publication.pending_fd, 0o600)
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(publication.pending_fd, view[written:])
            if count <= 0:
                raise OSError("short output write")
            written += count
        os.fsync(publication.pending_fd)
        output_stat = os.fstat(publication.pending_fd)
        if (
            (output_stat.st_dev, output_stat.st_ino) != publication.inode_identity
            or not stat.S_ISREG(output_stat.st_mode)
            or output_stat.st_nlink != 1
            or output_stat.st_uid != os.geteuid()
            or stat.S_IMODE(output_stat.st_mode) != 0o600
            or output_stat.st_size != len(data)
        ):
            _fail(
                f"{publication.relative}: staged output properties changed "
                "during creation"
            )
        os.fsync(publication.parent_fd)
    except EvidenceError:
        raise
    except OSError as exc:
        _fail(f"{publication.relative}: cannot stage durable private output: {exc}")


def _publish_output_file(publication: _OutputPublication, data_size: int) -> None:
    assert publication.pending_leaf is not None
    assert publication.pending_fd is not None
    assert publication.inode_identity is not None
    _revalidate_output_chain(publication)
    if _entry_identity(publication, publication.leaf) is not None:
        _fail(
            f"{publication.relative}: output already exists; refusing replacement"
        )
    try:
        os.link(
            publication.pending_leaf,
            publication.leaf,
            src_dir_fd=publication.parent_fd,
            dst_dir_fd=publication.parent_fd,
            follow_symlinks=False,
        )
        publication.final_linked = True
    except FileExistsError:
        _fail(
            f"{publication.relative}: output already exists; refusing replacement"
        )
    except OSError as exc:
        _fail(
            f"{publication.relative}: cannot atomically publish staged output: {exc}"
        )
    os.fsync(publication.parent_fd)
    output_stat = os.fstat(publication.pending_fd)
    if (
        (output_stat.st_dev, output_stat.st_ino) != publication.inode_identity
        or output_stat.st_nlink != 2
        or output_stat.st_size != data_size
        or _entry_identity(publication, publication.leaf)
        != publication.inode_identity
    ):
        _fail(
            f"{publication.relative}: published output alias state is invalid"
        )
    os.unlink(publication.pending_leaf, dir_fd=publication.parent_fd)
    publication.pending_exists = False
    output_stat = os.fstat(publication.pending_fd)
    if (
        output_stat.st_nlink != 1
        or output_stat.st_size != data_size
        or _entry_identity(publication, publication.leaf)
        != publication.inode_identity
    ):
        _fail(
            f"{publication.relative}: final output has aliases or changed "
            "after publication"
        )
    os.fsync(publication.parent_fd)
    _revalidate_output_chain(publication)


def _assert_private_existing_manifest(
    root_fd: int,
    relative: str,
    capture: _Capture,
) -> None:
    publication = _pin_output_publication(root_fd, relative)
    try:
        _revalidate_output_chain(publication)
        _assert_no_pending_output_state(publication)
        if (
            capture.identity[4] != os.geteuid()
            or stat.S_IMODE(capture.identity[2]) != 0o600
        ):
            _fail(f"{relative}: manifest must remain owner-owned mode 0600")
    finally:
        close_errors = _close_output_publication(publication)
    if close_errors:
        _fail(f"{relative}: {'; '.join(close_errors)}")


def verify_manifest(root: Path, manifest_path: str) -> dict[str, object]:
    root_fd = _open_root_fd(root)
    try:
        manifest_path = _canonical_relative_path(manifest_path, name="manifest path")
        manifest_capture, raw_manifest = _capture_regular(
            root_fd,
            manifest_path,
            limit=MAX_JSON_BYTES,
            collect=True,
        )
        _assert_private_existing_manifest(root_fd, manifest_path, manifest_capture)
        assert raw_manifest is not None
        manifest = _validate_manifest_shape(
            _decode_json(raw_manifest, name=manifest_path)
        )
        _validate_path_sets(manifest, manifest_path)

        journey_path = manifest["journeyArtifact"]["path"]
        journey_capture, raw_journey = _capture_regular(
            root_fd,
            journey_path,
            limit=MAX_JSON_BYTES,
            collect=True,
        )
        assert raw_journey is not None
        _facts_match(
            manifest["journeyArtifact"],
            journey_capture.facts,
            name="journey artifact",
        )
        journey = _validate_journey(_decode_json(raw_journey, name=journey_path))
        references = _reference_paths(journey)
        source_entries = manifest["sourceInputs"]
        source_paths = [entry["path"] for entry in source_entries]
        source_captures, collected = _capture_source_inputs(
            root_fd,
            source_paths,
            collect_paths=references,
            path_limits=_reference_limits(journey),
        )
        if not references <= set(source_paths):
            _fail("journey bound artifacts must all be declared sourceInputs")
        for expected, actual in zip(source_entries, source_captures, strict=True):
            _facts_match(expected, actual.facts, name="source input")

        screenshot_entries = manifest["screenshots"]
        screenshot_captures = _capture_screenshots(
            root_fd,
            [entry["path"] for entry in screenshot_entries],
        )
        for expected, actual in zip(
            screenshot_entries,
            screenshot_captures,
            strict=True,
        ):
            _facts_match(expected, actual.facts, name="screenshot")

        derived_workflow = _derive_workflow(journey, source_captures, collected)
        if manifest["workflow"] != derived_workflow:
            _fail("manifest workflow does not match exact bound journey/artifact bytes")
        captures = [
            manifest_capture,
            journey_capture,
            *source_captures,
            *screenshot_captures,
        ]
        _assert_unique_captures(captures)
        _revalidate_captures(root_fd, captures)
        return manifest
    finally:
        os.close(root_fd)


def create_manifest(
    *,
    root: Path,
    output_path: str,
    journey_path: str,
    source_paths: list[str],
    screenshot_paths: list[str],
    playwright_version: str,
    chromium_version: str,
) -> dict[str, object]:
    root_fd = _open_root_fd(root)
    try:
        output_path = _canonical_relative_path(output_path, name="output path")
        journey_path = _canonical_relative_path(journey_path, name="journey path")
        source_paths = [
            _canonical_relative_path(path, name="source path") for path in source_paths
        ]
        screenshot_paths = [
            _canonical_relative_path(path, name="screenshot path")
            for path in screenshot_paths
        ]
        if not 1 <= len(source_paths) <= MAX_SOURCE_INPUTS:
            _fail(f"create requires from 1 through {MAX_SOURCE_INPUTS} --source paths")
        if not 1 <= len(screenshot_paths) <= MAX_SCREENSHOTS:
            _fail(
                f"create requires from 1 through {MAX_SCREENSHOTS} "
                "--screenshot paths"
            )
        if len(set(source_paths)) != len(source_paths):
            _fail("create source paths must be unique")
        if len(set(screenshot_paths)) != len(screenshot_paths):
            _fail("create screenshot paths must be unique")
        path_groups = [
            {output_path},
            {journey_path},
            set(source_paths),
            set(screenshot_paths),
        ]
        for left in range(len(path_groups)):
            for right in range(left + 1, len(path_groups)):
                if path_groups[left] & path_groups[right]:
                    _fail("output, journey, source, and screenshot paths must be distinct")

        journey_capture, raw_journey = _capture_regular(
            root_fd,
            journey_path,
            limit=MAX_JSON_BYTES,
            collect=True,
        )
        assert raw_journey is not None
        journey = _validate_journey(_decode_json(raw_journey, name=journey_path))
        references = _reference_paths(journey)
        if not references <= set(source_paths):
            _fail("journey bound artifacts must all be declared --source paths")
        source_captures, collected = _capture_source_inputs(
            root_fd,
            source_paths,
            collect_paths=references,
            path_limits=_reference_limits(journey),
        )
        screenshot_captures = _capture_screenshots(root_fd, screenshot_paths)
        workflow = _derive_workflow(journey, source_captures, collected)
        runtime = {
            "python": platform.python_version(),
            "playwright": _text(
                playwright_version,
                name="playwright version",
                maximum=128,
            ),
            "chromium": _text(
                chromium_version,
                name="chromium version",
                maximum=128,
            ),
        }
        manifest = {
            "apiVersion": API_VERSION,
            "assurance": dict(ASSURANCE),
            "captureRuntime": runtime,
            "journeyArtifact": journey_capture.facts,
            "workflow": workflow,
            "sourceInputs": [capture.facts for capture in source_captures],
            "screenshots": [capture.facts for capture in screenshot_captures],
        }
        _validate_manifest_shape(manifest)
        _validate_path_sets(manifest, output_path)
        encoded = (
            json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        captures = [journey_capture, *source_captures, *screenshot_captures]
        _assert_unique_captures(captures)
        _revalidate_captures(root_fd, captures)
        publication = _pin_output_publication(root_fd, output_path)
        try:
            _stage_output_file(publication, encoded)
            _revalidate_captures(root_fd, captures)
            _revalidate_output_chain(publication)
            _publish_output_file(publication, len(encoded))
            _revalidate_captures(root_fd, captures)
            _revalidate_output_chain(publication)
        except Exception as exc:
            cleanup_errors = _cleanup_output_publication(publication)
            failure = (
                str(exc)
                if isinstance(exc, EvidenceError)
                else f"{output_path}: output publication failed: {exc}"
            )
            if cleanup_errors:
                failure += (
                    f"; cleanup failed: {'; '.join(cleanup_errors)}; "
                    "fail-closed publication residue may remain"
                )
            raise EvidenceError(failure) from exc
        finally:
            close_errors = _close_output_publication(publication)
        if close_errors:
            _fail(f"{output_path}: {'; '.join(close_errors)}")
        return manifest
    finally:
        os.close(root_fd)


def _parser() -> argparse.ArgumentParser:
    assurance = (
        "This tool produces unsigned local-integrity-only evidence. It does not "
        "provide execution, server, provenance, or TEE attestation."
    )
    parser = argparse.ArgumentParser(
        description=(
            f"Create or verify a closed {API_VERSION} manifest. {assurance} "
            "All artifact paths are canonical POSIX paths relative to --root."
        )
    )
    parser.add_argument("--root", default=".", help="pinned evidence filesystem root")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    create = subparsers.add_parser(
        "create",
        help="create an unsigned local-integrity-only manifest",
        description=assurance,
    )
    create.add_argument("--journey", required=True, help="bound journey JSON path")
    create.add_argument("--source", action="append", required=True, help="source input")
    create.add_argument("--screenshot", action="append", required=True, help="strict PNG")
    create.add_argument("--playwright-version", required=True)
    create.add_argument("--chromium-version", required=True)
    create.add_argument(
        "--output",
        required=True,
        help="new private 0600 manifest path; existing output is refused",
    )
    verify = subparsers.add_parser(
        "verify",
        help="verify unsigned local artifact integrity only",
        description=assurance,
    )
    verify.add_argument("--manifest", required=True, help="manifest path")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.mode == "create":
            manifest = create_manifest(
                root=Path(arguments.root),
                output_path=arguments.output,
                journey_path=arguments.journey,
                source_paths=arguments.source,
                screenshot_paths=arguments.screenshot,
                playwright_version=arguments.playwright_version,
                chromium_version=arguments.chromium_version,
            )
            action = f"created {arguments.output}"
        else:
            manifest = verify_manifest(Path(arguments.root), arguments.manifest)
            action = f"verified {arguments.manifest}"
        print(
            f"{action}: {len(manifest['sourceInputs'])} source inputs, "
            f"{len(manifest['screenshots'])} screenshots; "
            "local-integrity-only, unsigned, not execution/server/TEE attestation"
        )
        return 0
    except EvidenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
