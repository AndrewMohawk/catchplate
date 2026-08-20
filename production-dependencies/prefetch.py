#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEPENDENCY_DIR = ROOT / "production-dependencies"
CACHE_DIR = DEPENDENCY_DIR / "cache"
PLATFORM = "linux/amd64"
MANIFEST_API_VERSION = "serverware.offlineDependencyManifest/v2"
SNAPSHOT_URL_ENV = "SERVERWARE_PRODUCTION_DEPENDENCY_SNAPSHOT_URL"
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 250_000
MAX_ARCHIVE_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
MAX_ARCHIVE_EXPANSION_RATIO = 200
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ARCHIVE_PATH_RE = re.compile(r"\A[A-Za-z0-9._@+/-]+\Z")

PYTHON_ARCHIVE = "cache/python-wheelhouse-linux-amd64.tar.gz"
CARGO_ARCHIVE = "cache/cargo-vendor.tar.gz"
MUSL_APK = "cache/musl-1.2.5-r12.apk"
MUSL_DEV_APK = "cache/musl-dev-1.2.5-r12.apk"

PYTHON_MANIFEST = DEPENDENCY_DIR / "python-linux-amd64.sha256"
RUST_MANIFEST = DEPENDENCY_DIR / "rust-linux-amd64.sha256"
PYTHON_INPUTS = ("requirements.lock", PYTHON_ARCHIVE)
RUST_INPUTS = (
    "data-plane/decision-gate-rs/Cargo.toml",
    "data-plane/decision-gate-rs/Cargo.lock",
    CARGO_ARCHIVE,
    MUSL_APK,
    MUSL_DEV_APK,
)
CACHE_INPUTS = {PYTHON_ARCHIVE, CARGO_ARCHIVE, MUSL_APK, MUSL_DEV_APK}
ARCHIVE_ROOTS = {
    PYTHON_ARCHIVE: "wheelhouse",
    CARGO_ARCHIVE: "vendor",
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _validate_archive_member_path(relative: str, expected_root: str) -> None:
    if (
        not relative
        or not relative.isascii()
        or SAFE_ARCHIVE_PATH_RE.fullmatch(relative) is None
        or relative.startswith("/")
        or "//" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
        or relative.split("/", 1)[0] != expected_root
    ):
        raise RuntimeError(f"dependency archive contains an unsafe path: {relative!r}")


def _validate_tar_archive(descriptor: int, archive_bytes: int, relative: str) -> None:
    expected_root = ARCHIVE_ROOTS[relative]
    observed: set[str] = set()
    expanded_bytes = 0
    regular_files = 0
    required_payload_seen = False
    os.lseek(descriptor, 0, os.SEEK_SET)
    with os.fdopen(os.dup(descriptor), "rb") as archive_source:
        with tarfile.open(fileobj=archive_source, mode="r:gz") as archive:
            for member_count, member in enumerate(archive, start=1):
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise RuntimeError(f"dependency archive contains too many members: {relative}")
                member_name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
                _validate_archive_member_path(member_name, expected_root)
                if member_name in observed:
                    raise RuntimeError(
                        f"dependency archive contains a duplicate member: {relative}:{member_name}"
                    )
                observed.add(member_name)
                if not (member.isdir() or member.isreg()):
                    raise RuntimeError(
                        f"dependency archive contains a non-file member: {relative}:{member_name}"
                    )
                if getattr(member, "sparse", None):
                    raise RuntimeError(
                        f"dependency archive contains a sparse member: {relative}:{member_name}"
                    )
                if member.mode & 0o7002:
                    raise RuntimeError(
                        f"dependency archive contains privileged or world-writable mode: "
                        f"{relative}:{member_name}"
                    )
                if member.isreg():
                    regular_files += 1
                    expanded_bytes += member.size
                    if member.size < 0 or expanded_bytes > MAX_ARCHIVE_EXPANDED_BYTES:
                        raise RuntimeError(
                            f"dependency archive exceeds the expanded-size bound: {relative}"
                        )
                    if relative == PYTHON_ARCHIVE and member_name.endswith(".whl"):
                        required_payload_seen = True
                    if relative == CARGO_ARCHIVE and member_name.endswith("/.cargo-checksum.json"):
                        required_payload_seen = True
    if not observed or regular_files == 0 or not required_payload_seen:
        raise RuntimeError(f"dependency archive lacks its required payload structure: {relative}")
    if archive_bytes == 0 or expanded_bytes > archive_bytes * MAX_ARCHIVE_EXPANSION_RATIO:
        raise RuntimeError(f"dependency archive exceeds the compression-ratio bound: {relative}")


def _verify_regular_input(path: Path, relative: str, expected_sha256: str) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise RuntimeError(f"missing regular pinned dependency input: {relative}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"missing regular pinned dependency input: {relative}")
        digest = hashlib.sha256()
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        actual = digest.hexdigest()
        if actual != expected_sha256:
            raise RuntimeError(
                f"dependency input {relative} has sha256:{actual}, expected sha256:{expected_sha256}"
            )
        if relative in ARCHIVE_ROOTS:
            _validate_tar_archive(descriptor, before.st_size, relative)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise RuntimeError(f"dependency input changed while it was verified: {relative}")
    finally:
        os.close(descriptor)


def input_path(relative: str) -> Path:
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise RuntimeError(f"invalid dependency input path: {relative}")
    base = DEPENDENCY_DIR if relative_path.parts[0] == "cache" else ROOT
    path = (base / relative_path).resolve()
    if path != base and base not in path.parents:
        raise RuntimeError(f"dependency input escapes its base directory: {relative}")
    return path


def parse_manifest(path: Path, expected_inputs: tuple[str, ...]) -> dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"missing pinned dependency manifest: {path.relative_to(ROOT)}")
    raw = path.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"dependency manifest is not ASCII: {path.relative_to(ROOT)}") from exc
    if not text.endswith("\n"):
        raise RuntimeError(f"dependency manifest must end with LF: {path.relative_to(ROOT)}")
    lines = text.splitlines()
    if not lines or not lines[0].startswith("# metadata="):
        raise RuntimeError(f"dependency manifest lacks closed metadata: {path.relative_to(ROOT)}")
    try:
        metadata = json.loads(lines[0].removeprefix("# metadata="))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"dependency manifest metadata is invalid: {path.relative_to(ROOT)}") from exc
    if not isinstance(metadata, dict) or set(metadata) != {
        "apiVersion",
        "artifacts",
        "platform",
        "snapshotId",
        "snapshotUrlSuffix",
    }:
        raise RuntimeError(f"dependency manifest metadata fields are not exact: {path.relative_to(ROOT)}")
    if (
        metadata["apiVersion"] != MANIFEST_API_VERSION
        or metadata["platform"] != PLATFORM
        or not isinstance(metadata["snapshotId"], str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", metadata["snapshotId"])
        or metadata["snapshotUrlSuffix"] != "/" + metadata["snapshotId"]
    ):
        raise RuntimeError(f"dependency snapshot identity is invalid: {path.relative_to(ROOT)}")
    artifacts = metadata["artifacts"]
    if not isinstance(artifacts, dict):
        raise RuntimeError(f"dependency artifact metadata is invalid: {path.relative_to(ROOT)}")

    entries: dict[str, str] = {}
    for line in lines[1:]:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\x00\r\n]+)", line)
        if match is None:
            raise RuntimeError(f"dependency manifest line is invalid: {path.relative_to(ROOT)}")
        digest, relative = match.groups()
        if relative in entries or relative.startswith("/") or ".." in Path(relative).parts:
            raise RuntimeError(f"dependency manifest path is unsafe or duplicated: {relative}")
        entries[relative] = digest
    if tuple(entries) != expected_inputs:
        raise RuntimeError(
            f"dependency manifest inputs differ from the closed inventory: {path.relative_to(ROOT)}"
        )
    expected_artifacts = {relative for relative in expected_inputs if relative in CACHE_INPUTS}
    if set(artifacts) != expected_artifacts:
        raise RuntimeError(f"dependency artifact metadata is incomplete: {path.relative_to(ROOT)}")
    for relative, descriptor in artifacts.items():
        if not isinstance(descriptor, dict) or set(descriptor) != {"kind", "name", "version"}:
            raise RuntimeError(f"dependency artifact descriptor is not exact: {relative}")
        if not all(isinstance(descriptor[field], str) and descriptor[field] for field in descriptor):
            raise RuntimeError(f"dependency artifact descriptor is invalid: {relative}")
        if not SHA256_RE.fullmatch(entries[relative]):
            raise RuntimeError(f"dependency artifact digest is invalid: {relative}")
    return {"metadata": metadata, "entries": entries, "sha256": hashlib.sha256(raw).hexdigest()}


def manifests() -> list[dict[str, Any]]:
    parsed = [
        parse_manifest(PYTHON_MANIFEST, PYTHON_INPUTS),
        parse_manifest(RUST_MANIFEST, RUST_INPUTS),
    ]
    snapshot_ids = {item["metadata"]["snapshotId"] for item in parsed}
    if len(snapshot_ids) != 1:
        raise RuntimeError("production dependency manifests do not identify one immutable snapshot")
    return parsed


def expected_cache_entries(parsed: list[dict[str, Any]]) -> dict[str, str]:
    entries: dict[str, str] = {}
    for manifest in parsed:
        for relative, digest in manifest["entries"].items():
            if relative not in CACHE_INPUTS:
                continue
            if relative in entries and entries[relative] != digest:
                raise RuntimeError(f"dependency manifests disagree about {relative}")
            entries[relative] = digest
    if set(entries) != CACHE_INPUTS:
        raise RuntimeError("dependency manifests do not cover every offline cache artifact")
    return entries


def verify() -> None:
    parsed = manifests()
    for manifest in parsed:
        for relative, expected in manifest["entries"].items():
            path = input_path(relative)
            _verify_regular_input(path, relative, expected)


def validated_snapshot_url(raw: str, snapshot_id: str) -> str:
    parsed = urllib.parse.urlsplit(raw)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/").split("/")[-1] != snapshot_id
    ):
        raise RuntimeError(
            "dependency snapshot URL must be credential-free HTTPS and end with the checked snapshot ID"
        )
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def fetch_one(snapshot_url: str, relative: str, expected_sha256: str) -> None:
    encoded_path = "/".join(urllib.parse.quote(part, safe="._-") for part in Path(relative).parts)
    url = f"{snapshot_url}/{encoded_path}"
    destination = input_path(relative)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_raw = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temporary = Path(temporary_raw)
    digest = hashlib.sha256()
    total = 0
    try:
        with os.fdopen(descriptor, "wb") as target:
            request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
            with urllib.request.urlopen(request, timeout=60) as response:
                if response.status != 200 or response.geturl() != url:
                    raise RuntimeError(f"immutable dependency fetch was redirected or denied: {relative}")
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ARTIFACT_BYTES:
                        raise RuntimeError(f"dependency artifact exceeds the size bound: {relative}")
                    digest.update(chunk)
                    target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        actual = digest.hexdigest()
        if total == 0 or actual != expected_sha256:
            raise RuntimeError(
                f"downloaded dependency {relative} has sha256:{actual}, expected sha256:{expected_sha256}"
            )
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def fetch(snapshot_url_raw: str) -> None:
    parsed = manifests()
    snapshot_id = parsed[0]["metadata"]["snapshotId"]
    snapshot_url = validated_snapshot_url(snapshot_url_raw, snapshot_id)
    for relative, digest in sorted(expected_cache_entries(parsed).items()):
        fetch_one(snapshot_url, relative, digest)
    verify()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch or verify one immutable, digest-pinned production dependency snapshot."
    )
    parser.add_argument("action", choices=("fetch", "verify"))
    parser.add_argument("--snapshot-url", default=os.getenv(SNAPSHOT_URL_ENV, ""))
    args = parser.parse_args()
    if args.action == "verify":
        verify()
        return
    if not args.snapshot_url:
        raise RuntimeError(f"fetch requires --snapshot-url or {SNAPSHOT_URL_ENV}")
    fetch(args.snapshot_url)


if __name__ == "__main__":
    main()
