#!/usr/bin/env python3
"""Prepare an unpublished dependency candidate; never install or publish pins."""
from __future__ import annotations

import argparse
import email.parser
import gzip
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, BinaryIO


ROOT = Path(__file__).resolve().parents[1]
PYTHON_IMAGE = "python:3.11-slim-bookworm@sha256:0030323c9ce4d6dfab5f0812577cb0abd13c806f86b3a1f5b5d8f200ebb1421c"
MAX_INPUT = 1024 * 1024
MAX_WHEEL = 256 * 1024 * 1024
MAX_WHEELHOUSE = 512 * 1024 * 1024
MAX_WHEELS = 512
MAX_CACHE_ARTIFACT = 1024 * 1024 * 1024
MIN_FREE_BYTES = 4 * 1024 * 1024 * 1024
WHEEL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,249}\.whl\Z")
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]{0,127})==([A-Za-z0-9][A-Za-z0-9._+!-]{0,127})\Z")
HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})\Z")
SOURCE_INPUTS = (
    "requirements.lock",
    "data-plane/decision-gate-rs/Cargo.toml",
    "data-plane/decision-gate-rs/Cargo.lock",
)
MANIFEST_NAMES = ("python-linux-amd64.sha256", "rust-linux-amd64.sha256", "native-broker-linux-amd64.sha256")


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def copy_verified(source: Path, destination: Path | None, *, expected: str | None = None,
                  maximum: int = MAX_CACHE_ARTIFACT) -> dict[str, Any]:
    """Copy once from a bounded regular file, retaining a digest of those bytes."""
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    target = None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise ValueError(f"input must be a bounded single-link regular file: {source.name}")
        if destination is not None:
            target = destination.open("xb")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > maximum:
                raise ValueError(f"input grew beyond its size bound: {source.name}")
            digest.update(chunk)
            if target is not None:
                target.write(chunk)
        if identity(before) != identity(os.fstat(descriptor)) or size != before.st_size:
            raise ValueError(f"input changed during capture: {source.name}")
        actual = digest.hexdigest()
        if expected is not None and actual != expected:
            raise ValueError(f"reviewed dependency digest mismatch: {source.name}")
        if target is not None:
            target.flush()
            os.fsync(target.fileno())
        return {"sha256": actual, "size": size}
    finally:
        if target is not None:
            target.close()
        os.close(descriptor)


def read_small(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_INPUT:
            raise ValueError(f"input must be a bounded single-link regular file: {path.name}")
        value = bytearray()
        while chunk := os.read(descriptor, min(65536, MAX_INPUT + 1 - len(value))):
            value.extend(chunk)
            if len(value) > MAX_INPUT:
                raise ValueError(f"input exceeds its size bound: {path.name}")
        if len(value) != before.st_size or identity(before) != identity(os.fstat(descriptor)):
            raise ValueError(f"input changed during capture: {path.name}")
        return bytes(value)
    finally:
        os.close(descriptor)


def locked_packages(data: bytes) -> dict[str, dict[str, Any]]:
    """Admit only pinned names/versions and SHA-256s; no URLs, options or markers."""
    if not data or len(data) > MAX_INPUT:
        raise ValueError("requirements lock is empty or oversized")
    entries: dict[str, dict[str, Any]] = {}
    parts: list[str] = []
    for raw in data.decode("ascii").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            if parts:
                raise ValueError("requirements lock has an interrupted entry")
            continue
        continued = line.endswith("\\")
        parts.extend((line[:-1] if continued else line).split())
        if continued:
            continue
        pin = PIN.fullmatch(parts[0])
        hashes = [HASH.fullmatch(value) for value in parts[1:]]
        if pin is None or not hashes or any(value is None for value in hashes):
            raise ValueError("requirements lock must contain only exact pins and SHA-256 hashes")
        name, version = pin.groups()
        name = canonical_name(name)
        digests = [value.group(1) for value in hashes if value is not None]
        if name in entries or len(digests) != len(set(digests)):
            raise ValueError("requirements lock has duplicate packages or hashes")
        entries[name] = {"version": version, "hashes": sorted(digests)}
        parts = []
    if parts or not entries or len(entries) > MAX_WHEELS:
        raise ValueError("requirements lock is incomplete or exceeds the package bound")
    return entries


def wheel_inventory(wheelhouse: Path, locked: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    inventory = []
    seen: set[str] = set()
    total = 0
    paths = sorted(wheelhouse.iterdir())
    if len(paths) > MAX_WHEELS:
        raise ValueError("wheelhouse exceeds the package bound")
    for path in paths:
        if not WHEEL_NAME.fullmatch(path.name):
            raise ValueError("wheelhouse contains an unexpected filename")
        measured = copy_verified(path, None, maximum=MAX_WHEEL)
        total += measured["size"]
        if total > MAX_WHEELHOUSE:
            raise ValueError("wheelhouse exceeds the total size bound")
        with zipfile.ZipFile(path) as wheel:
            metadata = [item for item in wheel.infolist()
                        if re.fullmatch(r"[^/]+\.dist-info/METADATA", item.filename)]
            if len(metadata) != 1 or metadata[0].file_size > MAX_INPUT:
                raise ValueError("wheel must contain one bounded package metadata file")
            message = email.parser.BytesParser().parsebytes(wheel.read(metadata[0]))
        names, versions = message.get_all("Name", []), message.get_all("Version", [])
        if len(names) != 1 or len(versions) != 1:
            raise ValueError("wheel metadata must identify one package and version")
        name = canonical_name(names[0])
        expected = locked.get(name)
        if name in seen or expected is None or versions[0] != expected["version"]:
            raise ValueError("wheelhouse package inventory differs from the committed lock")
        if measured["sha256"] not in expected["hashes"]:
            raise ValueError("wheel bytes do not match an approved lock hash")
        seen.add(name)
        inventory.append({"file": path.name, "name": name, "version": versions[0], **measured})
    if seen != set(locked):
        raise ValueError("wheelhouse does not close every committed package pin")
    return inventory


def package_wheels(wheelhouse: Path, output: BinaryIO) -> None:
    with gzip.GzipFile(filename="", mode="wb", compresslevel=9, mtime=0, fileobj=output) as compressed:
        with tarfile.open(mode="w|", fileobj=compressed, format=tarfile.PAX_FORMAT) as archive:
            root = tarfile.TarInfo("wheelhouse")
            root.type, root.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(root)
            for path in sorted(wheelhouse.iterdir()):
                if not WHEEL_NAME.fullmatch(path.name) or path.is_symlink() or not path.is_file():
                    raise ValueError("cannot package a non-wheel or non-regular input")
                info = tarfile.TarInfo("wheelhouse/" + path.name)
                info.size, info.mode = path.stat().st_size, 0o644
                with path.open("rb") as source:
                    archive.addfile(info, source)


class DigestWriter:
    def __init__(self) -> None:
        self.digest = hashlib.sha256()

    def write(self, value: bytes) -> int:
        self.digest.update(value)
        return len(value)

    def flush(self) -> None:
        pass


def unpack_wheels(path: Path, destination: Path) -> None:
    seen: set[str] = set()
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            if member.name in seen or len(seen) > MAX_WHEELS:
                raise ValueError("wheel archive has duplicate or excess entries")
            seen.add(member.name)
            if member.name == "wheelhouse" and member.isdir():
                continue
            prefix, separator, name = member.name.partition("/")
            if prefix != "wheelhouse" or not separator or not WHEEL_NAME.fullmatch(name) or not member.isreg():
                raise ValueError("wheel archive contains an unexpected entry")
            total += member.size
            if not 0 < member.size <= MAX_WHEEL or total > MAX_WHEELHOUSE:
                raise ValueError("wheel archive exceeds its expanded size bound")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("wheel archive lacks file content")
            with source, (destination / name).open("xb") as target:
                shutil.copyfileobj(source, target, 1024 * 1024)


def run_pip(arguments: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run([sys.executable, "-m", "pip", "--isolated", *arguments],
                   check=True, timeout=1200, env=env)


def container_phase(phase: str) -> None:
    """Fixed container operations. All bulky temporary data stays in bounded tmpfs."""
    lock_path = Path("/inputs/requirements.lock")
    locked = locked_packages(read_small(lock_path))
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="snapshot-") as temporary:
        scratch = Path(temporary)
        wheelhouse = scratch / "wheelhouse"
        wheelhouse.mkdir()
        if phase == "download":
            run_pip(["download", "--quiet", "--no-cache-dir", "--only-binary=:all:",
                     "--require-hashes", "--index-url", "https://pypi.org/simple",
                     "--dest", str(wheelhouse), "-r", str(lock_path)])
            inventory = wheel_inventory(wheelhouse, locked)
            archive_path = Path("/output/python-wheelhouse-linux-amd64.tar.gz")
            with archive_path.open("xb") as output:
                package_wheels(wheelhouse, output)
            measured = copy_verified(archive_path, None)
            repeated = DigestWriter()
            package_wheels(wheelhouse, repeated)
            if repeated.digest.hexdigest() != measured["sha256"]:
                raise ValueError("wheelhouse packaging is not deterministic")
            result = {"archive": measured, "wheels": inventory, "deterministic_packaging": True}
        else:
            unpack_wheels(Path("/archive/python-wheelhouse-linux-amd64.tar.gz"), wheelhouse)
            inventory = wheel_inventory(wheelhouse, locked)
            # Native extensions require executable mappings. Only this offline
            # install target gets an executable tmpfs; wheel/download scratch
            # stays on the separate noexec /tmp mount in both fixed phases.
            installed = Path("/installed")
            run_pip(["install", "--quiet", "--no-cache-dir", "--no-compile", "--no-index",
                     "--only-binary=:all:", "--require-hashes", "--ignore-installed",
                     "--find-links", str(wheelhouse), "--target", str(installed), "-r", str(lock_path)])
            packages = {canonical_name(item.metadata["Name"]): item.version
                        for item in importlib.metadata.distributions(path=[str(installed)])}
            if packages != {name: item["version"] for name, item in locked.items()}:
                raise ValueError("offline installed package inventory differs from the committed lock")
            environment = {**os.environ, "PYTHONPATH": str(installed)}
            run_pip(["check"], env=environment)
            smoke = subprocess.run(
                [sys.executable, "-c", "import cryptography; from cryptography.hazmat.bindings import _rust; print(cryptography.__version__)"],
                check=True, timeout=30, env=environment, text=True, stdout=subprocess.PIPE,
            ).stdout.strip()
            if smoke != locked.get("cryptography", {}).get("version"):
                raise ValueError("offline cryptography import differs from the committed lock")
            result = {"wheels": inventory, "installed": packages, "pip_check": True,
                      "cryptography_import": smoke, "network": "none"}
        result.update({"python": platform.python_version(), "machine": platform.machine(),
                       "pip": importlib.metadata.version("pip"), "ok": True})
        Path("/output/" + phase + ".json").write_bytes(canonical_json(result))


def prefetch_module(root: Path, dependency_directory: Path) -> Any:
    spec = importlib.util.spec_from_file_location("snapshot_prefetch", ROOT / "production-dependencies/prefetch.py")
    if spec is None or spec.loader is None:
        raise ValueError("could not load dependency verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT, module.DEPENDENCY_DIR = root, dependency_directory
    module.CACHE_DIR = dependency_directory / "cache"
    module.PYTHON_MANIFEST = dependency_directory / MANIFEST_NAMES[0]
    module.RUST_MANIFEST = dependency_directory / MANIFEST_NAMES[1]
    module.BROKER_MANIFEST = dependency_directory / MANIFEST_NAMES[2]
    return module


def prepare_rust_vendor(candidate: Path, expected_commit: str) -> dict[str, Any]:
    """Use the separate fixed Cargo producer only when explicitly requested."""
    spec = importlib.util.spec_from_file_location(
        "snapshot_rust_vendor", ROOT / "production-dependencies/prepare_rust_vendor.py"
    )
    if spec is None or spec.loader is None:
        raise ValueError("could not load the Rust dependency producer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.prepare_vendor(candidate, expected_commit)


def git_bytes(*arguments: str) -> bytes:
    return subprocess.run(["git", "-C", str(ROOT), *arguments], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout


def capture_source(expected_commit: str) -> tuple[dict[str, str], dict[str, bytes]]:
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise ValueError("expected commit must be one complete lowercase Git commit ID")
    commit = git_bytes("rev-parse", "HEAD^{commit}").decode("ascii").strip()
    if commit != expected_commit or git_bytes("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("dependency preparation requires the exact clean recorded commit")
    paths = [*SOURCE_INPUTS, "Dockerfile.production", "data-plane/decision-gate-rs/Dockerfile.production",
             "production-dependencies/prepare_snapshot.py", "production-dependencies/prepare_rust_vendor.py",
             "production-dependencies/prefetch.py", *("production-dependencies/" + name for name in MANIFEST_NAMES)]
    captured = {}
    for relative in paths:
        size = int(git_bytes("cat-file", "-s", f"{commit}:{relative}"))
        if not 0 < size <= MAX_INPUT:
            raise ValueError("committed source input exceeds its size bound")
        data = git_bytes("show", f"{commit}:{relative}")
        if not data or len(data) > MAX_INPUT or read_small(ROOT / relative) != data:
            raise ValueError("source input differs from its recorded commit")
        captured[relative] = data
    if f"FROM {PYTHON_IMAGE} AS python-deps\n".encode("ascii") not in captured["Dockerfile.production"]:
        raise ValueError("producer image no longer matches the production Python dependency stage")
    return {"commit": commit, "tree": git_bytes("rev-parse", "HEAD^{tree}").decode("ascii").strip()}, captured


def docker_command(phase: str, candidate: Path, name: str) -> list[str]:
    if phase not in {"download", "verify"}:
        raise ValueError("unknown fixed preparation phase")
    mounts = [
        (candidate / "inputs", "/inputs", True),
        (candidate / "work" / phase, "/output", False),
        (ROOT / "production-dependencies/prepare_snapshot.py", "/tool/prepare_snapshot.py", True),
    ]
    if phase == "verify":
        mounts.append((candidate / "snapshot/cache", "/archive", True))
    command = ["docker", "run", "--rm", "--pull=never", "--name", name,
               "--platform", "linux/amd64", "--network", "bridge" if phase == "download" else "none",
               "--user", f"{os.geteuid()}:{os.getegid()}", "--read-only", "--cap-drop=ALL",
               "--security-opt=no-new-privileges", "--cpus=1", "--memory=2g", "--memory-swap=2g",
               "--pids-limit=128", "--tmpfs",
               "/tmp:rw,nosuid,nodev,noexec,size=" + ("1536m" if phase == "download" else "1024m") + ",mode=1777",
               "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PIP_DISABLE_PIP_VERSION_CHECK=1"]
    if phase == "verify":
        # Keep the combined tmpfs budget at 1536 MiB, within the unchanged
        # 2 GiB container memory cap, and never expose executable download space.
        command.extend(["--tmpfs", "/installed:rw,nosuid,nodev,exec,size=512m,mode=1777"])
    for source, destination, readonly in mounts:
        if any(character in str(source) for character in (",", "\n", "\r")):
            raise ValueError("candidate paths must not contain Docker mount separators")
        command.extend(["--mount", f"type=bind,src={source},dst={destination}" + (",readonly" if readonly else "")])
    return [*command, PYTHON_IMAGE, "timeout", "--signal=TERM", "--kill-after=15s", "1400s",
            "python", "/tool/prepare_snapshot.py", "--container-phase", phase]


def run_container(phase: str, candidate: Path) -> dict[str, Any]:
    name = "catchplate-dependency-" + phase + "-" + os.urandom(8).hex()
    command = docker_command(phase, candidate, name)
    (candidate / "work" / (phase + "-invocation.json")).write_bytes(canonical_json(
        {"phase": phase, "container_name": name, "command": command}
    ))
    # A client timeout must also stop this exact task container. Workloads never
    # receive a Docker socket, host networking, privileges, or repository tree.
    try:
        with (candidate / "work" / (phase + ".log")).open("xb") as log:
            subprocess.run(command, check=True, timeout=1500, stdout=log, stderr=subprocess.STDOUT)
    finally:
        subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False, timeout=30)
    result = json.loads(read_small(candidate / "work" / phase / (phase + ".json")))
    if result.get("ok") is not True or result.get("machine") != "x86_64" or not result.get("python", "").startswith("3.11."):
        raise ValueError("container did not produce the required Linux/amd64 Python 3.11 result")
    return result


def proposed_manifest(original: dict[str, Any], *, snapshot_id: str,
                      entries: dict[str, str], verifier: Any) -> bytes:
    metadata = {**original["metadata"], "snapshotId": snapshot_id, "snapshotUrlSuffix": "/" + snapshot_id}
    metadata["artifacts"] = {name: verifier.expected_artifact_descriptor(name, entries)
                             for name in original["metadata"]["artifacts"]}
    return b"# metadata=" + canonical_json(metadata) + "".join(
        f"{digest}  {name}\n" for name, digest in entries.items()
    ).encode("ascii")


def validate_output(output: Path) -> Path:
    output = output.absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.resolve() != output.parent:
        raise ValueError("candidate output must be absent beneath an existing real absolute directory")
    if output == ROOT or ROOT in output.parents or Path("/tmp") in output.parents:
        raise ValueError("candidate output must be outside the checkout and root-backed /tmp")
    if shutil.disk_usage(output.parent).free < MIN_FREE_BYTES:
        raise ValueError("candidate filesystem requires at least 4 GiB free")
    return output


def prepare(*, expected_commit: str, existing_cache: Path, snapshot_id: str, output: Path,
            refresh_rust: bool = False) -> dict[str, Any]:
    if os.geteuid() == 0:
        raise ValueError("run dependency preparation as an unprivileged operator account")
    source, captured = capture_source(expected_commit)
    locked_packages(captured["requirements.lock"])
    verifier = prefetch_module(ROOT, ROOT / "production-dependencies")
    originals = verifier.manifests()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", snapshot_id) or snapshot_id == originals[0]["metadata"]["snapshotId"]:
        raise ValueError("candidate must use a valid new snapshot ID")
    cargo_inputs = {relative: hashlib.sha256(captured[relative]).hexdigest()
                    for relative in SOURCE_INPUTS[1:]}
    if not refresh_rust and any(digest != originals[1]["entries"][relative]
                                for relative, digest in cargo_inputs.items()):
        raise ValueError("Cargo inputs changed; use --refresh-rust to prepare a new unpublished vendor candidate")
    output = validate_output(output)
    image = json.loads(subprocess.run(
        ["docker", "image", "inspect", PYTHON_IMAGE], check=True, timeout=30,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout)
    if len(image) != 1 or image[0].get("Os") != "linux" or image[0].get("Architecture") != "amd64":
        raise ValueError("the exact pinned Linux/amd64 Python image must be present before preparation")
    image_id = image[0].get("Id", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("builder image lacks an immutable configuration digest")
    output.mkdir(mode=0o700)
    report: dict[str, Any] = {"apiVersion": "catchplate.dependencySnapshotCandidate/v1", "ok": False,
        "published": False, "reviewed_pins_installed": False, "production_release_authority": False,
        "scope": "local-engineering-preparation-only", "source": source,
        "carried_forward_source_directory": str(existing_cache.resolve()),
        "rust_vendor_mode": "refresh-locked" if refresh_rust else "unchanged-reviewed-carry-forward",
        "snapshot_id": snapshot_id, "builder": {"reference": PYTHON_IMAGE, "image_id": image_id}}
    try:
        # Set every owned ancestor explicitly. Path.mkdir(parents=True) does
        # not apply its mode to intermediate directories, and a permissive
        # operator umask must not create group-writable input/cache parents.
        for relative in ("data-plane", "data-plane/decision-gate-rs", "inputs",
                         "work", "work/download", "work/verify", "snapshot", "snapshot/cache"):
            (output / relative).mkdir(mode=0o700)
        for relative in SOURCE_INPUTS:
            path = output / relative
            path.write_bytes(captured[relative])
        (output / "inputs/requirements.lock").write_bytes(captured["requirements.lock"])
        snapshot = output / "snapshot"
        cache = snapshot / "cache"
        carried = {}
        for original in originals[1:]:
            for relative, digest in original["entries"].items():
                if relative not in verifier.CACHE_INPUTS:
                    continue
                if refresh_rust and relative == verifier.CARGO_ARCHIVE:
                    continue
                path = cache / Path(relative).name
                carried[relative] = copy_verified(existing_cache / path.name, path, expected=digest)
                verifier._verify_regular_input(path, relative, digest)
        rust = None
        if refresh_rust:
            rust = prepare_rust_vendor(output, expected_commit)
            if rust.get("inputs") != cargo_inputs:
                raise ValueError("Rust vendor producer did not retain the exact captured Cargo inputs")
            cargo_archive = cache / Path(verifier.CARGO_ARCHIVE).name
            cargo_measured = copy_verified(cargo_archive, None, expected=rust["archive"]["sha256"])
            if cargo_measured != rust["archive"]:
                raise ValueError("Rust vendor archive size differs from the producer result")
            verifier._verify_regular_input(cargo_archive, verifier.CARGO_ARCHIVE, cargo_measured["sha256"])
        download = run_container("download", output)
        if download.get("deterministic_packaging") is not True:
            raise ValueError("download phase did not prove deterministic packaging")
        python_archive = cache / "python-wheelhouse-linux-amd64.tar.gz"
        measured = copy_verified(output / "work/download" / python_archive.name, python_archive,
                                 expected=download["archive"]["sha256"])
        verifier._verify_regular_input(python_archive, verifier.PYTHON_ARCHIVE, measured["sha256"])
        offline = run_container("verify", output)
        if (offline.get("network") != "none" or offline.get("pip_check") is not True
                or offline["wheels"] != download["wheels"]):
            raise ValueError("offline installation did not consume the exact freshly downloaded wheelhouse")
        for name, original in zip(MANIFEST_NAMES, originals):
            entries = dict(original["entries"])
            if "requirements.lock" in entries:
                entries["requirements.lock"] = hashlib.sha256(captured["requirements.lock"]).hexdigest()
                entries[verifier.PYTHON_ARCHIVE] = measured["sha256"]
            if rust is not None and verifier.CARGO_ARCHIVE in entries:
                entries.update(cargo_inputs)
                entries[verifier.CARGO_ARCHIVE] = cargo_measured["sha256"]
            (snapshot / name).write_bytes(proposed_manifest(original, snapshot_id=snapshot_id,
                                                          entries=entries, verifier=verifier))
        prefetch_module(output, snapshot).verify()
        # Guard the code/source identity through the complete preparation step.
        if capture_source(expected_commit) != (source, captured):
            raise ValueError("recorded source changed during dependency preparation")
        report.update({"ok": True, "download": download, "offline_validation": offline,
            "rust_preparation": rust,
            "carried_forward": carried,
            "inputs": {name: hashlib.sha256(value).hexdigest() for name, value in captured.items()},
            "proposed_manifests": {name: copy_verified(snapshot / name, None, maximum=MAX_INPUT)
                                   for name in MANIFEST_NAMES},
            "publication_directory": str(snapshot),
            "next_step": "dependency-release owner reviews this unpublished candidate; publication and reviewed pin installation are separate operations"})
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (output / "candidate-report.json").write_bytes(canonical_json(report))
    return report


def main() -> None:
    # A separate offline mode augments retained evidence without regenerating
    # dependencies or rewriting the original candidate/consumer manifests.
    if sys.argv[1:2] == ["--prepare-native-source-companion"]:
        spec = importlib.util.spec_from_file_location(
            "native_source_companion", ROOT / "production-dependencies/prepare_native_source_companion.py"
        )
        if spec is None or spec.loader is None:
            raise ValueError("could not load native source companion preparer")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.main(sys.argv[2:])
        return
    # Internal fixed phases are entered only in the disposable container. They
    # have no Docker operations and accept no caller-provided commands or paths.
    if len(sys.argv) == 3 and sys.argv[1] == "--container-phase" and sys.argv[2] in {"download", "verify"}:
        container_phase(sys.argv[2])
        return
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "Offline companion mode: --prepare-native-source-companion --candidate DIR "
        "--source-directory DIR --output DIR (no download, rebuild or publication)."))
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--existing-cache", required=True, type=Path)
    parser.add_argument("--snapshot-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--refresh-rust", action="store_true",
                        help="prepare a new locked Rust vendor candidate instead of carrying forward the reviewed archive")
    args = parser.parse_args()
    try:
        report = prepare(expected_commit=args.expected_commit, existing_cache=args.existing_cache,
                         snapshot_id=args.snapshot_id, output=args.output, refresh_rust=args.refresh_rust)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"dependency candidate preparation failed: {error}\n")
    print(canonical_json({"ok": report["ok"], "published": False,
                          "candidate_report": str(args.output / "candidate-report.json")}).decode("ascii"), end="")


if __name__ == "__main__":
    main()
