#!/usr/bin/env python3
"""Prepare an unpublished Rust vendor candidate; never update reviewed pins.

Only prepare_vendor() starts its fixed, bounded network-fetch container. The
subsequent archive/checksum verification and deterministic packaging are host
data operations, not Cargo compilation, tests or dependency build scripts.

The pinned Cargo invocation owns package-file selection (including manifest
include/exclude rules). Host verification checks every selected file against
the locked crate and the exact vendor census, and records omitted archive
files for dependency-owner review. This is local engineering preparation,
not an independent proof of Cargo's selection or reviewed release authority.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import tarfile
import time
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUST_IMAGE = "rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89"
INPUTS = ("data-plane/decision-gate-rs/Cargo.toml", "data-plane/decision-gate-rs/Cargo.lock")
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
MAX_INPUT = 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_CRATES = 2048
MAX_MEMBERS = 250_000
MAX_VENDOR = 2 * 1024**3
MAX_TRANSFER = 4 * 1024**3
MAX_ARCHIVE = 1024**3
MIN_FREE = 12 * 1024**3
MAX_LOG = 8 * 1024**2
SECONDS = 1500
SAFE = re.compile(r"[A-Za-z0-9._@+()/\-]+\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?\Z")


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def live(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    require(remaining > 0, "Rust candidate original preparation deadline expired")
    return remaining


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path: Path, maximum: int, deadline: float) -> bytes:
    live(deadline)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
                "Rust candidate input is not a bounded single-link regular file")
        chunks, size = [], 0
        while True:
            live(deadline)
            data = os.read(fd, min(65536, maximum + 1 - size))
            if not data: break
            size += len(data)
            require(size <= maximum, "Rust candidate input grew beyond its bound")
            chunks.append(data)
        require(size == before.st_size and identity(before) == identity(os.fstat(fd)), "Rust candidate input changed")
        return b"".join(chunks)
    finally:
        os.close(fd)


def digest_file(path: Path, maximum: int, deadline: float) -> dict[str, Any]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
                "Rust candidate file metadata exceeds its bounds")
        digest, size = hashlib.sha256(), 0
        while True:
            live(deadline)
            value = os.read(fd, 1024 * 1024)
            if not value: break
            size += len(value)
            require(size <= maximum, "Rust candidate file grew")
            digest.update(value)
        require(size == before.st_size and identity(before) == identity(os.fstat(fd)), "Rust candidate file changed while hashing")
        return {"sha256": digest.hexdigest(), "size": size}
    finally:
        os.close(fd)


def git(deadline: float, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(30, live(deadline))).stdout


def capture(expected_commit: str, candidate: Path, deadline: float) -> dict[str, bytes]:
    require(re.fullmatch(r"[0-9a-f]{40}", expected_commit) is not None, "expected commit must be full lowercase Git ID")
    require(git(deadline, "rev-parse", "HEAD^{commit}").decode("ascii").strip() == expected_commit
        and not git(deadline, "status", "--porcelain", "--untracked-files=all"), "Rust candidate needs exact clean recorded source")
    paths = (*INPUTS, "data-plane/decision-gate-rs/Dockerfile.production", "production-dependencies/prepare_rust_vendor.py")
    result = {}
    for name in paths:
        size = int(git(deadline, "cat-file", "-s", expected_commit + ":" + name))
        require(0 < size <= MAX_INPUT, "Rust source capture exceeds bound")
        data = git(deadline, "show", expected_commit + ":" + name)
        require(len(data) == size and data == read_file(ROOT / name, MAX_INPUT, deadline), "Rust source differs from commit")
        if name in INPUTS:
            require((candidate / name).parent.resolve() == (candidate / name).parent, "candidate Cargo parent is a symlink")
            require(data == read_file(candidate / name, MAX_INPUT, deadline), "candidate Cargo original differs from captured commit")
        result[name] = data
    require(("FROM " + RUST_IMAGE + " AS build\n").encode("ascii") in result[paths[2]],
            "pinned Rust vendor image differs from actual production builder")
    return result


def lock_inventory(manifest_raw: bytes, lock_raw: bytes) -> dict[str, dict[str, str]]:
    manifest, lock = tomllib.loads(manifest_raw.decode("utf-8")), tomllib.loads(lock_raw.decode("utf-8"))
    require(not set(manifest) & {"workspace", "patch", "replace"}, "Rust candidate forbids workspace/patch/replace source redirection")
    package = manifest.get("package", {})
    require(type(package) is dict and NAME.fullmatch(package.get("name", "")) is not None
        and VERSION.fullmatch(package.get("version", "")) is not None, "root package identity invalid")
    # Cargo may discover existing targets from the narrowly mounted actual src;
    # no path dependency, alternate registry, toolchain file or .cargo config.
    def dependencies(value):
        if type(value) is not dict: return
        for key, selected in value.items():
            if key in {"dependencies", "dev-dependencies", "build-dependencies"}:
                require(type(selected) is dict, "dependency section is not a table")
                for spec in selected.values():
                    require(type(spec) is str or (type(spec) is dict
                        and not set(spec) & {"path", "git", "branch", "tag", "rev", "registry", "registry-index", "workspace"}),
                        "only ordinary crates.io dependencies are admitted")
            elif type(selected) is dict:
                dependencies(selected)
    dependencies(manifest)
    for section in ("lib", "bin", "example", "test", "bench"):
        entries = manifest.get(section, [])
        if type(entries) is dict: entries = [entries]
        require(type(entries) is list, "target section invalid")
        for entry in entries:
            require(type(entry) is dict, "target entry invalid")
            if "path" in entry:
                parts = safe_path(entry["path"])
                require(parts[0] == "src", "target path escapes the only source mount")
    require(type(lock) is dict and lock.get("version") in {3, 4} and set(lock) <= {"version", "package"}, "unsupported Cargo lock structure")
    packages = lock.get("package")
    require(type(packages) is list and 1 < len(packages) <= MAX_CRATES + 1, "Cargo package census exceeds bound")
    result, roots = {}, 0
    for entry in packages:
        require(type(entry) is dict and set(entry) <= {"name", "version", "source", "checksum", "dependencies", "replace"}
            and "replace" not in entry, "Cargo package has unsupported fields")
        name, version = entry.get("name", ""), entry.get("version", "")
        require(type(name) is str and NAME.fullmatch(name) is not None and type(version) is str
            and VERSION.fullmatch(version) is not None, "Cargo package name/version invalid")
        if "source" not in entry:
            require(name == package["name"] and version == package["version"] and "checksum" not in entry,
                    "Cargo lock contains a non-root path package")
            roots += 1
            continue
        checksum = entry.get("checksum", "")
        require(entry["source"] == REGISTRY and type(checksum) is str and SHA.fullmatch(checksum) is not None,
                "Cargo lock contains a non-crates.io source or invalid checksum")
        directory = name + "-" + version
        require(directory not in result, "duplicate Cargo package identity")
        result[directory] = {"name": name, "version": version, "checksum": checksum, "source": REGISTRY}
    require(roots == 1 and result, "Cargo lock must have exactly its actual workspace-root package")
    return result


def safe_path(value: str) -> tuple[str, ...]:
    require(type(value) is str and 0 < len(value) <= 1024 and SAFE.fullmatch(value) is not None
        and not value.startswith("/") and all(p not in {"", ".", ".."} for p in value.split("/")), "unsafe Rust archive path")
    return tuple(value.split("/"))


def docker_environment(config: Path) -> dict[str, str]:
    # No inherited registry tokens, Cargo config, proxy values, credential
    # helpers, Docker context or remote DOCKER_HOST selection.
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "DOCKER_CONFIG": str(config)}


def download(work: Path, candidate: Path, image_id: str, deadline: float) -> None:
    name = "serverware-rust-candidate-" + os.urandom(12).hex()
    env = docker_environment(work / "docker-config")
    source_directory = ROOT / "data-plane/decision-gate-rs/src"
    require(source_directory.is_dir() and source_directory.resolve() == source_directory, "actual Cargo src mount is not a real directory")
    # No host output bind mount. Both Cargo expansion locations have hard
    # tmpfs ceilings; only this capped public-data tar crosses to the host.
    command = ["docker", "--host=unix:///var/run/docker.sock", "run", "--rm", "--pull=never", "--name", name,
        "--label", "serverware.dependency-candidate=" + name, "--platform=linux/amd64", "--network=bridge",
        "--user", f"{os.geteuid()}:{os.getegid()}", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--cpus=1", "--memory=5g", "--memory-swap=5g", "--pids-limit=64", "--ulimit=nofile=512:512",
        "--ulimit=fsize=134217728:134217728", "--log-driver=none",
        "--tmpfs=/cargo-home:rw,nosuid,nodev,noexec,size=2g,mode=1777",
        "--tmpfs=/output:rw,nosuid,nodev,noexec,size=2g,mode=1777",
        "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--env=CARGO_HOME=/cargo-home", "--env=CARGO_TERM_COLOR=never", "--env=CARGO_NET_RETRY=2",
        "--env=CARGO_HTTP_TIMEOUT=60", "--env=CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse",
        "--env=RUSTC=/usr/local/cargo/bin/rustc", "--env=RUSTDOC=/usr/local/cargo/bin/rustdoc",
        "--workdir=/project"]
    for source, target in ((candidate / INPUTS[0], "/project/Cargo.toml"),
                           (candidate / INPUTS[1], "/project/Cargo.lock"),
                           (source_directory, "/project/src")):
        require(not any(c in str(source) for c in ",\n\r"), "Docker mount path contains separators")
        command += ["--mount", f"type=bind,src={source},dst={target},readonly"]
    command += ["--entrypoint=/usr/bin/timeout", image_id, "--signal=TERM", "--kill-after=15s", "1200s",
        "/bin/sh", "-ec", "umask 022; /usr/local/cargo/bin/cargo vendor --locked --versioned-dirs /output/vendor > /output/cargo-config.txt; "
        "exec /bin/tar --format=posix -c -C /output vendor -C /cargo-home registry/cache"]
    (work / "invocation.json").write_bytes(canonical({"container_name": name, "command": command, "network": "bridge"}))
    process = None
    try:
        with (work / "transfer.tar").open("xb") as transfer, (work / "download.log").open("xb") as log:
            process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with selectors.DefaultSelector() as poll:
                for stream, target, maximum in ((process.stdout, transfer, MAX_TRANSFER), (process.stderr, log, MAX_LOG)):
                    os.set_blocking(stream.fileno(), False)
                    poll.register(stream, selectors.EVENT_READ, [target, maximum, 0])
                while poll.get_map():
                    for event, _ in poll.select(min(1, live(deadline))):
                        data = os.read(event.fileobj.fileno(), 65536)
                        if not data:
                            poll.unregister(event.fileobj); continue
                        state = event.data; state[2] += len(data)
                        require(state[2] <= state[1], "Rust download transfer/log exceeds its bound")
                        state[0].write(data)
                require(process.wait(timeout=live(deadline)) == 0, "fixed cargo vendor container failed")
            transfer.flush(); os.fsync(transfer.fileno()); log.flush(); os.fsync(log.fileno())
    finally:
        # Delete only this random task-named container. Never prune Docker or
        # infer that a timed-out client stopped its separately running daemon job.
        if process is not None:
            if process.poll() is None: process.kill()
            process.wait(timeout=30)
            for stream in (process.stdout, process.stderr):
                if stream is not None: stream.close()
        # --rm may already have removed a definite failed/successful attempt.
        # Resolve only this exact random name AND task label to its actual ID;
        # a colliding unrelated container is never a cleanup target.
        select = ["docker", "--host=unix:///var/run/docker.sock", "container", "ls", "--all", "--no-trunc",
            "--filter", "name=^/" + name + "$", "--filter", "label=serverware.dependency-candidate=" + name,
            "--format={{.ID}}"]
        selected = subprocess.run(select, env=env, check=True, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode("ascii").splitlines()
        require(len(selected) <= 1 and all(SHA.fullmatch(value) is not None for value in selected), "task Rust container identity ambiguous")
        if selected:
            subprocess.run(["docker", "--host=unix:///var/run/docker.sock", "rm", "--force", selected[0]], env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=30)
        require(not subprocess.run(select, env=env, check=True, timeout=30, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE).stdout.strip(), "task Rust container cleanup could not be confirmed")


def unpack(work: Path, deadline: float) -> None:
    seen, total, vendor_total = set(), 0, 0
    with tarfile.open(work / "transfer.tar", "r:") as archive:
        for member in archive:
            live(deadline)
            name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
            parts = safe_path(name)
            require(name not in seen and len(seen) < MAX_MEMBERS and (member.isdir() or member.isreg())
                and not member.sparse and not member.mode & 0o7002, "Rust transfer has duplicate/unsafe members")
            seen.add(name)
            require(parts[0] == "vendor" or parts[:2] == ("registry", "cache") or parts == ("registry",),
                    "Rust transfer contains an unselected directory")
            path = work.joinpath(*parts)
            if member.isdir():
                path.mkdir(mode=0o755, parents=True, exist_ok=True); continue
            require(len(parts) >= 3 and 0 <= member.size <= MAX_FILE, "Rust transfer file shape/bound invalid")
            total += member.size
            if parts[0] == "vendor": vendor_total += member.size
            require(total <= MAX_TRANSFER and vendor_total <= MAX_VENDOR, "Rust transfer expanded size exceeds bound")
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            source = archive.extractfile(member)
            require(source is not None, "Rust transfer file lacks data")
            with source, path.open("xb") as output:
                remaining = member.size
                while remaining:
                    live(deadline); data = source.read(min(1024 * 1024, remaining))
                    require(bool(data), "Rust transfer file truncated")
                    output.write(data); remaining -= len(data)
                output.flush(); os.fsync(output.fileno())
            path.chmod(0o755 if member.mode & 0o111 else 0o644)
    require(seen and (work / "vendor").is_dir() and (work / "registry/cache").is_dir(), "Rust transfer lacks required payloads")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate Cargo checksum key")
        result[key] = value
    return result


def inventory(work: Path, locked: dict[str, dict[str, str]], deadline: float) -> tuple[list[dict[str, Any]], list[tuple[str, dict[str, Any], int]]]:
    vendor = work / "vendor"
    require({p.name for p in vendor.iterdir()} == set(locked), "vendored crate census differs from lock")
    caches = list((work / "registry/cache").iterdir())
    require(len(caches) == 1 and caches[0].is_dir() and not caches[0].is_symlink(), "ambiguous registry cache")
    require({p.name for p in caches[0].iterdir()} == {name + ".crate" for name in locked}, "cached crate census differs from lock")
    crates, files, total = [], [], 0
    for directory, pin in sorted(locked.items()):
        live(deadline)
        crate = caches[0] / (directory + ".crate")
        require(digest_file(crate, MAX_FILE, deadline)["sha256"] == pin["checksum"], "downloaded crate does not match Cargo.lock checksum")
        checksum_path = vendor / directory / ".cargo-checksum.json"
        checksums = json.loads(read_file(checksum_path, 16 * MAX_INPUT, deadline), object_pairs_hook=no_duplicates)
        require(type(checksums) is dict and set(checksums) == {"files", "package"}
            and checksums["package"] == pin["checksum"] and type(checksums["files"]) is dict, "vendor checksum contract differs")
        expected = checksums["files"]
        require(0 < len(expected) <= 50_000, "crate file census exceeds bound")
        for name, checksum in expected.items():
            safe_path(name)
            require(name != ".cargo-checksum.json" and type(checksum) is str and SHA.fullmatch(checksum) is not None,
                    "crate file checksum invalid")
        archive_files, archive_seen, expanded, count = {}, set(), 0, 0
        with tarfile.open(crate, "r:gz") as archive:
            for member in archive:
                live(deadline); count += 1
                name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
                parts = safe_path(name)
                require(parts[0] == directory and count <= 50_000 and (member.isdir() or member.isreg())
                    and not member.sparse and not member.mode & 0o7002 and name not in archive_seen, "locked crate archive member invalid")
                archive_seen.add(name)
                if member.isdir(): continue
                relative = "/".join(parts[1:])
                require(bool(relative) and 0 <= member.size <= MAX_FILE, "locked crate archive file shape/bound invalid")
                expanded += member.size
                require(expanded <= MAX_VENDOR, "locked crate expansion exceeds bound")
                require(relative not in archive_files, "locked crate archive has duplicate files")
                source = archive.extractfile(member)
                require(source is not None, "locked crate file data absent")
                digest = hashlib.sha256()
                with source:
                    while data := source.read(1024 * 1024):
                        live(deadline); digest.update(data)
                archive_files[relative] = digest.hexdigest()
        # Cargo 1.88 ops/vendor.rs calls sources/path.rs::list_files before
        # its own metadata filter. In particular, .cargo_vcs_info.json can
        # be omitted by package.include/exclude or the default dotfile rule;
        # it is not an unconditional fixed exclusion. Do not guess that
        # selection here or accept modified/extra selected bytes. The exact
        # omitted census remains visible in this unpublished candidate.
        require(all(archive_files.get(name) == checksum for name, checksum in expected.items()),
                "selected vendor file is absent from or differs from the locked crate archive")
        omitted = sorted(set(archive_files) - set(expected))
        seen, crate_bytes = set(), 0
        for current, directories, names in os.walk(vendor / directory, followlinks=False):
            directories.sort(); names.sort()
            for name in directories:
                path = Path(current) / name
                require(stat.S_ISDIR(path.lstat().st_mode), "vendor directory is a link or special file")
            for name in names:
                path = Path(current) / name
                relative = path.relative_to(vendor / directory).as_posix()
                safe_path(relative)
                require(relative == ".cargo-checksum.json" or relative in expected, "unaccounted vendored file")
                measured = digest_file(path, MAX_FILE, deadline)
                if relative != ".cargo-checksum.json":
                    require(measured["sha256"] == expected[relative], "vendored file checksum differs")
                    seen.add(relative)
                total += measured["size"]; crate_bytes += measured["size"]
                require(total <= MAX_VENDOR and len(files) < MAX_MEMBERS - MAX_CRATES - 1, "vendor archive bounds exceeded")
                files.append(("vendor/" + directory + "/" + relative, measured, 0o755 if path.stat().st_mode & 0o111 else 0o644))
        require(seen == set(expected), "vendored crate missing checksum files")
        crates.append({**pin, "directory": directory, "files": len(expected), "bytes": crate_bytes,
            "omitted_archive_files": omitted,
            "checksum_manifest_sha256": digest_file(checksum_path, 16 * MAX_INPUT, deadline)["sha256"]})
    return crates, sorted(files)


class BoundedWriter:
    def __init__(self, target=None):
        self.target, self.size, self.digest = target, 0, hashlib.sha256()
    def write(self, data):
        self.size += len(data)
        require(self.size <= MAX_ARCHIVE, "vendor compressed archive exceeds reviewed verifier bound")
        self.digest.update(data)
        if self.target is not None: self.target.write(data)
        return len(data)
    def flush(self):
        if self.target is not None: self.target.flush()


def package(work: Path, files, output: BoundedWriter, deadline: float) -> None:
    with gzip.GzipFile(filename="", mode="wb", compresslevel=9, mtime=0, fileobj=output) as compressed:
        with tarfile.open(mode="w|", fileobj=compressed, format=tarfile.PAX_FORMAT) as archive:
            directories = {"vendor"}
            for name, _, _ in files:
                directories.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
            require(len(directories) + len(files) <= MAX_MEMBERS, "normalized vendor tar member count exceeds bound")
            for name in sorted(directories):
                info = tarfile.TarInfo(name); info.type, info.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(info)
            for name, measured, mode in files:
                live(deadline)
                path = work / name
                require(digest_file(path, MAX_FILE, deadline) == measured, "verified vendor original changed before packaging")
                info = tarfile.TarInfo(name); info.size, info.mode = measured["size"], mode
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "rb") as source:
                    before = os.fstat(source.fileno()); archive.addfile(info, source)
                    require(identity(before) == identity(os.fstat(source.fileno())), "vendor original changed during packaging")


def prepare_vendor(candidate: Path, expected_commit: str) -> dict[str, Any]:
    deadline = time.monotonic() + SECONDS
    require(os.geteuid() != 0, "run Rust candidate preparation as an unprivileged operator")
    candidate = candidate.absolute()
    nvme = Path("/srv/catchplate-fast")
    require(candidate.is_dir() and candidate.resolve() == candidate and nvme in candidate.parents
        and candidate.stat().st_dev == nvme.stat().st_dev and candidate.stat().st_uid == os.geteuid()
        and candidate.stat().st_mode & 0o022 == 0 and ROOT not in candidate.parents,
        "candidate must be a real task-owned protected NVMe directory outside the checkout")
    require(shutil.disk_usage(candidate).free >= MIN_FREE, "Rust vendor preparation requires at least12GiB free")
    captured = capture(expected_commit, candidate, deadline)
    locked = lock_inventory(captured[INPUTS[0]], captured[INPUTS[1]])
    work, cache = candidate / "work/rust-download", candidate / "snapshot/cache"
    for parent in (work.parent, cache):
        require(parent.is_dir() and parent.resolve() == parent and parent.stat().st_uid == os.geteuid()
            and parent.stat().st_mode & 0o022 == 0, "candidate work/cache parent is not a protected original")
    require(not work.exists() and not work.is_symlink() and not (cache / "cargo-vendor.tar.gz").exists(), "Rust candidate outputs must be fresh")
    work.mkdir(mode=0o700); (work / "docker-config").mkdir(mode=0o700)
    env = docker_environment(work / "docker-config")
    image = json.loads(subprocess.run(["docker", "--host=unix:///var/run/docker.sock", "image", "inspect", RUST_IMAGE],
        env=env, check=True, timeout=min(30, live(deadline)), stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout)
    pinned_digest = RUST_IMAGE.split("@", 1)[1]
    require(type(image) is list and len(image) == 1 and image[0].get("Os") == "linux"
        and image[0].get("Architecture") == "amd64" and any(value in image[0].get("RepoDigests", [])
            for value in ("rust@" + pinned_digest, "docker.io/library/rust@" + pinned_digest)),
        "exact pinned Linux/amd64 Rust image must already be available; pulling is forbidden")
    image_id = image[0].get("Id", "")
    require(type(image_id) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is not None, "builder lacks immutable image ID")
    download(work, candidate, image_id, deadline)
    unpack(work, deadline)
    crates, files = inventory(work, locked, deadline)
    archive_path = cache / "cargo-vendor.tar.gz"
    with archive_path.open("xb") as stream:
        output = BoundedWriter(stream); package(work, files, output, deadline)
        stream.flush(); os.fsync(stream.fileno())
    repeated = BoundedWriter(); package(work, files, repeated, deadline)
    measured = digest_file(archive_path, MAX_ARCHIVE, deadline)
    require(measured == {"sha256": output.digest.hexdigest(), "size": output.size}
        and output.size == repeated.size and output.digest.digest() == repeated.digest.digest(), "vendor packaging is not deterministic")
    require(sum(item[1]["size"] for item in files) <= measured["size"] * 200, "vendor archive exceeds reviewed expansion-ratio bound")
    require(capture(expected_commit, candidate, deadline) == captured, "recorded Rust source changed during preparation")
    report = {"archive": measured, "crates": crates, "builder": {"reference": RUST_IMAGE, "image_id": image_id},
        "inputs": {name: hashlib.sha256(captured[name]).hexdigest() for name in INPUTS},
        "source_commit": expected_commit, "offline_integrity_verified": True, "deterministic_packaging": True,
        "published": False, "reviewed_pins_installed": False, "production_release_authority": False}
    with (work / "result.json").open("xb") as stream:
        stream.write(canonical(report)); stream.flush(); os.fsync(stream.fileno())
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    report = prepare_vendor(args.candidate, args.expected_commit)
    print(canonical(report).decode("ascii"), end="")


if __name__ == "__main__": main()
