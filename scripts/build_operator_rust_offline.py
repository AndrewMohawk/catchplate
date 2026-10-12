#!/usr/bin/env python3
"""One-shot ordinary Rust engineering build from committed Git objects.

No pulls, installs, tests, deployment or native commissioning. A retained target
is only a compiler cache, not an authenticated release. Copy each selected tree
once into new inodes; never edit the predecessor or retained cache/vendor. The
existing conservative snapshot helper is unchanged. Artifact receipts always
say tested=false. Use an explicit reviewed full commit, not HEAD or worktree.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import prepare_operator_build_snapshot as snapshot
from scripts.run_ordinary_regression import child_exit_status, stop_group

IMAGE = "rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89"
IMAGE_ID = "sha256:c8211ab4ab64eb72091912fa408ac59daaeb56d0ae1a2bf243c08753777c4382"
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
LABEL = "com.serverware.ordinary-rust-build"
MAX_LOG = 32 * 1024 * 1024
MAX_COPY = 6 * 1024**3
RESERVE = 16 * 1024**3
CONFIG = b'[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "/vendor"\n'
ADDITIONS = {"rustls-0.23.45": "0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634",
             "rustls-webpki-0.103.14": "0527518605e68109d875e248ea259b6758801cf165e4b2c2733ae3b51f12535a"}
OWN_SOURCES = ("scripts/build_operator_rust_offline.py", "scripts/prepare_operator_build_snapshot.py",
               "scripts/run_ordinary_regression.py")


class Refused(ValueError):
    pass


def need(value, message="ordinary Rust build refused"):
    if not value:
        raise Refused(message)


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: need(False, "nonfinite JSON"))


def read(path, maximum, *, allow_hardlinks=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and (allow_hardlinks or before.st_nlink == 1) and before.st_size <= maximum)
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(maximum + 1)
        need(len(raw) == before.st_size and snapshot._stamp(os.fstat(fd)) == snapshot._stamp(before)
             and snapshot._stamp(path.lstat()) == snapshot._stamp(before), "input changed")
        return raw
    finally:
        os.close(fd)


def save(path, value):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())


def inventory(root, *, allow_internal_hardlinks=False):
    """Metadata only; actual bytes are hashed during the single private copy."""
    fd = snapshot._directory(root)
    os.close(fd)
    rows, total, directories = {}, 0, 0
    for parent, dirs, files in os.walk(root, followlinks=False):
        directories += 1
        need(directories <= 20000 and len(Path(parent).relative_to(root).parts) <= 64, "retained directory bound")
        for path in [Path(parent), *(Path(parent) / name for name in files + dirs)]:
            info = path.lstat()
            need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), "tree contains link/special file")
            need(not info.st_mode & 0o7002, "unsafe retained mode")
            if stat.S_ISREG(info.st_mode):
                name = path.relative_to(root).as_posix()
                need((allow_internal_hardlinks or info.st_nlink == 1) and info.st_size <= 512 * 1024**2, "unsafe retained file")
                total += info.st_size
                need(total <= MAX_COPY and len(rows) < 100000, "retained tree bound")
                rows[name] = list(snapshot._stamp(info))
    need(rows, "empty retained tree")
    aliases = {}
    for row in rows.values():
        identity = tuple(row[:2])
        aliases[identity] = aliases.get(identity, 0) + 1
    need(all(row[3] == aliases[tuple(row[:2])] for row in rows.values()), "unaccounted retained hardlink")
    return rows


def verify_predecessor_pins(pins, predecessor):
    need(type(pins) is dict and pins.get("sourceRoot") == str(predecessor)
         and type(pins.get("files")) is dict and 1 <= len(pins["files"]) <= 4096)
    for name, digest in pins["files"].items():
        need(type(name) is str and not name.startswith("/") and "\\" not in name
             and all(part not in ("", ".", "..") for part in name.split("/"))
             and type(digest) is str and re.fullmatch("[0-9a-f]{64}", digest))
        path = predecessor / name
        fd = snapshot._directory(path.parent)
        os.close(fd)
        need(hashlib.sha256(read(path, 16 * 1024**2)).hexdigest() == digest, "cache source pin differs from predecessor")


def copy_tree(source, destination, before):
    destination.mkdir(mode=0o700)
    digests = {}
    for name, expected in sorted(before.items()):
        path = source / name
        raw_mode = stat.S_IMODE(expected[2])
        output = destination / name
        output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME)
        try:
            need(list(snapshot._stamp(os.fstat(fd))) == expected, "retained file changed")
            digest, count = hashlib.sha256(), 0
            with output.open("xb") as writer:
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    count += len(chunk)
                    need(count <= expected[6])
                    writer.write(chunk)
                    digest.update(chunk)
                writer.flush()
                os.fchmod(writer.fileno(), raw_mode)
                os.utime(writer.fileno(), ns=(expected[7], expected[7]))
                info = os.fstat(writer.fileno())
                need((info.st_dev, info.st_ino) != tuple(expected[:2]) and info.st_nlink == 1)
            need(count == expected[6] and list(snapshot._stamp(os.fstat(fd))) == expected
                 and list(snapshot._stamp(path.lstat())) == expected, "retained copy drift")
            digests[name] = digest.hexdigest()
        finally:
            os.close(fd)
    need(inventory(source, allow_internal_hardlinks=any(row[3] > 1 for row in before.values())) == before, "retained tree changed during copy")
    return digests


def unpack(archive, package, checksum, vendor):
    raw = read(archive, 2 * 1024**2)
    need(hashlib.sha256(raw).hexdigest() == checksum, "archive checksum differs from lock")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as source:
        members, seen, total = [], set(), 0
        for entry in source:
            name = entry.name.rstrip("/") if entry.isdir() else entry.name
            parts = name.split("/")
            need(parts[0] == package and all(part not in ("", ".", "..") for part in parts)
                 and "\\" not in name and len(name.encode()) <= 1024
                 and all(ord(c) >= 32 and ord(c) != 127 for c in name)
                 and name not in seen and (entry.isfile() or entry.isdir())
                 and not entry.mode & 0o7000 and 0 <= entry.size <= 16 * 1024**2
                 and parts[-1] != ".cargo-checksum.json", "unsafe crate member")
            need(len(parts) > 1 or entry.isdir(), "crate root is not a directory")
            seen.add(name)
            total += entry.size
            need(len(seen) <= 10000 and total <= 64 * 1024**2, "crate expansion bound")
            members.append((entry, PurePosixPath(*parts[1:])))
        destination = vendor / package
        destination.mkdir(mode=0o755)
        files = {}
        for entry, relative in members:
            if str(relative) == ".":
                continue
            path = destination / relative
            if entry.isdir():
                path.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            reader = source.extractfile(entry)
            need(reader is not None)
            with reader:
                body = reader.read(entry.size + 1)
            need(len(body) == entry.size)
            with path.open("xb") as output:
                output.write(body)
                os.fchmod(output.fileno(), 0o555 if entry.mode & 0o111 else 0o444)
            files[relative.as_posix()] = hashlib.sha256(body).hexdigest()
        need(files, "empty crate")
        save(destination / ".cargo-checksum.json", {"files": files, "package": checksum})
    return {package + "/" + name: value for name, value in files.items()}


def verify_vendor(lock, vendor, digests):
    for package in lock["package"]:
        if "source" not in package:
            need(package["name"] == "serverware-decision-gate", "unexpected local dependency")
            continue
        need(package["source"] == "registry+https://github.com/rust-lang/crates.io-index")
        name = package["name"] + "-" + package["version"]
        value = document(read(vendor / name / ".cargo-checksum.json", 4 * 1024**2))
        need(type(value) is dict and set(value) == {"files", "package"}
             and value["package"] == package["checksum"] and type(value["files"]) is dict)
        actual = {key[len(name) + 1:]: digest for key, digest in digests.items()
                  if key.startswith(name + "/") and key != name + "/.cargo-checksum.json"}
        need(actual == value["files"], "vendored bytes differ from package checksum roster")


def freeze(root):
    for parent, dirs, files in os.walk(root, topdown=False):
        for name in files:
            path = Path(parent) / name
            path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
        Path(parent).chmod(0o555)


def command(directory, name, argv, seconds, *, watch_space=False):
    save(directory / (name + ".command.json"), argv)
    started, size, outcome, code = time.monotonic(), 0, "completed", None
    with (directory / (name + ".stdout.log")).open("xb") as out, (directory / (name + ".stderr.log")).open("xb") as err:
        os.fchmod(out.fileno(), 0o600)
        os.fchmod(err.fileno(), 0o600)
        process = subprocess.Popen(argv, env=ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, out)
                selector.register(process.stderr, selectors.EVENT_READ, err)
                while selector.get_map() or child_exit_status(process) is None:
                    if time.monotonic() - started > seconds:
                        outcome = "timeout"
                        break
                    if watch_space and shutil.disk_usage(directory).free < RESERVE:
                        outcome = "disk_reserve"
                        break
                    for key, _ in selector.select(0.1):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        if size > MAX_LOG:
                            outcome = "output_limit"
                            break
                        key.data.write(chunk)
                    if outcome != "completed":
                        break
                code = child_exit_status(process)
        finally:
            try:
                stop_group(process)  # WNOWAIT ownership, kill descendants, then reap.
            finally:
                process.stdout.close()
                process.stderr.close()
    save(directory / (name + ".host.json"), {"status": outcome, "exitCode": code,
        "seconds": round(time.monotonic() - started, 3), "bytes": min(size, MAX_LOG)})
    return code if outcome == "completed" else 124


def docker_output(directory, name, arguments):
    need(command(directory, name, DOCKER + arguments, 30) == 0, "Docker command failed")
    return read(directory / (name + ".stdout.log"), 1024**2).strip()


def create_arguments(root, name, token, kind):
    need(kind in ("test", "normal"))
    cargo = ["cargo", "test" if kind == "test" else "build", "--release", "--frozen", "--offline",
             "--bin", "serverware-decision-gate", "--message-format=json"]
    if kind == "test":
        cargo.append("--no-run")
    return ["create", "--pull", "never", "--name", name, "--label", LABEL + "=" + token,
        "--network", "none", "--ipc", "none", "--read-only", "--restart", "no", "--no-healthcheck",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--cpus", "2",
        "--cpu-shares", "256", "--memory", "24g", "--memory-swap", "24g", "--pids-limit", "512",
        "--user", "1000:1000", "--ulimit", "core=0:0", "--log-driver", "local",
        "--log-opt", "max-size=32m", "--log-opt", "max-file=2",
        "--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=1g,mode=1777",
        "--tmpfs", "/cargo-home:rw,nosuid,nodev,noexec,size=256m,uid=1000,gid=1000",
        "--mount", f"type=bind,src={root}/source,dst=/repository,readonly",
        "--mount", f"type=bind,src={root}/vendor,dst=/vendor,readonly",
        "--mount", f"type=bind,src={root}/cargo-config.toml,dst=/cargo-home/config.toml,readonly",
        "--mount", f"type=bind,src={root}/target,dst=/target",
        "--workdir", "/repository/data-plane/decision-gate-rs",
        "--env", "CARGO_HOME=/cargo-home", "--env", "CARGO_TARGET_DIR=/target",
        "--env", "CARGO_NET_OFFLINE=true", "--env", "CARGO_BUILD_JOBS=2",
        "--env", "SOURCE_DATE_EPOCH=0", "--env", "RUSTFLAGS=-C link-arg=-Wl,--build-id=none",
        IMAGE, "timeout", "--signal=TERM", "--kill-after=10s", "1800s", *cargo]


def inspect_owned(directory, phase, cid, name, token):
    need(re.fullmatch("[0-9a-f]{64}", cid), "invalid container ID")
    template = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"Labels":{{json .Config.Labels}},"State":{{json .State}}}'
    row = document(docker_output(directory, phase, ["inspect", "--format", template, cid]))
    need(row["Id"] == cid and row["Name"] == "/" + name and row["Image"] == IMAGE_ID
         and row["Labels"].get(LABEL) == token, "container ownership changed")
    return row


def compile_artifact(root, kind):
    directory = root / kind
    directory.mkdir(mode=0o700)
    token = secrets.token_hex(16)
    name, cid = "serverware-ordinary-rust-" + token, None
    save(directory / "ownership.json", {"name": name, "label": LABEL, "token": token})
    need(not docker_output(directory, "existing", ["ps", "-aq", "--no-trunc", "--filter", "name=^/" + name + "$"]))
    try:
        code = command(directory, "create", DOCKER + create_arguments(root, name, token, kind), 30)
        candidate = read(directory / "create.stdout.log", 1024).decode("ascii").strip()
        if re.fullmatch("[0-9a-f]{64}", candidate):
            cid = candidate
        need(code == 0 and cid is not None, "container creation uncertain")
        inspect_owned(directory, "created", cid, name, token)
        code = command(directory, "attached", DOCKER + ["start", "--attach", cid], 1830, watch_space=True)
        row = inspect_owned(directory, "terminal", cid, name, token)
        need(code == 0 and row["State"]["Running"] is False and row["State"]["Pid"] == 0
             and row["State"]["ExitCode"] == 0 and row["State"]["OOMKilled"] is False, "compile failed")
    finally:
        if cid is None:
            found = docker_output(directory, "recover", ["ps", "-aq", "--no-trunc", "--filter",
                "name=^/" + name + "$", "--filter", "label=" + LABEL + "=" + token]).decode().splitlines()
            need(len(found) <= 1, "ambiguous creation")
            cid = found[0] if found else None
        if cid is not None:
            row = inspect_owned(directory, "cleanup-before", cid, name, token)
            if row["State"]["Running"]:
                command(directory, "stop", DOCKER + ["stop", "--time", "10", cid], 20)
                row = inspect_owned(directory, "cleanup-stopped", cid, name, token)
            if row["State"]["Running"]:
                command(directory, "kill", DOCKER + ["kill", cid], 10)
                row = inspect_owned(directory, "cleanup-killed", cid, name, token)
            need(not row["State"]["Running"] and row["State"]["Pid"] == 0, "owned container remains live")
            need(docker_output(directory, "remove", ["rm", cid]).decode() == cid)
        need(not docker_output(directory, "remaining", ["ps", "-aq", "--no-trunc",
             "--filter", "label=" + LABEL + "=" + token]), "cleanup incomplete")
        save(directory / "cleanup.json", {"ok": True, "containerId": cid, "ownedContainersRemaining": 0})
    return artifact(root, kind, read(directory / "attached.stdout.log", MAX_LOG))


def artifact(root, kind, output):
    found, finished = [], []
    for line in output.splitlines():
        row = document(line)
        if row.get("reason") == "build-finished":
            finished.append(row.get("success"))
        if row.get("reason") == "compiler-artifact" and row.get("target", {}).get("name") == "serverware-decision-gate" \
                and row.get("target", {}).get("kind") == ["bin"] and row.get("profile", {}).get("test") is (kind == "test") \
                and row.get("executable") is not None:
            found.append(row)
    need(finished == [True] and len(found) == 1, "missing unique successful Cargo artifact")
    expected = r"/target/release/deps/serverware_decision_gate-[0-9a-f]{16}" if kind == "test" else r"/target/release/serverware-decision-gate"
    need(re.fullmatch(expected, found[0]["executable"]), "unexpected artifact path")
    path = root / "target" / found[0]["executable"].removeprefix("/target/")
    inventory(root / "target", allow_internal_hardlinks=True)
    body = read(path, 512 * 1024**2, allow_hardlinks=True)
    need(body.startswith(b"\x7fELF") and path.stat().st_mode & 0o111, "artifact is not executable ELF")
    destination = root / ("test-binary" if kind == "test" else "serverware-decision-gate")
    with destination.open("xb") as stream:
        stream.write(body)
        os.fchmod(stream.fileno(), 0o555)
    return {"kind": kind, "path": str(destination), "sha256": hashlib.sha256(body).hexdigest(),
        "bytes": len(body), "cargoFresh": found[0]["fresh"], "tested": False, "deployed": False}


def run(args):
    need(os.getuid() == 1000 and os.getgid() == 1000, "build wrapper requires UID/GID 1000")
    names = ("repository", "output", "predecessor", "cache", "vendor", "cache_receipt", "cache_source_pins")
    for name in names:
        setattr(args, name, snapshot._absolute(getattr(args, name)))
    need(re.fullmatch("[0-9a-f]{40}", args.revision) and re.fullmatch("[0-9a-f]{40}", args.predecessor_revision))
    roots = [getattr(args, name) for name in ("repository", "output", "predecessor", "cache", "vendor")]
    need(all(not a.is_relative_to(b) and not b.is_relative_to(a) for i, a in enumerate(roots) for b in roots[i + 1:]), "overlapping roots")
    fd = snapshot._directory(args.output.parent)
    os.close(fd)
    need(not args.output.exists() and not args.output.is_symlink(), "output must be absent")
    need(shutil.disk_usage(args.output.parent).free >= RESERVE + MAX_COPY, "insufficient disk reserve")
    cache_before, vendor_before = inventory(args.cache, allow_internal_hardlinks=True), inventory(args.vendor)
    need(sum(v[6] for tree in (cache_before, vendor_before) for v in tree.values()) <= MAX_COPY)
    floor = max(v[7] for v in cache_before.values())
    prior = document(read(args.cache_receipt, 65536))
    pins_raw = read(args.cache_source_pins, 2 * 1024**2)
    pins = document(pins_raw)
    need(prior["schema"] == "serverware.privateProxyRelease/v1" and prior["compilerImageId"] == IMAGE_ID
         and prior["executable"] == str(args.cache / "release/serverware-decision-gate")
         and prior["tested"] is True and prior["sourcePinsSha256"] == hashlib.sha256(pins_raw).hexdigest()
         and pins["sourceRoot"] == str(args.predecessor), "retained provenance receipt mismatch")
    args.output.mkdir(mode=0o700)
    phase, results = "source", []
    try:
        receipt = snapshot.prepare_snapshot(args.repository, args.revision, args.output / "source",
            predecessor=args.predecessor, predecessor_revision=args.predecessor_revision,
            fresh_after_epoch_ns=floor)
        save(args.output / "source.json", receipt)
        verify_predecessor_pins(pins, args.predecessor)
        for relative in OWN_SOURCES:
            need(read(Path(__file__).resolve().parents[1] / relative, 1024**2)
                 == read(args.output / "source" / relative, 1024**2), "running build helper differs from frozen commit")
        crate = args.output / "source/data-plane/decision-gate-rs"
        for path in (args.output / "source/Cargo.toml", args.output / "source/data-plane/Cargo.toml",
                     crate / "build.rs", args.output / "source/.cargo", args.output / "source/data-plane/.cargo", crate / ".cargo"):
            need(not path.exists(), "unreviewed workspace/build configuration")
        manifest = tomllib.loads(read(crate / "Cargo.toml", 1024**2).decode())
        need("build" not in manifest["package"] and "workspace" not in manifest
             and "build-dependencies" not in manifest, "unreviewed build script")
        lock = tomllib.loads(read(crate / "Cargo.lock", 2 * 1024**2).decode())
        selected = {p["name"] + "-" + p["version"]: p["checksum"] for p in lock["package"] if "source" in p}
        missing = {name: value for name, value in selected.items() if not (args.vendor / name).is_dir()}
        need(missing == ADDITIONS, "unexpected missing vendor packages")
        phase = "copy"
        cache_hashes = copy_tree(args.cache, args.output / "target", cache_before)
        need(cache_hashes["release/serverware-decision-gate"] == prior["sha256"], "retained normal binary changed")
        vendor_hashes = copy_tree(args.vendor, args.output / "vendor", vendor_before)
        for path, package in ((args.rustls_archive, "rustls-0.23.45"), (args.webpki_archive, "rustls-webpki-0.103.14")):
            archive = snapshot._absolute(path)
            fd = snapshot._directory(archive.parent)
            os.close(fd)
            vendor_hashes.update(unpack(archive, package, missing[package], args.output / "vendor"))
        verify_vendor(lock, args.output / "vendor", vendor_hashes)
        with (args.output / "cargo-config.toml").open("xb") as stream:
            stream.write(CONFIG)
            os.fchmod(stream.fileno(), 0o444)
        freeze(args.output / "source")
        freeze(args.output / "vendor")
        save(args.output / "staged.json", {"cache": str(args.cache), "vendor": str(args.vendor),
            "cacheFileSha256": cache_hashes, "vendorFileSha256": vendor_hashes,
            "independentInodes": True, "retainedReleaseReceipt": prior, "cacheAuthenticated": False,
            "archiveChecksums": missing, "sourceReadOnly": True, "freshAfterEpochNs": floor})
        phase = "image"
        image = document(docker_output(args.output, "image", ["image", "inspect", "--format",
            '{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}}}', IMAGE]))
        need(image == {"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64"}, "cached compiler identity differs")
        for kind in (("test", "normal") if args.artifacts == "both" else (args.artifacts,)):
            phase = kind
            need(shutil.disk_usage(args.output).free >= RESERVE, "disk reserve exhausted")
            result = compile_artifact(args.output, kind)
            results.append(result)
            save(args.output / (kind + ".json"), {**result, "revision": args.revision,
                 "compilerImageId": IMAGE_ID, "sourceManifestSha256": receipt["manifestSha256"]})
        phase = "retained-check"
        need(inventory(args.cache, allow_internal_hardlinks=True) == cache_before and inventory(args.vendor) == vendor_before, "retained inputs changed")
        save(args.output / "result.json", {"ok": True, "revision": args.revision, "artifacts": results,
            "retainedInputsUnchanged": True, "tested": False, "deployed": False, "nativeAdmission": False})
    except BaseException:
        save(args.output / "failure.json", {"ok": False, "phase": phase, "artifacts": results,
            "tested": False, "deployed": False, "error": "ordinary Rust build failed"})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "revision", "output", "predecessor", "predecessor-revision", "cache",
                 "vendor", "cache-receipt", "cache-source-pins", "rustls-archive", "webpki-archive"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--artifacts", choices=("normal", "test", "both"), required=True)
    args = parser.parse_args()
    try:
        run(args)
    except Exception:
        print('{"ok":false,"error":"ordinary Rust build failed; inspect private receipts"}')
        return 1
    print('{"ok":true,"tested":false,"deployed":false}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
