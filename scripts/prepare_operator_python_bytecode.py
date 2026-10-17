#!/usr/bin/env python3
"""Prepare separately pinned, read-only ordinary-app Python bytecode.

source-manifest runs on the host; compile/verify-consumption run in the exact
app image under the caller's bounded launcher. This helper does not launch or
authenticate a container. The launcher's retained inspect receipt proves the
actual image; this manifest binds its required identity and observed interpreter.
No application import, source write, network request, or runtime admission occurs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import re
import stat
import subprocess
import sys

APP_IMAGE = "sha256:ec14a558a42e483a834860521e399b461a2df880fcba495e7127b0d8d2a51e01"
INTERPRETER = {"version": "3.11.15 (main, Jul 14 2026, 02:08:37) [GCC 14.2.0]",
    "versionInfo": [3, 11, 15, "final", 0], "implementation": "cpython",
    "cacheTag": "cpython-311", "magicHex": "a70d0d0a", "optimization": 0}
SCRIPT = "scripts/prepare_operator_python_bytecode.py"
PACKAGES = {"catchplate": "cache/catchplate", "catchplate/authority_store": "cache/authority_store"}
MAX_FILES, MAX_SOURCE, MAX_PYC, MAX_TOTAL, MAX_MANIFEST = 4096, 8 << 20, 16 << 20, 256 << 20, 2 << 20


def require(value):
    if not value:
        raise ValueError("Python bytecode artifact refused")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _hex(value, length=64):
    require(type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value))
    return value


def _path(value):
    path = Path(value)
    require(path.is_absolute() and str(path) == os.fspath(value) and ".." not in path.parts
        and path.resolve() == path)
    return path


def _stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
        info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _read(path, limit, *, immutable=False):
    _path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit)
    if immutable:
        require(before.st_size > 0 and stat.S_IMODE(before.st_mode) == 0o444)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        require(_stamp(os.fstat(stream.fileno())) == _stamp(before))
        raw = stream.read(limit + 1)
    require(len(raw) == before.st_size and _stamp(path.lstat()) == _stamp(before))
    return raw, _stamp(before)


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def _json(raw):
    def invalid(_):
        raise ValueError("Python bytecode artifact refused")
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=invalid)
    require(canonical(value) == raw)
    return value


def _git(repository, *arguments):
    raw = subprocess.check_output(["/usr/bin/git", "--no-replace-objects", "-C", str(repository),
        "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "gc.auto=0", *arguments],
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": ""},
        stderr=subprocess.DEVNULL, timeout=30)
    require(len(raw) <= 8 << 20)
    return raw


def _source_record(source, commit, repository):
    source, repository = _path(source), _path(repository)
    _hex(commit, 40)
    helper = _git(repository, "cat-file", "blob", commit + ":" + SCRIPT)
    require(helper == _read(source / SCRIPT, MAX_SOURCE)[0] == _read(Path(__file__).resolve(), MAX_SOURCE)[0])
    files, total = [], 0
    for entry in _git(repository, "ls-tree", "-rz", "--full-tree", commit, "--", "catchplate").split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        name = name.decode("utf-8")
        if not name.endswith(".py"):
            continue
        mode, kind, oid = metadata.decode("ascii").split()
        require(mode in {"100644", "100755"} and kind == "blob")
        require(Path(name).parent.as_posix() in PACKAGES and re.fullmatch(r"[A-Za-z0-9_]+\.py", Path(name).name))
        raw, _ = _read(source / name, MAX_SOURCE)
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid)
        files.append({"path": name, "gitBlob": oid, "sha256": sha(raw), "size": len(raw)})
        total += len(raw)
        require(len(files) <= MAX_FILES and total <= MAX_TOTAL)
    require(files)
    files.sort(key=lambda item: item["path"])
    return {"schema": "catchplate.operatorPythonBytecodeSource/v1", "sourceCommit": commit,
        "image": APP_IMAGE, "helperSha256": sha(helper), "sourceTreeSha256": sha(canonical(files)), "files": files}


def _source_check(record, source):
    require(type(record) is dict and set(record) == {"schema", "sourceCommit", "image", "helperSha256", "sourceTreeSha256", "files"}
        and record["schema"] == "catchplate.operatorPythonBytecodeSource/v1" and record["image"] == APP_IMAGE)
    _hex(record["sourceCommit"], 40)
    _hex(record["helperSha256"]); _hex(record["sourceTreeSha256"])
    require(sha(_read(source / SCRIPT, MAX_SOURCE)[0]) == record["helperSha256"]
        == sha(_read(Path(__file__).resolve(), MAX_SOURCE)[0]))
    files = record["files"]
    require(type(files) is list and 0 < len(files) <= MAX_FILES and sha(canonical(files)) == record["sourceTreeSha256"])
    names, total = [], 0
    for item in files:
        require(type(item) is dict and set(item) == {"path", "gitBlob", "sha256", "size"})
        name = item["path"]
        require(type(name) is str and Path(name).parent.as_posix() in PACKAGES
            and re.fullmatch(r"[A-Za-z0-9_]+\.py", Path(name).name))
        _hex(item["gitBlob"], 40); _hex(item["sha256"])
        require(type(item["size"]) is int and 0 <= item["size"] <= MAX_SOURCE)
        raw, _ = _read(source / name, MAX_SOURCE)
        require(len(raw) == item["size"] and sha(raw) == item["sha256"]
            and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == item["gitBlob"])
        names.append(name); total += len(raw)
        require(total <= MAX_TOTAL)
    require(names == sorted(set(names)))


def _interpreter():
    value = {"version": sys.version, "versionInfo": list(sys.version_info),
        "implementation": sys.implementation.name, "cacheTag": sys.implementation.cache_tag,
        "magicHex": importlib.util.MAGIC_NUMBER.hex(), "optimization": sys.flags.optimize}
    require(value == INTERPRETER and sys.pycache_prefix is None and sys.dont_write_bytecode)
    return value


def _cache_path(name):
    path = Path(name)
    return PACKAGES[path.parent.as_posix()] + "/" + path.stem + ".cpython-311.pyc"


def _new_directory(value):
    path = _path(value)
    require(path.parent.is_dir() and not path.exists() and not path.is_symlink())
    path.mkdir(mode=0o700)
    return path


def _write(path, raw):
    with path.open("xb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    path.chmod(0o444)


def _freeze(root):
    for directory in (root / "cache/catchplate", root / "cache/authority_store", root / "cache", root):
        if directory.exists():
            directory.chmod(0o555)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)


def source_manifest(*, source, commit, output, repository=None):
    record = _source_record(source, commit, repository or Path(__file__).resolve().parents[1])
    require(not _path(output).is_relative_to(_path(source)) and not _path(source).is_relative_to(_path(output)))
    root = _new_directory(output)
    raw = canonical(record)
    _write(root / "source-manifest.json", raw); _freeze(root)
    return {"sourceManifestSha256": sha(raw), "sourceCommit": commit, "files": len(record["files"])}


def compile_artifact(*, source, source_manifest_path, expected_source_manifest_sha256, output):
    source = _path(source)
    require(source == Path("/app"))
    interpreter = _interpreter()
    raw, _ = _read(_path(source_manifest_path), MAX_MANIFEST, immutable=True)
    require(sha(raw) == _hex(expected_source_manifest_sha256))
    record = _json(raw); _source_check(record, source)
    require(not _path(output).is_relative_to(source) and not source.is_relative_to(_path(output)))
    root = _new_directory(output)
    for relative in ("cache", "cache/catchplate", "cache/authority_store"):
        (root / relative).mkdir(mode=0o700)
    payload, total = [], 0
    for item in record["files"]:
        target = root / _cache_path(item["path"])
        py_compile.compile(str(source / item["path"]), cfile=str(target),
            dfile="/app/" + item["path"], doraise=True, optimize=0,
            invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)
        target.chmod(0o444)
        value, _ = _read(target, MAX_PYC, immutable=True)
        source_raw, _ = _read(source / item["path"], MAX_SOURCE)
        require(sha(source_raw) == item["sha256"] and len(source_raw) == item["size"]
            and value[:4].hex() == interpreter["magicHex"] and value[4:8] == b"\x03\0\0\0"
            and value[8:16] == importlib.util.source_hash(source_raw))
        payload.append({"path": target.relative_to(root).as_posix(), "sha256": sha(value), "size": len(value),
            "sourceHashHex": value[8:16].hex()})
        total += len(value); require(total <= MAX_TOTAL)
    _source_check(record, source)
    manifest = {"schema": "catchplate.operatorPythonBytecode/v1", "source": record,
        "sourceManifestSha256": sha(raw), "interpreter": interpreter, "files": payload}
    result = canonical(manifest); require(len(result) <= MAX_MANIFEST)
    _write(root / "manifest.json", result); _freeze(root)
    return {"manifestSha256": sha(result), "sourceCommit": record["sourceCommit"],
        "files": len(payload), "bytecodeBytes": total, "image": APP_IMAGE,
        "imageProvenance": "requires-caller-launch-receipt"}


def mounts(root):
    # Pure projection for daemonless recipes; validate() owns filesystem admission.
    root = Path(root)
    require(root.is_absolute() and ".." not in root.parts)
    return [{"type": "bind", "source": str(root / leaf), "target": "/app/" + package + "/__pycache__",
        "read_only": True, "bind": {"create_host_path": False}} for package, leaf in PACKAGES.items()]


def _artifact(root, source, expected_manifest_sha256):
    root, source = _path(root), _path(source)
    require(not root.is_relative_to(source) and not source.is_relative_to(root))
    raw, _ = _read(root / "manifest.json", MAX_MANIFEST, immutable=True)
    require(sha(raw) == _hex(expected_manifest_sha256))
    manifest = _json(raw)
    require(type(manifest) is dict and set(manifest) == {"schema", "source", "sourceManifestSha256", "interpreter", "files"}
        and manifest["schema"] == "catchplate.operatorPythonBytecode/v1"
        and canonical(manifest["interpreter"]) == canonical(INTERPRETER))
    _source_check(manifest["source"], source)
    require(manifest["sourceManifestSha256"] == sha(canonical(manifest["source"])))
    files, inputs = manifest["files"], manifest["source"]["files"]
    require(type(files) is list and len(files) == len(inputs))
    expected = {"manifest.json"}; identities, total = [], 0
    for item, original in zip(files, inputs):
        require(type(item) is dict and set(item) == {"path", "sha256", "size", "sourceHashHex"}
            and item["path"] == _cache_path(original["path"]))
        _hex(item["sha256"]); _hex(item["sourceHashHex"], 16)
        require(type(item["size"]) is int and 16 < item["size"] <= MAX_PYC)
        value, identity = _read(root / item["path"], MAX_PYC, immutable=True)
        require(len(value) == item["size"] and sha(value) == item["sha256"]
            and value[:4].hex() == INTERPRETER["magicHex"] and value[4:8] == b"\x03\0\0\0"
            and value[8:16].hex() == item["sourceHashHex"])
        expected.add(item["path"]); identities.append([item["path"], identity])
        total += len(value); require(total <= MAX_TOTAL)
    directories = {"", "cache", "cache/catchplate", "cache/authority_store"}
    observed = set()
    for relative in sorted(directories):
        directory = root / relative
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o555)
        identities.append([relative, _stamp(info)])
        for path in directory.iterdir():
            name = path.relative_to(root).as_posix()
            require(not path.is_symlink() and (name in directories or name in expected))
            if name in expected:
                observed.add(name)
    require(observed == expected)
    identities.append(["manifest.json", _read(root / "manifest.json", MAX_MANIFEST, immutable=True)[1]])
    return manifest, {"schema": "catchplate.operatorPythonBytecodeValidation/v1",
        "manifestSha256": sha(raw), "sourceCommit": manifest["source"]["sourceCommit"],
        "sourceTreeSha256": manifest["source"]["sourceTreeSha256"], "image": APP_IMAGE,
        "interpreter": INTERPRETER.copy(), "files": len(files), "bytecodeBytes": total,
        "artifactIdentitySha256": sha(canonical(sorted(identities)))}


def validate(root, *, source, commit, expected_manifest_sha256, repository=None):
    manifest, receipt = _artifact(root, source, expected_manifest_sha256)
    actual = _source_record(source, commit, repository or Path(__file__).resolve().parents[1])
    # Source-only/docs-only followups reuse bytecode only when the entire selected
    # source/helper roster still equals committed objects and the producer input.
    require({key: value for key, value in actual.items() if key != "sourceCommit"}
        == {key: value for key, value in manifest["source"].items() if key != "sourceCommit"})
    for package in PACKAGES:
        mountpoint = _path(Path(source) / package / "__pycache__")
        require(stat.S_ISDIR(mountpoint.lstat().st_mode))
    receipt["producerCommit"], receipt["sourceCommit"] = receipt["sourceCommit"], commit
    return receipt


def _cached_code(path):
    """Read/unmarshal code without execution; a cache miss is a hard refusal."""
    class CachedOnly(importlib.machinery.SourceFileLoader):
        def source_to_code(self, *args, **kwargs):
            raise ValueError("Python bytecode cache was not consumed")
    return CachedOnly("bytecode_consumption_probe", str(path)).get_code("bytecode_consumption_probe")


def verify_consumption(*, source, artifact, expected_manifest_sha256):
    require(_path(source) == Path("/app"))
    _interpreter()
    manifest, receipt = _artifact(artifact, source, expected_manifest_sha256)
    for item in manifest["source"]["files"]:
        path = Path(source) / item["path"]
        mounted = Path(importlib.util.cache_from_source(str(path)))
        expected = Path(artifact) / _cache_path(item["path"])
        require(_read(mounted, MAX_PYC, immutable=True)[0] == _read(expected, MAX_PYC, immutable=True)[0])
        code = _cached_code(path)
        require(code is not None and code.co_filename == "/app/" + item["path"])
    return {"cachedCodeLoadedWithoutExecution": True, "files": receipt["files"],
        "manifestSha256": expected_manifest_sha256}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="phase", required=True)
    prepare = sub.add_parser("source-manifest")
    for name in ("source", "commit", "output"):
        prepare.add_argument("--" + name, required=True)
    prepare.add_argument("--repository")
    compile_parser = sub.add_parser("compile")
    for name in ("source", "source-manifest-path", "expected-source-manifest-sha256", "output"):
        compile_parser.add_argument("--" + name, required=True)
    consume = sub.add_parser("verify-consumption")
    for name in ("source", "artifact", "expected-manifest-sha256"):
        consume.add_argument("--" + name, required=True)
    args = vars(parser.parse_args()); phase = args.pop("phase")
    function = {"source-manifest": source_manifest, "compile": compile_artifact, "verify-consumption": verify_consumption}[phase]
    try:
        print(json.dumps(function(**args), sort_keys=True))
    except Exception:
        print('{"ok":false,"error":"Python bytecode artifact refused"}')
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
