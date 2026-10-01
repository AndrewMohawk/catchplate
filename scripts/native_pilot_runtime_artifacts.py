#!/usr/bin/env python3
"""Bounded, offline inventory of the fixed exported conductor rootfs.

Uses the existing artifact helpers' no-follow, before/after identity and SHA-256
read contract, extended to one explicitly selected tree. Symlinks are interpreted
in the recorded rootfs namespace, never resolved against the inspecting host.
This is source/package observation, not dependency approval or runtime admission.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

API_VERSION = "serverware.nativePilotConductorRuntime/v1"
MAX_ENTRIES = 50000
MAX_DEPTH = 32
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_SYMLINK_HOPS = 40
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
SOURCE_FIELDS = ("revision", "source_tree_digest", "source_manifest_digest",
                 "source_archive_digest", "source_date_epoch")
SOURCE_MANIFEST = "usr/share/serverware/source-manifest.json"
INTERPRETER = "runtime/python/bin/python3"
ENTRYPOINT = "app/scripts/native_pilot_runtime_entrypoint.py"
CONDUCTOR = "app/scripts/run_native_pilot.py"
COMMAND = ["/" + INTERPRETER, "-I", "-B", "/" + ENTRYPOINT, "--run-native-pilot"]
AUTHORITY_API_VERSION = "serverware.nativePilotAuthorityRuntime/v1"
AUTHORITY_TARGET = "native-pilot-authority-artifact"
AUTHORITY_ENTRYPOINT = "authority/app/scripts/native_pilot_authority_runtime_entrypoint.py"
AUTHORITY_FILES = (
    "scripts/native_pilot_authority_runtime_entrypoint.py",
    "scripts/run_native_pilot_authority_coordinator.py",
    "scripts/native_pilot_runtime_artifacts.py",
    "scripts/verify_nitro_tee.py",
    "scripts/authority/native_pilot_authority_io.py",
)
AUTHORITY_COMMAND = ["/" + INTERPRETER, "-I", "-B", "/" + AUTHORITY_ENTRYPOINT, "--run-native-pilot"]
READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _identity(info):
    return tuple(getattr(info, field) for field in (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def _text(value):
    return (isinstance(value, str) and 0 < len(value) <= MAX_PATH_BYTES
            and all(32 <= ord(character) < 127 and character != "\\" for character in value))


def _path(value):
    _require(_text(value) and not value.startswith("/")
             and all(part not in ("", ".", "..") and len(part) <= 255 for part in value.split("/"))
             and len(value.split("/")) <= MAX_DEPTH, "runtime artifact path exceeds its fixed spelling/bounds")


def _source(metadata):
    _require(isinstance(metadata, dict) and all(key in metadata for key in SOURCE_FIELDS),
             "runtime inventory requires the existing complete source identity")
    source = {key: metadata[key] for key in SOURCE_FIELDS}
    _require(isinstance(source["revision"], str) and re.fullmatch(r"[0-9a-f]{40}", source["revision"]) is not None,
             "conductor runtime requires an exact committed source identity")
    _require(all(isinstance(source[key], str) and DIGEST.fullmatch(source[key]) is not None
                 for key in SOURCE_FIELDS[1:4]), "runtime source digests are not canonical")
    epoch = source["source_date_epoch"]
    _require(isinstance(epoch, str) and re.fullmatch(r"0|[1-9][0-9]{0,11}", epoch) is not None
             and int(epoch) <= 253402300799, "runtime source epoch is outside the fixed archive bound")
    return source


class _Inventory:
    def __init__(self):
        self.records = {}
        self.identities = {}
        self.children = {}
        self.inodes = set()
        self.total = 0
        self.manifest = None
        self.interpreter_head = None

    def walk(self, descriptor, parent="", *, recheck=False):
        before = os.fstat(descriptor)
        _require(stat.S_ISDIR(before.st_mode), "runtime inventory directory changed type")
        if recheck:
            _require(_identity(before) == self.identities[parent], "runtime directory changed after inventory")
        else:
            self.identities[parent] = _identity(before)
        names = set()
        # Open a fresh directory OFD: scandir's duplicated FD otherwise shares
        # an enumeration offset with a retained descriptor on repeated checks.
        scan = os.open(".", READ_FLAGS | os.O_DIRECTORY, dir_fd=descriptor)
        try:
            _require(_identity(os.fstat(scan)) == _identity(before), "runtime enumeration directory differs")
            with os.scandir(scan) as entries:
                for entry in entries:
                    name = entry.name
                    relative = parent + "/" + name if parent else name
                    _path(relative)
                    _require(name not in names and len(names) < MAX_ENTRIES,
                             "runtime directory enumeration exceeds its bound")
                    names.add(name)
                    info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if recheck:
                        _require(relative in self.identities and _identity(info) == self.identities[relative],
                                 "runtime entry changed after inventory")
                    else:
                        _require(len(self.records) < MAX_ENTRIES and info.st_dev == before.st_dev
                                 and not info.st_mode & (stat.S_ISUID | stat.S_ISGID),
                                 "runtime export exceeds bounds, crosses a mount, or contains set-id modes")
                        self.identities[relative] = _identity(info)
                        record = {"path": relative, "mode": format(stat.S_IMODE(info.st_mode), "04o")}
                        self.records[relative] = record
                    if stat.S_ISDIR(info.st_mode):
                        if not recheck:
                            self.records[relative]["type"] = "directory"
                        child = os.open(name, READ_FLAGS | os.O_DIRECTORY, dir_fd=descriptor)
                        try:
                            _require(_identity(os.fstat(child)) == _identity(info), "runtime directory name changed")
                            self.walk(child, relative, recheck=recheck)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode):
                        if not recheck:
                            self.file(descriptor, name, relative, info)
                    elif stat.S_ISLNK(info.st_mode):
                        target = os.readlink(name, dir_fd=descriptor)
                        _require(info.st_nlink == 1 and _text(target), "runtime symlink is hardlinked or not bounded ASCII")
                        if recheck:
                            _require(target == self.records[relative]["target"], "runtime symlink changed")
                        else:
                            self.records[relative].update(type="symlink", target=target)
                    else:
                        raise RuntimeError("runtime export contains a special file")
                    _require(_identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) == _identity(info),
                             "runtime entry changed during inventory")
        finally:
            os.close(scan)
        _require(_identity(os.fstat(descriptor)) == _identity(before), "runtime directory changed during enumeration")
        if recheck:
            _require(names == self.children[parent], "runtime directory population changed after inventory")
        else:
            self.children[parent] = names

    def file(self, directory, name, relative, info):
        inode = (info.st_dev, info.st_ino)
        _require(info.st_nlink == 1 and inode not in self.inodes and 0 <= info.st_size <= MAX_FILE_BYTES,
                 "runtime file is hardlinked, aliased, or exceeds its bound")
        self.inodes.add(inode)
        self.total += info.st_size
        _require(self.total <= MAX_TOTAL_BYTES, "runtime regular bytes exceed the aggregate bound")
        capture = relative == SOURCE_MANIFEST
        if capture:
            _require(0 < info.st_size <= MAX_MANIFEST_BYTES, "runtime source manifest exceeds its bound")
        raw = bytearray()
        head = bytearray()
        digest = hashlib.sha256()
        total = 0
        descriptor = os.open(name, READ_FLAGS, dir_fd=directory)
        try:
            _require(_identity(os.fstat(descriptor)) == _identity(info), "runtime file name changed before read")
            while total <= info.st_size:
                chunk = os.read(descriptor, min(1024 * 1024, info.st_size - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                _require(total <= info.st_size, "runtime file grew during read")
                digest.update(chunk)
                if capture:
                    raw.extend(chunk)
                if relative == INTERPRETER and len(head) < 64:
                    head.extend(chunk[:64 - len(head)])
            _require(total == info.st_size and _identity(os.fstat(descriptor)) == _identity(info),
                     "runtime file changed during hash read")
        finally:
            os.close(descriptor)
        self.records[relative].update(type="file", bytes=total, sha256="sha256:" + digest.hexdigest())
        if capture:
            self.manifest = bytes(raw)
        if relative == INTERPRETER:
            self.interpreter_head = bytes(head)

    def resolve(self, path):
        # Interpret absolute symlinks as chroot-root relative. Path.resolve()
        # here would incorrectly inspect /lib, /usr or /etc on the host.
        pending = path.split("/")
        resolved = []
        hops = 0
        while pending:
            part = pending.pop(0)
            if part in ("", "."):
                continue
            if part == "..":
                _require(bool(resolved), "runtime symlink escapes its root")
                resolved.pop()
                continue
            candidate = "/".join([*resolved, part])
            _require(candidate in self.records, "runtime symlink target is absent from the export")
            record = self.records[candidate]
            if record["type"] == "symlink":
                hops += 1
                _require(hops <= MAX_SYMLINK_HOPS, "runtime symlink resolution exceeds its cycle/hop bound")
                target = record["target"]
                if target.startswith("/"):
                    resolved = []
                pending = target.split("/") + pending
            else:
                _require(not pending or record["type"] == "directory", "runtime symlink traverses a non-directory")
                resolved.append(part)
        return "/".join(resolved)


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "runtime source manifest has duplicate JSON fields")
        result[key] = value
    return result


def _bind_source(observed, source, *, authority=False):
    raw = observed.manifest
    _require(raw is not None and _sha(raw) == source["source_manifest_digest"],
             "exported source manifest does not match the build's exact original pin")
    contract = json.loads(raw.decode("ascii"), object_pairs_hook=_object)
    _require(isinstance(contract, dict) and _canonical(contract) + b"\n" == raw
             and contract.get("apiVersion") == "serverware.sourceArchive/v1"
             and contract.get("identityMode") == "production-commit"
             and contract.get("productionReleaseEligible") is True
             and contract.get("commit") == source["revision"]
             and contract.get("commitTimestamp") == source["source_date_epoch"]
             and contract.get("sourceTreeDigest") == source["source_tree_digest"],
             "exported source contract differs from the exact production source identity")
    tree = contract.get("sourceTreeManifest")
    archive = contract.get("archive")
    _require(isinstance(tree, dict) and _sha(_canonical(tree)) == source["source_tree_digest"]
             and tree.get("version") == "serverware.sourceTree/v3"
             and tree.get("identityMode") == "production-commit"
             and tree.get("productionReleaseEligible") is True
             and tree.get("commit") == source["revision"]
             and tree.get("commitTimestamp") == source["source_date_epoch"]
             and isinstance(archive, dict) and archive.get("sha256") == source["source_archive_digest"],
             "runtime source-tree/archive association differs from its original")
    entries = tree.get("files")
    _require(isinstance(entries, list) and 0 < len(entries) <= MAX_ENTRIES,
             "runtime source file inventory exceeds its bound")
    installed = {}
    seen = set()
    for entry in entries:
        _require(isinstance(entry, dict) and isinstance(entry.get("path"), str), "source file entry is malformed")
        path = entry["path"]
        _path(path)
        _require(path not in seen, "runtime source manifest contains duplicate paths")
        seen.add(path)
        if path.startswith("serverware/") or path in (ENTRYPOINT[4:], CONDUCTOR[4:]) or (authority and path in AUTHORITY_FILES):
            _require(entry.get("type") == "file" and entry.get("mode") in ("100644", "100755")
                     and type(entry.get("bytes")) is int and 0 <= entry["bytes"] <= MAX_FILE_BYTES
                     and isinstance(entry.get("sha256"), str) and DIGEST.fullmatch(entry["sha256"]) is not None,
                     "installed source entry is not an admitted regular original")
            prefix = "authority/app/" if authority and path in AUTHORITY_FILES else "app/"
            installed[prefix + path] = entry
    actual = {path for path, record in observed.records.items()
              if (path.startswith("app/") or (authority and path.startswith("authority/")))
              and record["type"] != "directory"}
    _require(actual == set(installed) and ENTRYPOINT in installed and CONDUCTOR in installed,
             "runtime application files differ from the complete source-selected package/scripts")
    if authority:
        _require(all("authority/app/" + path in installed for path in AUTHORITY_FILES),
                 "authority runtime lacks a fixed source original")
    expected_directories = {"app"}
    for path in installed:
        parts = path.split("/")
        expected_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    _require({path for path, record in observed.records.items()
              if (path == "app" or path.startswith("app/") or (authority and (path == "authority" or path.startswith("authority/"))))
              and record["type"] == "directory"}
             == expected_directories, "runtime application directories differ from the exact source package")
    for path, entry in installed.items():
        record = observed.records[path]
        _require(record["type"] == "file" and record["mode"] == "0444"
                 and record["bytes"] == entry["bytes"] and record["sha256"] == entry["sha256"],
                 "installed application original differs from its source manifest")


def inventory(root: Path, metadata: dict) -> dict:
    """Observe one completed local export, without executing or modifying it.

    The caller owns the private output directory. The second name/identity pass
    detects drift during observation; a packager must recheck while consuming
    bytes and repeat this inventory, not treat this JSON as retained ownership.
    """
    return _inventory(root, metadata, authority=False)


def authority_inventory(root: Path, metadata: dict) -> dict:
    """Inventory only the separate fixed authority-coordinator artifact.

    This is not a conductor inventory, installed runtime owner or independent
    approval. The real coordinator still requires the separately approved
    conductor inventory and original protected authority capabilities.
    """
    return _inventory(root, metadata, authority=True)


def _inventory(root: Path, metadata: dict, *, authority: bool) -> dict:
    source = _source(metadata)
    _require(isinstance(root, Path) and root.is_absolute() and root != Path("/")
             and root.resolve(strict=True) == root, "runtime export needs an explicit real absolute directory")
    before = root.lstat()
    _require(stat.S_ISDIR(before.st_mode) and not before.st_mode & (stat.S_ISUID | stat.S_ISGID),
             "runtime export root is not an ordinary directory")
    descriptor = os.open(root, READ_FLAGS | os.O_DIRECTORY)
    try:
        _require(_identity(os.fstat(descriptor)) == _identity(before), "runtime export root changed during open")
        observed = _Inventory()
        observed.walk(descriptor)
        for path, record in observed.records.items():
            if record["type"] == "symlink":
                record["resolvedPath"] = observed.resolve(path)
        for path in ("app", "app/serverware", "app/scripts", "runtime", "runtime/python", "vendor"):
            _require(observed.records.get(path, {}).get("type") == "directory", "fixed runtime directory is absent")
        _require(observed.children["app"] == {"serverware", "scripts"}
                 and observed.children["app/scripts"] == {"run_native_pilot.py", "native_pilot_runtime_entrypoint.py"},
                 "conductor application layout differs from the source-fixed target")
        if authority:
            for path in ("authority", "authority/app", "authority/app/scripts", "authority/app/scripts/authority"):
                _require(observed.records.get(path, {}).get("type") == "directory"
                         and observed.records[path]["mode"] == "0555", "authority runtime directory is absent")
        for path, mode in ((INTERPRETER, "0555"), (SOURCE_MANIFEST, "0444"),
                           (ENTRYPOINT, "0444"), (CONDUCTOR, "0444")):
            record = observed.records.get(path, {})
            _require(record.get("type") == "file" and record.get("mode") == mode
                     and record.get("bytes", 0) > 0, "fixed runtime file/mode is absent")
        head = observed.interpreter_head
        _require(head is not None and len(head) == 64 and head[:7] == b"\x7fELF\x02\x01\x01"
                 and int.from_bytes(head[16:18], "little") in (2, 3)
                 and int.from_bytes(head[18:20], "little") == 62,
                 "runtime interpreter is not a Linux/amd64 executable ELF")
        _bind_source(observed, source, authority=authority)
        observed.walk(descriptor, recheck=True)
        _require(_identity(root.lstat()) == _identity(before), "runtime export root name changed")
    finally:
        os.close(descriptor)
    records = [observed.records[path] for path in sorted(observed.records)]
    result = {
        "apiVersion": API_VERSION, "source": source, "target": "native-pilot-conductor-artifact",
        "command": COMMAND[:], "records": records, "recordsSha256": _sha(_canonical(records)),
        "counts": {"entries": len(records), "files": sum(r["type"] == "file" for r in records),
                   "directories": sum(r["type"] == "directory" for r in records),
                   "symlinks": sum(r["type"] == "symlink" for r in records), "regularBytes": observed.total},
        "limits": {"entries": MAX_ENTRIES, "depth": MAX_DEPTH, "fileBytes": MAX_FILE_BYTES,
                   "regularBytes": MAX_TOTAL_BYTES, "pathBytes": MAX_PATH_BYTES, "symlinkHops": MAX_SYMLINK_HOPS},
        "intendedInstalledOwnership": {"uid": 0, "gid": 0},
        "exportOwnership": "Host-export UID/GID are checked for stability, not interpreted as installed ownership.",
        "releaseAuthority": False, "liveReady": False, "launchPrepared": False,
        "dynamicLoaderClosureVerified": False,
        "boundary": "Offline package/source observations only. No execution, DSO-resolution proof, independent approval, installation, authority coordinator, or native service readiness is produced.",
    }
    if authority:
        result.update(apiVersion=AUTHORITY_API_VERSION, target=AUTHORITY_TARGET, command=AUTHORITY_COMMAND[:],
            requiredArguments={"runtimeInventory": ["--runtime-inventory-fd", "--runtime-inventory-sha256"],
                "authorityKeys": "--authority-key PURPOSE=FD repeated for the exact source-selected KEY_PURPOSES",
                "inventoryKind": API_VERSION, "conductorInventoryDerived": False},
            boundary="Offline authority-coordinator package/source observations only. No execution, DSO-resolution proof, independent approval, installed owner, keys, protected inputs or native pilot acceptance is produced. The original separate conductor inventory remains required.")
    _require(len(_canonical(result)) <= MAX_MANIFEST_BYTES, "runtime inventory manifest exceeds its bound")
    return result
