#!/usr/bin/env python3
"""Prepare a new Git-exact build snapshot without retimestamping unchanged inputs.

This is not a deployment or cache verifier. The caller must separately verify
the cache/compiler/environment and pin/freeze the output read-only before use.
With a predecessor, fresh_after_epoch_ns must be a verified upper bound over
the selected cache's dep-info, invoked and build-script output timestamps, not
the predecessor source or cache directory timestamp. Added/deleted paths disable
ALL reuse. Changed/new files are strictly newer than that bound, captured wall
time and every predecessor file mtime. This is not an authority clock.

Predecessors may use conventional Git/archive or read-only modes: 0644/0664/0444
for non-executable files, 0755/0775/0555 for executable files. Reused files retain
that exact mode; changed/new files use 0644/0755. The receipt binds actual modes.

Only committed objects are read from Git; archive attributes, working files,
hooks, replacement objects and lazy network fetches cannot supply source bytes.
No cache is opened. Failure can leave an incomplete NEW destination for manual
inspection; this helper never removes or rewrites an existing snapshot.
The export is disposable build input, not a power-loss-durable source backup.
Do not sync thousands of individual files to disk: Git remains the source of
truth, and the completed export is byte-verified before use. After a crash,
reverify or recreate the export rather than trusting a partial destination.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time

MAX_FILES = 16384
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_NS = 2**63 - 1
GIT_SECONDS = 300
OID = re.compile(r"[0-9a-f]{40}")
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class SnapshotError(ValueError):
    pass


def require(ok):
    if not ok:
        raise SnapshotError("build snapshot preparation refused")


def _absolute(value):
    path = Path(value)
    require(path.is_absolute() and path.anchor == "/" and str(path) == os.fspath(value)
            and all(part not in (".", "..") for part in path.parts))
    return path


def _directory(path, *, noatime=False):
    """Retain each ancestor without following any symlink."""
    fd = os.open("/", DIR_FLAGS)
    try:
        for index, part in enumerate(path.parts[1:]):
            flags = DIR_FLAGS
            if noatime and index == len(path.parts) - 2:
                flags |= os.O_NOATIME
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _relative_directory(root_fd, relative):
    fd = os.dup(root_fd)
    try:
        for part in relative.split("/") if relative else ():
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _component(raw):
    name = raw.decode("utf-8")
    require(name not in ("", ".", "..") and name.lower() != ".git"
            and not any(character in name for character in "/\\")
            and all(ord(character) >= 32 and ord(character) != 127 for character in name))
    return name


class _GitObjects:
    """One bounded local cat-file child; every returned object's identity is checked."""
    def __init__(self, repository):
        self.deadline = time.monotonic() + GIT_SECONDS
        self.process = subprocess.Popen(
            ["/usr/bin/git", "--no-replace-objects", "-C", str(repository),
             "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
             "-c", "gc.auto=0", "cat-file", "--batch"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                 "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                 "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
                 "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
                 "GIT_ALLOW_PROTOCOL": ""})
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)

    def _wait(self, fd, write=False):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0)
        ready = select.select([] if write else [fd], [fd] if write else [], [], remaining)
        require(bool(ready[1] if write else ready[0]))

    def _read(self, size):
        result = bytearray()
        while len(result) < size:
            fd = self.process.stdout.fileno()
            self._wait(fd)
            chunk = os.read(fd, min(65536, size - len(result)))
            require(bool(chunk))
            result.extend(chunk)
        return bytes(result)

    def get(self, oid, kind, maximum):
        require(type(oid) is str and OID.fullmatch(oid))
        pending = (oid + "\n").encode("ascii")
        while pending:
            fd = self.process.stdin.fileno()
            self._wait(fd, write=True)
            written = os.write(fd, pending)
            require(written > 0)
            pending = pending[written:]
        header = bytearray()
        while not header.endswith(b"\n"):
            require(len(header) < 128)
            header.extend(self._read(1))
        fields = header[:-1].decode("ascii").split(" ")
        require(len(fields) == 3 and fields[:2] == [oid, kind]
                and re.fullmatch(r"0|[1-9][0-9]{0,10}", fields[2]))
        size = int(fields[2])
        require(size <= maximum)
        body = self._read(size)
        require(self._read(1) == b"\n")
        prefix = kind.encode() + b" " + str(size).encode() + b"\0"
        require(hashlib.sha1(prefix + body).hexdigest() == oid)
        return body

    def close(self):
        self.process.stdin.close()
        self.process.stdout.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()  # Only this retained direct child, never a name/group.
            self.process.wait(timeout=5)


def _tree(git, revision):
    require(type(revision) is str and OID.fullmatch(revision))
    commit = git.get(revision, "commit", 1024 * 1024)
    first = commit.partition(b"\n")[0]
    require(re.fullmatch(rb"tree [0-9a-f]{40}", first))
    tree_oid = first[5:].decode("ascii")
    entries, directories = {}, {""}

    def visit(oid, prefix, depth):
        require(depth <= 64 and len(directories) <= MAX_FILES)
        raw = git.get(oid, "tree", 8 * 1024 * 1024)
        require(bool(raw))
        offset, names = 0, set()
        while offset < len(raw):
            space, end = raw.find(b" ", offset), raw.find(b"\0", offset)
            require(offset < space < end and end + 21 <= len(raw))
            mode, name = raw[offset:space].decode("ascii"), _component(raw[space + 1:end])
            require(name not in names)
            names.add(name)
            child_oid = raw[end + 1:end + 21].hex()
            offset = end + 21
            relative = prefix + name
            if mode == "40000":
                directories.add(relative)
                visit(child_oid, relative + "/", depth + 1)
            else:
                require(mode in ("100644", "100755") and len(entries) < MAX_FILES)
                entries[relative] = (mode, child_oid)

    visit(tree_oid, "", 0)
    require(bool(entries))
    return tree_oid, entries, directories


def _verify_snapshot(root, entries, directories, *, identity=None):
    """Exact no-follow roster; unknown paths are refused before their contents are read."""
    children = {name: set() for name in directories}
    for relative in (set(entries) | directories) - {""}:
        parent, _, name = relative.rpartition("/")
        children[parent].add(name)
    records, directory_records, total = {}, {}, 0

    def visit(fd, relative):
        nonlocal total
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode)
                and stat.S_IMODE(before.st_mode) in (0o700, 0o750, 0o755, 0o775, 0o500, 0o550, 0o555))
        observed = set()
        with os.scandir(fd) as stream:
            for entry in stream:
                require(entry.name in children[relative] and entry.name not in observed)
                observed.add(entry.name)
        require(observed == children[relative])
        directory_records[relative] = _stamp(before)
        for name in sorted(children[relative]):
            path = relative + "/" + name if relative else name
            if path in directories:
                child = os.open(name, DIR_FLAGS | os.O_NOATIME, dir_fd=fd)
                try:
                    visit(child, path)
                    require(_stamp(os.stat(name, dir_fd=fd, follow_symlinks=False))
                            == directory_records[path])
                finally:
                    os.close(child)
                continue
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME,
                            dir_fd=fd)
            try:
                info = os.fstat(child)
                mode, oid = entries[path]
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and stat.S_IMODE(info.st_mode) in
                        ((0o755, 0o775, 0o555) if mode == "100755" else (0o644, 0o664, 0o444))
                        and 0 <= info.st_size <= MAX_FILE)
                total += info.st_size
                require(total <= MAX_TOTAL)
                blob = hashlib.sha1(b"blob " + str(info.st_size).encode() + b"\0")
                content = hashlib.sha256()
                count = 0
                while True:
                    chunk = os.read(child, 65536)
                    if not chunk:
                        break
                    count += len(chunk)
                    require(count <= info.st_size)
                    blob.update(chunk)
                    content.update(chunk)
                require(count == info.st_size and blob.hexdigest() == oid
                        and _stamp(os.fstat(child)) == _stamp(info)
                        and _stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)) == _stamp(info))
                records[path] = {"stamp": _stamp(info), "sha256": content.hexdigest(),
                                 "mtimeNs": info.st_mtime_ns, "size": info.st_size}
            finally:
                os.close(child)
        require(_stamp(os.fstat(fd)) == _stamp(before))

    root_fd = _directory(root, noatime=True)
    try:
        root_info = os.fstat(root_fd)
        require(identity is None or (root_info.st_dev, root_info.st_ino) == identity)
        visit(root_fd, "")
        require(_stamp(root.lstat()) == directory_records[""])
    finally:
        os.close(root_fd)
    return records, directory_records


def prepare_snapshot(repository, revision, output, *, predecessor=None,
                     predecessor_revision=None, fresh_after_epoch_ns=None):
    repository, output = _absolute(repository), _absolute(output)
    require(type(revision) is str and OID.fullmatch(revision))
    require((predecessor is None) == (predecessor_revision is None))
    if predecessor is not None:
        predecessor = _absolute(predecessor)
        require(type(predecessor_revision) is str and OID.fullmatch(predecessor_revision)
                and type(fresh_after_epoch_ns) is int and 0 <= fresh_after_epoch_ns < MAX_NS)
    elif fresh_after_epoch_ns is not None:
        require(type(fresh_after_epoch_ns) is int and 0 <= fresh_after_epoch_ns < MAX_NS)
    locations = [repository, output] + ([] if predecessor is None else [predecessor])
    require(all(not left.is_relative_to(right) and not right.is_relative_to(left)
                for index, left in enumerate(locations) for right in locations[index + 1:]))
    repo_fd = _directory(repository)
    os.close(repo_fd)
    parent_fd = _directory(output.parent)
    git = None
    try:
        try:
            os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            require(False)
        git = _GitObjects(repository)
        tree_oid, entries, directories = _tree(git, revision)
        old_entries, old_records, old_directories, old_dir_records = {}, {}, set(), {}
        if predecessor is not None:
            _, old_entries, old_directories = _tree(git, predecessor_revision)
            old_records, old_dir_records = _verify_snapshot(predecessor, old_entries, old_directories)
        topology_equal = (set(entries) == set(old_entries) and directories == old_directories)
        captured_now = time.time_ns()
        floor = max(captured_now, fresh_after_epoch_ns or 0,
                    max((record["mtimeNs"] for record in old_records.values()), default=0))
        require(0 <= captured_now <= floor < MAX_NS)
        fresh_ns = floor + 1
        os.mkdir(output.name, 0o700, dir_fd=parent_fd)
        root_fd = os.open(output.name, DIR_FLAGS, dir_fd=parent_fd)
        output_identity = os.fstat(root_fd)
        reused, total, expected_times = 0, 0, {}
        try:
            for relative in sorted(directories - {""}, key=lambda name: (name.count("/"), name)):
                parent, _, name = relative.rpartition("/")
                fd = _relative_directory(root_fd, parent)
                try:
                    os.mkdir(name, 0o755, dir_fd=fd)
                    child = os.open(name, DIR_FLAGS, dir_fd=fd)
                    try:
                        os.fchmod(child, 0o755)
                    finally:
                        os.close(child)
                finally:
                    os.close(fd)
            for relative, (mode, oid) in sorted(entries.items()):
                body = git.get(oid, "blob", MAX_FILE)
                total += len(body)
                require(total <= MAX_TOTAL)
                old = old_records.get(relative)
                reuse = (topology_equal and old_entries[relative] == (mode, oid)
                         and old["size"] == len(body)
                         and old["sha256"] == hashlib.sha256(body).hexdigest())
                mtime = old["mtimeNs"] if reuse else fresh_ns
                actual_mode = stat.S_IMODE(old["stamp"][2]) if reuse else (0o755 if mode == "100755" else 0o644)
                parent, _, name = relative.rpartition("/")
                directory_fd = _relative_directory(root_fd, parent)
                try:
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory_fd)
                    try:
                        view = memoryview(body)
                        while view:
                            written = os.write(fd, view)
                            require(written > 0)
                            view = view[written:]
                        os.fchmod(fd, actual_mode)
                        os.utime(fd, ns=(captured_now, mtime))
                        info = os.fstat(fd)
                        require(info.st_mtime_ns == mtime and stat.S_IMODE(info.st_mode) == actual_mode
                                and (reuse or info.st_mtime_ns > floor)
                                and (old is None or (info.st_dev, info.st_ino) != old["stamp"][:2]))
                    finally:
                        os.close(fd)
                finally:
                    os.close(directory_fd)
                expected_times[relative] = (mtime, actual_mode)
                reused += int(reuse)
            require((output.lstat().st_dev, output.lstat().st_ino)
                    == (output_identity.st_dev, output_identity.st_ino))
            records, _ = _verify_snapshot(output, entries, directories,
                identity=(output_identity.st_dev, output_identity.st_ino))
            require(all((records[name]["mtimeNs"], stat.S_IMODE(records[name]["stamp"][2]))
                        == expected_times[name] for name in entries))
            if predecessor is not None:
                after, after_dirs = _verify_snapshot(predecessor, old_entries, old_directories)
                require(after == old_records and after_dirs == old_dir_records)
            manifest = [[name, entries[name][0], entries[name][1], records[name]["sha256"],
                         format(stat.S_IMODE(records[name]["stamp"][2]), "04o")]
                        for name in sorted(entries)]
            return {"schema": "catchplate.operatorBuildSnapshot/v1", "ok": True,
                    "revision": revision, "tree": tree_oid, "source": str(output),
                    "predecessorRevision": predecessor_revision, "files": len(entries),
                    "bytes": total, "reusedMtimes": reused, "freshMtimes": len(entries) - reused,
                    "reuseDisabledReason": ("no_predecessor" if predecessor is None else
                                             None if topology_equal else "path_roster_changed"),
                    "freshAfterEpochNs": fresh_after_epoch_ns, "freshMtimeNs": fresh_ns,
                    "manifestSha256": hashlib.sha256(json.dumps(manifest, ensure_ascii=True,
                        separators=(",", ":")).encode("ascii")).hexdigest(),
                    "gitBlobEquality": True, "cacheVerified": False, "readOnlyFrozen": False}
        finally:
            os.close(root_fd)
    finally:
        if git is not None:
            git.close()
        os.close(parent_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--predecessor")
    parser.add_argument("--predecessor-revision")
    parser.add_argument("--fresh-after-epoch-ns", type=int)
    args = parser.parse_args()
    try:
        receipt = prepare_snapshot(args.repository, args.revision, args.output,
            predecessor=args.predecessor, predecessor_revision=args.predecessor_revision,
            fresh_after_epoch_ns=args.fresh_after_epoch_ns)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except Exception:
        print('{"ok":false,"error":"build snapshot preparation refused"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
