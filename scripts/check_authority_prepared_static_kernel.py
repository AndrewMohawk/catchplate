#!/usr/bin/env python3
"""Optional, destructive-only-to-fresh-fixtures kernel component check.

Run ONLY in the explicitly marked offline guest, with a dedicated ext4 mount
at /run/probe and this checkout mounted read-only. No mounts are created here.
All files are known synthetic bytes; immutable outputs are retained, including
on failure. No flags are cleared, authority keys/receipts created, installer.run
called, or pilot started. The parent must impose its independent 60s watchdog.

The component owner below deliberately does not authenticate a signed package.
It supplies only a synthetic process/FD lifetime to the actual filesystem
helpers. Success is NOT signed-installation or startup-latency acceptance.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import threading
import time

ROOT = "/run/probe/prepared-static-component"
MOUNT = "/run/probe"
MARKER = "catchplate_prepared_static_component=1"
SCHEMA = "catchplate.preparedStaticKernelComponent/v1"
READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
CONTENT = {
    "late/config.txt": b"synthetic late configuration, not an authority receipt\n",
    "settings.txt": b"synthetic public static settings\n",
    "static/payload.bin": b"synthetic immutable static payload\n" * 512,
}
FRESH = "late/config.txt"


def require(value):
    if not value:
        raise ValueError("kernel component check refused")


def bounded_text(path, maximum):
    with open(path, "rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum)
    return raw.decode("ascii")


def admit(root):
    """No writes or authority-module imports before the fixed guest guard."""
    require(root == ROOT and os.geteuid() == os.getegid() == 0
            and sys.platform == "linux" and os.uname().machine == "x86_64"
            and sys.dont_write_bytecode and threading.active_count() == 1)
    require(bounded_text("/proc/cmdline", 16384).split().count(MARKER) == 1)
    require(set(os.listdir("/sys/class/net")) == {"lo"})
    require(not any(name.startswith("CATCHPLATE_") for name in os.environ))
    require(Path(MOUNT).resolve().as_posix() == MOUNT
            and not os.path.lexists(root))
    mount = os.stat(MOUNT, follow_symlinks=False)
    require(stat.S_ISDIR(mount.st_mode) and mount.st_uid == mount.st_gid == 0
            and not stat.S_IMODE(mount.st_mode) & 0o022
            and mount.st_dev != os.stat("/").st_dev)
    rows = []
    for line in bounded_text("/proc/self/mountinfo", 262144).splitlines():
        before, separator, after = line.partition(" - ")
        require(bool(separator))
        fields, filesystem = before.split(), after.split()
        require(len(fields) >= 6 and len(filesystem) >= 3)
        if fields[4] == MOUNT:
            rows.append((fields, filesystem))
        require(not fields[4].startswith(MOUNT + "/"))
    require(len(rows) == 1)
    fields, filesystem = rows[0]
    require(filesystem[0] == "ext4" and fields[3] == "/"
            and "rw" in fields[5].split(",")
            and fields[2] == f"{os.major(mount.st_dev)}:{os.minor(mount.st_dev)}")
    source = Path(__file__).resolve().parents[1]
    require(os.statvfs(source).f_flag & os.ST_RDONLY)
    return source


def mkdir(path, mode=0o700):
    os.mkdir(path, mode)
    os.chmod(path, mode, follow_symlinks=False)


def open_dir(path):
    return os.open(path, READ | os.O_DIRECTORY)


def write_fixture(path, raw, local, *, verity=True, frozen=True, alias=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            require(count > 0)
            offset += count
        os.fchmod(fd, 0o400)
        os.fsync(fd)
    finally:
        os.close(fd)
    if alias is not None:
        os.link(path, alias, follow_symlinks=False)
    fd = os.open(path, READ)
    try:
        if verity:
            local._verity(fd)
        if frozen:
            local._immutable(fd)
        os.fsync(fd)
    finally:
        os.close(fd)


def freeze_directory(path, local):
    fd = open_dir(path)
    try:
        local._immutable(fd)
        os.fsync(fd)
    finally:
        os.close(fd)


def count_reads(function):
    """Observe actual pread C calls; never replace reads, ioctls or results."""
    require(sys.getprofile() is None)
    calls = [0]

    def observe(_frame, event, value):
        if event == "c_call" and value is os.pread:
            calls[0] += 1

    sys.setprofile(observe)
    try:
        result = function()
    finally:
        sys.setprofile(None)
    return result, calls[0]


def fixture_owner(local, root, source, entries, deadline):
    class ComponentOwner(local.LocalAuthorityInstaller):
        """Synthetic lifetime ONLY; intentionally not original authority admission."""

        def check(self):
            require(os.getpid() == self.pid and not self.closed and not self.closing
                    and not self.uncertain and threading.current_thread() is threading.main_thread()
                    and os.geteuid() == os.getegid() == 0
                    and time.monotonic() < deadline)
            require(local._identity(self.source_root) == self.source_identity)
            local._frozen(self.source_root)
            for parent, name, fd, identity in self.links:
                named, actual = os.stat(name, dir_fd=parent, follow_symlinks=False), os.fstat(fd)
                require((named.st_dev, named.st_ino) == identity == (actual.st_dev, actual.st_ino)
                        and actual.st_uid == actual.st_gid == 0 and not actual.st_mode & 0o022)

    owner = ComponentOwner(local._TOKEN)
    try:
        owner.root = owner._hold(open_dir(root))
        owner.source_root = owner._hold(open_dir(source))
        owner.source_identity = local._identity(owner.source_root)
        prepared = open_dir(root / "prepared-static")
        try:
            pin = local._identity(prepared)
        finally:
            os.close(prepared)
        owner.value = {"preparedStatic": {"relativePath": "prepared-static",
            **{name: pin[name] for name in ("device", "inode", "generation")}, "freshPaths": [FRESH]}}
        owner.plan = {"entries": entries}
        owner.check()
        return owner
    except BaseException:
        owner.close()
        raise


def prepare_case(base, name, source, entries, local, deadline, *, variant=None):
    root = base / name
    mkdir(root, 0o750)
    prepared = root / "prepared-static"
    mkdir(prepared)
    mkdir(prepared / "static")
    for path, raw in CONTENT.items():
        if path == FRESH or (variant == "missing" and path == "settings.txt"):
            continue
        selected = path == "settings.txt"
        write_fixture(prepared / path, (b"x" * len(raw) if variant == "wrong-bytes" and selected else raw),
            local, verity=not (variant == "unsealed" and selected),
            frozen=not (variant == "not-frozen" and selected),
            alias=root / "outside-alias" if variant == "hardlink" and selected else None)
    if variant == "extra":
        write_fixture(prepared / "extra.txt", b"synthetic extra entry\n", local)
    owner = fixture_owner(local, root, source, entries, deadline)
    if variant == "generation":
        owner.value["preparedStatic"]["generation"] += 1
    return owner


def rebind_tree(owner, parent, name):
    owner.links = [row for row in owner.links if row[2] != owner.tree]
    info = os.fstat(owner.tree)
    owner.links.append((parent, name, owner.tree, (info.st_dev, info.st_ino)))


def run_component(base, local, measure, deadline, report):
    report["stage"] = "source-create-and-seal"
    source = base / "source"
    mkdir(source)
    mkdir(source / "late")
    mkdir(source / "static")
    for path, raw in CONTENT.items():
        write_fixture(source / path, raw, local)
    for path in (source / "late", source / "static", source):
        freeze_directory(path, local)
    inputs = [dict(path=path, kind="data", mode=0o400, uid=0, gid=0) for path in sorted(CONTENT)]
    entries = [dict(path=path, sourceSha256="sha256:" + hashlib.sha256(CONTENT[path]).hexdigest(),
        size=len(CONTENT[path]), mode=0o400, uid=0, gid=0, requireFsVerity=True,
        requireImmutable=True, action="copy-fresh" if path == FRESH else "adopt-prepared-static")
        for path in sorted(CONTENT)]
    source_fd = open_dir(source)
    try:
        def measure_source():
            return measure.measure_tree(source_fd, inputs, runtime_path=str(source),
                check=lambda: require(time.monotonic() < deadline))
        report["stage"] = "source-cold-and-warm-measurement"
        cold, cold_reads = count_reads(measure_source)
        warm, warm_reads = count_reads(measure_source)
        require(cold == warm and warm_reads == len(CONTENT) and cold_reads == 2 * len(CONTENT))
        require([row["sha256"] for row in warm["files"]] == [row["sourceSha256"] for row in entries])
    finally:
        os.close(source_fd)

    refused = []
    for variant in ("wrong-bytes", "missing", "unsealed", "not-frozen", "extra", "hardlink", "generation"):
        report["stage"] = "negative-" + variant
        owner = prepare_case(base, variant, source, entries, local, deadline, variant=variant)
        try:
            try:
                owner._prepared_tree()
            except ValueError:
                refused.append(variant)
            else:
                raise RuntimeError("negative component control accepted")
            require(os.path.isdir(base / variant / "prepared-static"))
        finally:
            owner.close()

    report["stage"] = "prepared-adoption"
    owner = prepare_case(base, "positive", source, entries, local, deadline)
    try:
        original_static = {}
        for entry in entries:
            if entry["path"] == FRESH:
                continue
            fd = local._open_beneath(owner.root, "prepared-static/" + entry["path"], READ)
            try:
                raw = os.pread(fd, entry["size"] + 1, 0)
                require(raw == CONTENT[entry["path"]] and os.fstat(fd).st_nlink == 1)
                key = measure._file_cache_key(fd, entry["size"])
                require(key is not None)
                original_static[entry["path"]] = dict(local._identity(fd),
                    sha256="sha256:" + hashlib.sha256(raw).hexdigest(), fsVerityDigest="sha256:" + key[0].hex())
            finally:
                os.close(fd)
        (parents, adopted), adopt_reads = count_reads(owner._prepared_tree)
        require(set(adopted) == set(CONTENT) - {FRESH} and adopt_reads == len(adopted))
        require(all(adopted[path][name] == value for path, row in original_static.items()
                    for name, value in row.items()))
        report["stage"] = "move-and-fresh-copy"
        original_tree = local._identity(owner.tree)
        incoming = owner._directory(owner.root, ".incoming", absent=True)
        generations = owner._directory(owner.root, "generations", absent=True)
        local._rename(owner.root, "prepared-static", incoming, "component-generation")
        rebind_tree(owner, incoming, "component-generation")
        os.fsync(owner.root)
        os.fsync(incoming)
        owner.check()
        require(local._identity(owner.tree) == original_tree
                and not os.path.lexists(base / "positive" / "prepared-static"))
        fresh_entry = next(row for row in entries if row["path"] == FRESH)
        fresh = owner._copy(fresh_entry, parents)
        require(fresh["immutable"] and fresh["sha256"] == fresh_entry["sourceSha256"])
        source_late = os.stat(source / FRESH)
        require((fresh["device"], fresh["inode"]) != (source_late.st_dev, source_late.st_ino))
        report["stage"] = "final-freeze-and-move"
        for path in sorted(parents, key=lambda value: (value.count("/"), value), reverse=True):
            local._set_generation_directory_mode(parents[path], local.contract.LOCAL_GENERATION_DIRECTORY_MODE)
            if path:
                local._immutable(parents[path])
                os.fsync(parents[path])
        local._rename(incoming, "component-generation", generations, "component-generation")
        rebind_tree(owner, generations, "component-generation")
        local._immutable(owner.tree)
        os.fsync(owner.tree)
        os.fsync(incoming)
        os.fsync(generations)
        owner.check()
        report["stage"] = "final-kernel-and-content-readback"
        final_rows = {}
        for entry in entries:
            fd = local._open_beneath(owner.tree, entry["path"], READ)
            try:
                info = os.fstat(fd)
                require(info.st_nlink == 1 and local._flags(fd) & local._IMMUTABLE)
                measured = measure.measure_file(owner.tree,
                    next(row for row in inputs if row["path"] == entry["path"]), check=owner.check)
                require(measured["sha256"] == entry["sourceSha256"])
                key = measure._file_cache_key(fd, info.st_size)
                require(key is not None)
                row = dict(local._identity(fd), sha256=measured["sha256"], fsVerityDigest="sha256:" + key[0].hex())
                expected = fresh if entry["path"] == FRESH else adopted[entry["path"]]
                require(all(row[name] == expected[name] for name in row))
                final_rows[entry["path"]] = row
            finally:
                os.close(fd)
        report["stage"] = "actual-write-refusal"
        # Attempt an actual write; immutable/verity must refuse, with bytes intact.
        try:
            fd = local._open_beneath(owner.tree, "settings.txt", os.O_WRONLY | os.O_CLOEXEC)
        except OSError as error:
            require(error.errno in (errno.EPERM, errno.EACCES))
        else:
            os.close(fd)
            raise RuntimeError("sealed component unexpectedly writable")
        unchanged = measure.measure_file(owner.tree, next(row for row in inputs if row["path"] == "settings.txt"), check=owner.check)
        require(unchanged["sha256"] == final_rows["settings.txt"]["sha256"])
        return {"sourceColdPreadCalls": cold_reads, "sourceWarmPreadCalls": warm_reads,
            "staticAdoptionPreadCalls": adopt_reads, "adoptedStaticFiles": len(adopted),
            "freshCopiedFiles": 1, "staticIdentityPreserved": True, "writeRefused": True,
            "negativeControlsRefused": refused, "crossMountExercised": False,
            "crossMountReason": "no separate guest mount supplied", "retainedFiles": final_rows}
    finally:
        owner.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, choices=[ROOT])
    args = parser.parse_args(argv)
    result = {"schema": SCHEMA, "ok": False, "filesystemComponentOnly": True,
        "signedInstallationVerified": False, "startupLatencyVerified": False,
        "authorityKeysUsed": False, "pilotStarted": False, "outputsRetained": False,
        "stage": "guest-admission"}
    try:
        source = admit(args.root)
        sys.path.insert(0, str(source))
        from catchplate import authority_local_artifact_measure as measure
        from catchplate import authority_local_install as local
        result["stage"] = "fresh-fixture"
        mkdir(args.root)
        result["outputsRetained"] = True
        fd = open_dir(args.root)
        try:
            require(measure._ext4_verity_cache_eligible(fd))
        finally:
            os.close(fd)
        result.update(run_component(Path(args.root), local, measure, time.monotonic() + 45, result))
        result["ok"] = True
        result["stage"] = "complete"
    except Exception as error:
        result["error"] = "component refused; inspect retained synthetic filesystem; no automatic retry"
        result["errorClass"] = ("os_error" if isinstance(error, OSError) else
            "contract_refusal" if isinstance(error, ValueError) else "component_error")
        if isinstance(error, OSError) and type(error.errno) is int and 0 < error.errno < 4096:
            result["errno"] = error.errno
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
