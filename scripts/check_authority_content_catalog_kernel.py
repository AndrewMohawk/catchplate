#!/usr/bin/env python3
"""Optional real ext4/fs-verity component probe in a fresh offline guest only.

Uses the existing prepared-static guest marker/root and absent-root admission.
Never run against an existing pilot: the dedicated synthetic disk is retained,
not reset or unsealed. Two new interpreters demonstrate cold catalog reuse;
this is not assembly authentication, signed installation or latency acceptance.
Parent limit 45s, each child 15s; caller also imposes its 60s guest watchdog.
With the actual readers' 1MiB chunks, a 2MiB cold read makes three pread calls
including EOF; a catalog hit makes only EOF. Empty files demonstrate parity,
not a claimed read saving. The profiler observes calls without replacing IO.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_authority_prepared_static_kernel as base

ROOT, MARKER, READ = base.ROOT, base.MARKER, base.READ
SCHEMA = "catchplate.contentCatalogKernelComponent/v1"
CATALOG = "content-catalog.json"
CONTENT = {"empty": b"", "payload": b"C" * (2 * 1024 * 1024),
           "changed": b"D" * (2 * 1024 * 1024)}
KNOWN = ("empty", "payload")
require = base.require


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def clock(deadline):
    require(time.monotonic_ns() < deadline and threading.current_thread() is threading.main_thread())


def timeout(_signal, _frame):
    raise TimeoutError("kernel component deadline")


def child_admit(identity):
    """Same fixed offline boundary; only parent may admit an absent root."""
    require(os.geteuid() == os.getegid() == 0 and sys.platform == "linux"
            and os.uname().machine == "x86_64" and sys.dont_write_bytecode
            and threading.active_count() == 1)
    require(base.bounded_text("/proc/cmdline", 16384).split().count(MARKER) == 1
            and set(os.listdir("/sys/class/net")) == {"lo"}
            and not any(name.startswith("CATCHPLATE_") for name in os.environ))
    require(Path(ROOT).resolve().as_posix() == ROOT)
    mount, root = os.stat(base.MOUNT, follow_symlinks=False), os.stat(ROOT, follow_symlinks=False)
    require(stat.S_ISDIR(mount.st_mode) and mount.st_uid == mount.st_gid == 0
            and not stat.S_IMODE(mount.st_mode) & 0o022 and mount.st_dev != os.stat("/").st_dev
            and stat.S_ISDIR(root.st_mode) and root.st_uid == root.st_gid == 0
            and stat.S_IMODE(root.st_mode) == 0o700 and root.st_dev == mount.st_dev
            and (root.st_dev, root.st_ino) == tuple(identity)
            and set(os.listdir(ROOT)) == set(CONTENT) | {CATALOG})
    rows = []
    for line in base.bounded_text("/proc/self/mountinfo", 262144).splitlines():
        before, separator, after = line.partition(" - ")
        fields, filesystem = before.split(), after.split()
        require(separator and len(fields) >= 6 and len(filesystem) >= 3
                and not fields[4].startswith(base.MOUNT + "/"))
        if fields[4] == base.MOUNT: rows.append((fields, filesystem))
    require(len(rows) == 1)
    fields, filesystem = rows[0]
    require(filesystem[0] == "ext4" and fields[3] == "/" and "rw" in fields[5].split(",")
            and fields[2] == f"{os.major(mount.st_dev)}:{os.minor(mount.st_dev)}")
    source = Path(__file__).resolve().parents[1]
    require(os.statvfs(source).f_flag & os.ST_RDONLY)
    return source


@contextmanager
def held(name, local, measure, deadline):
    parent = base.open_dir(ROOT)
    fd = None
    try:
        fd = os.open(name, READ, dir_fd=parent)
        original, directory = measure._identity(os.fstat(fd)), measure._identity(os.fstat(parent))
        physical = local._identity(fd)
        require(stat.S_ISREG(original[2]) and stat.S_IMODE(original[2]) == 0o400
                and original[3:6] == (0, 0, 1) and original[0] == directory[0])
        def check():
            clock(deadline)
            require(measure._identity(os.fstat(parent)) == directory
                    == measure._identity(os.stat(ROOT, follow_symlinks=False))
                    and measure._identity(os.fstat(fd)) == original
                    == measure._identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                    and local._identity(fd) == physical)
            local._frozen(fd)
        check()
        yield parent, fd, check
        check()
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def measured(name, kind, local, measure, deadline):
    with held(name, local, measure, deadline) as (parent, fd, check):
        if kind == "owned":
            result, count = base.count_reads(lambda: measure._digest_owned_file(
                fd, maximum=measure.spec.MAX_FILE_BYTES, check=check))
        else:
            row, count = base.count_reads(lambda: measure.measure_file(parent,
                dict(path=name, kind="data", mode=0o400, uid=0, gid=0), check=check))
            result = row["sha256"]
        require(result == sha(CONTENT[name]))
        return count


def worker(args, local, measure, deadline):
    require(not measure._FILE_DIGEST_CACHE)
    with held(CATALOG, local, measure, deadline) as (_, fd, check):
        size = os.fstat(fd).st_size
        require(0 < size <= 8192)
        raw = os.pread(fd, size + 1, 0)
        require(len(raw) == size); check()
    wrong = "sha256:" + ("0" if args.pin[7:8] != "0" else "1") + args.pin[8:]
    try: measure.pinned_content_catalog(raw, wrong)
    except ValueError: pass
    else: raise ValueError("wrong catalog pin accepted")
    hits = {}
    with measure.pinned_content_catalog(raw, args.pin):
        for kind in ("owned", "tree"):
            hits[kind] = {name: measured(name, kind, local, measure, deadline) for name in KNOWN}
            require(set(hits[kind].values()) == {1})
        require(not measure._FILE_DIGEST_CACHE)
        miss = measured("changed", args.worker, local, measure, deadline)
        require(miss == 3 and len(measure._FILE_DIGEST_CACHE) == 1)
        with held("changed", local, measure, deadline) as (_, fd, _):
            require(set(measure._FILE_DIGEST_CACHE) == {measure._file_cache_key(fd, len(CONTENT["changed"]))})
    # No clearing: the only observed entry is the genuinely read changed file.
    full = {name: measured(name, args.worker, local, measure, deadline) for name in KNOWN}
    require(full == {"empty": 1, "payload": 3})
    return dict(caller=args.worker, pid=os.getpid(), initialObservedMemoEmpty=True,
        catalogPreadCalls=hits, changedIdentityPreadCalls=miss, afterExitPreadCalls=full,
        catalogHitsDidNotPopulateObservedMemo=True, wrongPinRefused=True)


def parent(args, source, local, measure, deadline):
    base.mkdir(ROOT)
    for name, raw in CONTENT.items():
        clock(deadline); base.write_fixture(Path(ROOT) / name, raw, local)
    rows, counts = [], {}
    for name in KNOWN:
        with held(name, local, measure, deadline) as (_, fd, check):
            row, count = base.count_reads(lambda: measure.observe_catalog_entry(fd, check=check))
            require(row["sha256"] == sha(CONTENT[name]) and row["size"] == len(CONTENT[name]))
            rows.append(row); counts[name] = count
    require(counts == {"empty": 1, "payload": 3})
    rows.sort(key=lambda row: (row["fsVerityDigest"], row["size"]))
    require(len({(row["fsVerityDigest"], row["size"]) for row in rows}) == 2)
    raw = measure.spec.canonical_json_bytes(dict(schema="catchplate.sealedContentCatalog/v1", entries=rows))
    base.write_fixture(Path(ROOT) / CATALOG, raw, local, verity=False)
    try: fd = os.open(Path(ROOT) / "payload", os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error: require(error.errno in (errno.EPERM, errno.EACCES))
    else:
        os.close(fd)
        raise ValueError("sealed synthetic file writable")
    identity = os.stat(ROOT, follow_symlinks=False)
    results = []
    for kind in ("owned", "tree"):
        clock(deadline)
        process = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
            "--root", ROOT, "--worker", kind, "--pin", sha(raw), "--identity",
            str(identity.st_dev), str(identity.st_ino), "--deadline", str(deadline)],
            cwd=source, env={"LANG": "C"}, capture_output=True,
            timeout=min(15, (deadline-time.monotonic_ns()) / 1e9))
        require(process.returncode == 0 and not process.stderr and 0 < len(process.stdout) <= 4096)
        result = json.loads(process.stdout)
        require(result["ok"] is True and result["worker"]["caller"] == kind
                and result["worker"]["pid"] != os.getpid())
        results.append(result["worker"])
    clock(deadline)
    return dict(producerPreadCalls=counts, writeRefused=True, freshInterpreters=2,
                catalogPin=sha(raw), workers=results, outputsRetained=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, choices=[ROOT])
    parser.add_argument("--worker", choices=["owned", "tree"])
    parser.add_argument("--pin")
    parser.add_argument("--identity", nargs=2, type=int)
    parser.add_argument("--deadline", type=int)
    args = parser.parse_args()
    report = dict(schema=SCHEMA, ok=False, componentOnly=True, pilotStarted=False,
        nativeStartupLatencyVerified=False, signedInstallationVerified=False, authorityKeysUsed=False)
    try:
        start = time.monotonic_ns()
        deadline = min(start + 15_000_000_000, args.deadline) if args.worker else start + 45_000_000_000
        signal.signal(signal.SIGALRM, timeout)
        signal.setitimer(signal.ITIMER_REAL, max(0.001, (deadline-start) / 1e9))
        if args.worker:
            require(args.identity is not None and args.pin is not None)
            source = child_admit(args.identity)
        else:
            require(args.pin is args.identity is args.deadline is None)
            source = base.admit(args.root)  # Unchanged strict absent-root parent gate.
        sys.path.insert(0, str(source))
        from catchplate import authority_local_artifact_measure as measure
        from catchplate import authority_local_install as local
        if args.worker: report["worker"] = worker(args, local, measure, deadline)
        else: report.update(parent(args, source, local, measure, deadline))
        report.update(ok=True, kernel=os.uname().release, filesystem="ext4", fsVerityAlgorithm="sha256")
    except Exception as error:
        report.update(error="component refused; retain synthetic fixture; no retry",
            errorClass="os_error" if isinstance(error, OSError) else "component_error")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
