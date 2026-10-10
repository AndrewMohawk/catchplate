#!/usr/bin/env python3
"""Real retained-file reads with SYNTHETIC kernel seals, ownership and clocks.

Exercises the actual startup custody callback and full-check method only. No
admitted startup, signed evidence, child process or real fs-verity is fabricated.
Filesystem bytes, descriptors, names and SHA256 are real. Outer startup joins
are inspected separately as source, not claimed as startup acceptance.
"""
import ast
import errno
import hashlib
import inspect
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import test_authority_local_artifact_measure_cache as cache_fixture
from serverware import authority_local_startup as startup
from serverware import authority_local_artifact_measure as measure


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class RetainedFile:
    def __init__(self, raw=b"synthetic public retained bytes"):
        self.raw = raw

    def __enter__(self):
        # Reuse the existing real-file/kernel-ioctl fixture, not its tests.
        self.kernel = cache_fixture.ArtifactMeasureCacheTests(methodName="runTest")
        self.kernel.setUp()
        self.stack = self.kernel.stack
        self.real_stat, self.real_fstat = os.stat, os.fstat
        self.metadata = {}
        self.stack.enter_context(patch.object(startup.os, "stat", side_effect=lambda *a, **kw: self.owned(self.real_stat(*a, **kw))))
        self.stack.enter_context(patch.object(startup.os, "fstat", side_effect=lambda fd: self.owned(self.real_fstat(fd))))
        self.euid = self.stack.enter_context(patch.object(startup.os, "geteuid", return_value=0))
        self.egid = self.stack.enter_context(patch.object(startup.os, "getegid", return_value=0))
        self.boot, self.epoch = 10_000, 20_000
        self.stack.enter_context(patch.object(startup.time, "clock_gettime_ns", side_effect=lambda _clock: self.boot))
        self.stack.enter_context(patch.object(startup.time, "time_ns", side_effect=lambda: self.epoch))
        self.boot_id = self.stack.enter_context(patch.object(startup, "_boot", return_value="sha256:" + "1" * 64))
        self.owner = startup.LocalAuthorityStartup(startup._TOKEN)
        self.stack.enter_context(patch.object(startup, "_LIVE", self.owner))
        self.owner.value = dict(bootIdDigest=self.boot_id.return_value,
            issuedAtBoottimeNs=1, deadlineBoottimeNs=100_000,
            issuedAtUnixNanos=1, expiresAtUnixNanos=200_000, retainedFiles=[])
        self.owner._hold(self.kernel.root)
        self.fds, self.reader_calls = [], 0
        self.capture(self.kernel.file("current", self.raw))
        return self

    def __exit__(self, *_):
        # Negative controls may deliberately corrupt synthetic bookkeeping.
        # Close the actual owned descriptors independently in all such cases.
        try:
            for fd in self.fds:
                os.close(fd)
        finally:
            if not self.kernel.doCleanups():
                raise AssertionError("kernel fixture cleanup failed")

    def owned(self, info):
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        fields.update(st_uid=0, st_gid=0)
        fields.update(self.metadata.get(info.st_ino, {}))
        return SimpleNamespace(**fields)

    def capture(self, path):
        self.path = path
        self.fd = self.owner._hold(os.open(path, startup._READ))
        self.fds.append(self.fd)
        identity = startup._identity(os.fstat(self.fd))
        self.named = (self.kernel.root, path.name, self.fd, identity, False)
        self.owner.names.append(self.named)
        self.owner.resource_file_custody[self.fd] = (self.owner.handles[-1], self.named)
        self.owner.resource_files = [self.fd]
        self.owner.value["retainedFiles"] = [dict(path=str(path), sha256=digest(self.raw))]

    def read_body(self):
        self.reader_calls += 1
        return startup._read(self.fd, startup.launcher.MAX_CLOSURE_FILE_BYTES, allow_empty=True)

    def read(self, **kwargs):
        self.kernel.reads.clear()
        return self.owner._retained_digest(self.fd, read=self.read_body, **kwargs)

    def assert_hit(self, case):
        case.assertEqual(self.kernel.reads, [(1, len(self.raw), 0)])


class StartupContentCacheTests(unittest.TestCase):
    def test_cold_actual_digest_then_warm_eof_only_with_original_reader(self):
        with RetainedFile(b"public\x00\xff" * 20_000) as item:
            self.assertEqual(item.read(), digest(item.raw))
            self.assertEqual(sum(size for _, _, size in item.kernel.reads), len(item.raw))
            self.assertEqual(item.reader_calls, 1)
            self.assertEqual(item.read(), digest(item.raw))
            item.assert_hit(self)
            self.assertEqual(item.reader_calls, 1)
            self.assertEqual(item.real_fstat(item.fd).st_size, len(item.raw))
            with patch.object(item.owner, "check", side_effect=AssertionError("recursive full scan")):
                self.assertEqual(item.read(), digest(item.raw))
                item.assert_hit(self)

    def test_empty_retained_content_is_cached_but_original_documents_stay_nonempty(self):
        with RetainedFile(b"") as item:
            with self.assertRaises(startup.LocalStartupError): startup._read(item.fd, 64)
            empty_sha = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            self.assertEqual(item.read(), empty_sha)
            self.assertEqual(item.reader_calls, 1)
            self.assertEqual(item.read(), empty_sha)
            item.assert_hit(self)
            self.assertEqual(item.reader_calls, 1)
            item.owner.check(full=True)

    def test_actual_full_check_rejects_false_claims_without_seeding_the_memo(self):
        with RetainedFile() as item:
            claim = item.owner.value["retainedFiles"][0]
            claim["sha256"] = "sha256:" + "0" * 64
            for _ in range(2):
                with self.assertRaises(startup.LocalStartupError): item.owner.check(full=True)
                self.assertEqual(set(measure._FILE_DIGEST_CACHE.values()), {hashlib.sha256(item.raw).hexdigest()})
            claim["sha256"] = digest(item.raw)
            item.kernel.reads.clear()
            item.owner.check(full=True)
            item.assert_hit(self)
            self.assertEqual((item.owner.last_boot, item.owner.last_epoch), (item.boot, item.epoch))

    def test_warm_hits_keep_current_owner_metadata_links_and_readonly_fd_checks(self):
        for change in ("mode", "uid", "gid", "nlink", "timestamp", "writable-fd"):
            with self.subTest(change=change), RetainedFile() as item:
                item.read()
                inode = item.real_fstat(item.fd).st_ino
                if change == "mode": item.path.chmod(0o600)
                elif change in {"uid", "gid"}: item.metadata[inode] = {"st_" + change: 23}
                elif change == "nlink": os.link(item.path, item.path.with_name("hardlink"))
                elif change == "timestamp":
                    before = item.real_stat(item.path)
                    os.utime(item.path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))
                else:
                    # Same inode and current anchors, but actually read/write.
                    item.path.chmod(0o600)
                    replacement = os.open(item.path, os.O_RDWR | os.O_CLOEXEC)
                    try: os.dup2(replacement, item.fd, inheritable=False)
                    finally: os.close(replacement)
                    item.path.chmod(0o400)
                    identity = startup._identity(os.fstat(item.fd))
                    held = next(row for row in item.owner.handles if row[0] == item.fd)
                    held[1] = identity
                    item.named = (*item.named[:3], identity, False)
                    item.owner.names[-1] = item.named
                    item.owner.resource_file_custody[item.fd] = (held, item.named)
                with self.assertRaises(startup.LocalStartupError): item.read()
                self.assertEqual(item.reader_calls, 1)

    def test_same_named_path_replacement_or_symlink_never_reuses_old_fd_authority(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), RetainedFile() as item:
                item.read()
                retained = item.path.with_name("old-retained-inode")
                item.path.rename(retained)
                if symlink: item.path.symlink_to(retained.name)
                else: item.kernel.file(item.path.name, item.raw)
                with self.assertRaises(startup.LocalStartupError): item.read()
                self.assertEqual(item.reader_calls, 1)
                self.assertEqual(item.kernel.real_pread(item.fd, len(item.raw), 0), item.raw)

    def test_new_real_content_and_kernel_identity_require_a_new_full_read(self):
        with RetainedFile(b"old-public-content") as item:
            old_digest = item.read()
            item.path.rename(item.path.with_name("old-retained"))
            old_fd = item.fd
            item.owner._close_fd(old_fd)
            item.fds.remove(old_fd)
            self.assertNotIn(old_fd, item.owner.resource_file_custody)
            item.owner.names.remove(item.named)
            item.raw = b"new-public-content"
            item.capture(item.kernel.file("current", item.raw))
            self.assertEqual(item.read(), digest(item.raw))
            self.assertNotEqual(old_digest, digest(item.raw))
            self.assertEqual(item.reader_calls, 2)
            self.assertEqual(sum(size for _, _, size in item.kernel.reads), len(item.raw))
            self.assertEqual(item.read(), digest(item.raw)); item.assert_hit(self)

    def test_unsealed_unknown_filesystem_and_supported_noncache_algorithm_use_full_reads(self):
        for variant in ("unsealed", "unsupported", "unknown-filesystem", "sha512"):
            with self.subTest(variant=variant), RetainedFile() as item:
                inode = item.real_fstat(item.fd).st_ino
                if variant == "unknown-filesystem": item.kernel.eligible.return_value = False
                elif variant == "sha512": item.kernel.verity[inode] = (2, 64, b"s" * 64)
                else: item.kernel.verity[inode] = OSError(errno.ENODATA if variant == "unsealed" else errno.ENOTTY, "synthetic no memo")
                for _ in range(2):
                    self.assertEqual(item.read(), digest(item.raw))
                    self.assertEqual(sum(size for _, _, size in item.kernel.reads), len(item.raw))
                self.assertEqual(item.reader_calls, 2)
                self.assertEqual(measure._FILE_DIGEST_CACHE, {})

    def test_warm_hit_rechecks_registration_closed_custody_and_original_lifetime(self):
        for change in ("closed", "uncertain", "pid", "thread", "euid", "egid", "live", "anchor", "boot", "wall", "boot-id"):
            with self.subTest(change=change), RetainedFile() as item:
                item.read()
                if change in {"closed", "uncertain"}: setattr(item.owner, change, True)
                elif change in {"pid", "thread"}: setattr(item.owner, change, getattr(item.owner, change) + 1)
                elif change == "euid": item.euid.return_value = 23
                elif change == "egid": item.egid.return_value = 23
                elif change == "live": item.stack.enter_context(patch.object(startup, "_LIVE", None))
                elif change == "anchor": item.owner.resource_file_custody.pop(item.fd)
                elif change == "boot": item.boot = item.owner.value["deadlineBoottimeNs"]
                elif change == "wall": item.epoch = item.owner.value["expiresAtUnixNanos"]
                else: item.boot_id.return_value = "sha256:" + "2" * 64
                with self.assertRaises(startup.LocalStartupError): item.read()
                self.assertEqual(item.reader_calls, 1)

    def test_postread_eof_mutation_cancellation_and_clock_rollback_fail_before_cache_population(self):
        for change in ("append", "truncate", "same-size", "verity", "path", "cancel", "deadline", "rollback", "anchor"):
            with self.subTest(change=change), RetainedFile() as item:
                sentinel = KeyboardInterrupt("synthetic cancellation")
                def after_read(fd, raw):
                    self.assertTrue(raw)
                    if change == "cancel": raise sentinel
                    if change == "deadline": item.boot = item.owner.value["deadlineBoottimeNs"]
                    elif change == "rollback": item.boot -= 1
                    elif change == "anchor":
                        held, named = item.owner.resource_file_custody[fd]
                        item.owner.resource_file_custody[fd] = tuple([held, named])
                    elif change == "verity": item.kernel.verity[item.real_fstat(fd).st_ino] = b"v" * 32
                    elif change == "path":
                        item.path.rename(item.path.with_name("postread-retained"))
                        item.kernel.file(item.path.name, item.raw)
                    else:
                        item.path.chmod(0o600)
                        item.path.write_bytes(item.raw + b"x" if change == "append" else b"" if change == "truncate" else b"x" * len(item.raw))
                        item.path.chmod(0o400)
                item.kernel.after_read = after_read
                with self.assertRaises((startup.LocalStartupError, ValueError, KeyboardInterrupt)) as caught:
                    item.read()
                if change == "cancel": self.assertIs(caught.exception, sentinel)
                self.assertEqual(measure._FILE_DIGEST_CACHE, {})
        with RetainedFile() as item:
            item.read()
            item.kernel.after_read = lambda _fd, _raw: setattr(item, "epoch", item.owner.value["expiresAtUnixNanos"])
            with self.assertRaises(startup.LocalStartupError): item.read()
            self.assertEqual(item.reader_calls, 1)

    def test_source_retains_all_full_check_boundaries_and_two_actual_empty_aware_readers(self):
        tree = ast.parse(inspect.getsource(startup.LocalAuthorityStartup))
        methods = {node.name: node for node in tree.body[0].body if isinstance(node, ast.FunctionDef)}
        sites = []
        for name, method in methods.items():
            for node in ast.walk(method):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "check":
                    keywords = {item.arg: item.value for item in node.keywords}
                    if isinstance(keywords.get("full"), ast.Constant) and keywords["full"].value is True:
                        child = keywords.get("child_live")
                        sites.append((name, isinstance(child, ast.Constant) and child.value is True))
        self.assertCountEqual(sites, [("open", False), ("_late", True), ("run", False), ("run", True)])
        for name in ("open", "check"):
            calls = [node for node in ast.walk(methods[name]) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute) and node.func.attr == "_retained_digest"]
            self.assertEqual(len(calls), 1)
            reader = next(item.value for item in calls[0].keywords if item.arg == "read")
            self.assertIsInstance(reader, ast.Lambda)
            self.assertEqual(reader.body.func.id, "_read")
            self.assertEqual(reader.body.args[1].attr, "MAX_CLOSURE_FILE_BYTES")
            self.assertTrue(next(item.value.value for item in reader.body.keywords if item.arg == "allow_empty"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
