#!/usr/bin/env python3
"""Real-file cache controls with SYNTHETIC kernel fs-verity responses.

Default tests mock filesystem eligibility/ioctl, not hashing or file contents;
they are not real fs-verity acceptance or a disk-scrub guarantee. The explicit
--real-fsverity group enables/measures verity only on its own TMPDIR tempfile.
No source tree, immutable flags, mounts, credentials or authority are changed.
"""
from collections import OrderedDict
from contextlib import ExitStack
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import authority_local_artifact_measure as measure


def entry(path):
    info = path.stat()
    return dict(path=path.name, kind="configuration", mode=stat.S_IMODE(info.st_mode),
                uid=info.st_uid, gid=info.st_gid)


def expected(path, raw):
    return dict(entry(path), size=len(raw), sha256="sha256:" + hashlib.sha256(raw).hexdigest())


class ArtifactMeasureCacheTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="artifact-cache-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.root)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE", OrderedDict()))
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE_PID", os.getpid()))
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE_LOCK", threading.Lock()))
        self.real_eligible = measure._ext4_verity_cache_eligible
        self.eligible = self.stack.enter_context(patch.object(measure, "_ext4_verity_cache_eligible", return_value=True))
        self.real_pread = os.pread
        self.reads, self.kernel_calls, self.verity = [], [], {}
        self.after_read = None
        self.stack.enter_context(patch.object(measure.os, "pread", side_effect=self.pread))
        self.stack.enter_context(patch.object(measure.fcntl, "ioctl", side_effect=self.ioctl))

    def file(self, name="public", raw=b"synthetic-public-content"):
        path = self.directory / name
        path.write_bytes(raw)
        path.chmod(0o400)
        self.verity[path.stat().st_ino] = hashlib.sha256(b"synthetic-verity:" + raw).digest()
        return path

    def ioctl(self, fd, request, buffer, mutate=True):
        info = os.fstat(fd)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(request, 0xC0046686)
        self.assertIs(mutate, True)
        self.assertEqual(len(buffer), 68)
        self.assertEqual(struct.unpack("=HH", buffer[:4]), (0, 64))
        self.kernel_calls.append((info.st_dev, info.st_ino))
        value = self.verity[info.st_ino]
        if isinstance(value, BaseException):
            raise value
        algorithm, length, digest = value if isinstance(value, tuple) else (1, 32, value)
        buffer[:] = struct.pack("=HH64s", algorithm, length, digest)
        return 0

    def pread(self, fd, count, offset):
        raw = self.real_pread(fd, count, offset)
        self.reads.append((count, offset, len(raw)))
        if self.after_read is not None:
            callback = self.after_read
            self.after_read = None
            callback(fd, raw)
        return raw

    def read(self, path, *, check=lambda: None, selected=None):
        self.reads.clear()
        self.kernel_calls.clear()
        return measure.measure_file(self.root, entry(path) if selected is None else selected, check=check)

    def assert_full_read(self, size):
        self.assertEqual(sum(length for _, _, length in self.reads), size)
        self.assertEqual(self.reads[-1], (1, size, 0))

    def assert_hit(self, size):
        self.assertEqual(self.reads, [(1, size, 0)])
        self.assertGreaterEqual(len(self.kernel_calls), 2)

    def test_first_hash_then_content_identity_hit_and_empty_file(self):
        raw = b"public" * 200_000  # Cross the actual 1 MiB chunk boundary.
        path = self.file(raw=raw)
        checks = []
        self.assertEqual(self.read(path, check=lambda: checks.append(None)), expected(path, raw))
        self.assert_full_read(len(raw))
        self.assertEqual(len(checks), 4)  # Pre-open, two chunks, terminal.
        checks.clear()
        first = self.read(path, check=lambda: checks.append(None))
        self.assert_hit(len(raw))
        self.assertEqual(len(checks), 2)  # Pre-open and terminal only.
        first["sha256"] = "sha256:" + "0" * 64
        self.assertEqual(self.read(path), expected(path, raw))
        self.assert_hit(len(raw))
        # Cache identity is content/size, not a trusted path/metadata shortcut.
        same = self.file("same-content", raw)
        self.assertNotEqual(path.stat().st_ino, same.stat().st_ino)
        self.assertEqual(self.read(same), expected(same, raw))
        self.assert_hit(len(raw))
        empty = self.file("empty", b"")
        self.assertEqual(self.read(empty), expected(empty, b""))
        self.assertEqual(self.read(empty), expected(empty, b""))
        self.assert_hit(0)

    def test_new_content_and_verity_miss_even_at_same_path(self):
        old, new = b"old-public-content", b"new-public-content"
        path = self.file(raw=old)
        self.read(path)
        path.chmod(0o600)
        path.write_bytes(new)
        path.chmod(0o400)
        self.verity[path.stat().st_ino] = hashlib.sha256(b"synthetic-verity:" + new).digest()
        self.assertEqual(self.read(path), expected(path, new))
        self.assert_full_read(len(new))
        self.assertEqual(self.read(path), expected(path, new))
        self.assert_hit(len(new))

    def test_nonverity_and_unknown_filesystems_rehash_without_cache(self):
        raw = b"not-sealed-public-content"
        path = self.file(raw=raw)
        for code in (errno.ENODATA, errno.ENOTTY, errno.EOPNOTSUPP):
            self.verity[path.stat().st_ino] = OSError(code, "synthetic unsupported verity")
            for _ in range(2):
                self.assertEqual(self.read(path), expected(path, raw))
                self.assert_full_read(len(raw))
            self.assertEqual(len(measure._FILE_DIGEST_CACHE), 0)
        self.verity[path.stat().st_ino] = (2, 64, b"s" * 64)
        for _ in range(2):
            self.assertEqual(self.read(path), expected(path, raw))
            self.assert_full_read(len(raw))
        self.assertEqual(len(measure._FILE_DIGEST_CACHE), 0)
        self.eligible.return_value = False
        self.verity[path.stat().st_ino] = AssertionError("unknown filesystem must not reach ioctl")
        for _ in range(2):
            self.assertEqual(self.read(path), expected(path, raw))
            self.assert_full_read(len(raw))
            self.assertEqual(self.kernel_calls, [])
        self.assertEqual(len(measure._FILE_DIGEST_CACHE), 0)

    def test_same_fd_filesystem_admission_is_ext4_only_and_fail_closed(self):
        path = self.file()
        with path.open("rb") as stream:
            descriptor = stream.fileno()
            for filesystem, admitted in ((0xEF53, True), (0x65735546, False),
                                          (0x01021994, False), (0, False)):
                def statfs(fd, pointer):
                    self.assertEqual(fd, descriptor)
                    pointer._obj.f_type = filesystem
                    return 0

                with patch.object(measure, "_FSTATFS", side_effect=statfs) as syscall:
                    self.assertIs(self.real_eligible(descriptor), admitted)
                    syscall.assert_called_once()
            with patch.object(measure, "_FSTATFS", return_value=-1), \
                    patch.object(measure.ctypes, "get_errno", return_value=errno.EIO):
                with self.assertRaises(OSError) as caught:
                    self.real_eligible(descriptor)
                self.assertEqual(caught.exception.errno, errno.EIO)
            with patch.object(measure, "_FSTATFS", return_value=1), self.assertRaises(ValueError):
                self.real_eligible(descriptor)
            with patch.object(measure.sys, "platform", "not-linux"), \
                    patch.object(measure, "_FSTATFS", side_effect=AssertionError("unsupported ABI")):
                self.assertIs(self.real_eligible(descriptor), False)

    def test_warm_cache_does_not_bypass_metadata_or_entry_validation(self):
        path = self.file()
        self.read(path)
        original = entry(path)
        for changes in ({"mode": 0o600}, {"uid": original["uid"] + 1},
                        {"gid": original["gid"] + 1}, {"kind": "not-an-artifact-kind"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.read(path, selected={**original, **changes})
            self.assertEqual(sum(length for _, _, length in self.reads), 0)
        linked = self.directory / "hardlink"
        os.link(path, linked)
        with self.assertRaises(ValueError):
            self.read(path)
        linked.unlink()
        alias = self.directory / "symlink"
        alias.symlink_to(path.name)
        with self.assertRaises(OSError):
            self.read(alias, selected={**original, "path": alias.name})
        self.assertEqual(self.read(path)["sha256"], expected(path, path.read_bytes())["sha256"])
        self.assert_hit(path.stat().st_size)

    def test_malformed_unexpected_ioctl_and_filesystem_failures_refuse(self):
        path = self.file()
        for value in ((2, 32, b"a" * 64), (1, 0, b"a" * 64), (1, 33, b"a" * 64),
                      (0, 64, bytes(64))):
            self.verity[path.stat().st_ino] = value
            with self.subTest(value=value[:2]), self.assertRaises(ValueError):
                self.read(path)
            self.assertEqual(len(measure._FILE_DIGEST_CACHE), 0)
            self.assertEqual(self.reads, [])
        for result in (False, True, 1, b"unexpected ioctl result"):
            with patch.object(measure.fcntl, "ioctl", return_value=result), self.assertRaises(ValueError):
                self.read(path)
            self.assertEqual(len(measure._FILE_DIGEST_CACHE), 0)
            self.assertEqual(self.reads, [])
        for code in (errno.EIO, errno.EPERM, errno.EINVAL, errno.EBADF, errno.ENOSYS):
            sentinel = OSError(code, "synthetic kernel refusal")
            self.verity[path.stat().st_ino] = sentinel
            with self.assertRaises(OSError) as caught:
                self.read(path)
            self.assertIs(caught.exception, sentinel)
            self.assertEqual(self.reads, [])
        sentinel = OSError(errno.EIO, "synthetic fstatfs failure")
        self.eligible.side_effect = sentinel
        with self.assertRaises(OSError) as caught:
            self.read(path)
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(self.kernel_calls, [])

    def test_deadline_failure_on_hit_or_before_insert_never_returns_success(self):
        path = self.file()
        self.read(path)
        sentinel = TimeoutError("synthetic original deadline")

        def fail_after_kernel_read():
            if self.kernel_calls:
                raise sentinel

        with self.assertRaises(TimeoutError) as caught:
            self.read(path, check=fail_after_kernel_read)
        self.assertIs(caught.exception, sentinel)
        self.assertEqual(sum(length for _, _, length in self.reads), 0)
        self.read(path)
        self.assert_hit(path.stat().st_size)
        fresh = self.file("not-yet-cached", b"different-public-content")

        def fail_after_eof():
            if self.reads and self.reads[-1][2] == 0:
                raise sentinel

        with self.assertRaises(TimeoutError) as caught:
            self.read(fresh, check=fail_after_eof)
        self.assertIs(caught.exception, sentinel)
        self.read(fresh)
        self.assert_full_read(fresh.stat().st_size)

    def test_postread_identity_or_verity_change_refuses_and_is_not_cached(self):
        for variant in ("identity", "verity"):
            with self.subTest(variant=variant):
                raw = ("public-" + variant).encode()
                path = self.file(variant, raw)

                def change(_fd, data):
                    self.assertEqual(data, raw)
                    if variant == "identity":
                        info = path.stat()
                        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000))
                    else:
                        self.verity[path.stat().st_ino] = b"v" * 32

                self.after_read = change
                with self.assertRaises(ValueError):
                    self.read(path)
                self.assertEqual(self.read(path), expected(path, raw))
                self.assert_full_read(len(raw))
                self.read(path)
                self.assert_hit(len(raw))

    def test_bounded_eviction_and_pid_changes_require_new_full_reads(self):
        self.assertLessEqual(measure._FILE_DIGEST_CACHE_LIMIT, 32768)
        with patch.object(measure, "_FILE_DIGEST_CACHE_LIMIT", 2):
            files = [self.file(str(index), ("public-" + str(index)).encode()) for index in range(3)]
            for path in files:
                self.read(path)
                self.assertLessEqual(len(measure._FILE_DIGEST_CACHE), 2)
            self.assertEqual(len(measure._FILE_DIGEST_CACHE), 2)
            self.read(files[-1])
            self.assert_hit(files[-1].stat().st_size)
            self.read(files[0])
            self.assert_full_read(files[0].stat().st_size)
        path = files[0]
        self.read(path)
        self.assert_hit(path.stat().st_size)
        original_pid = os.getpid()
        with patch.object(measure.os, "getpid", return_value=original_pid + 1):
            self.read(path)
            self.assert_full_read(path.stat().st_size)
            self.read(path)
            self.assert_hit(path.stat().st_size)
        self.read(path)
        self.assert_full_read(path.stat().st_size)


class RealKernelVerityTest(unittest.TestCase):
    def test_real_tempfile_verity_hash_then_hit_without_body_read(self):
        # Opt-in only. This mutates just the new test file; no mount/immutable
        # operation or imported installer runs. Unsupported kernels are the
        # only skip: permission errors and malformed successful ioctls fail.
        with tempfile.TemporaryDirectory(prefix="artifact-cache-real-verity-") as directory:
            path = Path(directory) / "public"
            raw = b"real-kernel-synthetic-public-content" * 4096
            path.write_bytes(raw)  # Writer is closed before enabling verity.
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                enable = struct.pack("=IIIIQIIQ11Q", 1, 1, 4096, 0, 0, 0, 0, 0, *([0] * 11))
                self.assertEqual(len(enable), 128)
                try:
                    fcntl.ioctl(descriptor, 0x40806685, enable)
                except OSError as error:
                    if error.errno in {errno.ENOTTY, errno.EOPNOTSUPP, errno.ENOSYS}:
                        self.skipTest("temporary filesystem/kernel does not support fs-verity")
                    raise
                digest = bytearray(struct.pack("=HH64s", 0, 64, bytes(64)))
                fcntl.ioctl(descriptor, 0xC0046686, digest, True)
                self.assertEqual(struct.unpack("=HH", digest[:4]), (1, 32))
                self.assertTrue(measure._ext4_verity_cache_eligible(descriptor))
                # Mode permits owner writes; the refusal must be actual verity,
                # not a synthetic ioctl or the ordinary 0400 permission bit.
                with self.assertRaises(OSError) as caught:
                    writer = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
                    os.close(writer)
                self.assertEqual(caught.exception.errno, errno.EPERM)
                pread = os.pread
                reads = []

                def tracked(fd, count, offset):
                    result = pread(fd, count, offset)
                    reads.append((count, offset, len(result)))
                    return result

                with patch.object(measure, "_FILE_DIGEST_CACHE", OrderedDict()), \
                        patch.object(measure, "_FILE_DIGEST_CACHE_PID", os.getpid()), \
                        patch.object(measure.os, "pread", side_effect=tracked):
                    self.assertEqual(measure.measure_file(root, entry(path), check=lambda: None), expected(path, raw))
                    self.assertEqual(sum(length for _, _, length in reads), len(raw))
                    reads.clear()
                    self.assertEqual(measure.measure_file(root, entry(path), check=lambda: None), expected(path, raw))
                    self.assertEqual(reads, [(1, len(raw), 0)])
            finally:
                os.close(root)
                os.close(descriptor)


RUN_REAL = False


def load_tests(loader, tests, pattern):
    result = loader.loadTestsFromTestCase(ArtifactMeasureCacheTests)
    if RUN_REAL:
        result.addTests(loader.loadTestsFromTestCase(RealKernelVerityTest))
    return result


if __name__ == "__main__":
    RUN_REAL = "--real-fsverity" in sys.argv
    if RUN_REAL:
        sys.argv.remove("--real-fsverity")
    unittest.main(verbosity=2)
