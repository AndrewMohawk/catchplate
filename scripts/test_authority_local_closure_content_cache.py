#!/usr/bin/env python3
"""Actual tempfile/FD/ELF reads with SYNTHETIC fs-verity and owner controls.

No file is executed, no real inode flags or verity are enabled, and no signing
key, authenticated snapshot, native owner or physical-pilot acceptance is used.
The mock kernel content identities exercise digest reuse, not hardware proof.
"""
from collections import OrderedDict
from contextlib import ExitStack
from copy import deepcopy
import asyncio
import errno
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.test_authority_local_closure import elf_bytes
from serverware import authority_local_artifact_measure as measure
from serverware import authority_local_closure as local


class ClosureContentCacheTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="closure-content-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.root)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE", OrderedDict()))
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE_PID", os.getpid()))
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE_LOCK", threading.Lock()))
        self.eligible = self.stack.enter_context(patch.object(
            measure, "_ext4_verity_cache_eligible", return_value=True))
        self.frozen = self.stack.enter_context(patch.object(measure, "_frozen"))
        self.verity = {}
        self.stack.enter_context(patch.object(measure.fcntl, "ioctl", side_effect=self.ioctl))
        self.real_pread, self.real_open = os.pread, local._open
        self.check = Mock()
        self.opened, self.reads, self.elf_calls = [], [], []
        bootstrap = self.directory / "bootstrap.py"
        bootstrap.write_bytes(b"pass\n")
        bootstrap.chmod(0o400)

    def ioctl(self, fd, request, buffer, mutate=True):
        self.assertEqual(request, measure.FS_IOC_MEASURE_VERITY)
        self.assertIs(mutate, True)
        self.assertEqual(struct.unpack("=HH", buffer[:4]), (0, 64))
        self.assertEqual(len(buffer), 68)
        value = self.verity[os.fstat(fd).st_ino]
        if isinstance(value, BaseException):
            raise value
        algorithm, length, digest = value if isinstance(value, tuple) else (1, 32, value)
        buffer[:] = struct.pack("=HH64s", algorithm, length, digest)
        return 0

    def file(self, name="native", raw=None):
        raw = elf_bytes() + b"public padding" * 90000 if raw is None else raw
        path = self.directory / name
        path.write_bytes(raw)
        path.chmod(0o400)
        self.verity[path.stat().st_ino] = hashlib.sha256(b"synthetic-verity:" + raw).digest()
        return path, raw

    def roster(self, path, raw):
        info = path.stat()
        native = dict(path=path.name, kind="elf-executable", mode=stat.S_IMODE(info.st_mode),
            uid=info.st_uid, gid=info.st_gid, size=len(raw), sha256=local.sha(raw))
        bootstrap = dict(path="bootstrap.py", kind="authority-source", mode=0o400,
            uid=os.geteuid(), gid=os.getegid(), size=5, sha256=local.sha(b"pass\n"))
        selected = dict(pythonImportClosure=[], nativeClosure=dict(executables=[dict(
            path=path.name, runtimePath="/runtime/python", elfClass="ELF64", machine=62,
            ptInterp=None, needed=[], sha256=native["sha256"])], objects=[]),
            stageZero=dict(path="bootstrap.py", size=5, sha256=bootstrap["sha256"],
                interpreter=dict(path=path.name, size=len(raw), sha256=native["sha256"])))
        return selected, {"files": [bootstrap, native]}

    def verify(self, selected, measured, *, after_read=None):
        self.opened, self.reads, self.elf_calls = [], [], []
        def opened(root, path):
            descriptor = self.real_open(root, path)
            self.opened.append(descriptor)
            return descriptor
        def read(fd, count, offset):
            raw = self.real_pread(fd, count, offset)
            self.reads.append((fd, count, offset, len(raw)))
            return raw if after_read is None else after_read(fd, count, offset, raw)
        with patch.object(local, "_open", side_effect=opened), \
                patch.object(local, "elf_metadata", wraps=local.elf_metadata) as elf, \
                patch.object(local.os, "pread", side_effect=read):
            try:
                return local.verify_roster(selected, measured, self.root, check=self.check)
            finally:
                self.elf_calls = list(elf.call_args_list)
                for descriptor in self.opened:
                    with self.assertRaises(OSError) as closed:
                        os.fstat(descriptor)
                    self.assertEqual(closed.exception.errno, errno.EBADF)

    def assert_hot(self, size):
        self.assertEqual(len(self.opened), 1)
        descriptor = self.opened[0]
        self.assertEqual([call.args for call in self.elf_calls], [(descriptor,)])
        self.assertEqual(self.reads, [(descriptor, 64, 0, 64),
            (descriptor, 56, 64, 56), (descriptor, 1, size, 0)])

    def assert_streamed(self, size):
        descriptor = self.opened[0]
        self.assertEqual(self.reads[:2], [(descriptor, 64, 0, 64), (descriptor, 56, 64, 56)])
        content = self.reads[2:-1]
        self.assertTrue(content)
        self.assertEqual(sum(length for _, _, _, length in content), size)
        offset = 0
        for fd, count, start, length in content:
            self.assertEqual((fd, start), (descriptor, offset))
            self.assertEqual(count, min(1024 * 1024, size - offset))
            self.assertEqual(count, length)
            offset += length
        self.assertEqual(self.reads[-1], (descriptor, 1, size, 0))

    def test_cold_stream_then_hot_same_opened_fd_elf_and_eof(self):
        path, raw = self.file()
        selected, measured = self.roster(path, raw)
        self.verify(selected, measured)
        self.assert_streamed(len(raw))
        self.check.reset_mock()
        self.frozen.reset_mock()
        self.verify(selected, measured)
        self.assert_hot(len(raw))
        self.assertGreaterEqual(self.check.call_count, 4)
        self.assertGreaterEqual(self.frozen.call_count, 2)

    def test_artifact_measurement_populates_the_same_content_only_cache(self):
        path, raw = self.file()
        selected, measured = self.roster(path, raw)
        entry = {key: measured["files"][1][key] for key in measure.FIELDS}
        actual = measure.measure_file(self.root, entry, check=self.check)
        self.assertEqual(actual["sha256"], measured["files"][1]["sha256"])
        self.verify(selected, measured)
        self.assert_hot(len(raw))

    def test_equivalent_content_new_inode_still_reads_its_own_elf(self):
        first, raw = self.file("one")
        second, _ = self.file("two", raw)
        self.assertNotEqual(first.stat().st_ino, second.stat().st_ino)
        self.verify(*self.roster(first, raw))
        self.verify(*self.roster(second, raw))
        self.assert_hot(len(raw))

    def test_changed_content_and_kernel_identity_require_a_new_stream(self):
        path, raw = self.file()
        self.verify(*self.roster(path, raw))
        updated = raw[:-1] + bytes((raw[-1] ^ 1,))
        path.chmod(0o600)
        path.write_bytes(updated)
        path.chmod(0o400)
        self.verity[path.stat().st_ino] = hashlib.sha256(b"synthetic-verity:" + updated).digest()
        self.verify(*self.roster(path, updated))
        self.assert_streamed(len(updated))
        self.assertEqual(set(measure._FILE_DIGEST_CACHE.values()),
            {local.sha(raw)[7:], local.sha(updated)[7:]})
        self.verify(*self.roster(path, updated))
        self.assert_hot(len(updated))

    def test_expected_sha_cannot_seed_or_override_actual_content_digest(self):
        path, raw = self.file()
        selected, measured = self.roster(path, raw)
        forged = "sha256:" + "0" * 64
        selected["nativeClosure"]["executables"][0]["sha256"] = forged
        selected["stageZero"]["interpreter"]["sha256"] = forged
        measured["files"][1]["sha256"] = forged
        with self.assertRaises(ValueError):
            self.verify(selected, measured)
        self.assert_streamed(len(raw))
        self.assertEqual(set(measure._FILE_DIGEST_CACHE.values()), {local.sha(raw)[7:]})
        with self.assertRaises(ValueError):
            self.verify(selected, measured)
        self.assert_hot(len(raw))

    def test_warm_content_never_caches_elf_admission(self):
        path, raw = self.file()
        selected, measured = self.roster(path, raw)
        self.verify(selected, measured)
        invalid = bytearray(raw)
        invalid[18:20] = struct.pack("<H", 183)
        path.chmod(0o600)
        path.write_bytes(invalid)
        path.chmod(0o400)
        # Deliberately retain the SYNTHETIC kernel identity only to force this
        # control's cache availability. Real enforced verity forbids this edit.
        with self.assertRaises(ValueError):
            self.verify(selected, measured)
        self.assertEqual(len(self.elf_calls), 1)
        self.assertEqual(self.reads, [(self.opened[0], 64, 0, 64)])

    def test_hot_lifetime_and_frozen_refusals_before_or_after_eof_close_fd(self):
        for variant in ("caller-before", "frozen-before", "caller-after", "frozen-after", "eof"):
            with self.subTest(variant=variant):
                path, raw = self.file(variant)
                selected, measured = self.roster(path, raw)
                self.verify(selected, measured)
                def changed(_fd, count, offset, content):
                    if (count, offset) == (1, len(raw)):
                        if variant == "caller-after":
                            self.check.side_effect = ValueError("original caller lifetime expired")
                        elif variant == "frozen-after":
                            self.frozen.side_effect = ValueError("no longer frozen")
                        elif variant == "eof":
                            return b"unexpected"
                    return content
                if variant == "caller-before":
                    self.check.side_effect = ValueError("caller identity refused")
                elif variant == "frozen-before":
                    self.frozen.side_effect = ValueError("not frozen")
                try:
                    with self.assertRaises(ValueError):
                        self.verify(selected, measured, after_read=changed)
                finally:
                    self.check.side_effect = None
                    self.frozen.side_effect = None

    def test_metadata_or_verity_drift_during_header_or_eof_refuses(self):
        for variant in ("metadata-header", "metadata-eof", "verity-eof"):
            with self.subTest(variant=variant):
                path, raw = self.file(variant)
                selected, measured = self.roster(path, raw)
                self.verify(selected, measured)
                def changed(_fd, count, offset, content):
                    trigger = (count, offset) == ((64, 0) if variant.endswith("header") else (1, len(raw)))
                    if trigger:
                        if variant.startswith("metadata"):
                            path.chmod(0o600)
                        else:
                            self.verity[path.stat().st_ino] = b"z" * 32
                    return content
                with self.assertRaises(ValueError):
                    self.verify(selected, measured, after_read=changed)

    def test_unsupported_filesystem_or_verity_keeps_bounded_streaming_fallback(self):
        for variant in ("filesystem", "no-verity", "sha512"):
            with self.subTest(variant=variant):
                path, raw = self.file(variant)
                selected, measured = self.roster(path, raw)
                self.verify(selected, measured)
                if variant == "filesystem":
                    self.eligible.return_value = False
                elif variant == "no-verity":
                    self.verity[path.stat().st_ino] = OSError(errno.ENODATA, "synthetic absent verity")
                else:
                    self.verity[path.stat().st_ino] = (2, 64, b"v" * 64)
                try:
                    for _ in range(2):
                        self.verify(selected, measured)
                        self.assert_streamed(len(raw))
                finally:
                    self.eligible.return_value = True

    def test_size_mismatch_and_actual_file_bound_cannot_use_warm_digest(self):
        path, raw = self.file()
        selected, measured = self.roster(path, raw)
        self.verify(selected, measured)
        for size in (len(raw) - 1, len(raw) + 1, True):
            wrong_selected, wrong_measured = deepcopy(selected), deepcopy(measured)
            wrong_selected["stageZero"]["interpreter"]["size"] = size
            wrong_measured["files"][1]["size"] = size
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.verify(wrong_selected, wrong_measured)
        with patch.object(local.spec, "MAX_FILE_BYTES", len(raw) - 1), self.assertRaises(ValueError):
            self.verify(selected, measured)

    def test_cold_chunk_cancellation_preserves_exception_and_never_caches_partial_digest(self):
        path, raw = self.file()
        selected, measured = self.roster(path, raw)
        cancelled = asyncio.CancelledError("synthetic original owner cancelled")
        def cancelled_after_chunk(_fd, count, offset, content):
            if (count, offset) == (1024 * 1024, 0):
                self.check.side_effect = cancelled
            return content
        try:
            with self.assertRaises(asyncio.CancelledError) as failure:
                self.verify(selected, measured, after_read=cancelled_after_chunk)
        finally:
            self.check.side_effect = None
        self.assertIs(failure.exception, cancelled)
        descriptor = self.opened[0]
        self.assertEqual(self.reads, [(descriptor, 64, 0, 64),
            (descriptor, 56, 64, 56), (descriptor, 1024 * 1024, 0, 1024 * 1024)])
        self.assertEqual(measure._FILE_DIGEST_CACHE, {})
        # A later independent verification must read the complete file; the
        # interrupted call has supplied neither a digest nor owner authority.
        self.verify(selected, measured)
        self.assert_streamed(len(raw))

    def test_cold_empty_content_chunk_refuses_without_memo_population(self):
        path, raw = self.file()
        selected, measured = self.roster(path, raw)
        def empty_second_chunk(_fd, count, offset, content):
            return b"" if offset == 1024 * 1024 else content
        with self.assertRaises(ValueError):
            self.verify(selected, measured, after_read=empty_second_chunk)
        self.assertEqual(measure._FILE_DIGEST_CACHE, {})
        self.assertFalse(any(count == 1 and offset == len(raw)
            for _, count, offset, _ in self.reads))
        self.verify(selected, measured)
        self.assert_streamed(len(raw))


if __name__ == "__main__":
    unittest.main()
