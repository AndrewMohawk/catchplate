#!/usr/bin/env python3
"""Real temporary files/FD custody, SYNTHETIC kernel and live-owner controls.

These tests exercise the issuer's real guarded reader and content-cache join.
Filesystem eligibility, fs-verity, frozen/generation and live-owner responses
are explicit test substitutes: no authentic child, signing, authority, physical
pilot admission, real fs-verity enforcement or measured latency is claimed.
"""
from collections import OrderedDict
from contextlib import ExitStack, contextmanager
import ast
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
from serverware import authority_local_artifact_measure as measure
from serverware import authority_local_launch_authorization as subject


class LaunchContentCacheTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="launch-content-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE", OrderedDict()))
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE_PID", os.getpid()))
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE_LOCK", threading.Lock()))
        self.eligible = self.stack.enter_context(patch.object(
            measure, "_ext4_verity_cache_eligible", return_value=True))
        self.generation = self.stack.enter_context(patch.object(subject, "_generation", return_value=7))
        self.frozen = self.stack.enter_context(patch.object(subject, "_frozen"))
        self.verity = {}
        self.stack.enter_context(patch.object(measure.fcntl, "ioctl", side_effect=self.ioctl))
        self.real_pread = os.pread

    def file(self, name="public", raw=b"public retained artifact" * 4000):
        path = self.directory / name
        path.write_bytes(raw)
        path.chmod(0o400)
        # Content-equivalent files deliberately have the same SYNTHETIC verity
        # identity, while their real inodes and each owner's descriptors differ.
        self.verity[path.stat().st_ino] = hashlib.sha256(b"synthetic-verity:" + raw).digest()
        return path

    def ioctl(self, fd, request, buffer, mutate=True):
        self.assertEqual(request, measure.FS_IOC_MEASURE_VERITY)
        self.assertIs(mutate, True)
        self.assertEqual(len(buffer), 68)
        self.assertEqual(struct.unpack("=HH", buffer[:4]), (0, 64))
        value = self.verity[os.fstat(fd).st_ino]
        if isinstance(value, BaseException):
            raise value
        buffer[:] = struct.pack("=HH64s", 1, 32, value)
        return 0

    @contextmanager
    def owner(self, path):
        owner = subject.LocalLaunchAuthorizationIssuer.__new__(subject.LocalLaunchAuthorizationIssuer)
        owner.handles, owner.owned, owner.links, owner.child_handles = [], {}, [], {}
        owner.link_by_fd, owner.mapping_fds = {}, set()
        owner._check_live = Mock()
        original = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            held = os.dup(original)
            owner._hold(held)
            info = os.fstat(held)
            identity = subject.io._identity(info)
            owner.links.append((held, str(path), identity))
            owner.link_by_fd[held] = (str(path), identity)
            owner.child_handles[original] = held
            row = dict(name="file-00000", purpose="configuration", surviveExec=True,
                fd=original, runtimePath="/runtime/public", device=info.st_dev,
                inode=info.st_ino, mode=stat.S_IMODE(info.st_mode), uid=info.st_uid,
                gid=info.st_gid, size=info.st_size, sha256=subject.sha(path.read_bytes()),
                generation=7, fsVerityDigest="sha256:" + self.verity[info.st_ino].hex())
            owner._read = Mock(wraps=owner._read)
            yield owner, row, held
        finally:
            for descriptor in reversed(owner.handles):
                os.close(descriptor)
            os.close(original)

    def warm(self, owner, row):
        result = owner._row(row, regular=True, reuse_content=True)
        owner._read.reset_mock()
        owner._check_live.reset_mock()
        return result

    def test_first_read_then_repeat_hit_keeps_eof_and_fresh_live_checks(self):
        for index, raw in enumerate((b"", b"public" * 22000)):
            with self.subTest(size=len(raw)), self.owner(self.file(str(index), raw)) as (owner, row, held):
                with patch.object(subject.os, "pread", wraps=self.real_pread) as reads:
                    self.assertEqual(owner._row(row, regular=True, reuse_content=True), held)
                owner._read.assert_called_once_with(held, subject.launch.MAX_CLOSURE_FILE_BYTES)
                body_reads = [call for call in reads.call_args_list if call.args[2] < len(raw)]
                self.assertEqual(sum(call.args[1] for call in body_reads), len(raw))
                self.assertTrue(all(call.args[1] <= 65536 for call in body_reads))
                owner._read.reset_mock()
                owner._check_live.reset_mock()
                with patch.object(subject.os, "pread", wraps=self.real_pread) as reads:
                    self.assertEqual(owner._row(row, regular=True, reuse_content=True), held)
                owner._read.assert_not_called()
                reads.assert_called_once_with(held, 1, len(raw))
                self.assertGreaterEqual(owner._check_live.call_count, 3)

    def test_separate_owners_and_inodes_share_content_not_custody(self):
        first, second = self.file("first"), self.file("second")
        self.assertNotEqual(first.stat().st_ino, second.stat().st_ino)
        with self.owner(first) as (one, first_row, first_fd), self.owner(second) as (two, second_row, second_fd):
            self.assertNotEqual(first_fd, second_fd)
            self.warm(one, first_row)
            self.assertEqual(two._row(second_row, regular=True, reuse_content=True), second_fd)
            two._read.assert_not_called()
            self.assertGreaterEqual(two._check_live.call_count, 3)
            self.assertEqual(two.child_handles, {second_row["fd"]: second_fd})
            self.assertNotIn(first_fd, two.owned)
            two._check_live.side_effect = ValueError("synthetic new owner expired")
            with self.assertRaises(ValueError):
                two._row(second_row, regular=True, reuse_content=True)

    def test_existing_artifact_measurement_memo_is_shared_not_a_second_cache(self):
        path = self.file()
        info = path.stat()
        root = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            measured = measure.measure_file(root, dict(path=path.name, kind="configuration",
                mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid), check=Mock())
        finally:
            os.close(root)
        with self.owner(path) as (owner, row, held):
            self.assertEqual(measured["sha256"], row["sha256"])
            self.assertEqual(owner._row(row, regular=True, reuse_content=True), held)
            owner._read.assert_not_called()
            self.assertGreaterEqual(owner._check_live.call_count, 3)

    def test_claimed_digest_never_seeds_content_cache(self):
        with self.owner(self.file()) as (owner, row, held):
            forged = dict(row, sha256="sha256:" + "0" * 64)
            with self.assertRaises(ValueError):
                owner._row(forged, regular=True, reuse_content=True)
            owner._read.assert_called_once_with(held, subject.launch.MAX_CLOSURE_FILE_BYTES)
            # The independently read actual digest may be memoized despite a
            # later signed-row mismatch; the claimed digest must never be used.
            self.assertEqual(set(measure._FILE_DIGEST_CACHE.values()), {row["sha256"][7:]})
            self.assertEqual(owner._row(row, regular=True, reuse_content=True), held)
            with self.assertRaises(ValueError):
                owner._row(forged, regular=True, reuse_content=True)
            self.assertEqual(owner._read.call_count, 1)

    def test_warm_hit_rejects_signed_hash_size_and_physical_binding_changes(self):
        with self.owner(self.file()) as (owner, row, _held):
            self.warm(owner, row)
            changes = {"sha256": "sha256:" + "f" * 64, "size": row["size"] + 1,
                "device": row["device"] + 1, "inode": row["inode"] + 1,
                "mode": row["mode"] ^ 0o200, "uid": row["uid"] + 1,
                "gid": row["gid"] + 1, "generation": 8,
                "fsVerityDigest": "sha256:" + "e" * 64}
            for field, changed in changes.items():
                with self.subTest(field=field), self.assertRaises(ValueError):
                    owner._row(dict(row, **{field: changed}), regular=True, reuse_content=True)
            owner._read.assert_not_called()

    def test_warm_hit_rejects_changed_generation_verity_frozen_and_live_owner(self):
        for variant in ("generation", "verity", "frozen", "owner", "deadline"):
            with self.subTest(variant=variant), self.owner(self.file(variant)) as (owner, row, _held):
                self.warm(owner, row)
                with ExitStack() as controls:
                    if variant == "generation":
                        controls.enter_context(patch.object(subject, "_generation", return_value=8))
                    elif variant == "verity":
                        self.verity[row["inode"]] = b"v" * 32
                    elif variant == "frozen":
                        controls.enter_context(patch.object(subject, "_frozen", side_effect=ValueError("mutable")))
                    else:
                        owner._check_live.side_effect = ValueError("synthetic " + variant + " refusal")
                    with self.assertRaises(ValueError):
                        owner._row(row, regular=True, reuse_content=True)
                owner._read.assert_not_called()

    def test_warm_hit_rejects_path_fd_registration_and_actual_metadata_drift(self):
        for variant in ("path", "owned", "child-index", "mapping", "mode"):
            with self.subTest(variant=variant), self.owner(self.file(variant)) as (owner, row, held):
                self.warm(owner, row)
                if variant == "path":
                    self.file("replacement").replace(self.directory / variant)
                elif variant == "owned":
                    del owner.owned[held]
                elif variant == "child-index":
                    del owner.child_handles[row["fd"]]
                    # Refuse the newly required acquisition, not an authentic
                    # child admission (this fixture deliberately has none).
                    owner._open = Mock(side_effect=ValueError("changed child index"))
                    owner.child_pid = os.getpid()
                elif variant == "mapping":
                    owner.mapping_fds.add(held)
                else:
                    (self.directory / variant).chmod(0o600)
                with self.assertRaises(ValueError):
                    owner._row(row, regular=True, reuse_content=True)
                owner._read.assert_not_called()

    def test_after_eof_changes_still_refuse_warm_hit(self):
        for variant in ("generation", "verity", "frozen", "deadline", "path", "owned",
                        "child-index", "mapping", "mode", "eof"):
            with self.subTest(variant=variant), self.owner(self.file(variant)) as (owner, row, held):
                self.warm(owner, row)
                def changed(fd, count, offset):
                    self.assertEqual((fd, count, offset), (held, 1, row["size"]))
                    result = self.real_pread(fd, count, offset)
                    if variant == "generation":
                        self.generation.return_value = 8
                    elif variant == "verity":
                        self.verity[row["inode"]] = b"z" * 32
                    elif variant == "frozen":
                        self.frozen.side_effect = ValueError("no longer frozen")
                    elif variant == "deadline":
                        owner._check_live.side_effect = ValueError("original deadline expired")
                    elif variant == "path":
                        self.file("after-replacement").replace(self.directory / variant)
                    elif variant == "owned":
                        del owner.owned[held]
                    elif variant == "child-index":
                        del owner.child_handles[row["fd"]]
                    elif variant == "mapping":
                        owner.mapping_fds.add(held)
                    elif variant == "mode":
                        (self.directory / variant).chmod(0o600)
                    else:
                        return b"unexpected"
                    return result
                try:
                    with patch.object(subject.os, "pread", side_effect=changed), self.assertRaises(ValueError):
                        owner._row(row, regular=True, reuse_content=True)
                    owner._read.assert_not_called()
                finally:
                    self.generation.return_value = 7
                    self.frozen.side_effect = None

    def test_default_mutable_credential_and_unsupported_rows_keep_real_reads(self):
        with self.owner(self.file()) as (owner, row, held):
            self.warm(owner, row)
            for variant in ("default", "false", "no-generation", "no-verity", "credential", "unsupported"):
                with self.subTest(variant=variant), ExitStack() as controls:
                    selected, keywords = dict(row), {"reuse_content": True}
                    if variant == "default":
                        keywords = {}
                    elif variant == "false":
                        keywords = {"reuse_content": False}
                    elif variant == "no-generation":
                        selected.pop("generation")
                    elif variant == "no-verity":
                        selected["fsVerityDigest"] = None
                    elif variant == "credential":
                        selected.pop("generation")
                        selected.pop("fsVerityDigest")
                        selected["name"] = "SYNTHETIC_CREDENTIAL_DESCRIPTOR"
                    else:
                        controls.enter_context(patch.object(measure, "_ext4_verity_cache_eligible", return_value=False))
                    owner._read.reset_mock()
                    self.assertEqual(owner._row(selected, regular=True, **keywords), held)
                    owner._read.assert_called_once_with(held, subject.launch.MAX_CLOSURE_FILE_BYTES)

    def test_reuse_switch_is_exact_boolean_and_regular_file_only(self):
        with self.owner(self.file()) as (owner, row, _held):
            for value in (None, 0, 1, "true", [], {}):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    owner._row(row, regular=True, reuse_content=value)
            with self.assertRaises(ValueError):
                owner._row(row, regular=False, reuse_content=True)
            owner._read.assert_not_called()

    def test_native_measurement_is_populated_from_each_current_owner(self):
        with self.owner(self.file()) as (one, first, first_fd), self.owner(self.file("same")) as (two, second, second_fd):
            one_map, two_map = {}, {}
            one._row(first, regular=True, native_measurements=one_map, reuse_content=True)
            two._row(second, regular=True, native_measurements=two_map, reuse_content=True)
            two._read.assert_not_called()
            for owner, row, fd, mapping in ((one, first, first_fd, one_map), (two, second, second_fd, two_map)):
                self.assertEqual(mapping, {row["runtimePath"]: (fd, row["fd"],
                    subject.io._identity(os.fstat(fd)), 7, row["fsVerityDigest"], row["sha256"])})
                with self.assertRaises(ValueError):
                    owner._row(row, regular=True, native_measurements=mapping, reuse_content=True)
            self.assertNotEqual(one_map[first["runtimePath"]][:3], two_map[second["runtimePath"]][:3])

    def test_borrowed_row_keeps_default_minimal_contract_and_optin_existing_primitives(self):
        class Borrower:
            _row = subject.LocalLaunchAuthorizationIssuer._row
        with self.owner(self.file()) as (owner, row, held):
            minimal = Borrower()
            minimal._child_fd, minimal._read = owner._child_fd, owner._read
            self.assertEqual(minimal._row(row, regular=True), held)
            self.assertFalse(hasattr(minimal, "_check_live"))
            owner._read.assert_called_once_with(held, subject.launch.MAX_CLOSURE_FILE_BYTES)
            borrowed = Borrower()
            for name in ("_child_fd", "_read", "_check_live", "_check_link", "_owned_identity",
                         "owned", "link_by_fd", "mapping_fds", "child_handles"):
                setattr(borrowed, name, getattr(owner, name))
            self.assertEqual(borrowed._row(row, regular=True, reuse_content=True), held)
            owner._read.reset_mock()
            self.assertEqual(borrowed._row(row, regular=True, reuse_content=True), held)
            owner._read.assert_not_called()

    def test_sdk_optin_is_only_the_retained_public_file_loop(self):
        tree = ast.parse(Path(subject.__file__).read_text())
        issuer = next(node for node in tree.body if isinstance(node, ast.ClassDef)
            and node.name == "LocalLaunchAuthorizationIssuer")
        verify = next(node for node in issuer.body if isinstance(node, ast.FunctionDef)
            and node.name == "verify_live")
        calls = [node for node in ast.walk(verify) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "_row"]
        opted = [node for node in calls if any(keyword.arg == "reuse_content"
            and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            for keyword in node.keywords)]
        self.assertEqual(len(opted), 1)
        loop = next(node for node in ast.walk(verify) if isinstance(node, ast.For)
            and ast.unparse(node.iter) == "request['retainedFiles']")
        self.assertIn(opted[0], list(ast.walk(loop)))
        self.assertGreaterEqual(len(calls), 4)  # Public files, directories, bootstrap and credentials.
        self.assertTrue(all(not any(keyword.arg == "reuse_content" for keyword in node.keywords)
            for node in calls if node is not opted[0]))
        mapping = next(node for node in issuer.body if isinstance(node, ast.FunctionDef)
            and node.name == "_mappings")
        self.assertNotIn("_digest_owned_file", ast.unparse(mapping))
        self.assertIn("mapping=True", ast.unparse(mapping))


if __name__ == "__main__":
    unittest.main()
