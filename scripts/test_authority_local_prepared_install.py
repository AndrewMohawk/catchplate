#!/usr/bin/env python3
"""Prepared-tree filesystem components, NOT a signed installer acceptance.

Actual temp files, openat2, reads, fsync and RENAME_NOREPLACE are exercised.
Root ownership and kernel generation/immutable/fs-verity are SYNTHETIC. No
package, signature, installer admission, activation or real kernel seal is
claimed. The component owner has a bounded, injectable lifetime callback.
"""
from collections import OrderedDict
from contextlib import ExitStack
import errno
import hashlib
import inspect
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import authority_local_install as install
from catchplate import authority_local_artifact_measure as measure


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class PreparedTree:
    STATIC = {"code/main.py": b"public source\n" * 8193, "code/nested/data": b"public\x00\xffdata"}
    FRESH = "code/configuration.json"
    FRESH_BYTES = b'{"public":"fresh-current-selection"}'

    def __enter__(self):
        self.stack = ExitStack()
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="prepared-install-component-")))
        self.prepared = self.directory / "prepared-static"
        self.source = self.directory / "source"
        for path in (self.prepared, self.source):
            path.mkdir(mode=0o700)
        for name, raw in {**self.STATIC, self.FRESH: self.FRESH_BYTES}.items():
            self.write(self.source / name, raw)
            if name in self.STATIC:
                self.write(self.prepared / name, raw)
        self.real_stat, self.real_fstat, self.real_pread = os.stat, os.fstat, os.pread
        self.metadata, self.flags, self.generations, self.verity = {}, {}, {}, {}
        self.reads, self.ioctls, self.chowns = [], [], []
        self.calls, self.cancel, self.after_read, self.allow_sealing = 0, None, None, False
        for parent in (self.source, self.prepared):
            for path in parent.rglob("*"):
                if path.is_file():
                    inode = path.stat().st_ino
                    self.flags[inode] = 0x10
                    self.verity[inode] = hashlib.sha256(b"synthetic-verity:" + path.read_bytes()).digest()
        self.stack.enter_context(patch.object(install.os, "stat", side_effect=self.stat))
        self.stack.enter_context(patch.object(install.os, "fstat", side_effect=self.fstat))
        self.stack.enter_context(patch.object(install.os, "pread", side_effect=self.pread))
        self.stack.enter_context(patch.object(install.os, "fchown", side_effect=self.chown))
        self.stack.enter_context(patch.object(install.fcntl, "ioctl", side_effect=self.ioctl))
        self.stack.enter_context(patch.object(measure, "_ext4_verity_cache_eligible", return_value=True))
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE", OrderedDict()))
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE_PID", os.getpid()))
        self.stack.enter_context(patch.object(measure, "_FILE_DIGEST_CACHE_LOCK", threading.Lock()))
        self.owner = install.LocalAuthorityInstaller(install._TOKEN)
        self.owner.check = self.check  # Explicit filesystem-only component seam.
        self.owner._check_scan_path = lambda _links: self.check()  # Same synthetic lifetime seam.
        self.owner.root = self.owner._hold(os.open(self.directory, install._READ | os.O_DIRECTORY))
        self.owner.source_root = self.owner._hold(os.open(self.source, install._READ | os.O_DIRECTORY))
        info = self.prepared.stat()
        self.pin = dict(relativePath="prepared-static", device=info.st_dev, inode=info.st_ino,
                        generation=17, freshPaths=[self.FRESH])
        self.entries = [dict(path=name, sourceSha256=digest(raw), size=len(raw), mode=0o444,
            uid=0, gid=0, requireFsVerity=True, requireImmutable=True,
            action="copy-fresh" if name == self.FRESH else "adopt-prepared-static")
            for name, raw in sorted({**self.STATIC, self.FRESH: self.FRESH_BYTES}.items())]
        self.owner.value = dict(schema=install.PREPARED_CONFIGURATION_SCHEMA, preparedStatic=self.pin)
        self.owner.plan = dict(entries=self.entries)
        return self

    def __exit__(self, *_):
        try:
            self.owner.close()
        finally:
            self.stack.close()

    @staticmethod
    def write(path, raw):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o444)

    def project(self, info):
        # Only ownership/kernel metadata are synthetic. Every identity, type,
        # mode, link count, length and timestamp otherwise comes from the FD.
        fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        fields.update(st_uid=0, st_gid=0)
        fields.update(self.metadata.get(info.st_ino, {}))
        return SimpleNamespace(**fields)

    def stat(self, *args, **kwargs):
        return self.project(self.real_stat(*args, **kwargs))

    def fstat(self, fd):
        return self.project(self.real_fstat(fd))

    def check(self):
        self.calls += 1
        if self.calls > 1024:
            raise AssertionError("component callback bound exceeded")
        if self.cancel is not None:
            self.cancel()

    def pread(self, fd, count, offset):
        raw = self.real_pread(fd, count, offset)
        self.reads.append((self.real_fstat(fd).st_ino, offset, len(raw)))
        if self.after_read is not None and raw:
            callback, self.after_read = self.after_read, None
            callback(fd)
        return raw

    def chown(self, fd, uid, gid):
        if (uid, gid) != (0, 0):
            raise AssertionError("unexpected synthetic owner")
        self.chowns.append(self.real_fstat(fd).st_ino)

    def ioctl(self, fd, request, buffer, mutate=True):
        info = self.real_fstat(fd)
        inode = info.st_ino
        self.ioctls.append((inode, request))
        if request == 0x80087601:
            buffer[0] = self.generations.get(inode, 17)
        elif request == 0x80086601:
            buffer[0] = self.flags.get(inode, 0)
        elif request == 0xC0046686:
            value = self.verity.get(inode)
            if isinstance(value, BaseException):
                raise value
            if value is None:
                raise OSError(errno.ENODATA, "synthetic unsealed inode")
            algorithm, length, raw = value if isinstance(value, tuple) else (1, 32, value)
            buffer[:] = struct.pack("=HH64s", algorithm, length, raw)
        elif request == 0x40806685 and self.allow_sealing:
            raw = self.real_pread(fd, info.st_size, 0)
            self.verity[inode] = hashlib.sha256(b"synthetic-verity:" + raw).digest()
        elif request == 0x40086602 and self.allow_sealing:
            self.flags[inode] = buffer[0]
        else:
            raise AssertionError("unexpected kernel mutation in adoption")
        return 0

    def adopt(self):
        return self.owner._prepared_tree()

    def identities(self):
        return {str(path.relative_to(self.prepared)): install.protected._identity(self.real_stat(path))
                for path in [self.prepared, *self.prepared.rglob("*")]}


class PreparedInstallFilesystemTests(unittest.TestCase):
    def test_exact_tree_reads_actual_bytes_and_retains_static_inode_metadata(self):
        with PreparedTree() as fixture:
            before = fixture.identities()
            parents, rows = fixture.adopt()
            self.assertEqual(set(parents), {"", "code", "code/nested"})
            self.assertEqual(set(rows), set(fixture.STATIC))
            self.assertEqual(fixture.identities(), before)
            self.assertEqual(fixture.chowns, [])
            for name, raw in fixture.STATIC.items():
                info = fixture.real_stat(fixture.prepared / name)
                row = rows[name]
                self.assertEqual(set(row), {"path", "sha256", "fsVerityDigest", "device", "inode",
                    "generation", "mode", "uid", "gid", "size", "immutable", "action"})
                self.assertEqual((row["inode"], row["device"], row["size"]), (info.st_ino, info.st_dev, len(raw)))
                self.assertEqual(row["sha256"], digest(raw))
                self.assertEqual(row["action"], "adopt-prepared-static")
                self.assertIs(row["immutable"], True)
                self.assertEqual(sum(size for inode, _, size in fixture.reads if inode == info.st_ino), len(raw))
                self.assertIn((info.st_ino, len(raw), 0), fixture.reads)
            self.assertTrue(fixture.prepared.is_dir())  # Validation did not consume it.
            self.assertFalse((fixture.prepared / fixture.FRESH).exists())

    def test_exact_file_and_directory_roster_and_fresh_action_partition(self):
        for change in ("extra-file", "extra-empty-directory", "missing-file", "fresh-present", "fresh-action"):
            with self.subTest(change=change), PreparedTree() as fixture:
                if change == "extra-file":
                    fixture.write(fixture.prepared / "unlisted", b"unlisted")
                elif change == "extra-empty-directory":
                    (fixture.prepared / "unused").mkdir(mode=0o700)
                elif change == "missing-file":
                    (fixture.prepared / "code/nested/data").unlink()
                elif change == "fresh-present":
                    fixture.write(fixture.prepared / fixture.FRESH, fixture.FRESH_BYTES)
                else:
                    next(row for row in fixture.entries if row["path"] == fixture.FRESH)["action"] = "adopt-prepared-static"
                with self.assertRaises(ValueError):
                    fixture.adopt()
                self.assertTrue(fixture.prepared.is_dir())
                self.assertFalse((fixture.directory / ".incoming").exists())

    def test_leaf_type_links_metadata_length_and_actual_digest_are_mandatory(self):
        for change in ("symlink", "hardlink", "fifo", "directory", "mode", "uid", "gid", "size", "sha"):
            with self.subTest(change=change), PreparedTree() as fixture:
                path = fixture.prepared / "code/main.py"
                inode = path.stat().st_ino
                if change in {"symlink", "fifo", "directory"}:
                    path.unlink()
                    if change == "symlink": path.symlink_to(fixture.source / "code/main.py")
                    elif change == "fifo": os.mkfifo(path, 0o444)
                    else: path.mkdir(mode=0o700)
                elif change == "hardlink": os.link(path, fixture.directory / "alias")
                elif change == "mode": path.chmod(0o400)
                elif change in {"uid", "gid"}: fixture.metadata[inode] = {"st_" + change: 23}
                elif change == "size": path.chmod(0o600); path.write_bytes(b"short"); path.chmod(0o444)
                else:
                    next(row for row in fixture.entries if row["path"] == "code/main.py")["sourceSha256"] = "sha256:" + "0" * 64
                with self.assertRaises((ValueError, OSError)):
                    fixture.adopt()
                if change == "sha":
                    self.assertGreater(sum(size for actual, _, size in fixture.reads if actual == inode), 0)
                    self.assertNotIn("0" * 64, measure._FILE_DIGEST_CACHE.values())

    def test_directory_pin_metadata_same_filesystem_and_mount_are_required(self):
        for change in ("pin-inode", "pin-generation", "mode", "owner", "immutable-dir", "directory-symlink",
                       "device", "mount", "leaf-device", "leaf-mount"):
            with self.subTest(change=change), PreparedTree() as fixture:
                child = fixture.prepared / ("code/main.py" if change.startswith("leaf-") else "code")
                inode = child.stat().st_ino
                if change == "pin-inode": fixture.pin["inode"] += 1
                elif change == "pin-generation": fixture.pin["generation"] += 1
                elif change == "mode": child.chmod(0o755)
                elif change == "owner": fixture.metadata[inode] = {"st_uid": 23}
                elif change == "immutable-dir": fixture.flags[inode] = 0x10
                elif change == "directory-symlink":
                    retained = fixture.directory / "retained-code"
                    child.rename(retained); child.symlink_to(retained, target_is_directory=True)
                elif change in {"device", "leaf-device"}: fixture.metadata[inode] = {"st_dev": child.stat().st_dev + 1}
                else:
                    original = install._mount_id
                    fixture.stack.enter_context(patch.object(install, "_mount_id", side_effect=lambda fd:
                        original(fd) + (1 if fixture.real_fstat(fd).st_ino == inode else 0)))
                with self.assertRaises((ValueError, OSError)): fixture.adopt()

    def test_leaf_immutable_real_generation_and_supported_verity_are_required(self):
        for change in ("mutable", "generation", "no-verity", "bad-verity", "foreign-filesystem"):
            with self.subTest(change=change), PreparedTree() as fixture:
                inode = (fixture.prepared / "code/main.py").stat().st_ino
                if change == "mutable": fixture.flags[inode] = 0
                elif change == "generation": fixture.generations[inode] = 0
                elif change == "no-verity": fixture.verity[inode] = None
                elif change == "bad-verity": fixture.verity[inode] = (2, 32, b"x" * 32)
                else: fixture.stack.enter_context(patch.object(measure, "_ext4_verity_cache_eligible", return_value=False))
                with self.assertRaises(ValueError): fixture.adopt()

    def test_original_deadline_cancellation_and_postread_changes_are_not_adopted(self):
        for failure in (TimeoutError("synthetic original deadline"), KeyboardInterrupt("synthetic cancellation")):
            with self.subTest(failure=type(failure).__name__), PreparedTree() as fixture:
                def cancel():
                    if fixture.reads: raise failure
                fixture.cancel = cancel
                with self.assertRaises(type(failure)) as caught: fixture.adopt()
                self.assertIs(caught.exception, failure)
                self.assertEqual(measure._FILE_DIGEST_CACHE, {})
                self.assertTrue(fixture.prepared.is_dir())
        for change in ("path", "verity", "generation", "immutable"):
            with self.subTest(change=change), PreparedTree() as fixture:
                def mutate(fd):
                    inode = fixture.real_fstat(fd).st_ino
                    if change == "path":
                        path = next(fixture.prepared / name for name in fixture.STATIC
                                    if fixture.real_stat(fixture.prepared / name).st_ino == inode)
                        path.rename(path.with_name(path.name + ".retained"))
                        fixture.write(path, b"replacement")
                    elif change == "verity": fixture.verity[inode] = b"v" * 32
                    elif change == "generation": fixture.generations[inode] = 18
                    else: fixture.flags[inode] = 0
                fixture.after_read = mutate
                with self.assertRaises(ValueError): fixture.adopt()
                self.assertEqual(measure._FILE_DIGEST_CACHE, {})

    def test_fresh_copy_is_exclusive_and_never_reuses_a_late_existing_leaf(self):
        with PreparedTree() as fixture:
            parents, rows = fixture.adopt()
            selected = next(row for row in fixture.entries if row["path"] == fixture.FRESH)
            with self.assertRaises(ValueError): fixture.owner._adopt(selected)
            target = fixture.prepared / fixture.FRESH
            fixture.write(target, b"late-existing-bytes")
            before = fixture.real_stat(target)
            with self.assertRaises(FileExistsError): fixture.owner._copy(selected, parents)
            self.assertEqual(target.read_bytes(), b"late-existing-bytes")
            self.assertEqual(fixture.real_stat(target).st_ino, before.st_ino)
            self.assertNotIn(fixture.FRESH, rows)
            self.assertEqual(fixture.chowns, [])
        with PreparedTree() as fixture:
            parents, rows = fixture.adopt()
            before = fixture.identities()
            selected = next(row for row in fixture.entries if row["path"] == fixture.FRESH)
            fixture.allow_sealing = True
            copied = fixture.owner._copy(selected, parents)
            self.assertEqual((fixture.prepared / fixture.FRESH).read_bytes(), fixture.FRESH_BYTES)
            self.assertEqual(copied["sha256"], digest(fixture.FRESH_BYTES))
            self.assertNotIn("action", copied)  # Legacy _copy row contract unchanged.
            for name in fixture.STATIC:
                self.assertEqual(fixture.identities()[name], before[name])
            self.assertNotIn(fixture.FRESH, rows)

    def test_actual_noreplace_retains_both_trees_on_failure_and_consumes_once(self):
        with PreparedTree() as fixture:
            fixture.adopt()
            incoming = fixture.directory / ".incoming"
            incoming.mkdir(mode=0o700)
            occupied = incoming / "generation"
            occupied.mkdir(mode=0o700)
            (occupied / "prior").write_bytes(b"prior-independent-operation")
            fd = fixture.owner._hold(os.open(incoming, install._READ | os.O_DIRECTORY))
            identity = fixture.real_stat(fixture.prepared).st_ino
            with self.assertRaises(FileExistsError):
                install._rename(fixture.owner.root, "prepared-static", fd, "generation")
            self.assertEqual(fixture.real_stat(fixture.prepared).st_ino, identity)
            self.assertEqual((occupied / "prior").read_bytes(), b"prior-independent-operation")
        # An independent disposable fixture demonstrates primitive success,
        # not a retry of the failed installation or an activation receipt.
        with PreparedTree() as fixture:
            fixture.adopt()
            incoming = fixture.directory / ".incoming"
            incoming.mkdir(mode=0o700)
            fd = fixture.owner._hold(os.open(incoming, install._READ | os.O_DIRECTORY))
            identity = fixture.real_stat(fixture.prepared).st_ino
            install._rename(fixture.owner.root, "prepared-static", fd, "unused-target")
            self.assertFalse(fixture.prepared.exists())
            self.assertEqual(fixture.real_stat(incoming / "unused-target").st_ino, identity)
            self.assertEqual(fixture.real_fstat(fixture.owner.tree).st_ino, identity)
            with self.assertRaises(FileNotFoundError):
                install._rename(fixture.owner.root, "prepared-static", fd, "another-target")

    def test_run_source_orders_new_plan_and_state_before_consumption_without_admission_stub(self):
        # Deliberately source-only ordering: do not mock successful package/key
        # verification to turn component tests into signed-installer evidence.
        source = inspect.getsource(install.LocalAuthorityInstaller.run)
        prepared = source.index("parents, adopted = self._prepared_tree()")
        plan = source.index('self._publish(self.name + ".plan.json"')
        state = source.index('self._state("Prepared")')
        consume = source.index('_rename(self.root, self.value["preparedStatic"]["relativePath"]')
        copying = source.index('self.stage = "copying"')
        self.assertLess(prepared, plan); self.assertLess(plan, state)
        self.assertLess(state, consume); self.assertLess(consume, copying)
        self.assertIn('adopted[entry["path"]] if entry["action"] == "adopt-prepared-static"', source)
        self.assertIn('self.failed = True', source)
        self.assertIn('raise LocalInstallError(self) from error', source)
        self.assertNotIn("os.unlink", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
