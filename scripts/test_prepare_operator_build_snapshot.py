#!/usr/bin/env python3
"""Synthetic Git/filesystem controls only: no real build, cache or deployment."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import prepare_operator_build_snapshot as snapshot


class BuildSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="serverware-build-snapshot-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        self.number = 0
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_AUTHOR_NAME": "Synthetic", "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
            "GIT_COMMITTER_NAME": "Synthetic", "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
            "GIT_AUTHOR_DATE": "2020-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2020-01-01T00:00:00Z"}
        self.git("init", "--quiet")
        for name, data in {
            "Cargo.toml": b"[package]\nname='synthetic'\n",
            "src/lib.rs": b"pub fn unchanged() {}\n",
            "schemas/policy.json": b'{"version":1}\n',
            "scripts/fixtures/vector.json": b'{"sample":true}\n',
            "run.sh": b"#!/bin/sh\nexit 0\n",
            ".gitattributes": b"scripts/fixtures/vector.json export-ignore\nsubstitute.txt export-subst\n",
            "substitute.txt": b"$Format:%H$\n",
        }.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.repo / "run.sh").chmod(0o755)
        self.first = self.commit()
        (self.repo / "untracked-private.txt").write_bytes(b"synthetic-untracked-secret")

    def git(self, *arguments):
        return subprocess.run(["/usr/bin/git", "--no-replace-objects", "-C", str(self.repo),
            "-c", "core.hooksPath=/dev/null", *arguments], env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True).stdout

    def commit(self):
        self.git("add", "--all")
        if (self.repo / "untracked-private.txt").exists():
            self.git("reset", "--quiet", "--", "untracked-private.txt")
        self.git("commit", "--quiet", "-m", "synthetic source")
        return self.git("rev-parse", "HEAD").decode().strip()

    def destination(self):
        self.number += 1
        return self.root / ("snapshot-" + str(self.number))

    def prepare(self, revision=None, **kwargs):
        output = self.destination()
        return output, snapshot.prepare_snapshot(self.repo, revision or self.first, output, **kwargs)

    def metadata(self, root):
        return {str(p.relative_to(root)): (p.lstat().st_dev, p.lstat().st_ino, p.lstat().st_mode,
            p.lstat().st_nlink, p.lstat().st_size, p.lstat().st_mtime_ns, p.lstat().st_ctime_ns)
            for p in [root, *sorted(root.rglob("*"))]}

    def assert_tree(self, root, revision, receipt):
        names, manifest = set(), []
        for row in self.git("ls-tree", "-rz", "--full-tree", revision).split(b"\0"):
            if not row:
                continue
            fields, name = row.split(b"\t", 1)
            mode, kind, oid = fields.decode().split()
            name = name.decode()
            path = root / name
            info, body = path.lstat(), path.read_bytes()
            self.assertEqual(kind, "blob")
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(bool(stat.S_IMODE(info.st_mode) & 0o111), mode == "100755")
            self.assertEqual(hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest(), oid)
            names.add(name)
            manifest.append([name, mode, oid, hashlib.sha256(body).hexdigest(),
                             format(stat.S_IMODE(info.st_mode), "04o")])
        self.assertEqual({str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}, names)
        self.assertEqual(receipt["manifestSha256"], hashlib.sha256(json.dumps(sorted(manifest),
            ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest())

    def test_exact_objects_not_archive_attributes_worktree_or_inherited_git_environment(self):
        (self.repo / "src/lib.rs").write_bytes(b"uncommitted replacement")
        with patch.dict(os.environ, {"GIT_DIR": "/not-repo", "GIT_WORK_TREE": "/not-source",
            "GIT_OBJECT_DIRECTORY": "/not-objects", "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/not-alternates"}):
            output, receipt = self.prepare()
        self.assert_tree(output, self.first, receipt)
        self.assertEqual((output / "src/lib.rs").read_bytes(), b"pub fn unchanged() {}\n")
        self.assertEqual((output / "substitute.txt").read_bytes(), b"$Format:%H$\n")
        self.assertTrue((output / "scripts/fixtures/vector.json").is_file())
        self.assertFalse((output / "untracked-private.txt").exists())
        self.assertEqual(receipt["reusedMtimes"], 0)
        self.assertFalse(receipt["cacheVerified"] or receipt["readOnlyFrozen"])
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)

    def test_identical_reuses_mtime_and_full_mode_without_old_inode_or_metadata_changes(self):
        for ordinary, executable, directory in ((0o644, 0o755, 0o700),
                (0o664, 0o775, 0o775), (0o444, 0o555, 0o555)):
            with self.subTest(modes=(ordinary, executable)):
                old, _ = self.prepare()
                for path in old.rglob("*"):
                    if path.is_file():
                        path.chmod(executable if path.name == "run.sh" else ordinary)
                old.chmod(directory)
                before = self.metadata(old)
                output, receipt = self.prepare(predecessor=old, predecessor_revision=self.first,
                    fresh_after_epoch_ns=time.time_ns() + 10_000_000_000)
                self.assertEqual(self.metadata(old), before)
                self.assertEqual(receipt["reusedMtimes"], receipt["files"])
                self.assertEqual(receipt["freshMtimes"], 0)
                for path in output.rglob("*"):
                    if path.is_file():
                        previous = old / path.relative_to(output)
                        self.assertEqual(path.stat().st_mtime_ns, previous.stat().st_mtime_ns)
                        self.assertEqual(path.stat().st_mode, previous.stat().st_mode)
                        self.assertNotEqual(path.stat().st_ino, previous.stat().st_ino)
                self.assert_tree(output, self.first, receipt)

    def test_changed_bytes_and_git_executable_mode_get_strictly_fresh_timestamps(self):
        old, _ = self.prepare()
        (self.repo / "schemas/policy.json").write_bytes(b'{"version":2}\n')
        (self.repo / "run.sh").chmod(0o644)
        second = self.commit()
        floor = time.time_ns() + 20_000_000_000
        before = self.metadata(old)
        output, receipt = self.prepare(second, predecessor=old, predecessor_revision=self.first,
                                      fresh_after_epoch_ns=floor)
        self.assertEqual(receipt["reusedMtimes"], receipt["files"] - 2)
        for name in ("schemas/policy.json", "run.sh"):
            self.assertGreater((output / name).stat().st_mtime_ns, floor)
            self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o644)
        self.assertEqual((output / "src/lib.rs").stat().st_mtime_ns, (old / "src/lib.rs").stat().st_mtime_ns)
        self.assertEqual(self.metadata(old), before)
        self.assert_tree(output, second, receipt)

    def test_added_and_deleted_external_inputs_disable_all_reuse(self):
        old, _ = self.prepare()
        for add in (True, False):
            if add:
                (self.repo / "scripts/fixtures/new.json").write_bytes(b"{}")
            else:
                (self.repo / "scripts/fixtures/new.json").unlink()
                (self.repo / "schemas/policy.json").unlink()
            revision = self.commit()
            output, receipt = self.prepare(revision, predecessor=old, predecessor_revision=self.first,
                                          fresh_after_epoch_ns=time.time_ns())
            self.assertEqual(receipt["reusedMtimes"], 0)
            self.assertEqual(receipt["reuseDisabledReason"], "path_roster_changed")
            self.assertGreater((output / "src/lib.rs").stat().st_mtime_ns, (old / "src/lib.rs").stat().st_mtime_ns)
            self.assert_tree(output, revision, receipt)

    def test_malicious_predecessors_refuse_before_output_and_without_mutation(self):
        for variant in ("bytes", "mode", "setid", "dir-mode", "dir-setid", "hardlink",
                        "symlink", "ancestor", "extra", "missing"):
            with self.subTest(variant=variant):
                old, _ = self.prepare()
                target = old / "src/lib.rs"
                if variant == "bytes": target.write_bytes(b"bad committed bytes")
                elif variant == "mode": target.chmod(0o666)
                elif variant == "setid": target.chmod(0o4644)
                elif variant == "dir-mode": (old / "src").chmod(0o777)
                elif variant == "dir-setid": (old / "src").chmod(0o2775)
                elif variant == "hardlink": os.link(target, self.root / ("link-" + str(self.number)))
                elif variant == "symlink":
                    target.unlink()
                    target.symlink_to(self.repo / "untracked-private.txt")
                elif variant == "ancestor":
                    (old / "src").rename(old / "elsewhere")
                    (old / "src").symlink_to(old / "elsewhere", target_is_directory=True)
                elif variant == "extra": (old / "untracked-secret").write_bytes(b"must not be read")
                elif variant == "missing": target.unlink()
                before, output = self.metadata(old), self.destination()
                with self.assertRaises((snapshot.SnapshotError, OSError)):
                    snapshot.prepare_snapshot(self.repo, self.first, output, predecessor=old,
                        predecessor_revision=self.first, fresh_after_epoch_ns=time.time_ns())
                self.assertFalse(output.exists())
                self.assertEqual(self.metadata(old), before)

    def test_exclusive_output_overlap_ancestor_symlink_and_revision_alias_refusals(self):
        old, _ = self.prepare()
        existing = self.root / "existing"
        existing.mkdir()
        marker = existing / "keep"
        marker.write_bytes(b"unchanged")
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for output in (existing, self.repo / "inside", old / "inside", alias / "new", self.root):
            with self.subTest(output=output), self.assertRaises((snapshot.SnapshotError, OSError)):
                snapshot.prepare_snapshot(self.repo, self.first, output, predecessor=old,
                    predecessor_revision=self.first, fresh_after_epoch_ns=time.time_ns())
        self.assertEqual(marker.read_bytes(), b"unchanged")
        for revision in ("HEAD", "main", "--help", self.first.upper(), self.first + "^{tree}"):
            with self.subTest(revision=revision), self.assertRaises(snapshot.SnapshotError):
                self.prepare(revision)
        for raw in (b"..", b".", b"/absolute", b"a/b", b"a\\b", b".git", b"new\nline"):
            with self.subTest(component=raw), self.assertRaises(snapshot.SnapshotError):
                snapshot._component(raw)

    def test_git_symlink_submodule_and_replacement_objects_do_not_supply_source(self):
        (self.repo / "src/lib.rs").write_bytes(b"replacement commit")
        second = self.commit()
        self.git("replace", self.first, second)
        output, receipt = self.prepare(self.first)
        self.assertEqual((output / "src/lib.rs").read_bytes(), b"pub fn unchanged() {}\n")
        self.assert_tree(output, self.first, receipt)
        (self.repo / "source-link").symlink_to("src/lib.rs")
        with self.assertRaises(snapshot.SnapshotError):
            self.prepare(self.commit())
        (self.repo / "source-link").unlink()
        self.git("add", "--all")
        self.git("reset", "--quiet", "--", "untracked-private.txt")
        self.git("update-index", "--add", "--cacheinfo", "160000," + second + ",submodule")
        self.git("commit", "--quiet", "-m", "synthetic submodule")
        with self.assertRaises(snapshot.SnapshotError):
            self.prepare(self.git("rev-parse", "HEAD").decode().strip())

    def test_required_cache_floor_object_bounds_deadline_and_timestamp_readback(self):
        old, _ = self.prepare()
        for floor in (None, -1, True, "123", snapshot.MAX_NS):
            output = self.destination()
            with self.subTest(floor=floor), self.assertRaises(snapshot.SnapshotError):
                snapshot.prepare_snapshot(self.repo, self.first, output, predecessor=old,
                    predecessor_revision=self.first, fresh_after_epoch_ns=floor)
            self.assertFalse(output.exists())
        with patch.object(snapshot.time, "time_ns", return_value=snapshot.MAX_NS):
            with self.assertRaises(snapshot.SnapshotError):
                self.prepare()
        for setting, value in (("GIT_SECONDS", 0), ("MAX_FILES", 1), ("MAX_FILE", 1), ("MAX_TOTAL", 1)):
            with self.subTest(setting=setting), patch.object(snapshot, setting, value):
                with self.assertRaises(snapshot.SnapshotError):
                    self.prepare()
        actual_utime = os.utime
        def rounded(fd, *, ns):
            actual_utime(fd, ns=(ns[0], (ns[1] // 1_000_000_000) * 1_000_000_000))
        with patch.object(snapshot.os, "utime", side_effect=rounded):
            with self.assertRaises(snapshot.SnapshotError):
                self.prepare()


if __name__ == "__main__":
    unittest.main()
