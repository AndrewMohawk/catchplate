#!/usr/bin/env python3
"""Synthetic files/archives/Cargo messages only; no Docker, Cargo or network."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import build_operator_rust_offline as build


def no_network(event, _args):
    if event.startswith("socket."):
        raise AssertionError("network forbidden in wrapper unit tests")


sys.addaudithook(no_network)


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ordinary-build-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, name, body=b"synthetic", mode=0o644):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(mode)
        return path

    def archive(self, entries, package="crate-1.0"):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:gz") as writer:
            for name, kind, body in entries:
                item = tarfile.TarInfo(name)
                item.mode = 0o644
                item.type = kind
                item.size = len(body) if kind == tarfile.REGTYPE else 0
                if kind == tarfile.SYMTYPE:
                    item.linkname = "/outside"
                writer.addfile(item, io.BytesIO(body) if kind == tarfile.REGTYPE else None)
        path = self.file(package + ".crate", raw.getvalue())
        return path, hashlib.sha256(raw.getvalue()).hexdigest()

    def test_cache_internal_aliases_copy_to_independent_exact_files_without_mutating_old(self):
        first = self.file("cache/release/main", b"exact compiler cache", 0o755)
        (first.parent / "deps").mkdir()
        os.link(first, first.parent / "deps/main")
        os.utime(first, ns=(1_600_000_000_000_000_000,) * 2)
        self.file("cache/.fingerprint/data", b"dep-info")
        before = build.inventory(self.root / "cache", allow_internal_hardlinks=True)
        hashes = build.copy_tree(self.root / "cache", self.root / "copy", before)
        self.assertEqual(build.inventory(self.root / "cache", allow_internal_hardlinks=True), before)
        for relative, original in before.items():
            copied = self.root / "copy" / relative
            info = copied.stat()
            self.assertEqual(info.st_nlink, 1)
            self.assertNotEqual((info.st_dev, info.st_ino), tuple(original[:2]))
            self.assertEqual((info.st_mode, info.st_mtime_ns), (original[2], original[7]))
            self.assertEqual(hashes[relative], hashlib.sha256(copied.read_bytes()).hexdigest())
        self.assertNotEqual((self.root / "copy/release/main").stat().st_ino,
                            (self.root / "copy/release/deps/main").stat().st_ino)
        with self.assertRaises(FileExistsError):
            build.copy_tree(self.root / "cache", self.root / "copy", before)

    def test_external_aliases_symlinks_unsafe_modes_and_copy_drift_refuse(self):
        path = self.file("cache/keep")
        os.link(path, self.root / "outside-alias")
        with self.assertRaises(build.Refused):
            build.inventory(self.root / "cache", allow_internal_hardlinks=True)
        (self.root / "outside-alias").unlink()
        (self.root / "cache/link").symlink_to(path)
        with self.assertRaises(build.Refused):
            build.inventory(self.root / "cache")
        (self.root / "cache/link").unlink()
        path.chmod(0o666)
        with self.assertRaises(build.Refused):
            build.inventory(self.root / "cache")
        path.chmod(0o644)
        before = build.inventory(self.root / "cache")
        path.write_bytes(b"changed")
        with self.assertRaises(build.Refused):
            build.copy_tree(self.root / "cache", self.root / "copy", before)

    def test_retained_cache_source_pins_join_actual_predecessor_not_just_path(self):
        path = self.file("old/src/main.rs", b"fn main() {}")
        pins = {"sourceRoot": str(self.root / "old"),
                "files": {"src/main.rs": hashlib.sha256(path.read_bytes()).hexdigest()}}
        build.verify_predecessor_pins(pins, self.root / "old")
        path.write_bytes(b"different committed predecessor")
        with self.assertRaises(build.Refused):
            build.verify_predecessor_pins(pins, self.root / "old")
        for name in ("../outside", "/outside", "src//main.rs", "src/./main.rs"):
            with self.subTest(name=name), self.assertRaises(build.Refused):
                build.verify_predecessor_pins({**pins, "files": {name: "0" * 64}}, self.root / "old")

    def test_real_tiny_gzip_crate_and_closed_vendored_checksum_roster(self):
        path, checksum = self.archive([("crate-1.0/src/lib.rs", tarfile.REGTYPE, b"pub fn test() {}")])
        vendor = self.root / "vendor"
        vendor.mkdir()
        hashes = build.unpack(path, "crate-1.0", checksum, vendor)
        self.assertEqual(hashes, {"crate-1.0/src/lib.rs": hashlib.sha256(b"pub fn test() {}").hexdigest()})
        lock = {"package": [{"name": "crate", "version": "1.0", "checksum": checksum,
            "source": "registry+https://github.com/rust-lang/crates.io-index"}]}
        build.verify_vendor(lock, vendor, hashes)
        with self.assertRaises(build.Refused):
            build.verify_vendor(lock, vendor, {**hashes, "crate-1.0/extra": "0" * 64})
        with self.assertRaises(build.Refused):
            build.verify_vendor(lock, vendor, {"crate-1.0/src/lib.rs": "0" * 64})
        with self.assertRaises(FileExistsError):
            build.unpack(path, "crate-1.0", checksum, vendor)

    def test_archive_checksum_traversal_links_duplicate_and_supplied_checksum_refusals(self):
        variants = [
            [("crate-1.0/../escape", tarfile.REGTYPE, b"x")],
            [("/crate-1.0/file", tarfile.REGTYPE, b"x")],
            [("crate-1.0/link", tarfile.SYMTYPE, b"")],
            [("crate-1.0/f", tarfile.REGTYPE, b"x")] * 2,
            [("crate-1.0/.cargo-checksum.json", tarfile.REGTYPE, b"{}")],
            [("wrong-package/file", tarfile.REGTYPE, b"x")],
        ]
        vendor = self.root / "vendor"
        vendor.mkdir()
        for entries in variants:
            with self.subTest(entries=entries):
                path, checksum = self.archive(entries)
                with self.assertRaises(build.Refused):
                    build.unpack(path, "crate-1.0", checksum, vendor)
                self.assertFalse((vendor / "crate-1.0").exists())
        path, _ = self.archive([("crate-1.0/f", tarfile.REGTYPE, b"x")])
        with self.assertRaises(build.Refused):
            build.unpack(path, "crate-1.0", "0" * 64, vendor)

    def test_compiler_arguments_are_explicit_offline_bounded_and_not_pilot(self):
        for kind, verb in (("normal", "build"), ("test", "test")):
            argv = build.create_arguments(self.root, "synthetic-name", "0" * 32, kind)
            for option, value in (("--pull", "never"), ("--network", "none"), ("--cpus", "2"),
                    ("--memory", "24g"), ("--memory-swap", "24g"), ("--pids-limit", "512"),
                    ("--user", "1000:1000"), ("--cap-drop", "ALL")):
                self.assertEqual(argv[argv.index(option) + 1], value)
            self.assertIn(build.IMAGE, argv)
            self.assertIn("--read-only", argv)
            self.assertNotIn("--privileged", argv)
            self.assertNotIn("--features", argv)
            cargo = argv[argv.index("cargo"):]
            self.assertEqual(cargo[:2], ["cargo", verb])
            self.assertIn("--frozen", cargo)
            self.assertIn("--offline", cargo)
            self.assertEqual("--no-run" in cargo, kind == "test")
            mounts = [argv[i + 1] for i, value in enumerate(argv) if value == "--mount"]
            self.assertEqual(len(mounts), 4)
            self.assertTrue(all(value.endswith(",readonly") for value in mounts[:3]))
            self.assertTrue(mounts[3].endswith(",dst=/target"))

    def test_cargo_artifact_success_requires_terminal_record_and_retains_tested_false(self):
        self.file("target/release/serverware-decision-gate", b"\x7fELFsynthetic-unexecuted", 0o755)
        row = {"reason": "compiler-artifact", "target": {"name": "serverware-decision-gate", "kind": ["bin"]},
            "profile": {"test": False}, "executable": "/target/release/serverware-decision-gate", "fresh": False}
        finish = {"reason": "build-finished", "success": True}
        encode = lambda rows: b"\n".join(json.dumps(item).encode() for item in rows)
        for rows in ([row], [row, row, finish], [row, {**finish, "success": False}],
                     [{**row, "executable": "/etc/passwd"}, finish]):
            with self.subTest(rows=rows), self.assertRaises(build.Refused):
                build.artifact(self.root, "normal", encode(rows))
        receipt = build.artifact(self.root, "normal", encode([row, finish]))
        self.assertFalse(receipt["tested"] or receipt["deployed"] or receipt["cargoFresh"])
        saved = Path(receipt["path"])
        self.assertEqual(receipt["sha256"], hashlib.sha256(saved.read_bytes()).hexdigest())
        self.assertEqual(saved.stat().st_mode & 0o777, 0o555)

    def test_owned_command_records_nonzero_timeout_and_bounded_output(self):
        for name, text, seconds, expected in (
                ("success", "print('synthetic')", 2, 0),
                ("failure", "raise SystemExit(7)", 2, 7),
                ("timeout", "import time; time.sleep(5)", 0.05, 124),
                ("overflow", "print('x'*4096)", 2, 124)):
            with self.subTest(name=name), patch.object(build, "MAX_LOG", 1024):
                self.assertEqual(build.command(self.root, name, [sys.executable, "-I", "-S", "-c", text], seconds), expected)
                record = json.loads((self.root / (name + ".host.json")).read_text())
                self.assertLessEqual(record["bytes"], 1024)
                self.assertEqual(record["status"], {"timeout": "timeout", "overflow": "output_limit"}.get(name, "completed"))


if __name__ == "__main__":
    unittest.main()
