#!/usr/bin/env python3
"""Local immutable-tree controls; Git's expected inventory is an explicit fixture.

No real repository mutation, Docker, application imports, or network operations.
These tests exercise the real verifier's byte/mode/inventory checks, not a live
container or the provenance of the synthetic ls-tree response.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


def deny_runtime(event, args):
    if event.startswith(("socket.", "subprocess.")) or event in {"os.system", "os.fork", "os.posix_spawn"}:
        raise AssertionError("unit test attempted runtime I/O")


sys.addaudithook(deny_runtime)
SPEC = importlib.util.spec_from_file_location("snapshot_verifier", Path(__file__).with_name("verify_operator_source_snapshot.py"))
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)
COMMIT = "b" * 40
FILES = {"README.md": (b"fixture bytes\n", "100644"), "scripts/check.py": (b"#!/usr/bin/python3\n", "100755")}


def inventory():
    result = b""
    for name, (content, mode) in FILES.items():
        oid = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        result += f"{mode} blob {oid}\t{name}".encode() + b"\0"
    return result


def create_tree(root):
    root.mkdir(parents=True)
    for name, (content, mode) in FILES.items():
        file = root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content)
        file.chmod(0o555 if mode == "100755" else 0o444)
    for directory, _, _ in os.walk(root, topdown=False):
        Path(directory).chmod(0o555)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="source-snapshot-test-")
        self.base = Path(self.temporary.name).resolve()
        self.repo = self.base / "canonical" / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        self.default = self.repo.parent / ("serverware-operator-artifacts/source-" + COMMIT)
        self.explicit = self.base / "other-volume" / ("source-" + COMMIT)
        create_tree(self.default)
        create_tree(self.explicit)
        self.location = patch.object(snapshot, "__file__", str(self.repo / "scripts" / "verify_operator_source_snapshot.py"))
        self.location.start()
        self.git = patch.object(snapshot.subprocess, "check_output", return_value=inventory()).start()

    def tearDown(self):
        patch.stopall()
        self.temporary.cleanup()

    def test_default_and_explicit_use_identical_complete_content_proof(self):
        default = snapshot.verify(COMMIT)
        explicit = snapshot.verify(COMMIT, str(self.explicit))
        self.assertEqual(default["source"], str(self.default))
        self.assertEqual(explicit["source"], str(self.explicit))
        self.assertEqual({**default, "source": explicit["source"]}, explicit)
        self.assertEqual(explicit["files"], 2)
        self.assertTrue(explicit["git_blob_equality"])
        self.assertTrue(explicit["world_readable_and_nonwritable"])
        self.git.assert_called_with(["git", "-C", str(self.repo), "ls-tree", "-rz", COMMIT], timeout=30)

    def test_invalid_and_noncanonical_paths_refuse_before_git(self):
        for value in ["", "source-" + COMMIT, str(self.explicit) + "/", str(self.explicit.parent) + "/./source-" + COMMIT,
                      str(self.explicit.parent) + "/../other-volume/source-" + COMMIT,
                      str(self.explicit.parent / ("source-" + "c" * 40)), "/", "x" * 4097, True]:
            with self.subTest(value=str(value)[:80]):
                with self.assertRaises((ValueError, TypeError, OSError)):
                    snapshot.verify(COMMIT, value)
        self.git.assert_not_called()

    def test_missing_file_leaf_symlink_and_parent_symlink_refuse(self):
        missing = self.base / "missing" / ("source-" + COMMIT)
        file = self.base / "file" / ("source-" + COMMIT)
        file.parent.mkdir()
        file.write_bytes(b"not a directory")
        leaf = self.base / "alias" / ("source-" + COMMIT)
        leaf.parent.mkdir()
        leaf.symlink_to(self.explicit, target_is_directory=True)
        parent = self.base / "parent-alias"
        parent.symlink_to(self.explicit.parent, target_is_directory=True)
        for value in [missing, file, leaf, parent / self.explicit.name]:
            with self.subTest(value=value):
                with self.assertRaises((ValueError, OSError)):
                    snapshot.verify(COMMIT, str(value))
        self.git.assert_not_called()

    def test_explicit_path_still_requires_blob_equality_and_exact_inventory(self):
        file = self.explicit / "README.md"
        file.chmod(0o644)
        file.write_bytes(b"changed content\n")
        file.chmod(0o444)
        with self.assertRaises(AssertionError):
            snapshot.verify(COMMIT, str(self.explicit))
        file.chmod(0o644)
        file.write_bytes(FILES["README.md"][0])
        file.chmod(0o444)
        self.explicit.chmod(0o755)
        extra = self.explicit / "extra"
        extra.write_bytes(b"extra")
        extra.chmod(0o444)
        self.explicit.chmod(0o555)
        with self.assertRaises(AssertionError):
            snapshot.verify(COMMIT, str(self.explicit))
        self.explicit.chmod(0o755)
        extra.unlink()
        file.unlink()
        self.explicit.chmod(0o555)
        with self.assertRaises(FileNotFoundError):
            snapshot.verify(COMMIT, str(self.explicit))

    def test_explicit_path_still_requires_exact_file_and_directory_modes(self):
        for path, wrong, original in [(self.explicit, 0o755, 0o555),
                (self.explicit / "scripts", 0o755, 0o555), (self.explicit / "README.md", 0o644, 0o444),
                (self.explicit / "scripts/check.py", 0o444, 0o555)]:
            with self.subTest(path=path):
                path.chmod(wrong)
                with self.assertRaises(AssertionError):
                    snapshot.verify(COMMIT, str(self.explicit))
                path.chmod(original)

    def test_explicit_path_still_refuses_hardlinks_and_nested_symlinks(self):
        file = self.explicit / "README.md"
        external = self.base / "external"
        os.link(file, external)
        with self.assertRaises(AssertionError):
            snapshot.verify(COMMIT, str(self.explicit))
        external.unlink()
        external.write_bytes(FILES["README.md"][0])
        external.chmod(0o444)
        self.explicit.chmod(0o755)
        file.unlink()
        file.symlink_to(external)
        self.explicit.chmod(0o555)
        with self.assertRaises(AssertionError):
            snapshot.verify(COMMIT, str(self.explicit))

    def test_commit_and_git_entry_kind_checks_are_unchanged(self):
        for commit in [COMMIT.upper(), COMMIT[:-1], "HEAD", "c" * 40]:
            with self.subTest(commit=commit):
                with self.assertRaises(ValueError):
                    snapshot.verify(commit, str(self.explicit))
        self.git.assert_not_called()
        for raw in [inventory().replace(b"100644 blob", b"120000 blob", 1),
                    inventory().replace(b"100644 blob", b"040000 tree", 1), b""]:
            self.git.return_value = raw
            with self.assertRaises(AssertionError):
                snapshot.verify(COMMIT, str(self.explicit))


if __name__ == "__main__":
    unittest.main(verbosity=2)
