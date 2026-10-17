#!/usr/bin/env python3
"""Real sealed-memfd offset controls, not authority/service startup admission.

Run the exact source-extracted inert readers without importing the active
service. The real launcher seals only synthetic public bytes in this test.
"""
import ast
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from catchplate import authority_launcher as launcher

SOURCE = ROOT / "catchplate/authority_service.py"
NAME = "SYNTHETIC_AUTHORITY_ORIGINAL"


@contextmanager
def sealed(value, *, mode=0o400):
    descriptor = launcher._seal_bytes("synthetic-public-original", value, mode=mode)
    duplicate = os.dup(descriptor)
    try:
        yield descriptor, duplicate
    finally:
        os.close(duplicate); os.close(descriptor)


class AuthorityServiceDescriptorReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE.stat().st_size > 2 * 1024 * 1024:
            raise AssertionError("source exceeds focused fixture bound")
        cls.tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        names = {"AuthorityServiceError", "_read_descriptor_original",
                 "_read_bounded_descriptor", "_load_ed25519_public_key"}
        nodes = [node for node in cls.tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))
                 and node.name in names]
        if len(nodes) != len(names):
            raise AssertionError("exact source helpers unavailable")
        cls.functions = dict(os=os, stat=stat, Path=Path, serialization=serialization,
                             Ed25519PublicKey=Ed25519PublicKey)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SOURCE), "exec"), cls.functions)

    def read(self, descriptor, maximum, *, root=False):
        with patch.dict(os.environ, {NAME + "_FD": str(descriptor)}, clear=True):
            return self.functions["_read_bounded_descriptor"](NAME, maximum=maximum,
                require_root_owned=root, require_descriptor=True)

    def test_real_resealed_root_at_eof_is_repeatably_read_without_moving_shared_offset(self):
        original = bytes(range(32))
        with sealed(original) as (descriptor, duplicate):
            self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), len(original))
            # The old consumer's dup/read sees the genuine producer's EOF.
            with os.fdopen(os.dup(descriptor), "rb") as old:
                self.assertEqual(old.read(65537), b"")
            with self.assertRaises(self.functions["AuthorityServiceError"]):
                self.functions["_load_ed25519_public_key"](b"")
            for position in (len(original), 1, len(original) + 7):
                os.lseek(duplicate, position, os.SEEK_SET)  # fixture position only
                for _ in range(2):
                    value = self.read(descriptor, len(original), root=os.getuid() == 0)
                    self.assertEqual(value, original)
                    key = self.functions["_load_ed25519_public_key"](value)
                    self.assertEqual(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), original)
                    self.assertEqual(os.lseek(descriptor, 0, os.SEEK_CUR), position)
                    self.assertEqual(os.lseek(duplicate, 0, os.SEEK_CUR), position)

    def test_complete_bounded_reads_and_existing_metadata_path_guards(self):
        original = b"public synthetic certificate bytes" * 3000
        with sealed(original) as (descriptor, duplicate):
            offset = os.lseek(duplicate, 0, os.SEEK_CUR)
            real_pread = os.pread
            # Legitimate partial reads still accumulate within maximum+1.
            with patch.object(os, "pread", side_effect=lambda fd, size, at: real_pread(fd, min(size, 997), at)):
                self.assertEqual(self.read(descriptor, len(original)), original)
            with self.assertRaises(self.functions["AuthorityServiceError"]):
                self.read(descriptor, len(original) - 1)
            self.assertEqual(os.lseek(duplicate, 0, os.SEEK_CUR), offset)
            fields = list(os.fstat(descriptor)); fields[4] = 12345
            with patch.object(os, "fstat", return_value=os.stat_result(fields)):
                with self.assertRaises(self.functions["AuthorityServiceError"]):
                    self.read(descriptor, len(original), root=True)
        with sealed(b"public", mode=0o660) as (descriptor, _duplicate):
            with self.assertRaises(self.functions["AuthorityServiceError"]):
                self.read(descriptor, 6)
        with tempfile.TemporaryDirectory(prefix="authority-descriptor-control-") as temporary:
            path = Path(temporary) / "public"
            path.write_bytes(b"public"); path.chmod(0o400)
            with patch.dict(os.environ, {NAME + "_PATH": str(path)}, clear=True):
                with self.assertRaises(self.functions["AuthorityServiceError"]):
                    self.functions["_read_bounded_descriptor"](NAME, maximum=6,
                        require_root_owned=False, require_descriptor=True)
                self.assertEqual(self.functions["_read_bounded_descriptor"](NAME, maximum=6,
                    require_root_owned=False), b"public")

    def test_launch_key_certificate_and_shared_reader_use_same_original_reader(self):
        process = next(node for node in self.tree.body if isinstance(node, ast.ClassDef) and node.name == "AuthorityProcess")
        constructor = next(node for node in process.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
        calls = [ast.unparse(node) for node in ast.walk(constructor) if isinstance(node, ast.Call)
                 and ast.unparse(node.func) == "_read_descriptor_original"]
        self.assertEqual(calls, ["_read_descriptor_original(launch_private_descriptor, 64 * 1024)",
                                "_read_descriptor_original(launch_certificate_descriptor, MAX_CONFIG_BYTES)"])
        reader = next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == "_read_bounded_descriptor")
        self.assertIn("_read_descriptor_original(descriptor, maximum)", ast.unparse(reader))
        self.assertNotIn("handle.read", ast.unparse(constructor))
        helper = next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == "_read_descriptor_original")
        self.assertNotIn("seek", ast.unparse(helper))
        for original, maximum in ((b"synthetic launch key original", 65536),
                                  (b'{"synthetic":"certificate"}', 4 * 1024 * 1024)):
            with sealed(original) as (descriptor, duplicate):
                self.assertEqual(self.functions["_read_descriptor_original"](descriptor, maximum), original)
                self.assertEqual(os.lseek(duplicate, 0, os.SEEK_CUR), len(original))


if __name__ == "__main__":
    unittest.main()
