"""Pure cache artifact controls; no image, application, Git or network execution.

Git output and 3.11 artifact payloads below are explicitly synthetic. The loader
control uses real host-Python bytecode for inert code, without executing it. Only
the separately pinned-image compile/consumption run establishes 3.11 provenance.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import py_compile
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_operator_python_bytecode as cache

COMMIT, NEXT = "a" * 40, "b" * 40


class BytecodeTests(unittest.TestCase):
    def setUp(self):
        for name in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "subprocess.Popen"):
            self.enterContext(patch(name, side_effect=AssertionError("runtime forbidden in pure cache controls")))
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="bytecode-unit-"))).resolve()
        self.source, self.artifact = self.root / "source", self.root / "artifact"
        self.source.mkdir()
        self.helper = Path(cache.__file__).read_bytes()
        (self.source / "scripts").mkdir()
        (self.source / cache.SCRIPT).write_bytes(self.helper)
        self.files = {"catchplate/__init__.py": b"", "catchplate/app.py": b"raise RuntimeError('never execute')\n",
            "catchplate/authority_store/example.py": b"VALUE = 7\n"}
        for name, raw in self.files.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        for package in cache.PACKAGES:
            (self.source / package / "__pycache__").mkdir()
        self.git = self.enterContext(patch.object(cache, "_git", side_effect=self.git_output))
        self.record = cache._source_record(self.source, COMMIT, self.source)
        self.artifact.mkdir()
        for relative in ("cache", "cache/catchplate", "cache/authority_store"):
            (self.artifact / relative).mkdir()
        payload = []
        for item in self.record["files"]:
            # Structural synthetic bytes, not loadable or claimed native 3.11 output.
            raw = bytes.fromhex(cache.INTERPRETER["magicHex"]) + b"\x03\0\0\0" + b"12345678" + b"synthetic-payload"
            name = cache._cache_path(item["path"])
            cache._write(self.artifact / name, raw)
            payload.append({"path": name, "sha256": cache.sha(raw), "size": len(raw), "sourceHashHex": raw[8:16].hex()})
        self.manifest = {"schema": "catchplate.operatorPythonBytecode/v1", "source": self.record,
            "sourceManifestSha256": cache.sha(cache.canonical(self.record)),
            "interpreter": deepcopy(cache.INTERPRETER), "files": payload}
        self.pin = self.write_manifest()

    def git_output(self, repository, *arguments):
        self.assertEqual(repository, self.source)
        if arguments[:2] == ("cat-file", "blob"):
            self.assertIn(arguments[2], (COMMIT + ":" + cache.SCRIPT, NEXT + ":" + cache.SCRIPT))
            return self.helper
        self.assertEqual(arguments[:3], ("ls-tree", "-rz", "--full-tree"))
        self.assertIn(arguments[3], (COMMIT, NEXT))
        self.assertEqual(arguments[4:], ("--", "catchplate"))
        return b"".join(b"100644 blob " + hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest().encode()
            + b"\t" + name.encode() + b"\0" for name, raw in sorted(self.files.items()))

    def write_manifest(self, raw=None):
        self.artifact.chmod(0o700)
        path = self.artifact / "manifest.json"
        if path.exists():
            path.chmod(0o600); path.unlink()
        raw = cache.canonical(self.manifest) if raw is None else raw
        cache._write(path, raw); cache._freeze(self.artifact)
        return cache.sha(raw)

    def validate(self, **overrides):
        args = dict(source=self.source, commit=COMMIT, repository=self.source, expected_manifest_sha256=self.pin)
        args.update(overrides)
        return cache.validate(self.artifact, **args)

    def mutate_payload(self, raw):
        row = self.manifest["files"][0]
        path = self.artifact / row["path"]
        path.chmod(0o600); path.write_bytes(raw); path.chmod(0o444)
        row.update(sha256=cache.sha(raw), size=len(raw), sourceHashHex=raw[8:16].hex())
        self.pin = self.write_manifest()

    def test_exact_source_artifact_and_stable_before_after_receipt(self):
        before = self.validate()
        self.assertEqual(before, self.validate())
        self.assertEqual((before["sourceCommit"], before["producerCommit"], before["files"]), (COMMIT, COMMIT, 3))
        self.assertEqual(before["image"], cache.APP_IMAGE)
        self.assertEqual(before["interpreter"], cache.INTERPRETER)
        self.assertEqual(set(before), {"schema", "manifestSha256", "sourceCommit", "producerCommit", "sourceTreeSha256",
            "image", "interpreter", "files", "bytecodeBytes", "artifactIdentitySha256"})

    def test_docs_only_commit_reuse_requires_exact_committed_payload_and_helper(self):
        result = self.validate(commit=NEXT)
        self.assertEqual((result["sourceCommit"], result["producerCommit"]), (NEXT, COMMIT))
        self.files["catchplate/new_module.py"] = b"NEW = 1\n"
        (self.source / "catchplate/new_module.py").write_bytes(self.files["catchplate/new_module.py"])
        with self.assertRaises(ValueError):
            self.validate(commit=NEXT)

    def test_changed_source_helper_and_wrong_external_pin_refuse(self):
        with self.assertRaises(ValueError):
            self.validate(expected_manifest_sha256="f" * 64)
        path = self.source / "catchplate/app.py"
        original = path.read_bytes(); path.write_bytes(b"different\n")
        with self.assertRaises(ValueError):
            self.validate()
        path.write_bytes(original)
        (self.source / cache.SCRIPT).write_bytes(self.helper + b"\n")
        with self.assertRaises(ValueError):
            self.validate()

    def test_full_payload_digest_not_only_checked_hash_header(self):
        path = self.artifact / self.manifest["files"][0]["path"]
        raw = path.read_bytes(); path.chmod(0o600)
        path.write_bytes(raw[:16] + b"substituted-code!"); path.chmod(0o444)
        with self.assertRaises(ValueError):
            self.validate()

    def test_wrong_magic_unchecked_hash_timestamp_and_unknown_flags_refuse(self):
        raw = (self.artifact / self.manifest["files"][0]["path"]).read_bytes()
        for magic, flags in ((b"wrong", 3), (raw[:4], 0), (raw[:4], 1), (raw[:4], 7)):
            with self.subTest(magic=magic, flags=flags):
                self.mutate_payload(magic[:4] + flags.to_bytes(4, "little") + raw[8:])
                with self.assertRaises(ValueError):
                    self.validate()

    def test_interpreter_image_and_boolean_optimization_refuse(self):
        original = deepcopy(self.manifest)
        mutations = (("interpreter", "cacheTag", "cpython-312"), ("interpreter", "version", "3.11.14"),
            ("interpreter", "optimization", False), ("interpreter", "optimization", 1),
            ("source", "image", "sha256:" + "0" * 64))
        for section, key, value in mutations:
            with self.subTest(section=section, key=key, value=value):
                self.manifest = deepcopy(original); self.manifest[section][key] = value
                self.pin = self.write_manifest()
                with self.assertRaises(ValueError):
                    self.validate()

    def test_extra_missing_writable_and_symlink_artifact_refuse(self):
        self.artifact.chmod(0o700)
        extra = self.artifact / "extra.pyc"; extra.write_bytes(b"extra"); extra.chmod(0o444)
        self.artifact.chmod(0o555)
        with self.assertRaises(ValueError):
            self.validate()
        self.artifact.chmod(0o700); extra.unlink(); self.artifact.chmod(0o555)
        path = self.artifact / self.manifest["files"][0]["path"]
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.validate()
        path.chmod(0o444)
        path.parent.chmod(0o755); raw = path.read_bytes(); path.unlink(); path.parent.chmod(0o555)
        with self.assertRaises(FileNotFoundError):
            self.validate()
        external = self.root / "external.pyc"; external.write_bytes(raw); external.chmod(0o444)
        path.parent.chmod(0o755); path.symlink_to(external); path.parent.chmod(0o555)
        with self.assertRaises(ValueError):
            self.validate()

    def test_source_mountpoints_are_existing_real_dirs_never_created_or_emptied(self):
        mountpoint = self.source / "catchplate/__pycache__"
        unrelated = mountpoint / "host-cache"; unrelated.write_bytes(b"unchanged")
        self.validate(); self.assertEqual(unrelated.read_bytes(), b"unchanged")
        second = self.source / "catchplate/authority_store/__pycache__"; second.rmdir()
        with self.assertRaises(FileNotFoundError):
            self.validate()
        self.assertFalse(second.exists())
        second.symlink_to(mountpoint, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.validate()

    def test_source_manifest_fresh_disjoint_output_and_git_object_binding(self):
        output = self.root / "prepared-input"
        result = cache.source_manifest(source=self.source, commit=COMMIT, repository=self.source, output=output)
        self.assertEqual(result["sourceManifestSha256"], cache.sha((output / "source-manifest.json").read_bytes()))
        self.assertEqual(output.stat().st_mode & 0o777, 0o555)
        for destination in (output, self.source / "new-output"):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                cache.source_manifest(source=self.source, commit=COMMIT, repository=self.source, output=destination)
        self.assertFalse((self.source / "new-output").exists())
        (self.source / "catchplate/app.py").write_bytes(b"wrong object\n")
        with self.assertRaises(ValueError):
            cache.source_manifest(source=self.source, commit=COMMIT, repository=self.source, output=self.root / "unused")

    def test_pure_exact_mount_projection_and_no_runtime_flag_changes(self):
        rows = cache.mounts(Path("/synthetic/artifact"))
        self.assertEqual([row["target"] for row in rows], ["/app/catchplate/__pycache__", "/app/catchplate/authority_store/__pycache__"])
        self.assertEqual([row["source"] for row in rows], ["/synthetic/artifact/cache/catchplate", "/synthetic/artifact/cache/authority_store"])
        self.assertTrue(all(row["read_only"] and row["bind"] == {"create_host_path": False} for row in rows))
        with self.assertRaises(ValueError):
            cache.mounts(Path("relative"))

    def test_duplicate_or_extra_manifest_fields_refuse_even_with_new_pin(self):
        raw = cache.canonical(self.manifest)
        self.pin = self.write_manifest(b'{"schema":"duplicate",' + raw[1:])
        with self.assertRaises(ValueError):
            self.validate()
        self.manifest["unexpected"] = True; self.pin = self.write_manifest()
        with self.assertRaises(ValueError):
            self.validate()

    def test_real_host_loader_consumes_checked_cache_without_executing_source(self):
        path = self.root / "inert.py"
        path.write_text("raise AssertionError('executing this module is forbidden')\n")
        py_compile.compile(str(path), doraise=True, optimize=0,
            invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)
        with patch.object(sys, "dont_write_bytecode", True):
            code = cache._cached_code(path)
            self.assertEqual(code.co_filename, str(path))
            path.write_text("raise AssertionError('changed source must not compile')\n")
            with self.assertRaisesRegex(ValueError, "cache was not consumed"):
                cache._cached_code(path)
            Path(importlib.util.cache_from_source(str(path))).unlink()
            with self.assertRaisesRegex(ValueError, "cache was not consumed"):
                cache._cached_code(path)


if __name__ == "__main__":
    unittest.main()
