#!/usr/bin/env python3
"""Small offline fixtures for reviewed dependency pins and snapshot updates."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PREFETCH_PATH = ROOT / "production-dependencies/prefetch.py"
LAUNCHER_PATH = ROOT / "scripts/test_production_launcher_adversarial.py"
SNAPSHOT_ID = "catchplate-production-dependencies-test-v2"
SNAPSHOT_URL = "https://artifacts.example.invalid/" + SNAPSHOT_ID
PYTHON_ARCHIVE = "cache/python-wheelhouse-linux-amd64.tar.gz"
CARGO_ARCHIVE = "cache/cargo-vendor.tar.gz"
MUSL_APK = "cache/musl-1.2.5-r12.apk"
MUSL_DEV_APK = "cache/musl-dev-1.2.5-r12.apk"


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load test subject: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive_fixture(member: str, content: bytes) -> bytes:
    # These are archive-layout fixtures, not installable package evidence.
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        info = tarfile.TarInfo(member)
        info.mode = 0o644
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


class DependencySnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="catchplate-dependency-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.dependencies = self.root / "production-dependencies"
        self.dependencies.mkdir()
        shutil.copyfile(PREFETCH_PATH, self.dependencies / "prefetch.py")
        self.prefetch = load_module(
            self.dependencies / "prefetch.py", "dependency_snapshot_test_subject"
        )
        self.sources = {
            "requirements.lock": b"pinned Python requirements fixture\n",
            "data-plane/decision-gate-rs/Cargo.toml": b"pinned Cargo manifest fixture\n",
            "data-plane/decision-gate-rs/Cargo.lock": b"pinned Cargo lock fixture\n",
        }
        self.artifacts = {
            PYTHON_ARCHIVE: archive_fixture("wheelhouse/package.whl", b"wheel fixture\n"),
            CARGO_ARCHIVE: archive_fixture("vendor/package/.cargo-checksum.json", b"{}\n"),
            MUSL_APK: b"musl archive fixture\n",
            MUSL_DEV_APK: b"musl-dev archive fixture\n",
        }
        self.digests = {
            name: hashlib.sha256(content).hexdigest()
            for name, content in {**self.sources, **self.artifacts}.items()
        }
        for name, content in self.sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.python_metadata = self.metadata(
            {
                PYTHON_ARCHIVE: {
                    "kind": "python-wheelhouse",
                    "name": "requirements.lock",
                    "version": "sha256:" + self.digests["requirements.lock"],
                }
            }
        )
        self.rust_metadata = self.metadata(
            {
                CARGO_ARCHIVE: {
                    "kind": "cargo-vendor",
                    "name": "Cargo.lock",
                    "version": "sha256:" + self.digests["data-plane/decision-gate-rs/Cargo.lock"],
                },
                MUSL_APK: {"kind": "alpine-apk", "name": "musl", "version": "1.2.5-r12"},
                MUSL_DEV_APK: {"kind": "alpine-apk", "name": "musl-dev", "version": "1.2.5-r12"},
            }
        )
        self.write_manifest(self.prefetch.PYTHON_MANIFEST, self.python_metadata, self.prefetch.PYTHON_INPUTS)
        self.write_manifest(self.prefetch.RUST_MANIFEST, self.rust_metadata, self.prefetch.RUST_INPUTS)

    @staticmethod
    def metadata(artifacts: dict[str, dict[str, str]]) -> dict[str, object]:
        return {
            "apiVersion": "catchplate.offlineDependencyManifest/v2",
            "artifacts": artifacts,
            "platform": "linux/amd64",
            "snapshotId": SNAPSHOT_ID,
            "snapshotUrlSuffix": "/" + SNAPSHOT_ID,
        }

    def write_manifest(self, path: Path, metadata: dict[str, object], inputs: tuple[str, ...]) -> None:
        text = "# metadata=" + json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n"
        text += "".join(f"{self.digests[name]}  {name}\n" for name in inputs)
        path.write_text(text, encoding="ascii")

    def install_artifacts(self) -> None:
        for name, content in self.artifacts.items():
            path = self.dependencies / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    def test_stale_source_pins_fail_before_fetch_or_cache_mutation(self) -> None:
        self.install_artifacts()
        for name, original in self.sources.items():
            with self.subTest(source=name):
                source = self.root / name
                source.write_bytes(original + b"changed\n")
                try:
                    with mock.patch.object(self.prefetch, "fetch_one") as fetch_one:
                        with self.assertRaisesRegex(RuntimeError, "dependency input .* has sha256"):
                            self.prefetch.fetch(SNAPSHOT_URL)
                        fetch_one.assert_not_called()
                    for artifact, content in self.artifacts.items():
                        self.assertEqual((self.dependencies / artifact).read_bytes(), content)
                finally:
                    source.write_bytes(original)

    def test_stale_source_does_not_create_missing_cache(self) -> None:
        (self.root / "requirements.lock").write_bytes(b"changed\n")
        with mock.patch.object(self.prefetch, "fetch_one") as fetch_one:
            with self.assertRaisesRegex(RuntimeError, "dependency input requirements.lock"):
                self.prefetch.fetch(SNAPSHOT_URL)
            fetch_one.assert_not_called()
        self.assertFalse(self.prefetch.CACHE_DIR.exists())

    def test_verify_checks_later_source_pins_before_missing_cache(self) -> None:
        (self.root / "data-plane/decision-gate-rs/Cargo.lock").write_bytes(b"changed\n")
        with self.assertRaisesRegex(RuntimeError, "dependency input data-plane/decision-gate-rs/Cargo.lock"):
            self.prefetch.verify()

    def test_fetch_consumes_complete_reviewed_snapshot(self) -> None:
        def fixture_fetch(url: str, relative: str, expected: str) -> None:
            self.assertEqual(url, SNAPSHOT_URL)
            self.assertEqual(expected, self.digests[relative])
            path = self.dependencies / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.artifacts[relative])

        with mock.patch.object(self.prefetch, "fetch_one", side_effect=fixture_fetch) as fetch_one:
            self.prefetch.fetch(SNAPSHOT_URL)
        self.assertEqual(fetch_one.call_count, len(self.artifacts))
        self.assertEqual({call.args[1] for call in fetch_one.call_args_list}, set(self.artifacts))
        self.prefetch.verify()

    def test_fetch_rechecks_downloaded_bytes_against_reviewed_pins(self) -> None:
        self.install_artifacts()
        (self.dependencies / PYTHON_ARCHIVE).write_bytes(b"substituted cache\n")
        with mock.patch.object(self.prefetch, "fetch_one"):
            with self.assertRaisesRegex(RuntimeError, "dependency input cache/python-wheelhouse"):
                self.prefetch.fetch(SNAPSHOT_URL)

    def test_descriptor_fields_must_match_closed_inventory(self) -> None:
        for path, metadata, inputs in (
            (self.prefetch.PYTHON_MANIFEST, self.python_metadata, self.prefetch.PYTHON_INPUTS),
            (self.prefetch.RUST_MANIFEST, self.rust_metadata, self.prefetch.RUST_INPUTS),
        ):
            for artifact in metadata["artifacts"]:
                for field in ("kind", "name", "version"):
                    with self.subTest(artifact=artifact, field=field):
                        mutated = copy.deepcopy(metadata)
                        mutated["artifacts"][artifact][field] = "incorrect-descriptor-value"
                        self.write_manifest(path, mutated, inputs)
                        with self.assertRaisesRegex(RuntimeError, "descriptor differs from its pinned inputs"):
                            self.prefetch.parse_manifest(path, inputs)
            self.write_manifest(path, metadata, inputs)

    def test_duplicate_metadata_is_rejected_at_every_depth(self) -> None:
        path = self.prefetch.PYTHON_MANIFEST
        original = path.read_text(encoding="ascii")
        for field in ('"snapshotId"', '"kind"'):
            with self.subTest(field=field):
                path.write_text(original.replace(field + ":", field + ':"ignored",' + field + ":", 1), encoding="ascii")
                with self.assertRaisesRegex(RuntimeError, "duplicate field"):
                    self.prefetch.parse_manifest(path, self.prefetch.PYTHON_INPUTS)

    def test_python_only_snapshot_update_is_rejected(self) -> None:
        metadata = copy.deepcopy(self.python_metadata)
        metadata["snapshotId"] = "python-only-update"
        metadata["snapshotUrlSuffix"] = "/python-only-update"
        self.write_manifest(self.prefetch.PYTHON_MANIFEST, metadata, self.prefetch.PYTHON_INPUTS)
        with self.assertRaisesRegex(RuntimeError, "one immutable snapshot"):
            self.prefetch.manifests()

    def load_launcher(self) -> ModuleType:
        path = self.root / "scripts/test_production_launcher_adversarial.py"
        path.parent.mkdir()
        shutil.copyfile(LAUNCHER_PATH, path)
        return load_module(path, "dependency_snapshot_launcher_test_subject")

    def test_launcher_expected_pins_follow_reviewed_manifests(self) -> None:
        # The new fixture manifests deliberately differ from the repository's
        # prior release. Neither local source nor cache bytes may choose pins.
        (self.root / "requirements.lock").write_bytes(b"unreviewed lock\n")
        launcher = self.load_launcher()
        self.assertEqual(launcher.REQUIREMENTS_LOCK_SHA256, self.digests["requirements.lock"])
        self.assertEqual(launcher.PYTHON_WHEELHOUSE_SHA256, self.digests[PYTHON_ARCHIVE])
        for artifact in (MUSL_APK, MUSL_DEV_APK, PYTHON_ARCHIVE):
            self.assertEqual(launcher.OFFLINE_BUILD_INPUT_SHA256[self.dependencies / artifact], self.digests[artifact])
        dockerfile = launcher.dockerfile()
        self.assertIn(self.digests["requirements.lock"] + " requirements.lock", dockerfile)
        self.assertIn(self.digests[PYTHON_ARCHIVE] + " python-wheelhouse-linux-amd64.tar.gz", dockerfile)
        self.assertFalse(self.prefetch.CACHE_DIR.exists())

    def test_launcher_rejects_inconsistent_reviewed_metadata(self) -> None:
        metadata = copy.deepcopy(self.python_metadata)
        metadata["artifacts"][PYTHON_ARCHIVE]["version"] = "sha256:" + "0" * 64
        self.write_manifest(self.prefetch.PYTHON_MANIFEST, metadata, self.prefetch.PYTHON_INPUTS)
        with self.assertRaisesRegex(RuntimeError, "descriptor differs from its pinned inputs"):
            self.load_launcher()


def verify_dependency_snapshot_contract() -> None:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DependencySnapshotTests)
    result = unittest.TestResult()
    suite.run(result)
    if not result.wasSuccessful():
        details = "\n".join(traceback for _, traceback in result.failures + result.errors)
        raise AssertionError("production dependency snapshot contract failed:\n" + details)


if __name__ == "__main__":
    unittest.main()
