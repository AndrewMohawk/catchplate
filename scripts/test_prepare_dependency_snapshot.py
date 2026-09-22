#!/usr/bin/env python3
"""Offline producer tests; synthetic wheel fixtures never count as release artifacts."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("prepare_dependency_snapshot", ROOT / "production-dependencies/prepare_snapshot.py")
assert SPEC is not None and SPEC.loader is not None
producer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(producer)


def wheel_bytes(name: str, version: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as wheel:
        info = zipfile.ZipInfo(f"{name}-{version}.dist-info/METADATA", date_time=(2020, 1, 1, 0, 0, 0))
        wheel.writestr(info, f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
    return output.getvalue()


def lock_bytes(name: str, version: str, artifact: bytes) -> bytes:
    return f"{name}=={version} \\\n    --hash=sha256:{hashlib.sha256(artifact).hexdigest()}\n".encode("ascii")


def vendor_bytes() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        info = tarfile.TarInfo("vendor/test/.cargo-checksum.json")
        info.mode, info.size = 0o644, 3
        archive.addfile(info, io.BytesIO(b"{}\n"))
    return output.getvalue()


class ProducerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="dependency-producer-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.wheels = self.directory / "wheels"
        self.wheels.mkdir()
        self.wheel_name = "cryptography-50.0.0-py3-none-any.whl"
        self.wheel = wheel_bytes("cryptography", "50.0.0")
        (self.wheels / self.wheel_name).write_bytes(self.wheel)
        self.lock = lock_bytes("cryptography", "50.0.0", self.wheel)
        self.locked = producer.locked_packages(self.lock)

    def test_lock_rejects_unpinned_or_network_directives(self) -> None:
        for content in (
            b"--index-url https://unreviewed.invalid/simple\n" + self.lock,
            b"cryptography>=50\n", b"cryptography @ https://unreviewed.invalid/pkg.whl\n",
            b"-r another.lock\n", self.lock + self.lock,
            self.lock.replace(b"sha256:", b"md5:"),
            self.lock.replace(b"\n    --hash", b"\n# interrupted\n    --hash"),
        ):
            with self.subTest(content=content):
                with self.assertRaises(ValueError):
                    producer.locked_packages(content)

    def test_wheels_must_match_names_versions_and_reviewed_bytes(self) -> None:
        inventory = producer.wheel_inventory(self.wheels, self.locked)
        self.assertEqual(inventory[0]["sha256"], hashlib.sha256(self.wheel).hexdigest())
        self.assertEqual(inventory[0]["version"], "50.0.0")
        for content in (wheel_bytes("cryptography", "49.0.0"), wheel_bytes("unreviewed", "50.0.0"), self.wheel + b"changed"):
            with self.subTest(content=content):
                (self.wheels / self.wheel_name).write_bytes(content)
                with self.assertRaises(ValueError):
                    producer.wheel_inventory(self.wheels, self.locked)

    def test_wheelhouse_rejects_missing_extra_and_symlinked_files(self) -> None:
        path = self.wheels / self.wheel_name
        path.unlink()
        with self.assertRaisesRegex(ValueError, "every committed package"):
            producer.wheel_inventory(self.wheels, self.locked)
        target = self.directory / self.wheel_name
        target.write_bytes(self.wheel)
        path.symlink_to(target)
        with self.assertRaises(OSError):
            producer.wheel_inventory(self.wheels, self.locked)
        path.unlink()
        path.write_bytes(self.wheel)
        (self.wheels / "unexpected.txt").write_bytes(b"extra\n")
        with self.assertRaisesRegex(ValueError, "unexpected filename"):
            producer.wheel_inventory(self.wheels, self.locked)

    def test_packaging_is_deterministic_and_roundtrips(self) -> None:
        first, second = io.BytesIO(), io.BytesIO()
        producer.package_wheels(self.wheels, first)
        path = self.wheels / self.wheel_name
        os.chmod(path, 0o600)
        os.utime(path, (42, 42))
        producer.package_wheels(self.wheels, second)
        self.assertEqual(first.getvalue(), second.getvalue())
        self.assertEqual(first.getvalue()[4:8], b"\0\0\0\0")
        with tarfile.open(fileobj=io.BytesIO(first.getvalue()), mode="r:gz") as archive:
            for member in archive:
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
        packed = self.directory / "wheelhouse.tar.gz"
        packed.write_bytes(first.getvalue())
        unpacked = self.directory / "unpacked"
        unpacked.mkdir()
        producer.unpack_wheels(packed, unpacked)
        self.assertEqual(producer.wheel_inventory(unpacked, self.locked), producer.wheel_inventory(self.wheels, self.locked))

    def test_unpacking_rejects_nonwheel_paths_and_links(self) -> None:
        for name, kind in (("../outside.whl", tarfile.REGTYPE), ("wheelhouse/pkg.whl", tarfile.SYMTYPE)):
            with self.subTest(name=name, kind=kind):
                archive_path = self.directory / "invalid.tar.gz"
                with tarfile.open(archive_path, "w:gz") as archive:
                    item = tarfile.TarInfo(name)
                    item.type, item.linkname = kind, "/outside"
                    archive.addfile(item)
                with self.assertRaises(ValueError):
                    producer.unpack_wheels(archive_path, self.directory)

    def test_fixed_container_commands_separate_network_and_authority(self) -> None:
        for phase, network in (("download", "bridge"), ("verify", "none")):
            command = producer.docker_command(phase, self.directory, "fixed-task-name")
            self.assertEqual(command[command.index("--network") + 1], network)
            self.assertIn("--pull=never", command)
            self.assertIn("--read-only", command)
            self.assertIn("--cap-drop=ALL", command)
            self.assertIn("--memory=2g", command)
            self.assertIn("--memory-swap=2g", command)
            self.assertIn("--pids-limit=128", command)
            self.assertIn("--cpus=1", command)
            self.assertIn(producer.PYTHON_IMAGE, command)
            self.assertIn("1400s", command)
            self.assertFalse(any("docker.sock" in value for value in command))
            self.assertNotIn("--privileged", command)
            self.assertNotIn("--env-file", command)
            mounts = [command[index + 1] for index, value in enumerate(command) if value == "--mount"]
            self.assertTrue(all(",readonly" in mount or "dst=/output" in mount for mount in mounts))
            tmpfs = [command[index + 1] for index, value in enumerate(command) if value == "--tmpfs"]
            expected_tmpfs = ["/tmp:rw,nosuid,nodev,noexec,size=1536m,mode=1777"] if phase == "download" else [
                "/tmp:rw,nosuid,nodev,noexec,size=1024m,mode=1777",
                "/installed:rw,nosuid,nodev,exec,size=512m,mode=1777",
            ]
            self.assertEqual(tmpfs, expected_tmpfs)
        with self.assertRaises(ValueError):
            producer.docker_command("arbitrary-command", self.directory, "fixed-task-name")

    def test_offline_install_inventory_and_native_import_use_only_exec_tmpfs(self) -> None:
        inventory = producer.wheel_inventory(self.wheels, self.locked)
        cases = (
            {"cryptography": "50.0.0"},
            {"cryptography": "49.0.0"},
            {"cryptography": "50.0.0", "unexpected": "1.0"},
        )
        for index, packages in enumerate(cases):
            with self.subTest(packages=packages):
                scratch = self.directory / f"verify-{index}"
                scratch.mkdir()
                distributions = [mock.Mock(metadata={"Name": name}, version=version)
                                 for name, version in packages.items()]
                with mock.patch.object(producer, "read_small", return_value=self.lock), \
                     mock.patch.object(producer.tempfile, "TemporaryDirectory") as temporary, \
                     mock.patch.object(producer, "unpack_wheels") as unpack, \
                     mock.patch.object(producer, "wheel_inventory", return_value=inventory), \
                     mock.patch.object(producer, "run_pip") as pip, \
                     mock.patch.object(producer.importlib.metadata, "distributions", return_value=distributions) as installed, \
                     mock.patch.object(producer.importlib.metadata, "version", return_value="24.0"), \
                     mock.patch.object(producer.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "50.0.0\n")) as smoke, \
                     mock.patch.object(producer.Path, "write_bytes") as report:
                    temporary.return_value.__enter__.return_value = str(scratch)
                    if index:
                        with self.assertRaisesRegex(ValueError, "installed package inventory"):
                            producer.container_phase("verify")
                        self.assertEqual(pip.call_count, 1)
                        smoke.assert_not_called()
                        report.assert_not_called()
                    else:
                        producer.container_phase("verify")
                        self.assertEqual(pip.call_count, 2)
                        self.assertEqual(pip.call_args_list[1].args, (["check"],))
                        self.assertEqual(pip.call_args_list[1].kwargs["env"]["PYTHONPATH"], "/installed")
                        self.assertEqual(smoke.call_args.kwargs["env"]["PYTHONPATH"], "/installed")
                        self.assertIn("from cryptography.hazmat.bindings import _rust", smoke.call_args.args[0][2])
                        result = json.loads(report.call_args.args[0])
                        self.assertEqual(result["installed"], packages)
                        self.assertEqual(result["cryptography_import"], "50.0.0")
                    temporary.assert_called_once_with(dir="/tmp", prefix="snapshot-")
                    unpack.assert_called_once_with(Path("/archive/python-wheelhouse-linux-amd64.tar.gz"), scratch / "wheelhouse")
                    arguments = pip.call_args_list[0].args[0]
                    self.assertEqual(arguments[arguments.index("--target") + 1], "/installed")
                    self.assertEqual(arguments[arguments.index("--find-links") + 1], str(scratch / "wheelhouse"))
                    self.assertIn("--no-index", arguments)
                    self.assertIn("--require-hashes", arguments)
                    installed.assert_called_once_with(path=["/installed"])

    def test_timeout_cleans_only_its_named_container(self) -> None:
        (self.directory / "work/download").mkdir(parents=True)
        with mock.patch.object(producer.subprocess, "run", side_effect=[subprocess.TimeoutExpired("docker", 1500), subprocess.CompletedProcess([], 0)]) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                producer.run_container("download", self.directory)
        start = run.call_args_list[0].args[0]
        name = start[start.index("--name") + 1]
        self.assertEqual(run.call_args_list[1].args[0], ["docker", "rm", "--force", name])

    def fixture_source(self) -> tuple[Path, dict[str, str], dict[str, bytes]]:
        root = self.directory / "source"
        dependencies = root / "production-dependencies"
        dependencies.mkdir(parents=True)
        shutil.copyfile(ROOT / "production-dependencies/prefetch.py", dependencies / "prefetch.py")
        cache = self.directory / "old-cache"
        cache.mkdir()
        old_lock = lock_bytes("cryptography", "49.0.0", wheel_bytes("cryptography", "49.0.0"))
        captured = {"requirements.lock": self.lock,
                    "data-plane/decision-gate-rs/Cargo.toml": b"same Cargo manifest\n",
                    "data-plane/decision-gate-rs/Cargo.lock": b"same Cargo lock\n"}
        for relative, content in captured.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        contents = {"cache/cargo-vendor.tar.gz": vendor_bytes(),
                    "cache/musl-1.2.5-r12.apk": b"reviewed musl bytes\n",
                    "cache/musl-dev-1.2.5-r12.apk": b"reviewed musl-dev bytes\n"}
        for relative, content in contents.items():
            (cache / Path(relative).name).write_bytes(content)
        (cache / "python-wheelhouse-linux-amd64.tar.gz").write_bytes(b"obsolete wheelhouse must never be reused\n")
        verifier = producer.prefetch_module(root, dependencies)
        entries = [
            {"requirements.lock": hashlib.sha256(old_lock).hexdigest(), verifier.PYTHON_ARCHIVE: "a" * 64},
            {name: hashlib.sha256(content).hexdigest() for name, content in {**{k: v for k, v in captured.items() if k != "requirements.lock"}, **contents}.items()},
        ]
        for name, values in zip(producer.MANIFEST_NAMES, entries):
            metadata = {"apiVersion": verifier.MANIFEST_API_VERSION, "platform": "linux/amd64",
                        "snapshotId": "reviewed-v1", "snapshotUrlSuffix": "/reviewed-v1",
                        "artifacts": {key: verifier.expected_artifact_descriptor(key, values) for key in values if key in verifier.CACHE_INPUTS}}
            data = b"# metadata=" + producer.canonical_json(metadata)
            data += "".join(f"{digest}  {relative}\n" for relative, digest in values.items()).encode("ascii")
            (dependencies / name).write_bytes(data)
        return root, {"commit": "1" * 40, "tree": "2" * 40}, captured

    def prepared_candidate(self, *, corrupt_rust: bool = False, bad_offline: bool = False) -> tuple[Path, Path]:
        root, source, captured = self.fixture_source()
        candidate = self.directory / "candidate"
        if corrupt_rust:
            (self.directory / "old-cache/musl-1.2.5-r12.apk").write_bytes(b"modified\n")
        original_manifests = {name: (root / "production-dependencies" / name).read_bytes() for name in producer.MANIFEST_NAMES}

        def fixed_phase(phase: str, output: Path) -> dict[str, object]:
            inventory = producer.wheel_inventory(self.wheels, self.locked)
            if phase == "download":
                archive = output / "work/download/python-wheelhouse-linux-amd64.tar.gz"
                with archive.open("wb") as destination:
                    producer.package_wheels(self.wheels, destination)
                return {"ok": True, "archive": producer.copy_verified(archive, None),
                        "wheels": inventory, "deterministic_packaging": True}
            return {"ok": True, "network": "none", "pip_check": not bad_offline,
                    "wheels": inventory, "installed": {"cryptography": "50.0.0"}}

        image = [{"Os": "linux", "Architecture": "amd64", "Id": "sha256:" + "3" * 64}]
        with mock.patch.object(producer, "ROOT", root), \
             mock.patch.object(producer.os, "geteuid", return_value=1000), \
             mock.patch.object(producer, "capture_source", return_value=(source, captured)), \
             mock.patch.object(producer, "validate_output", return_value=candidate), \
             mock.patch.object(producer, "run_container", side_effect=fixed_phase) as phases, \
             mock.patch.object(producer.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, producer.canonical_json(image))):
            if corrupt_rust or bad_offline:
                with self.assertRaises(ValueError):
                    producer.prepare(expected_commit=source["commit"], existing_cache=self.directory / "old-cache",
                                     snapshot_id="candidate-v2", output=candidate)
                if corrupt_rust:
                    phases.assert_not_called()
                self.assertFalse((candidate / "snapshot/python-linux-amd64.sha256").exists())
                self.assertFalse(json.loads((candidate / "candidate-report.json").read_bytes())["ok"])
            else:
                report = producer.prepare(expected_commit=source["commit"], existing_cache=self.directory / "old-cache",
                                          snapshot_id="candidate-v2", output=candidate)
                self.assertTrue(report["ok"])
                self.assertFalse(report["published"])
                self.assertFalse(report["reviewed_pins_installed"])
                self.assertFalse(report["production_release_authority"])
                self.assertEqual([call.args[0] for call in phases.call_args_list], ["download", "verify"])
        for name, original in original_manifests.items():
            self.assertEqual((root / "production-dependencies" / name).read_bytes(), original)
        return root, candidate

    def test_candidate_uses_fresh_python_and_carries_only_verified_rust(self) -> None:
        root, candidate = self.prepared_candidate()
        verifier = producer.prefetch_module(candidate, candidate / "snapshot")
        verifier.verify()
        manifests = verifier.manifests()
        self.assertEqual({item["metadata"]["snapshotId"] for item in manifests}, {"candidate-v2"})
        self.assertEqual(manifests[0]["entries"]["requirements.lock"], hashlib.sha256(self.lock).hexdigest())
        for artifact in ("cargo-vendor.tar.gz", "musl-1.2.5-r12.apk", "musl-dev-1.2.5-r12.apk"):
            self.assertEqual((candidate / "snapshot/cache" / artifact).read_bytes(), (self.directory / "old-cache" / artifact).read_bytes())
        self.assertNotEqual((candidate / "snapshot/cache/python-wheelhouse-linux-amd64.tar.gz").read_bytes(),
                            (self.directory / "old-cache/python-wheelhouse-linux-amd64.tar.gz").read_bytes())

    def test_changed_rust_is_rejected_before_download(self) -> None:
        self.prepared_candidate(corrupt_rust=True)

    def test_failed_offline_validation_never_emits_proposed_pins(self) -> None:
        self.prepared_candidate(bad_offline=True)

    def test_output_cannot_replace_existing_data(self) -> None:
        with self.assertRaises(ValueError):
            producer.validate_output(self.directory)
        link = self.directory / "candidate-link"
        link.symlink_to(self.directory / "absent")
        with self.assertRaises(ValueError):
            producer.validate_output(link)

    def test_source_must_be_the_exact_clean_recorded_commit(self) -> None:
        expected = "1" * 40
        for responses in ((b"2" * 40 + b"\n",), (expected.encode() + b"\n", b" M requirements.lock\n")):
            with self.subTest(responses=responses):
                with mock.patch.object(producer, "git_bytes", side_effect=responses):
                    with self.assertRaisesRegex(ValueError, "exact clean recorded commit"):
                        producer.capture_source(expected)

    def test_reusing_snapshot_id_or_changed_cargo_never_contacts_docker(self) -> None:
        root, source, captured = self.fixture_source()
        for snapshot_id, change_cargo in (("reviewed-v1", False), ("candidate-v2", True)):
            with self.subTest(snapshot_id=snapshot_id, change_cargo=change_cargo):
                selected = dict(captured)
                if change_cargo:
                    selected["data-plane/decision-gate-rs/Cargo.lock"] = b"changed Cargo lock\n"
                with mock.patch.object(producer, "ROOT", root), \
                     mock.patch.object(producer.os, "geteuid", return_value=1000), \
                     mock.patch.object(producer, "capture_source", return_value=(source, selected)), \
                     mock.patch.object(producer.subprocess, "run") as run:
                    with self.assertRaises(ValueError):
                        producer.prepare(expected_commit=source["commit"], existing_cache=self.directory / "old-cache",
                                         snapshot_id=snapshot_id, output=self.directory / "candidate")
                    run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
