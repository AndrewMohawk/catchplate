#!/usr/bin/env python3
"""Synthetic offline package controls, not installed-runtime acceptance.

The tiny source tree, manifest, ELF header and script bytes are test fixtures.
No interpreter, bootstrap main, supervisor, protected owner, issuer, channel,
container or native service is executed. Only temporary package files are made.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_pilot_runtime_artifacts as runtime
import native_pilot_supervisor_runtime_entrypoint as entrypoint
import package_native_pilot_runtime as packaging


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write(path, raw, mode=0o444):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)


def thaw(root):
    if root.exists():
        for directory, _, files in os.walk(root):
            Path(directory).chmod(0o700)
            for name in files:
                path = Path(directory) / name
                if not path.is_symlink():
                    path.chmod(0o600)


def fixture(parent, profile="supervisor"):
    """A fake, non-executable exported root and independently framed source pins."""
    root = parent / "root"
    root.mkdir()
    source_names = (
        "serverware/__init__.py", "serverware/synthetic.py",
        "scripts/native_pilot_runtime_entrypoint.py", "scripts/run_native_pilot.py",
        "scripts/native_pilot_authority_runtime_entrypoint.py",
        "scripts/run_native_pilot_authority_coordinator.py", "scripts/native_pilot_runtime_artifacts.py",
        "scripts/verify_nitro_tee.py", "scripts/authority/native_pilot_authority_io.py",
        "scripts/authority/prepare_native_pilot_closure_set.py",
        "scripts/native_pilot_supervisor_runtime_entrypoint.py", "scripts/run_native_pilot_supervisor.py",
        "scripts/native_pilot_publication_runtime_entrypoint.py",
    )
    originals = {name: ("# synthetic source original: " + name + "\n").encode("ascii") for name in source_names}
    for name, raw in originals.items():
        if name.startswith("serverware/") or name in source_names[2:4]:
            prefix = "app/"
        elif name in source_names[4:10] and profile in ("authority", "supervisor"):
            prefix = "authority/app/"
        elif name in source_names[10:] and profile == "supervisor":
            prefix = "supervisor/app/"
        else:
            continue
        write(root / (prefix + name), raw)
    tree = {"version": "serverware.sourceTree/v3", "identityMode": "production-commit",
        "productionReleaseEligible": True, "commit": "1" * 40, "commitTimestamp": "1234567890",
        "files": [{"path": name, "type": "file", "mode": "100644", "bytes": len(raw), "sha256": sha(raw)}
                  for name, raw in sorted(originals.items())]}
    source = {"revision": tree["commit"], "source_tree_digest": sha(canonical(tree)),
        "source_archive_digest": sha(b"synthetic archive identity, not an actual Git archive"),
        "source_date_epoch": tree["commitTimestamp"]}
    manifest = {"apiVersion": "serverware.sourceArchive/v1", "identityMode": "production-commit",
        "productionReleaseEligible": True, "commit": source["revision"],
        "commitTimestamp": source["source_date_epoch"], "sourceTreeDigest": source["source_tree_digest"],
        "sourceTreeManifest": tree, "archive": {"sha256": source["source_archive_digest"]}}
    manifest_raw = canonical(manifest) + b"\n"
    source["source_manifest_digest"] = sha(manifest_raw)
    write(root / "usr/share/serverware/source-manifest.json", manifest_raw)
    elf = bytearray(64)
    elf[:7] = b"\x7fELF\x02\x01\x01"
    elf[16:18] = (2).to_bytes(2, "little")
    elf[18:20] = (62).to_bytes(2, "little")
    write(root / "runtime/python/bin/python3", bytes(elf), 0o555)
    write(root / "vendor/synthetic.txt", b"not an installed dependency\n")
    for directory, _, _ in os.walk(root):
        Path(directory).chmod(0o555)
    return root, source


def arguments():
    result = ["--run-native-pilot"]
    for number, name in enumerate(("supervisor-inventory", "policy", "recipe",
                                   "conductor-inventory", "authority-inventory"), 3):
        result.extend(("--" + name + "-fd", str(number), "--" + name + "-sha256", "sha256:" + "a" * 64))
    result.extend(("--approval-fd", "8", "--approval-peer-pid", "123",
                   "--approval-peer-uid", "0", "--approval-peer-gid", "0"))
    for number in range(113):
        # Multiple independently bound purposes can use the same supplied key.
        result.extend(("--authority-key", "synthetic-purpose-" + str(number) + "=9"))
    return result


class SupervisorRuntimeTests(unittest.TestCase):
    def directory(self):
        owner = tempfile.TemporaryDirectory(prefix="pilot-supervisor-package-")
        path = Path(owner.name).resolve()
        self.addCleanup(owner.cleanup)
        self.addCleanup(thaw, path)
        return path

    def test_distinct_supervisor_inventory_and_source_namespaces(self):
        root, source = fixture(self.directory())
        observed = runtime.supervisor_inventory(root, source)
        self.assertEqual(observed["apiVersion"], "serverware.nativePilotSupervisorRuntime/v1")
        self.assertEqual(observed["target"], "native-pilot-supervisor-artifact")
        self.assertEqual(observed["command"], ["/runtime/python/bin/python3", "-I", "-B",
            "/supervisor/app/scripts/native_pilot_supervisor_runtime_entrypoint.py", "--run-native-pilot"])
        self.assertEqual(observed["recordsSha256"], sha(canonical(observed["records"])))
        files = {row["path"] for row in observed["records"] if row["type"] == "file"}
        self.assertEqual({name for name in files if name.startswith("supervisor/")}, {
            "supervisor/app/scripts/native_pilot_supervisor_runtime_entrypoint.py",
            "supervisor/app/scripts/run_native_pilot_supervisor.py",
            "supervisor/app/scripts/native_pilot_publication_runtime_entrypoint.py"})
        self.assertIn("authority/app/scripts/authority/native_pilot_authority_io.py", files)
        self.assertIn("authority/app/scripts/authority/prepare_native_pilot_closure_set.py", files)
        self.assertIn("authority/app/scripts/verify_nitro_tee.py", files)
        self.assertIn("app/serverware/synthetic.py", files)
        self.assertFalse(observed["requiredArguments"]["childInventoriesDerived"])
        self.assertFalse(observed["requiredArguments"]["currentnessDecisionsDerived"])
        for name in ("releaseAuthority", "liveReady", "launchPrepared", "dynamicLoaderClosureVerified"):
            self.assertIs(observed[name], False)

    def test_child_profiles_remain_source_fixed(self):
        for profile, observe, api in (("conductor", runtime.inventory, "serverware.nativePilotConductorRuntime/v1"),
                ("authority", runtime.authority_inventory, "serverware.nativePilotAuthorityRuntime/v1")):
            with self.subTest(profile=profile):
                root, source = fixture(self.directory(), profile)
                value = observe(root, source)
                self.assertEqual(value["apiVersion"], api)
                with self.assertRaises(RuntimeError):
                    runtime.supervisor_inventory(root, source)
                (root / "app/scripts").chmod(0o755)
                write(root / "app/scripts/run_native_pilot_supervisor.py", b"# misplaced\n")
                with self.assertRaises(RuntimeError):
                    observe(root, source)

    def test_missing_extra_and_changed_source_refuse(self):
        for mutation in ("missing-supervisor", "extra-supervisor", "changed-authority", "missing-shared"):
            with self.subTest(mutation=mutation):
                root, source = fixture(self.directory())
                if mutation == "missing-supervisor":
                    path = root / "supervisor/app/scripts/run_native_pilot_supervisor.py"
                    path.parent.chmod(0o755); path.unlink(); path.parent.chmod(0o555)
                elif mutation == "extra-supervisor":
                    path = root / "supervisor/app/scripts/unapproved.py"
                    path.parent.chmod(0o755); write(path, b"# not source selected\n"); path.parent.chmod(0o555)
                elif mutation == "changed-authority":
                    path = root / "authority/app/scripts/verify_nitro_tee.py"
                    path.chmod(0o600); write(path, b"# altered public validator\n")
                else:
                    path = root / "app/serverware/synthetic.py"
                    path.parent.chmod(0o755); path.unlink(); path.parent.chmod(0o555)
                with self.assertRaises(RuntimeError):
                    runtime.supervisor_inventory(root, source)

    def test_source_contract_and_duplicate_source_paths_refuse(self):
        for mutation in ("not-production", "duplicate", "wrong-original-pin"):
            with self.subTest(mutation=mutation):
                root, source = fixture(self.directory())
                path = root / "usr/share/serverware/source-manifest.json"
                value = json.loads(path.read_bytes())
                if mutation == "not-production":
                    value["productionReleaseEligible"] = False
                elif mutation == "duplicate":
                    tree = value["sourceTreeManifest"]
                    tree["files"].append(copy.deepcopy(tree["files"][0]))
                    source["source_tree_digest"] = sha(canonical(tree))
                    value["sourceTreeDigest"] = source["source_tree_digest"]
                raw = canonical(value) + b"\n"
                path.chmod(0o600); write(path, raw)
                source["source_manifest_digest"] = sha(raw) if mutation != "wrong-original-pin" else sha(b"wrong")
                with self.assertRaises(RuntimeError):
                    runtime.supervisor_inventory(root, source)

    def test_source_namespace_symlink_and_hardlink_refuse(self):
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                root, source = fixture(self.directory())
                target = root / "supervisor/app/scripts/run_native_pilot_supervisor.py"
                target.parent.chmod(0o755); target.unlink()
                other = root / "authority/app/scripts/run_native_pilot_authority_coordinator.py"
                if kind == "symlink":
                    target.symlink_to("/authority/app/scripts/run_native_pilot_authority_coordinator.py")
                else:
                    os.link(other, target)
                target.parent.chmod(0o555)
                with self.assertRaises(RuntimeError):
                    runtime.supervisor_inventory(root, source)

    def test_package_supervisor_is_reproducible_and_exact(self):
        parent = self.directory()
        root, source = fixture(parent)
        observed = runtime.supervisor_inventory(root, source)
        first = packaging.package_supervisor(root, observed, parent / "first")
        second = packaging.package_supervisor(root, observed, parent / "second")
        self.assertEqual(first, second)
        self.assertEqual(first["apiVersion"], "serverware.nativePilotSupervisorPackage/v1")
        archive_raw = (parent / "first/runtime-rootfs.tar").read_bytes()
        self.assertEqual(first["archive"]["sha256"], sha(archive_raw))
        self.assertEqual(first["inventorySha256"], sha(canonical(observed)))
        self.assertEqual((parent / "first/package.json").read_bytes(), canonical(first))
        with tarfile.open(parent / "first/runtime-rootfs.tar", "r:") as archive:
            members = archive.getmembers()
            self.assertEqual([row.name for row in members], [row["path"] for row in observed["records"]])
            self.assertTrue(all(row.uid == row.gid == 0 and row.mtime == 1234567890 for row in members))
            for member in members:
                if member.isfile():
                    self.assertEqual(archive.extractfile(member).read(), (root / member.name).read_bytes())
        for name in ("releaseAuthority", "liveReady", "installed", "executionAccepted"):
            self.assertIs(first[name], False)

    def test_package_rejects_wrong_profile_drift_and_output_adoption(self):
        parent = self.directory()
        root, source = fixture(parent)
        observed = runtime.supervisor_inventory(root, source)
        for package in (packaging.package, packaging.package_authority):
            with self.assertRaises(ValueError):
                package(root, observed, parent / "wrong")
            self.assertFalse((parent / "wrong").exists())
        altered = copy.deepcopy(observed)
        altered["boundary"] = "unapproved interpretation"
        with self.assertRaises(ValueError):
            packaging.package_supervisor(root, altered, parent / "altered")
        self.assertFalse((parent / "altered").exists())
        (parent / "existing").mkdir()
        with self.assertRaises(FileExistsError):
            packaging.package_supervisor(root, observed, parent / "existing")
        self.assertEqual(list((parent / "existing").iterdir()), [])
        target = root / "supervisor/app/scripts/run_native_pilot_supervisor.py"
        target.chmod(0o600); write(target, b"# changed after inventory\n")
        with self.assertRaises(RuntimeError):
            packaging.package_supervisor(root, observed, parent / "drift")
        self.assertFalse((parent / "drift").exists())

    def test_bootstrap_closed_arguments_and_boundaries(self):
        approved_syntax = arguments()
        self.assertTrue(entrypoint.valid_arguments(approved_syntax))
        self.assertEqual(entrypoint.IMPORT_ROOTS, ("/supervisor/app", "/authority/app", "/vendor", "/app"))
        self.assertEqual(entrypoint.CLI, "/supervisor/app/scripts/run_native_pilot_supervisor.py")
        for index, value in ((0, "--help"), (1, "--runtime-inventory-fd"), (2, "03"),
                (4, "sha256:" + "A" * 64), (6, "3"), (22, "3"), (24, "0"), (24, "1"),
                (26, str((1 << 32) - 1)), (28, str((1 << 32) - 1)), (26, str(1 << 32)),
                (30, "synthetic-purpose-0=3"), (32, "synthetic-purpose-0=9")):
            with self.subTest(index=index):
                altered = approved_syntax[:]; altered[index] = value
                self.assertFalse(entrypoint.valid_arguments(altered))
        self.assertFalse(entrypoint.valid_arguments(approved_syntax + ["--module", "unapproved"]))
        self.assertFalse(entrypoint.valid_arguments(approved_syntax[:29]))
        self.assertFalse(entrypoint.valid_arguments(tuple(approved_syntax)))
        self.assertFalse(entrypoint.valid_arguments(approved_syntax[:29] +
            [value for number in range(129) for value in ("--authority-key", "purpose-" + str(number) + "=9")]))


if __name__ == "__main__":
    unittest.main()
