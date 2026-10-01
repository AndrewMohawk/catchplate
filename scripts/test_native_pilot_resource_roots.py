#!/usr/bin/env python3
"""Fixed inventory controls and real FD-relative operations in a temporary tree.

Filesystem controls require an isolated Linux root/user namespace. Only the
initial slash descriptor/stat is redirected to that temporary tree; directory
opens, metadata, population checks, exclusive creation and fsync remain real.
These are directory-helper controls, not host provisioning or pilot admission.
"""
from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
import errno
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare_native_pilot_resource_roots as roots


LEGACY_LEAVES = (
    "/run/serverware-custody-business", "/run/serverware-shadow-retrieval",
    "/run/serverware-shadow-persistence", "/run/serverware-shadow-trusted-time",
    "/run/serverware-shadow-generation-install", "/run/serverware-shadow-commit-request",
    "/run/serverware-shadow-ingress-admission", "/run/serverware-shadow-terminal-append",
    "/run/serverware-shadow-dispatch-barrier", "/run/serverware-shadow-active-effect-barrier",
    "/run/serverware-shadow-active-effect-commit", "/run/serverware-native-pilot-bridge",
    "/var/lib/serverware/custody-business", "/var/lib/serverware/native-ledger-spool",
    "/var/lib/serverware/native-shadow-persistence", "/var/lib/serverware/native-shadow-generation-install",
    "/var/lib/serverware/native-pilot-bridge",
) + tuple("/var/lib/serverware/custody-generation/" + role for role in (
    "durable-recovery-store", "cleanup-authorization-consumer", "recovery-target-provider",
    "current-signature-authority", "bounded-cleanup-helper"))
ADDITIONS = {
    "/run/serverware-custody-genesis": 0o711,
    "/var/lib/serverware/custody-genesis": 0o711,
    "/var/lib/serverware/publication-genesis-endpoints": 0o711,
    "/run/serverware-shadow-publication-reconciliation": 0o711,
    "/run/serverware/native-pilot-core-handoff": 0o700,
}
OPERATIONAL_OBJECTS = "/var/lib/serverware/native-pilot-retrieval-objects"


class InventoryControls(unittest.TestCase):
    def test_legacy_inventory_and_report_unchanged(self):
        shared, leaves, modes = roots.selection("legacy")
        self.assertEqual(shared, ("/var/lib/serverware", "/var/lib/serverware/custody-generation"))
        self.assertEqual(leaves, LEGACY_LEAVES)
        self.assertEqual(modes, dict.fromkeys(LEGACY_LEAVES, 0o711))
        self.assertEqual(roots.TARGETS, shared + leaves)
        self.assertEqual(roots.initial_report("legacy", False), {
            "apiVersion": "serverware.nativePilotResourceRoots/v1", "operation": "inspect", "result": "refused",
            "directories": [{"path": path, "kind": "resource-parent" if path in leaves else "shared-container",
                "state": "not-inspected"} for path in shared + leaves],
            "releaseAuthority": False, "liveReady": False, "runtimeResourcesCreated": False,
            "filesystemSupportVerified": False})

    def test_adopted_inventory_modes_parent_order_and_report(self):
        shared, leaves, modes = roots.selection("adopted-cold")
        self.assertEqual(shared, roots.SHARED + ("/run/serverware",))
        self.assertEqual(leaves, LEGACY_LEAVES + tuple(ADDITIONS))
        self.assertEqual(modes, {**dict.fromkeys(LEGACY_LEAVES, 0o711), **ADDITIONS})
        seen = set(roots.ANCHORS)
        for path in shared + leaves:
            self.assertIn(roots.split(path)[0], seen)
            self.assertNotIn(path, seen)
            seen.add(path)
        report = roots.initial_report("adopted-cold", False)
        self.assertEqual(report, {
            "apiVersion": "serverware.nativePilotResourceRoots/v2", "profile": "adopted-cold",
            "operation": "inspect", "result": "refused",
            "directories": [{"path": path, "kind": "resource-parent" if path in leaves else "shared-container",
                "state": "not-inspected"} for path in shared + leaves],
            "releaseAuthority": False, "liveReady": False, "runtimeResourcesCreated": False,
            "filesystemSupportVerified": False})
        self.assertLess(len(json.dumps(report).encode("ascii")), roots.MAX_REPORT_BYTES)

    def test_operational_is_explicit_exact_extension_with_no_authority(self):
        shared, leaves, modes = roots.selection("adopted-operational")
        cold_shared, cold_leaves, cold_modes = roots.selection("adopted-cold")
        self.assertEqual(shared, cold_shared)
        self.assertEqual(leaves, cold_leaves + (OPERATIONAL_OBJECTS,))
        self.assertEqual(modes, {**cold_modes, OPERATIONAL_OBJECTS: 0o700})
        self.assertEqual(roots.OPERATIONAL_OBJECTS, OPERATIONAL_OBJECTS)
        report = roots.initial_report("adopted-operational", False)
        expected = roots.initial_report("adopted-cold", False)
        expected["profile"] = "adopted-operational"
        expected["directories"].append({"path": OPERATIONAL_OBJECTS,
            "kind": "auxiliary-retrieval-objects", "state": "not-inspected", "expectedMode": "0700"})
        self.assertEqual(report, expected)
        self.assertLess(len(json.dumps(report).encode("ascii")), roots.MAX_REPORT_BYTES)
        for profile in ("legacy", "adopted-cold"):
            self.assertNotIn(OPERATIONAL_OBJECTS, roots.selection(profile)[1])

    def test_profile_and_operation_are_closed(self):
        for value in (None, {}, "adopted", "../adopted-cold", "legacy "):
            with self.subTest(value=value), self.assertRaises(roots.Refused):
                roots.selection(value)
        with self.assertRaises(roots.Refused):
            roots.initial_report("adopted-cold", 1)


@contextmanager
def sandbox(profile="adopted-cold"):
    with tempfile.TemporaryDirectory(prefix="serverware-root-controls-") as directory:
        tree = Path(directory)
        for path in (tree / "run", tree / "var", tree / "var/lib"):
            path.mkdir()
            path.chmod(0o755)
        real_open, real_stat = os.open, os.stat

        def opened(path, flags, mode=0o777, *, dir_fd=None):
            if path == "/" and dir_fd is None:
                path = str(tree)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        def stated(path, *, dir_fd=None, follow_symlinks=True):
            if path == "/" and dir_fd is None:
                path = str(tree)
            return real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

        report = roots.initial_report(profile, True)
        owner = roots.Roots(report, profile=profile)
        with patch.object(roots.os, "open", opened), patch.object(roots.os, "stat", stated):
            try:
                yield tree, owner, report
            finally:
                owner.close()


@unittest.skipUnless(sys.platform == "linux" and os.getresuid() == (0, 0, 0)
    and os.getresgid() == (0, 0, 0), "requires isolated Linux root/user namespace")
class FilesystemControls(unittest.TestCase):
    def test_default_cli_is_legacy_inspection_only(self):
        with sandbox("legacy") as (tree, _, _):
            output = io.StringIO()
            with patch.object(sys, "argv", ["prepare_native_pilot_resource_roots.py"]), redirect_stdout(output):
                self.assertEqual(roots.main(), 1)
            report = json.loads(output.getvalue())
            self.assertEqual(report["apiVersion"], "serverware.nativePilotResourceRoots/v1")
            self.assertNotIn("profile", report)
            self.assertEqual(report["operation"], "inspect")
            self.assertEqual(report["result"], "parents-missing")
            self.assertFalse((tree / "var/lib/serverware").exists())
            self.assertEqual(tuple((tree / "run").iterdir()), ())

    def test_adopted_inspect_then_explicit_create_exact_empty_modes(self):
        with sandbox() as (tree, owner, report):
            owner.inspect()
            self.assertTrue(all(row["state"] == "missing" for row in report["directories"]))
            self.assertFalse((tree / "run/serverware").exists())
            owner.create_missing()
            owner.check_populations()
            self.assertEqual(set(owner.nodes), set(roots.ANCHORS + owner.targets))
            for path in owner.targets:
                info = (tree / path.lstrip("/")).stat()
                self.assertEqual((info.st_uid, info.st_gid), (0, 0))
                self.assertEqual(stat.S_IMODE(info.st_mode), owner.leaf_modes.get(path, 0o755))
            for path in owner.leaves:
                self.assertEqual(tuple((tree / path.lstrip("/")).iterdir()), ())
            self.assertTrue(all(row["state"] == "created" for row in report["directories"]))

    def test_legacy_create_does_not_select_any_adopted_path(self):
        with sandbox("legacy") as (tree, owner, _):
            owner.inspect(); owner.create_missing()
            for path in ("/run/serverware",) + tuple(ADDITIONS):
                self.assertFalse((tree / path.lstrip("/")).exists())

    def test_operational_inspect_and_explicit_create_empty_auxiliary_directory(self):
        with sandbox("adopted-operational") as (tree, owner, report):
            owner.inspect()
            leaf = tree / OPERATIONAL_OBJECTS.lstrip("/")
            self.assertFalse(leaf.exists())
            owner.create_missing(); owner.check_populations()
            self.assertEqual(set(owner.nodes), set(roots.ANCHORS + owner.targets))
            self.assertEqual(tuple(leaf.iterdir()), ())
            info = leaf.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (0, 0, 0o700))
            self.assertEqual(report["directories"][-1]["mode"], "0700")
            self.assertEqual(report["directories"][-1]["expectedMode"], "0700")
            self.assertEqual(tuple((tree / "run/serverware/native-pilot-core-handoff").iterdir()), ())

    def test_cold_create_does_not_create_operational_objects(self):
        with sandbox("adopted-cold") as (tree, owner, _):
            owner.inspect(); owner.create_missing()
            self.assertFalse((tree / OPERATIONAL_OBJECTS.lstrip("/")).exists())

    def test_operational_wrong_mode_refuses_before_creation_without_repair(self):
        with sandbox("adopted-operational") as (tree, owner, _):
            leaf = tree / OPERATIONAL_OBJECTS.lstrip("/")
            leaf.mkdir(parents=True); leaf.chmod(0o555)
            with self.assertRaises(roots.Refused) as caught:
                owner.inspect()
            self.assertEqual(caught.exception.code, "resource-parent-mode-differs")
            self.assertFalse((tree / "run/serverware").exists())
            self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o555)

    def test_operational_populated_directory_refuses_before_creation(self):
        with sandbox("adopted-operational") as (tree, owner, _):
            leaf = tree / OPERATIONAL_OBJECTS.lstrip("/")
            leaf.mkdir(parents=True); leaf.chmod(0o700)
            marker = leaf / "existing"
            marker.write_bytes(b"preserve")
            with self.assertRaises(roots.Refused) as caught:
                owner.inspect()
            self.assertEqual(caught.exception.code, "resource-parent-not-empty")
            self.assertFalse((tree / "run/serverware").exists())
            self.assertEqual(marker.read_bytes(), b"preserve")

    def test_operational_symlink_refuses_without_mutation(self):
        with sandbox("adopted-operational") as (tree, owner, _):
            target = tree / "elsewhere"
            target.mkdir(); target.chmod(0o700)
            leaf = tree / OPERATIONAL_OBJECTS.lstrip("/")
            leaf.parent.mkdir(parents=True)
            leaf.symlink_to(target, target_is_directory=True)
            with self.assertRaises(OSError):
                owner.inspect()
            self.assertFalse((tree / "run/serverware").exists())
            self.assertEqual(tuple(target.iterdir()), ())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)

    def test_wrong_handoff_mode_refuses_before_first_creation(self):
        with sandbox() as (tree, _, _):
            leaf = tree / "run/serverware/native-pilot-core-handoff"
            leaf.mkdir(parents=True); leaf.chmod(0o711)
            output = io.StringIO()
            with patch.object(sys, "argv", ["prepare_native_pilot_resource_roots.py",
                "--profile", "adopted-cold", "--create"]), redirect_stdout(output):
                self.assertEqual(roots.main(), 2)
            report = json.loads(output.getvalue())
            self.assertEqual(report["error"]["code"], "resource-parent-mode-differs")
            self.assertEqual(report["profile"], "adopted-cold")
            self.assertFalse((tree / "var/lib/serverware").exists())
            self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o711)

    def test_populated_last_parent_refuses_before_first_creation(self):
        with sandbox() as (tree, owner, _):
            leaf = tree / "run/serverware/native-pilot-core-handoff"
            leaf.mkdir(parents=True); leaf.chmod(0o700)
            marker = leaf / "existing"
            marker.write_bytes(b"preserve")
            with self.assertRaises(roots.Refused) as caught:
                owner.inspect()
            self.assertEqual(caught.exception.code, "resource-parent-not-empty")
            self.assertFalse((tree / "var/lib/serverware").exists())
            self.assertEqual(marker.read_bytes(), b"preserve")

    def test_symlink_parent_refuses_without_target_mutation(self):
        with sandbox() as (tree, owner, _):
            target = tree / "elsewhere"
            target.mkdir(); target.chmod(0o711)
            (tree / "run/serverware-custody-genesis").symlink_to(target, target_is_directory=True)
            with self.assertRaises(OSError):
                owner.inspect()
            self.assertFalse((tree / "var/lib/serverware").exists())
            self.assertEqual(tuple(target.iterdir()), ())

    def test_shared_ancestor_preserves_unrelated_entries_and_protected_mode(self):
        with sandbox() as (tree, owner, _):
            shared = tree / "run/serverware"
            shared.mkdir(); shared.chmod(0o700)
            marker = shared / "unrelated"
            marker.write_bytes(b"preserve")
            owner.inspect(); owner.create_missing(); owner.check_populations()
            self.assertEqual(stat.S_IMODE(shared.stat().st_mode), 0o700)
            self.assertEqual(marker.read_bytes(), b"preserve")

    def test_retained_name_replacement_refuses(self):
        with sandbox() as (tree, owner, _):
            owner.inspect(); owner.create_missing()
            leaf = tree / "run/serverware-custody-genesis"
            held = tree / "run/retained-old-directory"
            leaf.rename(held); leaf.mkdir(); leaf.chmod(0o711)
            with self.assertRaises(roots.Refused) as caught:
                owner.recheck()
            self.assertEqual(caught.exception.code, "retained-name-changed")
            self.assertTrue(held.is_dir())

    def test_concurrent_creation_refuses_without_adopting_or_repair(self):
        with sandbox() as (tree, owner, _):
            owner.inspect()
            unexpected = tree / "var/lib/serverware"
            unexpected.mkdir(); unexpected.chmod(0o700)
            with self.assertRaises(FileExistsError):
                owner.create_missing()
            self.assertNotIn("/var/lib/serverware", owner.nodes)
            self.assertEqual(stat.S_IMODE(unexpected.stat().st_mode), 0o700)
            self.assertEqual(tuple(unexpected.iterdir()), ())

    def test_fsync_failure_preserves_partial_directory(self):
        with sandbox() as (tree, owner, report):
            owner.inspect()
            with patch.object(roots.os, "fsync", side_effect=OSError(errno.EIO, "synthetic fsync failure")):
                with self.assertRaises(OSError):
                    owner.create_missing()
            self.assertTrue((tree / "var/lib/serverware").is_dir())
            self.assertFalse((tree / "var/lib/serverware/custody-generation").exists())
            self.assertEqual(report["directories"][0]["state"], "created-unconfirmed")


if __name__ == "__main__":
    unittest.main()
