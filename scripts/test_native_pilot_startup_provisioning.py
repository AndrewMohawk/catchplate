#!/usr/bin/env python3
"""Actual startup atomic-file controls and bounded runtime source joins.

The real Linux backend runs in disposable chroot children. Byte fixtures are
public storage inputs, not independently authorized admissions. No installed
runtime, provisioner, launcher or process owner is fabricated or mocked.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import stat
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from scripts.test_native_pilot_current_head_state import _isolated, _pin, _read
from catchplate import native_pilot_current_head_state as storage
from catchplate import native_pilot_startup_profile as startup

p = startup.p


def isolated(action):
    # Load the only lazy selected codec before the isolated child loses access
    # to the source checkout. This is not a runtime/package-admission fixture.
    storage.StartupAtomicPublisher._limits()
    def run(_source):
        os.mkdir(startup.DIRECTORY, 0o700)
        action()
    _isolated({}, run)


@unittest.skipUnless(sys.platform == "linux" and os.getresuid() == os.getresgid() == (0, 0, 0),
    "actual startup storage controls require root-owned test files and chroot")
class StartupAtomicPublicationControls(unittest.TestCase):
    def test_two_real_publishers_observe_complete_original_then_six_inputs_and_admission(self):
        def action():
            pin = _pin(startup.DIRECTORY)
            observer = storage.StartupAtomicPublisher.open(directory=pin, check=lambda: None)
            provisioner = storage.StartupAtomicPublisher.open(directory=pin, check=lambda: None)
            self.assertEqual(observer.names(), set()); provisioner.preflight_inputs()
            raw = p.canonical({"syntheticStorageObservation": True})
            observer.publish(startup.OBSERVATION_NAME, raw)
            self.assertEqual(provisioner.observation_original(), raw)
            values = {name: p.canonical({"syntheticStoragePurpose": name}) for name in startup.SOURCE_NAMES}
            for purpose in startup.SOURCE_NAMES:
                provisioner.publish(startup.SOURCE_FILENAMES[purpose], values[purpose])
            admission = p.canonical({"syntheticStorageAdmission": True})
            provisioner.publish(startup.ADMISSION_NAME, admission)
            self.assertEqual(len(provisioner.names()), 8)
            self.assertEqual(_read(startup.DIRECTORY + "/" + startup.ADMISSION_NAME), admission)
            for name in provisioner.names():
                info = os.stat(startup.DIRECTORY + "/" + name)
                self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_nlink), (0o400, 0, 0, 1))
            provisioner.close(); observer.close()
        isolated(action)

    def test_observation_final_name_never_exposes_partial_bytes(self):
        def action():
            raw = p.canonical({"syntheticStorageObservation": "x" * 60000})
            path = startup.DIRECTORY + "/" + startup.OBSERVATION_NAME
            checks = {"absent": 0, "complete": 0}
            def check():
                if os.path.exists(path):
                    self.assertEqual(_read(path), raw); checks["complete"] += 1
                else: checks["absent"] += 1
            owner = storage.StartupAtomicPublisher.open(directory=_pin(startup.DIRECTORY), check=check)
            owner.publish(startup.OBSERVATION_NAME, raw)
            self.assertGreater(checks["absent"], 0); self.assertGreater(checks["complete"], 0)
            owner.close()
        isolated(action)

    def test_existing_input_is_not_overwritten_or_resumed(self):
        def action():
            pin = _pin(startup.DIRECTORY)
            first = storage.StartupAtomicPublisher.open(directory=pin, check=lambda: None)
            name = startup.SOURCE_FILENAMES["recipe"]
            first.publish(name, b"existing public bytes")
            second = storage.StartupAtomicPublisher.open(directory=pin, check=lambda: None)
            with self.assertRaises(ValueError): second.preflight_inputs()
            with self.assertRaises(storage.StateStoreError) as error: second.publish(name, b"replacement")
            self.assertIs(error.exception.owner, second)
            self.assertEqual(_read(startup.DIRECTORY + "/" + name), b"existing public bytes")
            second.close(); first.close()
        isolated(action)

    def test_wrong_directory_identity_and_nonfixed_public_names_refuse(self):
        def action():
            pin = _pin(startup.DIRECTORY)
            with self.assertRaises(storage.StateStoreError) as error:
                storage.StartupAtomicPublisher.open(directory=pin | {"inode": pin["inode"] + 1}, check=lambda: None)
            error.exception.owner.close()
            owner = storage.StartupAtomicPublisher.open(directory=pin, check=lambda: None)
            with self.assertRaises(storage.StateStoreError) as error: owner.publish("../outside.json", b"x")
            self.assertIs(error.exception.owner, owner)
            self.assertEqual(os.listdir(startup.DIRECTORY), [])
            owner.close()
        isolated(action)

    def test_failure_after_atomic_link_keeps_complete_file_and_closes_without_callback(self):
        def action():
            path = startup.DIRECTORY + "/" + startup.ADMISSION_NAME
            def expired():
                if os.path.exists(path): raise TimeoutError("synthetic expiry after actual link")
            owner = storage.StartupAtomicPublisher.open(directory=_pin(startup.DIRECTORY), check=expired)
            raw = b"complete synthetic public original"
            with self.assertRaises(storage.StateStoreError) as error: owner.publish(startup.ADMISSION_NAME, raw)
            self.assertIs(error.exception.owner, owner)
            self.assertEqual(_read(path), raw)
            owner.close(); owner.close()
            self.assertEqual(_read(path), raw)  # Cleanup never retracts admission.
        isolated(action)


class StartupProvisioningConnectionControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse((ROOT / "catchplate/native_pilot_startup_provisioning.py").read_text())
        owner = next(node for node in cls.tree.body if isinstance(node, ast.ClassDef) and node.name == "StartupProvisioner")
        cls.methods = {node.name: ast.unparse(node) for node in owner.body if isinstance(node, ast.FunctionDef)}

    def test_profile_decides_after_actual_observation_and_admission_is_last(self):
        run = self.methods["run"]
        self.assertLess(run.index("self._publisher.observation_original()"), run.index("profile.compose("))
        self.assertLess(run.index("profile.compose("), run.index("self._publisher.publish("))
        self.assertLess(run.index("for name in startup.SOURCE_NAMES"), run.index("startup.ADMISSION_NAME"))
        self.assertIn("min(self._prepared[name], self._result[name])", run)
        self.assertLess(run.index("self._runtime.check(installed=True)"), run.index("self.admission_sha256 ="))
        for forbidden in ("sign", "signing_key", "from_private_bytes", "unlink", "remove", "mkdir", "Popen", "fork"):
            for node in ast.walk(self.tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    self.assertNotEqual(node.func.attr, forbidden)

    def test_partial_actual_owner_retained_and_cleanup_has_no_workflow_clock(self):
        opened, checked, close = (self.methods[name] for name in ("open", "check", "close"))
        self.assertIn("_Protected(owner._sources", opened)
        self.assertIn("owner._publisher = error.owner", opened)
        self.assertIn("type(error.owner) is StartupAtomicPublisher", opened)
        self.assertIn("self._publisher._retained()", checked)
        self.assertNotIn("self._publisher.check()", checked)
        self.assertIn("self._last <= now < deadline", checked)
        self.assertIn("self._wall <= wall < expiry", checked)
        self.assertIn("not self._closing", close)
        self.assertIn("self._publisher.close()", close)
        self.assertNotIn("self.check(", close)
        self.assertNotIn("self._closing = False", close)

    def test_real_startup_observation_uses_same_atomic_owner_until_child_cleanup(self):
        tree = ast.parse((ROOT / "catchplate/native_pilot_startup.py").read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Startup")
        methods = {node.name: ast.unparse(node) for node in owner.body if isinstance(node, ast.FunctionDef)}
        published = methods["_publish"]
        self.assertIn("self._atomic = error.owner", published)
        self.assertIn("self._atomic.publish(name, raw)", published)
        self.assertNotIn("os.write", published)
        self.assertNotIn("os.O_CREAT", published)
        self.assertLess(published.index("self._atomic.publish(name, raw)"), published.index("self._read(name, len(raw))"))
        self.assertLess(methods["close"].index("self._collect("), methods["close"].index("self._atomic.close()"))


if __name__ == "__main__":
    unittest.main()
