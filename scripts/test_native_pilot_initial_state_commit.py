#!/usr/bin/env python3
"""Real registry/worker-file IO, not a fabricated completed Installation.

The actual source profile authenticates signed synthetic installation inputs.
Storage-only cases explicitly supply synthetic state rows under real original
process clocks, then use the production initializer and worker-file publisher.
No completed fifteen-file owner, installed _Runtime, worker or approval is faked.
"""
from __future__ import annotations

import ast
import codecs
import fcntl
import importlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from serverware import native_pilot_current_head_state as storage
from serverware import native_pilot_initial_state_installation as installation
from serverware import native_pilot_initial_state_profile as profile
from serverware import native_shadow_nitro_originals as originals
from scripts.test_native_pilot_initial_state_profile import fixture, prepared, runtime_fixture
from scripts.test_native_pilot_current_head_state import _isolated, _pin, _read

p, worker = profile.p, profile.worker


def _initialized(source):
    # This is independent synthetic state for filesystem controls, not a
    # retagged live signed checkpoint or proof of production currentness.
    boot, now, wall = originals._boot(), originals._clock(), time.time_ns()
    current = worker.state(source["prepared"]["stateOriginal"])
    scope = dict(zip(worker.BOOT, boot, strict=True)) | dict(issuedAtBoottimeNs=str(now),
        deadlineBoottimeNs=str(now + 8_000_000_000), issuedAtUnixNanos=wall, expiresAtUnixNanos=wall + 8_000_000_000)
    current.update(scope)
    state_raw = p.canonical(current)
    policy = p.document(source["prepared"]["workerPolicyOriginal"], worker.MAX_POLICY)
    policy.update(scope, stateDirectory=_pin(profile.STATE_DIRECTORY), decisionDirectory=_pin(worker.DECISION_DIRECTORY),
        initialStateSha256=p.sha(state_raw), supervisorInventorySha256=p.sha(source["inventory_raw"]))
    policy_raw = p.canonical(policy)
    authorization = p.canonical(dict(apiVersion=worker.UPDATE_API, directory=_pin(profile.STATE_DIRECTORY),
        expectedStateSha256=None, expectedGeneration=0, nextStateOriginal=state_raw.decode("ascii")))
    guard = {"active": True}
    def check():
        if not guard["active"]: raise ValueError("initial publication guard is no longer available")
        worker._live(current, originals._boot(), originals._clock(), time.time_ns())
    owner = storage.StateStore.open_update(authorization_raw=authorization, check=check)
    if owner.apply_update() != state_raw: raise AssertionError("initializer changed the supplied state")
    return owner, state_raw, policy_raw, guard


@unittest.skipUnless(sys.platform == "linux" and os.getresuid() == os.getresgid() == (0, 0, 0),
    "actual protected initial-state controls require root-owned files and private mount/chroot")
class InitialStateCommitControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Private storage chroots intentionally contain no Python library.
        # Load the real text codec before entering them; do not stub _boot.
        codecs.lookup("ascii")
        # StateStore lazily imports its fixed directory profile. Standalone
        # reruns must not depend on another suite having already loaded it.
        importlib.import_module("serverware.native_pilot_startup_profile")
        directory = tempfile.TemporaryDirectory(prefix="initial-state-commit-fixture-", dir=os.environ.get("TMPDIR"))
        cls.addClassCleanup(directory.cleanup)
        cls.addClassCleanup(runtime_fixture.thaw, Path(directory.name))
        source = fixture(Path(directory.name))
        cls.source = dict(prepared=prepared(source), inventory_raw=source["inventory_raw"])

    def test_actual_initializer_publishes_fixed_inventory_and_policy_with_borrowed_readonly_fds(self):
        def action(source):
            owner, state_raw, policy_raw, _ = _initialized(source)
            owner.publish_worker_inputs(source["inventory_raw"], policy_raw)
            owner.release(retain_current=True)
            received = owner.worker_inputs()
            self.assertEqual(set(received), {"supervisor_inventory_fd", "supervisor_inventory_sha256", "policy_fd", "policy_sha256"})
            self.assertNotEqual(received["supervisor_inventory_fd"], received["policy_fd"])
            for field, name, raw in (("supervisor_inventory", profile.INVENTORY_NAME, source["inventory_raw"]),
                    ("policy", profile.POLICY_NAME, policy_raw)):
                fd = received[field + "_fd"]
                self.assertEqual(os.pread(fd, len(raw) + 1, 0), raw)
                self.assertEqual(received[field + "_sha256"], p.sha(raw))
                self.assertEqual(_read(profile.STATE_DIRECTORY + "/" + name), raw)
                info = os.fstat(fd)
                self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_nlink), (0o400, 0, 0, 1))
                self.assertEqual(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
                self.assertFalse(os.get_inheritable(fd))
            self.assertEqual(_read(profile.STATE_DIRECTORY + "/current.json"), state_raw)
            self.assertEqual(set(os.listdir(profile.STATE_DIRECTORY)), {"lock", "current.json",
                "update-00000000000000000001.json", profile.INVENTORY_NAME, profile.POLICY_NAME})
            other = os.open(profile.STATE_DIRECTORY + "/lock", os.O_RDWR | os.O_CLOEXEC)
            try:
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(other, fcntl.LOCK_UN)
            finally: os.close(other)
            owner.close()
        _isolated(self.source, action)

    def test_retained_source_checks_do_not_reuse_completed_publication_guard(self):
        def action(source):
            owner, _, policy_raw, guard = _initialized(source)
            owner.publish_worker_inputs(source["inventory_raw"], policy_raw)
            owner.release(retain_current=True)
            guard["active"] = False
            owner.check_retained()
            self.assertEqual(owner.worker_inputs()["policy_sha256"], p.sha(policy_raw))
            self.assertEqual(_read(profile.STATE_DIRECTORY + "/" + profile.POLICY_NAME), policy_raw)
            owner.close(); owner.close()
        _isolated(self.source, action)

    def test_wrong_inventory_pin_refuses_without_worker_files_and_keeps_initialized_state(self):
        def action(source):
            owner, state_raw, policy_raw, _ = _initialized(source)
            wrong = p.document(policy_raw, worker.MAX_POLICY)
            wrong["supervisorInventorySha256"] = p.sha(b"different public inventory")
            with self.assertRaises(storage.StateStoreError) as error:
                owner.publish_worker_inputs(source["inventory_raw"], p.canonical(wrong))
            self.assertIs(error.exception.owner, owner)
            self.assertEqual(_read(profile.STATE_DIRECTORY + "/current.json"), state_raw)
            self.assertFalse(os.path.exists(profile.STATE_DIRECTORY + "/" + profile.INVENTORY_NAME))
            self.assertFalse(os.path.exists(profile.STATE_DIRECTORY + "/" + profile.POLICY_NAME))
            owner.close()
        _isolated(self.source, action)

    def test_existing_policy_refuses_before_inventory_and_never_overwrites(self):
        def action(source):
            owner, _, policy_raw, _ = _initialized(source)
            path = profile.STATE_DIRECTORY + "/" + profile.POLICY_NAME
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o400)
            try: os.write(fd, b"existing-public-policy")
            finally: os.close(fd)
            with self.assertRaises(storage.StateStoreError): owner.publish_worker_inputs(source["inventory_raw"], policy_raw)
            self.assertEqual(_read(path), b"existing-public-policy")
            self.assertFalse(os.path.exists(profile.STATE_DIRECTORY + "/" + profile.INVENTORY_NAME))
            owner.close()
        _isolated(self.source, action)

    def test_completed_worker_publication_cannot_repeat(self):
        def action(source):
            owner, _, policy_raw, _ = _initialized(source)
            owner.publish_worker_inputs(source["inventory_raw"], policy_raw)
            with self.assertRaises(storage.StateStoreError): owner.publish_worker_inputs(source["inventory_raw"], policy_raw)
            self.assertEqual(_read(profile.STATE_DIRECTORY + "/" + profile.POLICY_NAME), policy_raw)
            owner.close()
        _isolated(self.source, action)

    def test_installation_result_dictionary_is_not_a_completed_file_owner(self):
        def action(_source):
            with self.assertRaises(installation.InitialStateInstallationError) as error:
                installation.InitialStateInstallation.install(installation={"apiVersion": installation.ordinary.RESULT_API},
                    input_original=b"{}", expected_sha256=p.sha(b"{}"), check=lambda: None)
            self.assertIs(type(error.exception.owner), installation.InitialStateInstallation)
            error.exception.owner.close()
            self.assertEqual(os.listdir(profile.STATE_DIRECTORY), [])
        _isolated(self.source, action)

    def test_factory_source_binds_actual_fifteen_file_result_and_retained_checks_have_no_clock_callback(self):
        tree = ast.parse((ROOT / "serverware/native_pilot_initial_state_installation.py").read_text())
        selected = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "InitialStateInstallation")
        methods = {node.name: ast.unparse(node) for node in selected.body if isinstance(node, ast.FunctionDef)}
        source = methods["install"]
        self.assertIn("type(installation) is ordinary.Installation", source)
        self.assertIn("installation.result()", source)
        self.assertIn("ordinary.INITIAL_STATE_API", source)
        self.assertIn("actual['inputSha256'] == expected_sha256", source)
        self.assertIn("len(expected) == 15", source)
        self.assertIn("actual['pins'] == expected", source)
        self.assertLess(source.index("installation.result()"), source.index("state.StateStore.open_update"))
        self.assertLess(source.index("apply_update()"), source.index("publish_worker_inputs"))
        self.assertNotIn("_outer", methods["check_retained"])
        self.assertNotIn("_clock", methods["check_retained"])
        self.assertNotIn("_installation.close", methods["close"])
        self.assertIn("self._store._files[state.profile.STATE_NAME][2]", methods["result"])
        self.assertIn("self.worker_inputs()", methods["result"])
        self.assertIn("value['generation'] == 1", methods["result"])


if __name__ == "__main__": unittest.main()
