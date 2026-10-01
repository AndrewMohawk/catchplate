#!/usr/bin/env python3
"""Real protected-file/fresh-directory controls inside a bounded child chroot.

The plan fixture supplies synthetic signed public associations, not native
adoption success or actual cold-core custody. No executor/process owner is
fabricated. These controls exercise the real publisher, reader, directory and
empty-store installer only; they do not commission or run an application.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import select
import signal
import stat
import sys
import tempfile
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from serverware import native_pilot_adopted_endpoint_publication as runtime
from serverware import native_pilot_genesis_core_profile as core
from test_native_pilot_adopted_endpoint_plan import fixture

p = runtime.p


def _write(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o400)
    try:
        os.fchmod(descriptor, 0o400)
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor, raw[offset:])
            if count <= 0: raise RuntimeError("short test-original write")
            offset += count
    finally:
        os.close(descriptor)


def _provision(root, case):
    """Test-only provisioning; the production helper never creates a directory."""
    destinations = [runtime.public_inputs.INPUT_ROOT, case["value"]["objectDirectory"]]
    for path in destinations:
        (root / path.lstrip("/")).mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(root / case["value"]["objectDirectory"].lstrip("/"), 0o700)
    bootstrap = runtime.profile._input(case["prior"], "install-precreation")["nativeColdOriginals"]
    for role, pin in case["value"]["coldOriginals"].items():
        path = root / pin["path"].lstrip("/")
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        _write(path, bootstrap[role].encode("ascii"))
    pin = case["value"]["adoptionAuthorization"]
    path = root / pin["path"].lstrip("/")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    _write(path, runtime.profile._output(case["prior"], "publication-adoption"))


def _isolated(case, action):
    """One actual forked child, PIDFD wait and consuming reap; never an owner DTO."""
    # Load every selected validator before entering an intentionally empty
    # filesystem. These controls are not tests of imports inside a chroot.
    runtime.plan.prepare(case["value"], prior=case["prior"], observations=case["observations"])
    with tempfile.TemporaryDirectory(prefix="epub-", dir=os.environ.get("TMPDIR")) as directory:
        root = Path(directory)
        _provision(root, case)
        reader, writer = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        if child == 0:
            os.close(reader)
            signal.alarm(12)
            status = 1
            try:
                os.chroot(root); os.chdir("/")
                action(copy.deepcopy(case))
                os.write(writer, b"ok")
                status = 0
            except BaseException:
                os.write(writer, traceback.format_exc().encode("utf-8")[-4096:])
            os.close(writer)
            os._exit(status)
        os.close(writer)
        pidfd = os.pidfd_open(child, 0)
        try:
            if not select.select([pidfd], [], [], 15)[0]:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
                if not select.select([pidfd], [], [], 3)[0]:
                    raise RuntimeError("actual publication test child did not retire")
            outcome = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
            report = os.read(reader, 8192)
            if outcome.si_pid != child or outcome.si_code != os.CLD_EXITED or outcome.si_status != 0 or report != b"ok":
                raise AssertionError("actual isolated publication failed: " + repr(report))
        finally:
            os.close(pidfd); os.close(reader)


def _owners():
    publisher = runtime.publication.PublicPublisher.open()
    public = runtime.public_inputs.PublicInputs.open()
    owner = runtime._Publication(publisher, public)

    def check():
        owner.check(); publisher.check(); public.check()

    return owner, publisher, public, check


def _publish(owner, case, check):
    owner.publish(case["value"], prior=case["prior"], observations=case["observations"], check=check)


@unittest.skipUnless(sys.platform == "linux" and os.getresuid() == (0, 0, 0)
    and os.getresgid() == (0, 0, 0), "real protected publication controls require root-owned test originals")
class AdoptedEndpointPublicationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.case = fixture()

    def isolated(self, action): _isolated(self.case, action)

    def test_real_publication_readback_and_empty_store_persist_after_descriptor_close(self):
        def action(case):
            owner, publisher, public, check = _owners()
            _publish(owner, case, check)
            planned = runtime.plan.prepare(case["value"], prior=case["prior"], observations=case["observations"])
            for purpose, raw in planned:
                pin = {"path": runtime.publication.DESTINATIONS[purpose], "sha256": p.sha(raw)}
                self.assertEqual(public.read(pin, maximum=runtime.publication.LIMITS[purpose]), raw)
                info = os.stat(pin["path"], follow_symlinks=False)
                self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_nlink), (0o400, 0, 0, 1))
            installed = p.document(owner.installation, 32768)
            self.assertFalse(installed["releaseAuthority"]); self.assertFalse(installed["serviceReady"])
            self.assertEqual(installed["objects"], [])
            self.assertEqual(installed["initialization"], "fresh-ledger")
            self.assertEqual(os.listdir(case["value"]["objectDirectory"]), [])
            self.assertEqual(stat.S_IMODE(os.stat(case["value"]["objectDirectory"]).st_mode), 0o555)
            owner.close(); owner.close(); public.close(); publisher.close()
            self.assertEqual(stat.S_IMODE(os.stat(case["value"]["objectDirectory"]).st_mode), 0o555)
            self.assertTrue(all(os.path.isfile(runtime.publication.DESTINATIONS[purpose]) for purpose, _ in planned))
        self.isolated(action)

    def test_all_destinations_preflight_before_freezing_or_any_publication(self):
        def action(case):
            owner, publisher, public, check = _owners()
            last = runtime.publication.DESTINATIONS[runtime.plan.PURPOSES[-1]]
            _write(last, b"independently existing file")
            with self.assertRaises(ValueError): _publish(owner, case, check)
            self.assertIsNone(owner.directory)
            self.assertEqual(stat.S_IMODE(os.stat(case["value"]["objectDirectory"]).st_mode), 0o700)
            self.assertTrue(all(not os.path.exists(runtime.publication.DESTINATIONS[purpose])
                for purpose in runtime.plan.PURPOSES[:-1]))
            self.assertEqual(Path(last).read_bytes(), b"independently existing file")
            owner.close(); public.close(); publisher.close()
        self.isolated(action)

    def test_missing_prerequisite_never_freezes_and_conservatively_fences_hidden_cleanup(self):
        def action(case):
            owner, publisher, public, check = _owners()
            os.unlink(next(iter(case["value"]["coldOriginals"].values()))["path"])
            with self.assertRaises(FileNotFoundError): _publish(owner, case, check)
            self.assertTrue(owner.failed and owner.uncertain)
            self.assertIsNone(owner.directory)
            self.assertEqual(stat.S_IMODE(os.stat(case["value"]["objectDirectory"]).st_mode), 0o700)
            with self.assertRaises(ValueError): owner.close()
            with self.assertRaises(ValueError): _publish(owner, case, check)
            # Child exit closes its test FDs; this is deliberately NOT reported
            # as the production helper having established known cleanup.
        self.isolated(action)

    def test_nonempty_store_is_not_adopted_repaired_or_frozen(self):
        def action(case):
            owner, publisher, public, check = _owners()
            entry = Path(case["value"]["objectDirectory"]) / "unexpected"
            _write(entry, b"preserved")
            with self.assertRaises(ValueError): _publish(owner, case, check)
            self.assertIsNotNone(owner.directory)
            self.assertFalse(owner.uncertain)
            self.assertEqual(entry.read_bytes(), b"preserved")
            self.assertEqual(stat.S_IMODE(entry.parent.stat().st_mode), 0o700)
            owner.close(); public.close(); publisher.close()
        self.isolated(action)

    def test_actual_target_identity_cannot_alias_observed_cold_directory(self):
        def action(case):
            owner, publisher, public, check = _owners()
            info = os.stat(case["value"]["objectDirectory"])
            observed = core.g.document(case["observations"]["endpoint-inputs"]["adoptedCore"]["observationOriginal"].encode("ascii"),
                core.MAX_OBSERVATION)
            # Synthetic public observation names this actual target inode. No
            # cold-core capability is constructed, opened, copied or claimed.
            observed["directory"].update(device=info.st_dev, inode=info.st_ino)
            observed["file"]["device"] = info.st_dev
            case["observations"]["endpoint-inputs"]["adoptedCore"]["observationOriginal"] = core.g.canonical(observed).decode("ascii")
            with self.assertRaises(ValueError): _publish(owner, case, check)
            self.assertEqual(owner.directory.identity[:2], (info.st_dev, info.st_ino))
            self.assertEqual(stat.S_IMODE(os.stat(case["value"]["objectDirectory"]).st_mode), 0o700)
            owner.close(); public.close(); publisher.close()
        self.isolated(action)

    def test_retained_directory_and_published_original_mutation_are_detected(self):
        def action(case):
            owner, publisher, public, check = _owners()
            _publish(owner, case, check)
            os.chmod(case["value"]["objectDirectory"], 0o700)
            with self.assertRaises(ValueError): owner.check()
            original = runtime.publication.DESTINATIONS[runtime.plan.PURPOSES[0]]
            os.chmod(original, 0o600)
            with self.assertRaises(ValueError): publisher.check()
            with self.assertRaises(ValueError): public.check()
            owner.close(); public.close(); publisher.close()
        self.isolated(action)

    def test_post_preflight_race_preserves_file_and_frozen_directory_without_retry(self):
        def action(case):
            owner, publisher, public, retained_check = _owners()
            target = runtime.publication.DESTINATIONS[runtime.plan.PURPOSES[0]]
            raced = False

            def check():
                nonlocal raced
                retained_check()
                if owner.mode == 0o555 and not raced:
                    _write(target, b"concurrent protected original")
                    raced = True

            with self.assertRaises(FileExistsError): _publish(owner, case, check)
            self.assertTrue(raced and owner.uncertain and owner.failed)
            self.assertEqual(Path(target).read_bytes(), b"concurrent protected original")
            self.assertEqual(stat.S_IMODE(os.stat(case["value"]["objectDirectory"]).st_mode), 0o555)
            with self.assertRaises(ValueError): owner.close()
            with self.assertRaises(ValueError): _publish(owner, case, check)
        self.isolated(action)

    def test_failed_close_is_sticky_and_never_relabels_retirement_on_retry(self):
        def action(case):
            owner, publisher, public, check = _owners()
            _publish(owner, case, check)
            descriptor = owner.directory.fds[-1]
            os.close(descriptor)  # Actual invalidation, not a mocked close result.
            with self.assertRaises(OSError): owner.close()
            self.assertTrue(owner.close_attempted)
            self.assertFalse(owner.closed)
            self.assertNotIn(descriptor, owner.directory.fds)
            with self.assertRaises(ValueError): owner.close()
        self.isolated(action)


if __name__ == "__main__": unittest.main()
