#!/usr/bin/env python3
"""Actual Linux storage controls in one bounded disposable child per case.

Signed-source fixtures supply synthetic state/pairs, not production authority.
These tests exercise the exact production filesystem/lock backend, never fake
installed _Runtime admission or a complete decision worker. No native process,
checkpoint key, independent freshness or completed pilot is claimed.
"""
from __future__ import annotations

import copy
import fcntl
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
from serverware import native_pilot_current_head_state as storage
from scripts.test_native_pilot_current_head_worker_profile import fixture, composed

profile, p = storage.profile, storage.p


def _pin(path):
    info = os.stat(path, follow_symlinks=False)
    return dict(device=info.st_dev, inode=info.st_ino)


def _authorization(source, after=None, *, initialize=False):
    return p.canonical(dict(apiVersion=profile.UPDATE_API, directory=_pin(profile.STATE_DIRECTORY),
        expectedStateSha256=None if initialize else p.sha(source["state_raw"]),
        expectedGeneration=0 if initialize else source["state"]["generation"],
        nextStateOriginal=p.canonical(source["state"] if after is None else after).decode("ascii")))


def _initialize(source):
    owner = storage.StateStore.open_update(authorization_raw=_authorization(source, initialize=True), check=lambda: None)
    owner.apply_update(); owner.release(); owner.close()


def _read(path):
    with open(path, "rb") as stream: return stream.read()


def _isolated(source, action):
    with tempfile.TemporaryDirectory(prefix="current-head-state-", dir=os.environ.get("TMPDIR")) as directory:
        root = Path(directory)
        for path in (profile.STATE_DIRECTORY, profile.DECISION_DIRECTORY):
            (root / path.lstrip("/")).mkdir(parents=True, mode=0o700)
            os.chmod(root / path.lstrip("/"), 0o700)
        reader, writer = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        if child == 0:
            os.close(reader); signal.alarm(12)
            status = 1
            try:
                os.chroot(root); os.chdir("/")
                action(copy.deepcopy(source))
                os.write(writer, b"ok"); status = 0
            except BaseException:
                os.write(writer, traceback.format_exc().encode("utf-8")[-4096:])
            os.close(writer); os._exit(status)
        os.close(writer)
        pidfd = os.pidfd_open(child, 0)
        try:
            if not select.select([pidfd], [], [], 15)[0]:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
                if not select.select([pidfd], [], [], 3)[0]:
                    raise AssertionError("actual storage test child did not retire")
            result = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
            report = os.read(reader, 8192)
            if result.si_pid != child or result.si_code != os.CLD_EXITED or result.si_status != 0 or report != b"ok":
                raise AssertionError("actual isolated storage control failed: " + repr(report))
        finally:
            os.close(pidfd); os.close(reader)


@unittest.skipUnless(sys.platform == "linux" and os.getresuid() == os.getresgid() == (0, 0, 0),
    "actual protected state controls require root-owned test files and chroot")
class CurrentHeadStateControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = fixture()
        cls.source["decision"] = composed(cls.source)

    def test_explicit_initialization_is_atomic_durable_and_not_repeatable(self):
        def action(source):
            _initialize(source)
            self.assertEqual(_read(profile.STATE_DIRECTORY + "/current.json"), source["state_raw"])
            self.assertEqual(set(os.listdir(profile.STATE_DIRECTORY)),
                {"lock", "current.json", "update-00000000000000000001.json"})
            self.assertEqual(stat.S_IMODE(os.stat(profile.STATE_DIRECTORY + "/lock").st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(profile.STATE_DIRECTORY + "/current.json").st_mode), 0o400)
            with self.assertRaises(storage.StateStoreError) as error:
                storage.StateStore.open_update(authorization_raw=_authorization(source, initialize=True), check=lambda: None)
            error.exception.owner.close()
        _isolated(self.source, action)

    def test_actual_compare_and_swap_revokes_and_preserves_update_audit(self):
        def action(source):
            _initialize(source)
            after = copy.deepcopy(source["state"]); after["generation"] = 2
            after["targets"][profile.JOB_NAMES[0]]["status"] = "revoked"
            owner = storage.StateStore.open_update(authorization_raw=_authorization(source, after), check=lambda: None)
            self.assertEqual(owner.apply_update(), p.canonical(after)); owner.release(); owner.close()
            self.assertEqual(_read(profile.STATE_DIRECTORY + "/current.json"), p.canonical(after))
            self.assertTrue(os.path.isfile(profile.STATE_DIRECTORY + "/update-00000000000000000002.json"))
            self.assertFalse(any(name.endswith(".pending") for name in os.listdir(profile.STATE_DIRECTORY)))
            stale = storage.StateStore.open_update(authorization_raw=_authorization(source, after), check=lambda: None)
            with self.assertRaises(storage.StateStoreError): stale.apply_update()
            stale.close()
            self.assertEqual(_read(profile.STATE_DIRECTORY + "/current.json"), p.canonical(after))
        _isolated(self.source, action)

    def test_real_shared_lock_excludes_writer_until_release(self):
        def action(source):
            _initialize(source)
            owner = storage.StateStore.open(directory=_pin(profile.STATE_DIRECTORY), check=lambda: None)
            self.assertEqual(owner.acquire_shared(), source["state_raw"])
            other = os.open(profile.STATE_DIRECTORY + "/lock", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                with self.assertRaises(BlockingIOError): fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                owner.release()
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(other, fcntl.LOCK_UN)
            finally: os.close(other); owner.close()
        _isolated(self.source, action)

    def test_real_receipt_and_complete_pair_use_exact_readonly_final_files(self):
        def action(source):
            _initialize(source)
            decision, job = source["decision"], profile.JOB_NAMES[0]
            owner = storage.StateStore.open(directory=_pin(profile.STATE_DIRECTORY), check=lambda: None)
            owner.acquire_shared(); owner.consume(job, decision["receiptOriginal"])
            owner.publish_pair(job, decision["inputOriginal"], decision["approvalOriginal"],
                directory=_pin(profile.DECISION_DIRECTORY))
            owner.release(); owner.close()
            names = profile.delivery.filenames(job)
            self.assertEqual(set(os.listdir(profile.DECISION_DIRECTORY)), {names["input"], names["approval"]})
            for suffix, raw in (("input", decision["inputOriginal"]), ("approval", decision["approvalOriginal"])):
                path = profile.DECISION_DIRECTORY + "/" + names[suffix]
                self.assertEqual(_read(path), raw)
                info = os.stat(path, follow_symlinks=False)
                self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink, info.st_uid, info.st_gid), (0o400, 1, 0, 0))
            self.assertEqual(_read(profile.STATE_DIRECTORY + "/" + job + ".receipt.json"), decision["receiptOriginal"])
        _isolated(self.source, action)

    def test_consumed_request_is_never_retried_after_pair_refusal(self):
        def action(source):
            _initialize(source)
            decision, job = source["decision"], profile.JOB_NAMES[0]
            names = profile.delivery.filenames(job)
            publisher = storage.AtomicPublisher.open(directory=_pin(profile.DECISION_DIRECTORY), check=lambda: None)
            publisher.publish(names["approval"], b"existing independently supplied original"); publisher.close()
            owner = storage.StateStore.open(directory=_pin(profile.STATE_DIRECTORY), check=lambda: None)
            owner.acquire_shared(); owner.consume(job, decision["receiptOriginal"])
            with self.assertRaises(storage.StateStoreError):
                owner.publish_pair(job, decision["inputOriginal"], decision["approvalOriginal"],
                    directory=_pin(profile.DECISION_DIRECTORY))
            owner.close()
            self.assertFalse(os.path.exists(profile.DECISION_DIRECTORY + "/" + names["input"]))
            later = storage.StateStore.open(directory=_pin(profile.STATE_DIRECTORY), check=lambda: None)
            later.acquire_shared()
            with self.assertRaises(storage.StateStoreError): later.consume(job, decision["receiptOriginal"])
            later.close()
        _isolated(self.source, action)

    def test_atomic_publication_rejects_overwrite_and_keeps_real_partial_owner(self):
        def action(_source):
            owner = storage.AtomicPublisher.open(directory=_pin(profile.DECISION_DIRECTORY), check=lambda: None)
            name = profile.delivery.filenames(profile.JOB_NAMES[0])["request"]
            owner.publish(name, b"literal-first-original")
            with self.assertRaises(storage.StateStoreError) as error: owner.publish(name, b"replacement")
            self.assertIs(error.exception.owner, owner)
            self.assertEqual(_read(profile.DECISION_DIRECTORY + "/" + name), b"literal-first-original")
            owner.close(); owner.close()
        _isolated(self.source, action)

    def test_real_clock_callback_refusal_does_not_prevent_descriptor_cleanup(self):
        def action(_source):
            expired = [False]
            def check():
                if expired[0]: raise ValueError("test caller original deadline expired")
            owner = storage.AtomicPublisher.open(directory=_pin(profile.DECISION_DIRECTORY), check=check)
            expired[0] = True
            with self.assertRaises(storage.StateStoreError):
                owner.publish(profile.delivery.filenames(profile.JOB_NAMES[0])["evidence"], b"no renewed publication")
            owner.close()
            self.assertEqual(os.listdir(profile.DECISION_DIRECTORY), [])
        _isolated(self.source, action)

    def test_uncooperative_named_state_replacement_is_detected(self):
        def action(source):
            _initialize(source)
            owner = storage.StateStore.open(directory=_pin(profile.STATE_DIRECTORY), check=lambda: None)
            owner.acquire_shared()
            path = profile.STATE_DIRECTORY + "/current.json"
            os.rename(path, path + ".external-change")
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o400)
            try: os.write(descriptor, source["state_raw"])
            finally: os.close(descriptor)
            with self.assertRaises(ValueError): owner.check()
            owner.close()
        _isolated(self.source, action)


if __name__ == "__main__": unittest.main()
