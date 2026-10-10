#!/usr/bin/env python3
"""Adversarial Linux flock schedule, not actual Rust/HTTP or live-starvation proof.

Two pipe-controlled child processes independently open the actual publication
inode. The writer uses unchanged operator_publication.exclusive(), including
its real five-second budget. No provider, native operation or SQL mutation runs.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

import test_operator_demo_persistence as common

SCRIPT = Path(__file__).resolve()
WAIT = 2.0
MAX_HANDOVERS = 1024
HOLD_BUDGET = 3.0


def no_network(event, _arguments):
    if event in {"socket.bind", "socket.connect", "socket.getaddrinfo"}:
        raise AssertionError("contention fixture attempted network contact")


class HolderFailure(Exception):
    pass


def holder(path):
    signal.alarm(20)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    started = None

    def emit(value):
        print(json.dumps(value, separators=(",", ":")), flush=True)

    try:
        info = os.fstat(descriptor)
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_uid == os.geteuid() and info.st_size == 0 and info.st_nlink == 1
        emit({"event": "opened", "device": info.st_dev, "inode": info.st_ino})
        for _ in range(2 * MAX_HANDOVERS + 16):
            assert select.select([sys.stdin], [], [], 10)[0], "holder command deadline"
            command = sys.stdin.readline(32).strip()
            if command == "acquire":
                assert started is None, "one open description per lane"
                before = time.monotonic()
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
                except BlockingIOError:
                    emit({"event": "busy"})
                else:
                    started = before
                    emit({"event": "held"})
            elif command == "release":
                assert started is not None
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                elapsed = time.monotonic() - started
                started = None
                emit({"event": "released", "hold_seconds": elapsed})
            elif command == "error":
                assert started is not None
                raise HolderFailure()
            elif command == "exit":
                assert started is not None
                os._exit(74)  # Deliberately bypass finally; kernel closes this OFD.
            elif command == "close":
                return
            else:
                raise AssertionError("unknown holder command")
        raise AssertionError("holder command count exceeded")
    finally:
        os.close(descriptor)


class Reader:
    def __init__(self, path, identity):
        self.process = subprocess.Popen([sys.executable, "-B", str(SCRIPT), "--holder", str(path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            close_fds=True)
        try:
            assert self.receive() == {"event": "opened", "device": identity[0], "inode": identity[1]}
        except BaseException:
            self.cleanup()
            raise

    def receive(self):
        assert select.select([self.process.stdout], [], [], WAIT)[0], "holder reply deadline"
        line = self.process.stdout.readline(1025)
        assert line.endswith("\n") and len(line) <= 1024
        return json.loads(line)

    def send(self, command):
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()

    def acquire(self, expected="held"):
        self.send("acquire")
        assert self.receive() == {"event": expected}

    def release(self):
        self.send("release")
        result = self.receive()
        assert set(result) == {"event", "hold_seconds"} and result["event"] == "released"
        assert isinstance(result["hold_seconds"], float) and 0 <= result["hold_seconds"] < HOLD_BUDGET

    def fail(self, command, code):
        self.send(command)
        assert self.process.wait(timeout=WAIT) == code

    def cleanup(self):
        try:
            if self.process.poll() is None:
                try:
                    self.send("close")
                    self.process.wait(timeout=WAIT)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    self.process.kill()
                    self.process.wait(timeout=WAIT)
        finally:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()


class Writer:
    def __init__(self, publication, identity):
        self.publication, self.identity = publication, identity
        self.condition = threading.Condition()
        self.entered, self.release, self.done = threading.Event(), threading.Event(), threading.Event()
        self.blocked, self.error, self.clean, self.elapsed = 0, None, False, None
        self.thread_id = None
        self.original_flock = fcntl.flock
        self.thread = threading.Thread(target=self.run)

    def flock(self, descriptor, flags):
        try:
            return self.original_flock(descriptor, flags)
        except BlockingIOError:
            if threading.get_ident() == self.thread_id and flags == fcntl.LOCK_EX | fcntl.LOCK_NB:
                info = os.fstat(descriptor)
                assert (info.st_dev, info.st_ino) == self.identity
                with self.condition:
                    self.blocked += 1
                    self.condition.notify_all()
            raise

    def run(self):
        self.thread_id = threading.get_ident()
        started = time.monotonic()
        try:
            with self.publication.exclusive():
                self.publication.assert_held()
                self.entered.set()
                assert self.release.wait(WAIT), "writer release deadline"
        except BaseException as error:
            self.error = error
        finally:
            self.elapsed = time.monotonic() - started
            self.clean = (getattr(self.publication._state, "depth", 0) == 0
                and getattr(self.publication._state, "deadline", None) is None)
            with self.condition:
                self.done.set()
                self.condition.notify_all()

    def next_failure(self, previous=0):
        with self.condition:
            assert self.condition.wait_for(lambda: self.blocked > previous or self.done.is_set(), WAIT), \
                "writer failed-flock barrier deadline"
            return self.blocked


@contextmanager
def scenario():
    # Actual development admission and first lock provisioning only. Importing
    # the backend with initialize=False does not create/initialize SQLite.
    config, _db, store, _bundles = common.backend(initialize=False)
    publication = store.operator_publication
    assert publication.ACQUISITION_SECONDS == 5.0
    with publication.exclusive(startup=True):
        publication.assert_held()
    assert not config.DB_PATH.exists()
    path = config.DATA_DIR / publication.LOCK_NAME
    before = publication._file_identity(path.stat())
    readers, writer = [], None
    try:
        readers = [Reader(path, before[:2])]
        readers.append(Reader(path, before[:2]))
        writer = Writer(publication, before[:2])
        with patch.object(publication.fcntl, "flock", writer.flock):
            try:
                yield publication, readers, writer
            finally:
                # Release every SH description before waiting for a failed test's
                # writer. Never leave a child or local lock behind on assertion.
                writer.release.set()
                for reader in readers:
                    reader.cleanup()
                readers.clear()
                if writer.thread.ident is not None:
                    writer.thread.join(publication.ACQUISITION_SECONDS + WAIT)
                    assert not writer.thread.is_alive(), "bounded writer cleanup"
    finally:
        for reader in readers:
            reader.cleanup()
    assert publication._file_identity(path.stat()) == before
    assert not config.DB_PATH.exists()
    publication.assert_not_held()
    assert publication.LOCAL_LOCK.acquire(blocking=False), "writer leaked local ownership"
    publication.LOCAL_LOCK.release()


def handover():
    with scenario() as (_publication, readers, writer):
        first, second = readers
        first.acquire()
        writer.thread.start()
        count = writer.next_failure()
        assert count >= 1 and not writer.entered.is_set()
        for _ in range(3):
            second.acquire()  # Late reader succeeds despite observed waiting EX.
            first.release()  # Acquire-before-release preserves continuous overlap.
            first, second = second, first
            count = writer.next_failure(count)
            assert not writer.entered.is_set()
        first.release()
        assert writer.entered.wait(WAIT), "writer did not enter after all SH releases"
        for reader in readers:
            reader.acquire("busy")
        writer.release.set()
        assert writer.done.wait(WAIT) and writer.error is None and writer.clean
        for reader in readers:
            reader.acquire()
            reader.release()
    return {"trace": ["writer_blocked", "late_readers_admitted", "all_readers_released",
        "writer_entered", "writer_excluded_readers", "ownership_released"], "handovers": 3}


def timeout():
    with scenario() as (publication, readers, writer):
        first, second = readers
        first.acquire()
        writer.thread.start()
        count = writer.next_failure()
        handovers = 0
        for _ in range(MAX_HANDOVERS):
            assert not writer.entered.is_set()
            second.acquire()
            first.release()
            first, second = second, first
            handovers += 1
            count = writer.next_failure(count)
            if writer.done.is_set():
                break
        else:
            raise AssertionError("bounded reader handover count exhausted")
        assert handovers >= 3 and not writer.entered.is_set()
        assert type(writer.error) is publication.PublicationError
        assert str(writer.error) == "operator publication ownership timed out"
        assert writer.elapsed >= publication.ACQUISITION_SECONDS == 5.0
        assert writer.clean
        first.release()
        writer.thread.join(WAIT)
        assert not writer.thread.is_alive()
        # A NEW independent operation, not a retry/rearm of the timed-out one.
        with publication.exclusive():
            publication.assert_held()
            for reader in readers:
                reader.acquire("busy")
        assert writer.done.is_set() and not writer.entered.is_set()
    return {"trace": ["continuous_reader_overlap", "original_five_second_timeout",
        "readers_released", "independent_new_writer_entered"], "handovers": handovers}


def exit_cleanup():
    with scenario() as (_publication, readers, writer):
        first, second = readers
        first.acquire()
        second.acquire()
        writer.thread.start()
        count = writer.next_failure()
        first.fail("error", 73)  # finally closes this independent description.
        writer.next_failure(count)
        assert not writer.entered.is_set()
        second.fail("exit", 74)  # No finally: kernel process-exit cleanup.
        assert writer.entered.wait(WAIT)
        writer.release.set()
        assert writer.done.wait(WAIT) and writer.error is None and writer.clean
    return {"trace": ["writer_blocked", "reader_error_closed", "other_reader_still_held",
        "reader_process_exit_closed", "writer_entered"], "exited_holders": 2}


class OperatorPublicationContentionTests(unittest.TestCase):
    setUp = common.OperatorDemoPersistenceTests.setUp

    def run_worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--worker", operation],
            cwd=common.ROOT, env=self.environment, capture_output=True, text=True, timeout=25)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-35:]))
        return json.loads(result.stdout)

    def test_waiting_writer_allows_late_shared_handover_then_enters(self):
        self.assertEqual(self.run_worker("handover")["handovers"], 3)

    def test_short_overlapping_readers_exhaust_original_writer_budget_without_rearm(self):
        self.assertGreaterEqual(self.run_worker("timeout")["handovers"], 3)

    def test_reader_error_and_process_exit_release_independent_descriptions(self):
        self.assertEqual(self.run_worker("exit")["exited_holders"], 2)


if __name__ == "__main__":
    os.umask(0o077)
    if len(sys.argv) == 3 and sys.argv[1] in {"--holder", "--worker"}:
        sys.addaudithook(no_network)
        if sys.argv[1] == "--holder":
            try:
                holder(sys.argv[2])
            except HolderFailure:
                sys.exit(73)
        else:
            operation = {"handover": handover, "timeout": timeout, "exit": exit_cleanup}[sys.argv[2]]
            print(json.dumps(operation(), sort_keys=True))
    else:
        unittest.main(verbosity=2)
