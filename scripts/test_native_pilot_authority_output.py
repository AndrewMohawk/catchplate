"""Real bounded pipe output under private user namespaces; no signing owner."""
from __future__ import annotations

import os
from pathlib import Path
import select
import signal
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.authority import native_pilot_authority_io as io


class AuthorityOutputControls(unittest.TestCase):
    def run_child(self, reject):
        # Harness runs isolated Python as namespace-root, not host-root. Only
        # anonymous pipes and an ordinary child are created by these controls.
        self.assertEqual(os.getresuid(), (0, 0, 0))
        read, write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        pidfd, reaped = None, False
        raw = b"public-output-control" * 8192
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read)
                os.dup2(write, 1); os.close(write)
                calls = 0

                def check():
                    nonlocal calls
                    calls += 1
                    if reject is not None and calls >= reject:
                        raise ValueError("deterministic retained guard refusal")

                try:
                    io.write_public(raw, deadline_boottime_ns=io._clock() + 900_000_000, check=check)
                except ValueError:
                    os._exit(7)
                os._exit(0 if calls >= 3 else 9)
            except BaseException:
                os._exit(10)
        os.close(write)
        try:
            pidfd = os.pidfd_open(pid, 0)
            deadline, received, eof = time.monotonic() + 2, bytearray(), False
            observed = None
            while time.monotonic() < deadline:
                try:
                    part = os.read(read, 65536)
                    if part: received.extend(part)
                    else: eof = True
                except BlockingIOError:
                    pass
                observed = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                if eof and observed is not None:
                    break
                select.select([read, pidfd], [], [], 0.001)
            self.assertTrue(eof)
            self.assertIsNotNone(observed)
            actual = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
            reaped = actual is not None
            self.assertEqual((actual.si_pid, actual.si_code), (pid, os.CLD_EXITED))
            return raw, bytes(received), actual.si_status
        finally:
            if not reaped:
                if pidfd is not None:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
                    os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
                else:
                    os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
            if pidfd is not None: os.close(pidfd)
            os.close(read)

    def test_actual_guarded_pipe_completes_exact_original(self):
        raw, received, status = self.run_child(None)
        self.assertEqual(status, 0)
        self.assertEqual(received, raw)

    def test_guard_before_first_write_releases_no_bytes(self):
        _, received, status = self.run_child(1)
        self.assertEqual((received, status), (b"", 7))

    def test_guard_between_chunks_refuses_remaining_bytes(self):
        raw, received, status = self.run_child(3)
        self.assertEqual(status, 7)
        self.assertGreater(len(received), 0)
        self.assertLess(len(received), len(raw))
        self.assertTrue(raw.startswith(received))


if __name__ == "__main__":
    unittest.main()
