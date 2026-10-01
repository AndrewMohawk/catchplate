"""Synthetic wire controls and one real rootless packet/PIDFD/reap primitive.

The fork control runs no service/helper or C9 owner and never fabricates a
native terminal notice. It proves only the actual kernel sender/reap seam.
"""
import copy
import os
from pathlib import Path
import select
import signal
import socket
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_ordinary_control_process as process
from serverware import native_pilot_genesis_ordinary_retirement as r
from serverware import native_pilot_genesis_parent_control_io as io

p = g.p


def fixture(result="ok"):
    stop = r.stop_original(delivery_sha256=p.sha(b"synthetic C9"), role=r.ROLES[0], invocation="a" * 32, deadline=3000)
    value = dict(g.document(stop, r.MAX_BYTES), apiVersion=r.TERMINAL_API, stopSha256=p.sha(stop),
        helper=dict(pid=102, startTimeTicks=(1 << 63) + 7, exitCode=os.CLD_EXITED,
            exitStatus=0, reapedAtBoottimeNs="2000"), serviceResult=result,
        serviceExitStatus=0 if result == "ok" else 1)
    kwargs = dict(stop_raw=stop, stop_sent_at=1000, now=2500, service_pid=101)
    return value, kwargs


class Controls(unittest.TestCase):
    def test_stop_is_exact_original_lifetime_and_two_cold_roles(self):
        for role in r.ROLES:
            raw = r.stop_original(delivery_sha256=p.sha(b"c9"), role=role, invocation="b" * 32,
                deadline=(1 << 64) - 1)
            value = g.document(raw, r.MAX_BYTES)
            self.assertEqual(set(value), set(r.STOP_FIELDS))
            self.assertEqual(value["deadlineBoottimeNs"], str((1 << 64) - 1))
        for changed in (dict(role="credential-signing-authority"), dict(deadline=True),
                dict(deadline=0), dict(deadline=1 << 64), dict(invocation="B" * 32)):
            args = dict(delivery_sha256=p.sha(b"c9"), role=r.ROLES[0], invocation="b" * 32, deadline=3000)
            args.update(changed)
            with self.assertRaises((ValueError, TypeError)):
                r.stop_original(**args)

    def test_terminal_preserves_error_not_business_success(self):
        for result in ("ok", "error"):
            value, kwargs = fixture(result)
            self.assertEqual(r.terminal(g.canonical(value), **kwargs), value)
            self.assertEqual(value["serviceExitStatus"], 0 if result == "ok" else 1)

    def test_every_original_binding_and_request_hash_is_required(self):
        value, kwargs = fixture()
        for field, replacement in (("apiVersion", r.STOP_API), ("deliverySha256", p.sha(b"other")),
                ("serviceRole", r.ROLES[1]), ("invocationId", "b" * 32), ("deadlineBoottimeNs", "3001"),
                ("stopSha256", p.sha(b"different stop"))):
            changed = copy.deepcopy(value); changed[field] = replacement
            with self.assertRaises((ValueError, TypeError)):
                r.terminal(g.canonical(changed), **kwargs)

    def test_helper_death_or_nonzero_exit_cannot_retire(self):
        value, kwargs = fixture()
        for field, replacement in (("pid", 101), ("pid", 0), ("startTimeTicks", True),
                ("exitCode", os.CLD_KILLED), ("exitCode", True), ("exitStatus", 1),
                ("exitStatus", False), ("reapedAtBoottimeNs", "999"), ("reapedAtBoottimeNs", "2501")):
            changed = copy.deepcopy(value); changed["helper"][field] = replacement
            with self.assertRaises((ValueError, TypeError)):
                r.terminal(g.canonical(changed), **kwargs)

    def test_original_deadline_cannot_be_renewed(self):
        value, kwargs = fixture()
        for changed in (dict(now=3000), dict(now=3001), dict(now=999), dict(stop_sent_at=2501), dict(now=True)):
            with self.assertRaises((ValueError, TypeError)):
                r.terminal(g.canonical(value), **dict(kwargs, **changed))
        later = g.document(kwargs["stop_raw"], r.MAX_BYTES)
        later["deadlineBoottimeNs"] = "4000"
        with self.assertRaises((ValueError, TypeError)):
            r.terminal(g.canonical(value), **dict(kwargs, stop_raw=g.canonical(later)))

    def test_closed_types_and_result_exit_join(self):
        value, kwargs = fixture()
        for field, replacement in (("serviceResult", "stopped"), ("serviceExitStatus", 1),
                ("serviceExitStatus", False), ("serviceExitStatus", 2), ("extra", None), ("helper", None)):
            changed = copy.deepcopy(value); changed[field] = replacement
            with self.assertRaises((ValueError, TypeError)):
                r.terminal(g.canonical(changed), **kwargs)
        changed = copy.deepcopy(value); changed["helper"]["processReaped"] = True
        with self.assertRaises((ValueError, TypeError)):
            r.terminal(g.canonical(changed), **kwargs)

    def test_noncanonical_missing_and_oversized_packets_refuse(self):
        value, kwargs = fixture()
        raw = g.canonical(value)
        missing = copy.deepcopy(value); del missing["helper"]
        for changed in (raw + b"\n", g.canonical(missing), b"{" + b" " * r.MAX_BYTES + b"}"):
            with self.assertRaises((ValueError, TypeError)):
                r.terminal(changed, **kwargs)
        request = g.document(kwargs["stop_raw"], r.MAX_BYTES); request["apiVersion"] = r.TERMINAL_API
        with self.assertRaises((ValueError, TypeError)):
            r.terminal(raw, **dict(kwargs, stop_raw=g.canonical(request)))

    @unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open"), "Linux PIDFD primitive required")
    def test_actual_packet_sender_and_consuming_same_child_reap(self):
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
        for channel in (parent, child):
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        pid = pidfd = None
        reaped, retained = False, []
        try:
            pid = os.fork()
            if pid == 0:
                try:
                    parent.close()
                    if child.send(b"ordinary-retirement-kernel-probe") != 32:
                        os._exit(2)
                    ready, _, _ = select.select([child], [], [], 2.0)
                    os._exit(1 if ready and child.recv(16) == b"exit-error" else 2)
                except BaseException:
                    os._exit(2)
            child.close()
            pidfd = os.pidfd_open(pid, 0)
            self.assertEqual(io.pidfd_pid(pidfd), pid)
            deadline, packet = time.monotonic() + 2.0, None
            while packet is None and time.monotonic() < deadline:
                packet = process.packet(parent, 0, retained)
                if packet is None:
                    select.select([parent, pidfd], [], [], 0.01)
            self.assertIsNotNone(packet)
            raw, rights, credentials = packet
            self.assertEqual(raw, b"ordinary-retirement-kernel-probe")
            self.assertEqual(rights, [])
            self.assertEqual(credentials, (pid, os.getuid(), os.getgid()))
            self.assertIsNone(os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG))
            self.assertEqual(parent.send(b"exit-error"), 10)
            result = None
            while result is None and time.monotonic() < deadline:
                with io.owning():
                    result = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
                    reaped = result is not None
                if result is None:
                    select.select([pidfd], [], [], 0.01)
            self.assertIsNotNone(result)
            r.require_reap(result, pid=pid, uid=os.getuid(), status=1)
            for wrong in (dict(pid=pid + 1), dict(uid=os.getuid() + 1), dict(status=0), dict(status=2)):
                with self.assertRaises((ValueError, TypeError)):
                    r.require_reap(result, **dict(dict(pid=pid, uid=os.getuid(), status=1), **wrong))
            with self.assertRaises(ChildProcessError):
                os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
        finally:
            if pid is not None and pid > 0 and not reaped:
                if pidfd is not None:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    # Test-only fallback uses this exact fork return, never a
                    # configured PID; production retirement has no such signal.
                    os.kill(pid, signal.SIGKILL)
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    with io.owning():
                        result = os.waitpid(pid, os.WNOHANG) if pidfd is None else os.waitid(
                            os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
                        reaped = (result[0] == pid) if pidfd is None else result is not None
                    if reaped:
                        break
                    select.select([] if pidfd is None else [pidfd], [], [], 0.01)
                self.assertTrue(reaped, "bounded probe child cleanup did not finish")
            for fd in retained:
                os.close(fd)
            if pidfd is not None:
                os.close(pidfd)
            parent.close(); child.close()


if __name__ == "__main__":
    unittest.main()
