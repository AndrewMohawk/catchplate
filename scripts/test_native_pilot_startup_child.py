#!/usr/bin/env python3
"""Actual local control peers and signed public role sources, not a live pilot.

Kernel controls use one actual child at a time, child-created connections,
SO_PEERPIDFD, SCM_CREDENTIALS and SCM_RIGHTS. The pure source controls use the
existing signed synthetic fixture. No installed StartupChild or successful
authority/cleanup validator is fabricated, and no private seed is read.
"""
from __future__ import annotations

import contextlib
import copy
import fcntl
import os
from pathlib import Path
import select
import signal
import socket
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))
from scripts import test_native_pilot_startup_profile as fixtures
from catchplate import native_pilot_startup_child as child

p = child.p


def public_fd():
    fd = os.memfd_create("startup-public-control", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(fd, b"public transport control, not authority")
    os.fchmod(fd, 0o400)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
        fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
    return fd


@contextlib.contextmanager
def actual_peer(action, *, inherited=False):
    """One bounded actual child; parent closes controls after consuming reap."""
    parent = child._process()
    boot = child.originals._boot()
    deadline, expiry = child.originals._clock() + 5_000_000_000, time.time_ns() + 5_000_000_000
    def check():
        if child.originals._clock() >= deadline or time.time_ns() >= expiry:
            raise ValueError("test original bound expired")
    release_r, release_w = os.pipe2(os.O_CLOEXEC)
    server = first = second = None
    if inherited:
        first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    else:
        address = b"\0catchplate.startup.test." + os.urandom(12).hex().encode("ascii")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        server.bind(address); server.listen(1); server.settimeout(2)
    pid = os.fork()
    if pid == 0:
        control = None
        try:
            os.close(release_w)
            if inherited:
                first.close(); channel = second
            else:
                server.close()
                channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                channel.settimeout(2); channel.connect(address)
            control = child._Control.open(channel, peer=parent, boot=boot, check=check)
            action(control)
            if not select.select([release_r], [], [], 4)[0]: raise ValueError("test parent did not release")
            os.read(release_r, 1)
            control.close(); os.close(release_r)
            os._exit(0)
        except BaseException:
            os._exit(2)
    os.close(release_r)
    pidfd = os.pidfd_open(pid)
    row = dict(control=None, channel=None, peer=None, boot=boot, check=check)
    try:
        if inherited:
            second.close(); row["channel"] = first
        else:
            row["channel"], _ = server.accept()
        parent_pid, start = child.mechanics._process(pid)
        row["peer"] = dict(pid=pid, uid=0, gid=0, startTimeTicks=start, parentPid=parent_pid)
        yield row
    finally:
        os.close(release_w)
        if not select.select([pidfd], [], [], 5)[0]:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        if not select.select([pidfd], [], [], 1)[0]:
            raise AssertionError("test child terminal state unknown")
        result = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
        os.close(pidfd)
        # This deliberately exercises cleanup after the actual peer is dead.
        if row["control"] is not None:
            row["control"].close(); row["control"].close()
        elif row["channel"] is not None:
            row["channel"].close()
        if server is not None: server.close()
        if result is None or (result.si_pid, result.si_code, result.si_status) != (pid, os.CLD_EXITED, 0):
            raise AssertionError("test child did not exit normally")


def open_control(row, *, peer=None):
    try:
        row["control"] = child._Control.open(row["channel"], peer=row["peer"] if peer is None else peer,
            boot=row["boot"], check=row["check"])
    except child._ControlError as error:
        row["control"] = error.owner
        raise
    return row["control"]


@unittest.skipUnless(hasattr(os, "fork") and hasattr(os, "pidfd_open") and os.geteuid() == 0,
    "actual root child/PIDFD and root-owned public test originals required")
class StartupKernelControls(unittest.TestCase):
    def test_actual_child_credentials_and_received_public_rights_retained(self):
        def action(control):
            raw, fds = control.receive(0)
            if raw != b"ping" or fds: raise ValueError("wrong test request")
            fd = public_fd()
            try: control.send(b"public", (fd,))
            finally: os.close(fd)
        received = None
        with actual_peer(action) as row:
            control = open_control(row)
            self.assertEqual(control.peer, row["peer"])
            control.send(b"ping")
            raw, descriptors = control.receive(1)
            received = descriptors[0]
            self.assertEqual(raw, b"public")
            self.assertFalse(os.get_inheritable(received))
            self.assertEqual(os.pread(received, 64, 0), b"public transport control, not authority")
            self.assertEqual(child.io.pidfd_pid(control._pidfd), row["peer"]["pid"])
        with self.assertRaises(OSError): os.fstat(received)

    def test_excess_rights_fail_closed_but_all_delivered_fds_remain_owned(self):
        def action(control):
            control.receive(0)
            fd = public_fd()
            try: control.send(b"extra", (fd, fd))
            finally: os.close(fd)
        received = ()
        with actual_peer(action) as row:
            control = open_control(row); control.send(b"go")
            with self.assertRaises(child._ControlError) as raised: control.receive(1)
            self.assertIs(raised.exception.owner, control)
            received = tuple(item[0] for item in control._incoming)
            self.assertEqual(len(received), 2)
            self.assertTrue(all(os.fstat(fd).st_size > 0 for fd in received))
            with self.assertRaises(child._ControlError): control.receive(1)
        for fd in received:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_wrong_actual_start_is_not_numeric_pid_authority(self):
        with actual_peer(lambda _: None) as row:
            with self.assertRaises(child._ControlError) as raised:
                open_control(row, peer=row["peer"] | {"startTimeTicks": row["peer"]["startTimeTicks"] + 1})
            self.assertIs(raised.exception.owner, row["control"])
            self.assertEqual(child.io.pidfd_pid(row["control"]._pidfd), row["peer"]["pid"])

    def test_parent_created_socketpair_cannot_claim_child_peer(self):
        with actual_peer(lambda _: None, inherited=True) as row:
            with self.assertRaises(child._ControlError) as raised: open_control(row)
            self.assertIs(raised.exception.owner, row["control"])


class StartupRoleSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix="startup-child-sources-")
        cls.addClassCleanup(directory.cleanup)
        cls.addClassCleanup(fixtures.policy_fixture.source_fixture.runtime_fixture.thaw, Path(directory.name))
        cls.source = fixtures.fixture(Path(directory.name))

    def context(self, role, *, source=None, peers=None, **clocks):
        value = self.source
        return child._role_context(role,
            {name: value["sources"][name] for name in child.profile.ROLE_SOURCES[role]} if source is None else source,
            value["inventory_raw"], value["peers"] if peers is None else peers, **(value["clocks"] | clocks))

    def test_all_three_actual_public_source_validators_preserve_original_caps(self):
        for role in child.profile.ROLES:
            with self.subTest(role=role):
                caps = self.context(role)
                self.assertLessEqual(caps["deadline"], p.ns(self.source["admission"]["deadlineBoottimeNs"]))
                self.assertLessEqual(caps["epochLimit"], self.source["admission"]["expiresAtUnixNanos"])

    def test_independently_pinned_peers_cannot_be_replaced_by_report_labels(self):
        for role, peer in (("provider", "lifecycle"), ("provider", "decisions"), ("decisions", "provider")):
            changed = copy.deepcopy(self.source["peers"])
            changed[peer]["startTimeTicks"] += 1
            with self.subTest(role=role, peer=peer), self.assertRaises(ValueError):
                self.context(role, peers=changed)

    def test_original_namespace_and_expiry_remain_required(self):
        for role in child.profile.ROLES:
            for clocks in ({"boot": (self.source["clocks"]["boot"][0], 1, 999)},
                    {"now_boottime_ns": p.ns(self.source["configuration"]["deadlineBoottimeNs"])},
                    {"now_unix_ns": self.source["configuration"]["expiresAtUnixNanos"]}):
                with self.subTest(role=role, clocks=clocks), self.assertRaises(ValueError):
                    self.context(role, **clocks)


if __name__ == "__main__":
    unittest.main()
