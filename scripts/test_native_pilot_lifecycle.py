#!/usr/bin/env python3
"""Pure source joins plus one real PIDFD/parent seam, not a pilot fixture.

No protected runtime, approval, native helper, core receiver, installer or
commissioning owner is fabricated. The single fork control checks only the
actual process identity primitive also used by the connected lifecycle.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import select
import signal
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import test_native_pilot_genesis_rendezvous as fixtures
from serverware import native_pilot_lifecycle as lifecycle

p = lifecycle.p


def fixture():
    value = fixtures.fixture()
    configuration = p.document(value["configuration_raw"], 4096)
    sender = {"pid": 100, "uid": 0, "gid": 0, "startTimeTicks": 123, "parentPid": 99}
    intake = {"apiVersion": lifecycle.intake.API, "purpose": lifecycle.intake.PURPOSE,
        "sender": {name: sender[name] for name in ("pid", "uid", "gid", "startTimeTicks")},
        **{name: configuration["window"][name] for name in lifecycle.rendezvous.wire.endpoints.WINDOW[:3]},
        "issuedAtBoottimeNs": "1200000000", "startupDeadlineBoottimeNs": "1900000000",
        "lifetimeDeadlineBoottimeNs": "3500000000", "issuedAtUnixNanos": 7000000000,
        "expiresAtUnixNanos": 8500000000}
    return value | {"identity": sender, "intake": intake}


def joined(value, *, intake=None, **clocks):
    return lifecycle._late_join(value["sender_raw"], value["configuration_raw"], value["identity"],
        p.canonical(value["intake"] if intake is None else intake),
        **({name: value[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")} | clocks))


class LifecycleSourceControls(unittest.TestCase):
    def test_independent_intervals_intersect_without_equal_window_requirement(self):
        value = fixture()
        self.assertEqual(joined(value), {"startup": 1900000000, "deadline": 3500000000, "epochLimit": 8500000000})
        later = copy.deepcopy(value["intake"])
        later.update(startupDeadlineBoottimeNs="2500000000", lifetimeDeadlineBoottimeNs="4500000000",
            expiresAtUnixNanos=9500000000)
        self.assertEqual(joined(value, intake=later),
            {"startup": 2000000000, "deadline": 4000000000, "epochLimit": 9000000000})

    def test_late_sender_must_equal_actual_cold_process_identity(self):
        value = fixture()
        for field, replacement in (("pid", 101), ("startTimeTicks", 124), ("uid", 1), ("gid", 1)):
            changed = copy.deepcopy(value["intake"])
            changed["sender"][field] = replacement
            with self.assertRaises(ValueError): joined(value, intake=changed)
        changed = value | {"identity": value["identity"] | {"startTimeTicks": 124}}
        with self.assertRaises(ValueError): joined(changed)

    def test_current_clocks_are_inside_both_originals_and_cleanup_reserve(self):
        value = fixture()
        for clocks in ({"now_boottime_ns": 1199999999}, {"now_boottime_ns": 1900000000},
                {"now_unix_ns": 6999999999}, {"now_unix_ns": 8500000000},
                {"boot": (value["boot"][0], 11, 13)}):
            with self.assertRaises(ValueError): joined(value, **clocks)
        changed = copy.deepcopy(value["intake"])
        changed.update(startupDeadlineBoottimeNs="1600000000", lifetimeDeadlineBoottimeNs="1700000000")
        with self.assertRaises(ValueError): joined(value, intake=changed)

    def test_sender_hash_configuration_and_exact_profile_remain_closed(self):
        value = fixture()
        for field, replacement in (("configurationSha256", p.sha(b"different")),
                ("listenerSha256", p.sha(b"different")), ("apiVersion", "serverware.nativePilotGenesisListenerRequest/v2"),
                ("sequence", True), ("expiresAtUnixNanos", 9000000001)):
            changed = p.document(value["sender_raw"], 8192) | {field: replacement}
            with self.assertRaises(ValueError): joined(value | {"sender_raw": p.canonical(changed)})

    def test_actual_rendezvous_cannot_be_replaced_by_another_valid_transcript(self):
        value = fixture()
        self.assertEqual(lifecycle._rendezvous_join(value["request_raw"], value["sender_raw"], value["configuration_raw"]),
            {"pid": 200, "uid": 0, "gid": 0, "startTimeTicks": 234})
        other = p.document(value["sender_raw"], 8192)
        observed = p.document(other["listenerOriginal"].encode("ascii"), 8192)
        observed["processStartTimeTicks"] += 1
        raw = p.canonical(observed)
        other.update(listenerOriginal=raw.decode("ascii"), listenerSha256=p.sha(raw))
        with self.assertRaises(ValueError): lifecycle._rendezvous_join(value["request_raw"],
            p.canonical(other), value["configuration_raw"])

    def test_no_legacy_intake_or_extra_approval_field_upgrades_selection(self):
        value = fixture()
        for changed in (value["intake"] | {"apiVersion": "serverware.nativePilotAdoptedIntakeConfiguration/v2"},
                value["intake"] | {"approved": True}):
            with self.assertRaises(ValueError): joined(value, intake=changed)

    def test_staged_order_requires_cold_completion_before_adopted_step(self):
        stage = "prepared"
        for operation in ("start", "attach_adopted", "receive_rendezvous", "submit_rendezvous"):
            with self.assertRaises(ValueError): lifecycle._next(stage, "adopted_step")
            stage = lifecycle._next(stage, operation)
        for _ in lifecycle._COLD_JOBS:
            stage = lifecycle._next(stage, "cold_step")
            stage = lifecycle._next(stage, "cold_submit")
        with self.assertRaises(ValueError): lifecycle._next(stage, "adopted_step")
        stage = lifecycle._next(stage, "finish_cold")
        stage = lifecycle._next(stage, "adopted_step")
        stage = lifecycle._next(stage, "adopted_submit")
        self.assertEqual(lifecycle._next(stage, "finish_adopted"), "adopted-finished")
        # This reducer only orders operations; actual owner methods separately
        # require all 66/176 genuine exchanges before each finish boundary.

    def test_duplicate_out_of_order_and_arbitrary_actions_are_refused(self):
        for stage, operation in (("sender", "start"), ("prepared", "cold_step"),
                ("adopted-waiting", "cold_submit"), ("rendezvous", "finish_cold"),
                ("cold-pending", "cold_step"), ("adopted-pending", "adopted_step"),
                ("adopted-finished", "adopted_step"), ("cold-ready", "approve-all")):
            with self.assertRaises(ValueError): lifecycle._next(stage, operation)

    def test_public_documents_cannot_construct_or_supply_a_lifecycle_owner(self):
        for value in ({"status": "closed", "completed": True}, fixture(), None, object()):
            with self.assertRaises(ValueError): lifecycle.CommissioningLifecycle(value)

    def test_public_joins_do_not_mutate_retained_literals(self):
        value = fixture()
        before = copy.deepcopy(value)
        result = joined(value)
        result["deadline"] = 1
        receiver = lifecycle._rendezvous_join(value["request_raw"], value["sender_raw"], value["configuration_raw"])
        receiver["pid"] = 999
        self.assertEqual(value, before)
        self.assertEqual(joined(value)["deadline"], 3500000000)


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open") and hasattr(os, "P_PIDFD"),
    "actual Linux PIDFD primitive required")
class ActualReceiverIdentityPrimitive(unittest.TestCase):
    def test_real_fork_pidfd_parent_start_credentials_and_namespace(self):
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        pid = os.fork()
        if pid == 0:
            try:
                os.close(write_fd)
                os.read(read_fd, 1)
            finally:
                os._exit(0)
        os.close(read_fd)
        pidfd, consumed = None, False
        try:
            pidfd = os.pidfd_open(pid, 0)
            os.set_inheritable(pidfd, False)
            boot = lifecycle.originals._boot()
            parent, start = lifecycle.mechanics._process(pid)
            self.assertEqual(parent, os.getpid())
            expected = dict(pid=pid, uid=os.getuid(), gid=os.getgid(), startTimeTicks=start)
            lifecycle._receiver_process(pidfd, expected, os.getpid(), boot)
            for wrong, parent_pid, namespace in (
                (expected | {"startTimeTicks": start + 1}, os.getpid(), boot),
                (expected | {"uid": os.getuid() + 1}, os.getpid(), boot),
                (expected, os.getpid() + 1, boot),
                (expected, os.getpid(), (boot[0], boot[1], boot[2] + 1))):
                with self.assertRaises(ValueError): lifecycle._receiver_process(pidfd, wrong, parent_pid, namespace)
            os.close(write_fd); write_fd = None
            self.assertTrue(select.select([pidfd], [], [], 2)[0])
            status = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
            consumed = True
            self.assertEqual((status.si_pid, status.si_code, status.si_status), (pid, os.CLD_EXITED, 0))
            with self.assertRaises(ValueError): lifecycle._receiver_process(pidfd, expected, os.getpid(), boot)
        finally:
            if write_fd is not None:
                os.close(write_fd)
            if not consumed:
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    got, _ = os.waitpid(pid, os.WNOHANG)
                    if got == pid:
                        consumed = True
                        break
                    time.sleep(0.01)
                if not consumed and pidfd is not None:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
                    if select.select([pidfd], [], [], 2)[0]:
                        os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
                        consumed = True
            if pidfd is not None:
                os.close(pidfd)
            self.assertTrue(consumed, "actual fork cleanup must be observed; no owner admission claimed")


if __name__ == "__main__":
    unittest.main()
