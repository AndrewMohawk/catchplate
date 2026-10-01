#!/usr/bin/env python3
"""Real local peer primitives, not a protected listener or core ceremony.

Each kernel control owns one short-lived child and uses the same production
PIDFD/identity functions. It neither constructs a listener from a DTO nor
substitutes a successful signature, installation or custody validator.
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path
import select
import signal
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import native_pilot_genesis_handoff_listener as listener
from serverware import native_pilot_genesis_receiver_observation as peer
from serverware import native_shadow_nitro_originals as originals
from test_native_pilot_genesis_handoff_listener import fixture


@contextlib.contextmanager
def actual_peer(kind=socket.SOCK_SEQPACKET):
    with tempfile.TemporaryDirectory(prefix="genesis-peer-") as directory:
        address = directory + "/peer.sock"
        server = socket.socket(socket.AF_UNIX, kind)
        server.bind(address); server.listen(1); server.settimeout(2)
        ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
        row = dict(child=None, pidfd=None, channel=None, release=ready_w)
        child = os.fork()
        if child == 0:
            try:
                server.close(); os.close(ready_w)
                client = socket.socket(socket.AF_UNIX, kind)
                client.settimeout(2); client.connect(address)
                select.select([ready_r], [], [], 3)
                client.close(); os.close(ready_r)
                os._exit(0)
            except BaseException:
                os._exit(2)
        row["child"] = child
        os.close(ready_r)
        try:
            row["pidfd"] = os.pidfd_open(child)
            row["channel"], _ = server.accept()
            row["channel"].setblocking(False)
            row["channel"].set_inheritable(False)
            yield row
        finally:
            if row["release"] is not None:
                os.close(row["release"]); row["release"] = None
            if row["channel"] is not None:
                row["channel"].close()
            server.close()
            if row["pidfd"] is not None:
                if not select.select([row["pidfd"]], [], [], 4)[0]:
                    signal.pidfd_send_signal(row["pidfd"], signal.SIGKILL)
                if not select.select([row["pidfd"]], [], [], 1)[0]:
                    raise AssertionError("owned peer did not become terminal")
                result = os.waitid(os.P_PIDFD, row["pidfd"], os.WEXITED | os.WNOHANG)
                os.close(row["pidfd"]); row["pidfd"] = None
                if result is None or (result.si_pid, result.si_code, result.si_status) != (child, os.CLD_EXITED, 0):
                    raise AssertionError("owned peer did not exit normally")
            else:
                # Only partial test startup before PIDFD acquisition; this is
                # consuming our direct child, never production peer fallback.
                os.waitpid(child, 0)


@contextlib.contextmanager
def kernel_pidfd(channel):
    held = peer.acquire_pidfd(channel)
    try:
        os.set_inheritable(held, False)
        yield held
    finally:
        os.close(held)


class ReceiverObservationControls(unittest.TestCase):
    def test_actual_connected_child_is_kernel_peer_without_sending_data(self):
        with actual_peer() as owned, kernel_pidfd(owned["channel"]) as held:
            value = peer.peer_identity(owned["channel"], held, boot=originals._boot())
            self.assertEqual(value["pid"], owned["child"])
            self.assertEqual((value["uid"], value["gid"]), (os.getuid(), os.getgid()))
            self.assertGreater(value["startTimeTicks"], 0)
            self.assertEqual(select.select([owned["channel"]], [], [], 0)[0], [])
            self.assertEqual(peer.io.pidfd_pid(held), owned["child"])

    def test_same_retained_socket_duplicate_keeps_exact_peer(self):
        with actual_peer() as owned, kernel_pidfd(owned["channel"]) as held:
            expected = peer.peer_identity(owned["channel"], held, boot=originals._boot())
            with socket.socket(fileno=os.dup(owned["channel"].fileno())) as duplicate:
                duplicate.set_inheritable(False)
                self.assertEqual(peer.peer_identity(duplicate, held, boot=originals._boot()), expected)

    def test_unrelated_actual_pidfd_cannot_match_observed_socket(self):
        with actual_peer() as owned:
            held = os.pidfd_open(os.getpid())
            try:
                with self.assertRaises(ValueError):
                    peer.peer_identity(owned["channel"], held, boot=originals._boot())
            finally:
                os.close(held)

    def test_terminal_actual_peer_refuses_instead_of_reusing_pid(self):
        with actual_peer() as owned, kernel_pidfd(owned["channel"]) as held:
            peer.peer_identity(owned["channel"], held, boot=originals._boot())
            os.close(owned["release"]); owned["release"] = None
            self.assertTrue(select.select([held], [], [], 2)[0])
            with self.assertRaises(ValueError):
                peer.peer_identity(owned["channel"], held, boot=originals._boot())

    def test_socketpair_creator_is_not_a_distinct_receiver(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            with kernel_pidfd(left) as held, self.assertRaises(ValueError):
                peer.peer_identity(left, held, boot=originals._boot())
        finally:
            left.close(); right.close()

    def test_actual_peer_cannot_be_reinterpreted_in_other_time_namespace(self):
        with actual_peer() as owned, kernel_pidfd(owned["channel"]) as held:
            boot = originals._boot()
            with self.assertRaises(ValueError):
                peer.peer_identity(owned["channel"], held, boot=(boot[0], boot[1], boot[2] + 1))

    def test_stream_transport_is_not_a_sequence_packet_observation(self):
        with actual_peer(socket.SOCK_STREAM) as owned, kernel_pidfd(owned["channel"]) as held:
            with self.assertRaises(ValueError):
                peer.peer_identity(owned["channel"], held, boot=originals._boot())

    def test_listener_configuration_two_is_never_an_implicit_upgrade(self):
        value, clocks = fixture()
        old = listener.p.canonical(value)
        value["apiVersion"] = listener.RENDEZVOUS_API
        new = listener.p.canonical(value)
        self.assertEqual(listener.configuration(new, rendezvous=True, **clocks), value)
        with self.assertRaises(ValueError): listener.configuration(new, **clocks)
        with self.assertRaises(ValueError): listener.configuration(old, rendezvous=True, **clocks)
        with self.assertRaises(ValueError): listener.configuration(new, rendezvous=1, **clocks)


if __name__ == "__main__":
    unittest.main()
