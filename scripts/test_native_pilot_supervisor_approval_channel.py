#!/usr/bin/env python3
"""Real local transport controls; synthetic observations are not approvals.

These exercise Linux sockets, credentials, PIDFDs and SCM_RIGHTS only. No
supervisor/resource owner, signing authority or currentness verdict is invented.
"""
from __future__ import annotations

import array
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
from catchplate import native_pilot_supervisor_approval_channel as channel


def pending(index=0, *, deadline=None, padding=0):
    deadline = channel._clock() + 10_000_000_000 if deadline is None else deadline
    name = channel.heads.JOB_NAMES[index]
    sequence = channel._SEQUENCES[name]
    request = channel.p.canonical({"apiVersion": "catchplate.nativePilotAuthorityJobRequest/v1",
        "sequence": sequence, "conductorSequence": 6, "conductorRequestSha256": "sha256:" + "1" * 64,
        "phase": "bridge-runtime", "jobIndex": index + 1, "job": name,
        "deadlineBoottimeNs": str(deadline), "conductorRequest": None, "previousResult": None})
    observation = channel.p.canonical({"apiVersion": channel.heads.OBSERVED_API, "jobName": name,
        "deadlineBoottimeNanos": deadline, "transportTestOriginal": "x" * padding})
    return {"phase": "bridge-runtime", "job": name, "sequence": sequence,
        "status": "awaiting-independent-current-head-approval", "requestOriginal": request.decode("ascii"),
        "requestSha256": channel.p.sha(request), "observationOriginal": observation.decode("ascii"),
        "observationSha256": channel.p.sha(observation)}


def peer_arguments():
    return dict(peer_pid=os.getpid(), peer_uid=os.getuid(), peer_gid=os.getgid())


@contextmanager
def pair():
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client = peer = None
    try:
        # Both SO_PASSCRED receivers are admitted before any packet is sent.
        client = channel.ApprovalChannel.open(left.fileno(), **peer_arguments())
        peer = channel.ApprovalPeer.open(right.fileno(), **peer_arguments())
        left.close(); right.close()
        yield client, peer
    finally:
        if client is not None: client.close()
        if peer is not None: peer.close()
        left.close(); right.close()


@contextmanager
def public_originals():
    descriptors = []
    raws = (b'{"transportInput":true}', b'{"transportApproval":true}')
    try:
        for raw in raws:
            fd = os.memfd_create("supervisor-transport-control", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            descriptors.append(fd)
            if os.write(fd, raw) != len(raw): raise RuntimeError("short fixture write")
            os.fchmod(fd, 0o400)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        yield tuple(descriptors), raws
    finally:
        for fd in descriptors: os.close(fd)


def copies(fd):
    """Bounded current-process FD census for these two actual memfd inodes."""
    original = os.fstat(fd)
    result = set()
    names = os.listdir("/proc/self/fd")
    if len(names) > 4096: raise RuntimeError("test FD census exceeds bound")
    for name in names:
        try: info = os.fstat(int(name))
        except OSError: continue  # The census directory FD has already closed.
        if (info.st_dev, info.st_ino) == (original.st_dev, original.st_ino): result.add(int(name))
    return result


def start(target):
    errors = []
    def run():
        try: target()
        except BaseException as error: errors.append(error)
    worker = threading.Thread(target=run)
    worker.start()
    return worker, errors


class ApprovalTransportControls(unittest.TestCase):
    def finish(self, worker, errors, client, peer):
        worker.join(2)
        if worker.is_alive():
            client.close(); peer.close()
            worker.join(1)
        self.assertFalse(worker.is_alive(), "bounded transport worker did not retire")
        self.assertEqual(errors, [])

    def test_eight_real_fd_exchanges_chunking_and_final_receipt_retirement(self):
        with pair() as (client, peer), public_originals() as (fds, raws):
            deadline = channel._clock() + 10_000_000_000
            values = [pending(index, deadline=deadline, padding=channel.CHUNK_BYTES + 701)
                for index in range(8)]
            seen, received = [], []
            def independent_peer():
                for value in values:
                    seen.append(peer.receive(deadline_boottime_ns=deadline))
                    peer.respond(input_fd=fds[0], input_sha256=channel.p.sha(raws[0]),
                        approval_fd=fds[1], approval_sha256=channel.p.sha(raws[1]))
                peer.close()  # Last respond returns only after the real receipt.
            worker, errors = start(independent_peer)
            try:
                for value in values:
                    result = client.exchange(value)
                    received.append(result)
                    actual = result.resume_kwargs()
                    self.assertEqual(os.pread(actual["input_fd"], 1024, 0), raws[0])
                    self.assertEqual(os.pread(actual["approval_fd"], 1024, 0), raws[1])
                    self.assertFalse(os.get_inheritable(actual["input_fd"]))
                    self.assertFalse(os.get_inheritable(actual["approval_fd"]))
            finally:
                self.finish(worker, errors, client, peer)
            self.assertEqual(seen, values)
            self.assertGreater(client._total, channel.CHUNK_BYTES * 8)
            self.assertEqual(os.pread(received[-1].resume_kwargs()["input_fd"], 1024, 0), raws[0])

    def test_wrong_kernel_peer_and_stream_socket_refused(self):
        for kind, changed in ((socket.SOCK_SEQPACKET, True), (socket.SOCK_STREAM, False)):
            with self.subTest(kind=kind):
                left, right = socket.socketpair(socket.AF_UNIX, kind)
                try:
                    selected = peer_arguments()
                    if changed: selected["peer_pid"] += 1
                    with self.assertRaises(ValueError): channel.ApprovalChannel.open(left.fileno(), **selected)
                finally: left.close(); right.close()

    def test_pending_order_hash_and_original_schema_refused(self):
        values = [pending(1), dict(pending(), requestSha256="sha256:" + "2" * 64),
            dict(pending(), approved=True)]
        wrong = pending(); wrong["requestOriginal"] = "{}"; wrong["requestSha256"] = channel.p.sha(b"{}")
        values.append(wrong)
        for value in values:
            with self.subTest(value=value["job"]), pair() as (client, peer):
                with self.assertRaises(ValueError): client.exchange(value)
                with self.assertRaises(ValueError): client.exchange(pending())

    def test_expired_original_deadline_refuses_without_renewal(self):
        with pair() as (client, peer):
            with self.assertRaises(ValueError): client.exchange(pending(deadline=channel._clock() - 1))
            self.assertTrue(client._failed)

    def malformed(self, mutation):
        with pair() as (client, peer), public_originals() as (fds, raws):
            deadline = channel._clock() + 10_000_000_000
            value = pending(deadline=deadline)
            before = [copies(fd) for fd in fds]
            def independent_peer():
                peer.receive(deadline_boottime_ns=deadline)
                reply = {"apiVersion": channel.REPLY_API, "requestBindingSha256": peer._binding,
                    "inputSha256": channel.p.sha(raws[0]), "approvalSha256": channel.p.sha(raws[1])}
                rights = fds
                if mutation == "binding": reply["requestBindingSha256"] = "sha256:" + "2" * 64
                elif mutation == "numeric-fds":
                    reply.update(inputFd=fds[0], approvalFd=fds[1]); rights = ()
                elif mutation == "extra-field": reply["approved"] = True
                elif mutation == "extra-rights": rights = (*fds, fds[0])
                elif mutation == "truncated-rights": rights = (fds[0],) * 24
                raw = channel.p.canonical(reply)
                if mutation == "truncated-data": raw += b" " * (channel.MAX_FRAME + 1)
                ancillary = [] if not rights else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", rights))]
                sent = peer._socket.sendmsg([raw], ancillary, socket.MSG_NOSIGNAL)
                if sent != len(raw): raise RuntimeError("short malformed fixture packet")
            worker, errors = start(independent_peer)
            try:
                with self.assertRaises(ValueError): client.exchange(value)
            finally:
                self.finish(worker, errors, client, peer)
            self.assertEqual([copies(fd) for fd in fds], before)
            self.assertTrue(client._failed)

    def test_reply_binding_closed_fields_and_numeric_fd_fiction_refused(self):
        for mutation in ("binding", "extra-field", "numeric-fds"):
            with self.subTest(mutation=mutation): self.malformed(mutation)

    def test_extra_and_truncated_received_rights_are_closed(self):
        for mutation in ("extra-rights", "truncated-rights", "truncated-data"):
            with self.subTest(mutation=mutation): self.malformed(mutation)

    def test_channel_retains_returned_fd_owner_until_terminal_transport_close(self):
        with pair() as (client, peer), public_originals() as (fds, raws):
            deadline = channel._clock() + 10_000_000_000
            def independent_peer():
                peer.receive(deadline_boottime_ns=deadline)
                peer.respond(input_fd=fds[0], input_sha256=channel.p.sha(raws[0]),
                    approval_fd=fds[1], approval_sha256=channel.p.sha(raws[1]))
                peer.close()
            worker, errors = start(independent_peer)
            try: received = client.exchange(pending(deadline=deadline))
            finally: self.finish(worker, errors, client, peer)
            actual = received.resume_kwargs()
            client.close()  # Even a caller that never closes the returned owner is covered.
            with self.assertRaises(ValueError): received.resume_kwargs()
            for name in ("input_fd", "approval_fd"):
                with self.assertRaises(OSError): os.fstat(actual[name])
            self.assertEqual([copies(fd) for fd in fds], [{fds[0]}, {fds[1]}])

    def test_linux_ucred_has_signed_pid_and_unsigned_high_uid_gid(self):
        expected = (os.getpid(), (1 << 31) + 7, (1 << 32) - 2)
        raw = struct.pack("=iII", *expected)
        self.assertEqual(channel._CREDENTIALS.size, 12)
        self.assertEqual(channel._CREDENTIALS.unpack(raw), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
