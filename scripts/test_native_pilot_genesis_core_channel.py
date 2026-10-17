#!/usr/bin/env python3
"""Transport framing and real Linux I/O primitives, not core admission.

The small public fixture is explicitly structural, not a signed cold Bundle.
Real socket/child controls call the same narrow packet primitive unbound; they
do not fabricate a root channel owner or a successful fs-verity validator.
No protected filesystem paths, signers, services or core copies are created.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import select
import socket
import stat
import sys
from types import SimpleNamespace
import unittest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS.parent))
from catchplate import native_pilot_genesis_core_channel as c


def fixture():
    """Only the closed transport projection; never a verified native result."""
    digest = "sha256:" + "1" * 64
    scope = dict(commissioningIdSha256=digest, issuedAtBoottimeNanos=10, expiresAtBoottimeNanos=100)
    core = dict(apiVersion="catchplate.nativeInitialPublicationCore/v1", nativeGrantSha256=digest,
        genesis={"scope": scope}, observedAtUnixNanos=1000, trustCheckpointSha256=digest,
        signingKeyId=digest, signingKeySpkiSha256=digest)
    core_raw = c.g.canonical(core)
    payload = {name: digest for name in c.profile.STORED_FIELDS}
    payload.update(apiVersion="catchplate.nativePublicationGenesisStorage/v1", sequence=1,
        guest=dict(uid=1001, gid=1002, deliverySha256=digest), objectSha256=c.p.sha(core_raw),
        coreSha256=c.p.framed(b"catchplate.nativeInitialPublicationCore/v1", (core_raw,)),
        storedAtBoottimeNanos=30, originalDeadlineBoottimeNanos=100)
    bundle = dict(completion=dict(apiVersion="catchplate.nativePublicationGenesisCompletion/v1",
        prepared=dict(core=core, preparedAtBoottimeNanos=20, signature="not-a-native-signature"),
        stored=dict(payload=payload, signature="not-a-retrieval-signature"), receiptOriginal="not-an-admitted-receipt",
        completedAtBoottimeNanos=40, signature="not-a-completion-signature"), durable={}, current={})
    bundle_raw = c.g.canonical(bundle)
    observed = {name: digest for name in c.profile.HASH_FIELDS}
    observed.update(apiVersion=c.profile.API, bundleSha256=c.p.sha(bundle_raw),
        scopeSha256=c.p.sha(c.g.canonical(scope)), coreSha256=payload["coreSha256"],
        objectSha256=payload["objectSha256"], filename=c.profile.FILENAME,
        directory=dict(device=2, inode=3, mode=stat.S_IFDIR | 0o700, uid=1001, gid=1002),
        file=dict(device=2, inode=4, mode=stat.S_IFREG | 0o400, uid=1001, gid=1002,
            nlink=1, length=len(core_raw), mtimeNanos=50, ctimeNanos=50),
        issuedAtBoottimeNs="10", deadlineBoottimeNs="90", issuedAtUnixNanos=1000, expiresAtUnixNanos=2000)
    return c.g.canonical(observed), bundle_raw


class CoreChannelControls(unittest.TestCase):
    def test_binary_container_preserves_literal_public_originals(self):
        observed, bundle = fixture()
        public = c.pack_originals(observed, bundle)
        self.assertEqual(c.unpack_originals(public), (observed, bundle))
        self.assertLessEqual(len(public), c.MAX_ORIGINALS)
        self.assertIn(b"not-an-admitted-receipt", public)

    def test_container_refuses_truncation_trailing_bytes_and_substitution(self):
        observed, bundle = fixture()
        raw = c.pack_originals(observed, bundle)
        for invalid in (raw[:-1], raw + b"\0", b"wrong" + raw, raw[:len(c.MAGIC)] + b"\xff" * 16 + raw[len(c.MAGIC) + 16:]):
            with self.assertRaises(ValueError): c.unpack_originals(invalid)
        changed = c.g.document(bundle, c.MAX_BUNDLE)
        changed["completion"]["prepared"]["core"]["observedAtUnixNanos"] += 1
        with self.assertRaises(ValueError): c.pack_originals(observed, c.g.canonical(changed))

    def test_request_and_ack_bind_sequence_and_all_literal_hashes(self):
        observed, bundle = fixture()
        public = c.pack_originals(observed, bundle)
        raw = c.request_original(observed, bundle, public, deadline=80, expiry=1900)
        ack = c.acknowledgment(raw)
        c.require_ack(ack, raw)
        for field, value in (("sequence", 2), ("requestSha256", "sha256:" + "2" * 64),
                ("bundleSha256", "sha256:" + "3" * 64), ("observationSha256", "sha256:" + "4" * 64)):
            changed = c.g.document(ack, c.MAX_PACKET); changed[field] = value
            with self.assertRaises(ValueError): c.require_ack(c.g.canonical(changed), raw)
        with self.assertRaises(ValueError): c.require_ack(ack + b"\n", raw)

    def test_request_cannot_extend_original_bounds_or_add_fields(self):
        observed, bundle = fixture(); public = c.pack_originals(observed, bundle)
        for deadline, expiry in ((91, 1900), (80, 2001), (True, 1900)):
            with self.assertRaises(ValueError):
                c.request_original(observed, bundle, public, deadline=deadline, expiry=expiry)
        raw = c.request_original(observed, bundle, public, deadline=80, expiry=1900)
        value = c.g.document(raw, c.MAX_PACKET)
        for change in ({"sequence": 0}, {"apiVersion": "catchplate.nativePilotCurrentHeadApprovalRequest/v1"},
                {"retry": True}):
            changed = copy.deepcopy(value); changed.update(change)
            with self.assertRaises(ValueError): c.request(c.g.canonical(changed))
        value["originals"]["length"] = c.MAX_ORIGINALS + 1
        with self.assertRaises(ValueError): c.request(c.g.canonical(value))

    def test_actual_unsealed_public_memfd_is_not_an_original(self):
        fd = os.memfd_create("core-channel-negative", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            raw = b"public-but-unsealed"
            self.assertEqual(os.write(fd, raw), len(raw)); os.fchmod(fd, 0o400)
            with self.assertRaises(ValueError): c._read_public(fd, c._pin(raw))
        finally:
            os.close(fd)

    def test_inherited_socketpair_creator_is_not_the_child_peer(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
        child, pidfd = None, None
        try:
            child = os.fork()
            if child == 0:
                try:
                    left.close(); os.close(ready_w)
                    select.select([ready_r], [], [], 1)
                    os._exit(0)
                except BaseException:
                    os._exit(2)
            os.close(ready_r); ready_r = None
            pidfd = os.pidfd_open(child)
            c._require_peer_credentials(left, (os.getpid(), os.getuid(), os.getgid()))
            with self.assertRaises(ValueError):
                c._require_peer_credentials(left, (child, os.getuid(), os.getgid()))
            os.close(ready_w); ready_w = None
            expected = child
            result = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
            child = None
            self.assertEqual((result.si_pid, result.si_code, result.si_status), (expected, os.CLD_EXITED, 0))
        finally:
            for fd in (ready_r, ready_w):
                if fd is not None: os.close(fd)
            left.close(); right.close()
            if child is not None: os.waitid(os.P_PIDFD, pidfd, os.WEXITED) if pidfd is not None else os.waitpid(child, 0)
            if pidfd is not None: os.close(pidfd)

    def test_real_ack_latches_before_immediate_peer_exit_and_postcheck(self):
        # Exact production send primitive, not a constructed channel/core owner.
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        child = os.fork(); pidfd = None
        if child == 0:
            try:
                left.close(); right.settimeout(1)
                os._exit(0 if right.recv(32) == b"actual-ack" else 2)
            except BaseException:
                os._exit(2)
        try:
            right.close(); pidfd = os.pidfd_open(child)
            primitive = SimpleNamespace(_socket=left, _acked=False, _rights_may_have_sent=False)
            primitive._wait = lambda reading, check: self.assertTrue(select.select([], [left], [], 1)[1])
            def after(check, *, terminal=False):
                nonlocal child
                self.assertTrue(primitive._acked)
                expected = child
                result = os.waitid(os.P_PIDFD, pidfd, os.WEXITED)
                child = None
                self.assertEqual((result.si_pid, result.si_code, result.si_status), (expected, os.CLD_EXITED, 0))
            primitive._guard = after
            c._Connection._send(primitive, b"actual-ack", (), lambda: None)
            child = None
            self.assertTrue(primitive._acked)
        finally:
            left.close(); right.close()
            if child is not None: os.waitid(os.P_PIDFD, pidfd, os.WEXITED) if pidfd is not None else os.waitpid(child, 0)
            if pidfd is not None: os.close(pidfd)

    def test_failed_actual_rights_send_consumes_ambiguity_latch(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        fd = os.memfd_create("core-channel-send-refusal", os.MFD_CLOEXEC)
        try:
            right.close()
            primitive = SimpleNamespace(_socket=left, _acked=False, _rights_may_have_sent=False,
                _wait=lambda reading, check: None, _guard=lambda check, **kwargs: None)
            with self.assertRaises(BrokenPipeError):
                c._Connection._send(primitive, b"no-retry", (fd,), lambda: None)
            self.assertTrue(primitive._rights_may_have_sent)
            self.assertFalse(primitive._acked)
        finally:
            os.close(fd); left.close(); right.close()


if __name__ == "__main__":
    unittest.main()
