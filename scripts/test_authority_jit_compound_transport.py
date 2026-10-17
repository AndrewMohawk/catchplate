"""Bounded opaque planning framing controls; no signed plan or DB success."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from catchplate import authority_jit_compound_transport as source
from test_authority_jit_original_transport import SocketDouble


ORIGINALS = (b"parent", b"request", b"context", b"manifest")


def frame(magic, bodies):
    return magic + b"".join(len(body).to_bytes(4, "big") for body in bodies) + b"".join(bodies)


class JitCompoundTransportControls(unittest.TestCase):
    def test_magics_limits_and_exact_distinct_body_schedule(self):
        self.assertEqual(source.REQUEST_MAGIC, b"SWJP\0\0\0\1")
        self.assertEqual(source.RESPONSE_MAGIC, b"SWJQ\0\0\0\1")
        self.assertEqual(source.REQUEST_LIMITS, (32768, source.plan.source.authority.MAX_REQUEST_BYTES))
        self.assertEqual(source.REPLY_LIMITS, (source.plan.MAX_PARENT_BYTES,
            source.plan.source.authority.MAX_REQUEST_BYTES, source.plan.MAX_CONTEXT_BYTES,
            source.plan.MAX_MANIFEST_BYTES))
        source._lengths(source.REQUEST_LIMITS, source.REQUEST_LIMITS)
        source._lengths(source.REPLY_LIMITS, source.REPLY_LIMITS)
        for bodies in (list(ORIGINALS), ORIGINALS[:3], (*ORIGINALS[:3], bytearray(b"xx"))):
            with self.assertRaises(source.AuthorityTransportError):
                source._bodies(bodies, source.REPLY_LIMITS)

    def test_real_unix_peer_exchange_retains_raw_four_and_actual_metrics(self):
        failures, received = [], []
        deadline = time.monotonic_ns() + 3_000_000_000
        with tempfile.TemporaryDirectory(prefix="jit-plan-wire-") as directory:
            path = str(Path(directory) / "socket")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                listener.settimeout(3)

                def serve():
                    try:
                        with listener.accept()[0] as connection:
                            uid, gid, _ = source.authority_transport._peer_identity(connection)
                            if (uid, gid) != (os.getuid(), os.getgid()):
                                raise AssertionError("unexpected actual local peer")
                            prefix = source.io._recv_prefix(connection, deadline_ns=deadline)
                            received.append(source._recv_request(connection,
                                prefix=prefix, deadline_ns=deadline))
                            source._send_reply(connection, originals=ORIGINALS, deadline_ns=deadline)
                    except BaseException as exc:
                        failures.append(exc)

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                try:
                    reply = source._socket_exchange(path, control_bytes=b"opaque control",
                        request_bytes=b"request", original_deadline_ns=deadline,
                        expected_peer_uid=os.getuid(), expected_peer_gid=os.getgid())
                finally:
                    worker.join(4)
                self.assertFalse(worker.is_alive())
        if failures:
            raise failures[0]
        self.assertEqual(reply.originals, ORIGINALS)
        self.assertEqual((received[0].control_bytes, received[0].request_bytes),
            (b"opaque control", b"request"))
        self.assertEqual(reply.metrics.request, source.FrameMetrics((14, 7), 16, 37))
        self.assertEqual(reply.metrics.reply,
            source.FrameMetrics(tuple(map(len, ORIGINALS)), 24, 24 + sum(map(len, ORIGINALS))))
        self.assertEqual(received[0].metrics, reply.metrics.request)

    def test_all_declared_lengths_are_checked_before_any_body_read(self):
        with mock.patch.object(source.io.time, "monotonic_ns", return_value=10):
            for limits in (source.REQUEST_LIMITS, source.REPLY_LIMITS):
                for ordinal, maximum in enumerate(limits):
                    for wrong in (0, 1, maximum + 1):
                        values = [2] * len(limits)
                        values[ordinal] = wrong
                        stream = SocketDouble(b"".join(value.to_bytes(4, "big") for value in values))
                        with self.subTest(lengths=values), self.assertRaises(source.AuthorityTransportError):
                            source._recv_bodies(stream, limits, 1000)
                        self.assertEqual(stream.read_sizes, [4 * len(limits)])

    def test_fragmented_raw_bodies_wrong_prefix_eof_and_trailing_bytes(self):
        with mock.patch.object(source.io.time, "monotonic_ns", return_value=10):
            stream = SocketDouble(frame(source.RESPONSE_MAGIC, ORIGINALS), chunk=1)
            self.assertEqual(source._recv_reply(stream, 1000)[0], ORIGINALS)
            request = frame(source.REQUEST_MAGIC, (b"{}", b"\0\xff"))
            actual = source._recv_request(SocketDouble(request[8:], chunk=1),
                prefix=source.REQUEST_MAGIC, deadline_ns=1000)
            self.assertEqual(actual.request_bytes, b"\0\xff")
            for value in (frame(source.RESPONSE_MAGIC, ORIGINALS)[:-1],
                    frame(source.RESPONSE_MAGIC, ORIGINALS) + b"trailing", b"wrong!!!"):
                with self.assertRaises(source.AuthorityTransportError):
                    source._recv_reply(SocketDouble(value), 1000)
            stream = SocketDouble(request[8:])
            with self.assertRaises(source.AuthorityTransportError):
                source._recv_request(stream, prefix=b"SWJO\0\0\0\1", deadline_ns=1000)
            self.assertEqual(stream.read_sizes, [])

    def test_real_peer_admission_precedes_send_and_cancellation_preserves_first_failure(self):
        for peer in ((1001, 1000, 5), KeyboardInterrupt()):
            stream = SocketDouble(close_failure=RuntimeError("cleanup failure"))
            kwargs = {"side_effect": peer} if isinstance(peer, BaseException) else {"return_value": peer}
            refusal = KeyboardInterrupt if isinstance(peer, BaseException) else source.AuthorityTransportError
            with mock.patch.object(source.io.time, "monotonic_ns", return_value=10), \
                    mock.patch.object(source.socket, "socket", return_value=stream), \
                    mock.patch.object(source.authority_transport, "_peer_identity", **kwargs), \
                    self.assertRaises(refusal) as caught:
                source._socket_exchange("/bounded.sock", control_bytes=b"{}", request_bytes=b"{}",
                    original_deadline_ns=1000, expected_peer_uid=1000, expected_peer_gid=1000)
            self.assertEqual((stream.sent, stream.closes), ([], 1))
            if isinstance(peer, BaseException):
                self.assertIs(caught.exception, peer)

    def test_original_absolute_deadline_and_scalar_refusals_precede_socket_creation(self):
        with mock.patch.object(source.socket, "socket") as factory:
            for changes in ({"expected_peer_uid": True}, {"control_bytes": bytearray(b"{}")},
                    {"original_deadline_ns": True}, {"original_deadline_ns": 10}):
                arguments = dict(control_bytes=b"{}", request_bytes=b"{}",
                    original_deadline_ns=1000, expected_peer_uid=1000, expected_peer_gid=1000)
                arguments.update(changes)
                with mock.patch.object(source.io.time, "monotonic_ns", return_value=10), \
                        mock.patch.object(source.io, "_deadline_ns", side_effect=AssertionError("renewal")), \
                        self.assertRaises(source.AuthorityTransportError):
                    source._socket_exchange("/bounded.sock", **arguments)
            factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
