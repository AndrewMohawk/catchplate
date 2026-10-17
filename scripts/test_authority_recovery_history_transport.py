"""Bounded raw framing controls; no signed parent, database or authority proof."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from catchplate import authority_recovery_history_transport as transport


def request_header(tag, control, body):
    return tag + control.to_bytes(4, "big") + body.to_bytes(4, "big")


def response_frame(control=b"OK", body=b"raw"):
    return (transport.RESPONSE_MAGIC + len(control).to_bytes(4, "big")
        + len(body).to_bytes(4, "big") + control + body)


class SocketDouble:
    """Byte-stream boundary double; never a real peer/admission substitute."""

    def __init__(self, incoming=b"", chunk=1024, close_failure=None):
        self.incoming, self.chunk = incoming, chunk
        self.sent, self.read_sizes, self.timeouts = [], [], []
        self.connected, self.shutdowns, self.closes = [], [], 0
        self.close_failure = close_failure

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, path):
        self.connected.append(path)

    def sendall(self, raw):
        self.sent.append(raw)

    def shutdown(self, direction):
        self.shutdowns.append(direction)

    def recv(self, maximum):
        self.read_sizes.append(maximum)
        size = min(maximum, self.chunk, len(self.incoming))
        result, self.incoming = self.incoming[:size], self.incoming[size:]
        return result

    def close(self):
        self.closes += 1
        if self.close_failure is not None:
            raise self.close_failure


class RecoveryHistoryTransportTests(unittest.TestCase):
    def exchange(self, stream, **changes):
        arguments = dict(action="read", control_bytes=b"{}", body_bytes=None,
            original_deadline_ns=1000, expected_peer_uid=1000, expected_peer_gid=1000)
        arguments.update(changes)
        with (mock.patch.object(transport.socket, "socket", return_value=stream) as factory,
              mock.patch.object(transport.authority_transport, "_peer_identity", return_value=(1000, 1000, 123))):
            result = transport._socket_exchange("/component.sock", **arguments)
        factory.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        return result

    def test_real_unix_peer_exchange_preserves_opaque_bytes_and_wire_metrics(self):
        failures, requests = [], []
        deadline = time.monotonic_ns() + 3_000_000_000
        with tempfile.TemporaryDirectory(prefix="history-wire-") as directory:
            path = str(Path(directory) / "socket")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                listener.settimeout(3)
                def serve():
                    try:
                        with listener.accept()[0] as connection:
                            # The actual peer is checked before any prefix read.
                            uid, gid, _ = transport.authority_transport._peer_identity(connection)
                            if (uid, gid) != (os.getuid(), os.getgid()):
                                raise AssertionError("unexpected local component peer")
                            prefix = transport.wire._recv_prefix(connection, deadline_ns=deadline)
                            requests.append(transport._recv_request(connection, prefix=prefix, deadline_ns=deadline))
                            transport._send_response(connection, control_bytes=b"OK", body_bytes=b"\x00\xffraw",
                                deadline_ns=deadline)
                    except BaseException as exc:
                        failures.append(exc)
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                try:
                    result = transport._socket_exchange(path, action="persist", control_bytes=b"not-json",
                        body_bytes=b"\x00\xffproof", original_deadline_ns=deadline,
                        expected_peer_uid=os.getuid(), expected_peer_gid=os.getgid())
                finally:
                    thread.join(4)
                self.assertFalse(thread.is_alive())
        if failures:
            raise failures[0]
        self.assertEqual((requests[0].action, requests[0].control_bytes, requests[0].body_bytes),
                         ("persist", b"not-json", b"\x00\xffproof"))
        self.assertEqual((result.control_bytes, result.body_bytes), (b"OK", b"\x00\xffraw"))
        self.assertEqual(result.metrics.request, transport.FrameMetrics(8, 7, 17, 32))
        self.assertEqual(result.metrics.response, transport.FrameMetrics(2, 5, 16, 23))
        self.assertEqual(requests[0].metrics, result.metrics.request)
        with self.assertRaises(FrozenInstanceError):
            result.body_bytes = b"changed"

    def test_read_frame_is_zero_body_and_fragmented_response_is_exact(self):
        stream = SocketDouble(response_frame(), chunk=1)
        with mock.patch.object(transport.wire.time, "monotonic_ns", return_value=10):
            result = self.exchange(stream)
            request = transport._recv_request(SocketDouble(request_header(b"R", 2, 0) + b"{}", chunk=1),
                prefix=transport.REQUEST_MAGIC, deadline_ns=1000)
        self.assertEqual(b"".join(stream.sent), transport.REQUEST_MAGIC + request_header(b"R", 2, 0) + b"{}")
        self.assertEqual((request.action, request.body_bytes), ("read", None))
        self.assertEqual(result.body_bytes, b"raw")
        self.assertEqual(stream.shutdowns, [socket.SHUT_WR])
        self.assertEqual(stream.closes, 1)
        self.assertTrue(stream.timeouts)
        self.assertTrue(all(value == 990 / 1_000_000_000 for value in stream.timeouts))

    def test_invalid_lengths_and_tags_are_rejected_before_body_reads(self):
        requests = ((b"X", 2, 1), (b"P", 1, 1), (b"P", 2, 0), (b"R", 2, 1),
                    (b"P", transport.MAX_CONTROL_BYTES + 1, 1), (b"P", 2, transport.MAX_BODY_BYTES + 1))
        with mock.patch.object(transport.wire.time, "monotonic_ns", return_value=10):
            for tag, control, body in requests:
                with self.subTest(tag=tag, control=control, body=body):
                    stream = SocketDouble(request_header(tag, control, body))
                    with self.assertRaises(transport.AuthorityTransportError):
                        transport._recv_request(stream, prefix=transport.REQUEST_MAGIC, deadline_ns=1000)
                    self.assertEqual(stream.read_sizes, [9])
            for control, body in ((1, 1), (2, 0), (transport.MAX_RESPONSE_CONTROL_BYTES + 1, 1),
                                  (2, transport.MAX_BODY_BYTES + 1)):
                with self.subTest(response_control=control, response_body=body):
                    stream = SocketDouble(transport.RESPONSE_MAGIC + control.to_bytes(4, "big") + body.to_bytes(4, "big"))
                    with self.assertRaises(transport.AuthorityTransportError):
                        transport._recv_response(stream, 1000)
                    self.assertEqual(stream.read_sizes, [8, 8])

    def test_wrong_magic_early_eof_trailing_bytes_and_nonexact_inputs_refuse(self):
        with mock.patch.object(transport.wire.time, "monotonic_ns", return_value=10):
            for raw in (b"wrong!!!", response_frame()[:-1], response_frame() + b"extra"):
                with self.subTest(raw_length=len(raw)), self.assertRaises(transport.AuthorityTransportError):
                    self.exchange(SocketDouble(raw))
            for raw in (request_header(b"P", 2, 1) + b"{}", request_header(b"R", 2, 0) + b"{}extra"):
                with self.subTest(request_length=len(raw)), self.assertRaises(transport.AuthorityTransportError):
                    transport._recv_request(SocketDouble(raw), prefix=transport.REQUEST_MAGIC, deadline_ns=1000)
            stream = SocketDouble()
            with self.assertRaises(transport.AuthorityTransportError):
                transport._recv_request(stream, prefix=b"wrong!!!", deadline_ns=1000)
            self.assertEqual(stream.read_sizes, [])
            for changes in (dict(action="READ"), dict(action=True), dict(body_bytes=b""),
                            dict(control_bytes=bytearray(b"{}")), dict(expected_peer_uid=True)):
                with self.subTest(changes=tuple(changes)), mock.patch.object(transport.socket, "socket") as factory:
                    arguments = dict(action="read", control_bytes=b"{}", body_bytes=None, original_deadline_ns=1000,
                        expected_peer_uid=1000, expected_peer_gid=1000)
                    arguments.update(changes)
                    with self.assertRaises(transport.AuthorityTransportError):
                        transport._socket_exchange("/component.sock", **arguments)
                    factory.assert_not_called()

    def test_peer_refusal_precedes_send_and_cancellation_preserves_original(self):
        with mock.patch.object(transport.wire.time, "monotonic_ns", return_value=10):
            stream = SocketDouble(response_frame())
            with mock.patch.object(transport.socket, "socket", return_value=stream), \
                    mock.patch.object(transport.authority_transport, "_peer_identity", return_value=(1001, 1000, 123)):
                with self.assertRaises(transport.AuthorityTransportError):
                    transport._socket_exchange("/component.sock", action="read", control_bytes=b"{}", body_bytes=None,
                        original_deadline_ns=1000, expected_peer_uid=1000, expected_peer_gid=1000)
            self.assertEqual((stream.sent, stream.closes), ([], 1))
            failure = KeyboardInterrupt()
            stream = SocketDouble(close_failure=RuntimeError("synthetic close failure"))
            with mock.patch.object(transport.socket, "socket", return_value=stream), \
                    mock.patch.object(transport.authority_transport, "_peer_identity", side_effect=failure):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    transport._socket_exchange("/component.sock", action="read", control_bytes=b"{}", body_bytes=None,
                        original_deadline_ns=1000, expected_peer_uid=1000, expected_peer_gid=1000)
            self.assertIs(caught.exception, failure)
            self.assertEqual((stream.sent, stream.closes), ([], 1))

    def test_original_deadline_is_not_renewed_at_expiry_or_during_response(self):
        with mock.patch.object(transport.wire, "_deadline_ns", side_effect=AssertionError("deadline renewal")):
            with mock.patch.object(transport.wire.time, "monotonic_ns", return_value=1000), \
                    mock.patch.object(transport.socket, "socket") as factory:
                with self.assertRaises(transport.AuthorityTransportError):
                    transport._socket_exchange("/component.sock", action="read", control_bytes=b"{}", body_bytes=None,
                        original_deadline_ns=1000, expected_peer_uid=1000, expected_peer_gid=1000)
                factory.assert_not_called()
            stream = SocketDouble(response_frame())
            with mock.patch.object(transport.wire.time, "monotonic_ns", return_value=10) as clock:
                original_recv = stream.recv
                def late_recv(size):
                    value = original_recv(size)
                    clock.return_value = 1000
                    return value
                stream.recv = late_recv
                with self.assertRaises(transport.AuthorityTransportError):
                    self.exchange(stream)
            self.assertEqual(stream.closes, 1)


if __name__ == "__main__":
    unittest.main()
