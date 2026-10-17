#!/usr/bin/env python3
"""Authored byte-transport controls against the real inert production helpers.

The socket recorder models reads, writes, peer-credential bytes and failures;
it neither opens a live socket nor supplies a successful authentication or
registry verdict. These tests establish no live peer, deadline, service route,
signature, database, or deployment evidence. They are unexecuted source in the
current implementation phase.
"""
from __future__ import annotations

from pathlib import Path
import socket
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_transport as transport


REQUEST_LIMIT = 4 * 1024 * 1024
LEGACY_LIMIT = 64 * 1024 * 1024
PEER_OPTION = getattr(socket, "SO_PEERCRED", 17)


def framed(raw):
    return len(raw).to_bytes(8, "big") + raw


class SocketRecorder:
    """Only an operating-system byte/exception model, not an authority mock."""

    def __init__(self, incoming=b"", *, fragment_size=None, uid=1001, gid=1002,
                 fail_at=None, failure=None):
        self.incoming = incoming
        self.offset = 0
        self.fragment_size = fragment_size
        self.uid = uid
        self.gid = gid
        self.fail_at = fail_at
        self.failure = failure if failure is not None else OSError("model transport failure")
        self.events = []
        self.recv_sizes = []
        self.sent = []
        self.close_count = 0

    def _event(self, name, *arguments):
        self.events.append((name, *arguments))
        if self.fail_at == name:
            raise self.failure

    def settimeout(self, value):
        self._event("settimeout", value)

    def connect(self, path):
        self._event("connect", path)

    def getsockopt(self, level, option, size):
        self._event("getsockopt", level, option, size)
        if (level, option, size) != (socket.SOL_SOCKET, PEER_OPTION, struct.calcsize("3i")):
            raise AssertionError("peer credential query is not exact")
        return struct.pack("3i", 7001, self.uid, self.gid)

    def recv(self, maximum):
        self._event("recv", maximum)
        self.recv_sizes.append(maximum)
        count = maximum if self.fragment_size is None else min(maximum, self.fragment_size)
        value = self.incoming[self.offset:self.offset + count]
        self.offset += len(value)
        return value

    def sendall(self, value):
        self._event("sendall", value)
        self.sent.append(value)

    def close(self):
        self.close_count += 1
        self._event("close")


def socket_api(connection):
    """Source socket constants and a recorder constructor, never live connect."""
    return SimpleNamespace(
        AF_UNIX=socket.AF_UNIX, SOCK_STREAM=socket.SOCK_STREAM,
        SOL_SOCKET=socket.SOL_SOCKET, SO_PEERCRED=PEER_OPTION,
        socket=Mock(return_value=connection),
    )


def request(raw):
    return transport._socket_request_revocation_bytes(
        "/fixture/authority.sock", raw, timeout_seconds=1.25,
        expected_peer_uid=1001, expected_peer_gid=1002,
    )


class AuthorityRevocationTransportTests(unittest.TestCase):
    def test_fragmented_header_and_body_preserve_opaque_original_bytes(self):
        for raw in (b"{}", b'{ "z":1, "a":2 }', b"\xff\x00[not JSON]", b"\x00\x00"):
            with self.subTest(raw=raw):
                connection = SocketRecorder(framed(raw), fragment_size=1)
                received = transport._recv_revocation_invocation_bytes(connection)
                self.assertEqual(received, raw)
                self.assertIs(type(received), bytes)
                self.assertEqual(connection.offset, 8 + len(raw))
                self.assertEqual(connection.recv_sizes[:8], list(range(8, 0, -1)))
                self.assertEqual(connection.close_count, 0)

    def test_receiver_reads_one_frame_without_consuming_the_next_header(self):
        first, second = b"\xffone", b"second\x00"
        connection = SocketRecorder(framed(first) + framed(second), fragment_size=3)
        self.assertEqual(transport._recv_revocation_invocation_bytes(connection), first)
        self.assertEqual(connection.offset, 8 + len(first))
        self.assertEqual(transport._recv_revocation_invocation_bytes(connection), second)
        self.assertEqual(connection.offset, len(connection.incoming))

    def test_short_header_and_body_fail_at_actual_eof_without_partial_result(self):
        for raw in (b"", b"\x00" * 7, (4).to_bytes(8, "big") + b"ab"):
            with self.subTest(raw=raw):
                connection = SocketRecorder(raw, fragment_size=2)
                with self.assertRaisesRegex(transport.AuthorityTransportError, "closed early"):
                    transport._recv_revocation_invocation_bytes(connection)
                self.assertEqual(connection.offset, len(raw))
                self.assertEqual(connection.close_count, 0)

    def test_successor_rejects_bad_frame_lengths_before_any_body_read(self):
        for size in (0, 1, REQUEST_LIMIT + 1, LEGACY_LIMIT, (1 << 64) - 1):
            with self.subTest(size=size):
                connection = SocketRecorder(size.to_bytes(8, "big") + b"unread body")
                with self.assertRaisesRegex(transport.AuthorityTransportError, "message size"):
                    transport._recv_revocation_invocation_bytes(connection)
                self.assertEqual(connection.recv_sizes, [8])
                self.assertEqual(connection.offset, 8)

    def test_exact_successor_ceiling_is_admitted_with_bounded_recv_chunks(self):
        raw = b"x" * REQUEST_LIMIT
        connection = SocketRecorder(framed(raw))
        self.assertEqual(transport._recv_revocation_invocation_bytes(connection), raw)
        self.assertEqual(connection.recv_sizes, [8] + [1024 * 1024] * 4)
        self.assertEqual(connection.offset, 8 + REQUEST_LIMIT)

    def test_legacy_ceiling_remains_distinct_without_allocating_oversize_body(self):
        raw = b"x" * (REQUEST_LIMIT + 1)
        connection = SocketRecorder(framed(raw))
        self.assertEqual(transport._recv_message_bytes(connection, maximum_bytes=LEGACY_LIMIT), raw)
        for size, message, reads in (
            (LEGACY_LIMIT, "closed early", [8, 1024 * 1024]),
            (LEGACY_LIMIT + 1, "message size", [8]),
        ):
            with self.subTest(size=size):
                connection = SocketRecorder(size.to_bytes(8, "big"))
                with self.assertRaisesRegex(transport.AuthorityTransportError, message):
                    transport._recv_message_bytes(connection, maximum_bytes=LEGACY_LIMIT)
                self.assertEqual(connection.recv_sizes, reads)

    def test_generic_frame_limits_are_exact_and_checked_before_io(self):
        for maximum in (True, 1, 4.0, "4", None, LEGACY_LIMIT + 1):
            with self.subTest(maximum=maximum):
                connection = SocketRecorder(framed(b"{}"))
                with self.assertRaisesRegex(transport.AuthorityTransportError, "transport limit"):
                    transport._recv_message_bytes(connection, maximum_bytes=maximum)
                with self.assertRaisesRegex(transport.AuthorityTransportError, "transport limit"):
                    transport._send_encoded_message(connection, b"{}", maximum_bytes=maximum)
                self.assertEqual(connection.events, [])

    def test_send_is_one_exact_frame_without_canonicalizing_or_decoding(self):
        for raw in (b"\xff\x00", b'{ "z":1, "a":2 }'):
            with self.subTest(raw=raw):
                connection = SocketRecorder()
                transport._send_encoded_message(connection, raw, maximum_bytes=REQUEST_LIMIT)
                self.assertEqual(connection.sent, [framed(raw)])
                self.assertEqual([item[0] for item in connection.events], ["sendall"])

    def test_invalid_original_request_never_opens_socket_or_sends_a_frame(self):
        class BytesSubclass(bytes):
            pass

        for raw in (None, "{}", bytearray(b"{}"), memoryview(b"{}"),
                    BytesSubclass(b"{}"), b"", b"x", b"x" * (REQUEST_LIMIT + 1)):
            with self.subTest(kind=type(raw).__name__):
                connection = SocketRecorder()
                api = socket_api(connection)
                with patch.object(transport, "socket", api):
                    with self.assertRaisesRegex(transport.AuthorityTransportError, "request bytes"):
                        request(raw)
                api.socket.assert_not_called()
                with self.assertRaisesRegex(transport.AuthorityTransportError, "response size"):
                    transport._send_encoded_message(connection, raw, maximum_bytes=REQUEST_LIMIT)
                self.assertEqual(connection.events, [])

    def test_raw_request_observes_peer_then_exact_original_send_and_raw_response(self):
        raw, reply = b'{ "signed":"original" }', b"\xffopaque reply\x00"
        connection = SocketRecorder(framed(reply), fragment_size=3)
        api = socket_api(connection)
        with patch.object(transport, "socket", api), patch.object(
            transport, "_send_encoded_message", wraps=transport._send_encoded_message,
        ) as sent:
            self.assertEqual(request(raw), reply)
        api.socket.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        self.assertIs(sent.call_args.args[0], connection)
        self.assertIs(sent.call_args.args[1], raw)
        self.assertEqual(sent.call_args.kwargs, {"maximum_bytes": REQUEST_LIMIT})
        self.assertEqual(connection.sent, [framed(raw)])
        self.assertEqual(connection.events[:3], [
            ("settimeout", 1.25), ("connect", "/fixture/authority.sock"),
            ("getsockopt", socket.SOL_SOCKET, PEER_OPTION, struct.calcsize("3i")),
        ])
        self.assertEqual(connection.events[3][0], "sendall")
        self.assertEqual(connection.events[-1], ("close",))
        self.assertEqual(connection.close_count, 1)

    def test_raw_request_exact_ceiling_is_sent_and_response_ceiling_is_enforced(self):
        raw = b"x" * REQUEST_LIMIT
        connection = SocketRecorder(framed(b"{}"))
        with patch.object(transport, "socket", socket_api(connection)):
            self.assertEqual(request(raw), b"{}")
        self.assertEqual(connection.sent, [framed(raw)])
        connection = SocketRecorder((REQUEST_LIMIT + 1).to_bytes(8, "big") + b"unread")
        with patch.object(transport, "socket", socket_api(connection)):
            with self.assertRaisesRegex(transport.AuthorityTransportError, "message size"):
                request(b"{}")
        self.assertEqual(connection.recv_sizes, [8])
        self.assertEqual(connection.offset, 8)
        self.assertEqual(connection.close_count, 1)

    def test_uid_or_gid_mismatch_denies_before_send_and_still_closes(self):
        for uid, gid in ((1003, 1002), (1001, 1003), (1003, 1003)):
            with self.subTest(uid=uid, gid=gid):
                connection = SocketRecorder(framed(b"{}"), uid=uid, gid=gid)
                with patch.object(transport, "socket", socket_api(connection)):
                    with self.assertRaisesRegex(transport.AuthorityTransportError, "identity is not exact"):
                        request(b"{}")
                self.assertEqual(connection.sent, [])
                self.assertEqual(connection.recv_sizes, [])
                self.assertEqual(connection.close_count, 1)

    def test_every_post_open_transport_failure_closes_and_preserves_the_error(self):
        for stage in ("settimeout", "connect", "getsockopt", "sendall", "recv"):
            for error in (OSError("failure at " + stage), TimeoutError("deadline at " + stage)):
                with self.subTest(stage=stage, error=type(error).__name__):
                    connection = SocketRecorder(framed(b"{}"), fail_at=stage, failure=error)
                    with patch.object(transport, "socket", socket_api(connection)):
                        with self.assertRaises(type(error)) as caught:
                            request(b"{}")
                    self.assertIs(caught.exception, error)
                    self.assertEqual(connection.close_count, 1)
                    self.assertEqual(connection.events[-1], ("close",))

    def test_constructor_failure_and_truncated_response_do_not_retry(self):
        connection = SocketRecorder()
        api = socket_api(connection)
        error = OSError("socket constructor failed")
        api.socket.side_effect = error
        with patch.object(transport, "socket", api):
            with self.assertRaises(OSError) as caught:
                request(b"{}")
        self.assertIs(caught.exception, error)
        api.socket.assert_called_once()
        self.assertEqual(connection.events, [])
        connection = SocketRecorder((4).to_bytes(8, "big") + b"ab")
        api = socket_api(connection)
        with patch.object(transport, "socket", api):
            with self.assertRaisesRegex(transport.AuthorityTransportError, "closed early"):
                request(b"{}")
        api.socket.assert_called_once()
        self.assertEqual(connection.sent, [framed(b"{}")])
        self.assertEqual(connection.close_count, 1)

    def test_real_peer_decoder_and_fallback_deny_missing_credential_mechanisms(self):
        connection = SocketRecorder(uid=1201, gid=1202)
        with patch.object(transport, "socket", socket_api(connection)):
            self.assertEqual(transport._peer_identity(connection), (1201, 1202, 7001))
        fallback = SimpleNamespace(getpeereid=Mock(return_value=(1301, 1302)))
        with patch.object(transport, "socket", SimpleNamespace()):
            self.assertEqual(transport._peer_identity(fallback), (1301, 1302, None))
            fallback.getpeereid.assert_called_once_with()
            with self.assertRaisesRegex(transport.AuthorityTransportError, "unavailable"):
                transport._peer_identity(object())


if __name__ == "__main__":
    unittest.main()
