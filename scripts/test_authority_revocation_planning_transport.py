#!/usr/bin/env python3
"""Actual planning framing over deterministic OS observations, not admission.

The reused recorder supplies only socket bytes, peer credentials, clocks and
native failures. No successful planner, root reader, configuration, registry or
proof result is substituted. These four framing-only controls remain unexecuted
under goal.md. Cryptographic, configured-client, configured-receiver and full-flow
coverage is deferred; no live peer, planning execution or database truth is claimed.
"""
from __future__ import annotations

from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_revocation_planning_transport as transport
import test_authority_revocation_writer_transport as os_oracle


REQUEST_MAGIC = b"SWRP\x00\x00\x00\x01"
RESPONSE_MAGIC = b"SWRS\x00\x00\x00\x01"
REQUEST_LIMITS = (4 * 1024 * 1024, 64 * 1024 * 1024, 64 * 1024 * 1024,
    512 * 1024, 512 * 1024)
RESPONSE_LIMITS = (64 * 1024 * 1024, 512 * 1024)
TOTAL_LIMIT = 64 * 1024 * 1024
NAMES = ("control_bytes", "request_bytes", "evidence_bytes", "context_bytes", "root_inventory_bytes")
ORIGINALS = (b'{ "control":1 }', b'{"request":2}', b"\xffopaque evidence\x00",
    b"not parsed context9", b'{ "inventory":3 }')
RESPONSE = (b"\xfforiginal signed plan\x00", b'{ "original":"context" }')
START, DEADLINE = os_oracle.START, os_oracle.DEADLINE
SocketRecorder, ClockRecorder, socket_scope = os_oracle.SocketRecorder, os_oracle.ClockRecorder, os_oracle.socket_scope


def request_header(lengths, magic=REQUEST_MAGIC):
    return magic + b"".join(size.to_bytes(8, "big") for size in lengths)


def request_segments(originals=ORIGINALS):
    return (request_header(tuple(map(len, originals))), *originals)


def response_header(lengths, magic=RESPONSE_MAGIC):
    return magic + b"".join(size.to_bytes(8, "big") for size in lengths)


def response_segments(originals=RESPONSE):
    return (response_header(tuple(map(len, originals))), *originals)


def request(originals=ORIGINALS, **changes):
    return transport._socket_request("/fixture/planner.sock", **{
        **dict(zip(NAMES, originals)), "timeout_seconds": 1.0,
        "expected_peer_uid": 1001, "expected_peer_gid": 1002, **changes})


def receive(connection, *, deadline_ns=DEADLINE):
    prefix = transport._recv_prefix(connection, deadline_ns=deadline_ns)
    return transport._recv_request(connection, deadline_ns=deadline_ns, prefix=prefix)


class RevocationPlanningTransportTests(unittest.TestCase):
    def test_literal_distinct_frames_preserve_fragmented_opaque_originals_and_shared_io(self):
        self.assertEqual(transport.TRANSFER_SCHEMA, "serverware.policyAuthorityRevocationPlanningTransfer/v1")
        self.assertEqual((transport.REQUEST_MAGIC, transport.RESPONSE_MAGIC), (REQUEST_MAGIC, RESPONSE_MAGIC))
        self.assertEqual((transport._REQUEST_LIMITS, transport._RESPONSE_LIMITS), (REQUEST_LIMITS, RESPONSE_LIMITS))
        self.assertEqual((transport.MAX_REQUEST_BYTES, transport.MAX_RESPONSE_BYTES), (TOTAL_LIMIT, TOTAL_LIMIT))
        self.assertIs(transport._deadline_ns, transport.io._deadline_ns)
        self.assertIs(transport._check_deadline, transport.io._check_deadline)
        self.assertIs(transport._recv_prefix, transport.io._recv_prefix)
        self.assertEqual((transport.io.REQUEST_MAGIC, transport.io.ACK_MAGIC),
            (b"SWRW\x00\x00\x00\x01", b"SWRA\x00\x00\x00\x01"))
        for fragment in (1, 3, None):
            received = SocketRecorder(request_segments(), fragment_size=fragment)
            with self.subTest(fragment=fragment), socket_scope(received):
                originals = receive(received)
            self.assertIs(type(originals), tuple)
            self.assertEqual(originals, ORIGINALS)
            self.assertTrue(all(type(raw) is bytes for raw in originals))
            self.assertEqual(received.received_bytes, 48 + sum(map(len, ORIGINALS)))
            self.assertEqual((received.recv_sizes[-1], received.close_count, received.sent), (1, 0, []))
            sent = SocketRecorder()
            with socket_scope(sent):
                transport._send_response(sent, *RESPONSE, deadline_ns=DEADLINE)
            self.assertEqual(sent.sent, list(response_segments()))
            self.assertEqual(sent.close_count, 0)
            connection = SocketRecorder(response_segments(), fragment_size=fragment)
            with socket_scope(connection):
                response = request()
            self.assertIs(type(response), tuple)
            self.assertEqual(response, RESPONSE)
            self.assertTrue(all(type(raw) is bytes for raw in response))
            self.assertEqual(b"".join(connection.sent), b"".join(request_segments()))
            self.assertEqual((connection.recv_sizes[-1], connection.close_count), (1, 1))

    def test_all_request_lengths_and_aggregate_are_admitted_before_any_body_read(self):
        cases = []
        for index, maximum in enumerate(REQUEST_LIMITS):
            for size in (0, 1, maximum + 1, (1 << 64) - 1):
                lengths = [2] * 5
                lengths[index] = size
                cases.append(tuple(lengths))
        cases.append((2, TOTAL_LIMIT - 7, 2, 2, 2))
        for lengths in cases:
            connection = SocketRecorder((request_header(lengths), b"unread request body"))
            with self.subTest(lengths=lengths), socket_scope(connection):
                with self.assertRaises(transport.AuthorityTransportError):
                    receive(connection)
            self.assertEqual(connection.received_bytes, 48)
            self.assertEqual(sum(connection.recv_sizes), 48)
            self.assertEqual(connection.close_count, 0)
        for lengths in (None, [2] * 5, (2,) * 4, (2,) * 6, (True, 2, 2, 2, 2), (2.0, 2, 2, 2, 2)):
            with self.subTest(lengths=lengths), self.assertRaises(transport.AuthorityTransportError):
                transport._validate_request_lengths(lengths)

    def test_both_response_lengths_and_aggregate_are_admitted_before_any_body_read(self):
        cases = []
        for index, maximum in enumerate(RESPONSE_LIMITS):
            for size in (0, 1, maximum + 1, (1 << 64) - 1):
                lengths = [2] * 2
                lengths[index] = size
                cases.append(tuple(lengths))
        cases.append((TOTAL_LIMIT - 1, 2))
        for lengths in cases:
            connection = SocketRecorder((response_header(lengths), b"unread response body"))
            with self.subTest(lengths=lengths), socket_scope(connection):
                with self.assertRaises(transport.AuthorityTransportError):
                    request()
            self.assertEqual(connection.received_bytes, 24)
            self.assertEqual(sum(connection.recv_sizes), 24)
            self.assertEqual(connection.close_count, 1)
        for lengths in (None, [2, 2], (2,), (2, 2, 2), (True, 2), (2, 2.0)):
            with self.subTest(lengths=lengths), self.assertRaises(transport.AuthorityTransportError):
                transport._validate_response_lengths(lengths)

    def test_exact_local_and_aggregate_limits_keep_each_io_chunk_bounded(self):
        for index, maximum in enumerate(REQUEST_LIMITS):
            originals = [b"{}"] * 5
            originals[index] = b"x" * min(maximum, TOTAL_LIMIT - 8)
            connection = SocketRecorder(request_segments(originals))
            with self.subTest(direction="request", index=index), socket_scope(connection):
                self.assertEqual(receive(connection), tuple(originals))
            self.assertLessEqual(max(connection.recv_sizes), 1024 * 1024)
            self.assertEqual(connection.received_bytes, 48 + sum(map(len, originals)))
            connection = SocketRecorder(response_segments())
            with socket_scope(connection):
                self.assertEqual(request(originals), RESPONSE)
            expected = iter(connection.sent)
            self.assertEqual(next(expected), request_header(tuple(map(len, originals))))
            for raw in originals:
                for offset in range(0, len(raw), 1024 * 1024):
                    self.assertEqual(next(expected), raw[offset:offset + 1024 * 1024])
            self.assertEqual(list(expected), [])
            self.assertLessEqual(max(map(len, connection.sent)), 1024 * 1024)
        for index, maximum in enumerate(RESPONSE_LIMITS):
            originals = [b"{}"] * 2
            originals[index] = b"x" * min(maximum, TOTAL_LIMIT - 2)
            connection = SocketRecorder(response_segments(originals))
            with self.subTest(direction="response", index=index), socket_scope(connection):
                self.assertEqual(request(), tuple(originals))
            self.assertLessEqual(max(connection.recv_sizes), 1024 * 1024)
            self.assertEqual(connection.received_bytes, 24 + sum(map(len, originals)))
            connection = SocketRecorder()
            with socket_scope(connection):
                transport._send_response(connection, *originals, deadline_ns=DEADLINE)
            expected = iter(connection.sent)
            self.assertEqual(next(expected), response_header(tuple(map(len, originals))))
            for raw in originals:
                for offset in range(0, len(raw), 1024 * 1024):
                    self.assertEqual(next(expected), raw[offset:offset + 1024 * 1024])
            self.assertEqual(list(expected), [])
            self.assertLessEqual(max(map(len, connection.sent)), 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
