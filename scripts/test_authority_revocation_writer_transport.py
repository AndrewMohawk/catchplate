#!/usr/bin/env python3
"""Deterministic OS observations against the actual detached-byte transport.

The recorder supplies socket bytes, peer-credential bytes, clock observations
and native failures only. It supplies no successful configuration, launch,
registry, proof, SQL or custody verdict. The optional genuine ACK verification
uses independent scalar expectations, not fields learned from the response.
No live socket, actual peer, deadline scheduling or service admission is proved.
These are authored, unexecuted component controls; old transport IDs are intact.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import socket
import struct
import sys
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_revocation_writer_transport as transport


REQUEST_MAGIC = b"SWRW\x00\x00\x00\x01"
ACK_MAGIC = b"SWRA\x00\x00\x00\x01"
LIMITS = (4 * 1024 * 1024, 4 * 1024 * 1024, 64 * 1024 * 1024,
    512 * 1024, 64 * 1024 * 1024)
TOTAL_LIMIT = 64 * 1024 * 1024
ACK_LIMIT = 16384
NAMES = ("intent_bytes", "relay_bytes", "envelope_bytes",
    "evaluation_context_bytes", "historical_expectations_bytes")
ORIGINALS = (b'{ "intent":1 }', b'{"relay":2}', b"\xffopaque plan\x00",
    b"not parsed context", b'{ "history":3 }')
START = 1_000_000_000
DEADLINE = START + 1_000_000_000
PEER_OPTION = getattr(socket, "SO_PEERCRED", 17)


def request_header(lengths, magic=REQUEST_MAGIC):
    return magic + b"".join(length.to_bytes(8, "big") for length in lengths)


def request_segments(originals=ORIGINALS):
    return (request_header(tuple(map(len, originals))), *originals)


def ack_segments(raw):
    return (ACK_MAGIC + len(raw).to_bytes(8, "big"), raw)


class ClockRecorder:
    def __init__(self, value=START):
        self.value = value
        self.calls = 0
        self.failure = None

    def __call__(self):
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return self.value


class SocketRecorder:
    """Bounded segmented stream: recv never returns more than requested."""
    def __init__(self, incoming=(), *, fragment_size=None, uid=1001, gid=1002,
            hook=None, fail_at=None, failure=None, empty_failure=None):
        self.incoming = (incoming,) if type(incoming) is bytes else tuple(incoming)
        self.segment = self.offset = self.received_bytes = 0
        self.fragment_size, self.uid, self.gid = fragment_size, uid, gid
        self.hook, self.fail_at, self.empty_failure = hook, fail_at, empty_failure
        self.failure = OSError("recorded socket failure") if failure is None else failure
        self.events, self.sent, self.recv_sizes, self.timeouts = [], [], [], []
        self.counts = {}
        self.close_count = 0

    def event(self, name, *arguments):
        self.events.append((name, *arguments))
        self.counts[name] = self.counts.get(name, 0) + 1
        if self.hook is not None:
            self.hook(self, name, *arguments)
        if self.fail_at in (name, (name, self.counts[name])):
            raise self.failure

    def settimeout(self, value):
        self.timeouts.append(value)
        self.event("settimeout", value)

    def connect(self, path):
        self.event("connect", path)

    def getsockopt(self, level, option, size):
        self.event("getsockopt", level, option, size)
        if (level, option, size) != (socket.SOL_SOCKET, PEER_OPTION, struct.calcsize("3i")):
            raise AssertionError("unexpected peer query")
        return struct.pack("3i", 7001, self.uid, self.gid)

    def recv(self, maximum):
        if type(maximum) is not int or maximum < 1:
            raise AssertionError("recv count must be positive")
        self.recv_sizes.append(maximum)
        while self.segment < len(self.incoming) and self.offset == len(self.incoming[self.segment]):
            self.segment += 1
            self.offset = 0
        if self.segment == len(self.incoming):
            value = b""
        else:
            count = maximum if self.fragment_size is None else min(maximum, self.fragment_size)
            value = self.incoming[self.segment][self.offset:self.offset + count]
            self.offset += len(value)
        self.received_bytes += len(value)
        self.event("recv", maximum)
        if not value and self.empty_failure is not None:
            raise self.empty_failure
        return value

    def sendall(self, value):
        self.event("sendall", value)
        self.sent.append(value)

    def shutdown(self, how):
        self.event("shutdown", how)

    def close(self):
        self.close_count += 1
        self.event("close")


@contextmanager
def socket_scope(connection, clock=None):
    clock = ClockRecorder() if clock is None else clock
    constructor = Mock(return_value=connection)
    with patch.object(transport.time, "monotonic_ns", clock), \
            patch.object(transport.socket, "socket", constructor), \
            patch.object(transport.socket, "SO_PEERCRED", PEER_OPTION, create=True):
        yield constructor, clock


def request(originals=ORIGINALS, **overrides):
    arguments = {**dict(zip(NAMES, originals)), "timeout_seconds": 1.0,
        "expected_peer_uid": 1001, "expected_peer_gid": 1002, **overrides}
    return transport._socket_request("/fixture/writer.sock", **arguments)


def receive(connection, *, deadline_ns=DEADLINE):
    prefix = transport._recv_prefix(connection, deadline_ns=deadline_ns)
    return transport._recv_request(connection, deadline_ns=deadline_ns, prefix=prefix)


class RevocationWriterTransportTests(unittest.TestCase):
    def test_literal_fixed_header_and_fragmented_opaque_five_originals(self):
        for fragment in (1, 3, None):
            connection = SocketRecorder(request_segments(), fragment_size=fragment)
            with self.subTest(fragment=fragment), socket_scope(connection):
                result = receive(connection)
            self.assertIs(type(result), tuple)
            self.assertEqual(result, ORIGINALS)
            self.assertTrue(all(type(value) is bytes for value in result))
            self.assertEqual(connection.received_bytes, 48 + sum(map(len, ORIGINALS)))
            self.assertEqual(connection.recv_sizes[-1], 1)
            self.assertEqual(connection.close_count, 0)
            self.assertEqual(connection.sent, [])

    def test_all_five_lengths_and_aggregate_are_checked_before_body_reads(self):
        cases = []
        for index, maximum in enumerate(LIMITS):
            for value in (0, 1, maximum + 1, (1 << 64) - 1):
                lengths = [2] * 5
                lengths[index] = value
                cases.append(tuple(lengths))
        # Each field is locally admissible; only the shared cap denies this.
        cases.append((2, 2, TOTAL_LIMIT - 7, 2, 2))
        for lengths in cases:
            connection = SocketRecorder((request_header(lengths), b"unread body"))
            with self.subTest(lengths=lengths), socket_scope(connection):
                with self.assertRaises(transport.AuthorityTransportError):
                    receive(connection)
            self.assertEqual(connection.received_bytes, 48)
            self.assertEqual(sum(connection.recv_sizes), 48)
            self.assertEqual(connection.close_count, 0)

    def test_exact_local_and_aggregate_bounds_use_bounded_receives(self):
        # A 64 MiB plan/history alone cannot coexist with four minimum 2-byte
        # bodies. Their maximum admissible transfer is 64 MiB minus those 8 bytes.
        for index, maximum in enumerate(LIMITS):
            size = min(maximum, TOTAL_LIMIT - 8)
            originals = [b"{}"] * 5
            originals[index] = b"x" * size
            connection = SocketRecorder(request_segments(originals))
            with self.subTest(index=index), socket_scope(connection):
                self.assertEqual(receive(connection), tuple(originals))
            self.assertEqual(connection.received_bytes, 48 + size + 8)
            self.assertLessEqual(max(connection.recv_sizes), 1024 * 1024)
            self.assertEqual(connection.recv_sizes[-1], 1)
            connection = SocketRecorder(ack_segments(b"{}"))
            with socket_scope(connection):
                self.assertEqual(request(originals), b"{}")
            sent = iter(connection.sent)
            self.assertEqual(next(sent), request_header(tuple(map(len, originals))))
            for original in originals:
                for offset in range(0, len(original), 1024 * 1024):
                    self.assertEqual(next(sent), original[offset:offset + 1024 * 1024])
            self.assertEqual(list(sent), [])
            self.assertLessEqual(max(map(len, connection.sent)), 1024 * 1024)
            self.assertEqual(connection.close_count, 1)

    def test_bad_magic_and_each_truncated_header_never_return_a_request(self):
        header = request_header(tuple(map(len, ORIGINALS)))
        for cut in range(len(header)):
            connection = SocketRecorder(header[:cut], fragment_size=3)
            with self.subTest(cut=cut), socket_scope(connection):
                with self.assertRaises(transport.AuthorityTransportError):
                    receive(connection)
            self.assertEqual(connection.received_bytes, cut)
        for magic in (ACK_MAGIC, b"SWRW\x00\x00\x00\x02", b"XXXXXXXX"):
            connection = SocketRecorder((request_header([2] * 5, magic), b"unread"))
            with self.subTest(magic=magic), socket_scope(connection):
                with self.assertRaises(transport.AuthorityTransportError):
                    receive(connection)
            self.assertLessEqual(connection.received_bytes, 48)

    def test_short_each_body_and_trailing_stream_data_fail_closed(self):
        header = request_header(tuple(map(len, ORIGINALS)))
        for index, original in enumerate(ORIGINALS):
            for cut in (0, len(original) - 1):
                connection = SocketRecorder((header, *ORIGINALS[:index], original[:cut]))
                with self.subTest(index=index, cut=cut), socket_scope(connection):
                    with self.assertRaises(transport.AuthorityTransportError):
                        receive(connection)
        connection = SocketRecorder((*request_segments(), b"extra request"))
        with socket_scope(connection), self.assertRaises(transport.AuthorityTransportError):
            receive(connection)
        self.assertEqual(connection.received_bytes, 48 + sum(map(len, ORIGINALS)) + 1)
        error = TimeoutError("peer never half-closed")
        connection = SocketRecorder(request_segments(), empty_failure=error)
        with socket_scope(connection), self.assertRaises(TimeoutError) as caught:
            receive(connection)
        self.assertIs(caught.exception, error)

    def test_client_peer_precedes_exact_send_halfclose_and_original_ack(self):
        raw_ack = b"\xffopaque ACK\x00"
        connection = SocketRecorder(ack_segments(raw_ack), fragment_size=3)
        with socket_scope(connection) as (opened, _clock):
            self.assertEqual(request(), raw_ack)
        opened.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        self.assertEqual(b"".join(connection.sent), b"".join(request_segments()))
        names = [event[0] for event in connection.events]
        self.assertLess(names.index("connect"), names.index("getsockopt"))
        self.assertLess(names.index("getsockopt"), names.index("sendall"))
        self.assertLess(max(index for index, name in enumerate(names) if name == "sendall"), names.index("shutdown"))
        self.assertLess(names.index("shutdown"), names.index("recv"))
        self.assertEqual([event for event in connection.events if event[0] == "shutdown"], [("shutdown", socket.SHUT_WR)])
        self.assertEqual(connection.recv_sizes[-1], 1)
        self.assertEqual(connection.close_count, 1)
        self.assertEqual(connection.events[-1], ("close",))

    def test_wrong_peer_denies_before_send_or_response_read(self):
        for uid, gid in ((1003, 1002), (1001, 1003), (1003, 1003)):
            connection = SocketRecorder(ack_segments(b"{}"), uid=uid, gid=gid)
            with self.subTest(uid=uid, gid=gid), socket_scope(connection):
                with self.assertRaises(transport.AuthorityTransportError):
                    request()
            self.assertEqual(connection.sent, [])
            self.assertEqual(connection.recv_sizes, [])
            self.assertNotIn("shutdown", connection.counts)
            self.assertEqual(connection.close_count, 1)

    def test_ack_sender_preserves_bytes_and_enforces_its_separate_cap(self):
        class BytesSubclass(bytes):
            pass

        for raw in (b"{}", b'{ "not":"canonical" }', b"x" * ACK_LIMIT):
            connection = SocketRecorder()
            with self.subTest(size=len(raw)), socket_scope(connection):
                transport._send_ack(connection, raw, deadline_ns=DEADLINE)
            self.assertEqual(b"".join(connection.sent), b"".join(ack_segments(raw)))
            self.assertEqual(connection.close_count, 0)
        for raw in (None, "{}", bytearray(b"{}"), memoryview(b"{}"),
                BytesSubclass(b"{}"), b"", b"x", b"x" * (ACK_LIMIT + 1)):
            connection = SocketRecorder()
            with self.subTest(kind=type(raw).__name__), socket_scope(connection):
                with self.assertRaises(transport.AuthorityTransportError):
                    transport._send_ack(connection, raw, deadline_ns=DEADLINE)
            self.assertEqual(connection.events, [])

    def test_every_original_is_exact_and_preflight_rejects_before_socket_creation(self):
        class BytesSubclass(bytes):
            pass

        for index in range(5):
            for value in (None, "{}", bytearray(b"{}"), memoryview(b"{}"),
                    BytesSubclass(b"{}"), b"", b"x"):
                originals = list(ORIGINALS)
                originals[index] = value
                connection = SocketRecorder(ack_segments(b"{}"))
                with self.subTest(index=index, kind=type(value).__name__), socket_scope(connection) as (opened, _clock):
                    with self.assertRaises(transport.AuthorityTransportError):
                        request(originals)
                opened.assert_not_called()
                self.assertEqual(connection.events, [])
        for index, maximum in enumerate(LIMITS):
            originals = [b"{}"] * 5
            # For the 64 MiB bodies this hits the aggregate guard while still
            # satisfying the local limit. Header negatives separately cover
            # each locally oversized 64-bit length without allocating its body.
            originals[index] = b"x" * min(maximum + 1, TOTAL_LIMIT - 7)
            connection = SocketRecorder()
            with self.subTest(index=index), socket_scope(connection) as (opened, _clock):
                with self.assertRaises(transport.AuthorityTransportError):
                    request(originals)
            opened.assert_not_called()
            self.assertEqual(connection.events, [])

    def test_ack_magic_size_truncation_and_trailing_bytes_never_publish(self):
        for size in (0, 1, ACK_LIMIT + 1, (1 << 64) - 1):
            connection = SocketRecorder((ACK_MAGIC + size.to_bytes(8, "big"), b"unread"))
            with self.subTest(size=size), socket_scope(connection):
                with self.assertRaises(transport.AuthorityTransportError):
                    request()
            self.assertEqual(connection.received_bytes, 16)
            self.assertEqual(sum(connection.recv_sizes), 16)
            self.assertEqual(connection.close_count, 1)
        raw = b"opaque ACK"
        framed = b"".join(ack_segments(raw))
        for incoming in ([framed[:cut] for cut in range(16)]
                + [framed[:-1], framed + b"trailing", REQUEST_MAGIC + framed[8:]]):
            connection = SocketRecorder(incoming, fragment_size=3)
            with self.subTest(incoming=incoming), socket_scope(connection):
                with self.assertRaises(transport.AuthorityTransportError):
                    request()
            self.assertEqual(connection.close_count, 1)
        connection = SocketRecorder(ack_segments(b"x" * ACK_LIMIT))
        with socket_scope(connection):
            self.assertEqual(request(), b"x" * ACK_LIMIT)
        self.assertEqual(connection.recv_sizes[-1], 1)
        self.assertEqual(connection.close_count, 1)

    def test_timeout_domain_is_exact_finite_bounded_and_uses_one_initial_clock(self):
        for timeout in (0.05, 1, 1.25, 30.0):
            clock = ClockRecorder()
            with self.subTest(timeout=timeout), patch.object(transport.time, "monotonic_ns", clock):
                self.assertEqual(transport._deadline_ns(timeout), START + int(timeout * 1_000_000_000))
            self.assertEqual(clock.calls, 1)
        for timeout in (True, False, None, "1", 0, -1, 0.049, 30.001,
                float("nan"), float("inf"), float("-inf")):
            connection = SocketRecorder()
            with self.subTest(timeout=timeout), socket_scope(connection) as (opened, _clock):
                with self.assertRaises(transport.AuthorityTransportError):
                    request(timeout_seconds=timeout)
            opened.assert_not_called()
            self.assertEqual(connection.events, [])
        clock = ClockRecorder()
        with patch.object(transport.time, "monotonic_ns", clock):
            self.assertEqual(transport._check_deadline(DEADLINE), DEADLINE - START)
            for deadline in (True, False, None, 0, -1, float(DEADLINE), str(DEADLINE)):
                with self.subTest(deadline=deadline), self.assertRaises(transport.AuthorityTransportError):
                    transport._check_deadline(deadline)
            for now in (DEADLINE, DEADLINE + 1):
                clock.value = now
                with self.subTest(now=now), self.assertRaises(transport.AuthorityTransportError):
                    transport._check_deadline(DEADLINE)
        for now in (True, False, -1, None, 1.5):
            clock, connection = ClockRecorder(now), SocketRecorder()
            with self.subTest(clock=now), socket_scope(connection, clock) as (opened, _clock):
                with self.assertRaises(transport.AuthorityTransportError):
                    request()
            opened.assert_not_called()
            self.assertEqual(connection.events, [])
        for after_open in (False, True):
            error, clock = RuntimeError("native clock failed"), ClockRecorder()

            def poison_clock(_connection, name, *_arguments):
                if name == "connect":
                    clock.failure = error

            connection = SocketRecorder(ack_segments(b"{}"), hook=poison_clock)
            if not after_open:
                clock.failure = error
            with self.subTest(after_open=after_open), socket_scope(connection, clock) as (opened, _clock):
                with self.assertRaises(RuntimeError) as caught:
                    request()
            self.assertIs(caught.exception, error)
            self.assertEqual(opened.call_count, int(after_open))
            self.assertEqual(connection.close_count, int(after_open))

    def test_genuine_ack_verification_uses_original_bytes_and_independent_expected_fields(self):
        from serverware import authority_query_read_work as accounting
        from serverware import authority_revocation_writer_acknowledgment as acknowledgment
        import test_authority_revocation_writer_acknowledgment as ack_oracle

        fixture = ack_oracle.AckFixture()
        expected = ack_oracle.independent_ack_work(fixture.request_fields,
            fixture.writer_pin, fixture.acknowledgment_bytes)["verify"]["total"]
        meter = accounting._ValidationWork(accounting.QueryReadValidationLimits(*expected))
        connection = SocketRecorder(ack_segments(fixture.acknowledgment_bytes), fragment_size=7)
        with socket_scope(connection), patch.object(acknowledgment, "_sign_on_work",
                side_effect=AssertionError("transport must not re-sign")), patch.object(
                accounting._ValidationWork, "__init__", side_effect=AssertionError("transport work allocation")):
            received = request()
        self.assertEqual(received, fixture.acknowledgment_bytes)
        self.assertEqual(ack_oracle.oracle.units(meter.metrics), (0, 0, 0))
        self.assertIsNone(acknowledgment._verify_on_work(acknowledgment_bytes=received,
            request_fields=fixture.request_fields, writer_public_key=fixture.writer_public_key,
            expected_writer_spki_digest=fixture.writer_pin, work=meter))
        self.assertEqual(ack_oracle.oracle.units(meter.metrics), expected)
        # The same transport also returns untrusted noncanonical bytes. Only
        # the actual verifier rejects them; framing does not create a verdict.
        raw = fixture.acknowledgment_bytes + b" "
        connection = SocketRecorder(ack_segments(raw))
        with socket_scope(connection):
            self.assertEqual(request(), raw)
        rejected = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        with self.assertRaises(ValueError):
            acknowledgment._verify_on_work(acknowledgment_bytes=raw,
                request_fields=fixture.request_fields, writer_public_key=fixture.writer_public_key,
                expected_writer_spki_digest=fixture.writer_pin, work=rejected)

    def test_client_path_and_independent_peer_pins_reject_before_open(self):
        for name in ("expected_peer_uid", "expected_peer_gid"):
            for value in (True, False, -1, 1.0, "1001", None, 1 << 64):
                connection = SocketRecorder()
                with self.subTest(name=name, value=value), socket_scope(connection) as (opened, _clock):
                    with self.assertRaises(transport.AuthorityTransportError):
                        request(**{name: value})
                opened.assert_not_called()
                self.assertEqual(connection.events, [])
        for path in (None, b"/fixture/writer.sock", "relative.sock", "", "/bad\x00path", "/" + "x" * 108):
            connection = SocketRecorder()
            with self.subTest(path=path), socket_scope(connection) as (opened, _clock):
                with self.assertRaises(transport.AuthorityTransportError):
                    transport._socket_request(path, **dict(zip(NAMES, ORIGINALS)),
                        timeout_seconds=1.0, expected_peer_uid=1001, expected_peer_gid=1002)
            opened.assert_not_called()
            self.assertEqual(connection.events, [])

    def test_slow_progress_cannot_refresh_the_whole_transfer_deadline(self):
        clock = ClockRecorder()

        def advance(_connection, name, *_arguments):
            if name == "recv":
                clock.value += 100_000_000

        connection = SocketRecorder(request_segments(), fragment_size=1, hook=advance)
        with socket_scope(connection, clock), self.assertRaises(transport.AuthorityTransportError):
            receive(connection)
        self.assertEqual(clock.value, DEADLINE)
        self.assertEqual(connection.received_bytes, 10)
        self.assertEqual(connection.timeouts, [remaining / 10 for remaining in range(10, 0, -1)])
        self.assertEqual(connection.close_count, 0)

        clock = ClockRecorder()

        def cumulative(_connection, name, *_arguments):
            if name in {"connect", "getsockopt", "sendall", "shutdown", "recv"}:
                clock.value += 100_000_000

        connection = SocketRecorder(ack_segments(b"{}"), fragment_size=1, hook=cumulative)
        with socket_scope(connection, clock) as (opened, _clock), patch.object(
                transport, "_deadline_ns", wraps=transport._deadline_ns) as deadline:
            with self.assertRaises(transport.AuthorityTransportError):
                request()
        deadline.assert_called_once_with(1.0)
        opened.assert_called_once()
        self.assertGreaterEqual(clock.value, DEADLINE)
        self.assertTrue(all(0 < value <= 1.0 for value in connection.timeouts))
        self.assertTrue(all(right <= left for left, right in zip(connection.timeouts, connection.timeouts[1:])))
        self.assertEqual(connection.close_count, 1)

    def test_post_callback_deadlines_include_final_body_and_eof_observations(self):
        for stage in ("settimeout", "connect", "getsockopt", "sendall", "shutdown", "recv"):
            clock = ClockRecorder()

            def expire(_connection, name, *_arguments):
                if name == stage:
                    clock.value = DEADLINE

            connection = SocketRecorder(ack_segments(b"{}"), hook=expire)
            with self.subTest(stage=stage), socket_scope(connection, clock):
                with self.assertRaises(transport.AuthorityTransportError):
                    request()
            names = [event[0] for event in connection.events]
            self.assertEqual(names[-2:], [stage, "close"])
            self.assertEqual(connection.close_count, 1)
        for direction in ("request", "ack"):
            for final_eof in (False, True):
                clock = ClockRecorder()
                segments = request_segments() if direction == "request" else ack_segments(b"actual ACK")
                size = sum(map(len, segments))

                def expire_last(connection, name, *arguments):
                    if name == "recv" and connection.received_bytes == size:
                        if not final_eof or arguments == (1,):
                            clock.value = DEADLINE

                connection = SocketRecorder(segments, hook=expire_last)
                with self.subTest(direction=direction, eof=final_eof), socket_scope(connection, clock):
                    with self.assertRaises(transport.AuthorityTransportError):
                        receive(connection) if direction == "request" else request()
                self.assertEqual(connection.received_bytes, size)
                self.assertEqual(connection.recv_sizes[-1] == 1, final_eof)
                self.assertEqual(connection.close_count, int(direction == "ack"))

    def test_native_socket_failures_close_once_without_retry_or_substitution(self):
        for stage in ("settimeout", "connect", "getsockopt", "sendall", "shutdown", "recv"):
            for error in (OSError("failure at " + stage), TimeoutError("timeout at " + stage)):
                connection = SocketRecorder(ack_segments(b"{}"), fail_at=stage, failure=error)
                with self.subTest(stage=stage, kind=type(error).__name__), socket_scope(connection) as (opened, _clock):
                    with self.assertRaises(type(error)) as caught:
                        request()
                self.assertIs(caught.exception, error)
                opened.assert_called_once()
                self.assertEqual(connection.close_count, 1)
                self.assertEqual(connection.events[-1], ("close",))
        # A missing FIN is a blocking EOF observation, not successful custody.
        error = TimeoutError("ACK peer never closed")
        connection = SocketRecorder(ack_segments(b"{}"), empty_failure=error)
        with socket_scope(connection), self.assertRaises(TimeoutError) as caught:
            request()
        self.assertIs(caught.exception, error)
        self.assertEqual(connection.close_count, 1)

    def test_socket_creation_and_cleanup_failures_never_return_an_ack(self):
        error = OSError("socket constructor failure")
        connection = SocketRecorder()
        with socket_scope(connection) as (opened, _clock):
            opened.side_effect = error
            with self.assertRaises(OSError) as caught:
                request()
        self.assertIs(caught.exception, error)
        opened.assert_called_once()
        self.assertEqual(connection.events, [])
        error = OSError("close failure after original ACK")
        connection = SocketRecorder(ack_segments(b"{}"), fail_at="close", failure=error)
        with socket_scope(connection) as (opened, _clock):
            with self.assertRaises(OSError) as caught:
                request()
        self.assertIs(caught.exception, error)
        opened.assert_called_once()
        self.assertEqual(connection.close_count, 1)
        first, cleanup = OSError("first recv failure"), RuntimeError("cleanup failure")

        def fail_close(_connection, name, *_arguments):
            if name == "close":
                raise cleanup

        connection = SocketRecorder(ack_segments(b"{}"), fail_at="recv", failure=first, hook=fail_close)
        with socket_scope(connection), self.assertRaises(OSError) as caught:
            request()
        self.assertIs(caught.exception, first)
        self.assertEqual(connection.close_count, 1)
        for stage in ("constructor", "close"):
            clock = ClockRecorder()

            def expire_close(_connection, name, *_arguments):
                if name == "close" and stage == "close":
                    clock.value = DEADLINE

            connection = SocketRecorder(ack_segments(b"{}"), hook=expire_close)
            with self.subTest(stage=stage), socket_scope(connection, clock) as (opened, _clock):
                if stage == "constructor":
                    def opened_late(*_arguments):
                        clock.value = DEADLINE
                        return connection
                    opened.side_effect = opened_late
                with self.assertRaises(transport.AuthorityTransportError):
                    request()
            opened.assert_called_once()
            self.assertEqual(connection.close_count, 1)
            if stage == "constructor":
                self.assertEqual(connection.events, [("close",)])

    def test_explicit_second_call_reuses_originals_but_transport_never_retries(self):
        failed = SocketRecorder((ACK_MAGIC,))
        with socket_scope(failed) as (opened, _clock):
            with self.assertRaises(transport.AuthorityTransportError):
                request()
        opened.assert_called_once()
        self.assertEqual(failed.close_count, 1)
        # This is a separate caller decision with identical originals, not a
        # transport retry, custody recovery claim or renewed signed deadline.
        second = SocketRecorder(ack_segments(b"original ACK"))
        with socket_scope(second) as (opened, _clock):
            self.assertEqual(request(), b"original ACK")
        opened.assert_called_once()
        self.assertEqual(second.sent, failed.sent)
        self.assertEqual(b"".join(second.sent), b"".join(request_segments()))
        self.assertEqual(second.close_count, 1)


if __name__ == "__main__":
    unittest.main()
