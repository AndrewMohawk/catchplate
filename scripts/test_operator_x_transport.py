#!/usr/bin/env python3
"""Real HTTP parser with socket/TLS doubles; no provider or work admission.

The process audit hook refuses real DNS/connect/listen/SQLite. Test sockets are
in-memory byte streams, not a replacement certificate or accepted TLS evidence.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import operator_x_oauth_profile as profiles
from catchplate import operator_x_oauth_protocol as protocol
from catchplate import operator_x_transport as transport
from catchplate.http_client import HttpDeadline


def no_external_effects(event, args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"} or event.startswith("sqlite3."):
        raise AssertionError("transport tests forbid external effects")


sys.addaudithook(no_external_effects)
WORK = "8a9f4561-1045-4b67-9173-b186c6f76d7d"
SECRET = "synthetic-private-client-secret"
ACCESS = "synthetic-private-access-token"
REFRESH = "synthetic-private-refresh-token"


def wire(body, *, status=200, headers=()):
    return (f"HTTP/1.1 {status} Synthetic\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"".join((name + ": " + value + "\r\n").encode("ascii") for name, value in headers)
        + b"\r\n" + body)


def token_body():
    return json.dumps({"access_token": ACCESS, "refresh_token": REFRESH,
        "token_type": "bearer", "expires_in": 3600,
        "scope": " ".join(protocol.SCOPES)}, separators=(",", ":")).encode()


class Clock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class Socket:
    def __init__(self, pieces, *, clock=None, elapsed=0.0, handshake_error=None):
        self.pieces = list(pieces)
        self.clock, self.elapsed = clock, elapsed
        self.handshake_error = handshake_error
        self.sent, self.timeouts, self.events = [], [], []
        self.closed = False

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        self.events.append(("connect", address))

    def do_handshake(self):
        self.events.append(("handshake",))
        if self.handshake_error is not None:
            raise self.handshake_error

    def selected_alpn_protocol(self):
        return "http/1.1"

    def sendall(self, data):
        self.events.append(("send",))
        self.sent.append(bytes(data))

    def recv(self, maximum):
        if self.clock is not None:
            self.clock.value += self.elapsed
        if not self.pieces:
            return b""
        piece = self.pieces.pop(0)
        if isinstance(piece, BaseException):
            raise piece
        result, remainder = piece[:maximum], piece[maximum:]
        if remainder:
            self.pieces.insert(0, remainder)
        return result

    def close(self):
        self.closed = True


class XTransportTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.clock_patch = patch.object(transport.time, "monotonic", self.clock)
        self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)
        self.profile = profiles.build_profile(client_id="synthetic-client",
            public_origin="https://operator.example.com")
        self.request = protocol.refresh_request(self.profile, SECRET, "old-refresh")
        self.deadline = HttpDeadline(110.0)

    def send(self, pieces, *, request=None, elapsed=0.0):
        stream = Socket(pieces, clock=self.clock, elapsed=elapsed)
        with patch.object(transport, "_connect", return_value=stream) as connect:
            result = transport.send(request or self.request, work_id=WORK, deadline=self.deadline)
        self.assertEqual(connect.call_count, 1)
        self.assertTrue(stream.closed)
        return result, stream

    def uncertain(self, capture):
        self.assertFalse(capture.complete)
        self.assertEqual(capture.outcome, "uncertain")
        for value in (SECRET, ACCESS, REFRESH):
            self.assertNotIn(value, repr(capture))
        transport.require_capture(capture, request=capture.request, work_id=WORK, deadline=self.deadline)

    def test_all_fixed_phases_send_original_bytes_and_capture_without_classification(self):
        requests = (protocol.code_exchange_request(self.profile, SECRET, "code", "v" * 43),
            self.request, protocol.identity_request(self.profile, ACCESS),
            protocol.revoke_request(self.profile, SECRET, REFRESH, "refresh_token"))
        for request in requests:
            with self.subTest(phase=request.phase), patch.object(protocol, "classify_token_response",
                    side_effect=AssertionError("classification must follow custody")):
                body = token_body()
                result, stream = self.send([wire(body)], request=request)
                self.assertTrue(result.complete)
                self.assertEqual((result.status, result.body, result.wire_prefix), (200, body, wire(body)))
                self.assertIs(result.request, request)
                self.assertIs(result.deadline, self.deadline)
                self.assertEqual(result.profile_binding_digest, self.profile.binding_digest)
                sent = b"".join(stream.sent)
                head, outgoing = sent.split(b"\r\n\r\n", 1)
                self.assertEqual(outgoing, request.body)
                self.assertEqual(head.split(b"\r\n")[0],
                    (request.method + " " + transport._PATHS[request.phase] + " HTTP/1.1").encode())
                for name, value in request.headers:
                    self.assertIn((name + ": " + value).encode(), head.split(b"\r\n"))
                self.assertIn(b"Host: api.x.com", head)
                self.assertIn(b"Connection: close", head)
                self.assertNotIn(b"Proxy-Authorization:", head)
                self.assertNotIn(b"Accept-Encoding:", head)
                self.assertEqual(head.count(b"Content-Length:"), int(request.method == "POST"))

    def test_standard_parser_chunked_and_close_delimited_success(self):
        body = token_body()
        chunked = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
            + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
        close_delimited = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body
        for raw in (chunked, close_delimited):
            result, _ = self.send([raw])
            self.assertTrue(result.complete)
            self.assertEqual(result.body, body)
            self.assertIs(type(protocol.classify_token_response(self.request, status=result.status,
                headers=result.headers, body=result.body)), protocol.AcceptedToken)

    def test_redirects_denials_and_nonjson_are_captured_not_followed(self):
        for status, headers, body in ((302, (("Location", "https://other.invalid/secret"),), token_body()),
                (400, (), b'{"error":"invalid_grant"}'), (500, (), b"not json")):
            result, stream = self.send([wire(body, status=status, headers=headers)])
            self.assertTrue(result.complete)
            self.assertEqual((result.status, result.body), (status, body))
            self.assertEqual(b"".join(stream.sent).count(b"POST /2/oauth2/token HTTP/1.1"), 1)
            classified = protocol.classify_token_response(self.request, status=result.status,
                headers=result.headers, body=result.body)
            self.assertIs(type(classified), protocol.RejectedToken if status == 400 else protocol.UncertainResponse)

    def test_truncated_content_length_and_chunked_retain_all_received_wire(self):
        part = b'{"access_token":"' + ACCESS.encode() + b'",'
        head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n"
        chunkhead = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
        for raw in (head + part, chunkhead + b"1000\r\n" + part,
                chunkhead + b"invalid\r\n" + part):
            result, _ = self.send([raw])
            self.uncertain(result)
            self.assertEqual(result.wire_prefix, raw)
            self.assertIn(ACCESS.encode(), result.wire_prefix)

    def test_partial_timeout_keeps_body_and_deadline_crossing_keeps_wire(self):
        body = token_body()
        head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n"
        result, _ = self.send([head, body, TimeoutError(SECRET)])
        self.uncertain(result)
        self.assertEqual(result.body, body)
        self.assertEqual(result.wire_prefix, head + body)
        # Valid-looking JSON in a partial message must NOT become rejection or
        # issuance simply by passing its body to the pure codec.
        self.assertFalse(result.complete)
        result, _ = self.send([wire(body)], elapsed=11)
        self.uncertain(result)
        self.assertEqual(result.wire_prefix, wire(body))
        self.assertEqual(result.body, b"")

    def test_original_deadline_bounds_each_read_without_renewal(self):
        body = token_body()
        header, _ = wire(body).split(b"\r\n\r\n", 1)
        result, stream = self.send([header + b"\r\n\r\n", body[:40], body[40:]], elapsed=1)
        self.assertTrue(result.complete)
        self.assertEqual(self.deadline.expires_at, 110.0)
        self.assertEqual(stream.timeouts, sorted(stream.timeouts, reverse=True))
        self.assertGreater(stream.timeouts[0], stream.timeouts[-1])
        self.assertTrue(all(0 < value <= 10.0 for value in stream.timeouts))
        self.deadline = HttpDeadline(1000.0)
        result, stream = self.send([wire(body)])
        self.assertTrue(result.complete)
        self.assertTrue(all(0 < value <= transport.MAX_SEND_SECONDS for value in stream.timeouts))
        self.assertIs(result.deadline, self.deadline)

    def test_limits_preserve_bounded_prefix_for_each_phase(self):
        for request, maximum in ((self.request, protocol.MAX_TOKEN_RESPONSE_BYTES),
                (protocol.identity_request(self.profile, ACCESS), protocol.MAX_IDENTITY_RESPONSE_BYTES),
                (protocol.revoke_request(self.profile, SECRET, REFRESH, "refresh_token"), protocol.MAX_REVOKE_RESPONSE_BYTES)):
            result, _ = self.send([wire(b"x" * (maximum + 1))], request=request)
            self.uncertain(result)
            self.assertEqual(result.body, b"x" * maximum)
            self.assertLessEqual(len(result.wire_prefix), maximum + transport.MAX_WIRE_OVERHEAD)
        raw = b"HTTP/1.1 200 OK\r\n" + b"A: x\r\n" * 100000
        result, _ = self.send([raw])
        self.uncertain(result)
        self.assertLessEqual(len(result.wire_prefix), protocol.MAX_TOKEN_RESPONSE_BYTES + transport.MAX_WIRE_OVERHEAD)

    def test_ambiguous_framing_and_bounded_physical_headers_refused(self):
        bodies = [b"Content-Length: 2\r\nContent-Length: 2\r\n",
            b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n",
            b"Content-Length: 02\r\n", b"Transfer-Encoding: gzip\r\n",
            b"X: y\r\n" * 65, b"X: " + b"y" * (16 * 1024) + b"\r\n",
            b"X: first\r\n second\r\n"]
        for headers in bodies:
            raw = b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n{}"
            result, _ = self.send([raw])
            self.uncertain(result)
            self.assertTrue(raw.startswith(result.wire_prefix))

    def test_fixed_inputs_refuse_before_contact(self):
        variants = [replace(self.request, url="https://api.x.com:443/2/oauth2/token"),
            replace(self.request, method="GET"), replace(self.request, body=b"secret"),
            replace(self.request, headers=self.request.headers + (("Cookie", SECRET),))]
        with patch.object(transport, "_connect") as connect:
            for request in variants:
                with self.assertRaises(transport.TransportError) as caught:
                    transport.send(request, work_id=WORK, deadline=self.deadline)
                self.assertEqual(str(caught.exception), "operator X OAuth transport refused")
            for deadline in (HttpDeadline(100.0), HttpDeadline(float("nan")), HttpDeadline(True), 110.0):
                with self.assertRaises(transport.TransportError):
                    transport.send(self.request, work_id=WORK, deadline=deadline)
            with self.assertRaises(transport.TransportError):
                transport.send(self.request, work_id="not-a-work-id", deadline=self.deadline)
            connect.assert_not_called()

    def test_capture_is_private_bound_and_retention_survives_expiry(self):
        result, _ = self.send([wire(token_body())])
        with self.assertRaises(FrozenInstanceError):
            result.complete = False
        self.clock.value = 111.0
        transport.require_capture(result, request=self.request, work_id=WORK, deadline=self.deadline)
        for value, request, work_id, deadline in ((object(), self.request, WORK, self.deadline),
                (transport.CapturedResponse(), self.request, WORK, self.deadline),
                (result, replace(self.request), WORK, self.deadline),
                (result, self.request, "737c5a96-3338-41c3-8f7e-b5f56c719112", self.deadline),
                (result, self.request, WORK, HttpDeadline(110.0))):
            with self.assertRaises(transport.TransportError):
                transport.require_capture(value, request=request, work_id=work_id, deadline=deadline)
        for secret in (SECRET, ACCESS, REFRESH):
            self.assertNotIn(secret, repr(result))

    def test_interruption_preserves_private_capture_for_store_before_propagation(self):
        part = b'{"access_token":"' + ACCESS.encode() + b'",'
        head = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"
        stream = Socket([head, part, KeyboardInterrupt(SECRET)])
        with patch.object(transport, "_connect", return_value=stream):
            with self.assertRaises(transport.TransportInterrupted) as caught:
                transport.send(self.request, work_id=WORK, deadline=self.deadline)
        result = caught.exception.capture
        self.uncertain(result)
        self.assertEqual(result.body, part)
        self.assertEqual(result.wire_prefix, head + part)
        self.assertEqual(str(caught.exception), "operator X OAuth transport interrupted")
        self.assertNotIn(SECRET, repr(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(stream.closed)

    def test_actual_connection_path_requires_tls_before_any_authentication_bytes(self):
        stream = Socket([wire(token_body())])

        class Context:
            check_hostname, verify_mode = True, ssl.CERT_REQUIRED
            def set_alpn_protocols(inner, protocols):
                self.assertEqual(protocols, ["http/1.1"])
            def wrap_socket(inner, raw, **kwargs):
                self.assertIs(raw, stream)
                self.assertEqual(kwargs, {"server_hostname": "api.x.com",
                    "do_handshake_on_connect": False, "suppress_ragged_eofs": False})
                return raw

        address = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443))
        with patch.object(transport, "_resolve", return_value=address) as resolve, \
                patch.object(transport.ssl, "create_default_context", return_value=Context()) as context, \
                patch.object(transport.socket, "socket", return_value=stream) as constructor, \
                patch.dict(os.environ, {"HTTPS_PROXY": "http://invalid.invalid:1", "HTTP_PROXY": "http://invalid.invalid:1"}):
            result = transport.send(self.request, work_id=WORK, deadline=self.deadline)
        self.assertTrue(result.complete)
        self.assertEqual(resolve.call_count, 1)
        context.assert_called_once_with(purpose=ssl.Purpose.SERVER_AUTH)
        constructor.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.assertEqual(stream.events[:3], [("connect", ("192.0.2.1", 443)), ("handshake",), ("send",)])
        stream = Socket([], handshake_error=ssl.SSLCertVerificationError(SECRET))
        with patch.object(transport, "_resolve", return_value=address), \
                patch.object(transport.ssl, "create_default_context", return_value=Context()), \
                patch.object(transport.socket, "socket", return_value=stream):
            result = transport.send(self.request, work_id=WORK, deadline=self.deadline)
        self.uncertain(result)
        self.assertEqual(stream.sent, [])
        self.assertEqual(result.wire_prefix, b"")

    def test_dns_is_fixed_bounded_no_credentials_and_no_connection_after_timeout(self):
        address = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.1", 443))
        with patch.object(transport.socket, "getaddrinfo", return_value=[address]) as lookup:
            self.assertEqual(transport._resolve(110.0), address)
        lookup.assert_called_once_with("api.x.com", 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        started, release, finished = threading.Event(), threading.Event(), threading.Event()
        def delayed(*args, **kwargs):
            started.set()
            try:
                self.assertTrue(release.wait(1.0))
                return [address]
            finally:
                finished.set()
        # Do not leave a daemon behind after exercising the deadline path.
        with patch.object(transport.socket, "getaddrinfo", side_effect=delayed), \
                patch.object(transport.socket, "socket") as connect:
            try:
                self.deadline = HttpDeadline(100.01)
                result = transport.send(self.request, work_id=WORK, deadline=self.deadline)
                self.assertTrue(started.is_set())
                self.uncertain(result)
                # While the single DNS worker is occupied, a second request
                # refuses without enqueuing another resolver or HTTP attempt.
                result = transport.send(self.request, work_id=WORK, deadline=self.deadline)
                self.uncertain(result)
                connect.assert_not_called()
            finally:
                release.set()
                self.assertTrue(finished.wait(1.0))


if __name__ == "__main__":
    unittest.main()
