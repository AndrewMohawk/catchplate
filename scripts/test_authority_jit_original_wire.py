"""UNRUN closed JIT codec and local raw-wire controls, not role-signature or DB admission.

The real Unix exchange admits the actual local peer only. Its authorization
bytes are intentionally opaque and unverified: a production service must call
the separate signature verifier before custody. Negative socket doubles model
framing/I/O only, never successful authority or proof replay.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_jit_original_wire as pages
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_jit_original_pages import binding
from test_authority_jit_original_transport import SocketDouble, response_frame


OPAQUE_AUTHORIZATION = b'{"unverified":"synthetic authorization original"}'


def meter(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def descriptor(body):
    selected = binding(body)
    return {"digest": selected["body_digest"], "byteCount": selected["body_byte_count"]}


def make_control(action="read", *, deadline=1000, body=b"raw"):
    selected = binding(body)
    context = {name: selected[name] for name in pages.control.store.CONTEXT_FIELDS}
    return pages.control.encode_control(action=action, context=context,
        original_deadline_ns=deadline,
        descriptor=descriptor(body) if action == "persist" else None, work=meter())


class JitOriginalWireControls(unittest.TestCase):
    def test_request_preserves_exact_opaque_authorization_and_canonical_control(self):
        for action in ("persist", "read"):
            control = make_control(action)
            packet = pages.encode_request(action=action, authorization_bytes=OPAQUE_AUTHORIZATION,
                control_bytes=control, work=meter())
            raw = pages.decode_request(packet, expected_action=action, work=meter())
            self.assertEqual((raw.authorization_bytes, raw.control_bytes), (OPAQUE_AUTHORIZATION, control))
            self.assertLessEqual(len(packet), pages.MAX_REQUEST_BYTES)
            with self.assertRaises(FrozenInstanceError):
                raw.authorization_bytes = b"changed"
        # Packet encoding deliberately does not claim this is a signed envelope.
        self.assertNotIn(b"signatureBase64Url", OPAQUE_AUTHORIZATION)

    def test_closed_packet_base64_action_size_and_canonical_rejections(self):
        control = make_control()
        packet = pages.encode_request(action="read", authorization_bytes=OPAQUE_AUTHORIZATION,
            control_bytes=control, work=meter())
        value = json.loads(packet)
        for changed in ({**value, "accepted": True}, {**value, "schema": "other"},
                {**value, "authorizationBase64Url": value["authorizationBase64Url"] + "="},
                {**value, "authorizationBase64Url": "***"},
                {**value, "authorizationBase64Url": "e31"},  # Nonzero unused bits for b"{}".
                {**value, "controlBase64Url": True}):
            with self.subTest(keys=tuple(changed)), self.assertRaises(ValueError):
                pages.decode_request(canonical(changed), expected_action="read", work=meter())
        for raw in (packet + b" ", b" " + packet, packet[:-1] + b',"schema":"duplicate"}',
                b"x" * (pages.MAX_REQUEST_BYTES + 1)):
            with self.assertRaises(ValueError):
                pages.decode_request(raw, expected_action="read", work=meter())
        with self.assertRaises(ValueError):
            pages.decode_request(packet, expected_action="persist", work=meter())
        for auth in (bytearray(OPAQUE_AUTHORIZATION), b"x", b"x" * (pages.authorization.MAX_BYTES + 1)):
            with self.assertRaises(ValueError):
                pages.encode_request(action="read", authorization_bytes=auth, control_bytes=control, work=meter())
        maximal = b"x" * pages.authorization.MAX_BYTES
        self.assertEqual(pages._decode64(pages._encode64(maximal, len(maximal), meter()),
            len(maximal), meter()), maximal)

    def test_response_joins_original_domains_actual_body_and_exact_integer(self):
        control, body = make_control(), b"\x00\xffactual raw page"
        raw = pages.encode_response(authorization_bytes=OPAQUE_AUTHORIZATION,
            control_bytes=control, body_bytes=body, work=meter())
        value = pages.decode_response(raw, authorization_bytes=OPAQUE_AUTHORIZATION,
            control_bytes=control, body_bytes=body, work=meter())
        self.assertEqual(value["bodyDigest"], descriptor(body)["digest"])
        self.assertEqual(value["authorizationDigest"], pages.evidence.plan._frame(
            pages.authorization.IDENTITY_DOMAIN, (OPAQUE_AUTHORIZATION,), meter()))
        self.assertEqual(value["controlDigest"], pages.evidence.plan._frame(
            pages.authorization.CONTROL_DOMAIN, (control,), meter()))
        for changes in (dict(authorization_bytes=OPAQUE_AUTHORIZATION + b" "),
                dict(control_bytes=control + b" "), dict(body_bytes=body + b"x")):
            inputs = dict(authorization_bytes=OPAQUE_AUTHORIZATION, control_bytes=control, body_bytes=body)
            inputs.update(changes)
            with self.assertRaises(ValueError):
                pages.decode_response(raw, **inputs, work=meter())
        for changed in ({**value, "bodyByteCount": True}, {**value, "bodyDigest": "sha256:" + "f" * 64},
                {**value, "accepted": True}):
            with self.assertRaises(ValueError):
                pages.decode_response(canonical(changed), authorization_bytes=OPAQUE_AUTHORIZATION,
                    control_bytes=control, body_bytes=body, work=meter())

    def test_real_local_peer_exchange_returns_literal_echo_and_actual_frame_metrics(self):
        body = b"\x00\xffuntrusted original page"
        deadline = time.monotonic_ns() + 3_000_000_000
        control = make_control("persist", deadline=deadline, body=body)
        requests, failures = [], []
        with tempfile.TemporaryDirectory(prefix="jit-original-page-wire-") as directory:
            path = str(Path(directory) / "socket")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen(1)
                listener.settimeout(3)
                def serve():
                    try:
                        with listener.accept()[0] as connection:
                            uid, gid, _ = pages.transport.authority_transport._peer_identity(connection)
                            if (uid, gid) != (os.getuid(), os.getgid()):
                                raise AssertionError("unexpected component peer")
                            prefix = pages.transport.wire._recv_prefix(connection, deadline_ns=deadline)
                            request = pages.transport._recv_request(connection, prefix=prefix, deadline_ns=deadline)
                            originals = pages.decode_request(request.control_bytes,
                                expected_action=request.action, work=meter())
                            requests.append(request)
                            response = pages.encode_response(authorization_bytes=originals.authorization_bytes,
                                control_bytes=originals.control_bytes, body_bytes=request.body_bytes, work=meter())
                            pages.transport._send_response(connection, control_bytes=response,
                                body_bytes=request.body_bytes, deadline_ns=deadline)
                    except BaseException as exc:
                        failures.append(exc)
                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                work = meter()
                try:
                    result = pages.exchange(path=path, action="persist", authorization_bytes=OPAQUE_AUTHORIZATION,
                        control_bytes=control, body_bytes=body, original_deadline_ns=deadline,
                        expected_peer_uid=os.getuid(), expected_peer_gid=os.getgid(), work=work)
                finally:
                    thread.join(4)
                self.assertFalse(thread.is_alive())
        if failures:
            raise failures[0]
        self.assertEqual(result.body_bytes, body)
        self.assertEqual(result.metrics.request, requests[0].metrics)
        self.assertEqual(result.metrics.request.framing_bytes, 17)
        self.assertEqual(result.metrics.response.framing_bytes, 16)
        self.assertEqual(result.metrics.response.body_bytes, len(body))
        self.assertGreater(work.input_bytes, result.metrics.request.wire_bytes + result.metrics.response.wire_bytes)

    def test_actual_transport_refuses_wrong_request_identity_and_nonliteral_persist_echo(self):
        control, original = make_control("persist"), b"raw"
        for response_auth, response_body in ((OPAQUE_AUTHORIZATION + b" ", original),
                (OPAQUE_AUTHORIZATION, b"other")):
            response = pages.encode_response(authorization_bytes=response_auth,
                control_bytes=control, body_bytes=response_body, work=meter())
            stream = SocketDouble(response_frame(response, response_body), chunk=1)
            with (mock.patch.object(pages.transport.wire.time, "monotonic_ns", return_value=10),
                    mock.patch.object(pages.transport.socket, "socket", return_value=stream),
                    mock.patch.object(pages.transport.authority_transport, "_peer_identity", return_value=(1000, 1000, 123))):
                with self.assertRaises(ValueError):
                    pages.exchange(path="/component.sock", action="persist", authorization_bytes=OPAQUE_AUTHORIZATION,
                        control_bytes=control, body_bytes=original, original_deadline_ns=1000,
                        expected_peer_uid=1000, expected_peer_gid=1000, work=meter())
            self.assertEqual(stream.closes, 1)

    def test_bad_deadline_descriptor_and_insufficient_original_work_refuse_before_socket(self):
        base = dict(path="/component.sock", action="persist", authorization_bytes=OPAQUE_AUTHORIZATION,
            control_bytes=make_control("persist"), body_bytes=b"raw", original_deadline_ns=1000,
            expected_peer_uid=1000, expected_peer_gid=1000)
        for changes in (dict(original_deadline_ns=1001), dict(original_deadline_ns=True),
                dict(body_bytes=b"wrong"), dict(body_bytes=b"x"), dict(work=meter(max_input_bytes=1024 * 1024)),
                dict(transport_deadline_ns=True), dict(transport_deadline_ns=0)):
            selected = {**base, "work": meter(), **changes}
            with mock.patch.object(pages.transport.socket, "socket") as factory:
                with self.assertRaises(ValueError):
                    pages.exchange(**selected)
                factory.assert_not_called()

    def test_narrow_transport_deadline_preserves_the_signed_control_original(self):
        original = make_control()
        response = pages.encode_response(authorization_bytes=OPAQUE_AUTHORIZATION,
            control_bytes=original, body_bytes=b"raw", work=meter())
        stream = SocketDouble(response_frame(response, b"raw"))
        with (mock.patch.object(pages.transport.wire.time, "monotonic_ns", return_value=10),
                mock.patch.object(pages.transport.socket, "socket", return_value=stream),
                mock.patch.object(pages.transport.authority_transport, "_peer_identity", return_value=(1000, 1000, 123))):
            result = pages.exchange(path="/component.sock", action="read", authorization_bytes=OPAQUE_AUTHORIZATION,
                control_bytes=original, body_bytes=None, original_deadline_ns=1000, transport_deadline_ns=500,
                expected_peer_uid=1000, expected_peer_gid=1000, work=meter())
        self.assertEqual(result.body_bytes, b"raw")
        self.assertTrue(stream.timeouts)
        self.assertTrue(all(timeout == 490 / 1_000_000_000 for timeout in stream.timeouts))
        sent = b"".join(stream.sent)
        packet_length = int.from_bytes(sent[9:13], "big")
        packet = pages.decode_request(sent[17:17 + packet_length], expected_action="read", work=meter())
        self.assertEqual(packet.control_bytes, original)

    def test_native_callback_cannot_replace_reset_or_spend_the_held_work(self):
        control, body = make_control(), b"[]"
        response = pages.encode_response(authorization_bytes=OPAQUE_AUTHORIZATION,
            control_bytes=control, body_bytes=body, work=meter())
        for mutation in (lambda work: setattr(work, "input_bytes", 0),
                lambda work: setattr(work, "limits", QueryReadValidationLimits()),
                lambda work: work.charge(input_bytes=1)):
            work = meter()
            def changed_transport(_path, **arguments):
                mutation(work)
                request = pages.transport._metrics(len(arguments["control_bytes"]), 0, 17)
                return pages.transport.RawResponse(response, body, pages.transport.ExchangeMetrics(
                    request, pages.transport._metrics(len(response), len(body), 16)))
            with mock.patch.object(pages.transport, "_socket_exchange", side_effect=changed_transport) as native:
                with self.assertRaises(ValueError):
                    pages.exchange(path="/component.sock", action="read", authorization_bytes=OPAQUE_AUTHORIZATION,
                        control_bytes=control, body_bytes=None, original_deadline_ns=1000,
                        expected_peer_uid=1000, expected_peer_gid=1000, work=work)
                native.assert_called_once()
        failure = KeyboardInterrupt("synthetic native cancellation")
        with mock.patch.object(pages.transport, "_socket_exchange", side_effect=failure) as native:
            with self.assertRaises(KeyboardInterrupt) as caught:
                pages.exchange(path="/component.sock", action="read", authorization_bytes=OPAQUE_AUTHORIZATION,
                    control_bytes=control, body_bytes=None, original_deadline_ns=1000,
                    expected_peer_uid=1000, expected_peer_gid=1000, work=meter())
            self.assertIs(caught.exception, failure)
            native.assert_called_once()

    def test_response_metrics_are_literal_and_single_byte_bodies_are_refused(self):
        control, body = make_control(), b"[]"
        response = pages.encode_response(authorization_bytes=OPAQUE_AUTHORIZATION,
            control_bytes=control, body_bytes=body, work=meter())
        def wrong_metrics(_path, **arguments):
            request = pages.transport._metrics(len(arguments["control_bytes"]), 0, 17)
            return pages.transport.RawResponse(response, body, pages.transport.ExchangeMetrics(
                request, pages.transport._metrics(len(response), len(body) + 1, 16)))
        with mock.patch.object(pages.transport, "_socket_exchange", side_effect=wrong_metrics) as native:
            with self.assertRaises(ValueError):
                pages.exchange(path="/component.sock", action="read", authorization_bytes=OPAQUE_AUTHORIZATION,
                    control_bytes=control, body_bytes=None, original_deadline_ns=1000,
                    expected_peer_uid=1000, expected_peer_gid=1000, work=meter())
            native.assert_called_once()
        with self.assertRaises(ValueError):
            pages.encode_response(authorization_bytes=OPAQUE_AUTHORIZATION,
                control_bytes=control, body_bytes=b"x", work=meter())


if __name__ == "__main__":
    unittest.main()
