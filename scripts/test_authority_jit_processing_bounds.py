"""UNRUN processing-bound components, not measured/native producer acceptance.

The request and page signatures are genuine. The private owner uses an explicit
clock-only caller (as the request-owner control does), never a replacement for
the measured factory. Socket doubles test fixed I/O guard ordering; action/wire
joins stop at transport without supplying successful custody or plan DTOs.
"""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from catchplate import authority_jit_compound_request_service as measured
from catchplate import authority_jit_compound_transport as planning_transport
from catchplate import authority_jit_original_actions as actions
from catchplate import authority_jit_original_authorization as authorization
from catchplate import authority_jit_original_service as pages
from catchplate import authority_jit_original_transport as transport
from catchplate import authority_jit_original_wire as wire
from catchplate.authority_query_read_work import QueryReadWorkError
from test_authority_jit_compound_request import (
    arguments, clocks, verify, pins, work, EPOCH, MONO, LIFE, DEADLINE, source)
from test_authority_jit_original_authorization import control, sign, verify as verify_page
from test_authority_jit_original_actions import control as action_control, TransportReached
from test_authority_jit_original_configuration import Fixture
from test_authority_jit_original_transport import SocketDouble, response_frame


RECEIVER = (EPOCH + 50, MONO + 50, MONO + 60,
    EPOCH + LIFE // 4, MONO + LIFE // 4, LIFE, 1000)
BOUND, EXPIRY = MONO + 200, EPOCH + 200


class ClockOnlyCaller:
    """Explicit clock seam; it grants no measured configuration or peer claim."""
    window, deadline = RECEIVER, BOUND

    def local(self):
        pass

    def check(self, actual_work):
        source.clock._check_on_work(self.window, work=actual_work)


class JitProcessingBoundsControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        values = arguments()
        with clocks():
            raw = source.sign_request(**values)
            cls.verified = verify(raw, values["request_bytes"], receiver_window=RECEIVER)
        cls.raw2 = raw, values["request_bytes"]

    def owner(self):
        return measured._RequestOwner(ClockOnlyCaller(), self.verified, pins(), self.raw2)

    def exchange(self, stream, owner, meter, **changes):
        values = dict(action="persist", control_bytes=b"{}", body_bytes=b"[]",
            original_deadline_ns=BOUND, expected_peer_uid=1000, expected_peer_gid=1000,
            processing_owner=owner, processing_work=meter)
        values.update(changes)
        with patch.object(transport.socket, "socket", return_value=stream), \
                patch.object(transport.authority_transport, "_peer_identity", return_value=(1000, 1000, 123)):
            return transport._socket_exchange("/component.sock", **values)

    def test_genuine_child_signature_narrows_both_bounds_without_rewriting_originals(self):
        with clocks():
            owner, raw = self.owner(), control()
            signed = sign(raw, live_window=owner.original, processing_owner=owner)
            observed = verify_page(signed, raw, live_window=owner.original)
            payload = json.loads(signed)["payload"]
            self.assertEqual((payload["issuedAtEpochNs"], payload["expiresAtEpochNs"],
                payload["originalDeadlineNs"]), (owner.original[0], EXPIRY, DEADLINE))
            self.assertEqual(observed.control, json.loads(raw))
            self.assertEqual(owner.verified.payload["originalDeadlineNs"], DEADLINE)
            self.assertGreater(owner.verified.payload["expiresAtEpochNs"], EXPIRY)
            self.assertIs(owner.original, self.verified.original_window)
            self.assertEqual(owner.raw2, self.raw2)

    def test_real_action_passes_same_owner_original_control_and_narrow_signed_expiry(self):
        configuration = Fixture().capture("planner")
        sent = []

        def stop(**values):
            sent.append(values)
            raise TransportReached()

        with clocks():
            owner, meter = self.owner(), work()
            raw = action_control(configuration, "persist")
            with patch.object(actions.wire, "exchange", side_effect=stop), self.assertRaises(TransportReached):
                actions.persist_page(configuration=configuration, control_bytes=raw,
                    body_bytes=b"raw", live_window=owner.original, work=meter,
                    check=lambda: None, processing_owner=owner)
            self.assertEqual(len(sent), 1)
            value = sent[0]
            self.assertIs(value["processing_owner"], owner)
            self.assertIs(value["control_bytes"], raw)
            self.assertIs(value["work"], meter)
            self.assertEqual((value["original_deadline_ns"], value["transport_deadline_ns"]),
                (DEADLINE, BOUND))
            verified = actions._verify(configuration, role="planner", action="persist",
                authorization_bytes=value["authorization_bytes"], control_bytes=raw,
                window=owner.original, work=work())
            self.assertEqual(verified.expires_at_epoch_ns, EXPIRY)

    def test_fixed_io_checks_bracket_fragmented_stream_with_one_absolute_deadline(self):
        checks = []
        original = measured._RequestOwner.check

        def checked(owner, meter):
            checks.append((owner, meter))
            return original(owner, meter)

        with clocks(), patch.object(measured._RequestOwner, "check", checked):
            owner, meter = self.owner(), work()
            stream = SocketDouble(response_frame(), chunk=1)
            before = meter.hash_work, meter.input_bytes, meter.json_nodes
            result = self.exchange(stream, owner, meter)
            self.assertEqual(result.body_bytes, b"raw")
            self.assertEqual((meter.hash_work, meter.input_bytes, meter.json_nodes), before)
            self.assertEqual(len(checks), 24)  # Eleven fixed calls, plus entry/return.
            self.assertTrue(all(item == (owner, meter) for item in checks))
            self.assertGreater(len(stream.read_sizes), 5)  # Fragmentation is not capped.
            self.assertTrue(stream.timeouts)
            self.assertTrue(all(value == 100 / 1_000_000_000 for value in stream.timeouts))
            self.assertEqual(stream.closes, 1)
            checks.clear()
            reply = SocketDouble()
            planning_transport._send_reply(reply, originals=(b"{}",) * 4,
                deadline_ns=BOUND, processing_owner=owner, processing_work=meter)
            self.assertEqual(len(checks), 12)  # Header/four bodies, entry/return.
            self.assertEqual(len(reply.sent), 5)
            self.assertEqual(reply.closes, 0)  # Accepted socket is borrowed.
            self.assertTrue(all(value == 100 / 1_000_000_000 for value in reply.timeouts))

    def test_epoch_expiry_after_control_send_stops_body_and_after_eof_stops_return(self):
        for boundary in ("control", "eof", "reply"):
            state = {"elapsed": 100}

            class ExpiringSocket(SocketDouble):
                def sendall(self, raw):
                    super().sendall(raw)
                    if boundary in ("control", "reply") and len(self.sent) == 2:
                        state["epoch_elapsed"] = 200

                def recv(self, maximum):
                    result = super().recv(maximum)
                    if boundary == "eof" and result == b"":
                        state["epoch_elapsed"] = 200
                    return result

            with self.subTest(boundary=boundary), clocks(state):
                owner, stream = self.owner(), ExpiringSocket(response_frame())
                with self.assertRaises(measured.JitCompoundRequestServiceError):
                    if boundary == "reply":
                        planning_transport._send_reply(stream, originals=(b"{}",) * 4,
                            deadline_ns=BOUND, processing_owner=owner, processing_work=work())
                    else:
                        self.exchange(stream, owner, work())
                self.assertTrue(owner.failed)
                self.assertEqual(stream.closes, 0 if boundary == "reply" else 1)
                if boundary in ("control", "reply"):
                    self.assertEqual(len(stream.sent), 2)
                    self.assertEqual(stream.shutdowns, [])
                    self.assertEqual(stream.read_sizes, [])

    def test_exception_keeps_first_failure_and_closes_after_expired_owner(self):
        state, cancelled = {"elapsed": 100}, KeyboardInterrupt("original cancellation")

        class CancelledSocket(SocketDouble):
            def connect(self, path):
                state["epoch_elapsed"] = 200
                raise cancelled

        with clocks(state):
            owner, stream = self.owner(), CancelledSocket(close_failure=RuntimeError("close"))
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.exchange(stream, owner, work())
            self.assertIs(caught.exception, cancelled)
            self.assertEqual(stream.closes, 1)
            self.assertTrue(owner.failed)
            self.assertEqual(stream.sent, [])

    def test_wire_reserves_before_native_and_passes_exact_source_owner(self):
        with clocks():
            owner, raw = self.owner(), control()
            signed = sign(raw, live_window=owner.original, processing_owner=owner)
            values = dict(path="/component.sock", action="read", authorization_bytes=signed,
                control_bytes=raw, body_bytes=None, original_deadline_ns=DEADLINE,
                expected_peer_uid=1000, expected_peer_gid=1000, processing_owner=owner)
            with patch.object(wire.transport, "_socket_exchange") as native:
                with self.assertRaises(QueryReadWorkError):
                    wire.exchange(**values, work=work(max_input_bytes=512 * 1024))
                native.assert_not_called()
            meter = work()
            with patch.object(wire.transport, "_socket_exchange", side_effect=TransportReached) as native:
                with self.assertRaises(TransportReached):
                    wire.exchange(**values, work=meter)
                native.assert_called_once()
                sent = native.call_args.kwargs
                self.assertIs(sent["processing_owner"], owner)
                self.assertIs(sent["processing_work"], meter)
                self.assertEqual(sent["original_deadline_ns"], BOUND)
                self.assertGreaterEqual(meter.input_bytes, 1024 * 1024)
                self.assertGreaterEqual(meter.json_nodes, 65536)

    def test_wrong_or_inactive_processing_owner_refuses_before_keys_or_socket(self):
        with clocks():
            inactive = self.owner()
            inactive.active = False
            for owner in (object(), inactive):
                with self.subTest(kind=type(owner).__name__):
                    with patch.object(authorization.evidence.keys, "_pair_on_work") as keys:
                        with self.assertRaises(ValueError):
                            sign(control(), live_window=self.verified.original_window, processing_owner=owner)
                        keys.assert_not_called()
                    with patch.object(transport.socket, "socket") as native:
                        with self.assertRaises((ValueError, transport.AuthorityTransportError)):
                            transport._socket_exchange("/component.sock", action="read", control_bytes=b"{}",
                                body_bytes=None, original_deadline_ns=BOUND, expected_peer_uid=1000,
                                expected_peer_gid=1000, processing_owner=owner, processing_work=work())
                        native.assert_not_called()

    def test_actual_source_stack_retains_exact_owner_without_selectable_io_callback(self):
        from catchplate import authority_jit_compound_service as compound_service

        for function in (compound_service._produce_on_work, compound_service._producer_on_work,
                pages._caller_on_work, actions.persist_page, actions.read_page,
                actions._sign, authorization.sign_control, wire.exchange, transport._socket_exchange):
            self.assertIsNone(inspect.signature(function).parameters["processing_owner"].default)
        self.assertIn("_page_bounds", inspect.getsource(pages._PageCaller._live))
        self.assertIn("processing_owner=", inspect.getsource(pages._PageCaller.persist))
        self.assertIn("processing_owner=", inspect.getsource(pages._PageCaller.read))
        root = Path(__file__).resolve().parents[1]
        tree = ast.parse((root / "catchplate/authority_service.py").read_text())
        method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
            and node.name == "_produce_jit_compound")
        self.assertIn("processing_owner=processing_owner", ast.unparse(method))
        self.assertNotIn("check", inspect.signature(transport._socket_exchange).parameters)
        self.assertEqual(set(inspect.signature(transport._ProcessingIO).parameters), {"owner", "work", "deadline"})


if __name__ == "__main__":
    unittest.main()
