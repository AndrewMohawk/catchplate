"""Opaque wire debit and source ingress controls, not measured/native success."""
from __future__ import annotations

import ast
from pathlib import Path
import unittest
from unittest import mock

from catchplate import authority_jit_compound_wire as source
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


ROOT = Path(__file__).resolve().parents[1]
ORIGINALS = (b"parent", b"request", b"context", b"manifest")


def work(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def reply(originals=ORIGINALS):
    return source.transport.RawReply(originals, source.transport.ExchangeMetrics(
        source.transport._metrics((2, 7), 16),
        source.transport._metrics(tuple(map(len, originals)), 24)))


def arguments(meter):
    return dict(control_bytes=b"{}", request_bytes=b"request", original_deadline_ns=1000,
        expected_peer_uid=1000, expected_peer_gid=1000, work=meter)


def tree(path):
    target = ROOT / path
    if target.stat().st_size > 2 * 1024 * 1024:
        raise AssertionError("source inspection bound")
    return ast.parse(target.read_bytes(), filename=path)


class JitCompoundWireControls(unittest.TestCase):
    def test_raw_exchange_exact_echo_and_actual_frame_debits(self):
        meter, actual = work(), reply()
        with mock.patch.object(source.transport, "_socket_exchange", return_value=actual) as exchange, \
                mock.patch.object(source.transport, "_deadline"):
            result = source.exchange("/bounded.sock", transport_deadline_ns=500, **arguments(meter))
        self.assertIs(result, actual)
        self.assertEqual(exchange.call_args.kwargs["original_deadline_ns"], 500)
        self.assertEqual(meter.input_bytes,
            actual.metrics.request.wire_bytes + actual.metrics.reply.wire_bytes + 14)
        self.assertEqual(meter.hash_work, 0)
        # No signature or replay verdict is inferred from these opaque bodies.
        changed = reply((b"not a plan", b"different", b"context", b"manifest"))
        with mock.patch.object(source.transport, "_socket_exchange", return_value=changed), \
                self.assertRaises(source.JitCompoundWireError):
            source.exchange("/bounded.sock", **arguments(work()))

    def test_receive_send_frame_metrics_and_live_check_surround_actual_send(self):
        meter = work()
        raw = source.transport.RawRequest(b"{}", b"request", source.transport._metrics((2, 7), 16))
        with mock.patch.object(source.transport, "_recv_request", return_value=raw):
            self.assertIs(source.receive_request(object(), prefix=source.transport.REQUEST_MAGIC,
                deadline_ns=1000, work=meter), raw)
        events = []
        expected = reply().metrics.reply
        with mock.patch.object(source.transport, "_send_reply",
                side_effect=lambda *args, **kwargs: events.append("send") or expected):
            source.send_reply(object(), originals=ORIGINALS, request_bytes=b"request",
                deadline_ns=1000, check=lambda: events.append("check"), work=meter)
        self.assertEqual(events, ["check", "send", "check"])
        self.assertEqual(meter.input_bytes, raw.metrics.wire_bytes + 14 + expected.wire_bytes)
        with mock.patch.object(source.transport, "_send_reply") as send, \
                self.assertRaises(source.JitCompoundWireError):
            source.send_reply(object(), originals=ORIGINALS, request_bytes=b"request",
                deadline_ns=1000, check=lambda: True, work=work())
        send.assert_not_called()

    def test_original_capacity_and_callback_neutrality_refuse_without_renewal(self):
        with mock.patch.object(source.transport, "_socket_exchange") as exchange, \
                self.assertRaises(ValueError):
            source.exchange("/bounded.sock", **arguments(work(max_input_bytes=100)))
        exchange.assert_not_called()
        for kind in ("spend", "limits", "cancel"):
            meter = work()
            failure = KeyboardInterrupt()

            def change(*args, **kwargs):
                if kind == "spend": meter.charge(input_bytes=1)
                if kind == "limits": meter.limits = work().limits
                if kind == "cancel": raise failure
                return reply()

            with self.subTest(kind=kind), mock.patch.object(source.transport, "_socket_exchange", side_effect=change):
                with self.assertRaises(KeyboardInterrupt if kind == "cancel" else ValueError) as caught:
                    source.exchange("/bounded.sock", **arguments(meter))
                if kind == "cancel":
                    self.assertIs(caught.exception, failure)

    def test_forged_metrics_and_nonexact_originals_are_not_accepted(self):
        for actual in (source.transport.RawReply(list(ORIGINALS), reply().metrics),
                source.transport.RawReply(ORIGINALS, source.transport.ExchangeMetrics(
                    source.transport.FrameMetrics((2, 7), 16, 26), reply().metrics.reply))):
            refusal = (source.transport.AuthorityTransportError
                if type(actual.originals) is list else source.JitCompoundWireError)
            with mock.patch.object(source.transport, "_socket_exchange", return_value=actual), \
                    self.assertRaises(refusal):
                source.exchange("/bounded.sock", **arguments(work()))

    def test_actual_ingress_keeps_one_local_window_and_verified_owner_through_send(self):
        parsed = tree("catchplate/authority_jit_compound_ingress.py")
        serve = next(node for node in parsed.body if isinstance(node, ast.FunctionDef)
            and node.name == "serve_process")
        calls = [node for node in ast.walk(serve) if isinstance(node, ast.Call)]
        named = lambda name: [node for node in calls if ast.unparse(node.func) == name]
        self.assertEqual(len(named("_ValidationWork")), 1)
        self.assertEqual(len(named("pages._receiving_window")), 1)
        self.assertEqual(len(named("requests.receive_request_on_work")), 1)
        self.assertEqual(len(named("owner.produce")), 1)
        owner = next(node for node in ast.walk(serve) if isinstance(node, ast.With))
        self.assertIn("owner.produce", ast.unparse(owner))
        self.assertIn("wire.send_reply", ast.unparse(owner))
        self.assertIn("check=lambda: owner.check(work)", ast.unparse(owner))
        self.assertIn("processing_owner=owner", ast.unparse(owner))
        self.assertIn("receiver_window=receiver", ast.unparse(owner))
        self.assertIn("deadline_ns=owner.deadline_ns", ast.unparse(owner))
        self.assertFalse(named("requests.decode_control"))
        self.assertLess(named("pages._receiving_window")[0].lineno,
            named("wire.receive_request")[0].lineno)

    def test_actual_listener_peer_and_writer_exception_precede_fixed_ingress(self):
        parsed = tree("catchplate/authority_service.py")
        server = next(node for node in parsed.body if isinstance(node, ast.ClassDef)
            and node.name == "AuthorityServer")
        serve = next(node for node in server.body if isinstance(node, ast.FunctionDef)
            and node.name == "_serve_connection")
        calls = [node for node in ast.walk(serve) if isinstance(node, ast.Call)]
        def only(name):
            return next(node for node in calls if ast.unparse(node.func) == name)
        peer = only("_peer_identity")
        prefix = only("writer_transport._recv_prefix")
        dispatch = only("authority_jit_compound_ingress.serve_process")
        denial = next(node for node in ast.walk(serve) if isinstance(node, ast.If)
            and "writer_reservation_peer and" in ast.unparse(node.test))
        self.assertLess(peer.lineno, prefix.lineno)
        self.assertLess(prefix.lineno, denial.lineno)
        self.assertLess(denial.lineno, dispatch.lineno)
        self.assertEqual([ast.unparse(value) for value in dispatch.args], ["self.process", "connection"])
        self.assertEqual({item.arg: ast.unparse(item.value) for item in dispatch.keywords},
            {"deadline_ns": "deadline_ns", "prefix": "prefix"})
        detached = next(node for node in ast.walk(serve) if isinstance(node, ast.Assign)
            and any(isinstance(value, ast.Name) and value.id == "detached" for value in node.targets)
            and isinstance(node.value, ast.Compare))
        self.assertIn("jit_compound_transport.REQUEST_MAGIC", ast.unparse(detached))


if __name__ == "__main__":
    unittest.main()
