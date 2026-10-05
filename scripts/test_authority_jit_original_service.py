"""Source-owned ingress/caller seams; no measured-process or PG acceptance."""
from __future__ import annotations

import ast
import inspect
import os
import threading
import unittest
from unittest import mock

from serverware import authority_jit_original_service as service
from test_authority_jit_original_configuration import Fixture
from test_authority_jit_original_pages import binding
from test_authority_jit_original_authorization import WINDOW, EPOCH, MONOTONIC, DEADLINE, clocks, work


class NativeBoundary(BaseException):
    pass


def caller(role="planner", *, check=lambda work: None):
    configured = Fixture().capture(role)
    result = object.__new__(service._PageCaller)
    object.__setattr__(result, "_configured", configured)
    object.__setattr__(result, "_check_owner", check)
    object.__setattr__(result, "_window", WINDOW)
    object.__setattr__(result, "_held", (configured, check, WINDOW))
    object.__setattr__(result, "_identity", (os.getpid(), threading.get_ident()))
    return result


def context(configured):
    value = binding()
    value["configuration_digest"] = configured.configuration_digest
    return {name: value[name] for name in service.wire.control.store.CONTEXT_FIELDS}


class JitOriginalServiceControls(unittest.TestCase):
    def test_caller_uses_real_fixed_signed_actions_and_stops_before_native_transport(self):
        for role, action in (("planner", "persist"), ("planner", "read"), ("verifier", "read")):
            owned = caller(role)
            sent = []
            def native(**arguments):
                sent.append(arguments)
                raise NativeBoundary()
            arguments = dict(context=context(owned._configured), original_deadline_ns=DEADLINE, work=work())
            if action == "persist":
                arguments.update(body_bytes=b"[]", descriptor={"digest": binding()["body_digest"], "byteCount": 2})
            with clocks(), mock.patch.object(service.wire, "exchange", side_effect=native):
                with self.assertRaises(NativeBoundary):
                    getattr(owned, action)(**arguments)
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0]["action"], action)
            expected = (owned._configured.planner_endpoint if role == "verifier"
                else owned._configured.writer_endpoint)
            self.assertEqual((sent[0]["path"], sent[0]["expected_peer_uid"], sent[0]["expected_peer_gid"]), expected)
            self.assertEqual(sent[0]["original_deadline_ns"], DEADLINE)

    def test_original_caller_identity_configuration_window_and_clock_cannot_be_replaced(self):
        for mutate in (lambda owner: object.__setattr__(owner, "_identity", (-1, -1)),
                lambda owner: object.__setattr__(owner, "_window", tuple(list(WINDOW))),
                lambda owner: object.__setattr__(owner, "_configured", Fixture().capture()),
                lambda owner: object.__setattr__(owner._configured, "local_role", "planner-writer")):
            owned = caller()
            mutate(owned)
            with clocks(), self.assertRaises(ValueError):
                service._PageCaller._live(owned, work())
        owned = caller()
        with clocks({"elapsed": WINDOW[4] - MONOTONIC}), self.assertRaises(ValueError):
            service._PageCaller._live(owned, work())

    def test_receiving_window_is_actual_sample_clipped_by_owned_socket_deadline(self):
        configured = Fixture().capture()
        sample = (MONOTONIC + 20, EPOCH + 30, MONOTONIC + 40)
        deadline = MONOTONIC + 100
        with mock.patch.object(service.clock, "_sample_on_work", return_value=sample) as observed:
            selected = service._receiving_window(deadline_ns=deadline, configured=configured, work=work())
        observed.assert_called_once()
        self.assertEqual(selected[:5], (sample[1], sample[0], sample[2], sample[1] + 80, deadline))
        for invalid in (True, 0, MONOTONIC + 10):
            with mock.patch.object(service.clock, "_sample_on_work", return_value=sample), self.assertRaises(ValueError):
                service._receiving_window(deadline_ns=invalid, configured=configured, work=work())

    def test_actual_measured_factory_and_ingress_have_no_request_selected_role_or_descriptor(self):
        tree = ast.parse(inspect.getsource(service))
        methods = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        selected = ast.unparse(methods["_configured_on_work"])
        for expression in ("type(process) is service.AuthorityProcess", "service.MeasuredConfiguration",
                "measured._measured_context_on_work", "configuration._from_configuration_on_work",
                "read_descriptor=_WRITER_DSN if local_role == 'planner-writer' else None",
                "service.authority_launch_guard.require_active"):
            self.assertIn(expression, selected)
        served = ast.unparse(methods["serve_process"])
        self.assertLess(served.index("process.role_name in ('planner', 'planner-writer')"),
            served.index("wire.transport._recv_request"))
        self.assertIn("request.action == 'read' and request.body_bytes is None", served)
        self.assertIn("min(deadline_ns, selected['originalDeadlineNs'])", served)
        self.assertLess(served.index("_configured_on_work("), served.index("actions.relay_read("))
        self.assertIn("actions.receive_writer", served)
        self.assertLess(served.index("signed = actions._verify"), served.index("def current"))
        self.assertIn("_original_interval_on_work(window, issued, expires, effective_deadline, work)", served)
        self.assertLess(served.index("actions.receive_writer"), served.index("wire.transport._send_response"))
        self.assertIn("work.charge(input_bytes=request.metrics.wire_bytes)", served)
        self.assertIn("work.charge(input_bytes=expected_metrics.wire_bytes)", served)
        self.assertIn("current()", served[served.index("response = wire.encode_response"):
            served.index("metrics = evidence.production._callback")])
        self.assertNotIn("jit.decide", served)
        self.assertNotIn("db.", served)

    def test_genuine_shorter_signed_interval_remains_live_only_through_its_original_expiry(self):
        configured = Fixture().capture()
        raw = service.wire.control.encode_control(action="read", context=context(configured),
            original_deadline_ns=DEADLINE, descriptor=None, work=work())
        shorter = (EPOCH, MONOTONIC, MONOTONIC + 10,
            EPOCH + 200, MONOTONIC + 200, WINDOW[5], 0)
        with clocks({"elapsed": 100}) as state:
            signed = service.actions._sign(configured, action="read", control_bytes=raw,
                window=shorter, work=work())
            original = service.actions._verify(configured, role="planner", action="read",
                authorization_bytes=signed, control_bytes=raw, window=WINDOW, work=work())
            meter = work()
            before = meter.metrics
            selected = service._original_interval_on_work(WINDOW, original.issued_at_epoch_ns,
                original.expires_at_epoch_ns, DEADLINE, meter)
            self.assertEqual(selected, MONOTONIC + 200)
            self.assertEqual(meter.metrics, before)
            # A later receiver window/control deadline cannot admit the final
            # response when actual original expiry has already been crossed.
            state["elapsed"] = 200
            with self.assertRaises(ValueError):
                service._original_interval_on_work(WINDOW, original.issued_at_epoch_ns,
                    original.expires_at_epoch_ns, selected, meter)


if __name__ == "__main__":
    unittest.main()
