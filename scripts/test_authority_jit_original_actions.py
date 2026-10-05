"""Actual role signatures/joins over public component fixtures, not DB custody.

The measured configuration mapper and Ed25519 are real. Synthetic immutable
configuration/clock originals do not prove launch admission. Outgoing tests
stop by raising at the transport boundary after capturing the real signature;
no successful transport/store or replay DTO is supplied. Writer tests refuse
before a connection. Native transport and persistence have separate controls.
"""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_jit_original_actions as actions
from test_authority_jit_original_configuration import Fixture
from test_authority_jit_original_authorization import WINDOW, EPOCH, MONOTONIC, DEADLINE, clocks, work
from test_authority_jit_original_pages import binding


REFUSALS = (ValueError, InvalidSignature)


class TransportReached(BaseException):
    pass


def control(configuration, action="read", *, operation=actions.OPERATION, body=b"raw"):
    stored = binding(body)
    selected = {name: stored[name] for name in actions.wire.control.store.CONTEXT_FIELDS}
    selected.update(configuration_digest=configuration.configuration_digest, operation=operation)
    return actions.wire.control.encode_control(action=action, context=selected,
        original_deadline_ns=DEADLINE,
        descriptor={"digest": stored["body_digest"], "byteCount": stored["body_byte_count"]}
            if action == "persist" else None, work=work())


def sign(configuration, raw, *, action="read", window=WINDOW):
    return actions._sign(configuration, action=action, control_bytes=raw, window=window, work=work())


class JitOriginalActionControls(unittest.TestCase):
    def setUp(self):
        fixture = Fixture()
        self.configs = {role: fixture.capture(role) for role in ("planner", "verifier", "planner-writer")}

    def stop_at_transport(self, method, **arguments):
        captured = []
        def stop(**values):
            captured.append(values)
            raise TransportReached()
        with mock.patch.object(actions.wire, "exchange", side_effect=stop):
            with self.assertRaises(TransportReached):
                method(**arguments)
        self.assertEqual(len(captured), 1)
        return captured[0]

    def test_fixed_outgoing_role_endpoints_and_genuine_original_signatures(self):
        with clocks():
            for role, action in (("planner", "persist"), ("planner", "read"), ("verifier", "read")):
                selected = self.configs[role]
                raw = control(selected, action)
                arguments = dict(configuration=selected, control_bytes=raw, live_window=WINDOW,
                    work=work(), check=lambda: None)
                if action == "persist":
                    arguments["body_bytes"] = b"raw"
                sent = self.stop_at_transport(actions.persist_page if action == "persist" else actions.read_page,
                    **arguments)
                endpoint = selected.planner_endpoint if role == "verifier" else selected.writer_endpoint
                self.assertEqual((sent["path"], sent["expected_peer_uid"], sent["expected_peer_gid"]), endpoint)
                self.assertEqual((sent["original_deadline_ns"], sent["transport_deadline_ns"]), (DEADLINE, WINDOW[4]))
                self.assertIs(sent["control_bytes"], raw)
                observed = actions._verify(selected, role=role, action=action,
                    authorization_bytes=sent["authorization_bytes"], control_bytes=raw, window=WINDOW, work=work())
                self.assertEqual((observed.issued_at_epoch_ns, observed.expires_at_epoch_ns), (WINDOW[0], WINDOW[3]))

    def test_genuine_verifier_relay_preserves_original_interval_with_narrow_receiving_window(self):
        planner, verifier = self.configs["planner"], self.configs["verifier"]
        raw = control(verifier)
        receiving = (EPOCH + 50, MONOTONIC + 50, MONOTONIC + 60,
            EPOCH + 200, MONOTONIC + 200, WINDOW[5], 0)
        with clocks():
            original = sign(verifier, raw)
            sent = self.stop_at_transport(actions.relay_read, configuration=planner,
                authorization_bytes=original, control_bytes=raw, live_window=receiving,
                work=work(), check=lambda: None)
            observed = actions._verify(planner, role="planner", action="read",
                authorization_bytes=sent["authorization_bytes"], control_bytes=raw, window=receiving, work=work())
        before, after = json.loads(original)["payload"], json.loads(sent["authorization_bytes"])["payload"]
        for name in ("issuedAtEpochNs", "expiresAtEpochNs", "originalDeadlineNs", "controlDigest", "controlByteCount"):
            self.assertEqual(after[name], before[name])
        self.assertEqual((before["role"], after["role"]), ("verifier", "planner"))
        self.assertEqual(observed.original_deadline_ns, DEADLINE)
        self.assertEqual(sent["transport_deadline_ns"], receiving[4])
        self.assertEqual(sent["original_deadline_ns"], DEADLINE)
        self.assertEqual(sent["path"], planner.writer_endpoint[0])

    def test_relay_refuses_planner_original_tampering_and_changed_control_before_forwarding(self):
        planner, verifier = self.configs["planner"], self.configs["verifier"]
        raw = control(verifier)
        with clocks():
            signed = sign(verifier, raw)
            changed = json.loads(signed)
            changed["payload"]["issuedAtEpochNs"] += 1
            invalid = (sign(planner, raw), signed + b" ",
                json.dumps(changed, sort_keys=True, separators=(",", ":")).encode("ascii"))
            for original in invalid:
                with mock.patch.object(actions.wire, "exchange") as forward, self.assertRaises(REFUSALS):
                    actions.relay_read(configuration=planner, authorization_bytes=original,
                        control_bytes=raw, live_window=WINDOW, work=work(), check=lambda: None)
                forward.assert_not_called()
            with mock.patch.object(actions.wire, "exchange") as forward, self.assertRaises(REFUSALS):
                actions.relay_read(configuration=planner, authorization_bytes=signed,
                    control_bytes=raw + b" ", live_window=WINDOW, work=work(), check=lambda: None)
            forward.assert_not_called()

    def test_jit_only_and_writer_exact_planner_signature_refuse_before_persistence(self):
        planner, verifier, writer = (self.configs[role] for role in ("planner", "verifier", "planner-writer"))
        with clocks(), mock.patch.object(actions.wire, "exchange") as network:
            for selected in self.configs.values():
                with self.assertRaises(REFUSALS):
                    actions.read_page(configuration=selected,
                        control_bytes=control(selected, operation="webauthn.challenge.create"),
                        live_window=WINDOW, work=work(), check=lambda: None)
            with self.assertRaises(REFUSALS):
                actions.persist_page(configuration=verifier, control_bytes=control(verifier, "persist"),
                    body_bytes=b"raw", live_window=WINDOW, work=work(), check=lambda: None)
            raw = control(verifier)
            verifier_original = sign(verifier, raw)
            with mock.patch.object(actions.selections.page_persistence, "_connect",
                    side_effect=AssertionError("unauthorized writer connection opened")) as connect:
                with self.assertRaises(REFUSALS):
                    actions.receive_writer(configuration=writer, action="read", authorization_bytes=verifier_original,
                        control_bytes=raw, body_bytes=None, live_window=WINDOW, work=work(), check=lambda: None)
                connect.assert_not_called()
            network.assert_not_called()

    def test_original_owner_clock_work_and_neutral_check_are_held(self):
        for kind in ("return", "spend", "replace", "endpoint"):
            selected, meter = Fixture().capture(), work()
            def check():
                if kind == "return": return True
                if kind == "spend": meter.charge(input_bytes=1)
                if kind == "replace": meter.input_bytes = 0
                if kind == "endpoint": object.__setattr__(selected, "writer_endpoint", ("/other.sock", 1, 1))
                return None
            with clocks(), mock.patch.object(actions.wire, "exchange") as network, self.assertRaises(REFUSALS):
                actions.read_page(configuration=selected, control_bytes=control(selected),
                    live_window=WINDOW, work=meter, check=check)
            network.assert_not_called()
        selected = self.configs["planner"]
        with clocks({"elapsed": DEADLINE - MONOTONIC}), self.assertRaises(REFUSALS):
            actions.read_page(configuration=selected, control_bytes=control(selected),
                live_window=WINDOW, work=work(), check=lambda: None)


    def test_writer_rechecks_actual_signed_expiry_during_local_io_not_only_receiver_window(self):
        planner, writer = self.configs["planner"], self.configs["planner-writer"]
        raw = control(planner)
        shorter = (EPOCH, MONOTONIC, MONOTONIC + 10,
            EPOCH + 200, MONOTONIC + 200, WINDOW[5], 0)
        reached = []
        with clocks({"elapsed": 100}) as state:
            signed = sign(planner, raw, window=shorter)
            def native_boundary(*args, **kwargs):
                reached.append(True)
                self.assertEqual(kwargs["original_deadline_ns"], MONOTONIC + 200)
                state["elapsed"] = 250
                kwargs["check"]()
                self.fail("original signed expiry was ignored")
            with mock.patch.object(actions.selections.page_persistence, "_run", side_effect=native_boundary):
                with self.assertRaises(REFUSALS):
                    actions.receive_writer(configuration=writer, action="read",
                        authorization_bytes=signed, control_bytes=raw, body_bytes=None,
                        live_window=WINDOW, work=work(), check=lambda: None)
        self.assertEqual(reached, [True])

    def test_relay_native_transport_deadline_is_narrowed_by_verified_original_expiry(self):
        planner, verifier = self.configs["planner"], self.configs["verifier"]
        raw = control(verifier)
        shorter = (EPOCH, MONOTONIC, MONOTONIC + 10,
            EPOCH + 200, MONOTONIC + 200, WINDOW[5], 0)
        with clocks():
            signed = sign(verifier, raw, window=shorter)
            sent = self.stop_at_transport(actions.relay_read, configuration=planner,
                authorization_bytes=signed, control_bytes=raw, live_window=WINDOW,
                work=work(), check=lambda: None)
        self.assertEqual(sent["transport_deadline_ns"], MONOTONIC + 200)
        self.assertEqual(sent["original_deadline_ns"], DEADLINE)
        before, after = json.loads(signed)["payload"], json.loads(sent["authorization_bytes"])["payload"]
        for name in ("issuedAtEpochNs", "expiresAtEpochNs", "originalDeadlineNs"):
            self.assertEqual(before[name], after[name])

    def test_actual_source_keeps_fixed_persistence_and_no_clock_or_allowance_creation(self):
        tree = ast.parse(inspect.getsource(actions))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertIn("configuration.persistence.persist", calls)
        self.assertIn("configuration.persistence.read", calls)
        self.assertIn("authorization.verify_control", calls)
        self.assertIn("authorization._sign", calls)
        self.assertIn("wire.exchange", calls)
        self.assertFalse(any(name.rsplit(".", 1)[-1] in
            {"_open_on_work", "_ValidationWork", "connect", "commit", "execute", "transaction"} for name in calls))
        source = inspect.getsource(actions._relay_authorization)
        self.assertLess(source.index("_verify("), source.index("authorization._sign("))
        self.assertNotIn("_open_on_work", source)


if __name__ == "__main__":
    unittest.main()
