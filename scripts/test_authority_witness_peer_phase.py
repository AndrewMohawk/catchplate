#!/usr/bin/env python3
"""Focused routing/cleanup controls for the actual witness connection handler.

Only the source-extracted handler and its exception classes execute. Socket IO,
framing, capture, transition, diagnostics and FD closure are labelled synthetic
spies: no sockets, proc reads, real FDs, authority admission, signatures, journal
state or database are exercised. A transition-spy result is not a valid receipt.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "serverware/authority_witness.py"


def named(parent, kind, name):
    found = [node for node in parent.body
             if isinstance(node, kind) and node.name == name]
    if len(found) != 1:
        raise AssertionError("source definition is not unique: " + name)
    return found[0]


class WitnessPeerPhaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE.stat().st_size > 1024 * 1024:
            raise AssertionError("witness source exceeds focused fixture bound")
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        server = named(tree, ast.ClassDef, "WitnessServer")
        cls.handler = named(server, ast.FunctionDef, "_serve_connection")
        cls.exceptions = [named(tree, ast.ClassDef, name)
                          for name in ("WitnessError", "WitnessConflict")]

    def scenario(self, *, phase="reserve", operation="webauthn.challenge.create",
                 peer=(4242, 65520, 65520), capture_error=None,
                 transition_error=None):
        events, captures, transitions, closed_fds, sent, errors = [], [], [], [], [], []
        # These are synthetic configured identities, not processes or admission.
        configuration = dict(requestTimeoutSeconds=7, peerUid=65520, peerGid=65520,
            releaseConsumerPeers={"verifier": dict(uid=20520, gid=20521)})
        request = dict(phase=phase, operation=operation)
        original = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("ascii")
        response = b'{"synthetic":"transition-spy-result-not-a-receipt"}'
        owner = {"pidfd": 424242, "testOnly": "not-a-real-peer-owner"}

        def timeout(value):
            events.append(("timeout", value))

        def close_connection():
            events.append(("connection-close",))

        connection = SimpleNamespace(settimeout=timeout, close=close_connection)

        def peer_identity(actual_connection):
            self.assertIs(actual_connection, connection)
            events.append(("peer",))
            return peer

        def receive(actual_connection):
            self.assertIs(actual_connection, connection)
            events.append(("receive",))
            return request, original

        def capture(pid):
            events.append(("capture",))
            captures.append(pid)
            if capture_error is not None:
                raise capture_error
            return owner

        def transition(actual_request, actual_original, *, peer_process):
            events.append(("transition",))
            transitions.append((actual_request, actual_original, peer_process))
            if transition_error is not None:
                raise transition_error
            return response

        def send_canonical(actual_connection, raw):
            self.assertIs(actual_connection, connection)
            events.append(("send-canonical",))
            sent.append(raw)

        def send_error(actual_connection, value):
            self.assertIs(actual_connection, connection)
            events.append(("send-error",))
            errors.append(value)

        def close_fd(fd):
            events.append(("fd-close",))
            closed_fds.append(fd)

        def diagnostic(stage, error):
            # Shared diagnostic behavior is covered by its own focused controls.
            events.append(("diagnostic", stage, type(error).__name__))

        namespace = dict(hashlib=hashlib, os=SimpleNamespace(close=close_fd),
            _peer_identity=peer_identity, _receive=receive,
            _capture_peer_process=capture, _send_canonical=send_canonical,
            _send=send_error, report_denial=diagnostic)
        module = ast.Module(body=[ast.ImportFrom(module="__future__",
            names=[ast.alias(name="annotations")], level=0),
            *copy.deepcopy(self.exceptions), copy.deepcopy(self.handler)], type_ignores=[])
        # The handler body is neither rewritten nor replaced by a fake handler.
        exec(compile(ast.fix_missing_locations(module), str(SOURCE), "exec"), namespace)
        server = SimpleNamespace(configuration=configuration,
            witness=SimpleNamespace(transition_bytes=transition))
        namespace["_serve_connection"](server, connection)
        self.assertEqual(events[:3], [("timeout", 7.0), ("peer",), ("receive",)])
        self.assertEqual(events.count(("connection-close",)), 1)
        self.assertEqual(events[-1], ("connection-close",))
        return SimpleNamespace(events=events, captures=captures, transitions=transitions,
            closed_fds=closed_fds, sent=sent, errors=errors, request=request,
            original=original, response=response, owner=owner)

    def denied(self, result, message):
        self.assertEqual(result.sent, [])
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0], {
            "schema": "serverware.policyAuthorityWitnessError/v1",
            "code": "witness_denied",
            "detailDigest": "sha256:" + hashlib.sha256(message.encode("utf-8")).hexdigest(),
        })

    def original_transition(self, result, owner):
        self.assertEqual(len(result.transitions), 1)
        request, original, actual_owner = result.transitions[0]
        self.assertIs(request, result.request)
        self.assertIs(original, result.original)
        self.assertIs(actual_owner, owner)

    def test_authorized_reserve_never_captures_and_passes_none(self):
        result = self.scenario()
        self.assertEqual(result.captures, [])
        self.assertEqual(result.closed_fds, [])
        self.original_transition(result, None)
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.sent), 1)
        self.assertIs(result.sent[0], result.response)
        self.assertEqual(result.events[3:], [
            ("transition",), ("send-canonical",), ("connection-close",)])

    def test_wrong_verifier_uid_or_gid_denies_before_capture_and_transition(self):
        for peer in ((4242, 65519, 65520), (4242, 65520, 65519)):
            with self.subTest(peer=peer):
                result = self.scenario(peer=peer)
                self.denied(result, "witness peer identity is not allowed")
                self.assertEqual(result.captures, [])
                self.assertEqual(result.transitions, [])
                self.assertEqual(result.closed_fds, [])

    def test_authorized_consume_passes_original_capture_owner_and_closes_fd(self):
        result = self.scenario(phase="credential-release-consume", operation="verifier",
                               peer=(4242, 20520, 20521))
        self.assertEqual(result.captures, [4242])
        self.original_transition(result, result.owner)
        self.assertEqual(result.closed_fds, [result.owner["pidfd"]])
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.sent), 1)
        self.assertIs(result.sent[0], result.response)
        self.assertEqual(result.events[3:], [("capture",), ("transition",),
            ("send-canonical",), ("fd-close",), ("connection-close",)])

    def test_consume_transition_exception_still_closes_original_capture_fd(self):
        error = ValueError("synthetic transition refusal")
        result = self.scenario(phase="credential-release-consume", operation="verifier",
            peer=(4242, 20520, 20521), transition_error=error)
        self.denied(result, str(error))
        self.assertEqual(result.captures, [4242])
        self.original_transition(result, result.owner)
        self.assertEqual(result.closed_fds, [result.owner["pidfd"]])
        self.assertEqual(result.events[-2:], [("fd-close",), ("connection-close",)])

    def test_failed_consumer_capture_refuses_without_transition_and_closes_connection(self):
        error = PermissionError(13, "synthetic capture refusal")
        result = self.scenario(phase="credential-release-consume", operation="verifier",
            peer=(4242, 20520, 20521), capture_error=error)
        self.denied(result, str(error))
        self.assertEqual(result.captures, [4242])
        self.assertEqual(result.transitions, [])
        # A failed capture returned no owner: its internal cleanup is not faked.
        self.assertEqual(result.closed_fds, [])

    def test_wrong_consumer_uid_gid_or_unknown_operation_denies_before_capture(self):
        for operation, peer in (("verifier", (4242, 20519, 20521)),
                                ("verifier", (4242, 20520, 20519)),
                                ("unknown-consumer", (4242, 20520, 20521))):
            with self.subTest(operation=operation, peer=peer):
                result = self.scenario(phase="credential-release-consume",
                    operation=operation, peer=peer)
                self.denied(result, "witness peer identity is not allowed")
                self.assertEqual(result.captures, [])
                self.assertEqual(result.transitions, [])
                self.assertEqual(result.closed_fds, [])


if __name__ == "__main__":
    unittest.main()
