#!/usr/bin/env python3
"""Source contracts for original witness-request and receipt byte preservation.

These controls inspect the actual service definitions without importing the
active service/registry or executing extracted functions. They do not open a
socket, invent a successful witness/ACL verdict, or establish runtime transport,
signature, deadline, peer identity or production admission evidence.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
ARGUMENTS = (
    "phase", "operation", "request_digest", "deadline_monotonic_ns",
    "capability_id", "result_digest", "predecessor_receipt",
)
RECEIPT_FIELDS = {
    "schema", "envelopeId", "parentEnvelopeId", "phase", "operation",
    "requestDigest", "capabilityId", "resultDigest", "witnessIdentityDigest",
    "sequence", "fence", "headDigest", "predecessorHeadDigest",
    "predecessorReceiptDigest", "logPredecessorHeadDigest", "deadlineMonotonicNs",
    "issuedAtEpochNs", "generationSequence", "generationDigest",
    "canonicalRequestDigest", "signature",
}


def named(node, kind, name):
    found = [item for item in node.body if isinstance(item, kind) and item.name == name]
    if len(found) != 1:
        raise AssertionError("witness source definition is not unique: " + name)
    return found[0]


def calls(node, expression):
    return sorted((item for item in ast.walk(node) if isinstance(item, ast.Call)
        and ast.unparse(item.func) == expression), key=lambda item: (item.lineno, item.col_offset))


def assignment(node, name):
    found = [item for item in ast.walk(node) if isinstance(item, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in item.targets)]
    if len(found) != 1:
        raise AssertionError("witness source assignment is not unique: " + name)
    return found[0]


def rejecting(node, message):
    found = [item for item in ast.walk(node) if isinstance(item, ast.If)
        and any(isinstance(statement, ast.Raise) and isinstance(statement.exc, ast.Call)
            and statement.exc.args and isinstance(statement.exc.args[0], ast.Constant)
            and statement.exc.args[0].value == message for statement in item.body)]
    if len(found) != 1:
        raise AssertionError("witness source denial is not unique: " + message)
    return found[0]


class AuthorityWitnessTransportSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = ROOT / "catchplate/authority_service.py"
        if source.stat().st_size > 2 * 1024 * 1024:
            raise AssertionError("authority service exceeds the bounded source fixture")
        cls.tree = ast.parse(source.read_text(encoding="utf-8"))
        cls.process = named(cls.tree, ast.ClassDef, "AuthorityProcess")
        cls.wrapper = named(cls.process, ast.FunctionDef, "_witness_transition")
        cls.request_wrapper = named(cls.process, ast.FunctionDef, "_witness_transition_with_request")
        cls.worker = named(cls.process, ast.FunctionDef, "_witness_transition_with_originals")
        cls.transport_wrapper = named(cls.tree, ast.FunctionDef, "_socket_request_bytes")
        cls.transport = named(cls.tree, ast.FunctionDef, "_socket_request_bytes_with_response")
        cls.receiver = named(cls.tree, ast.FunctionDef, "_recv_message_with_bytes")
        cls.service_sender = named(cls.tree, ast.FunctionDef, "_send_encoded_message")
        framing = ROOT / "catchplate/authority_transport.py"
        if framing.stat().st_size > 64 * 1024:
            raise AssertionError("authority framing exceeds the bounded source fixture")
        cls.framing = ast.parse(framing.read_text(encoding="utf-8"))
        cls.sender = named(cls.framing, ast.FunctionDef, "_send_encoded_message")
        cls.frame_receiver = named(cls.framing, ast.FunctionDef, "_recv_message_bytes")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual),
            ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_legacy_mapping_send_uses_its_original_encoding_and_shared_fixed_framing(self):
        legacy = named(self.tree, ast.FunctionDef, "_send_message")
        self.assertEqual(len(legacy.body), 2)
        self.shape(assignment(legacy, "encoded").value, "_canonical(dict(value))")
        self.shape(legacy.body[1].value, "_send_encoded_message(connection, encoded)")
        delegated = calls(self.service_sender, "authority_transport._send_encoded_message")
        self.assertEqual(len(delegated), 1)
        self.shape(delegated[0], "authority_transport._send_encoded_message(connection, encoded, maximum_bytes=MAX_MESSAGE_BYTES)")
        guard = rejecting(self.sender, "authority response size is invalid")
        self.shape(guard.test, "type(encoded) is not bytes or not 2 <= len(encoded) <= maximum_bytes")
        sent = calls(self.sender, "connection.sendall")
        self.assertEqual(len(sent), 1)
        self.shape(sent[0], "connection.sendall(len(encoded).to_bytes(8, 'big') + encoded)")
        self.assertLess(guard.end_lineno, sent[0].lineno)
        self.assertFalse(calls(self.sender, "_canonical"))

    def test_raw_transport_rejects_nonexact_or_out_of_bounds_bytes_before_socket_creation(self):
        guard = rejecting(self.transport, "authority request bytes are not exact and bounded")
        self.shape(guard.test, "type(encoded) is not bytes or not 2 <= len(encoded) <= MAX_MESSAGE_BYTES")
        opened = calls(self.transport, "socket.socket")
        self.assertEqual(len(opened), 1)
        self.shape(opened[0], "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)")
        self.assertLess(guard.end_lineno, opened[0].lineno)
        self.assertFalse(calls(self.transport, "bytes"))
        self.assertFalse(calls(self.transport, "_canonical"))
        self.assertFalse(calls(self.transport, "json.loads"))
        self.assertFalse(any(isinstance(item, (ast.For, ast.While)) for item in ast.walk(self.transport)))

    def test_raw_transport_keeps_timeout_peer_checks_shared_response_and_unconditional_close(self):
        scopes = [node for node in self.transport.body if isinstance(node, ast.Try)]
        self.assertEqual(len(scopes), 1)
        scope = scopes[0]
        self.assertFalse(scope.handlers)
        self.assertFalse(scope.orelse)
        self.assertEqual(len(scope.finalbody), 1)
        self.shape(scope.finalbody[0].value, "connection.close()")
        self.shape(scope.body[0].value, "connection.settimeout(timeout_seconds)")
        self.shape(scope.body[1].value, "connection.connect(path)")
        peer = calls(scope, "_peer_identity")
        self.assertEqual(len(peer), 1)
        self.shape(peer[0], "_peer_identity(connection)")
        guard = rejecting(scope, "authority socket server identity is not exact")
        self.shape(guard.test, "peer_uid != expected_peer_uid or peer_gid != expected_peer_gid")
        sent = calls(scope, "_send_encoded_message")
        self.assertEqual(len(sent), 1)
        self.shape(sent[0], "_send_encoded_message(connection, encoded)")
        self.assertLess(peer[0].lineno, guard.lineno)
        self.assertLess(guard.end_lineno, sent[0].lineno)
        self.assertIsInstance(scope.body[-1], ast.Return)
        self.shape(scope.body[-1].value, "_recv_message_with_bytes(connection)")
        legacy = named(self.tree, ast.FunctionDef, "_socket_request")
        self.assertEqual(len(calls(legacy, "_send_message")), 1)
        self.assertEqual(len(calls(legacy, "_recv_message")), 1)
        self.assertEqual(len(calls(legacy, "_peer_identity")), 1)

    def test_shared_response_parser_still_requires_bounded_canonical_object(self):
        receiver = self.receiver
        framing = self.frame_receiver
        self.shape(assignment(framing, "size").value, "int.from_bytes(_recv_exact(connection, 8), 'big')")
        guard = rejecting(framing, "authority message size is invalid")
        self.shape(guard.test, "not 2 <= size <= maximum_bytes")
        self.assertLess(guard.end_lineno, framing.body[-1].lineno)
        self.shape(framing.body[-1].value, "_recv_exact(connection, size)")
        encoded = assignment(receiver, "encoded")
        self.shape(encoded.value, "_recv_message_bytes(connection)")
        wrapper = named(self.tree, ast.FunctionDef, "_recv_message_bytes")
        self.assertEqual([argument.arg for argument in wrapper.args.kwonlyargs], ["maximum_bytes"])
        self.shape(wrapper.args.kw_defaults[0], "MAX_MESSAGE_BYTES")
        self.shape(calls(wrapper, "authority_transport._recv_message_bytes")[0],
            "authority_transport._recv_message_bytes(connection, maximum_bytes=maximum_bytes)")
        self.shape(assignment(receiver, "value").value, "json.loads(encoded)")
        closed = rejecting(receiver, "authority message is not canonical")
        self.shape(closed.test, "not isinstance(value, dict) or _canonical(value) != encoded")
        self.shape(receiver.body[-1].value, "(encoded, value)")

    def test_receipt_only_wrapper_forwards_all_seven_arguments_without_new_defaults(self):
        self.assertEqual(ast.dump(self.wrapper.args), ast.dump(self.worker.args))
        self.assertEqual(ast.dump(self.wrapper.args), ast.dump(self.request_wrapper.args))
        self.assertEqual(tuple(arg.arg for arg in self.wrapper.args.kwonlyargs), ARGUMENTS)
        self.assertEqual(len(self.wrapper.body), 2)
        self.assertIsInstance(self.wrapper.body[0], ast.Assign)
        self.assertEqual(ast.unparse(self.wrapper.body[0].targets[0]), "(_request_bytes, receipt)")
        delegated = calls(self.wrapper, "self._witness_transition_with_request")
        self.assertEqual(len(delegated), 1)
        self.assertFalse(delegated[0].args)
        self.assertEqual(tuple(keyword.arg for keyword in delegated[0].keywords), ARGUMENTS)
        for keyword in delegated[0].keywords:
            self.shape(keyword.value, keyword.arg)
        self.assertIsInstance(self.wrapper.body[-1], ast.Return)
        self.shape(self.wrapper.body[-1].value, "receipt")

    def test_signed_request_is_encoded_once_and_identical_local_bytes_are_sent_bound_and_returned(self):
        signed = assignment(self.worker, "request")
        self.assertEqual(len(calls(signed, "self.signing_key.sign")), 1)
        encoded = assignment(self.worker, "request_bytes")
        self.shape(encoded.value, "_canonical(request)")
        encodings = [call for call in calls(self.worker, "_canonical")
            if len(call.args) == 1 and ast.unparse(call.args[0]) == "request"]
        self.assertEqual(encodings, [encoded.value])
        sent = calls(self.worker, "_socket_request_bytes_with_response")
        self.assertEqual(len(sent), 1)
        self.shape(sent[0].args[1], "request_bytes")
        self.assertLess(signed.end_lineno, encoded.lineno)
        self.assertLess(encoded.end_lineno, sent[0].lineno)
        digest = [call for call in calls(self.worker, "_domain_digest")
            if len(call.args) == 2 and ast.unparse(call.args[1]) == "request_bytes"]
        self.assertEqual(len(digest), 1)
        self.shape(digest[0], "_domain_digest(WITNESS_REQUEST_SCHEMA_V2, request_bytes)")
        self.assertGreater(digest[0].lineno, sent[0].end_lineno)
        stored = [node for node in ast.walk(self.worker) if isinstance(node, ast.Name)
            and node.id == "request_bytes" and isinstance(node.ctx, ast.Store)]
        self.assertEqual(len(stored), 1)
        returned = [node for node in ast.walk(self.worker) if isinstance(node, ast.Return)]
        self.assertEqual(returned, [self.worker.body[-1]])
        self.shape(returned[0].value, "(request_bytes, response_bytes, dict(response))")
        self.assertFalse(calls(self.worker, "_socket_request"))

    def test_existing_phases_registry_role_and_both_deadline_checks_remain_required(self):
        guard = rejecting(self.worker, "external replay witness v2 transition is invalid")
        self.shape(guard.test, """
            phase not in {'reserve', 'commit', 'abort', 'reconcile', 'webauthn-trust-publish'}
            or operation not in authority_transition_registry.PLANNABLE_OPERATIONS
            or (phase not in {'abort', 'reconcile'} and time.monotonic_ns() >= deadline_monotonic_ns)
        """)
        signer = rejecting(self.worker, "verifier signer is unavailable")
        self.shape(signer.test, "self.signing_key is None or self.role_name != 'verifier'")
        self.assertLess(guard.end_lineno, signer.lineno)
        sent = calls(self.worker, "_socket_request_bytes_with_response")[0]
        actual = {keyword.arg: keyword.value for keyword in sent.keywords}
        self.assertEqual(set(actual), {"timeout_seconds", "expected_peer_uid", "expected_peer_gid"})
        self.shape(actual["timeout_seconds"], """
            float(witness['requestTimeoutSeconds']) if phase in {'abort', 'reconcile'}
            else min(float(witness['requestTimeoutSeconds']),
                max(0.001, (deadline_monotonic_ns - time.monotonic_ns()) / 1_000_000_000))
        """)
        self.shape(actual["expected_peer_uid"], "int(witness['serviceUid'])")
        self.shape(actual["expected_peer_gid"], "int(witness['serviceGid'])")
        response = rejecting(self.worker, "external replay witness v2 response is not exact")
        self.assertIn(ast.dump(ast.parse("phase not in {'abort', 'reconcile'} and "
            "time.monotonic_ns() >= deadline_monotonic_ns", mode="eval").body),
            {ast.dump(node) for node in ast.walk(response.test)})

    def test_closed_receipt_and_real_pinned_signature_verification_precede_byte_publication(self):
        fields = assignment(self.worker, "required").value
        self.assertIsInstance(fields, ast.Set)
        self.assertEqual({node.value for node in fields.elts}, RECEIPT_FIELDS)
        self.assertEqual(len(fields.elts), 21)
        guard = rejecting(self.worker, "external replay witness v2 response is not exact")
        conditions = {ast.dump(node) for node in ast.walk(guard.test)}
        for expression in (
            "set(response) != required",
            "response.get('canonicalRequestDigest') != _domain_digest(WITNESS_REQUEST_SCHEMA_V2, request_bytes)",
            "response.get('witnessIdentityDigest') != witness.get('identityDigest')",
            "response.get('generationSequence') != generation.get('sequence')",
            "response.get('generationDigest') != generation.get('digest')",
            "response.get('predecessorReceiptDigest') != predecessor_digest",
        ):
            self.assertIn(ast.dump(ast.parse(expression, mode="eval").body), conditions)
        self.shape(assignment(self.worker, "witness_key").value,
            "Ed25519PublicKey.from_public_bytes(_b64url_decode(witness['signingPublicKeyBase64Url'], size=32))")
        verified = calls(self.worker, "witness_key.verify")
        self.assertEqual(len(verified), 1)
        self.shape(verified[0], "witness_key.verify(signature, "
            "_domain_digest(WITNESS_RECEIPT_SCHEMA_V2, _canonical(unsigned_response)).encode('ascii'))")
        self.assertLess(guard.end_lineno, verified[0].lineno)
        scopes = [node for node in self.worker.body if isinstance(node, ast.Try)
            and verified[0] in list(ast.walk(node))]
        self.assertEqual(len(scopes), 1)
        self.assertEqual(len(scopes[0].handlers), 1)
        self.shape(scopes[0].handlers[0].type, "InvalidSignature")
        self.assertIsInstance(scopes[0].handlers[0].body[0], ast.Raise)
        self.assertLess(scopes[0].end_lineno, self.worker.body[-1].lineno)

    def test_new_private_result_is_not_a_public_route_cache_or_re_signing_path(self):
        uses = calls(self.process, "self._witness_transition_with_request")
        self.assertEqual(uses, calls(self.wrapper, "self._witness_transition_with_request"))
        self.assertEqual(len(uses), 1)
        original_uses = calls(self.process, "self._witness_transition_with_originals")
        self.assertEqual(original_uses, calls(self.request_wrapper, "self._witness_transition_with_originals"))
        self.assertEqual(len(original_uses), 1)
        self.assertEqual(len(calls(self.worker, "self.signing_key.sign")), 1)
        self.assertFalse(any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(self.worker)))
        self.assertFalse(any(isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store)
            for node in ast.walk(self.worker)))
        dispatcher = named(self.process, ast.FunctionDef, "handle")
        self.assertFalse(calls(dispatcher, "self._witness_transition_with_request"))
        self.assertFalse(calls(dispatcher, "self._witness_transition_with_originals"))
        self.assertFalse(calls(dispatcher, "_socket_request_bytes"))
        self.assertFalse(calls(dispatcher, "_socket_request_bytes_with_response"))

    def test_existing_receive_and_socket_interfaces_delegate_without_reencoding_response(self):
        receiver = named(self.tree, ast.FunctionDef, "_recv_message")
        self.assertEqual(len(receiver.body), 2)
        self.assertIsInstance(receiver.body[0], ast.Assign)
        self.assertEqual(ast.unparse(receiver.body[0].targets[0]), "(_encoded, value)")
        self.shape(receiver.body[0].value, "_recv_message_with_bytes(connection)")
        self.shape(receiver.body[1].value, "value")
        self.assertEqual(ast.dump(self.transport_wrapper.args), ast.dump(self.transport.args))
        self.assertEqual(len(self.transport_wrapper.body), 2)
        self.assertEqual(ast.unparse(self.transport_wrapper.body[0].targets[0]), "(_response_bytes, response)")
        self.shape(self.transport_wrapper.body[0].value, """
            _socket_request_bytes_with_response(path, encoded,
                timeout_seconds=timeout_seconds, expected_peer_uid=expected_peer_uid,
                expected_peer_gid=expected_peer_gid)
        """)
        self.shape(self.transport_wrapper.body[1].value, "response")
        for wrapper in (receiver, self.transport_wrapper):
            self.assertFalse(calls(wrapper, "_canonical"))
            self.assertFalse(calls(wrapper, "json.loads"))
            self.assertFalse(any(isinstance(node, (ast.Try, ast.For, ast.While)) for node in ast.walk(wrapper)))

    def test_request_pair_wrapper_discards_only_original_response_bytes(self):
        wrapper = self.request_wrapper
        self.assertEqual(ast.dump(wrapper.args), ast.dump(self.worker.args))
        self.assertEqual(tuple(arg.arg for arg in wrapper.args.kwonlyargs), ARGUMENTS)
        self.assertEqual(len(wrapper.body), 2)
        self.assertEqual(ast.unparse(wrapper.body[0].targets[0]), "(request_bytes, _response_bytes, receipt)")
        delegated = calls(wrapper, "self._witness_transition_with_originals")
        self.assertEqual(len(delegated), 1)
        self.assertFalse(delegated[0].args)
        self.assertEqual(tuple(keyword.arg for keyword in delegated[0].keywords), ARGUMENTS)
        for keyword in delegated[0].keywords:
            self.shape(keyword.value, keyword.arg)
        self.shape(wrapper.body[1].value, "(request_bytes, receipt)")
        self.assertFalse(calls(wrapper, "_canonical"))
        self.assertFalse(calls(wrapper, "self.signing_key.sign"))
        self.assertFalse(any(isinstance(node, (ast.Try, ast.For, ast.While)) for node in ast.walk(wrapper)))

    def test_original_response_is_received_before_parse_and_never_rebuilt_for_publication(self):
        received = assignment(self.receiver, "encoded")
        parsed = assignment(self.receiver, "value")
        self.shape(received.value, "_recv_message_bytes(connection)")
        self.assertLess(received.end_lineno, parsed.lineno)
        self.shape(parsed.value, "json.loads(encoded)")
        self.assertEqual(len(calls(self.receiver, "json.loads")), 1)
        self.assertEqual(len(calls(self.receiver, "_canonical")), 1)
        self.shape(self.receiver.body[-1].value, "(encoded, value)")
        received_response = [node for node in ast.walk(self.worker) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Tuple) and any(isinstance(value, ast.Name)
                and value.id == "response_bytes" for value in target.elts) for target in node.targets)]
        self.assertEqual(len(received_response), 1)
        self.assertEqual(ast.unparse(received_response[0].targets[0]), "(response_bytes, response)")
        self.assertEqual(ast.unparse(received_response[0].value.func), "_socket_request_bytes_with_response")
        stored = [node for node in ast.walk(self.worker) if isinstance(node, ast.Name)
            and node.id == "response_bytes" and isinstance(node.ctx, ast.Store)]
        self.assertEqual(len(stored), 1)
        self.assertFalse([call for call in calls(self.worker, "_canonical")
            if len(call.args) == 1 and ast.unparse(call.args[0]) == "response"])
        self.assertFalse(calls(self.worker, "bytes"))
        verified = calls(self.worker, "witness_key.verify")
        self.assertEqual(len(verified), 1)
        self.assertLess(received_response[0].end_lineno, verified[0].lineno)
        self.assertLess(verified[0].end_lineno, self.worker.body[-1].lineno)
        self.shape(self.worker.body[-1].value, "(request_bytes, response_bytes, dict(response))")

    def test_truncated_invalid_or_noncanonical_frames_cannot_publish_original_bytes(self):
        exact = named(self.framing, ast.FunctionDef, "_recv_exact")
        loop = [node for node in exact.body if isinstance(node, ast.While)]
        self.assertEqual(len(loop), 1)
        closed = rejecting(exact, "authority socket closed early")
        self.shape(closed.test, "not chunk")
        appended = calls(exact, "chunks.append")
        self.assertEqual(len(appended), 1)
        self.assertLess(closed.end_lineno, appended[0].lineno)
        delegated = named(self.tree, ast.FunctionDef, "_recv_exact")
        self.shape(calls(delegated, "authority_transport._recv_exact")[0],
            "authority_transport._recv_exact(connection, count)")
        size = rejecting(self.frame_receiver, "authority message size is invalid")
        self.assertLess(size.end_lineno, self.frame_receiver.body[-1].lineno)
        parsers = [node for node in self.receiver.body if isinstance(node, ast.Try)]
        self.assertEqual(len(parsers), 1)
        parser = parsers[0]
        self.assertEqual(len(parser.handlers), 1)
        self.shape(parser.handlers[0].type, "(UnicodeDecodeError, json.JSONDecodeError)")
        self.assertIsInstance(parser.handlers[0].body[0], ast.Raise)
        self.shape(parser.handlers[0].body[0].exc, "AuthorityServiceError('authority message is not JSON')")
        self.shape(parser.handlers[0].body[0].cause, "exc")
        canonical = rejecting(self.receiver, "authority message is not canonical")
        self.assertLess(parser.end_lineno, canonical.lineno)
        self.assertLess(canonical.end_lineno, self.receiver.body[-1].lineno)
        self.assertEqual([node for node in ast.walk(self.receiver) if isinstance(node, ast.Return)],
            [self.receiver.body[-1]])
        self.shape(self.receiver.body[-1].value, "(encoded, value)")


if __name__ == "__main__":
    unittest.main()
