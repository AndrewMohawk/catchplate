#!/usr/bin/env python3
"""Unexecuted linkage controls for fixed writer ingress, not launch evidence.

Read bounded source as AST only when the sealed verification lane runs. These
checks do not import or extract the active service, replace registry admission,
or claim a live socket, transaction, planner flow or authenticated ACK client.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, keywords, source


class RevocationWriterTransportSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.service = source("catchplate/authority_service.py", 2 * 1024 * 1024)
        cls.server = definition(cls.service, "AuthorityServer")
        cls.process = definition(cls.service, "AuthorityProcess")
        cls.served = definition(cls.server, "_serve_connection")
        cls.ingress = definition(cls.server, "_serve_revocation_writer")
        cls.adapter = definition(cls.process, "_persist_and_reserve_revocation_commitments")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_writer_only_ingress_receives_complete_originals_before_one_source_bounded_work(self):
        self.assertEqual([item.arg for item in self.ingress.args.args], ["self", "connection"])
        self.assertEqual([item.arg for item in self.ingress.args.kwonlyargs], ["deadline_ns", "prefix"])
        self.assertIsNone(self.ingress.args.kwarg)
        self.assertIsNone(self.ingress.args.vararg)
        self.shape(assigned(self.ingress, "process"), "self.process")
        guard, = [node for node in self.ingress.body if isinstance(node, ast.If)]
        self.shape(guard.test, '''type(process) is not AuthorityProcess
            or process.role_name != "planner-writer"
            or process.process_mode != "policy-authority-planner-writer"''')
        self.assertIsInstance(guard.body[0], ast.Raise)
        receive = call(self.ingress, "writer_transport._recv_request")
        self.shape(receive, "writer_transport._recv_request(connection, deadline_ns=deadline_ns, prefix=prefix)")
        allowance = call(self.ingress, "_ValidationWork")
        self.shape(allowance, "_ValidationWork(QueryReadValidationLimits())")
        self.assertLess(guard.end_lineno, receive.lineno)
        self.assertLess(receive.lineno, allowance.lineno)
        planning_ingress = definition(self.server, "_serve_revocation_planning")
        custody_ingress = definition(self.server, "_serve_revocation_custody")
        custody_read_ingress = definition(self.server, "_serve_revocation_custody_read")
        self.assertEqual(calls(self.ingress, "_ValidationWork"), [allowance])
        self.assertEqual(calls(self.server, "_ValidationWork"),
                         [allowance, call(planning_ingress, "_ValidationWork"),
                          call(custody_ingress, "_ValidationWork"),
                          call(custody_read_ingress, "_ValidationWork")])
        self.assertEqual(calls(self.server, "QueryReadValidationLimits"),
                         [call(self.ingress, "QueryReadValidationLimits"),
                          call(planning_ingress, "QueryReadValidationLimits"),
                          call(custody_ingress, "QueryReadValidationLimits"),
                          call(custody_read_ingress, "QueryReadValidationLimits")])

    def test_original_five_and_same_work_reach_real_composition_before_exact_ack_send(self):
        operation = call(self.ingress, "process._persist_and_reserve_revocation_commitments")
        self.shape(operation, '''process._persist_and_reserve_revocation_commitments(
            intent_bytes=originals[0], relay_bytes=originals[1], envelope_bytes=originals[2],
            evaluation_context_bytes=originals[3], historical_expectations_bytes=originals[4], work=work)''')
        owner, = [node for node in self.ingress.body if isinstance(node, ast.Assign)
                  and node.value is operation]
        self.assertIsInstance(owner.targets[0], ast.Tuple)
        self.assertTrue(all(isinstance(item, ast.Name) for item in owner.targets[0].elts))
        self.assertEqual([item.id for item in owner.targets[0].elts],
                         ["_receipt", "_reservation", "acknowledgment_bytes"])
        checks = calls(self.ingress, "writer_transport._check_deadline")
        self.assertEqual(len(checks), 2)
        for check in checks:
            self.shape(check, "writer_transport._check_deadline(deadline_ns)")
        sent = call(self.ingress, "writer_transport._send_ack")
        self.shape(sent, "writer_transport._send_ack(connection, acknowledgment_bytes, deadline_ns=deadline_ns)")
        self.assertLess(checks[0].lineno, operation.lineno)
        self.assertLess(operation.lineno, checks[1].lineno)
        self.assertLess(checks[1].lineno, sent.lineno)
        self.assertFalse(any(isinstance(node, (ast.Try, ast.Return)) for node in ast.walk(self.ingress)))
        for forbidden in ("_canonical", "json.loads", "_send_message", "_sign_internal",
                          "_verify_internal_envelope", "_connect", "psycopg.connect"):
            self.assertFalse(calls(self.ingress, forbidden))
        self.assertEqual(calls(self.service, "process._persist_and_reserve_revocation_commitments"), [operation])

    def test_existing_peer_guard_precedes_discriminator_and_detached_branch_cannot_fall_through(self):
        peer = call(self.served, "_peer_identity")
        guard, = [node for node in ast.walk(self.served) if isinstance(node, ast.If)
                  and ast.unparse(node.test) == "uid != self.peer_uid or gid != self.peer_gid"]
        self.assertIsInstance(guard.body[0], ast.Raise)
        prefix = call(self.served, "writer_transport._recv_prefix")
        self.shape(prefix, "writer_transport._recv_prefix(connection, deadline_ns=deadline_ns)")
        assignments = [node for node in ast.walk(self.served) if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "detached" for target in node.targets)]
        self.assertEqual(len(assignments), 2)
        self.shape(assignments[0].value, "False")
        self.shape(assignments[1].value,
                   '''prefix in (writer_transport.REQUEST_MAGIC, planning_transport.REQUEST_MAGIC,
                       custody_transport.RELAY_REQUEST_MAGIC, custody_transport.FORWARD_REQUEST_MAGIC,
                       custody_read_transport.REQUEST_MAGIC)''')
        routed = call(self.served, "self._serve_revocation_writer")
        self.shape(routed, "self._serve_revocation_writer(connection, deadline_ns=deadline_ns, prefix=prefix)")
        branch, = [node for node in ast.walk(self.served) if isinstance(node, ast.If)
                   and any(child is routed for child in ast.walk(node))]
        self.shape(branch.test, "prefix == writer_transport.REQUEST_MAGIC")
        self.assertEqual(len(branch.body), 2)
        self.assertIsInstance(branch.body[-1], ast.Return)
        self.assertEqual([peer.lineno, guard.lineno, prefix.lineno, routed.lineno],
                         sorted([peer.lineno, guard.lineno, prefix.lineno, routed.lineno]))
        self.assertLess(routed.lineno, call(self.served, "json.loads").lineno)
        self.assertLess(routed.lineno, call(self.served, "self.process.handle").lineno)

    def test_accept_queue_and_worker_share_deadline_and_all_normal_worker_paths_close(self):
        loop = definition(self.server, "serve_forever")
        accepted = call(loop, "self.socket.accept")
        deadline = call(loop, "writer_transport._deadline_ns")
        submitted = call(loop, "self.pool.submit")
        self.shape(deadline, "writer_transport._deadline_ns(self.timeout_seconds)")
        self.shape(submitted, "self.pool.submit(self._serve_connection, connection, deadline_ns=deadline_ns)")
        self.assertLess(accepted.lineno, deadline.lineno)
        self.assertLess(deadline.lineno, submitted.lineno)
        submission, = [node for node in ast.walk(loop) if isinstance(node, ast.Try)
                       and any(child is submitted for statement in node.body for child in ast.walk(statement))]
        failure, = submission.handlers
        self.shape(failure.type, "BaseException")
        cleanup = failure.body[0]
        self.assertIsInstance(cleanup, ast.Try)
        self.shape(cleanup.body[0].value, "connection.close()")
        self.shape(cleanup.handlers[0].type, "BaseException")
        self.assertIsInstance(cleanup.handlers[0].body[0], ast.Pass)
        self.shape(failure.body[1].value, "self.in_flight.release()")
        self.assertIsInstance(failure.body[2], ast.Raise)
        self.assertFalse(calls(self.served, "writer_transport._deadline_ns"))
        self.assertFalse(calls(self.ingress, "writer_transport._deadline_ns"))
        outer, = [node for node in self.served.body if isinstance(node, ast.Try)]
        self.assertEqual(len(outer.finalbody), 1)
        self.shape(outer.finalbody[0].value, "connection.close()")
        failure, = outer.handlers
        self.shape(failure.type, "Exception")
        self.shape(failure.body[0].test, "detached")
        self.assertIsInstance(failure.body[0].body[0], ast.Return)
        self.assertEqual(len(calls(self.served, "self._serve_revocation_writer")), 1)
        self.assertEqual(len(calls(self.ingress, "process._persist_and_reserve_revocation_commitments")), 1)

    def test_real_configuration_registry_and_atomic_owner_admissions_are_not_replaced(self):
        main = definition(self.service, "main")
        self.assertLess(call(main, "MeasuredConfiguration.load").lineno,
                        call(main, "AuthorityProcess").lineno)
        self.assertLess(call(main, "AuthorityProcess").lineno,
                        call(main, "AuthorityServer").lineno)
        mapped = call(self.adapter, "_revocation_writer_from_owned_configuration")
        composed = call(self.adapter, "authority_revocation_writer_composition._persist_commitments_on_configuration")
        self.assertLess(mapped.lineno, composed.lineno)
        self.shape(keywords(composed)["work"], "work")
        _, worker = source("catchplate/authority_revocation_writer_composition.py", 64 * 1024)
        actual = definition(worker, "_persist_commitments_on_configuration")
        verified = call(actual, "commitment._verify_commitments_on_work")
        policy = call(actual, "action._assert_policy_on_work")
        persisted = call(actual, "persistence._persist_and_reserve_request_on_configuration")
        self.assertLess(verified.lineno, policy.lineno)
        self.assertLess(policy.lineno, persisted.lineno)
        self.assertFalse(calls(actual, "_ValidationWork"))
        _, registry = source("catchplate/authority_transition_registry.py")
        self.shape(assigned(registry, "_CLOSURE_ERRORS"), "_registry_closure_errors()")
        guard, = [node for node in registry.body if isinstance(node, ast.If)]
        self.shape(guard.test, "_CLOSURE_ERRORS")
        self.assertIsInstance(guard.body[0], ast.Raise)

    def test_legacy_purposes_and_existing_transport_limits_stay_separate(self):
        handle = definition(self.process, "handle")
        writer, = [node for node in ast.walk(handle) if isinstance(node, ast.If)
                   and ast.unparse(node.test) == "self.role_name == 'planner-writer'"]
        self.shape(keywords(call(writer, "self._verify_internal_envelope"))["allowed_purposes"],
                   "{'persist-measured-plan', 'read-persisted-plan', 'reserve-execution-envelope'}")
        self.assertFalse(calls(handle, "self._serve_revocation_writer"))
        self.assertFalse(calls(handle, "self._persist_and_reserve_revocation_commitments"))
        self.shape(assigned(self.service, "MAX_MESSAGE_BYTES"), "authority_contract.MAX_RESULT_BYTES")
        _, legacy = source("catchplate/authority_transport.py", 64 * 1024)
        receive = definition(legacy, "_recv_revocation_invocation_bytes")
        send = definition(legacy, "_socket_request_revocation_bytes")
        self.shape(keywords(call(receive, "_recv_message_bytes"))["maximum_bytes"],
                   "authority_contract.MAX_REQUEST_BYTES")
        self.shape(keywords(call(send, "_socket_request_bytes"))["maximum_bytes"],
                   "authority_contract.MAX_REQUEST_BYTES")
        legacy_send = definition(self.service, "_send_message_until")
        self.shape(assigned(legacy_send, "encoded"), "_canonical(dict(value))")
        writes = calls(legacy_send, "writer_transport._send_exact_until")
        self.assertEqual(len(writes), 2)
        self.shape(writes[0], '''writer_transport._send_exact_until(connection,
            len(encoded).to_bytes(8, "big"), deadline_ns=deadline_ns)''')
        self.shape(writes[1], "writer_transport._send_exact_until(connection, encoded, deadline_ns=deadline_ns)")
        self.assertEqual(len(calls(self.served, "_send_message_until")), 2)
        self.assertFalse(calls(self.served, "_send_message"))
        text, transfer = source("catchplate/authority_revocation_writer_transport.py", 64 * 1024)
        for imported in (node for node in transfer.body if isinstance(node, (ast.Import, ast.ImportFrom))):
            for forbidden in ("authority_service", "authority_transition_registry", "psycopg", "import db"):
                self.assertNotIn(forbidden, ast.unparse(imported))
        self.assertNotIn("_ValidationWork(", text)
        self.assertNotIn("QueryReadValidationLimits(", text)


if __name__ == "__main__":
    unittest.main()
