#!/usr/bin/env python3
"""Nonimporting linkage for the private authenticated writer composition.

These bounded source controls do not execute extracted functions, import the
active service/database/registry, or establish launch, socket, SQL, signature,
rollback or durable acknowledgment admission. The inert worker owns aliases;
its local configuration pins require the actual measured service path. Signed
sender claims still require measured policy and both genuine retained replays.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, keywords, source


ORIGINALS = ["intent_bytes", "relay_bytes", "envelope_bytes", "evaluation_context_bytes",
             "historical_expectations_bytes"]


class RevocationWriterCompositionSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.tree = source("serverware/authority_revocation_writer_composition.py", 64 * 1024)
        cls.worker = definition(cls.tree, "_persist_commitments_on_configuration")
        _, cls.service = source("serverware/authority_service.py", 2 * 1024 * 1024)
        cls.process = definition(cls.service, "AuthorityProcess")
        cls.adapter = definition(cls.process, "_persist_and_reserve_revocation_commitments")
        cls.continuation = definition(cls.service, "_revocation_writer_from_owned_configuration")
        _, cls.persistence = source("serverware/authority_revocation_persistence.py", 64 * 1024)

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_private_service_accepts_only_five_originals_and_existing_work_not_claim_or_callback_overrides(self):
        self.assertEqual([item.arg for item in self.adapter.args.args], ["self"])
        self.assertEqual([item.arg for item in self.adapter.args.kwonlyargs], ORIGINALS + ["work"])
        self.assertEqual([item.arg for item in self.worker.args.args], ["configuration"])
        self.assertEqual([item.arg for item in self.worker.args.kwonlyargs], ORIGINALS + [
            "owned_payload", "configuration_digest", "generation_sequence", "generation_digest",
            "maximum_age_ns", "work"])
        for function in (self.adapter, self.worker):
            self.assertIsNone(function.args.vararg)
            self.assertIsNone(function.args.kwarg)
            self.assertTrue(all(value is None for value in function.args.kw_defaults))
        # This inert composition neither imports an active role nor accepts a
        # successful receiver DTO, operation, opener, clock, signer or new limit.
        for forbidden in ("authority_service", "authority_transition_registry", "from serverware import db",
                "import psycopg", "Ed25519PrivateKey", "_ValidationWork(", "_PackagingLedger(",
                "_ProducedIntent", "_ProducedRelay", "_AuthenticatedCommitments("):
            self.assertNotIn(forbidden, self.text)

    def test_service_owns_complete_measured_payload_and_scalar_pins_before_any_launch_or_key_callback(self):
        adapter = self.adapter
        guards = [node for node in adapter.body if isinstance(node, ast.If)]
        self.assertEqual(len(guards), 3)
        self.shape(guards[0].test, '''self.role_name != "planner-writer"
            or self.process_mode != "policy-authority-planner-writer"
            or type(self.configuration) is not MeasuredConfiguration''')
        self.shape(assigned(adapter, "configuration"), "self.configuration")
        payload_pin, = [node for node in adapter.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Tuple) and [ast.unparse(item) for item in target.elts]
                    == ["payload", "configuration_digest"] for target in node.targets)]
        self.shape(payload_pin.value, "(configuration.payload, configuration.digest)")
        originals = call(adapter, "authority_revocation_writer_composition._validate_originals")
        self.shape(originals, '''authority_revocation_writer_composition._validate_originals(
            intent_bytes=intent_bytes, relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes)''')
        ledger = call(adapter, "authority_revocation_configuration.capability.capture._SharedLedger")
        self.shape(ledger, "authority_revocation_configuration.capability.capture._SharedLedger(work)")
        self.shape(guards[1].test, "type(payload) is not dict")
        owned = assigned(adapter, "owned_payload")
        self.shape(owned, '''authority_revocation_configuration._ConfigurationCapture(
            ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES).visit(payload)''')
        self.shape(guards[2].test, '''type(owned_payload.get("roles")) is not dict
            or type(owned_payload["roles"].get("planner-writer")) is not dict''')
        sequence = assigned(adapter, "generation_sequence")
        generation = assigned(adapter, "generation_digest")
        age = assigned(adapter, "maximum_age_ns")
        self.shape(sequence, 'owned_payload["generationSequence"]')
        self.shape(generation, 'owned_payload["generationDigest"]')
        self.shape(age, 'owned_payload["roles"]["planner-writer"]["maximumInternalAgeNs"]')
        self.assertEqual([ast.unparse(node) for node in calls(adapter,
            "authority_revocation_configuration.capability.shape._integer")], [
                "authority_revocation_configuration.capability.shape._integer(generation_sequence, minimum=1)",
                "authority_revocation_configuration.capability.shape._integer(maximum_age_ns, minimum=1)"])
        factory = call(adapter, "_revocation_writer_from_owned_configuration")
        self.shape(factory, '''_revocation_writer_from_owned_configuration(owned_payload=owned_payload,
            configuration_digest=configuration_digest, work=work)''')
        snapshot = assigned(adapter, "configuration_snapshot")
        self.shape(snapshot, "persistence._snapshot_configuration()")
        delegated = call(adapter, "authority_revocation_writer_composition._persist_commitments_on_configuration")
        self.shape(delegated, '''authority_revocation_writer_composition._persist_commitments_on_configuration(
            configuration_snapshot, intent_bytes=intent_bytes, relay_bytes=relay_bytes,
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes, owned_payload=owned_payload,
            configuration_digest=configuration_digest, generation_sequence=generation_sequence,
            generation_digest=generation_digest, maximum_age_ns=maximum_age_ns, work=work)''')
        self.assertIs(adapter.body[-1].value, delegated)
        ordered = (payload_pin, originals, ledger, owned, sequence, generation, age, factory, snapshot, delegated)
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        self.assertEqual(len(calls(adapter, "persistence._snapshot_configuration")), 1)
        self.assertFalse(calls(adapter, "min"))
        for node in ast.walk(adapter):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
                self.assertLess(node.lineno, originals.lineno)
        for forbidden in ("self._persist_and_reserve_revocation_plan", "self._revocation_planner_persistence",
                "authority_launch_guard.generation", "time.monotonic_ns", "time.time_ns"):
            self.assertFalse(calls(adapter, forbidden))

    def test_fixed_writer_continuation_uses_exclusive_descriptor_then_generation_last_and_real_key_mapper(self):
        continuation = self.continuation
        self.assertEqual([item.arg for item in continuation.args.kwonlyargs],
                         ["owned_payload", "configuration_digest", "work"])
        callbacks = calls(continuation, "authority_revocation_configuration.production._callback")
        self.assertEqual(len(callbacks), 3)
        for actual, expected in zip(callbacks, (
                'authority_revocation_configuration.production._callback(work, lambda: authority_launch_guard.require_active("planner-writer"))',
                '''authority_revocation_configuration.production._callback(work,
                    lambda: _read_dsn_descriptor("SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN"))''',
                'authority_revocation_configuration.production._callback(work, lambda: dict(authority_launch_guard.generation()))')):
            self.shape(actual, expected)
        mapper = call(continuation, "authority_revocation_writer_configuration._persistence_from_configuration_on_work")
        self.shape(mapper, '''authority_revocation_writer_configuration._persistence_from_configuration_on_work(
            payload=owned_payload, configuration_digest=configuration_digest,
            generation=generation, persistence_dsn=persistence_dsn, work=work)''')
        self.assertIs(continuation.body[-1].value, mapper)
        self.assertIs(continuation.body[-2].value, callbacks[2])
        self.assertEqual([node.lineno for node in (*callbacks, mapper)],
                         sorted(node.lineno for node in (*callbacks, mapper)))
        _, mapper_tree = source("serverware/authority_revocation_writer_configuration.py", 64 * 1024)
        factory = definition(mapper_tree, "_persistence_from_configuration_on_work")
        capture = call(factory, "configuration._capture_configuration_on_work")
        self.shape(capture, '''configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)''')
        keys = calls(factory, "configuration._key")
        self.assertEqual(len(keys), 2)
        actual_owner = call(factory, "persistence.RevocationPlannerPersistence")
        fields = keywords(actual_owner)
        self.shape(fields["planner_public_key"], "planner_key")
        self.shape(fields["verifier_public_key"], "verifier_key")
        self.shape(fields["persistence_dsn"], "persistence_dsn")
        self.shape(fields["writer_database_identity"], "database_identity")
        self.assertEqual([node.lineno for node in (capture, *keys, actual_owner)],
                         sorted(node.lineno for node in (capture, *keys, actual_owner)))
        _, config_tree = source("serverware/authority_revocation_configuration.py", 64 * 1024)
        shared = definition(config_tree, "_capture_configuration_on_work")
        self.shape(call(shared, "_generation_binding"), "_generation_binding(owned, launch, configuration_digest, work)")
        binding = definition(config_tree, "_generation_binding")
        self.shape(call(binding, "capability.plan._same"), '''capability.plan._same(
            (generation["sequence"], generation["digest"], generation["predecessorDigest"],
             generation["minimumRollbackSequence"], generation["operationManifestDigest"]),
            (payload["generationSequence"], payload["generationDigest"], payload["generationPredecessorDigest"],
             payload["generationMinimumRollbackSequence"], authority.OPERATION_MANIFEST_DIGEST), work,
            "issuer configuration differs from the active launch generation")''')
        for function in (continuation, self.adapter):
            for forbidden in ("SERVERWARE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN", "self.role_config",
                    "self.signing_key", "_produce_revocation_observed_plan"):
                self.assertNotIn(forbidden, ast.unparse(function))

    def test_worker_recaptures_full_payload_and_holds_exact_seven_tuple_before_clock_or_key_callbacks(self):
        worker = self.worker
        self.shape(worker.body[1].value, "persistence._validate_configuration(configuration)")
        self.shape(assigned(worker, "ledger"), "commitment.capture._SharedLedger(work)")
        originals = call(worker, "_validate_originals")
        self.shape(originals, '''_validate_originals(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes)''')
        self.shape(call(worker, "commitment._pins"),
                   "commitment._pins(configuration_digest, generation_sequence, generation_digest)")
        self.shape(call(worker, "commitment.plan.contract._integer"),
                   "commitment.plan.contract._integer(maximum_age_ns, minimum=1)")
        guard, = [node for node in worker.body if isinstance(node, ast.If)]
        self.shape(guard.test, "type(owned_payload) is not dict")
        owned = assigned(worker, "payload")
        self.shape(owned, '''configuration_capture._ConfigurationCapture(
            ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(owned_payload)''')
        self.assertEqual(len(calls(worker, "configuration_capture._ConfigurationCapture")), 1)
        keys, = [node for node in worker.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Tuple) and [ast.unparse(item) for item in target.elts]
                    == ["planner_key", "verifier_key"] for target in node.targets)]
        self.shape(keys.value, "configuration[2:4]")
        clock = assigned(worker, "now_monotonic_ns")
        self.assertEqual([node.lineno for node in (originals, guard, owned, keys, clock)],
                         sorted(node.lineno for node in (originals, guard, owned, keys, clock)))
        self.assertFalse(any(isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            and node.id in {"configuration", "work"} for node in ast.walk(worker)))
        for forbidden in ("persistence._snapshot_configuration", "configuration_capture._capture_configuration_on_work",
                "configuration_capture._configuration_wire", "commitment.plan._frame", "min"):
            self.assertFalse(calls(worker, forbidden))
        bounds = definition(self.tree, "_validate_originals")
        self.assertEqual([ast.unparse(node) for node in calls(bounds, "commitment._raw")], [
            "commitment._raw(intent_bytes, commitment.MAX_CONTROL_BYTES)",
            "commitment._raw(relay_bytes, commitment.MAX_CONTROL_BYTES)"])
        self.shape(call(bounds, "commitment._body_bounds"),
                   "commitment._body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)")
        _, commitment_tree = source("serverware/authority_revocation_writer_commitment.py", 128 * 1024)
        self.shape(definition(commitment_tree, "_raw").body[0].test,
                   "type(raw) is not bytes or not 2 <= len(raw) <= maximum")
        actual_bounds = definition(commitment_tree, "_body_bounds")
        self.assertEqual([ast.unparse(node) for node in calls(actual_bounds, "_raw")], [
            "_raw(envelope_bytes, plan.contract.MAX_PAYLOAD_BYTES)",
            "_raw(evaluation_context_bytes, retention.MAX_CONTEXT_BYTES)",
            "_raw(historical_expectations_bytes, MAX_HISTORY_BYTES)"])

    def test_guarded_actual_clocks_precede_real_dual_authentication_then_measured_policy_and_same_tuple_atomic_suffix(self):
        worker = self.worker
        callbacks = calls(worker, "commitment.production._callback")
        self.assertEqual([ast.unparse(node) for node in callbacks], [
            "commitment.production._callback(work, time.monotonic_ns)",
            "commitment.production._callback(work, time.time_ns)"])
        self.assertIs(assigned(worker, "now_monotonic_ns"), callbacks[0])
        self.assertIs(assigned(worker, "now_epoch_ns"), callbacks[1])
        receiver = call(worker, "commitment._verify_commitments_on_work")
        self.shape(receiver, '''commitment._verify_commitments_on_work(intent_bytes=intent_bytes,
            relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            planner_public_key=planner_key, verifier_public_key=verifier_key,
            expected_configuration_digest=configuration_digest,
            expected_generation_sequence=generation_sequence,
            expected_generation_digest=generation_digest,
            now_epoch_ns=now_epoch_ns, now_monotonic_ns=now_monotonic_ns,
            maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=authority.VERIFIER_MAX_CLOCK_SKEW_NS,
            work=work)''')
        self.assertIs(assigned(worker, "received"), receiver)
        policy = call(worker, "action._assert_policy_on_work")
        self.shape(policy, "action._assert_policy_on_work(payload, received.expectations, work)")
        atomic = call(worker, "persistence._persist_and_reserve_request_on_configuration")
        self.shape(atomic, '''persistence._persist_and_reserve_request_on_configuration(configuration,
            intent_bytes=intent_bytes, relay_bytes=relay_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            configuration_digest=configuration_digest, generation_sequence=generation_sequence,
            generation_digest=generation_digest,
            **received.arguments, work=work, **received.expectations)''')
        self.assertIs(worker.body[-1].value, atomic)
        ordered = (assigned(worker, "payload"), *callbacks, receiver, policy, atomic)
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        self.assertFalse(any(isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(node.ctx, ast.Store)
            for node in ast.walk(worker)))
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr in {
            "_snapshot_configuration", "metrics", "sign", "commit", "rollback"} for node in ast.walk(worker)))
        _, commitment_tree = source("serverware/authority_revocation_writer_commitment.py", 128 * 1024)
        actual_receiver = definition(commitment_tree, "_verify_commitments_on_work")
        signatures = calls(actual_receiver, "capability._signature")
        self.assertEqual([ast.unparse(node) for node in signatures], [
            "capability._signature(planner_public_key, relay_signature, ENVELOPE_SCHEMA, relay_unsigned, ledger)",
            "capability._signature(verifier_public_key, intent_signature, ENVELOPE_SCHEMA, intent_unsigned, ledger)"])
        self.assertLess(signatures[1].lineno, call(actual_receiver, "_bind_intent").lineno)
        _, policy_tree = source("serverware/authority_revocation_writer_action.py", 64 * 1024)
        actual_policy = definition(policy_tree, "_assert_policy_on_work")
        self.shape(assigned(actual_policy, "assertion_age"), 'payload["webauthn"]["maximumChallengeAgeNs"]')
        self.shape(assigned(actual_policy, "verifier_age"), 'payload["roles"]["verifier"]["maximumInternalAgeNs"]')
        self.shape(assigned(actual_policy, "measured"), '''(assertion_age,
            min(verifier_age, authority.VERIFIER_RESPONSE_MAX_AGE_NS), authority.VERIFIER_MAX_CLOCK_SKEW_NS)''')
        self.shape(call(actual_policy, "retention.plan._same"), '''retention.plan._same(supplied, measured, work,
            "revocation writer action policy differs from its measured configuration")''')

    def test_fixed_atomic_path_keeps_original_input_capture_real_admission_two_replays_and_separate_live_deadline_checks(self):
        fixed = definition(self.persistence, "_persist_and_reserve_request_on_configuration")
        self.shape(call(fixed, "_validate_configuration"), "_validate_configuration(configuration)")
        arguments = call(fixed, "_atomic_arguments_on_work")
        self.shape(arguments, '''_atomic_arguments_on_work(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, planned_at_epoch_ns=planned_at_epoch_ns,
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id,
            work=work, **expectations)''')
        preflight = definition(self.persistence, "_atomic_arguments_on_work")
        joined = call(preflight, "retention.plan._same")
        self.shape(joined, '''retention.plan._same(planner_transaction_id, expected_planner_transaction_id, work,
            "atomic revocation planner transaction differs from its independent expectation")''')
        runner_call = call(fixed, "_run_on_configuration")
        self.shape(runner_call.args[0], "configuration")
        self.shape(runner_call.args[1], "_persist_and_reserve_request_on_connection")
        self.shape(runner_call.args[-2], "expectations")
        self.shape(runner_call.args[-1], "work")
        self.assertLess(arguments.lineno, runner_call.lineno)
        self.assertLess(joined.lineno, preflight.body[-1].lineno)
        runner = definition(self.persistence, "_run_on_configuration")
        inputs = call(runner, "_inputs_from_configuration")
        db_import, = [node for node in runner.body if isinstance(node, ast.ImportFrom)
                      and node.module == "serverware" and [item.name for item in node.names] == ["db"]]
        opened = call(runner, "_connect")
        actual_connection = call(runner, "writer_connection._run_on_connection")
        self.assertEqual([node.lineno for node in (inputs, db_import, opened, actual_connection)],
                         sorted(node.lineno for node in (inputs, db_import, opened, actual_connection)))
        self.shape(call(definition(self.persistence, "_inputs_from_configuration"), "store._owned_expectations"),
                   "store._owned_expectations({**expectations, **pins}, work)")
        operation = definition(self.persistence, "_persist_and_reserve_request_on_connection")
        common, = [node for node in operation.body if isinstance(node, ast.With)]
        self.shape(common.items[0].context_expr, "store._context(store._callback(work, raw.transaction), work)")
        self.shape(call(common, "_retain_and_reserve_in_common"), '''_retain_and_reserve_in_common(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            planned_at_epoch_ns=planned_at_epoch_ns, envelope_id=envelope_id,
            planner_transaction_id=planner_transaction_id, connection=connection, raw=raw,
            work=work, **expectations)''')
        inner = definition(self.persistence, "_retain_and_reserve_in_common")
        retain = call(inner, "store.persist_revocation_planner_record")
        reserve = call(inner, "revocation_execution.reserve_revocation_execution_envelope")
        self.assertLess(retain.lineno, reserve.lineno)
        self.shape(operation.body[-1].value, "(retained_receipt, execution_reservation)")
        _, store = source("serverware/authority_store/revocation_retention.py", 64 * 1024)
        stored_replay = definition(store, "_read_revocation_record_on_work")
        self.shape(call(definition(store, "persist_revocation_planner_record"), "retention._verify_record_on_work"),
            '''retention._verify_record_on_work(envelope_bytes=envelope_bytes,
                evaluation_context_bytes=evaluation_context_bytes, work=work, **expectations)''')
        self.shape(call(stored_replay, "retention._verify_record_on_work"),
            '''retention._verify_record_on_work(envelope_bytes=envelope,
                evaluation_context_bytes=context, work=work, **expectations)''')
        _, execution = source("serverware/authority_store/revocation_execution.py", 64 * 1024)
        actual_reserve = definition(execution, "reserve_revocation_execution_envelope")
        self.shape(call(actual_reserve, "store._read_revocation_record_on_work"),
            '''store._read_revocation_record_on_work(planner_transaction_id=planner_transaction_id,
                connection=connection, work=work, _expected_raw=raw, expectations=owned)''')
        # Envelope clocks are sampled before authentication, not at commit.
        # Existing custody deadline checks independently resample actual clocks;
        # neither those samples nor historical replay prove current root authority.
        fresh = [node for node in calls(actual_reserve, "store._callback")
                 if len(node.args) > 1 and ast.unparse(node.args[1]) == "store._fresh"]
        self.assertEqual([ast.unparse(node) for node in fresh],
                         ["store._callback(work, store._fresh, parent)"] * 2)
        inserted, = [node for node in calls(actual_reserve, "store._callback")
                     if len(node.args) > 2 and ast.unparse(node.args[2]) == "_INSERT"]
        self.assertLess(fresh[0].lineno, inserted.lineno)
        self.assertLess(call(actual_reserve, "store._match").lineno, fresh[1].lineno)
        self.shape(call(definition(store, "_fresh"), "_require_fresh_deadline"),
            '''_require_fresh_deadline(deadline_monotonic_ns=reservation["deadline_monotonic_ns"],
                deadline_epoch_ns=reservation["deadline_epoch_ns"], reserved_at_epoch_ns=reservation["reserved_at_epoch_ns"])''')
        _, connection = source("serverware/authority_store/planner_connection.py", 64 * 1024)
        deadline = definition(connection, "_require_fresh_deadline")
        self.shape(assigned(deadline, "now_monotonic_ns"), "time.monotonic_ns()")
        self.shape(assigned(deadline, "now_epoch_ns"), "time.time_ns()")

    def test_actual_loader_and_writer_only_credentials_remain_required_without_public_routes_or_durable_ack(self):
        main = definition(self.service, "main")
        loaded = call(main, "MeasuredConfiguration.load")
        constructed = call(main, "AuthorityProcess")
        self.shape(loaded, "MeasuredConfiguration.load(role=args.role)")
        self.shape(constructed, "AuthorityProcess(role=args.role, configuration=configuration)")
        self.assertLess(loaded.lineno, constructed.lineno)
        measured = definition(self.service, "MeasuredConfiguration")
        loader = definition(measured, "load")
        self.shape(call(loader, "root_key.verify"),
            '''root_key.verify(_b64url_decode(envelope["signature"], size=64),
                _domain_digest(SIGNED_CONFIG_SCHEMA, payload_bytes).encode("ascii"))''')
        _, launcher = source("serverware/authority_launcher.py", 256 * 1024)
        inventory = assigned(launcher, "ROLE_CREDENTIAL_DESCRIPTOR_NAMES")
        writer_descriptors, = [value for key, value in zip(inventory.keys, inventory.values)
                               if key.value == "planner-writer"]
        self.shape(writer_descriptors, '''frozenset({
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_LAUNCH_MANIFEST_FD",
            "SERVERWARE_POLICY_AUTHORITY_ROOT_PUBLIC_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD",
            "SERVERWARE_POLICY_AUTHORITY_ATTESTATION_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD",
            "SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_POSTGRES_DSN_FD"})''')
        handle = definition(self.process, "handle")
        served = definition(definition(self.service, "AuthorityServer"), "_serve_connection")
        writer, = [node for node in ast.walk(handle) if isinstance(node, ast.If)
                   and ast.unparse(node.test) == "self.role_name == 'planner-writer'"]
        self.shape(keywords(call(writer, "self._verify_internal_envelope"))["allowed_purposes"],
                   "{'persist-measured-plan', 'read-persisted-plan', 'reserve-execution-envelope'}")
        for dispatcher in (handle, served):
            for forbidden in ("_persist_and_reserve_revocation_commitments", "_persist_commitments_on_configuration",
                    "authority_revocation_writer_composition", "authorize-revocation-writer-custody",
                    "relay-revocation-writer-custody"):
                self.assertNotIn(forbidden, ast.unparse(dispatcher))
        self.assertFalse(calls(self.service, "self._persist_and_reserve_revocation_commitments"))
        self.assertFalse(calls(self.service, "self._persist_and_reserve_revocation_plan"))
        self.assertFalse(calls(self.service, "self._revocation_planner_persistence"))
        peer, = [node for node in ast.walk(served) if isinstance(node, ast.If)
                 and ast.unparse(node.test) == "uid != self.peer_uid or gid != self.peer_gid"]
        self.assertLess(peer.lineno, call(served, "self.process.handle").lineno)
        topology = ast.unparse(definition(measured, "_verify_role_topology"))
        self.assertIn("(int(planner_writer.get('peerUid', -1)), int(planner_writer.get('peerGid', -1))) != "
                      "(int(planner['serviceUid']), int(planner['serviceGid']))", topology)
        _, registry = source("serverware/authority_transition_registry.py")
        self.shape(assigned(registry, "_CLOSURE_ERRORS"), "_registry_closure_errors()")
        closed, = [node for node in registry.body if isinstance(node, ast.If)]
        self.shape(closed.test, "_CLOSURE_ERRORS")
        self.assertIsInstance(closed.body[0], ast.Raise)
        for function in (self.worker, self.adapter):
            for forbidden in ("_socket_request", "_socket_request_bytes", "_socket_request_revocation_bytes",
                    "_recv_message", "_recv_revocation_invocation_bytes", "sign", "execute"):
                self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr == forbidden
                    for node in ast.walk(function)))


if __name__ == "__main__":
    unittest.main()
