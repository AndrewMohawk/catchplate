#!/usr/bin/env python3
"""Nonimporting linkage for exact-original writer request custody.

Bounded source inspection does not authenticate inputs, execute extracted
functions, import the active database/service/registry, or prove PostgreSQL,
transaction, migration or signature admission. The request row is immutable
custody, not an ACK, proof token or execution result. The actual owning path
must authenticate all originals, compare measured policy and run both genuine
retained replays before its common and outer transaction scopes can complete.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, keywords, source


REQUEST_FIELDS = (
    "intent_envelope_id", "relay_envelope_id", "execution_envelope_id",
    "planner_transaction_id", "plan_protocol", "retained_record_digest",
    "configuration_digest", "generation_sequence", "generation_digest",
    "exact_intent_base64url", "exact_intent_bytes_digest", "exact_intent_byte_count",
    "exact_relay_base64url", "exact_relay_bytes_digest", "exact_relay_byte_count",
    "historical_expectations_base64url", "historical_expectations_bytes_digest",
    "historical_expectations_byte_count", "planner_key_digest", "verifier_key_digest",
    "planned_at_epoch_ns", "source_revision",
)


class RevocationWriterRequestSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.store = source("catchplate/authority_store/revocation_writer_request.py", 64 * 1024)
        _, cls.persistence = source("catchplate/authority_revocation_persistence.py", 64 * 1024)
        _, cls.composition = source("catchplate/authority_revocation_writer_composition.py", 64 * 1024)
        _, cls.contract = source("catchplate/authority_contract.py", 512 * 1024)

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_literal_request_inventory_preserves_all_original_controls_without_plan_context_or_ack_duplication(self):
        self.assertEqual(len(REQUEST_FIELDS), 22)
        self.shape(assigned(self.contract, "REVOCATION_WRITER_REQUEST_TABLE"),
                   '"policy_authority_revocation_writer_requests"')
        fields = assigned(self.contract, "REVOCATION_WRITER_REQUEST_COLUMNS")
        self.assertIsInstance(fields, ast.Tuple)
        self.assertEqual(tuple(item.value for item in fields.elts), REQUEST_FIELDS)
        self.assertFalse(set(REQUEST_FIELDS) & {
            "exact_envelope_base64url", "evaluation_context_base64url", "exact_response_base64url",
            "terminal_receipt_json", "failure_code", "terminal_at_epoch_ns"})
        descriptor = assigned(self.contract, "REVOCATION_WRITER_REQUEST_CUSTODY_CONTRACT")
        values = {key.value: value for key, value in zip(descriptor.args[0].keys, descriptor.args[0].values)}
        self.shape(values["requestColumns"], "REVOCATION_WRITER_REQUEST_COLUMNS")
        self.shape(values["primaryKey"], '("intent_envelope_id",)')
        self.shape(values["uniqueKeys"], '''(("relay_envelope_id",), ("execution_envelope_id",),
            ("intent_envelope_id", "configuration_digest", "generation_sequence", "generation_digest", "source_revision"))''')
        self.shape(values["identityScope"], '"global-across-configuration-generation-and-key-rotations"')
        self.shape(values["plannedAtBinding"], '"exact-original-stored-plan-time"')
        self.shape(values["plannerPrivileges"], '("SELECT", "INSERT")')
        self.shape(values["planAndContextStorage"], '"existing-retained-plan-sidecar"')

    def test_prefix_uses_actual_stable_ids_and_three_original_byte_hashes_and_codecs_on_existing_work(self):
        prefix = definition(self.store, "_prefix_on_work")
        self.assertEqual(prefix.args.args, [])
        self.assertEqual([item.arg for item in prefix.args.kwonlyargs], [
            "intent_bytes", "relay_bytes", "historical_expectations_bytes", "configuration_digest",
            "generation_sequence", "generation_digest", "planned_at_epoch_ns", "envelope_id",
            "planner_transaction_id", "work"])
        self.assertIsNone(prefix.args.kwarg)
        self.assertIsNone(prefix.args.vararg)
        self.assertTrue(all(value is None for value in prefix.args.kw_defaults))
        self.shape(prefix.body[1].value, "commitment.capture._SharedLedger(work)")
        self.assertEqual([ast.unparse(node) for node in calls(prefix, "commitment._raw")], [
            "commitment._raw(intent_bytes, commitment.MAX_CONTROL_BYTES)",
            "commitment._raw(relay_bytes, commitment.MAX_CONTROL_BYTES)",
            "commitment._raw(historical_expectations_bytes, commitment.MAX_HISTORY_BYTES)"])
        intent = assigned(prefix, "intent_id")
        relay = assigned(prefix, "relay_id")
        self.shape(intent, "commitment._intent_id(envelope_id, planner_transaction_id, work)")
        self.shape(relay, "commitment._relay_id(intent_id, work)")
        fields = assigned(prefix, "prefix")
        self.shape(fields, '''{"intent_envelope_id": intent_id, "relay_envelope_id": relay_id,
            "execution_envelope_id": envelope_id, "planner_transaction_id": planner_transaction_id,
            "plan_protocol": store.retention.PLAN_PROTOCOL,
            "configuration_digest": configuration_digest, "generation_sequence": generation_sequence,
            "generation_digest": generation_digest, "planned_at_epoch_ns": planned_at_epoch_ns,
            "source_revision": authority.SOURCE_REVISION}''')
        loop, = [node for node in prefix.body if isinstance(node, ast.For)]
        self.shape(loop.iter, '''(("exact_intent", intent_bytes), ("exact_relay", relay_bytes),
            ("historical_expectations", historical_expectations_bytes))''')
        self.assertEqual([ast.unparse(node.targets[0]) for node in loop.body], [
            "prefix[name + '_base64url']", "prefix[name + '_bytes_digest']", "prefix[name + '_byte_count']"])
        self.shape(loop.body[0].value, "store._encode(raw, work)")
        self.shape(loop.body[1].value, "store.retention._bytes_digest(raw, work)")
        self.shape(loop.body[2].value, "len(raw)")
        self.assertEqual(len(fields.keys) + 3 * len(loop.iter.elts), 19)
        self.shape(prefix.body[-1].value, "prefix")
        self.assertEqual([node.lineno for node in (intent, relay, fields, loop)],
                         sorted(node.lineno for node in (intent, relay, fields, loop)))
        _, commitment = source("catchplate/authority_revocation_writer_commitment.py", 128 * 1024)
        self.shape(call(definition(commitment, "_intent_id"), "plan._frame"),
            '''plan._frame(INTENT_ID_DOMAIN,
                (plan._ascii(execution_id, work), plan._ascii(planner_id, work)), work)''')
        self.shape(call(definition(commitment, "_relay_id"), "plan._frame"),
                   "plan._frame(RELAY_ID_DOMAIN, (plan._ascii(intent_id, work),), work)")
        _, retention = source("catchplate/authority_revocation_retention.py", 64 * 1024)
        digest = definition(retention, "_bytes_digest")
        self.shape(digest.body[0].value, "work.charge(hashes=1, input_bytes=len(raw))")
        self.shape(digest.body[1].value, '"sha256:" + hashlib.sha256(raw).hexdigest()')
        # These are custody hashes, not a duplicate signature/proof verifier.
        for forbidden in ("commitment._verify_commitments_on_work", "commitment.wire._decode_object",
                "store.retention._verify_record_on_work", "_ValidationWork", "QueryReadValidationLimits"):
            self.assertFalse(calls(self.store, forbidden))

    def test_lookup_uses_fixed_ordinary_select_and_rejects_unbounded_driver_rows_before_real_copy_and_comparison(self):
        self.shape(assigned(self.store, "_TABLE"), '"catchplate_metadata." + authority.REVOCATION_WRITER_REQUEST_TABLE')
        self.shape(assigned(self.store, "_FIELDS"), "authority.REVOCATION_WRITER_REQUEST_COLUMNS")
        self.shape(assigned(self.store, "_DERIVED"),
                   'frozenset({"retained_record_digest", "planner_key_digest", "verifier_key_digest"})')
        self.shape(assigned(self.store, "_SELECT"),
            '"SELECT " + ", ".join(_FIELDS) + " FROM " + _TABLE + " WHERE intent_envelope_id = %s"')
        self.shape(assigned(self.store, "_INSERT"), '''"INSERT INTO " + _TABLE + " (" + ", ".join(_FIELDS)
            + ") VALUES (" + ", ".join(("%s",) * len(_FIELDS))
            + ") ON CONFLICT (intent_envelope_id) DO NOTHING"''')
        for name in ("_SELECT", "_INSERT"):
            literal_text = "".join(node.value for node in ast.walk(assigned(self.store, name))
                                   if isinstance(node, ast.Constant) and type(node.value) is str)
            for forbidden in ("FOR UPDATE", "FOR SHARE", "DO UPDATE", "DELETE", "TRUNCATE"):
                self.assertNotIn(forbidden, literal_text)
        owned = definition(self.store, "_owned_request")
        self.shape(owned.body[1].test, '''type(row) is not dict or len(row) != len(_FIELDS)
            or any(type(name) is not str for name in row) or set(row) != set(_FIELDS)''')
        loop = owned.body[2]
        self.shape(loop.iter, "row.items()")
        branch = loop.body[0]
        self.shape(branch.test, "name in _DERIVED")
        self.shape(branch.body[0].value, "commitment.plan.contract._digest(value)")
        self.shape(branch.orelse[0].value, "prefix[name]")
        self.shape(branch.orelse[1].test, '''type(value) is not type(expected)
            or type(value) is str and len(value) > len(expected)
            or type(value) is int and not 1 <= value <= 2**63 - 1''')
        self.shape(owned.body[3].value, "work.prepare_copy(row)")
        self.shape(owned.body[4].value, "row.copy()")
        lookup = definition(self.store, "_lookup")
        self.shape(assigned(lookup, "row"), 'store._read(cursor, _SELECT, (prefix["intent_envelope_id"],), work)')
        self.shape(lookup.body[1].test, "row is None")
        self.shape(lookup.body[1].body[0].value, "None")
        self.shape(assigned(lookup, "owned"), "_owned_request(row, prefix, work)")
        self.shape(call(lookup, "store._match"), "store._match(owned, prefix, work)")
        self.assertLess(call(lookup, "_owned_request").lineno, call(lookup, "store._match").lineno)
        self.shape(lookup.body[-1].value, "owned")

    def test_completion_joins_actual_replay_outputs_and_original_time_then_all_paths_recheck_complete_custody(self):
        complete = definition(self.store, "_complete_on_work")
        matches = calls(complete, "store._match")
        self.assertEqual(len(matches), 2)
        self.shape(matches[0], '''store._match(receipt, {"plannerTransactionId": prefix["planner_transaction_id"],
            "planProtocol": prefix["plan_protocol"], "plannedAtEpochNs": prefix["planned_at_epoch_ns"]}, work)''')
        self.shape(matches[1], '''store._match(reservation, {"envelope_id": prefix["execution_envelope_id"],
            "planner_transaction_id": prefix["planner_transaction_id"], "status": "reserved",
            "source_revision": prefix["source_revision"]}, work)''')
        derived = assigned(complete, "derived")
        self.shape(derived, '''{"retained_record_digest": receipt["retainedRecordDigest"],
            "planner_key_digest": receipt["plannerKeyDigest"], "verifier_key_digest": receipt["verifierKeyDigest"]}''')
        loop, = [node for node in complete.body if isinstance(node, ast.For)]
        self.shape(loop.iter, "derived.values()")
        self.shape(loop.body[0].value, "commitment.plan.contract._digest(value)")
        self.shape(complete.body[-1].value, "{**prefix, **derived}")
        self.assertLess(matches[1].lineno, derived.lineno)
        persist = definition(self.store, "_persist")
        self.assertEqual([item.arg for item in persist.args.kwonlyargs], ["insert"])
        self.shape(persist.body[0].test, "type(insert) is not bool")
        self.shape(assigned(persist, "expected"), "_complete_on_work(prefix, receipt, reservation, work)")
        insert = persist.body[2]
        self.shape(insert.test, "insert")
        self.shape(insert.body[0].value, "store._parameters(expected, _FIELDS, work)")
        self.shape(insert.body[1].value, "store._callback(work, cursor.execute, _INSERT, parameters)")
        reread = call(persist, "store._read")
        self.shape(reread, 'store._read(cursor, _SELECT, (prefix["intent_envelope_id"],), work)')
        self.assertLess(insert.end_lineno, reread.lineno)
        self.shape(assigned(persist, "row"), '''_owned_request(store._read(cursor, _SELECT,
            (prefix["intent_envelope_id"],), work), prefix, work)''')
        self.shape(call(persist, "store._match"), "store._match(row, expected, work)")
        self.shape(persist.body[-1].value, "row")
        self.assertFalse(any(isinstance(node, ast.With) for node in ast.walk(self.store)))
        self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr in {
            "transaction", "commit", "rollback", "sign", "verify", "time_ns", "monotonic_ns"}
            for node in ast.walk(self.store)))

    def test_fixed_original_byte_suffix_follows_real_authentication_and_same_payload_policy_without_a_dto_input(self):
        worker = definition(self.composition, "_persist_commitments_on_configuration")
        authenticated = call(worker, "commitment._verify_commitments_on_work")
        policy = call(worker, "action._assert_policy_on_work")
        suffix = call(worker, "persistence._persist_and_reserve_request_on_configuration")
        self.shape(policy, "action._assert_policy_on_work(payload, received.expectations, work)")
        self.assertIs(assigned(worker, "received"), authenticated)
        self.shape(suffix, '''persistence._persist_and_reserve_request_on_configuration(configuration,
            intent_bytes=intent_bytes, relay_bytes=relay_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            configuration_digest=configuration_digest, generation_sequence=generation_sequence,
            generation_digest=generation_digest,
            writer_private_key=writer_private_key, writer_public_key=writer_public_key,
            writer_response_spki_digest=writer_response_spki_digest,
            **received.arguments, work=work, **received.expectations)''')
        self.assertEqual([node.lineno for node in (authenticated, policy, suffix)],
                         sorted(node.lineno for node in (authenticated, policy, suffix)))
        self.assertIs(worker.body[-1].value, suffix)
        fixed = definition(self.persistence, "_persist_and_reserve_request_on_configuration")
        self.assertEqual([item.arg for item in fixed.args.args], ["configuration"])
        self.assertEqual([item.arg for item in fixed.args.kwonlyargs], [
            "intent_bytes", "relay_bytes", "historical_expectations_bytes", "configuration_digest",
            "generation_sequence", "generation_digest", "envelope_bytes", "evaluation_context_bytes",
            "planned_at_epoch_ns", "envelope_id", "planner_transaction_id", "writer_private_key",
            "writer_public_key", "writer_response_spki_digest", "work"])
        self.assertTrue(all(value is None for value in fixed.args.kw_defaults))
        self.assertEqual(fixed.args.kwarg.arg, "expectations")
        self.assertIsNone(fixed.args.vararg)
        validated = call(fixed, "_validate_configuration")
        arguments = call(fixed, "_atomic_arguments_on_work")
        self.shape(validated, "_validate_configuration(configuration)")
        self.shape(arguments, '''_atomic_arguments_on_work(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, planned_at_epoch_ns=planned_at_epoch_ns,
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id, work=work, **expectations)''')
        raw_checks = calls(fixed, "commitment._raw")
        self.assertEqual([ast.unparse(node) for node in raw_checks], [
            "commitment._raw(intent_bytes, commitment.MAX_CONTROL_BYTES)",
            "commitment._raw(relay_bytes, commitment.MAX_CONTROL_BYTES)",
            "commitment._raw(historical_expectations_bytes, commitment.MAX_HISTORY_BYTES)"])
        pins = call(fixed, "commitment._pins")
        self.shape(pins, "commitment._pins(configuration_digest, generation_sequence, generation_digest)")
        update = call(fixed, "arguments.update")
        self.shape(update, '''arguments.update(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            configuration_digest=configuration_digest, generation_sequence=generation_sequence,
            generation_digest=generation_digest, writer_private_key=writer_private_key,
            writer_public_key=writer_public_key, writer_response_spki_digest=writer_response_spki_digest)''')
        key_guard, = [node for node in fixed.body if isinstance(node, ast.If)
                      and "Ed25519PrivateKey" in ast.unparse(node.test)]
        self.shape(key_guard.test, '''not isinstance(writer_private_key, Ed25519PrivateKey)
            or not isinstance(writer_public_key, Ed25519PublicKey)''')
        self.assertLess(key_guard.lineno, update.lineno)
        self.shape(call(fixed, "commitment.plan.contract._digest"),
                   "commitment.plan.contract._digest(writer_response_spki_digest)")
        runner = call(fixed, "_run_on_configuration")
        self.shape(runner, '''_run_on_configuration(configuration, _persist_and_reserve_request_on_connection,
            arguments, expectations, work)''')
        ordered = (validated, arguments, *raw_checks, pins, update, runner)
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        self.assertIs(fixed.body[-1].value, runner)
        preflight = definition(self.persistence, "_atomic_arguments_on_work")
        self.shape(call(preflight, "retention.plan._same"), '''retention.plan._same(
            planner_transaction_id, expected_planner_transaction_id, work,
            "atomic revocation planner transaction differs from its independent expectation")''')
        for function in (fixed, preflight):
            self.assertFalse(any(isinstance(node, ast.Name) and node.id in {
                "received", "receipt", "reservation", "operation", "opener", "self"}
                for node in ast.walk(function)))
            self.assertFalse(calls(function, "commitment._verify_commitments_on_work"))
            self.assertFalse(calls(function, "_ValidationWork"))

    def test_one_common_scope_checks_existing_custody_then_runs_both_real_replays_before_mandatory_journal_readback(self):
        operation = definition(self.persistence, "_persist_and_reserve_request_on_connection")
        self.assertEqual(operation.args.args, [])
        self.assertEqual([item.arg for item in operation.args.kwonlyargs], [
            "intent_bytes", "relay_bytes", "historical_expectations_bytes", "configuration_digest",
            "generation_sequence", "generation_digest", "envelope_bytes", "evaluation_context_bytes",
            "planned_at_epoch_ns", "envelope_id", "planner_transaction_id", "writer_private_key",
            "writer_public_key", "writer_response_spki_digest", "connection", "work"])
        self.assertEqual(operation.args.kwarg.arg, "expectations")
        self.assertIsNone(operation.args.vararg)
        facade, = [node for node in calls(operation, "store._callback")
                   if len(node.args) > 1 and ast.unparse(node.args[1]) == "store._transaction_connection"]
        self.shape(facade, "store._callback(work, store._transaction_connection, connection)")
        raw = assigned(operation, "raw")
        self.shape(raw, "store._callback(work, store._require_planner_writer, connection)")
        prefix = call(operation, "request_store._prefix_on_work")
        self.shape(prefix, '''request_store._prefix_on_work(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            configuration_digest=configuration_digest, generation_sequence=generation_sequence,
            generation_digest=generation_digest, planned_at_epoch_ns=planned_at_epoch_ns,
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id, work=work)''')
        common, = [node for node in operation.body if isinstance(node, ast.With)]
        self.shape(common.items[0].context_expr, "store._context(store._callback(work, raw.transaction), work)")
        self.assertEqual([node.lineno for node in (facade, raw, prefix, common)],
                         sorted(node.lineno for node in (facade, raw, prefix, common)))
        cursors = [node for node in common.body if isinstance(node, ast.With)]
        self.assertEqual(len(cursors), 2)
        for cursor in cursors:
            self.shape(cursor.items[0].context_expr, "store._context(store._callback(work, raw.cursor), work)")
            self.assertEqual(ast.unparse(cursor.items[0].optional_vars), "cursor")
        lookup = call(cursors[0], "request_store._lookup")
        self.shape(lookup, "request_store._lookup(cursor, prefix, work)")
        self.assertIs(assigned(operation, "existing"), lookup)
        replay = call(common, "_retain_and_reserve_in_common")
        self.shape(replay, '''_retain_and_reserve_in_common(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, planned_at_epoch_ns=planned_at_epoch_ns,
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id,
            connection=connection, raw=raw, work=work, **expectations)''')
        replay_assignment, = [node for node in common.body if isinstance(node, ast.Assign)]
        self.assertEqual(ast.unparse(replay_assignment.targets[0]), "(retained_receipt, execution_reservation)")
        self.assertIs(replay_assignment.value, replay)
        journal = call(cursors[1], "request_store._persist")
        self.shape(journal, '''request_store._persist(cursor, prefix, retained_receipt,
            execution_reservation, work, insert=existing is None)''')
        self.assertIs(assigned(operation, "request_row"), journal)
        ack = call(cursors[1], "ack_store._persist")
        self.shape(ack, '''ack_store._persist(cursor, request_row,
            writer_private_key=writer_private_key, writer_public_key=writer_public_key,
            writer_response_spki_digest=writer_response_spki_digest, work=work)''')
        self.assertIs(assigned(operation, "acknowledgment_bytes"), ack)
        self.assertEqual(len(cursors[1].body), 5)
        self.assertLess(journal.lineno, ack.lineno)
        self.assertLess(cursors[0].end_lineno, replay.lineno)
        self.assertLess(replay.lineno, cursors[1].lineno)
        continuity = "store._callback(work, revocation_execution._same_connection, connection, raw)"
        for node in (common.body[0], common.body[2], common.body[-1], operation.body[-2],
                     cursors[0].body[0], cursors[0].body[-1], cursors[1].body[0], cursors[1].body[-1]):
            self.shape(node.value, continuity)
        self.shape(cursors[1].body[2].value, continuity)
        self.shape(operation.body[-1].value, "(retained_receipt, execution_reservation, acknowledgment_bytes)")
        self.assertLess(common.end_lineno, operation.body[-2].lineno)
        self.assertFalse(any(isinstance(node, (ast.If, ast.Try, ast.ExceptHandler)) for node in ast.walk(operation)))
        inner = definition(self.persistence, "_retain_and_reserve_in_common")
        self.assertFalse(any(isinstance(node, ast.With) for node in ast.walk(inner)))
        retained = call(inner, "store.persist_revocation_planner_record")
        reserved = call(inner, "revocation_execution.reserve_revocation_execution_envelope")
        self.shape(retained, '''store.persist_revocation_planner_record(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, planned_at_epoch_ns=planned_at_epoch_ns,
            connection=connection, work=work, **expectations)''')
        self.shape(reserved, '''revocation_execution.reserve_revocation_execution_envelope(
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id,
            connection=connection, work=work, **expectations)''')
        for index in (2, 4, 6):
            self.shape(inner.body[index].value, continuity)
        self.assertLess(retained.lineno, reserved.lineno)
        self.shape(inner.body[-1].value, "(retained_receipt, execution_reservation)")

    def test_custody_preserves_real_runner_admission_original_replay_and_closed_public_boundaries(self):
        runner = definition(self.persistence, "_run_on_configuration")
        captured = call(runner, "_inputs_from_configuration")
        self.shape(captured, "_inputs_from_configuration(configuration, expectations, work)")
        db_import, = [node for node in runner.body if isinstance(node, ast.ImportFrom)
                      and node.module == "catchplate" and [item.name for item in node.names] == ["db"]]
        opened = call(runner, "_connect")
        delegated = call(runner, "writer_connection._run_on_connection")
        ordered = (captured, db_import, opened, delegated)
        self.assertEqual([node.lineno for node in ordered], sorted(node.lineno for node in ordered))
        self.shape(delegated, '''writer_connection._run_on_connection(connection,
            database_identity=configuration[6], work=work, operation=operation,
            arguments=arguments, expectations=owned)''')
        _, store = source("catchplate/authority_store/revocation_retention.py", 64 * 1024)
        _, execution = source("catchplate/authority_store/revocation_execution.py", 64 * 1024)
        self.shape(call(definition(store, "persist_revocation_planner_record"), "retention._verify_record_on_work"),
            '''retention._verify_record_on_work(envelope_bytes=envelope_bytes,
                evaluation_context_bytes=evaluation_context_bytes, work=work, **expectations)''')
        self.shape(call(definition(store, "_read_revocation_record_on_work"), "retention._verify_record_on_work"),
            '''retention._verify_record_on_work(envelope_bytes=envelope,
                evaluation_context_bytes=context, work=work, **expectations)''')
        self.shape(call(definition(execution, "reserve_revocation_execution_envelope"), "store._read_revocation_record_on_work"),
            '''store._read_revocation_record_on_work(planner_transaction_id=planner_transaction_id,
                connection=connection, work=work, _expected_raw=raw, expectations=owned)''')
        # Four transaction managers remain: admitted writer outer, common,
        # actual retained persist, actual execution reserve. Cursor scopes do
        # not add transactions, and the inner replay helper owns no manager.
        for function, prefix in ((definition(self.persistence, "_persist_and_reserve_request_on_connection"), "store."),
                (definition(store, "persist_revocation_planner_record"), ""),
                (definition(execution, "reserve_revocation_execution_envelope"), "store.")):
            transactions = [node for node in ast.walk(function) if isinstance(node, ast.With)
                and ast.unparse(node.items[0].context_expr)
                    == prefix + "_context(" + prefix + "_callback(work, raw.transaction), work)"]
            self.assertEqual(len(transactions), 1)
        _, writer = source("catchplate/authority_revocation_writer_connection.py", 64 * 1024)
        owner = definition(writer, "_run_on_connection")
        self.assertEqual(len(calls(owner, "connection.transaction")), 1)
        actual = call(owner, "operation")
        self.assertLess(call(owner, "_admit_identity").lineno, actual.lineno)
        self.assertLess(call(owner, "planner_writer_privilege_check").lineno, actual.lineno)
        _, service = source("catchplate/authority_service.py", 2 * 1024 * 1024)
        process = definition(service, "AuthorityProcess")
        adapter = definition(process, "_persist_and_reserve_revocation_commitments")
        self.assertEqual([item.arg for item in adapter.args.kwonlyargs], [
            "intent_bytes", "relay_bytes", "envelope_bytes", "evaluation_context_bytes",
            "historical_expectations_bytes", "work"])
        self.assertIsNone(adapter.args.kwarg)
        self.assertFalse(calls(service, "self._persist_and_reserve_revocation_commitments"))
        for dispatcher in (definition(process, "handle"),
                definition(definition(service, "AuthorityServer"), "_serve_connection")):
            for spelling in ("_persist_and_reserve_revocation_commitments", "revocation_writer_request",
                    "_persist_and_reserve_request_on_configuration", "authorize-revocation-writer-custody",
                    "relay-revocation-writer-custody"):
                self.assertNotIn(spelling, ast.unparse(dispatcher))
        _, registry = source("catchplate/authority_transition_registry.py")
        self.shape(assigned(registry, "_CLOSURE_ERRORS"), "_registry_closure_errors()")
        closed, = [node for node in registry.body if isinstance(node, ast.If)]
        self.shape(closed.test, "_CLOSURE_ERRORS")
        self.assertIsInstance(closed.body[0], ast.Raise)
        for name in ("_persist_and_reserve_request_on_configuration", "_persist_and_reserve_request_on_connection",
                     "_retain_and_reserve_in_common"):
            function = definition(self.persistence, name)
            for spelling in ("commitment._verify_commitments_on_work", "_ValidationWork", "QueryReadValidationLimits"):
                self.assertFalse(calls(function, spelling))
            self.assertFalse(any(isinstance(node, ast.Attribute) and node.attr in {
                "commit", "rollback", "sign", "verify", "time_ns", "monotonic_ns"}
                for node in ast.walk(function)))


if __name__ == "__main__":
    unittest.main()
