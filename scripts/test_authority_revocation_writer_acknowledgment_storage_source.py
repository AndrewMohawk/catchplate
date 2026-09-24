#!/usr/bin/env python3
"""Bounded nonimporting linkage for immutable original ACK storage.

These checks inspect actual source, never execute extracted functions or import
the active facade/registry. They do not establish signature admission, database
durability, committed custody, globally once-only signing or public transport.
"""
from __future__ import annotations

import ast
import unittest

from test_authority_revocation_planning_source import assigned, call, calls, definition, source


ACK_FIELDS = ("ack_envelope_id", "intent_envelope_id", "configuration_digest",
    "generation_sequence", "generation_digest", "writer_response_spki_digest",
    "exact_ack_base64url", "exact_ack_bytes_digest", "exact_ack_byte_count", "source_revision")
REQUEST_SCALARS = ("intent_envelope_id", "relay_envelope_id", "execution_envelope_id",
    "planner_transaction_id", "plan_protocol", "retained_record_digest",
    "configuration_digest", "generation_sequence", "generation_digest",
    "exact_intent_bytes_digest", "exact_intent_byte_count", "exact_relay_bytes_digest",
    "exact_relay_byte_count", "historical_expectations_bytes_digest", "historical_expectations_byte_count",
    "planner_key_digest", "verifier_key_digest", "planned_at_epoch_ns", "source_revision")


class RevocationWriterAcknowledgmentStorageSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.tree = source("serverware/authority_store/revocation_writer_acknowledgment.py", 64 * 1024)
        _, cls.persistence = source("serverware/authority_revocation_persistence.py", 64 * 1024)
        _, cls.request = source("serverware/authority_store/revocation_writer_request.py", 64 * 1024)
        _, cls.retention = source("serverware/authority_store/revocation_retention.py", 64 * 1024)
        _, cls.writer = source("serverware/authority_revocation_writer_connection.py", 64 * 1024)
        _, cls.contract = source("serverware/authority_contract.py", 512 * 1024)

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_exact_ten_field_sql_and_nineteen_scalar_request_projection_are_source_owned(self):
        self.shape(assigned(self.tree, "_TABLE"), '"serverware_metadata." + authority.REVOCATION_WRITER_ACK_TABLE')
        self.shape(assigned(self.tree, "_FIELDS"), "authority.REVOCATION_WRITER_ACK_COLUMNS")
        self.assertEqual(tuple(item.value for item in assigned(self.contract, "REVOCATION_WRITER_ACK_COLUMNS").elts), ACK_FIELDS)
        self.shape(assigned(self.contract, "REVOCATION_WRITER_ACK_TABLE"),
                   '"policy_authority_revocation_writer_acknowledgments"')
        self.shape(assigned(self.tree, "_SELECT"),
            '"SELECT " + ", ".join(_FIELDS) + " FROM " + _TABLE + " WHERE intent_envelope_id = %s"')
        self.shape(assigned(self.tree, "_INSERT"), '''"INSERT INTO " + _TABLE + " (" + ", ".join(_FIELDS)
            + ") VALUES (" + ", ".join(("%s",) * len(_FIELDS))
            + ") ON CONFLICT (intent_envelope_id) DO NOTHING"''')
        self.shape(assigned(self.tree, "_BODY_FIELDS"), '''frozenset({"exact_intent_base64url",
            "exact_relay_base64url", "historical_expectations_base64url"})''')
        omitted = {item.value for item in assigned(self.tree, "_BODY_FIELDS").args[0].elts}
        columns = assigned(self.contract, "REVOCATION_WRITER_REQUEST_COLUMNS")
        self.assertEqual(tuple(item.value for item in columns.elts if item.value not in omitted), REQUEST_SCALARS)
        self.assertEqual(len(REQUEST_SCALARS), 19)
        projected = definition(self.tree, "_request_fields")
        self.shape(assigned(projected, "columns"), "authority.REVOCATION_WRITER_REQUEST_COLUMNS")
        self.shape(projected.body[1].test, '''type(request_row) is not dict or len(request_row) != len(columns)
            or any(type(name) is not str for name in request_row) or set(request_row) != set(columns)''')
        self.shape(assigned(projected, "result"),
            "{name: request_row[name] for name in columns if name not in _BODY_FIELDS}")
        loop, = [node for node in projected.body if isinstance(node, ast.For)]
        self.shape(loop.iter, "result.items()")
        bounded = loop.body[0]
        self.shape(bounded.test, 'name in {"generation_sequence", "planned_at_epoch_ns"} or name.endswith("_byte_count")')
        self.shape(bounded.body[0].test, "type(value) is not int or not 1 <= value <= 2**63 - 1")
        self.shape(bounded.orelse[0].test, "type(value) is not str or not 1 <= len(value) <= 128")
        self.shape(projected.body[-1].value, "result")
        prefix = definition(self.tree, "_prefix_on_work")
        self.shape(prefix.body[0].value, "store.retention.capture._SharedLedger(work)")
        self.shape(prefix.body[1].value, "store.retention.plan.contract._digest(writer_response_spki_digest)")
        self.shape(prefix.body[-1].value, '''{"ack_envelope_id": acknowledgment._ack_id_on_work(request_fields["intent_envelope_id"], work),
            "intent_envelope_id": request_fields["intent_envelope_id"],
            "configuration_digest": request_fields["configuration_digest"],
            "generation_sequence": request_fields["generation_sequence"],
            "generation_digest": request_fields["generation_digest"],
            "writer_response_spki_digest": writer_response_spki_digest,
            "source_revision": request_fields["source_revision"]}''')

    def test_driver_row_is_closed_and_bounded_before_its_owned_copy(self):
        owned = definition(self.tree, "_owned_row")
        self.shape(owned.body[0].test, '''type(row) is not dict or len(row) != len(_FIELDS)
            or any(type(name) is not str for name in row) or set(row) != set(_FIELDS)''')
        self.shape(owned.body[1].value, '(row["exact_ack_byte_count"], row["exact_ack_base64url"])')
        self.shape(owned.body[2].test, '''type(count) is not int or not 2 <= count <= acknowledgment.MAX_ACK_BYTES
            or type(encoded) is not str or len(encoded) != (4 * count + 2) // 3''')
        self.shape(call(owned, "store.retention.plan.contract._digest"),
                   'store.retention.plan.contract._digest(row["exact_ack_bytes_digest"])')
        loop, = [node for node in owned.body if isinstance(node, ast.For)]
        self.shape(loop.iter, "prefix.items()")
        self.shape(loop.body[0].value, "row[name]")
        self.shape(loop.body[1].test, '''type(value) is not type(expected)
            or type(value) is str and len(value) > len(expected)
            or type(value) is int and not 1 <= value <= 2**63 - 1''')
        copy = call(owned, "work.prepare_copy")
        self.shape(copy, "work.prepare_copy(row)")
        self.assertLess(loop.end_lineno, copy.lineno)
        self.shape(owned.body[-1].value, "row.copy()")

    def test_every_stored_original_uses_real_canonical_codec_hash_and_pinned_signature_verifier(self):
        verify = definition(self.tree, "_verify_row")
        self.shape(assigned(verify, "owned"), "_owned_row(row, prefix, work)")
        comparisons = calls(verify, "store._match")
        self.assertEqual(len(comparisons), 2)
        self.shape(comparisons[0], "store._match(owned, prefix, work)")
        raw = assigned(verify, "raw")
        self.shape(raw, '''store._decode(owned["exact_ack_base64url"], owned["exact_ack_byte_count"],
            acknowledgment.MAX_ACK_BYTES, work)''')
        self.shape(comparisons[1], '''store._match(owned,
            {"exact_ack_bytes_digest": store.retention._bytes_digest(raw, work)}, work)''')
        signature = call(verify, "acknowledgment._verify_on_work")
        self.shape(signature, '''acknowledgment._verify_on_work(acknowledgment_bytes=raw,
            request_fields=request_fields, writer_public_key=writer_public_key,
            expected_writer_spki_digest=prefix["writer_response_spki_digest"], work=work)''')
        self.assertEqual([node.lineno for node in (comparisons[0], raw, comparisons[1], signature)],
                         sorted(node.lineno for node in (comparisons[0], raw, comparisons[1], signature)))
        self.shape(verify.body[-1].value, "(raw, owned)")
        decoder = definition(self.retention, "_decode")
        charged = call(decoder, "work.charge")
        decoded = call(decoder, "base64.b64decode")
        self.assertLess(charged.lineno, decoded.lineno)
        self.shape(decoded, 'base64.b64decode(value + "=" * (-length % 4), altchars=b"-_", validate=True)')
        self.shape(decoder.body[-2].test, '''len(raw) != count
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value''')
        matcher = definition(self.retention, "_match")
        self.shape(call(matcher, "work.prepare_comparison"), "work.prepare_comparison(actual, value)")
        self.shape(matcher.body[0].body[-1].test, "type(actual) is not type(value) or actual != value")

    def test_existing_ack_never_signs_and_new_ack_returns_only_verified_full_row_readback(self):
        persist = definition(self.tree, "_persist")
        self.assertEqual([item.arg for item in persist.args.args], ["cursor", "request_row"])
        self.assertEqual([item.arg for item in persist.args.kwonlyargs], [
            "writer_private_key", "writer_public_key", "writer_response_spki_digest", "work"])
        self.assertTrue(all(value is None for value in persist.args.kw_defaults))
        self.assertIsNone(persist.args.vararg)
        self.assertIsNone(persist.args.kwarg)
        self.shape(persist.body[1].test, '''not isinstance(writer_private_key, Ed25519PrivateKey)
            or not isinstance(writer_public_key, Ed25519PublicKey)''')
        self.shape(assigned(persist, "request_fields"), "_request_fields(request_row)")
        self.shape(assigned(persist, "prefix"), "_prefix_on_work(request_fields, writer_response_spki_digest, work)")
        self.shape(assigned(persist, "existing"), 'store._read(cursor, _SELECT, (prefix["intent_envelope_id"],), work)')
        existing, = [node for node in persist.body if isinstance(node, ast.If) and ast.unparse(node.test) == "existing is not None"]
        self.shape(existing.body[0].value, "_verify_row(existing, prefix, request_fields, writer_public_key, work)")
        self.shape(existing.body[-1].value, "raw")
        self.assertFalse(calls(existing, "acknowledgment._sign_on_work"))
        signed = call(persist, "acknowledgment._sign_on_work")
        self.shape(signed, '''acknowledgment._sign_on_work(request_fields=request_fields,
            writer_private_key=writer_private_key, writer_public_key=writer_public_key,
            expected_writer_spki_digest=writer_response_spki_digest, work=work)''')
        self.assertLess(existing.end_lineno, signed.lineno)
        expected = assigned(persist, "expected")
        self.shape(expected, '''{**prefix, "exact_ack_base64url": store._encode(raw, work),
            "exact_ack_bytes_digest": store.retention._bytes_digest(raw, work), "exact_ack_byte_count": len(raw)}''')
        parameters = call(persist, "store._parameters")
        self.shape(parameters, "store._parameters(expected, _FIELDS, work)")
        inserted = call(persist, "store._callback")
        self.shape(inserted, "store._callback(work, cursor.execute, _INSERT, parameters)")
        verified = calls(persist, "_verify_row")
        self.assertEqual(len(verified), 2)
        self.shape(verified[1], '''_verify_row(store._read(cursor, _SELECT,
            (prefix["intent_envelope_id"],), work), prefix, request_fields, writer_public_key, work)''')
        matched = call(persist, "store._match")
        self.shape(matched, "store._match(owned, expected, work)")
        self.assertEqual([node.lineno for node in (signed, expected, parameters, inserted, verified[1], matched)],
            sorted(node.lineno for node in (signed, expected, parameters, inserted, verified[1], matched)))
        self.shape(persist.body[-1].value, "stored")
        self.assertFalse(any(isinstance(node, ast.With) for node in ast.walk(self.tree)))
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, {"transaction", "commit", "rollback", "time_ns", "monotonic_ns"})
            if isinstance(node, ast.Name):
                self.assertNotIn(node.id, {"_ValidationWork", "QueryReadValidationLimits", "operation", "opener"})

    def test_same_common_scope_uses_matched_request_after_both_actual_replays_and_returns_an_ordinary_triple(self):
        operation = definition(self.persistence, "_persist_and_reserve_request_on_connection")
        common, = [node for node in operation.body if isinstance(node, ast.With)]
        self.shape(common.items[0].context_expr, "store._context(store._callback(work, raw.transaction), work)")
        replay = call(common, "_retain_and_reserve_in_common")
        cursors = [node for node in common.body if isinstance(node, ast.With)]
        self.assertEqual(len(cursors), 2)
        journal = call(cursors[1], "request_store._persist")
        self.assertIs(assigned(operation, "request_row"), journal)
        self.shape(journal, '''request_store._persist(cursor, prefix, retained_receipt, execution_reservation,
            work, insert=existing is None)''')
        ack = call(cursors[1], "ack_store._persist")
        self.assertIs(assigned(operation, "acknowledgment_bytes"), ack)
        self.shape(ack, '''ack_store._persist(cursor, request_row,
            writer_private_key=writer_private_key, writer_public_key=writer_public_key,
            writer_response_spki_digest=writer_response_spki_digest, work=work)''')
        self.assertLess(replay.lineno, journal.lineno)
        self.assertLess(journal.lineno, ack.lineno)
        continuity = "store._callback(work, revocation_execution._same_connection, connection, raw)"
        for node in (cursors[1].body[0], cursors[1].body[2], cursors[1].body[-1], common.body[-1], operation.body[-2]):
            self.shape(node.value, continuity)
        self.shape(operation.body[-1].value, "(retained_receipt, execution_reservation, acknowledgment_bytes)")
        self.assertLess(common.end_lineno, operation.body[-2].lineno)
        inner = definition(self.persistence, "_retain_and_reserve_in_common")
        retained = call(inner, "store.persist_revocation_planner_record")
        reserved = call(inner, "revocation_execution.reserve_revocation_execution_envelope")
        self.assertLess(retained.lineno, reserved.lineno)
        self.assertFalse(any(isinstance(node, (ast.If, ast.With)) for node in ast.walk(inner)))
        actual_request = definition(self.request, "_persist")
        self.shape(actual_request.body[-1].value, "row")
        self.shape(call(actual_request, "store._match"), "store._match(row, expected, work)")
        self.assertLess(call(actual_request, "store._read").lineno, call(actual_request, "store._match").lineno)

    def test_mandatory_held_keys_follow_real_registry_and_writer_gates_and_bytes_escape_only_after_owner_exits(self):
        fixed = definition(self.persistence, "_persist_and_reserve_request_on_configuration")
        names = [item.arg for item in fixed.args.kwonlyargs]
        self.assertEqual(names[-4:], ["writer_private_key", "writer_public_key", "writer_response_spki_digest", "work"])
        self.assertTrue(all(value is None for value in fixed.args.kw_defaults))
        self.assertEqual(fixed.args.kwarg.arg, "expectations")
        guarded, = [node for node in fixed.body if isinstance(node, ast.If)]
        self.shape(guarded.test, '''not isinstance(writer_private_key, Ed25519PrivateKey)
            or not isinstance(writer_public_key, Ed25519PublicKey)''')
        update = call(fixed, "arguments.update")
        options = {item.arg: item.value for item in update.keywords}
        for name in ("writer_private_key", "writer_public_key", "writer_response_spki_digest"):
            self.shape(options[name], name)
        self.assertLess(guarded.lineno, update.lineno)
        self.shape(fixed.body[-1].value, '''_run_on_configuration(configuration,
            _persist_and_reserve_request_on_connection, arguments, expectations, work)''')
        runner = definition(self.persistence, "_run_on_configuration")
        captured = call(runner, "_inputs_from_configuration")
        imported, = [node for node in runner.body if isinstance(node, ast.ImportFrom)
                     and node.module == "serverware" and [item.name for item in node.names] == ["db"]]
        opened = call(runner, "_connect")
        delegated = call(runner, "writer_connection._run_on_connection")
        self.assertEqual([node.lineno for node in (captured, imported, opened, delegated)],
                         sorted(node.lineno for node in (captured, imported, opened, delegated)))
        self.assertIs(runner.body[-1].value, delegated)
        owner = definition(self.writer, "_run_on_connection")
        tried = owner.body[1]
        self.assertIsInstance(tried, ast.Try)
        connection, = [node for node in tried.body if isinstance(node, ast.With)]
        transaction, = [node for node in connection.body if isinstance(node, ast.With)]
        self.shape(connection.items[0].context_expr, "reader._context(connection, work)")
        self.shape(transaction.items[0].context_expr, "reader._context(transaction, work)")
        actual = call(transaction, "operation")
        self.shape(actual, "operation(connection=db.PostgresMetadataConnection(guarded), work=work, **arguments, **expectations)")
        self.assertIs(assigned(transaction, "result"), actual)
        self.assertLess(call(transaction, "_admit_identity").lineno, actual.lineno)
        self.assertLess(call(transaction, "planner_writer_privilege_check").lineno, actual.lineno)
        self.shape(transaction.body[-1].value, "guarded._call(lambda: None)")
        self.shape(connection.body[-1].value, "_callback(work, reader._require_connection, connection, original, 0)")
        self.shape(tried.body[-2].test, "_callback(work, lambda: connection.closed) is not True")
        self.shape(tried.body[-1].value, "result")
        self.assertLess(connection.end_lineno, tried.body[-2].lineno)
        self.assertTrue(all(any(isinstance(node, ast.Raise) for node in handler.body) for handler in tried.handlers))


if __name__ == "__main__":
    unittest.main()
