#!/usr/bin/env python3
"""UNRUN JIT ownership/read-proof components, not live PostgreSQL admission.

Synthetic independently built primary trees and real synthetic ES256 bytes
exercise the actual membership/receipt/transition helpers. Native lifecycle
checks below use clock doubles and source structure only: no fake successful
TLS/catalog/snapshot DTO and no assertion of a completed native acquisition.
"""
from __future__ import annotations

import ast
import copy
from contextlib import ExitStack
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_retention as retention
from catchplate import authority_jit_assertion_acquisition as acquisition
from catchplate import authority_jit_assertion_planning as source
from catchplate.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
from test_authority_jit_assertion_receipt import fixture
from test_authority_radix_mutation import IndependentTree
from test_authority_primary_original_reader import Cursor


def work():
    return _ValidationWork(QueryReadValidationLimits())


def digest(value):
    return "sha256:" + value * 64


def configuration():
    return dict(read_dsn="host=synthetic.invalid dbname=synthetic", connect_timeout_seconds=2,
        database_identity=("synthetic_planner", "CN=synthetic", "17", "CN=syntheticCA",
            digest("1"), digest("2"), digest("3")),
        assertion_policy={"rp_id": "synthetic.invalid", "origin": "https://synthetic.invalid",
            "maximum_assertion_age_seconds": 30})


def guard(owner, check=lambda: None, meter=None):
    return source._Guard(owner, owner._configured, (10000, 10, 11, 11000, 1010, 1000, 0),
        10000, 10900, check, meter or work())


def originals():
    values = fixture()
    values["approval"]["status"] = "pending"
    challenge = retention._empty(values["challenge"])
    trust = {**values["trust"], "id": "synthetic-trust", "status": "published",
        "rollback_epoch": 1, "payload_digest": digest("8")}
    rows = {
        "approval_requests": [values["approval"]], "webauthn_challenges": [challenge],
        "webauthn_credentials": [values["credential"]],
        "webauthn_trust_publications": [trust],
        "webauthn_trust_publication_high_water": [{"authority_scope": "webauthn-metadata",
            "rollback_epoch": 1, "publication_sequence": trust["sequence"],
            "publication_digest": trust["bundle_digest"], "metadata_blob_digest": trust["payload_digest"]}],
        "rbac_role_bindings": [], "policy_high_water": [{"scope": "global",
            "policy_hash": values["approval"]["policy_hash"]}],
        "jit_webauthn_assertion_receipts": [],
    }
    contracts = acquisition.primary_contract.primary_table_contracts(acquisition.OPERATION)
    trees = {item.table: IndependentTree(rows[item.table], table=item.table, columns=item.key_columns)
        for item in contracts}
    args = {"approval_request_id": values["approval"]["id"], "approver_id": values["approver_id"],
        "challenge_id": challenge["id"], "credential_record_id": values["credential"]["id"],
        "trust_publication_id": trust["id"], "decision": "approve", "assertion": values["assertion"]}
    args["businessIntent"] = acquisition.authority.synthesize_business_intent(acquisition.OPERATION, args)
    request = {"schema": "catchplate.policyAuthorityV9Request/v1", "operation": acquisition.OPERATION,
        "operationId": digest("0"), "requestDigest": digest("0"), "handler": acquisition.receipt.HANDLER,
        "operationManifestDigest": acquisition.authority.OPERATION_MANIFEST_DIGEST, "arguments": args}
    request["requestDigest"] = acquisition.commitment._typed_request_digest(request, work=work())
    request["operationId"] = acquisition.commitment.operation_id(acquisition.OPERATION, request["requestDigest"])
    business = tuple(trees[item.table].root.json_projection() for item in contracts if item.root_class == "business")
    authorization = tuple(trees[item.table].root.json_projection() for item in contracts if item.root_class == "authorization")
    return values, request, trees, business, authorization


class JitAssertionPlanningControls(unittest.TestCase):
    def test_inert_owned_policy_and_closed_native_pins(self):
        args = configuration()
        with patch.object(source.physical, "_connect", side_effect=AssertionError("no native I/O")):
            owner = source.JitAssertionReadPlanner(**args)
        args["assertion_policy"]["rp_id"] = "replaced.invalid"
        self.assertEqual(owner._configured[3][0], "synthetic.invalid")
        with self.assertRaises(FrozenInstanceError):
            owner._configured = ()
        for changes in (dict(connect_timeout_seconds=True), dict(connect_timeout_seconds=1),
                dict(connect_timeout_seconds=301), dict(read_dsn="host=x\npassword=redacted"),
                dict(assertion_policy={**configuration()["assertion_policy"], "maximum_assertion_age_seconds": True}),
                dict(database_identity=(*configuration()["database_identity"][:4], digest("1"), digest("2"), "bad"))):
            args = configuration()
            args.update(changes)
            with self.subTest(fields=tuple(changes)), self.assertRaises(ValueError):
                source.JitAssertionReadPlanner(**args)

    def test_original_clock_work_config_and_cancellation_are_preserved(self):
        owner = source.JitAssertionReadPlanner(**configuration())
        with patch.object(source.time, "monotonic_ns", return_value=20), \
                patch.object(source.clock, "_check_on_work", return_value=10020):
            held = guard(owner)
            held.check()
            held._original = (*held._original[:3], 11000, 1010, *held._original[5:])
            with self.assertRaises(ValueError):
                held.check()
            meter = work()
            meter.charge(hashes=1)
            held = guard(owner, lambda: setattr(meter, "hash_work", 0), meter)
            with self.assertRaises(ValueError):
                held.check()
            held = guard(owner, lambda: held.check())
            with self.assertRaises(ValueError):
                held.check()
            class Cancel(BaseException):
                pass
            error = Cancel()
            def cancel():
                raise error
            held = guard(owner, cancel)
            with self.assertRaises(Cancel) as caught:
                held.check()
            self.assertIs(caught.exception, error)
            self.assertTrue(held._failed)
        with patch.object(source.time, "monotonic_ns", return_value=910), \
                patch.object(source.clock, "_check_on_work", return_value=10020):
            with self.assertRaises(ValueError):
                guard(owner).check()

    def test_real_memberships_precede_es256_derived_absence_and_inline_effects(self):
        from catchplate import authority_planner as planner

        values, request, trees, business, authorization = originals()
        meter = work()
        acquisition._request(request, meter)
        first_queries = acquisition.receipt.queries(request["arguments"])

        cursor = Cursor(trees)
        trace = planner.PlannerTrace(operation=acquisition.OPERATION, _jit_successor=True)
        manifest = tuple(item for item in acquisition.primary_contract.source_query_manifest()
            if item["operation"] == acquisition.OPERATION)
        collector = acquisition.reader._ReadAcquisitionBudget(cursor, trace, work=meter)
        scope = ExitStack()
        self.addCleanup(scope.close)
        scope.enter_context(collector.read_phase(cursor, trace, meter))

        def read(queries):
            selected, actual_proofs, _, records = acquisition._stage(cursor,
                request=request, queries=queries, manifest=manifest, business=business,
                authorization=authorization, trace=trace, work=meter, acquisition=collector)
            self.assertIsNone(cursor.pending)
            by_key = {(proof["table"], proof["keyDigest"]): proof for proof in actual_proofs}
            for row in selected:
                self.assertEqual(by_key[(row["table"], row["keyDigest"])], trees[row["table"]].proof(row))
            return selected, records

        selected, first_records = read(first_queries)
        proofs = tuple(trees[row["table"]].proof(row) for row in selected)
        checked, checked_proofs = acquisition._memberships(selected, proofs, business, authorization, meter)
        context = acquisition.core.KernelContext(acquisition.OPERATION, request["arguments"], checked,
            values["verified_at"], request["requestDigest"], query_reads=first_records)
        policy = configuration()["assertion_policy"]
        actual_receipt = acquisition.receipt.receipt_from_context(context, assertion_policy=policy, work=meter)
        query = acquisition.receipt.receipt_query(actual_receipt["assertion_receipt_digest"])
        second, second_records = read((query,))
        absent = second[0]
        self.assertTrue(query.require_absence)
        self.assertFalse(absent["present"])
        checked, _ = acquisition._memberships((*checked, absent),
            (*checked_proofs, trees[query.table].proof(absent)), business, authorization, meter)
        context = acquisition.core.KernelContext(acquisition.OPERATION, request["arguments"], checked,
            values["verified_at"], request["requestDigest"], query_reads=first_records + second_records)
        transition = acquisition.receipt.transition(context, assertion_policy=policy, work=meter)
        self.assertEqual(len(transition.mutations), 3)
        changed_challenge = next(row["row"] for row in transition.mutations if row["table"] == "webauthn_challenges")
        self.assertEqual(changed_challenge["retention_reference_mask"], 2)
        self.assertEqual(changed_challenge["retention_jit_receipt_digest"], actual_receipt["assertion_receipt_digest"])
        self.assertEqual(collector.sql_reads, 8 * acquisition.primary_reader.SQL_READS_PER_ORIGINAL)
        self.assertNotIn("receipt", acquisition.FIELDS)
        self.assertNotIn("result", acquisition.FIELDS)
        self.assertNotIn("businessAfterRoots", acquisition.FIELDS)

    def test_modified_membership_or_unpinned_policy_cannot_select_receipt_absence(self):
        values, request, trees, business, authorization = originals()
        queries = acquisition.receipt.queries(request["arguments"])
        selected = tuple(trees[query.table].selected(query.absent_key) for query in queries)
        proofs = tuple(trees[row["table"]].proof(row) for row in selected)
        changed = copy.deepcopy(selected)
        changed[0]["row"]["status"] = "approved"
        with self.assertRaises(ValueError):
            acquisition._memberships(changed, proofs, business, authorization, work())
        checked, _ = acquisition._memberships(selected, proofs, business, authorization, work())
        context = acquisition.core.KernelContext(acquisition.OPERATION, request["arguments"], checked,
            values["verified_at"], request["requestDigest"])
        with self.assertRaises(ValueError):
            acquisition.receipt.receipt_from_context(context,
                assertion_policy={**configuration()["assertion_policy"], "rp_id": "different.invalid"}, work=work())

    def test_private_trace_scope_does_not_widen_default_or_other_successors(self):
        from catchplate import authority_planner as planner
        key = {"profile": acquisition.heads.READ_PROFILE,
            "indexIds": list(acquisition.heads.required_index_ids(acquisition.OPERATION, include_write_heads=True)),
            "rowLimit": 13}
        with self.assertRaises(ValueError):
            planner.PlannerTrace(operation=acquisition.OPERATION).read(acquisition.heads.HEAD_TABLE, key)
        planner.PlannerTrace(operation=acquisition.OPERATION, _jit_successor=True).read(acquisition.heads.HEAD_TABLE, key)
        for options in ({"_jit_successor": 1}, {"_jit_successor": True, "_counted_writes": True},
                {"_jit_successor": True, "_recovery_successor": True}):
            with self.assertRaises(ValueError):
                planner.PlannerTrace(operation=acquisition.OPERATION, **options)
        with self.assertRaises(ValueError):
            planner.PlannerTrace(operation="webauthn.challenge.maintain", _jit_successor=True)

    def test_setup_trace_is_fixed_four_catalog_plus_six_real_transaction_queries(self):
        spec = acquisition.authority.operation_spec(acquisition.OPERATION)
        self.assertEqual(source._CATALOG_ROWS, (1, 1, 4, 4))
        self.assertEqual(len(set(spec["businessReads"]) | set(spec["businessWrites"])), 4)
        self.assertEqual(len(spec["authorizationReads"]), 4)
        trace = source._SetupTrace()
        transaction = (source.transaction_source._TRANSACTION_TABLE,
            {"profile": source.transaction_source._TRANSACTION_PROFILE, "rowLimit": 2})
        trace.read(*transaction)
        for ordinal, table in enumerate(source._CATALOG):
            trace.read(table, {"operation": acquisition.OPERATION, "setupOrdinal": ordinal,
                "rowLimit": source._CATALOG_ROWS[ordinal] + 1})
        for _ in range(5):
            trace.read(*transaction)
        self.assertEqual((trace.catalog, trace.transactions), (4, 6))
        with self.assertRaises(ValueError):
            trace.read(*transaction)

    def test_native_and_raw_source_preserve_originals_and_two_stage_order(self):
        native_text = Path(source.__file__).read_text(encoding="utf-8")
        raw_text = Path(acquisition.__file__).read_text(encoding="utf-8")
        native_tree, raw_tree = ast.parse(native_text), ast.parse(raw_text)
        methods = [node for node in ast.walk(native_tree) if isinstance(node, ast.FunctionDef)]
        body = ast.get_source_segment(native_text, next(node for node in methods if node.name == "acquire_originals"))
        self.assertLess(body.index("wrapped.execute(physical._SET_TRANSACTION)"), body.index("original_transaction ="))
        self.assertLess(body.index("original_transaction ="), body.index("planner._validate_database_identity"))
        self.assertLess(body.index("connection.closed is True"), body.index("return raw"))
        self.assertIn("planner._load_authorization_manifest", body)
        self.assertIn("len(manifest) == len(authorization) == 4", body)
        self.assertIn("manifest=read_manifest", body)
        self.assertIn("current_snapshot()", body)
        self.assertNotIn("_open_on_work", native_text)
        functions = [node for node in raw_tree.body if isinstance(node, ast.FunctionDef)]
        raw_body = ast.get_source_segment(raw_text, next(node for node in functions if node.name == "_acquire_on_work"))
        self.assertLess(raw_body.index("first = _stage"), raw_body.index("receipt.receipt_from_context"))
        self.assertLess(raw_body.index("receipt.receipt_from_context"), raw_body.index("receipt.receipt_query"))
        self.assertLess(raw_body.index("second = _stage"), raw_body.index("receipt.transition"))
        self.assertIn("mutation_reader._acquire_indexed_primary_batch", raw_body)
        self.assertIn("trace.close", raw_body)
        self.assertIn("(16, 3, 512)", raw_body)
        stage = ast.get_source_segment(raw_text, next(node for node in functions if node.name == "_stage"))
        self.assertIn("primary_reader.acquire_exact_primary", stage)
        self.assertNotIn("_derive_multiproofs", stage)
        self.assertNotIn("_read_bounded_transition_rows", stage)


if __name__ == "__main__":
    unittest.main()
