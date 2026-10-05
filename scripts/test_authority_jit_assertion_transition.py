"""UNRUN fixed-stage semantic controls with actual synthetic ES256 assertions.

These are transition components, not membership/current-root, native SQL or
compound-clock admission. Large synthetic context fields exercise the selected
envelope/work boundary; they do not assert a legacy producer or full schema
accepts those fixture rows. No signature/retention guard is replaced by success.
"""
from __future__ import annotations

import ast
import copy
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_jit_assertion_transition as staged
from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
from test_authority_jit_assertion_planning import originals, configuration


def meter(**limits):
    return _ValidationWork(QueryReadValidationLimits(**limits))


def fixture():
    values, request, trees, _business, _authorization = originals()
    policy = configuration()["assertion_policy"]
    queries = staged.source.queries(request["arguments"])
    first = tuple(trees[query.table].selected(query.absent_key) for query in queries)
    context = staged.core.KernelContext(staged.source.OPERATION, request["arguments"], first,
        values["verified_at"], request["requestDigest"])
    actual = staged.source.receipt_from_context(context, assertion_policy=policy, work=meter())
    query = staged.source.receipt_query(actual["assertion_receipt_digest"])
    selected = tuple(sorted((*first, trees[query.table].selected(query.absent_key)),
        key=lambda item: (item["table"], item["keyDigest"])))
    return replace(context, selected_rows=selected), policy, actual


def finish(owner, works):
    if owner.actor_policy(works[1]) is not None:
        raise AssertionError("actor-policy inputs escaped private custody")
    derived = owner.receipt(works[2])
    for method, work in zip((owner.base_mutations, owner.normalize_selected,
            owner.normalize_mutations, owner.validate_inventory, owner.expand_inline), works[3:8], strict=True):
        if method(work) is not None:
            raise AssertionError("intermediate escaped private custody")
    return derived, owner.finish(works[8])


def receipt_fixture():
    full, policy, receipt = fixture()
    selected = tuple(item for item in full.selected_rows if item["table"] != staged.source.RECEIPT_TABLE)
    records = []
    for query in staged.source.queries(full.arguments):
        original = next(item for item in selected if item["table"] == query.table)
        records.append(staged.reads._capture_query_read(staged.source.OPERATION,
            query, resolved_query=query, ordered_selected_rows=(original,),
            returned_row_count=int(original["present"]), work=meter()))
    return replace(full, selected_rows=selected, query_reads=tuple(records)), policy, receipt


class JitAssertionTransitionControls(unittest.TestCase):
    def test_first_seven_receipt_uses_same_real_bodies_and_closes_before_eighth_read(self):
        context, policy, expected = receipt_fixture()
        works = [meter() for _ in staged.RECEIPT_STAGES]
        owner = staged._JitAssertionReceipt(context, assertion_policy=policy, work=works[0])
        self.assertEqual(staged.RECEIPT_STAGES, ("capture", "actor-policy", "receipt"))
        self.assertEqual(len(owner._context.selected_rows), 7)
        self.assertEqual(len(owner._context.query_reads), 7)
        self.assertFalse(any(item["table"] == staged.source.RECEIPT_TABLE
            for item in owner._context.selected_rows))
        self.assertIs(staged._JitAssertionReceipt.actor_policy, staged._JitAssertionTransition.actor_policy)
        self.assertIs(staged._JitAssertionReceipt.receipt, staged._JitAssertionTransition.receipt)
        self.assertIsNone(owner.actor_policy(works[1]))
        digest = owner.receipt(works[2])
        self.assertEqual(digest, expected["assertion_receipt_digest"])
        self.assertEqual(staged.source.receipt_query(digest).absent_key,
            {"assertion_receipt_digest": digest})
        self.assertTrue(owner._closed)
        self.assertFalse(owner._failed)
        self.assertEqual(owner._phase, 3)
        self.assertEqual(len(owner._meters), 3)
        self.assertIsNone(owner._mutations)
        for name in ("base_mutations", "normalize_selected", "normalize_mutations",
                "validate_inventory", "expand_inline", "finish"):
            self.assertFalse(hasattr(owner, name))
        with self.assertRaises(ValueError):
            staged._JitAssertionTransition.base_mutations(owner, meter())
        self.assertTrue(owner._failed)

    def test_receipt_capture_requires_exact_seven_source_records_without_placeholders(self):
        for defect in ("no-records", "missing-record", "extra-record", "reordered-records",
                "duplicate-record", "wrong-presence", "wrong-row-key", "eighth-placeholder"):
            context, policy, _ = receipt_fixture()
            if defect == "no-records":
                context = replace(context, query_reads=())
            elif defect == "missing-record":
                context = replace(context, query_reads=context.query_reads[:-1])
            elif defect == "extra-record":
                context = replace(context, query_reads=context.query_reads + context.query_reads[:1])
            elif defect == "reordered-records":
                context = replace(context, query_reads=tuple(reversed(context.query_reads)))
            elif defect == "duplicate-record":
                context = replace(context, query_reads=context.query_reads[:1] + context.query_reads[:-1])
            elif defect == "wrong-presence":
                context = replace(context, query_reads=(replace(context.query_reads[0],
                    returned_row_count=0), *context.query_reads[1:]))
            elif defect == "wrong-row-key":
                context.selected_rows[0]["row"]["id"] = "another-primary"
            else:
                full, _, _ = fixture()
                placeholder = next(item for item in full.selected_rows
                    if item["table"] == staged.source.RECEIPT_TABLE)
                context = replace(context, selected_rows=tuple(sorted((*context.selected_rows, placeholder),
                    key=lambda item: (item["table"], item["keyDigest"]))))
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                staged._JitAssertionReceipt(context, assertion_policy=policy, work=meter())
        context, policy, _ = receipt_fixture()
        with self.assertRaises(ValueError):
            staged._JitAssertionTransition(context, assertion_policy=policy, work=meter())

    def test_first_receipt_owns_actual_inputs_and_retains_real_signature_and_cutoff_refusals(self):
        context, policy, expected = receipt_fixture()
        works = [meter() for _ in staged.RECEIPT_STAGES]
        owner = staged._JitAssertionReceipt(context, assertion_policy=policy, work=works[0])
        context.arguments["assertion"]["response"]["signature"] = "aW52YWxpZA"
        context.selected_rows[0]["row"]["status"] = "changed"
        policy["origin"] = "https://changed.invalid"
        owner.actor_policy(works[1])
        self.assertEqual(owner.receipt(works[2]), expected["assertion_receipt_digest"])
        for defect in ("signature", "cutoff"):
            context, policy, _ = receipt_fixture()
            if defect == "signature":
                context.arguments["assertion"]["response"]["signature"] = "aW52YWxpZA"
            else:
                context = replace(context, database_now=context.database_now + timedelta(seconds=31))
            owner = staged._JitAssertionReceipt(context, assertion_policy=policy, work=meter())
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                owner.actor_policy(meter())
                owner.receipt(meter())
            self.assertTrue(owner._failed)
            self.assertIsNone(owner._mutations)

    def test_first_receipt_stage_budget_order_and_cancellation_are_terminal(self):
        for defect in ("skip", "reuse", "reset", "limits", "cancel", "reentry", "unbound-mutation"):
            context, policy, _ = receipt_fixture()
            first = meter()
            owner = staged._JitAssertionReceipt(context, assertion_policy=policy, work=first)
            if defect == "reset":
                first.input_bytes = 0
            elif defect == "limits":
                first.limits = QueryReadValidationLimits()
            class Cancel(BaseException):
                pass
            with self.subTest(defect=defect), self.assertRaises((ValueError, Cancel)):
                if defect == "skip":
                    owner.receipt(meter())
                elif defect == "unbound-mutation":
                    staged._JitAssertionTransition.base_mutations(owner, meter())
                elif defect in ("cancel", "reentry"):
                    failure = Cancel("synthetic cancellation") if defect == "cancel" else (
                        lambda *_a, **_k: owner.actor_policy(meter()))
                    with patch.object(staged.source, "_receipt_inputs_from_context", side_effect=failure):
                        owner.actor_policy(meter())
                else:
                    owner.actor_policy(first if defect == "reuse" else meter())
            self.assertTrue(owner._failed)
            with self.assertRaises(ValueError):
                owner.receipt(meter())

    def test_genuine_receipt_three_mutations_and_inline_match_original_path(self):
        context, policy, row = fixture()
        originals_before = copy.deepcopy((context, policy))
        expected_work = meter()
        expected = staged.source.transition(context, assertion_policy=policy, work=expected_work)
        works = [meter() for _ in staged.STAGES]
        owner = staged._JitAssertionTransition(context, assertion_policy=policy, work=works[0])
        derived, actual = finish(owner, works)
        self.assertEqual(derived, row["assertion_receipt_digest"])
        self.assertEqual(actual, expected)
        self.assertEqual((context, policy), originals_before)
        self.assertEqual(len(actual.mutations), 3)
        challenge = next(item["row"] for item in actual.mutations
                         if item["table"] == staged.retention.CHALLENGE_TABLE)
        self.assertEqual(challenge["retention_reference_mask"], 2)
        self.assertEqual(challenge["retention_jit_receipt_digest"], derived)
        self.assertEqual(challenge["retention_jit_row_digest"],
            staged.retention._reference_digest(staged.source.RECEIPT_TABLE, row, meter()))
        self.assertEqual(owner._phase, len(staged.STAGES))
        for work in works:
            self.assertEqual(work.limits, QueryReadValidationLimits())
            self.assertLessEqual(work.input_bytes, 64 * 1024 * 1024)

    def test_owned_context_policy_cannot_be_changed_after_capture(self):
        context, policy, row = fixture()
        works = [meter() for _ in staged.STAGES]
        owner = staged._JitAssertionTransition(context, assertion_policy=policy, work=works[0])
        context.arguments["assertion"]["response"]["signature"] = "aW52YWxpZA"
        context.selected_rows[0]["row"]["status"] = "replaced"
        policy["origin"] = "https://changed.invalid"
        derived, result = finish(owner, works)
        self.assertEqual(derived, row["assertion_receipt_digest"])
        self.assertEqual(result.result["assertion_receipt_digest"], derived)

    def test_large_synthetic_selected_envelope_uses_original_per_stage_ceiling(self):
        context, policy, _row = fixture()
        for item in context.selected_rows:
            if item["table"] == "webauthn_trust_publications":
                item["row"]["bundle_json"] = '{"synthetic":"' + "t" * (2 * 1024 * 1024 - 64) + '"}'
            if item["table"] == "approval_requests":
                item["row"]["opaque_request_ciphertext"] = "a" * (1792 * 1024)
        encoded = staged.core.canonical_bytes(context.selected_rows)
        self.assertLess(len(encoded), staged.MAX_SELECTED_BYTES)
        self.assertGreater(len(encoded), 3 * 1024 * 1024)
        works = [meter() for _ in staged.STAGES]
        owner = staged._JitAssertionTransition(context, assertion_policy=policy, work=works[0])
        _digest, result = finish(owner, works)
        self.assertEqual(len(result.mutations), 3)
        self.assertEqual(len(owner._meters), 9)
        for work in works:
            self.assertLessEqual(work.input_bytes, QueryReadValidationLimits().max_input_bytes)
            self.assertLessEqual(work.json_nodes, QueryReadValidationLimits().max_json_nodes)

    def test_real_crypto_cutoff_absence_and_reference_denials_are_preserved(self):
        for defect in ("signature", "cutoff", "wrong-receipt-key", "occupied-inline"):
            context, policy, _row = fixture()
            if defect == "signature":
                context.arguments["assertion"]["response"]["signature"] = "aW52YWxpZA"
            elif defect == "cutoff":
                context = replace(context, database_now=context.database_now + timedelta(seconds=31))
            else:
                for item in context.selected_rows:
                    if defect == "wrong-receipt-key" and item["table"] == staged.source.RECEIPT_TABLE:
                        item["key"]["assertion_receipt_digest"] = "sha256:" + "a" * 64
                    if defect == "occupied-inline" and item["table"] == staged.retention.CHALLENGE_TABLE:
                        item["row"]["retention_jit_receipt_digest"] = "sha256:" + "a" * 64
                        item["row"]["retention_jit_row_digest"] = "sha256:" + "b" * 64
                        item["row"]["retention_reference_mask"] = 2
            works = [meter() for _ in staged.STAGES]
            owner = staged._JitAssertionTransition(context, assertion_policy=policy, work=works[0])
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                finish(owner, works)
            self.assertTrue(owner._failed)
            with self.assertRaises(ValueError):
                owner.receipt(meter())

    def test_no_skips_reused_limits_counter_reset_or_new_meter_inside_owner(self):
        for defect in ("skip", "reuse", "limits", "reset", "process"):
            context, policy, _row = fixture()
            first = meter()
            owner = staged._JitAssertionTransition(context, assertion_policy=policy, work=first)
            if defect == "limits":
                first.limits = QueryReadValidationLimits()
            elif defect == "reset":
                first.input_bytes = 0
            elif defect == "process":
                owner._process = (owner._process[0] + 1, owner._process[1])
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                if defect == "skip":
                    owner.finish(meter())
                else:
                    owner.actor_policy(first if defect == "reuse" else meter())
            self.assertTrue(owner._failed)
        context, policy, _row = fixture()
        limited = meter(max_input_bytes=1024)
        original_limits = limited.limits
        with self.assertRaises(ValueError):
            staged._JitAssertionTransition(context, assertion_policy=policy, work=limited)
        self.assertIs(limited.limits, original_limits)
        self.assertLessEqual(limited.input_bytes, 1024)

    def test_first_base_exception_and_reentrancy_poison_without_retry(self):
        context, policy, _row = fixture()
        owner = staged._JitAssertionTransition(context, assertion_policy=policy, work=meter())
        class Cancel(BaseException):
            pass
        original = Cancel("synthetic cancellation")
        # Failure injection only; no fake crypto/retention success is returned.
        with patch.object(staged.source, "_receipt_inputs_from_context", side_effect=original):
            with self.assertRaises(Cancel) as caught:
                owner.actor_policy(meter())
        self.assertIs(caught.exception, original)
        self.assertTrue(owner._failed)
        owner = staged._JitAssertionTransition(context, assertion_policy=policy, work=meter())
        with patch.object(staged.source, "_receipt_inputs_from_context",
                side_effect=lambda *_a, **_k: owner.actor_policy(meter())):
            with self.assertRaises(ValueError):
                owner.actor_policy(meter())
        self.assertTrue(owner._failed)

    def test_existing_public_bodies_share_extracted_semantics_and_accounting(self):
        root = Path(__file__).resolve().parents[1] / "serverware"
        parsed = ast.parse((root / "authority_jit_assertion_receipt.py").read_text())
        transition = next(item for item in parsed.body if isinstance(item, ast.FunctionDef)
                          and item.name == "transition")
        calls = [ast.unparse(item.func) for statement in transition.body for item in ast.walk(statement)
                 if isinstance(item, ast.Call)]
        self.assertEqual(calls, ["receipt_from_context", "_base_mutations",
                                "retention.expand_mutations", "_transition_result"])
        receipt = next(item for item in parsed.body if isinstance(item, ast.FunctionDef)
                       and item.name == "receipt_from_context")
        self.assertEqual([ast.unparse(item.func) for statement in receipt.body for item in ast.walk(statement)
                          if isinstance(item, ast.Call)], ["_receipt_inputs_from_context", "derive_receipt"])
        parsed = ast.parse((root / "authority_challenge_retention.py").read_text())
        inventory = next(item for item in parsed.body if isinstance(item, ast.FunctionDef)
                         and item.name == "_inventory")
        copies = [item for item in ast.walk(inventory) if isinstance(item, ast.Call)
                  and isinstance(item.func, ast.Name) and item.func.id == "_copy"]
        self.assertEqual(len(copies), 2)
        self.assertEqual(ast.unparse(inventory.body[-1]),
                         "return _validate_inventory(operation, selected, entries)")
        owner_source = ast.parse((root / "authority_jit_assertion_transition.py").read_text())
        self.assertFalse(any(isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
            and item.func.id in {"_ValidationWork", "QueryReadValidationLimits"} for item in ast.walk(owner_source)))
        self.assertFalse(any(isinstance(item, (ast.Import, ast.ImportFrom))
            and (getattr(item, "module", None) == "time" or any(alias.name == "time" for alias in item.names))
            for item in ast.walk(owner_source)))


if __name__ == "__main__":
    unittest.main()
