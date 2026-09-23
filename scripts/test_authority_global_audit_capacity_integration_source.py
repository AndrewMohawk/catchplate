#!/usr/bin/env python3
"""Source linkage and real source-contract checks, not planner execution.

No planner/DB/transition-registry import or registry replacement is used. These
AST checks pin the actual producer/consumer ordering and separate trace budget;
they do not prove SQL execution, signatures, an authenticated initial count,
delivery, whole-operation replay, or complete production startup.
"""
from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract


PARTICIPANTS = frozenset({
    "policy.activation.prepare", "policy.activation.finalize", "policy.activation.abort",
    "policy.genesis.prepare", "rbac.binding.mutate",
    "control-approval.request", "control-approval.decide", "control-approval.consume",
    "control-approval.deny", "jit.request", "jit.review-receipt.issue", "jit.decide", "jit.deny",
    "release.reserve", "release.v1.reserve", "webauthn.trust.complete",
    "webauthn.registration.create", "webauthn.registration.finalize", "webauthn.credential.revoke",
})
REPLACEMENTS = PARTICIPANTS - {
    "policy.activation.finalize", "release.reserve", "release.v1.reserve",
    "webauthn.trust.complete", "webauthn.registration.create",
    "webauthn.registration.finalize", "webauthn.credential.revoke",
}
NEW_ROOTS = frozenset({
    "webauthn.trust.complete", "webauthn.registration.create",
    "webauthn.registration.finalize", "webauthn.credential.revoke",
})


def source(path):
    text = (ROOT / path).read_text(encoding="utf-8")
    return text, ast.parse(text, filename=path)


def definition(tree, name, owner=None):
    if owner is not None:
        owners = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == owner]
        if len(owners) != 1:
            raise AssertionError(f"source class is not unique: {owner}")
        nodes = owners[0].body
    else:
        nodes = tree.body
    matches = [node for node in nodes if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name == name]
    if len(matches) != 1:
        raise AssertionError(f"source definition is not unique: {owner}.{name}")
    return matches[0]


def calls(node, name):
    return [item for item in ast.walk(node) if isinstance(item, ast.Call) and ast.unparse(item.func) == name]


def call(node, name):
    matches = calls(node, name)
    if len(matches) != 1:
        raise AssertionError(f"source call is not unique: {name}")
    return matches[0]


def keywords(node):
    return {item.arg: ast.unparse(item.value) for item in node.keywords}


class GlobalAuditCapacityIntegrationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text, cls.tree = source("serverware/authority_planner.py")
        _, cls.trace_tree = source("serverware/authority_audit_trace.py")

    def method(self, name, owner="TypedTransitionPlanningProgram"):
        return definition(self.tree, name, owner)

    def test_all_nineteen_source_participants_have_only_named_framework_slots(self):
        actual = {name for name, spec in authority_contract.OPERATIONS.items()
                  if "metadata_audit_outbox" in spec["businessWrites"]}
        self.assertEqual(actual, PARTICIPANTS)
        self.assertEqual(len(REPLACEMENTS), 12)
        for name, spec in authority_contract.OPERATIONS.items():
            with self.subTest(operation=name):
                participates = name in PARTICIPANTS
                self.assertIs(spec["globalAuditCapacity"], participates)
                self.assertEqual(spec["auditCapacityCounterSlotsReplaced"], int(name in REPLACEMENTS))
                self.assertIs(spec["auditCapacityAddsAggregateRoot"], name in NEW_ROOTS)
                self.assertEqual(spec["maximumQueryRows"], spec["maximumBusinessQueryRows"] + int(participates))
                self.assertEqual(spec["maximumMutations"], spec["maximumBusinessMutations"] + int(participates))
                self.assertEqual(spec["maximumWorkUnits"], spec["maximumBusinessWorkUnits"] + 2 * int(participates))
                if participates:
                    self.assertIn("aggregate-high-water", spec["proofPrimitives"])
                    self.assertIn("policy_authority_bounded_aggregate_states", spec["businessWrites"])
                    self.assertTrue(any(item["table"] == "policy_authority_bounded_aggregate_states"
                                        and item["mutation"] == "UPDATE" for item in spec["mutationTemplates"]))

    def test_base_budgets_are_not_redefined_as_plan_budgets(self):
        self.assertEqual((authority_contract.MAX_QUERY_PROOFS, authority_contract.MAX_MUTATIONS,
                          authority_contract.MAX_WORK_UNITS), (256, 512, 16384))
        self.assertEqual((authority_contract.MAX_PLAN_QUERY_ROWS, authority_contract.MAX_PLAN_MUTATIONS,
                          authority_contract.MAX_PLAN_WORK_UNITS), (257, 513, 16386))
        self.assertEqual(authority_contract.MAX_PLAN_SELECTED_BYTES,
                         authority_contract.MAX_REQUEST_BYTES + 8192)
        self.assertEqual(authority_contract.MAX_RESULT_BYTES, 64 * 1024 * 1024)

    def test_framework_query_is_added_once_after_both_kernel_branches_before_reads(self):
        method = self.method("read_inputs")
        added = call(method, "authority_audit_capacity.add_capacity_query")
        read = call(method, "_read_bounded_transition_rows")
        self.assertEqual([ast.unparse(item) for item in added.args], ["self.operation", "proposed_queries"])
        self.assertLess(call(method, "query_program").lineno, added.lineno)
        self.assertLess(call(method, "self.kernel.queries").lineno, added.lineno)
        self.assertLess(added.lineno, read.lineno)
        self.assertEqual(keywords(read)["queries"], "queries")
        self.assertFalse(calls(method, "authority_transition_core.close_queries"))
        state = call(method, "PlanningState")
        charged_query = next(item.value for item in state.keywords if item.arg == "query_work_units")
        self.assertEqual(ast.dump(charged_query), ast.dump(ast.parse(
            "sum(query.work_units for query in queries)", mode="eval",
        ).body))

    def test_explicit_context_and_complete_kernel_batch_are_retained_before_finalization(self):
        method = self.method("__call__")
        context = call(method, "authority_transition_core.KernelContext")
        kernel = call(method, "self.kernel.transition")
        finalized = call(method, "authority_audit_capacity.finalize_capacity")
        self.assertEqual(keywords(context)["database_now"], "state.database_now")
        self.assertEqual(keywords(context)["selected_rows"], "selected_rows")
        self.assertEqual(keywords(context)["query_reads"], "state.query_reads")
        self.assertEqual([ast.unparse(item) for item in kernel.args], ["context"])
        self.assertEqual([ast.unparse(item) for item in finalized.args], ["context", "transition.mutations"])
        self.assertLess(context.lineno, kernel.lineno)
        self.assertLess(kernel.lineno, finalized.lineno)
        self.assertLess(finalized.lineno, call(method, "sorted").lineno)
        self.assertIn("for entry in finalized_mutations", ast.unparse(method))
        no_op_guards = [node for node in ast.walk(method) if isinstance(node, ast.If)
                       and any(isinstance(item, ast.Constant)
                               and item.value == "typed transition kernel returned an undeclared no-op"
                               for item in ast.walk(node))]
        self.assertEqual(len(no_op_guards), 1)
        self.assertEqual(ast.dump(no_op_guards[0].test), ast.dump(ast.parse(
            "not finalized_mutations and not self.kernel.permits_empty_mutation", mode="eval",
        ).body))

    def test_query_observations_are_retained_and_rechecked_against_owned_primary_rows(self):
        reader = definition(self.tree, "_read_bounded_transition_rows")
        snapshotted = call(reader, "authority_query_reads.snapshot_queries")
        resolved = call(reader, "authority_query_reads.resolve_query")
        executed = call(reader, "cursor.execute")
        captured = call(reader, "authority_query_reads.capture_query_read")
        bounded = call(reader, "authority_query_reads.validate_read_budget")
        validated = call(reader, "authority_query_reads.validate_query_reads")
        self.assertLess(snapshotted.lineno, resolved.lineno)
        self.assertLess(resolved.lineno, executed.lineno)
        self.assertLess(executed.lineno, captured.lineno)
        self.assertLess(captured.lineno, bounded.lineno)
        self.assertLess(bounded.lineno, validated.lineno)
        self.assertEqual(keywords(captured)["returned_row_count"], "len(rows)")
        rendered = ast.unparse(reader)
        self.assertIn("for predicate in resolved_query.predicates", rendered)
        self.assertIn("parameters.append(predicate.value)", rendered)
        self.assertIn("resolved_absent_key = resolved_query.absent_key", rendered)
        self.assertIn("canonical_bytes(previous) != canonical_bytes(entry)", rendered)
        state = call(self.method("read_inputs"), "PlanningState")
        self.assertEqual(keywords(state)["query_program"], "queries")
        self.assertEqual(keywords(state)["query_reads"], "query_reads")
        producer = self.method("derive", "MeasuredPlanner")
        primary = call(producer, "authority_root_transition.verify_primary_plan_inputs")
        association = call(producer, "authority_query_reads.validate_query_reads")
        self.assertLess(primary.lineno, association.lineno)
        self.assertEqual(keywords(association), {
            "queries": "planning_state.query_program", "query_reads": "planning_state.query_reads",
            "selected_rows": "selected",
        })

    def test_transition_work_uses_finalized_batch_and_explicit_shared_accounting(self):
        method = self.method("__call__")
        work = call(method, "authority_audit_capacity.transition_work_units")
        self.assertEqual(keywords(work), {
            "operation": "operation", "query_work_units": "state.query_work_units",
            "kernel_work_units": "transition.work_units", "mutations": "finalized_mutations",
        })
        checked = call(method, "authority_audit_capacity.validate_transition_work_units")
        self.assertEqual(keywords(checked), {
            "operation": "operation", "work_units": "total_work_units", "mutations": "finalized_mutations",
        })
        self.assertLess(work.lineno, checked.lineno)
        self.assertEqual(keywords(call(method, "PlannedTransition"))["work_units"], "total_work_units")

    def test_final_producer_checks_precede_proof_reads_and_root_computation(self):
        # Keep this existing test identity while updating its old ordering
        # contract: membership now precedes the kernel; final mutation checks
        # still precede complete after-root recomputation.
        method = self.method("derive", "MeasuredPlanner")
        capacity = call(method, "authority_audit_capacity.validate_capacity_transition")
        work = call(method, "authority_audit_capacity.validate_transition_work_units")
        proof = call(method, "_derive_multiproofs")
        before = call(method, "authority_root_transition.verify_primary_plan_inputs")
        roots = call(method, "authority_root_transition.derive_primary_root_transition")
        self.assertEqual(keywords(capacity), {
            "operation": "operation", "selected_rows": "selected", "mutations": "mutations",
        })
        self.assertEqual(keywords(work)["work_units"], "transition.work_units")
        self.assertLess(proof.lineno, before.lineno)
        program_calls = [node for node in ast.walk(method) if isinstance(node, ast.Call)
                         and ast.unparse(node.func) == "self.programs[operation]"]
        self.assertEqual(len(program_calls), 1)
        self.assertLess(before.lineno, program_calls[0].lineno)
        self.assertLess(program_calls[0].lineno, capacity.lineno)
        self.assertLess(program_calls[0].lineno, work.lineno)
        self.assertLess(capacity.lineno, roots.lineno)
        self.assertLess(work.lineno, roots.lineno)
        self.assertEqual(keywords(before), {
            "operation": "operation", "business_before_roots": "roots",
            "authorization_before_roots": "authorization_roots",
            "selected_rows": "selected", "before_proofs": "multiproofs",
        })
        rendered = ast.unparse(method)
        self.assertIn("selected = verified_inputs.selected_rows", rendered)
        self.assertIn("multiproofs = verified_inputs.before_proofs", rendered)
        self.assertEqual(keywords(roots)["mutations"], "mutation_value")

    def test_payload_rederives_capacity_and_work_before_root_acceptance(self):
        method = definition(self.tree, "validate_measured_plan_payload")
        capacity = call(method, "authority_audit_capacity.validate_capacity_transition")
        work = call(method, "authority_audit_capacity.validate_transition_work_units")
        roots = call(method, "authority_root_transition.verify_primary_root_transition")
        self.assertEqual(keywords(capacity), {
            "operation": "operation", "selected_rows": "selected", "mutations": "mutations",
        })
        self.assertEqual(keywords(work)["work_units"], "measured_plan['workUnits']")
        self.assertLess(capacity.lineno, roots.lineno)
        self.assertLess(work.lineno, roots.lineno)
        self.assertIn("authority_contract.MAX_PLAN_WORK_UNITS", ast.unparse(method))
        self.assertNotIn("authority_contract.MAX_WORK_UNITS", ast.unparse(method))

    def test_existing_persistence_and_service_admission_still_call_payload_validator(self):
        self.assertEqual(len(calls(self.tree, "validate_measured_plan_payload")), 2)
        _, service = source("serverware/authority_service.py")
        self.assertEqual(len(calls(service, "authority_planner.validate_measured_plan_payload")), 2)
        for item in calls(self.tree, "validate_measured_plan_payload"):
            self.assertIn("expected_identity", keywords(item))

    def test_final_proof_inventory_only_uses_plan_limit_not_business_challenge_limit(self):
        proofs = definition(self.tree, "_derive_multiproofs")
        self.assertIn("len(selected_rows) > authority_contract.MAX_PLAN_QUERY_ROWS", ast.unparse(proofs))
        self.assertLess(next(node.lineno for node in ast.walk(proofs) if isinstance(node, ast.Raise)),
                        call(proofs, "authority_radix_proof.derive_multiproofs").lineno)
        aliases = {node.targets[0].id: ast.unparse(node.value) for node in self.tree.body
                   if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
        self.assertEqual(aliases["WEBAUTHN_CHALLENGE_SELECTOR_OVERFLOW_LIMIT"], "authority_contract.MAX_QUERY_PROOFS")
        aliases = {node.targets[0].id: ast.unparse(node.value) for node in self.trace_tree.body
                   if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
        self.assertEqual(aliases["MAX_TRACE_ENTRIES"], "4096")
        self.assertEqual(aliases["MAX_AUDIT_CAPACITY_TRACE_ENTRIES"], "69")
        self.assertEqual(aliases["MAX_PLAN_TRACE_ENTRIES"], "MAX_TRACE_ENTRIES + MAX_AUDIT_CAPACITY_TRACE_ENTRIES")

    def test_only_exact_source_owned_global_query_gets_scan_marker(self):
        query = definition(self.tree, "_query_trace_key")
        rendered = ast.unparse(query)
        self.assertIn("authority_audit_capacity.QUERY_NAME", rendered)
        self.assertIn("query.query_id != query_id", rendered)
        self.assertIn("query != expected", rendered)
        self.assertIn("['globalAuditCapacity']", rendered)
        expected = call(query, "authority_transition_core.BoundedQuery")
        self.assertEqual(keywords(expected)["maximum_rows"], "1")
        self.assertEqual(keywords(expected)["absent_key"], "{'aggregate_id': authority_audit_capacity.AGGREGATE_ID}")
        reader = definition(self.tree, "_read_bounded_transition_rows")
        marked = call(reader, "_query_trace_key")
        self.assertEqual([ast.unparse(item) for item in marked.args], ["operation", "query"])
        self.assertLess(marked.lineno, call(reader, "cursor.execute").lineno)

    def test_trace_partition_uses_exact_authenticated_key_and_contiguous_proof_block(self):
        init = definition(self.trace_tree, "__init__", "AuditTraceBudget")
        self.assertEqual([ast.unparse(item) for item in
                          call(init, "authority_radix_proof.authenticated_key_digest").args], ["aggregate", "key"])
        text = ast.unparse(init)
        self.assertIn("spec['auditCapacityAddsAggregateRoot']", text)
        self.assertIn("if self.adds_root:", text)
        self.assertIn("'depth': depth + 1", text)
        self.assertIn("'pathPrefix': path[:depth]", text)
        append = ast.unparse(definition(self.trace_tree, "append", "AuditTraceBudget"))
        self.assertIn("identity != self._nodes[depth]", append)
        self.assertIn("marker in self._seen", append)
        self.assertIn("self.business_entries > MAX_TRACE_ENTRIES", append)
        self.assertIn("MAX_AUDIT_CAPACITY_TRACE_ENTRIES - 1 + int(self.adds_root)", append)
        self.assertIn("self.business_entries += 1", append)

    def test_trace_complete_set_is_checked_in_both_producer_and_payload(self):
        complete = ast.unparse(definition(self.trace_tree, "close", "AuditTraceBudget"))
        self.assertIn("self._next_proof_node is not None or self._seen != required", complete)
        self.assertIn("authority_audit_capacity.AGGREGATE_ID", complete)
        self.assertIn("required.add('write')", complete)
        imports = [node for node in self.tree.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware.authority_audit_trace"]
        self.assertEqual(len(imports), 1)
        self.assertEqual({item.name for item in imports[0].names}, {
            "AuditTraceBudget", "AuditTraceError", "MAX_PLAN_TRACE_ENTRIES", "audit_capacity_scan_key",
        })
        self.assertEqual(len(calls(self.tree, "AuditTraceBudget")), 2)
        self.assertFalse(any(isinstance(node, ast.ClassDef) and node.name == "_PlannerTraceBudget"
                             for node in self.tree.body))
        producer = self.method("close", "PlannerTrace")
        self.assertEqual([ast.unparse(item) for item in call(producer, "self._budget.close").args], ["mutation_plan"])
        append = self.method("_append", "PlannerTrace")
        self.assertLess(call(append, "self._budget.append").lineno, call(append, "self._entries.append").lineno)
        consumer = definition(self.tree, "validate_measured_plan_payload")
        self.assertLess(call(consumer, "trace_budget.append").lineno, call(consumer, "trace_budget.close").lineno)
        self.assertEqual([ast.unparse(item) for item in call(consumer, "trace_budget.close").args], ["mutations"])
        for method in (producer, append, consumer):
            self.assertTrue(any(isinstance(node, ast.ExceptHandler)
                                and isinstance(node.type, ast.Name) and node.type.id == "AuditTraceError"
                                for node in ast.walk(method)))


if __name__ == "__main__":
    unittest.main()
