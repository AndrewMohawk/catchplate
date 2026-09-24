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
        snapshotted = call(reader, "authority_query_reads._snapshot_queries")
        staged = call(reader, "query_sources.authenticate_references")
        resolved = call(reader, "authority_query_reads._resolve_query")
        executed = call(reader, "cursor.execute")
        captured = call(reader, "authority_query_reads._capture_query_read")
        bounded = call(reader, "authority_query_reads._validate_read_budget")
        validations = sorted(calls(reader, "authority_query_reads._validate_query_reads"),
                             key=lambda node: node.lineno)
        self.assertEqual(len(validations), 2)
        validated = validations[0]
        self.assertLess(snapshotted.lineno, staged.lineno)
        self.assertLess(staged.lineno, resolved.lineno)
        self.assertLess(resolved.lineno, executed.lineno)
        self.assertLess(executed.lineno, captured.lineno)
        self.assertLess(captured.lineno, bounded.lineno)
        self.assertLess(bounded.lineno, validated.lineno)
        self.assertEqual(keywords(captured)["returned_row_count"], "len(rows)")
        rendered = ast.unparse(reader)
        self.assertIn("for predicate in resolved_query.predicates", rendered)
        self.assertIn("parameters.append(predicate.value)", rendered)
        self.assertIn("resolved_absent_key = None if is_complete else resolved_query.absent_key", rendered)
        self.assertIn("canonical_bytes(previous) != canonical_bytes(entry)", rendered)
        self.assertIn("for entry in staged_rows", rendered)
        overlaps = [node for node in ast.walk(reader) if isinstance(node, ast.If)
                    and ast.unparse(node.test) == "previous is not None"]
        self.assertEqual(len(overlaps), 1)
        self.assertEqual(ast.dump(overlaps[0].body[0]), ast.dump(ast.parse("entry = previous").body[0]))
        self.assertEqual(keywords(staged), {
            "query": "query", "query_reads": "tuple(query_reads)",
            "selected_rows": "tuple(selected.values())", "trace": "trace",
        })
        state = call(self.method("read_inputs"), "PlanningState")
        self.assertEqual(keywords(state)["query_program"], "queries")
        self.assertEqual(keywords(state)["query_reads"], "query_reads")
        producer = self.method("derive", "MeasuredPlanner")
        primary = call(producer, "authority_root_transition.verify_primary_plan_inputs")
        association = call(producer, "authority_query_reads._validate_query_reads")
        self.assertLess(primary.lineno, association.lineno)
        self.assertEqual(keywords(association), {
            "queries": "planning_state.query_program", "query_reads": "planning_state.query_reads",
            "selected_rows": "selected", "work": "query_work",
        })

    def test_staged_proofs_are_transaction_local_and_only_unproved_rows_are_reread(self):
        producer = self.method("derive", "MeasuredPlanner")
        roots = call(producer, "_read_root_set")
        created = call(producer, "authority_query_staging.StagedQueryProofs")
        selected = call(producer, "_read_planning_inputs")
        pending = call(producer, "query_sources.unproved_rows")
        acquired = call(producer, "_derive_multiproofs")
        merged = call(producer, "query_sources.merge_proofs")
        verified = call(producer, "authority_root_transition.verify_primary_plan_inputs")
        for before, after in zip((roots, created, selected, pending, acquired, merged),
                                 (created, selected, pending, acquired, merged, verified)):
            self.assertLess(before.lineno, after.lineno)
        self.assertEqual(keywords(created), {
            "operation": "operation", "business_before_roots": "roots",
            "authorization_before_roots": "authorization_roots",
            "query_work": "query_work",
        })
        self.assertEqual(keywords(selected)["query_sources"], "query_sources")
        self.assertEqual([ast.unparse(item) for item in pending.args], ["selected"])
        self.assertEqual(keywords(acquired)["selected_rows"], "unproved_selected")
        self.assertEqual(keywords(merged), {
            "selected_rows": "selected", "remaining_proofs": "multiproofs",
        })
        inputs = definition(self.tree, "_read_planning_inputs")
        self.assertEqual(keywords(call(inputs, "program.read_inputs"))["query_sources"], "query_sources")
        self.assertIn("type(query_sources) is not authority_query_staging.StagedQueryProofs", ast.unparse(inputs))
        reader = call(self.method("read_inputs"), "_read_bounded_transition_rows")
        self.assertEqual(keywords(reader)["query_sources"], "query_sources")

    def test_one_source_bounded_query_meter_is_threaded_through_every_real_bookkeeping_phase(self):
        producer = self.method("derive", "MeasuredPlanner")
        meter = call(producer, "_ValidationWork")
        limits = call(producer, "QueryReadValidationLimits")
        self.assertEqual([ast.unparse(value) for value in meter.args], [ast.unparse(limits)])
        self.assertEqual(keywords(limits), {
            "max_hashes": "bookkeeping['maxHashes']",
            "max_input_bytes": "bookkeeping['maxInputBytes']",
            "max_json_nodes": "bookkeeping['maxJsonNodes']",
        })
        allocation, = [node for node in ast.walk(producer) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "query_work" for target in node.targets)]
        self.assertIsInstance(allocation.value, ast.IfExp)
        self.assertEqual(ast.unparse(allocation.value.test),
            "isinstance(self.programs[operation], TypedTransitionPlanningProgram)")
        self.assertEqual(ast.unparse(allocation.value.orelse), "None")
        self.assertLess(meter.lineno, call(producer, "psycopg.connect").lineno)
        self.assertIn("bookkeeping = authority_contract.PLANNER_QUERY_BOOKKEEPING_CONTRACT", ast.unparse(producer))
        for name in ("authority_query_staging.StagedQueryProofs", "_read_planning_inputs"):
            self.assertEqual(keywords(call(producer, name))["query_work"], "query_work")
        forwarding = definition(self.tree, "_read_planning_inputs")
        self.assertEqual(keywords(call(forwarding, "program.read_inputs"))["query_work"], "query_work")
        self.assertEqual(keywords(call(self.method("read_inputs"), "_read_bounded_transition_rows"))["query_work"],
            "query_work")
        reader = definition(self.tree, "_read_bounded_transition_rows")
        pinned = call(reader, "query_sources._require_query_work")
        self.assertEqual([ast.unparse(value) for value in pinned.args], ["query_work"])
        for name in ("_snapshot_queries", "_resolve_query", "_capture_query_read", "_validate_read_budget"):
            actual = call(reader, "authority_query_reads." + name)
            self.assertEqual(keywords(actual)["work"], "query_work")
            self.assertLess(pinned.lineno, actual.lineno)
        validations = calls(reader, "authority_query_reads._validate_query_reads")
        self.assertEqual(len(validations), 2)
        for actual in validations:
            self.assertEqual(keywords(actual)["work"], "query_work")
            self.assertLess(pinned.lineno, actual.lineno)
        self.assertEqual(keywords(call(producer, "authority_query_reads._validate_query_reads"))["work"], "query_work")
        for node in (reader, forwarding, self.method("read_inputs")):
            self.assertFalse(calls(node, "_ValidationWork"))
            self.assertFalse(calls(node, "authority_query_reads.validate_query_reads_measured"))
        state = definition(self.tree, "PlanningState")
        self.assertNotIn("query_work", [node.target.id for node in state.body if isinstance(node, ast.AnnAssign)])

    def test_query_work_failures_abort_typed_planning_and_post_primary_validation_without_reset(self):
        for node, message in ((self.method("read_inputs"), "typed transition query program denied the request"),
                (self.method("derive", "MeasuredPlanner"), "planner before-kernel input verification failed")):
            handlers = [item for item in ast.walk(node) if isinstance(item, ast.ExceptHandler)
                and item.type is not None and "QueryReadWorkError" in ast.unparse(item.type)]
            self.assertEqual(len(handlers), 1)
            self.assertEqual(len(handlers[0].body), 1)
            self.assertIsInstance(handlers[0].body[0], ast.Raise)
            self.assertIn(message, ast.unparse(handlers[0].body[0]))
            self.assertFalse(calls(handlers[0], "_ValidationWork"))
        reader = definition(self.tree, "_read_bounded_transition_rows")
        self.assertFalse(any(isinstance(node, ast.ExceptHandler) for node in ast.walk(reader)))
        imports = [node for node in self.tree.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware.authority_index_contract"]
        self.assertEqual(len(imports), 1)
        self.assertIn(("IndexRangeError", None), [(item.name, item.asname) for item in imports[0].names])
        handler, = [node for node in ast.walk(self.method("read_inputs"))
                    if isinstance(node, ast.ExceptHandler) and node.type is not None
                    and "IndexRangeError" in ast.unparse(node.type)]
        self.assertIsInstance(handler.type, ast.Tuple)
        self.assertIn("IndexRangeError", [ast.unparse(item) for item in handler.type.elts])
        self.assertNotIn("authority_index_reader.IndexReadError", ast.unparse(handler.type))
        self.assertEqual(len(handler.body), 1)
        self.assertIsInstance(handler.body[0], ast.Raise)
        self.assertIn("typed transition query program denied the request", ast.unparse(handler.body[0]))

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

    def test_private_complete_rows_do_not_fall_through_to_ordinary_predicate_or_absence_sql(self):
        reader = definition(self.tree, "_read_bounded_transition_rows")
        branches = [node for node in ast.walk(reader) if isinstance(node, ast.If)
                    and ast.unparse(node.test) == "is_complete"
                    and calls(node, "complete_acquisition.read_rows")]
        self.assertEqual(len(branches), 1)
        branch = branches[0]
        complete_call = call(branch, "complete_acquisition.read_rows")
        self.assertEqual([ast.unparse(value) for value in complete_call.args], ["resolved_query"])
        self.assertFalse(any(calls(node, "cursor.execute") for node in branch.body))
        self.assertFalse(any(calls(node, "_query_trace_key") for node in branch.body))
        ordinary = ast.Module(body=branch.orelse, type_ignores=[])
        executed = call(ordinary, "cursor.execute")
        self.assertEqual(ast.unparse(executed.args[1]), "(*parameters, query.maximum_rows + 1)")
        self.assertLess(call(ordinary, "_query_trace_key").lineno, executed.lineno)
        rendered = ast.unparse(ordinary)
        for fragment in ("for predicate in resolved_query.predicates", "parameters.append(predicate.value)",
                         "len(rows) > query.maximum_rows", "query.require_absence and rows",
                         "typed transition query exceeded its manifest bound",
                         "typed transition exact-absence query found a row"):
            self.assertIn(fragment, rendered)
        self.assertIn("resolved_absent_key = None if is_complete else resolved_query.absent_key",
                      ast.unparse(reader))
        self.assertLess(complete_call.lineno, call(reader, "authority_query_reads._capture_query_read").lineno)
        self.assertFalse(calls(reader, "_ValidationWork"))

    def test_private_complete_reader_finishes_real_proofs_and_rechecks_owned_rows_before_return(self):
        reader = definition(self.tree, "_read_bounded_transition_rows")
        validations = sorted(calls(reader, "authority_query_reads._validate_query_reads"),
                             key=lambda node: node.lineno)
        self.assertEqual(len(validations), 2)
        finished = call(reader, "complete_acquisition.finish_reads")
        pending = call(reader, "query_sources.unproved_rows")
        roots = call(reader, "complete_acquisition.roots_for_proofs")
        acquired = call(reader, "_derive_multiproofs")
        merged = call(reader, "query_sources.merge_proofs")
        verified = call(reader, "complete_acquisition.verify")
        ordered = (validations[0], finished, pending, acquired, merged, verified, validations[1])
        for before, after in zip(ordered, ordered[1:]):
            self.assertLess(before.lineno, after.lineno)
        self.assertEqual([ast.unparse(item) for item in pending.args], ["selected_rows"])
        self.assertEqual(keywords(acquired), {
            "selected_rows": "pending", "roots": ast.unparse(roots), "trace": "trace",
        })
        self.assertEqual(keywords(merged), {
            "selected_rows": "selected_rows", "remaining_proofs": "proofs",
        })
        self.assertEqual(keywords(verified), {"selected_rows": "selected_rows", "before_proofs": "proofs"})
        owned, = [node for node in ast.walk(reader) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "selected_rows" for target in node.targets)
            and ast.unparse(node.value) == "verified.selected_rows"]
        self.assertLess(verified.lineno, owned.lineno)
        self.assertLess(owned.lineno, validations[1].lineno)
        self.assertEqual(keywords(validations[1]), {
            "queries": "queries", "query_reads": "checked_reads", "selected_rows": "selected_rows",
            "work": "query_work",
        })
        returns = [node for node in ast.walk(reader) if isinstance(node, ast.Return)]
        self.assertEqual(len(returns), 1)
        self.assertLess(validations[1].lineno, returns[0].lineno)
        self.assertEqual(ast.unparse(returns[0].value), "(selected_rows, queries, checked_reads)")
        _, collector_tree = source("serverware/authority_complete_acquisition.py")
        collector = definition(collector_tree, "verify", "_CompleteQueryAcquisition")
        genuine = call(collector, "batch._verify_complete_query_batch")
        self.assertEqual(keywords(genuine)["work"], "self._work")
        self.assertEqual(keywords(genuine)["selected_rows"], "selected_rows")
        self.assertEqual(keywords(genuine)["before_proofs"], "before_proofs")
        self.assertFalse(calls(collector, "batch.verify_complete_query_batch"))
        self.assertFalse(calls(collector, "_ValidationWork"))
        _, batch_tree = source("serverware/authority_complete_query_batch.py")
        actual = definition(batch_tree, "_verify")
        primary = call(actual, "primary.evaluate_primary_radix_memberships")
        joined = call(actual, "join.join_index_range")
        self.assertLess(primary.lineno, joined.lineno)

    def test_public_v3_never_constructs_or_passes_complete_context_or_emits_its_evidence(self):
        forwarding = definition(self.tree, "_read_planning_inputs")
        self.assertNotIn("complete_acquisition", keywords(call(forwarding, "program.read_inputs")))
        producer = self.method("derive", "MeasuredPlanner")
        self.assertNotIn("_complete_queries", keywords(call(producer, "PlannerTrace")))
        method = self.method("read_inputs")
        for public_path in (forwarding, producer, method):
            self.assertFalse(calls(public_path, "authority_complete_acquisition._CompleteQueryAcquisition"))
            self.assertFalse(calls(public_path, "program._read_revocation_inputs"))
            self.assertFalse(calls(public_path, "self._read_revocation_inputs"))
        private = self.method("_read_revocation_inputs")
        self.assertEqual(calls(self.tree, "authority_complete_acquisition._CompleteQueryAcquisition"),
                         calls(private, "authority_complete_acquisition._CompleteQueryAcquisition"))
        self.assertEqual(len(calls(private, "authority_complete_acquisition._CompleteQueryAcquisition")), 1)
        defaults = dict(zip((arg.arg for arg in method.args.kwonlyargs), method.args.kw_defaults))
        self.assertEqual(ast.unparse(defaults["complete_acquisition"]), "None")
        self.assertEqual(keywords(call(method, "_read_bounded_transition_rows"))["complete_acquisition"],
                         "complete_acquisition")
        state = call(method, "PlanningState")
        self.assertEqual(keywords(state)["complete_query_evidence"],
            "None if complete_acquisition is None else complete_acquisition.retained_evidence()")
        self.assertLess(call(method, "_read_bounded_transition_rows").lineno,
                        call(method, "complete_acquisition.retained_evidence").lineno)
        kernel = self.method("__call__")
        denial, = [node for node in kernel.body if isinstance(node, ast.If)
                   and ast.unparse(node.test) == "state.complete_query_evidence is not None"]
        self.assertEqual(len(denial.body), 1)
        self.assertIsInstance(denial.body[0], ast.Raise)
        self.assertIn("successor retained-evidence protocol", ast.unparse(denial.body[0]))
        self.assertLess(denial.lineno, call(kernel, "authority_transition_core.KernelContext").lineno)
        self.assertLess(denial.lineno, call(kernel, "self.kernel.transition").lineno)

    def test_private_revocation_factory_captures_exact_context_before_one_clock_and_one_generation(self):
        method = self.method("_read_revocation_inputs")
        parameters = {argument.arg for argument in method.args.kwonlyargs}
        self.assertEqual(parameters, {"request", "manifest", "trace", "query_work",
            "business_before_roots", "authorization_before_roots", "verified_webauthn_evidence"})
        identity, = [node for node in method.body if isinstance(node, ast.FunctionDef)
                     and node.name == "require_identity"]
        rendered = ast.unparse(identity)
        for predicate in ("type(query_work) is not _ValidationWork",
                "type(kernel) is not authority_transition_webauthn.WebAuthnCredentialRevokeKernel",
                "self.kernel is not kernel", "self.operation != operation", "self.handler != kernel.handler",
                "kernel.program_id != authority_contract.transition_program_id(operation)",
                "type(trace) is not PlannerTrace", "trace.operation != operation",
                "trace._complete_queries is not True"):
            self.assertIn(predicate, rendered)
        self.assertIn("operation = authority_transition_webauthn.OPERATION", ast.unparse(method))
        self.assertIn("type(verified_webauthn_evidence) not in (dict, MappingProxyType)", ast.unparse(method))
        self.assertIn("set(verified_webauthn_evidence) != fields", ast.unparse(method))
        projection = call(method, "query_work.prepare_copy")
        self.assertEqual([ast.unparse(item) for item in projection.args], ["evidence_items"])
        copied = call(method, "authority_query_reads._CopyBudget(query_work).copy")
        self.assertIsInstance(copied.args[0], ast.Dict)
        self.assertEqual({key.value: ast.unparse(value)
                          for key, value in zip(copied.args[0].keys, copied.args[0].values)}, {
            "request": "request", "manifest": "manifest", "evidence": "evidence_projection",
            "businessBeforeRoots": "business_before_roots", "authorizationBeforeRoots": "authorization_before_roots"})
        clock = call(method, "_read_database_now")
        cutoff = call(method, "authority_complete_query.cutoff_microseconds")
        generated = call(method, "authority_transition_webauthn._revocation_query_program")
        for first, second in zip((projection, copied, clock, cutoff), (copied, clock, cutoff, generated)):
            self.assertLess(first.lineno, second.lineno)
        self.assertEqual([ast.unparse(item) for item in clock.args], ["cursor"])
        self.assertEqual([ast.unparse(item) for item in cutoff.args], ["database_now"])
        self.assertEqual(keywords(generated), {
            "arguments": "actual_request['arguments']", "cutoff_us": "cutoff_us",
            "request_digest": "request_digest", "evidence": "owned['evidence']", "work": "query_work"})
        identities = sorted(calls(method, "require_identity"), key=lambda node: node.lineno)
        self.assertEqual(len(identities), 3)
        self.assertLess(identities[0].lineno, projection.lineno)
        self.assertLess(clock.lineno, identities[1].lineno)
        self.assertLess(identities[1].lineno, generated.lineno)
        self.assertFalse(calls(method, "_ValidationWork"))
        self.assertFalse(calls(method, "self.kernel.queries"))
        self.assertFalse(calls(method, "authority_audit_capacity.add_capacity_query"))
        self.assertFalse(calls(method, "authority_webauthn_assertion.verify_revoke_assertion_evidence"))

    def test_private_revocation_factory_threads_original_roots_cursor_trace_and_meter_to_real_reader(self):
        method = self.method("_read_revocation_inputs")
        generated = call(method, "authority_transition_webauthn._revocation_query_program")
        collector = call(method, "authority_complete_acquisition._CompleteQueryAcquisition")
        staging = call(method, "authority_query_staging.StagedQueryProofs")
        read = call(method, "_read_bounded_transition_rows")
        retained = call(method, "collector.retained_evidence")
        state = call(method, "PlanningState")
        for before, after in zip((generated, collector, staging, read, retained),
                                 (collector, staging, read, retained, state)):
            self.assertLess(before.lineno, after.lineno)
        self.assertEqual([ast.unparse(item) for item in collector.args], ["cursor"])
        self.assertEqual([ast.unparse(item) for item in read.args], ["cursor"])
        self.assertEqual(keywords(collector), {
            "operation": "operation", "arguments": "actual_request['arguments']", "cutoff_us": "cutoff_us",
            "queries": "tuple((query for query in queries if type(query) is authority_complete_query.CompleteIndexQuery))",
            "business_before_roots": "owned['businessBeforeRoots']",
            "authorization_before_roots": "owned['authorizationBeforeRoots']", "trace": "trace", "work": "query_work"})
        self.assertEqual(keywords(staging), {
            "operation": "operation", "business_before_roots": "owned['businessBeforeRoots']",
            "authorization_before_roots": "owned['authorizationBeforeRoots']", "query_work": "query_work"})
        self.assertEqual(keywords(read), {
            "operation": "operation", "request": "actual_request", "queries": "queries",
            "manifest": "owned['manifest']", "trace": "trace", "query_sources": "staging",
            "query_work": "query_work", "complete_acquisition": "collector"})
        self.assertEqual(keywords(state), {
            "database_now": "database_now", "query_work_units": "sum((query.work_units for query in queries))",
            "verified_webauthn_evidence": "owned['evidence']", "query_program": "queries",
            "query_reads": "query_reads", "complete_query_evidence": "evidence"})
        self.assertFalse(calls(method, "_derive_multiproofs"))
        handlers = [node for node in ast.walk(method) if isinstance(node, ast.ExceptHandler)]
        self.assertEqual(len(handlers), 1)
        for error in ("QueryReadWorkError", "authority_query_staging.QueryStagingError",
                      "authority_complete_acquisition.CompleteAcquisitionError"):
            self.assertIn(error, ast.unparse(handlers[0].type))
        self.assertIn("raise AuthorityPlannerError('private revocation read phase denied the request') from exc",
                      ast.unparse(handlers[0]))

    def test_private_complete_export_retains_actual_merged_proofs_and_never_reacquires_sql(self):
        _, tree = source("serverware/authority_complete_acquisition.py")
        record = definition(tree, "CompleteAcquisitionEvidence")
        self.assertEqual([node.target.id for node in record.body if isinstance(node, ast.AnnAssign)],
            ["cutoff_us", "heads", "frontiers", "business_before_roots", "authorization_before_roots", "before_proofs"])
        verified = definition(tree, "verify", "_CompleteQueryAcquisition")
        genuine = call(verified, "batch._verify_complete_query_batch")
        copied = call(verified, "reads._CopyBudget(self._work).copy")
        self.assertEqual([ast.unparse(item) for item in copied.args], ["actual.before_proofs"])
        self.assertLess(genuine.lineno, copied.lineno)
        saved, = [node for node in ast.walk(verified) if isinstance(node, ast.Assign)
                  and any(ast.unparse(target) == "self._proofs" for target in node.targets)]
        self.assertEqual(ast.unparse(saved.value), ast.unparse(copied))
        export = definition(tree, "retained_evidence", "_CompleteQueryAcquisition")
        self.assertEqual([ast.unparse(item) for item in call(export, "reads._CopyBudget").args], ["self._work"])
        self.assertEqual([ast.unparse(item) for item in call(export, "self._guard").args], ["'complete'"])
        copy_values = [ast.unparse(item.args[0]) for item in calls(export, "copier.copy")]
        for value in ("self._business", "self._authorization", "self._proofs", "proof.query_id"):
            self.assertIn(value, copy_values)
        returned = call(export, "CompleteAcquisitionEvidence")
        self.assertEqual([ast.unparse(item) for item in returned.args],
            ["self._cutoff", "tuple(copied_heads)", "tuple(copied_frontiers)", "business", "authorization", "proofs"])
        for forbidden in ("cursor.execute", "self._cursor.execute", "batch._verify_complete_query_batch",
                          "_ValidationWork", "hashlib.sha256"):
            self.assertFalse(calls(export, forbidden))

    def test_private_complete_trace_uses_source_markers_and_existing_global_budget_only(self):
        init = self.method("__init__", "PlannerTrace")
        defaults = dict(zip((arg.arg for arg in init.args.kwonlyargs), init.args.kw_defaults))
        self.assertEqual(ast.unparse(defaults["_complete_queries"]), "False")
        self.assertIn("type(_complete_queries) is not bool", ast.unparse(init))
        self.assertIn("_complete_queries and operation != authority_complete_query.OPERATION", ast.unparse(init))
        assigned = {node.targets[0].attr: node.value for node in init.body if isinstance(node, ast.Assign)
                    and isinstance(node.targets[0], ast.Attribute)}
        allowed = ast.unparse(assigned["allowed_reads"])
        for name in ("authority_index_heads.HEAD_TABLE", "authority_index_reader.LEAF_TABLE",
                     "authority_index_reader.NODE_TABLE", "if _complete_queries else set()"):
            self.assertIn(name, allowed)
        self.assertNotIn("_complete_queries", ast.unparse(assigned["allowed_writes"]))
        self.assertEqual([ast.unparse(item) for item in call(init, "AuditTraceBudget").args], ["operation"])
        self.assertEqual(len(calls(self.tree, "AuditTraceBudget")), 2)
        read = self.method("read", "PlannerTrace")
        checked = call(read, "authority_index_trace.validate_complete_read_trace")
        self.assertEqual([ast.unparse(item) for item in checked.args], ["self.operation", "table", "key"])
        self.assertLess(checked.lineno, call(read, "self._append").lineno)
        self.assertIn("if not self._complete_queries:", ast.unparse(read))
        self.assertIn("authority_index_trace.PRIMARY_READ_PROFILE", ast.unparse(read))
        self.assertIn("complete trace profile has no current planner admission", ast.unparse(read))
        self.assertIn("raise AuthorityPlannerError('complete trace read is not source closed') from exc", ast.unparse(read))
        append = self.method("_append", "PlannerTrace")
        self.assertLess(call(append, "self._budget.append").lineno, call(append, "self._entries.append").lineno)


if __name__ == "__main__":
    unittest.main()
