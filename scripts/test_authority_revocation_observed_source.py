#!/usr/bin/env python3
"""Nonimporting linkage for independently observed planner root contexts.

These are bounded source contracts, not a running planner, authenticated roots,
SQL or successful signature/proof evidence. The active transition registry is
never imported, patched or replaced. Runtime coverage of the inert helpers is
separate and retains its deterministic-observation boundary.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(path, maximum=256 * 1024):
    target = ROOT / path
    if target.stat().st_size > maximum:
        raise AssertionError("observed-root source exceeds its inspection bound")
    source = target.read_text(encoding="utf-8")
    return source, ast.parse(source, filename=path)


def definition(tree, name):
    result = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name]
    if len(result) != 1:
        raise AssertionError("observed-root definition is not unique: " + name)
    return result[0]


def calls(tree, name):
    return sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
        and ast.unparse(node.func) == name), key=lambda node: (node.lineno, node.col_offset))


def call(tree, name):
    result = calls(tree, name)
    if len(result) != 1:
        raise AssertionError("observed-root call is not unique: " + name)
    return result[0]


def keywords(node):
    if any(item.arg is None for item in node.keywords):
        raise AssertionError("observed-root call has open keyword expansion")
    return {item.arg: item.value for item in node.keywords}


def assigned(tree, name):
    result = [node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(result) != 1:
        raise AssertionError("observed-root assignment is not unique: " + name)
    return result[0]


class RevocationObservedSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper_source, cls.helper = read("serverware/authority_revocation_observed.py")
        cls.planner_source, cls.planner = read("serverware/authority_planner.py", 2 * 1024 * 1024)
        cls.program = definition(cls.planner, "TypedTransitionPlanningProgram")

    def shape(self, actual, expected):
        self.assertEqual(ast.dump(actual), ast.dump(ast.parse("(" + expected.strip() + ")", mode="eval").body))

    def test_partial_context_is_closed_source_fourteen_and_helpers_do_not_promote_authority(self):
        self.shape(assigned(self.helper, "_PARTIAL_CONTEXT_FIELDS"),
            'production._CONTEXT_FIELDS - {"expectedBefore"}')
        self.shape(assigned(self.helper, "_MUTATION_TABLES"),
            'frozenset(authority.operation_spec(complete.OPERATION)["businessWrites"])')
        method = definition(self.helper, "_validate_partial_context")
        self.shape(call(method, "batch._SharedLedger"), 'batch._SharedLedger(work)')
        self.shape(call(method, "plan.contract._object"),
            'plan.contract._object(context, _PARTIAL_CONTEXT_FIELDS, "observed production context")')
        self.shape(call(method, "plan._expectation_context"), 'plan._expectation_context(context)')
        self.assertLess(call(method, "batch._SharedLedger").lineno,
            call(method, "plan.contract._object").lineno)
        imports = {(node.module, item.name) for node in self.helper.body
            if isinstance(node, ast.ImportFrom) for item in node.names}
        self.assertEqual(imports, {("__future__", "annotations"), *(
            ("serverware", name) for name in (
                "authority_complete_query", "authority_complete_query_batch", "authority_contract",
                "authority_index_contract", "authority_index_heads", "authority_index_projection",
                "authority_query_reads", "authority_revocation_plan",
                "authority_revocation_plan_production", "authority_revocation_roots"))})
        self.assertFalse(any(isinstance(node, ast.Import) for node in self.helper.body))
        for forbidden in ("plan._verify_signed_revocation_plan_on_work", "reads._ValidationWork",
                "roots._read_revocation_root_inventory_on_work", "production._build_and_sign"):
            self.assertEqual(calls(self.helper, forbidden), [])

    def test_capture_copies_full_source_rows_and_reconstructs_exact_fresh_carriers(self):
        self.shape(assigned(self.helper, "_HEAD_FIELDS"), '''(
            "index_id", "table_name", "counted_profile", "projection_digest",
            "projection_manifest_digest", "index_revision", "root_digest", "leaf_count")''')
        graph = definition(self.helper, "_inventory_graph")
        self.shape(graph.body[0].value, '''{
            "businessRoots": [{name: getattr(row, name) for name in roots._PRIMARY_FIELDS}
                for row in inventory.business_roots],
            "authorizationRoots": [{name: getattr(row, name) for name in roots._PRIMARY_FIELDS}
                for row in inventory.authorization_roots],
            "countedHeads": [dict(zip(_HEAD_FIELDS, (row.index_id, row.table, row.counted_profile,
                row.projection_digest, row.projection_manifest_digest, row.index_revision,
                row.index_root.digest, row.index_root.count))) for row in inventory.counted_heads]}''')
        capture = definition(self.helper, "_capture_root_inventory")
        self.shape(assigned(capture, "owned"), 'reads._CopyBudget(work).copy(_inventory_graph(root_inventory))')
        validations = calls(capture, "_validate_inventory")
        self.assertEqual(len(validations), 2)
        self.shape(validations[0], '_validate_inventory(root_inventory)')
        self.shape(validations[1], '_validate_inventory(result)')
        self.assertLess(validations[0].lineno, assigned(capture, "owned").lineno)
        self.assertLess(assigned(capture, "result").lineno, validations[1].lineno)
        self.assertEqual(len(calls(capture, "roots._RootInventory")), 1)
        self.assertEqual(len(calls(capture, "roots._PrimaryObservation")), 2)
        self.assertEqual(len(calls(capture, "heads.CapturedIndexHead")), 1)
        self.assertEqual(len(calls(capture, "counted.CountedNode")), 1)
        inventory = ast.unparse(definition(self.helper, "_validate_inventory"))
        for source_guard in (
                "type(inventory) is not roots._RootInventory",
                "type(row) is not roots._PrimaryObservation",
                "type(row) is not heads.CapturedIndexHead",
                "type(row.index_root) is not counted.CountedNode",
                "row.manifest_digest != plan._QUERY_MANIFEST_DIGEST",
                "zip(inventory.counted_heads, roots._HEAD_IDS)",
                "row.table != projection._definition(identity).table"):
            self.assertIn(source_guard, inventory)
        self.shape(definition(self.helper, "_counter").body[0].test,
            'type(value) is not int or not 0 <= value <= counted.I64_MAX')

    def test_full_comparison_precedes_source_role_write_union_and_owned_subset(self):
        project = definition(self.helper, "_project_expected_context")
        self.shape(assigned(project, "full_before"), '_inventory_before(root_inventory)')
        strict = call(project, "plan.semantics._expected_before")
        comparison = call(project, "plan.semantics._canonical_equal")
        self.shape(strict, 'plan.semantics._expected_before(acquired_before)')
        self.shape(comparison, '''plan.semantics._canonical_equal(acquired_before, full_before,
            work=work, label="full acquired roots differ from independent observations")''')
        self.assertLess(strict.lineno, comparison.lineno)
        self.assertLess(comparison.lineno, assigned(project, "writes").lineno)
        self.shape(assigned(project, "writes"),
            '{identity for table in mutated_tables for identity in projection.index_ids_for_table(table)}')
        self.shape(assigned(project, "selected"),
            'writes | {complete._role(complete.OPERATION, name).index_id for name in query_roles}')
        predicates = [node.test for node in project.body if isinstance(node, ast.If)]
        self.assertEqual(len(predicates), 3)
        for actual, expected in zip(predicates, (
                'len(query_roles) != len(complete.ROLES) or set(query_roles) != set(complete.ROLES)',
                'any(table not in _MUTATION_TABLES for table in mutated_tables)',
                'tuple(sorted(writes)) != write_index_ids')):
            self.shape(actual, expected)
        self.shape(assigned(project, "before"), '''{
            "businessBeforeRoots": full_before["businessBeforeRoots"],
            "authorizationBeforeRoots": full_before["authorizationBeforeRoots"],
            "indexBeforeHeads": [row for row in full_before["indexBeforeHeads"] if row["indexId"] in selected]}''')
        self.shape(assigned(project, "projected"),
            'reads._CopyBudget(work).copy({**context, "expectedBefore": before})')
        self.assertLess(assigned(project, "selected").lineno, assigned(project, "projected").lineno)
        self.shape(call(project, "production._validate_context"), 'production._validate_context(projected, work)')
        self.shape(project.body[-1].value, 'projected')

    def test_private_entry_points_share_real_body_and_capture_before_acquisition_callbacks(self):
        legacy = definition(self.program, "_produce_revocation_plan")
        observed = definition(self.program, "_produce_observed_revocation_plan")
        shared = definition(self.program, "_produce_revocation_plan_on_work")
        legacy_call = call(legacy, "self._produce_revocation_plan_on_work")
        observed_call = call(observed, "self._produce_revocation_plan_on_work")
        self.assertEqual([ast.unparse(item) for item in legacy_call.args], ['cursor'])
        self.assertEqual([ast.unparse(item) for item in observed_call.args], ['cursor'])
        common = {name: name for name in ("request", "manifest", "evidence", "context",
            "verifier_public_key", "planner_private_key", "planner_public_key", "query_work", "trace")}
        self.assertEqual({key: ast.unparse(value) for key, value in keywords(legacy_call).items()}, common)
        self.assertEqual({key: ast.unparse(value) for key, value in keywords(observed_call).items()},
            {**common, "root_inventory": "root_inventory"})
        self.shape(observed.body[1].test, 'root_inventory is None')
        self.assertIsInstance(observed.body[1].body[0], ast.Raise)
        self.shape(assigned(shared, "independent_inventory"), '''None if root_inventory is None else
            authority_revocation_observed._capture_root_inventory(root_inventory, work=query_work)''')
        self.shape(assigned(shared, "owned"), '''authority_query_reads._CopyBudget(query_work).copy({
            "request": request, "manifest": manifest, "evidence": evidence, "context": context})''')
        acquired = call(shared, "self._acquire_revocation_transition")
        self.assertLess(assigned(shared, "independent_inventory").lineno, assigned(shared, "owned").lineno)
        self.assertLess(assigned(shared, "owned").lineno, acquired.lineno)
        self.assertLess(call(shared, "authority_revocation_observed._validate_partial_context").lineno,
            acquired.lineno)
        self.shape(keywords(acquired)["query_work"], 'query_work')
        self.shape(keywords(acquired)["trace"], 'trace')
        self.shape(keywords(acquired)["business_before_roots"], 'expected_before["businessBeforeRoots"]')
        self.shape(keywords(acquired)["authorization_before_roots"], 'expected_before["authorizationBeforeRoots"]')
        self.assertEqual(calls(shared, "_ValidationWork"), [])

    def test_actual_acquisition_projects_full_tuple_vectors_before_packaging_or_signing(self):
        shared = definition(self.program, "_produce_revocation_plan_on_work")
        project = call(shared, "authority_revocation_observed._project_expected_context")
        self.assertEqual([ast.unparse(item) for item in project.args], ['actual_context', 'independent_inventory'])
        actual = keywords(project)
        self.assertEqual(set(actual), {"acquired_before", "query_roles", "mutated_tables", "write_index_ids", "work"})
        self.shape(actual["acquired_before"], '''{
            "businessBeforeRoots": list(raw.business_before_roots),
            "authorizationBeforeRoots": list(raw.authorization_before_roots),
            "indexBeforeHeads": [{"indexId": item.index_id, "indexRevision": item.index_revision,
                "rootDigest": item.index_root.digest, "leafCount": item.index_root.count} for item in raw.heads]}''')
        self.shape(actual["query_roles"], 'tuple(query.role for query in queries)')
        self.shape(actual["mutated_tables"], 'tuple(mutation["table"] for mutation in acquired.mutations)')
        self.shape(actual["write_index_ids"], 'tuple(head.index_id for head in acquired.write_evidence.result.before_heads)')
        self.shape(actual["work"], 'query_work')
        self.shape(assigned(shared, "queries"), '''tuple(query for query in state.query_program
            if type(query) is authority_complete_query.CompleteIndexQuery)''')
        self.assertLess(call(shared, "self._acquire_revocation_transition").lineno, project.lineno)
        self.assertLess(project.lineno, assigned(shared, "index_ids").lineno)
        self.assertLess(project.lineno, assigned(shared, "heads").lineno)
        self.assertLess(project.lineno, call(shared, "authority_revocation_proof_bundle._derive_on_work").lineno)
        self.assertLess(project.lineno, call(shared, "authority_revocation_plan_production._build_and_sign").lineno)

    def test_owned_expected_context_reaches_original_context_bytes_and_detached_return(self):
        shared = definition(self.program, "_produce_revocation_plan_on_work")
        encoded = call(shared, "authority_revocation_retention._encode_context_on_work")
        detached = assigned(shared, "independent_context")
        signed = call(shared, "authority_revocation_plan_production._build_and_sign")
        returned = call(shared, "_ProducedObservedRevocationPlan")
        self.shape(encoded, '''authority_revocation_retention._encode_context_on_work(
            actual_context, database_now=state.database_now, work=query_work)''')
        self.shape(detached, '''None if independent_inventory is None else
            authority_query_reads._CopyBudget(query_work).copy(actual_context)''')
        self.assertLess(encoded.lineno, detached.lineno)
        self.assertLess(detached.lineno, signed.lineno)
        self.assertLess(signed.lineno, returned.lineno)
        self.shape(keywords(signed)["context"], 'actual_context')
        self.shape(keywords(signed)["work"], 'query_work')
        self.shape(returned, '''_ProducedObservedRevocationPlan(signed, state.database_now,
            query_work.metrics, evaluation_context_bytes, independent_context)''')
        for name, fields in (("_ProducedRevocationPlan", (
                "signed", "database_now", "metrics", "evaluation_context_bytes")),
                ("_ProducedObservedRevocationPlan", (
                "signed", "database_now", "metrics", "evaluation_context_bytes", "expected_context"))):
            carrier = definition(self.planner, name)
            self.assertEqual([item.target.id for item in carrier.body if isinstance(item, ast.AnnAssign)], list(fields))
            self.assertEqual([ast.unparse(item) for item in carrier.decorator_list], ['dataclass(frozen=True, slots=True)'])
        public = definition(self.program, "__call__")
        self.assertEqual(calls(public, "self._produce_observed_revocation_plan"), [])
        self.assertEqual(calls(public, "self._produce_revocation_plan_on_work"), [])
        self.assertIn("complete planning requires the successor retained-evidence protocol", ast.unparse(public))
        # There are exactly two private delegates. This is source linkage, not
        # an invocation of the registry-closed planner or a successful proof.
        self.assertEqual(len(calls(self.planner, "self._produce_revocation_plan_on_work")), 2)


if __name__ == "__main__":
    unittest.main()
