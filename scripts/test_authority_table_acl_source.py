#!/usr/bin/env python3
"""Source-only authority table ACL closure checks; no PostgreSQL proof.

Import only the real pure contract. Inspect bounded committed source ASTs,
never import db/schema, execute extracted functions, or replace the registry.
These controls cannot prove GRANT/REVOKE, effective role membership, column
privileges, catalog behavior, migrations or whole startup admission at runtime.
"""
from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract


PHASE2 = (
    "policy_authority_activation_evidence_bindings",
    "policy_authority_bounded_aggregate_states",
    "policy_authority_continuations",
    "policy_authority_exact_pages",
    "policy_authority_external_evidence_receipts",
    "policy_authority_opaque_values",
    "policy_authority_sealed_values",
    "policy_authority_secondary_index_heads",
    "policy_authority_tombstones",
    "policy_authority_work_pages",
)
ADDITIONAL = tuple(sorted((*PHASE2,
    "policy_authority_authorization_dependency_manifests",
    "policy_authority_operation_mutation_templates")))
READ_ONLY = "_POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES"
LEGACY_UNIONS = {
    "_POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES",
    "_POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES",
    "_JIT_AUTHORITY_RUNTIME_READ_ONLY_TABLES",
}
LEGACY_EXPLICIT = {
    "policy_authority_genesis_preparations", "policy_authority_genesis_finalizations",
    "policy_high_water", "policy_publications", "webauthn_trust_publications",
    "control_plane_approvals", "webauthn_challenges", "webauthn_credentials",
    "rbac_authority_state", "rbac_role_bindings", "metadata_audit_outbox", "audit_events",
}


def read_source(relative, maximum):
    path = ROOT / relative
    if path.stat().st_size > maximum:
        raise AssertionError("source fixture exceeded its explicit file bound")
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source)


def named_function(tree, name):
    matches = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(matches) != 1:
        raise AssertionError("source function is not unique: " + name)
    return matches[0]


def assignments(tree, name, *, recursive=False):
    nodes = ast.walk(tree) if recursive else tree.body
    return [node for node in nodes if
        (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name
            for target in node.targets)) or
        (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name)]


def named_assignment(tree, name, *, recursive=False):
    matches = assignments(tree, name, recursive=recursive)
    if len(matches) != 1:
        raise AssertionError("source assignment is not unique: " + name)
    return matches[0]


def call_named(node, name):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name


def keyword(call, name):
    values = [item.value for item in call.keywords if item.arg == name]
    if len(values) != 1:
        raise AssertionError("call keyword is not exact: " + name)
    return values[0]


class AuthorityTableAclSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db_source, cls.db_tree = read_source("serverware/db.py", 16 * 1024 * 1024)
        cls.schema_source, cls.schema_tree = read_source("serverware/authority_store/schema.py", 2 * 1024 * 1024)
        cls.seal = named_function(cls.db_tree, "_seal_postgres_schema_acl")

    def assert_shape(self, node, expression):
        # Parse a fixed fixture expression for structural comparison only;
        # neither this expression nor the inspected source is executed.
        self.assertEqual(ast.dump(node), ast.dump(ast.parse(expression, mode="eval").body))

    def test_exact_ten_phase2_and_twelve_additional_tables_are_source_constants(self):
        self.assertIs(type(authority_contract.PHASE2_STORE_TABLES), tuple)
        self.assertIs(type(authority_contract.V9_ADDITIONAL_PROTECTED_TABLES), tuple)
        self.assertEqual(authority_contract.PHASE2_STORE_TABLES, PHASE2)
        self.assertEqual(authority_contract.V9_ADDITIONAL_PROTECTED_TABLES, ADDITIONAL)
        self.assertEqual(len(set(ADDITIONAL)), 12)
        self.assertEqual(set(ADDITIONAL) - set(PHASE2), {
            "policy_authority_authorization_dependency_manifests",
            "policy_authority_operation_mutation_templates",
        })
        self.assertTrue(set(ADDITIONAL).isdisjoint({"credentials", "principals", "routes", "oidc_browser_sessions"}))

    def test_runtime_read_only_union_keeps_all_three_legacy_sets_and_explicit_tables(self):
        value = named_assignment(self.db_tree, READ_ONLY).value
        self.assertTrue(call_named(value, "frozenset"))
        self.assertEqual(len(value.args), 1)
        self.assertFalse(value.keywords)
        self.assertIsInstance(value.args[0], ast.Set)
        members = value.args[0].elts
        stars = [member.value for member in members if isinstance(member, ast.Starred)]
        self.assertEqual(len(stars), 4)
        self.assertEqual({node.id for node in stars if isinstance(node, ast.Name)}, LEGACY_UNIONS)
        attributes = [node for node in stars if isinstance(node, ast.Attribute)]
        self.assertEqual(len(attributes), 1)
        self.assert_shape(attributes[0], "authority_contract.V9_ADDITIONAL_PROTECTED_TABLES")
        literals = [node for node in members if not isinstance(node, ast.Starred)]
        self.assertTrue(all(isinstance(node, ast.Constant) and type(node.value) is str for node in literals))
        self.assertEqual(len(literals), len(LEGACY_EXPLICIT))
        self.assertEqual({node.value for node in literals}, LEGACY_EXPLICIT)

    def test_phase2_tables_are_not_blanket_immutable_or_head_classifications(self):
        for name in ("_POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES", "_POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES"):
            value = named_assignment(self.db_tree, name).value
            self.assertIsInstance(value, ast.Tuple)
            self.assertTrue(all(isinstance(node, ast.Constant) and type(node.value) is str for node in value.elts))
            self.assertTrue(set(ADDITIONAL).isdisjoint(node.value for node in value.elts))

    def test_phase2_spec_alias_and_operation_manifest_use_the_same_source_inventories(self):
        _, spec_tree = read_source("scripts/authority/phase2_store_spec.py", 1024 * 1024)
        alias = named_assignment(spec_tree, "PHASE2_TABLES")
        self.assertIsInstance(alias, ast.AnnAssign)
        self.assert_shape(alias.value, "authority_contract.PHASE2_STORE_TABLES")
        _, contract_tree = read_source("serverware/authority_contract.py", 2 * 1024 * 1024)
        digest = named_assignment(contract_tree, "OPERATION_MANIFEST_DIGEST").value
        self.assertTrue(call_named(digest, "_digest"))
        self.assertEqual(len(digest.args), 2)
        self.assertFalse(digest.keywords)
        self.assert_shape(digest.args[0], "CONTRACT_SCHEMA")
        self.assertIsInstance(digest.args[1], ast.Dict)
        for field, expression in (("phase2StoreTables", "list(PHASE2_STORE_TABLES)"),
                ("v9AdditionalProtectedTables", "list(V9_ADDITIONAL_PROTECTED_TABLES)")):
            values = [value for key, value in zip(digest.args[1].keys, digest.args[1].values)
                if isinstance(key, ast.Constant) and key.value == field]
            self.assertEqual(len(values), 1)
            self.assert_shape(values[0], expression)

    def test_canonical_metadata_sealer_rejects_missing_or_partial_closure_before_sql(self):
        first = self.seal.body[0]
        self.assertIsInstance(first, ast.If)
        self.assert_shape(first.test,
            "schema == _POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME and "
            "(type(runtime_read_only_tables) is not frozenset or "
            "runtime_read_only_tables != _POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES)")
        self.assertEqual(len(first.body), 1)
        self.assertIsInstance(first.body[0], ast.Raise)
        self.assert_shape(first.body[0].exc,
            "error_type('metadata runtime read-only table closure is not source exact')")
        self.assertFalse(first.orelse)
        cursor_calls = [node for node in ast.walk(self.seal) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr in {"cursor", "execute"}]
        self.assertTrue(cursor_calls)
        self.assertTrue(all(node.lineno > first.end_lineno for node in cursor_calls))

    def test_all_three_metadata_callers_pass_the_actual_complete_read_only_set(self):
        owners = ((self.db_tree, "init_db"),
            (self.schema_tree, "_policy_candidate_authority_expected_structure_manifest"),
            (self.schema_tree, "repair_policy_candidate_authority_completed_v9_receipt"))
        for tree, name in owners:
            function = named_function(tree, name)
            calls = [node for node in ast.walk(function) if call_named(node, "_seal_postgres_schema_acl")]
            self.assertEqual(len(calls), 1, name)
            self.assert_shape(keyword(calls[0], "runtime_read_only_tables"), READ_ONLY)
            self.assert_shape(keyword(calls[0], "runtime_role"), "_METADATA_STORE_RUNTIME_ROLE")
            self.assert_shape(keyword(calls[0], "table_privileges"), "('SELECT', 'INSERT', 'UPDATE', 'DELETE')")
        all_calls = [node for tree in (self.db_tree, self.schema_tree) for node in ast.walk(tree)
            if call_named(node, "_seal_postgres_schema_acl")]
        self.assertEqual(len(all_calls), 5)
        unrelated = [node for node in all_calls if not any(item.arg == "runtime_read_only_tables" for item in node.keywords)]
        self.assertEqual(len(unrelated), 2)
        self.assertEqual({ast.dump(keyword(node, "schema")) for node in unrelated}, {
            ast.dump(ast.Name(id="_RECOVERY_WITNESS_POSTGRES_SCHEMA", ctx=ast.Load())),
            ast.dump(ast.Name(id="_AUDIT_POSTGRES_SCHEMA", ctx=ast.Load())),
        })

    def test_actual_runtime_revoke_loop_uses_the_same_source_inventory_and_role(self):
        loops = [node for node in ast.walk(self.seal) if isinstance(node, ast.For)
            and ast.dump(node.iter) == ast.dump(ast.parse("sorted(runtime_read_only_tables)", mode="eval").body)]
        revoke = [node for node in loops if "REVOKE INSERT, UPDATE, DELETE ON "
            in ast.get_source_segment(self.db_source, node)]
        self.assertEqual(len(revoke), 1)
        source = ast.get_source_segment(self.db_source, revoke[0])
        self.assertIn("_policy_candidate_authority_identifier(table)", source)
        self.assertIn("+ role_name", source)
        self.assertNotIn("+ planner_writer_role_name", source)
        self.assertNotIn("+ executor_role_name", source)
        role = named_assignment(self.seal, "role_name", recursive=True)
        self.assert_shape(role.value, "_policy_candidate_authority_identifier(runtime_role)")

    def test_actual_runtime_acl_expected_branch_requires_select_only_for_protected_tables(self):
        checks = [node for node in ast.walk(self.seal) if isinstance(node, ast.For)
            and "actual_runtime_grants.get(name, set())" in ast.get_source_segment(self.db_source, node)]
        self.assertEqual(len(checks), 1)
        expected = named_assignment(checks[0], "expected", recursive=True)
        self.assert_shape(expected.value,
            "set() if kind == 'S' else {'SELECT'} if kind in {'r', 'p'} "
            "and name in runtime_read_only_tables else requested_table_privileges "
            "if kind in {'r', 'p'} else set()")
        source = ast.get_source_segment(self.db_source, checks[0])
        self.assertIn("actual_runtime_grants.get(name, set()) != expected", source)
        self.assertIn("exact_runtime_acl = False", source)
        rejecting = [node for node in ast.walk(self.seal) if isinstance(node, ast.If)
            and any(isinstance(item, ast.UnaryOp) and isinstance(item.op, ast.Not)
                and isinstance(item.operand, ast.Name) and item.operand.id == "exact_runtime_acl"
                for item in ast.walk(node.test))]
        self.assertEqual(len(rejecting), 1)
        self.assertTrue(any(isinstance(node, ast.Raise) for node in ast.walk(rejecting[0])))

    def test_runtime_effective_table_and_column_privileges_are_checked_before_owner_admission(self):
        function = named_function(self.db_tree, "_metadata_pg_connect_with_dsn")
        assignment = named_assignment(function, "invalid_protected_table_privilege", recursive=True)
        blocks = [node for node in ast.walk(function) if isinstance(node, ast.If)
            and ast.dump(node.test) == ast.dump(ast.parse("not admin", mode="eval").body)
            and assignment in node.body]
        self.assertEqual(len(blocks), 1)
        query = assignment.value.func.value
        self.assertIsInstance(query, ast.Call)
        self.assertIsInstance(query.func, ast.Attribute)
        self.assertEqual(query.func.attr, "execute")
        self.assertEqual(len(query.args), 2)
        self.assertIsInstance(query.args[0], ast.Constant)
        sql = query.args[0].value
        self.assert_shape(query.args[1],
            "(sorted(_POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES), _POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME)")
        for fragment in ("FROM pg_catalog.unnest(%s::text[])",
                "LEFT JOIN pg_catalog.pg_namespace AS namespace ON namespace.nspname = %s",
                "ON relation.relnamespace = namespace.oid AND relation.relname = required.table_name",
                "WHERE namespace.oid IS NULL OR relation.oid IS NULL",
                "relation.relkind NOT IN ('r', 'p')",
                "CASE WHEN relation.relkind IN ('r', 'p') THEN (",
                "pg_catalog.has_table_privilege(current_user, relation.oid, 'SELECT') IS NOT TRUE",
                "'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') IS NOT FALSE",
                "pg_catalog.has_any_column_privilege(current_user, relation.oid, 'INSERT,UPDATE,REFERENCES') IS NOT FALSE",
                ") ELSE FALSE END LIMIT 1"):
            self.assertIn(fragment, sql)
        owner = named_assignment(function, "live_owner_contract", recursive=True)
        self.assertLess(assignment.lineno, owner.lineno)
        index = blocks[0].body.index(assignment)
        denial = blocks[0].body[index + 1]
        self.assertIsInstance(denial, ast.If)
        self.assert_shape(denial.test, "invalid_protected_table_privilege is not None")
        self.assert_shape(denial.body[0].exc,
            "MetadataStoreError('runtime metadata protected-table privileges are not source exact')")
        self.assertLess(denial.end_lineno, owner.lineno)

    def test_default_detailed_schema_inventory_contains_the_same_twelve_tables(self):
        function = named_function(self.schema_tree, "_policy_candidate_authority_schema_tables")
        self.assertEqual(len(function.body), 1)
        self.assertIsInstance(function.body[0], ast.Return)
        self.assert_shape(function.body[0].value,
            "tuple(dict.fromkeys(_POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES + "
            "_POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES + authority_contract.V9_ADDITIONAL_PROTECTED_TABLES + "
            "('metadata_audit_outbox', 'rbac_authority_state', 'rbac_role_bindings')))")
        manifest = named_function(self.schema_tree, "_policy_candidate_authority_structure_manifest")
        selection = named_assignment(manifest, "selected_tables", recursive=True)
        self.assert_shape(selection.value, "tables or _policy_candidate_authority_schema_tables()")

    def test_source_contract_hash_binds_complete_readonly_and_additional_inventories(self):
        function = named_function(self.schema_tree, "_policy_candidate_authority_source_contract_digest")
        material = named_assignment(function, "material", recursive=True).value
        self.assertIsInstance(material, ast.Call)
        self.assertIsInstance(material.func, ast.Attribute)
        self.assertEqual(material.func.attr, "encode")
        self.assertEqual(len(material.args), 1)
        self.assert_shape(material.args[0], "'utf-8'")
        self.assertFalse(material.keywords)
        serialized = material.func.value
        self.assertTrue(call_named(serialized, "dumps"))
        self.assertEqual(len(serialized.args), 1)
        self.assertFalse(serialized.keywords)
        self.assertIsInstance(serialized.args[0], ast.Dict)
        entries = {key.value: value for key, value in zip(serialized.args[0].keys, serialized.args[0].values)
            if isinstance(key, ast.Constant) and type(key.value) is str}
        self.assert_shape(entries["authorityRuntimeReadOnlyTables"], "sorted(_POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES)")
        self.assert_shape(entries["v9AdditionalProtectedTables"], "list(authority_contract.V9_ADDITIONAL_PROTECTED_TABLES)")
        self.assert_shape(entries["jitAuthorityRuntimeReadOnlyTables"], "sorted(_JIT_AUTHORITY_RUNTIME_READ_ONLY_TABLES)")
        self.assert_shape(entries["immutableTables"], "list(_POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES)")
        self.assert_shape(entries["headTables"], "list(_POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES)")
        returned = [node for node in function.body if isinstance(node, ast.Return)]
        self.assertEqual(len(returned), 1)
        self.assert_shape(returned[0].value,
            "_policy_candidate_authority_framed_digest('serverware.policyCandidateAuthoritySourceContract/v1', material)")

    def test_executor_and_planner_direct_dml_allowlists_are_not_expanded(self):
        self.assert_shape(named_assignment(self.db_tree, "_POLICY_AUTHORITY_CONTROLLED_WRITER_TABLES").value,
            "frozenset()")
        value = named_assignment(self.db_tree, "_POLICY_AUTHORITY_PLANNER_WRITER_TABLE_PRIVILEGES").value
        self.assertTrue(call_named(value, "MappingProxyType"))
        self.assertIsInstance(value.args[0], ast.Dict)
        actual = {}
        for key, privileges in zip(value.args[0].keys, value.args[0].values):
            self.assertIsInstance(key, ast.Constant)
            self.assertTrue(call_named(privileges, "frozenset"))
            self.assertEqual(len(privileges.args), 1)
            self.assertIsInstance(privileges.args[0], ast.Set)
            actual[key.value] = {node.value for node in privileges.args[0].elts}
        self.assertEqual(actual, {
            "policy_authority_authorization_dependency_manifests": {"SELECT"},
            "policy_authority_authorization_projections": {"SELECT", "INSERT"},
            "policy_authority_execution_envelopes": {"SELECT", "INSERT", "UPDATE"},
            "policy_authority_fence_heads": {"SELECT"},
            "policy_authority_operation_mutation_templates": {"SELECT"},
            "policy_authority_planner_transactions": {"SELECT", "INSERT", "UPDATE"},
            "policy_authority_query_dependency_manifests": {"SELECT"},
            "policy_authority_authenticated_table_roots": {"SELECT"},
            "policy_authority_webauthn_assertion_evidence": {"SELECT", "INSERT"},
            "policy_authority_writer_capabilities": {"SELECT", "UPDATE"},
        })
        self.assertTrue(set(PHASE2).isdisjoint(actual))

    def test_source_revision_and_all_seventeen_v9_ddl_checks_are_pinned(self):
        self.assertEqual(authority_contract.SOURCE_REVISION,
            "serverware.policyCandidateAuthoritySource/2026-07-30.26")
        _, executor = read_source("serverware/authority_store/executor_v9.py", 2 * 1024 * 1024)
        self.assertFalse(any(isinstance(node, ast.FunctionDef)
            and node.name == "authority_v9_schema_source" for node in executor.body))
        aliases = [alias for node in executor.body if isinstance(node, ast.ImportFrom)
            and node.module == "serverware.authority_store.v9_schema_source"
            for alias in node.names]
        self.assertEqual([(alias.name, alias.asname) for alias in aliases],
            [("authority_v9_schema_source", None)])
        _, tree = read_source("serverware/authority_store/v9_schema_source.py", 2 * 1024 * 1024)
        function = named_function(tree, "authority_v9_schema_source")
        literals = [node.value for node in ast.walk(function)
            if isinstance(node, ast.Constant) and type(node.value) is str]
        self.assertEqual(sum(value.count(authority_contract.SOURCE_REVISION) for value in literals), 17)
        self.assertFalse(any("serverware.policyCandidateAuthoritySource/2026-07-30.25" in value for value in literals))


if __name__ == "__main__":
    unittest.main()
