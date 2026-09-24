#!/usr/bin/env python3
"""Source-only authority table ACL closure checks; no PostgreSQL proof.

Import only the real pure contract. Inspect bounded committed source ASTs,
never import db/schema, execute extracted functions, or replace the registry.
These controls cannot prove GRANT/REVOKE, effective role membership, column
privileges, catalog behavior, migrations or whole startup admission at runtime.
"""
from __future__ import annotations

import ast
import re
import sys
import unittest
from pathlib import Path
from types import MappingProxyType


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_query_read_work


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
COUNTED_COLUMNS = {
    "policy_authority_counted_index_heads": (
        "index_id", "table_name", "counted_profile", "projection_digest",
        "projection_manifest_digest", "index_revision", "root_digest", "leaf_count"),
    "policy_authority_counted_index_leaves": (
        "index_id", "projection_digest", "index_key", "primary_id",
        "primary_key_digest", "primary_row_digest", "index_revision"),
    "policy_authority_counted_index_nodes": (
        "index_id", "projection_digest", "depth", "path_prefix", "node_digest",
        "subtree_count", "index_revision"),
}
COUNTED_SIGNATURES = {
    "serverware_policy_authority_counted_profile": ("text",),
    "serverware_policy_authority_counted_frame_digest": ("text", "text[]"),
    "serverware_policy_authority_counted_empty": ("text", "text"),
    "serverware_policy_authority_counted_leaf": ("text", "text", "text", "text"),
    "serverware_policy_authority_counted_branch": ("text", "text", "text[]", "bigint[]"),
    "serverware_policy_authority_counted_expiry_micros": ("text",),
    "serverware_policy_authority_counted_signed_order": ("bigint",),
    "serverware_policy_authority_counted_field": ("jsonb", "text", "text"),
    "serverware_policy_authority_counted_project": ("text", "jsonb"),
    "serverware_policy_authority_counted_apply_index": ("text", "text", "jsonb", "jsonb"),
    "serverware_policy_authority_counted_apply_event": ("text", "text", "jsonb", "jsonb"),
}
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
        self.assertEqual(len(stars), 5)
        self.assertEqual({node.id for node in stars if isinstance(node, ast.Name)}, LEGACY_UNIONS)
        attributes = [node for node in stars if isinstance(node, ast.Attribute)]
        self.assertEqual(len(attributes), 2)
        self.assertEqual({ast.dump(node) for node in attributes}, {
            ast.dump(ast.parse(expression, mode="eval").body)
            for expression in ("authority_contract.V9_ADDITIONAL_PROTECTED_TABLES",
                               "authority_contract.POSTGRES_COUNTED_STORE_TABLES")
        })
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
        verifier_guard = self.seal.body[1]
        self.assertIsInstance(verifier_guard, ast.If)
        self.assert_shape(verifier_guard.test,
            "schema in {_POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME, 'serverware_candidate_authority_expected_v9'} "
            "and (type(authority_verifier_role) is not str "
            "or re.fullmatch('[a-z][a-z0-9_]{0,62}', authority_verifier_role) is None "
            "or authority_verifier_role != _METADATA_STORE_AUTHORITY_VERIFIER_ROLE "
            "or authority_verifier_role in {runtime_role, authority_executor_role, authority_owner_role, "
            "authority_capability_issuer_role, authority_planner_writer_role} "
            "or type(authority_verifier_read_tables) is not frozenset "
            "or authority_verifier_read_tables != _POLICY_AUTHORITY_VERIFIER_READ_TABLES)")
        self.assert_shape(verifier_guard.body[0].exc,
            "error_type('metadata verifier role/read closure is not source exact')")
        self.assertTrue(all(node.lineno > verifier_guard.end_lineno for node in cursor_calls))

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
            "(authority_contract.POSTGRES_COUNTED_STORE_TABLES if postgres else ()) + "
            "('metadata_audit_outbox', 'rbac_authority_state', 'rbac_role_bindings')))")
        self.assertEqual([argument.arg for argument in function.args.kwonlyargs], ["postgres"])
        self.assert_shape(function.args.kw_defaults[0], "False")
        manifest = named_function(self.schema_tree, "_policy_candidate_authority_structure_manifest")
        selection = named_assignment(manifest, "selected_tables", recursive=True)
        self.assert_shape(selection.value,
            "tables or _policy_candidate_authority_schema_tables(postgres=isinstance(conn, PostgresMetadataConnection))")

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
        self.assert_shape(entries["postgresCountedInstallation"],
            "counted_installation.counted_installation_contract()")
        self.assert_shape(entries["postgresCountedMaintenance"],
            "dict(authority_contract.POSTGRES_COUNTED_MAINTENANCE_CONTRACT)")
        self.assert_shape(entries["postgresCountedStoreColumns"],
            "{table: list(columns) for table, columns in authority_contract.POSTGRES_COUNTED_STORE_COLUMNS.items()}")
        self.assert_shape(entries["postgresCountedFunctionContracts"],
            "{name: {field: list(value) if isinstance(value, tuple) else value "
            "for field, value in contract.items()} for name, contract in "
            "authority_contract.POSTGRES_COUNTED_FUNCTION_CONTRACTS.items()}")
        returned = [node for node in function.body if isinstance(node, ast.Return)]
        self.assertEqual(len(returned), 1)
        self.assert_shape(returned[0].value,
            "_policy_candidate_authority_framed_digest('serverware.policyCandidateAuthoritySourceContract/v1', material)")

    def test_executor_and_planner_direct_dml_allowlists_are_not_expanded(self):
        self.assert_shape(named_assignment(self.db_tree, "_POLICY_AUTHORITY_CONTROLLED_WRITER_TABLES").value,
            "frozenset()")
        self.assert_shape(named_assignment(self.db_tree,
            "_POLICY_AUTHORITY_PLANNER_WRITER_TABLE_PRIVILEGES").value,
            "_authority_planner_writer_sql.PLANNER_WRITER_TABLE_PRIVILEGES")
        _, writer_tree = read_source("serverware/authority_store/planner_writer_sql.py", 128 * 1024)
        value = named_assignment(writer_tree, "PLANNER_WRITER_TABLE_PRIVILEGES").value
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
            "policy_authority_revocation_retained_plans": {"SELECT", "INSERT"},
            "policy_authority_revocation_writer_requests": {"SELECT", "INSERT"},
            "policy_authority_revocation_writer_acknowledgments": {"SELECT", "INSERT"},
            "policy_authority_query_dependency_manifests": {"SELECT"},
            "policy_authority_authenticated_table_roots": {"SELECT"},
            "policy_authority_webauthn_assertion_evidence": {"SELECT", "INSERT"},
            "policy_authority_writer_capabilities": {"SELECT", "UPDATE"},
        })
        self.assertTrue(set(PHASE2).isdisjoint(actual))

    def test_source_revision_and_all_seventeen_v9_ddl_checks_are_pinned(self):
        self.assertEqual(authority_contract.SOURCE_REVISION,
            "serverware.policyCandidateAuthoritySource/2026-07-30.82")
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
        # Preserve this historical method ID: .37 added the eighteenth check;
        # .45 adds retained capability's nineteenth; .65/.67 add request/ACK custody.
        self.assertEqual(sum(value.count(authority_contract.SOURCE_REVISION) for value in literals), 21)
        self.assertFalse(any("serverware.policyCandidateAuthoritySource/2026-07-30.26" in value for value in literals))

    def test_planner_query_bookkeeping_contract_binds_narrow_cumulative_limits(self):
        contract = authority_contract.PLANNER_QUERY_BOOKKEEPING_CONTRACT
        self.assertIs(type(contract), MappingProxyType)
        self.assertEqual(dict(contract), {
            "schema": "serverware.policyAuthorityPlannerQueryBookkeeping/v1",
            "allocation": "once-per-typed-derive",
            "maxHashes": 8_000_000, "maxInputBytes": 64 * 1024 * 1024,
            "maxJsonNodes": 1_000_000, "maxJsonDepth": 128,
            "includedPhases": (
                "snapshot", "reference-sources", "resolve", "capture", "prefix-budget",
                "end-of-read-validation", "post-primary-validation",
            ),
            "excludedWork": (
                "sql-acquisition", "primary-proof-verification", "staging-cache-stamps",
                "kernel", "range-and-mutation-proofs", "whole-plan",
            ),
        })
        with self.assertRaises(TypeError):
            contract["maxHashes"] = 1
        limits = authority_query_read_work.QueryReadValidationLimits()
        self.assertEqual((limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes,
                          authority_query_read_work.MAX_JSON_DEPTH),
                         (contract["maxHashes"], contract["maxInputBytes"],
                          contract["maxJsonNodes"], contract["maxJsonDepth"]))
        _, tree = read_source("serverware/authority_contract.py", 2 * 1024 * 1024)
        material = named_assignment(tree, "OPERATION_MANIFEST_DIGEST").value.args[1]
        fields = {key.value: value for key, value in zip(material.keys, material.values)}
        self.assert_shape(fields["plannerQueryBookkeeping"], "dict(PLANNER_QUERY_BOOKKEEPING_CONTRACT)")
        source_contract = named_function(self.schema_tree, "_policy_candidate_authority_source_contract_digest")
        serialized = named_assignment(source_contract, "material", recursive=True).value.func.value.args[0]
        source_fields = {key.value: value for key, value in zip(serialized.keys, serialized.values)
                         if isinstance(key, ast.Constant) and type(key.value) is str}
        self.assert_shape(source_fields["operationContractDigest"], "authority_contract.OPERATION_MANIFEST_DIGEST")
        self.assertEqual(authority_contract.SCHEMA_VERSION, 9)
        self.assertEqual(authority_contract.CONTRACT_SCHEMA, "serverware.policyAuthorityOperationContract/v3")
        self.assertEqual(authority_contract.MAX_PLAN_WORK_UNITS, 16386)

    def test_private_complete_acquisition_contract_binds_actual_limits_and_excludes_public_v3(self):
        contract = authority_contract.PLANNER_COMPLETE_ACQUISITION_CONTRACT
        self.assertIs(type(contract), MappingProxyType)
        self.assertEqual(dict(contract), {
            "schema": "serverware.policyAuthorityPlannerCompleteAcquisition/v1",
            "admission": "private-worker-only", "publicV3Enabled": False,
            "operation": "webauthn.credential.revoke",
            "producerReadPhase": "single-cutoff-source-program/v1",
            "producerAcquisitionPhase": "single-ledger-read-effects-write/v1",
            "retainedPrimaryEvidence": "detached-original-roots-and-proofs/v1",
            "headTraceProfile": "serverware.policyAuthorityCountedHeadRead/v1",
            "rangeTraceProfile": "serverware.policyAuthorityCountedIndexRead/v1",
            "primaryTraceProfile": "serverware.policyAuthorityCompletePrimaryRead/v1",
            "mutationTraceProfile": "serverware.policyAuthorityCountedIndexMutationRead/v1",
            "maxSqlReads": 4096, "maxParameterBytes": 4 * 1024 * 1024,
            "maxReturnedFrameBytes": 4 * 1024 * 1024,
            "maxPrimaryRowBytes": 1024 * 1024, "maxRangeSqlReads": 20,
            "maxSharedHashes": 8_000_000, "maxSharedInputBytes": 64 * 1024 * 1024,
            "maxSharedJsonNodes": 1_000_000,
            "maxBusinessTraceEntries": 4096, "maxFrameworkTraceEntries": 69,
            "includedPhases": (
                "owned-producer-context", "request-and-operation-binding",
                "assertion-receipt-verification",
                "owned-read-phase-context", "single-cutoff-source-query-generation",
                "source-role-and-cutoff-binding", "counted-head-capture",
                "range-acquisition-and-reconstruction", "exact-primary-row-fetch",
                "raw-evidence-retention", "global-primary-and-range-row-reverification",
                "shared-query-bookkeeping", "detached-root-and-primary-proof-retention",
                "actual-kernel-and-capacity-effects", "ordered-mutation-copy",
                "write-frontier-acquisition", "indexed-primary-and-sparse-write-proofs",
                "shared-physical-acquisition",
            ),
            "excludedWork": (
                "sql-execution", "driver-allocation", "process-allocation",
                "staged-proof-work", "staging-cache-stamps", "primary-proof-acquisition",
                "trace-serialization", "fixed-metadata-scaffolding", "indexed-projection-allocation",
                "retained-protocol", "whole-plan",
            ),
        })
        self.assertIs(contract["publicV3Enabled"], False)
        with self.assertRaises(TypeError):
            contract["publicV3Enabled"] = True
        _, tree = read_source("serverware/authority_contract.py", 2 * 1024 * 1024)
        material = named_assignment(tree, "OPERATION_MANIFEST_DIGEST").value.args[1]
        fields = {key.value: value for key, value in zip(material.keys, material.values)}
        self.assert_shape(fields["plannerCompleteAcquisition"], "dict(PLANNER_COMPLETE_ACQUISITION_CONTRACT)")
        # Keep the contract importable below the actual reader/head/trace
        # modules. Their literal profiles are bound by source below, not eager
        # imports back into their own contract dependency.
        imports = {alias.name for node in tree.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware" for alias in node.names}
        self.assertTrue({"authority_index_heads", "authority_index_reader", "authority_index_trace",
                         "authority_complete_acquisition"}.isdisjoint(imports))
        sources = {}
        for name in ("authority_index_heads", "authority_index_reader", "authority_index_trace",
                     "authority_complete_query", "authority_audit_trace", "authority_complete_acquisition",
                     "authority_index_mutation_reader"):
            _, sources[name] = read_source(f"serverware/{name}.py", 256 * 1024)
        for module, constant, field in (
            ("authority_index_heads", "READ_PROFILE", "headTraceProfile"),
            ("authority_index_reader", "READ_PROFILE", "rangeTraceProfile"),
            ("authority_index_trace", "PRIMARY_READ_PROFILE", "primaryTraceProfile"),
            ("authority_index_mutation_reader", "READ_PROFILE", "mutationTraceProfile"),
            ("authority_complete_query", "OPERATION", "operation"),
            ("authority_audit_trace", "MAX_TRACE_ENTRIES", "maxBusinessTraceEntries"),
            ("authority_audit_trace", "MAX_AUDIT_CAPACITY_TRACE_ENTRIES", "maxFrameworkTraceEntries"),
        ):
            self.assert_shape(named_assignment(sources[module], constant).value, repr(contract[field]))
        reader = sources["authority_index_reader"]
        for constant, expression in (
            ("MAX_CUMULATIVE_SQL_READS", "4096"), ("MAX_PARAMETER_BYTES", "4 * 1024 * 1024"),
            ("MAX_TRANSPORT_BYTES", "4 * 1024 * 1024"), ("MAX_PRIMARY_ROW_BYTES", "1024 * 1024"),
            ("MAX_NODE_IDENTITIES", "256"),
            ("MAX_SQL_READS", "1 + (MAX_OUTSIDE_PREFIXES + MAX_NODE_IDENTITIES - 1) // MAX_NODE_IDENTITIES"),
        ):
            self.assert_shape(named_assignment(reader, constant).value, expression)
        _, frontier = read_source("serverware/authority_index_frontier.py", 128 * 1024)
        self.assert_shape(named_assignment(frontier, "MAX_OUTSIDE_PREFIXES").value,
                          "2 * KEY_NIBBLES * 15")
        self.assertEqual(contract["maxRangeSqlReads"], 1 + (4800 + 255) // 256)
        limits = authority_query_read_work.QueryReadValidationLimits()
        self.assertEqual((contract["maxSharedHashes"], contract["maxSharedInputBytes"], contract["maxSharedJsonNodes"]),
                         (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes))
        self.assert_shape(named_assignment(sources["authority_audit_trace"], "MAX_PLAN_TRACE_ENTRIES").value,
                          "MAX_TRACE_ENTRIES + MAX_AUDIT_CAPACITY_TRACE_ENTRIES")
        collector_calls = {node.func.attr for node in ast.walk(sources["authority_complete_acquisition"])
                           if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertTrue({"read_operation_index_heads", "_read_complete_frontier", "charge_primary_row",
                         "_verify_complete_query_batch"}.issubset(collector_calls))
        # These are source linkage assertions, not executed SQL/proof or a new
        # measured envelope. Schema9, operation-contract/v3 and business units
        # are unchanged; the old bookkeeping descriptor has its own full pin.
        self.assertEqual(authority_contract.SCHEMA_VERSION, 9)
        self.assertEqual(authority_contract.CONTRACT_SCHEMA, "serverware.policyAuthorityOperationContract/v3")
        self.assertEqual(authority_contract.MAX_PLAN_WORK_UNITS, 16386)

    def test_signed_revocation_verifier_contract_pins_private_v4_without_production_admission(self):
        contract = authority_contract.SIGNED_REVOCATION_PLAN_CONTRACT
        self.assertIs(type(contract), MappingProxyType)
        self.assertEqual(dict(contract), {
            "schema": "serverware.policyAuthoritySignedRevocationPlanVerification/v1",
            "admission": "private-verifier-only", "operation": "webauthn.credential.revoke",
            "publicV3Enabled": False, "productionV4Enabled": False,
            "responseSchema": "serverware.policyAuthorityPlannerResponse/v4",
            "measuredPlanSchema": "serverware.policyAuthorityMeasuredPlan/v4",
            "signedPlanSchema": "serverware.signedPolicyAuthorityMeasuredPlan/v4",
            "snapshotDomain": "serverware.policyAuthoritySnapshot/v4",
            "writerTraceBinding": "exact-contiguous-source-batches-before-writes/v1",
            "maxPayloadBytes": 64 * 1024 * 1024, "maxSharedHashes": 8_000_000,
            "maxSharedInputBytes": 64 * 1024 * 1024, "maxSharedJsonNodes": 1_000_000,
            "maxJsonDepth": 128,
            "includedPhases": (
                "joint-envelope-and-expectation-capture", "full-transport-encoding",
                "planner-signature", "assertion-receipt-signature", "source-query-closure",
                "primary-and-complete-range-proofs", "actual-kernel-and-capacity-effects",
                "authorization-source-binding", "snapshot-and-result-commitments",
                "source-bound-trace-consistency",
                "mutation-writer-target-geometry", "exact-mutation-writer-trace",
            ),
            "excludedWork": (
                "indexed-projection-allocation", "fixed-metadata-scaffolding", "whole-plan",
            ),
            "excludedAuthority": (
                "key-and-identity-enrollment", "before-root-and-cutoff-currentness",
                "capability-reservation", "one-use-persistence", "sql-commit",
                "registry-admission", "terminal-witness",
            ),
        })
        with self.assertRaises(TypeError):
            contract["productionV4Enabled"] = True
        _, tree = read_source("serverware/authority_contract.py", 2 * 1024 * 1024)
        material = named_assignment(tree, "OPERATION_MANIFEST_DIGEST").value.args[1]
        fields = {key.value: value for key, value in zip(material.keys, material.values)}
        self.assert_shape(fields["signedRevocationPlanVerification"], "dict(SIGNED_REVOCATION_PLAN_CONTRACT)")
        imports = {alias.name for node in tree.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware" for alias in node.names}
        self.assertTrue({"authority_revocation_plan", "authority_revocation_plan_contract"}.isdisjoint(imports))
        _, shape = read_source("serverware/authority_revocation_plan_contract.py", 128 * 1024)
        for constant, field in (("PLANNER_RESPONSE_SCHEMA", "responseSchema"),
                                ("MEASURED_PLAN_SCHEMA", "measuredPlanSchema"),
                                ("SIGNED_MEASURED_PLAN_SCHEMA", "signedPlanSchema"),
                                ("SNAPSHOT_DOMAIN", "snapshotDomain")):
            self.assert_shape(named_assignment(shape, constant).value, repr(contract[field]))
        for constant, expression in (("MAX_PAYLOAD_BYTES", "64 * 1024 * 1024"),
                                      ("MAX_JSON_NODES", "1_000_000"), ("MAX_JSON_DEPTH", "128")):
            self.assert_shape(named_assignment(shape, constant).value, expression)
        _, verifier = read_source("serverware/authority_revocation_plan.py", 128 * 1024)
        calls = {node.func.attr for node in ast.walk(verifier)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
        self.assertTrue({"_JSONCapture", "_PackagingLedger", "_verify",
                         "derive_authorization_sources", "verify"}.issubset(calls))
        # Source linkage and closed shapes are not runtime or enrollment proof.
        self.assertEqual(authority_contract.SCHEMA_VERSION, 9)
        self.assertEqual(authority_contract.CONTRACT_SCHEMA, "serverware.policyAuthorityOperationContract/v3")

    def test_original_signed_wire_contract_is_private_source_bound_and_immutable(self):
        contract = authority_contract.SIGNED_REVOCATION_WIRE_CONTRACT
        self.assertIs(type(contract), MappingProxyType)
        self.assertEqual(dict(contract), {
            "schema": "serverware.policyAuthoritySignedRevocationWireAdmission/v1",
            "admission": "private-wire-verifier-only", "operation": "webauthn.credential.revoke",
            "publicV3Enabled": False, "productionV4Enabled": False,
            "inputEncoding": "canonical-ascii-json/v1",
            "workOwnership": "existing-invocation-remaining-allowance/v1",
            "decoderByteReservation": "four-times-original-byte-count/v1",
            "decoderNodeReservation": "tokens-plus-objects-plus-two-members/v1",
            "canonicalComparison": "actual-transport-encoder-before-signature/v1",
            "maxPayloadBytes": 64 * 1024 * 1024, "maxSharedHashes": 8_000_000,
            "maxSharedInputBytes": 64 * 1024 * 1024, "maxSharedJsonNodes": 1_000_000,
            "maxJsonDepth": 128, "maxIntegerBits": 16384,
            "includedPhases": (
                "raw-lexical-preflight", "ascii-decode", "strict-json-parse",
                "duplicate-and-integer-callback-reservation",
                "joint-envelope-and-independent-expectation-capture",
                "original-canonical-wire-comparison", "signature-callback-meter-stability",
                "genuine-signed-semantic-verification",
            ),
            "excludedWork": (
                "transport-buffer-acquisition", "indexed-projection-allocation",
                "fixed-metadata-scaffolding", "whole-process-memory", "whole-plan",
            ),
            "excludedAuthority": (
                "key-and-identity-enrollment", "before-root-and-cutoff-currentness",
                "capability-reservation", "one-use-persistence", "sql-commit",
                "registry-admission", "terminal-witness",
            ),
        })
        with self.assertRaises(TypeError):
            contract["productionV4Enabled"] = True
        _, tree = read_source("serverware/authority_contract.py", 2 * 1024 * 1024)
        material = named_assignment(tree, "OPERATION_MANIFEST_DIGEST").value.args[1]
        fields = {key.value: value for key, value in zip(material.keys, material.values)}
        self.assert_shape(fields["signedRevocationWireAdmission"], "dict(SIGNED_REVOCATION_WIRE_CONTRACT)")
        imports = {alias.name for node in tree.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware" for alias in node.names}
        self.assertTrue({"authority_revocation_wire", "authority_revocation_plan"}.isdisjoint(imports))
        limits = authority_query_read_work.QueryReadValidationLimits()
        self.assertEqual((contract["maxSharedHashes"], contract["maxSharedInputBytes"],
                          contract["maxSharedJsonNodes"], contract["maxJsonDepth"]),
                         (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes,
                          authority_query_read_work.MAX_JSON_DEPTH))
        self.assertEqual(authority_contract.SCHEMA_VERSION, 9)
        self.assertEqual(authority_contract.CONTRACT_SCHEMA, "serverware.policyAuthorityOperationContract/v3")

    def test_private_signed_production_contract_binds_shared_replay_and_precharged_transport(self):
        contract = authority_contract.SIGNED_REVOCATION_PRODUCTION_CONTRACT
        self.assertIs(type(contract), MappingProxyType)
        self.assertEqual(dict(contract), {
            "schema": "serverware.policyAuthoritySignedRevocationPlanProduction/v1",
            "admission": "private-producer-only", "operation": "webauthn.credential.revoke",
            "publicV3Enabled": False, "productionV4Enabled": False,
            "proofPackaging": "genuine-mixed-replay-on-original-work/v1",
            "transportReservation": "measured-payload-and-envelope-before-signing/v1",
            "contextSchema": "serverware.policyAuthorityRevocationEvaluationContext/v1",
            "maxContextBytes": 512 * 1024, "maxContextNodes": 4096, "maxContextDepth": 8,
            "maxPayloadBytes": 64 * 1024 * 1024, "maxSharedHashes": 8_000_000,
            "maxSharedInputBytes": 64 * 1024 * 1024, "maxSharedJsonNodes": 1_000_000,
            "maxJsonDepth": 128,
            "includedPhases": (
                "joint-request-evidence-context-capture", "reservation-context-binding",
                "actual-root-read-binding",
                "single-cutoff-read-effects-write-acquisition", "independent-before-vector-binding",
                "raw-proof-normalization", "genuine-mixed-proof-replay", "compact-proof-packaging",
                "original-evaluation-context-encoding",
                "source-authorization-and-plan-commitments", "exact-outer-transport-preflight",
                "planner-signature", "paired-public-key-verification",
                "post-sign-payload-and-meter-stability", "original-envelope-encoding",
            ),
            "excludedWork": (
                "sql-execution", "driver-allocation", "process-allocation",
                "staged-proof-work", "staging-cache-stamps", "primary-proof-acquisition",
                "acquisition-trace-serialization", "indexed-projection-allocation",
                "fixed-metadata-scaffolding", "whole-plan",
            ),
            "excludedAuthority": (
                "key-and-identity-enrollment", "read-only-transaction-ownership",
                "before-root-and-cutoff-currentness", "capability-reservation",
                "one-use-persistence", "sql-commit", "registry-admission", "terminal-witness",
            ),
        })
        with self.assertRaises(TypeError):
            contract["productionV4Enabled"] = True
        _, tree = read_source("serverware/authority_contract.py", 2 * 1024 * 1024)
        material = named_assignment(tree, "OPERATION_MANIFEST_DIGEST").value.args[1]
        fields = {key.value: value for key, value in zip(material.keys, material.values)}
        self.assert_shape(fields["signedRevocationPlanProduction"],
                          "dict(SIGNED_REVOCATION_PRODUCTION_CONTRACT)")
        imports = {alias.name for node in tree.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware" for alias in node.names}
        self.assertTrue({"authority_planner", "authority_revocation_plan_production",
                         "authority_revocation_proof_bundle"}.isdisjoint(imports))
        limits = authority_query_read_work.QueryReadValidationLimits()
        self.assertEqual((contract["maxSharedHashes"], contract["maxSharedInputBytes"],
                          contract["maxSharedJsonNodes"]),
                         (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes))
        self.assertEqual(authority_contract.SCHEMA_VERSION, 9)
        self.assertEqual(authority_contract.CONTRACT_SCHEMA, "serverware.policyAuthorityOperationContract/v3")

    def test_retained_record_contract_binds_private_postgres_storage_and_exact_fields(self):
        columns = ("planner_transaction_id", "plan_protocol", "exact_envelope_base64url",
            "exact_envelope_bytes_digest", "exact_envelope_byte_count", "evaluation_context_base64url",
            "evaluation_context_bytes_digest", "evaluation_context_byte_count", "planner_key_digest",
            "verifier_key_digest", "retained_record_digest", "source_revision")
        reservation = ("planner_transaction_id", "plan_protocol", "operation", "operation_id", "request_digest",
            "capability_id", "operation_contract_digest", "query_manifest_digest", "selected_business_rows_json",
            "selected_business_rows_digest", "mutation_plan_json", "mutation_plan_digest", "work_units",
            "authority_root_set_before_digest", "planner_session_identity_digest", "planner_measurement_digest",
            "planner_attestation_receipt_digest", "deadline_monotonic_ns", "deadline_epoch_ns", "fence",
            "reserved_at_epoch_ns", "source_revision")
        payload = ("authorization_projection_digest", "authority_snapshot_digest", "exact_plan_base64url",
            "exact_plan_bytes_digest", "exact_plan_byte_count", "planned_at_epoch_ns", "retained_record_digest")
        terminal = ("status", "exact_response_base64url", "exact_response_bytes_digest", "exact_response_byte_count",
            "terminal_receipt_json", "terminal_receipt_digest", "terminal_at_epoch_ns")
        self.assertEqual(authority_contract.REVOCATION_RETAINED_COLUMNS, columns)
        self.assertEqual(authority_contract.PLANNER_RESERVATION_IMMUTABLE_COLUMNS, reservation)
        self.assertEqual(authority_contract.PLANNER_PAYLOAD_IMMUTABLE_COLUMNS, payload)
        self.assertEqual(authority_contract.PLANNER_TERMINAL_IMMUTABLE_COLUMNS, terminal)
        contract = authority_contract.REVOCATION_RETENTION_CONTRACT
        self.assertIs(type(contract), MappingProxyType)
        self.assertEqual(dict(contract), {
            "schema": "serverware.policyAuthorityRevocationRetention/v1",
            "operation": "webauthn.credential.revoke", "planProtocol": "revocation-v4",
            "publicExecutionEnabled": False, "postgresOnly": True, "sqliteAdmission": False,
            "retainedTable": "policy_authority_revocation_retained_plans", "retainedColumns": columns,
            "reservationImmutableColumns": reservation, "payloadImmutableColumns": payload,
            "terminalImmutableColumns": terminal,
            "recordSchema": "serverware.policyAuthorityRevocationRetainedPlan/v1",
            "contextSchema": "serverware.policyAuthorityRevocationEvaluationContext/v1",
            "contextFields": 18, "recordHeaderFields": 13, "maxEnvelopeBytes": 67108864,
            "maxContextBytes": 524288, "maxContextNodes": 4096, "maxContextDepth": 8,
            "parentBinding": "symmetric-deferred-composite-foreign-keys",
            "plannerPrivileges": ("SELECT", "INSERT"), "executorPrivileges": ("SELECT",),
            "legacyReplay": "explicit-v3-null-retained-digest-only",
            "existingStoreMigration": "separately-reviewed-no-synthesis-or-cascade",
            "authorityExclusions": ("stored-context", "key-enrollment", "currentness", "execution", "witness"),
        })
        with self.assertRaises(TypeError):
            contract["publicExecutionEnabled"] = True
        _, tree = read_source("serverware/authority_contract.py", 2 * 1024 * 1024)
        material = named_assignment(tree, "OPERATION_MANIFEST_DIGEST").value.args[1]
        fields = {key.value: value for key, value in zip(material.keys, material.values)}
        self.assert_shape(fields["revocationRetention"], "dict(REVOCATION_RETENTION_CONTRACT)")

    def test_retained_sidecar_is_immutable_planner_insert_only_and_revoke_executor_read_only(self):
        table = "policy_authority_revocation_retained_plans"
        immutable = named_assignment(self.db_tree, "_POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES").value
        self.assertEqual(sum(node.value == table for node in immutable.elts), 1)
        for name in ("_POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES", "_POLICY_CANDIDATE_AUTHORITY_REPLACEABLE_TABLES"):
            self.assertNotIn(table, [node.value for node in named_assignment(self.db_tree, name).value.elts])
        self.assertIn(table, authority_contract._FRAMEWORK_CUSTODY_TABLES)
        for operation, spec in authority_contract.OPERATIONS.items():
            for field in ("businessReads", "businessWrites", "authorizationReads", "frameworkWrites",
                          "frameworkReadBeforeWrite"):
                self.assertNotIn(table, spec[field])
            self.assertEqual(table in spec["frameworkPreconditions"], operation == "webauthn.credential.revoke")
        for operation, grants in authority_contract.SQL_GRANT_MANIFEST.items():
            self.assertNotIn(table, grants["frameworkMutate"])
            self.assertEqual(table in grants["frameworkSelect"], operation == "webauthn.credential.revoke")
        installer = named_function(self.db_tree, "_install_policy_candidate_authority_guards")
        text = ast.get_source_segment(self.db_source, installer)
        self.assertIn("BEFORE UPDATE OR DELETE ON {table}", text)
        self.assertIn("serverware_reject_policy_authority_mutation()", text)
        for function in ("_legacy_migrate_policy_candidate_authority_offline", "_prepare_policy_candidate_authority_schema"):
            source = ast.get_source_segment(self.db_source, named_function(self.db_tree, function))
            guard = source.index("_metadata_table_exists(conn, authority_contract.REVOCATION_RETAINED_TABLE)")
            self.assertLess(guard, source.index('"DROP TABLE "', guard))
            self.assertIn("retained revocation storage requires a separately reviewed migration", source)
        # Sidecar cannot become a phantom required table in an admitted v8 source.
        _, migration = read_source("scripts/authority/migrate_v8_to_v9.py", 2 * 1024 * 1024)
        new_tables = named_assignment(migration, "_V9_NEW_TABLES").value.args[0]
        self.assertIn(table, [node.value for node in new_tables.elts])

    def test_writer_request_contract_and_complete_ddl_bind_global_original_custody(self):
        columns = (
            "intent_envelope_id", "relay_envelope_id", "execution_envelope_id",
            "planner_transaction_id", "plan_protocol", "retained_record_digest",
            "configuration_digest", "generation_sequence", "generation_digest",
            "exact_intent_base64url", "exact_intent_bytes_digest", "exact_intent_byte_count",
            "exact_relay_base64url", "exact_relay_bytes_digest", "exact_relay_byte_count",
            "historical_expectations_base64url", "historical_expectations_bytes_digest",
            "historical_expectations_byte_count", "planner_key_digest", "verifier_key_digest",
            "planned_at_epoch_ns", "source_revision",
        )
        table = "policy_authority_revocation_writer_requests"
        self.assertEqual(authority_contract.REVOCATION_WRITER_REQUEST_TABLE, table)
        self.assertEqual(authority_contract.REVOCATION_WRITER_REQUEST_COLUMNS, columns)
        contract = authority_contract.REVOCATION_WRITER_REQUEST_CUSTODY_CONTRACT
        self.assertIs(type(contract), MappingProxyType)
        self.assertEqual(dict(contract), {
            "schema": "serverware.policyAuthorityRevocationWriterRequestCustody/v1",
            "operation": "webauthn.credential.revoke", "planProtocol": "revocation-v4",
            "postgresOnly": True, "sqliteAdmission": False, "publicExecutionEnabled": False,
            "requestTable": table, "requestColumns": columns,
            "primaryKey": ("intent_envelope_id",),
            "uniqueKeys": (("relay_envelope_id",), ("execution_envelope_id",),
                           ("intent_envelope_id", "configuration_digest", "generation_sequence",
                            "generation_digest", "source_revision")),
            "identityScope": "global-across-configuration-generation-and-key-rotations",
            "plannerBinding": "deferred-retained-plan-composite-foreign-key",
            "executionBinding": "deferred-execution-and-planner-composite-foreign-key",
            "maxControlBytes": 4194304, "maxHistoricalExpectationsBytes": 67108864,
            "planAndContextStorage": "existing-retained-plan-sidecar",
            "plannedAtBinding": "exact-original-stored-plan-time",
            "plannerPrivileges": ("SELECT", "INSERT"),
            "existingStoreMigration": "separately-reviewed-no-synthesis-or-cascade",
            "authorityExclusions": ("acknowledgement", "signature-verification", "key-enrollment",
                                    "currentness", "semantic-replay", "execution", "witness"),
        })
        with self.assertRaises(TypeError):
            contract["publicExecutionEnabled"] = True
        _, ddl_tree = read_source("serverware/authority_store/v9_schema_source.py", 2 * 1024 * 1024)
        ddl = named_function(ddl_tree, "authority_v9_schema_source").body[0].value.value
        start = ddl.index(table + " (")
        request = ddl[start:ddl.index("\n            );", start)]
        declarations = re.findall(r"^                ([a-z_]+) (TEXT|BIGINT) (.+),$", request, re.M)
        self.assertEqual(tuple(name for name, _, _ in declarations), columns)
        self.assertTrue(all("NOT NULL" in suffix or suffix == "PRIMARY KEY"
                            for _, _, suffix in declarations))
        self.assertIn("intent_envelope_id TEXT PRIMARY KEY", request)
        self.assertIn("relay_envelope_id TEXT NOT NULL UNIQUE", request)
        self.assertIn("execution_envelope_id TEXT NOT NULL UNIQUE", request)
        self.assertEqual(request.count("DEFERRABLE INITIALLY DEFERRED"), 2)
        compact = " ".join(request.split())
        self.assertIn("FOREIGN KEY (planner_transaction_id, plan_protocol, retained_record_digest) "
            "REFERENCES policy_authority_revocation_retained_plans "
            "(planner_transaction_id, plan_protocol, retained_record_digest)", compact)
        self.assertIn("FOREIGN KEY (execution_envelope_id, planner_transaction_id) "
            "REFERENCES policy_authority_execution_envelopes (envelope_id, planner_transaction_id)", compact)
        self.assertIn("UNIQUE (envelope_id, planner_transaction_id)", ddl[:start])
        self.assertIn("UNIQUE (intent_envelope_id, configuration_digest, generation_sequence, "
                      "generation_digest, source_revision)", compact)
        for field in ("intent_envelope_id", "relay_envelope_id", "execution_envelope_id",
                      "planner_transaction_id", *[name for name in columns if name.endswith("_digest")]):
            self.assertIn("CHECK (" + field + " ~ '^sha256:[0-9a-f]{64}$')", request)
        for prefix, maximum in (("exact_intent", 4194304), ("exact_relay", 4194304),
                                ("historical_expectations", 67108864)):
            self.assertIn(f"CHECK ({prefix}_byte_count BETWEEN 2 AND {maximum})", request)
            self.assertIn(f"length({prefix}_base64url) = (4 * {prefix}_byte_count + 2) / 3", request)
            self.assertIn(f"{prefix}_base64url ~ '^[A-Za-z0-9_-]+$'", request)
            self.assertIn(f"{prefix}_byte_count % 3 = 1", request)
            self.assertIn(f"{prefix}_byte_count % 3 = 2", request)
        self.assertIn("CHECK (plan_protocol = 'revocation-v4')", request)
        self.assertIn("CHECK (generation_sequence > 0 AND planned_at_epoch_ns > 0)", request)
        self.assertIn("CHECK (source_revision = '" + authority_contract.SOURCE_REVISION + "')", request)
        self.assertNotIn("exact_envelope_base64url", request)
        self.assertNotIn("evaluation_context_base64url", request)

    def test_writer_request_storage_is_immutable_framework_only_and_migration_closed(self):
        table = "policy_authority_revocation_writer_requests"
        immutable = named_assignment(self.db_tree, "_POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES").value
        self.assertEqual(sum(node.value == table for node in immutable.elts), 1)
        for name in ("_POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES", "_POLICY_CANDIDATE_AUTHORITY_REPLACEABLE_TABLES"):
            self.assertNotIn(table, [node.value for node in named_assignment(self.db_tree, name).value.elts])
        self.assertIn(table, authority_contract._FRAMEWORK_CUSTODY_TABLES)
        for spec in authority_contract.OPERATIONS.values():
            for field in ("businessReads", "businessWrites", "authorizationReads", "frameworkWrites",
                          "frameworkReadBeforeWrite", "frameworkPreconditions"):
                self.assertNotIn(table, spec[field])
        for grants in authority_contract.SQL_GRANT_MANIFEST.values():
            self.assertNotIn(table, grants["frameworkSelect"])
            self.assertNotIn(table, grants["frameworkMutate"])
        for function in ("_legacy_migrate_policy_candidate_authority_offline", "_prepare_policy_candidate_authority_schema"):
            source = ast.get_source_segment(self.db_source, named_function(self.db_tree, function))
            guard = source.index("_metadata_table_exists(conn, authority_contract.REVOCATION_WRITER_REQUEST_TABLE)")
            self.assertLess(guard, source.index('"DROP TABLE "', guard))
        _, migration = read_source("scripts/authority/migrate_v8_to_v9.py", 2 * 1024 * 1024)
        self.assertIn(table, [node.value for node in
            named_assignment(migration, "_V9_NEW_TABLES").value.args[0].elts])
        source, tree = read_source("serverware/authority_store/v9_schema_source.py", 2 * 1024 * 1024)
        sqlite = ast.get_source_segment(source, named_function(tree, "planner_retention_sqlite_guards_sql"))
        self.assertIn("BEFORE INSERT ON " + table, sqlite)
        self.assertIn("SQLite writer request custody is disabled", sqlite)
        self.assertIn('"serverware_writer_request_sqlite_insert_guard"', self.schema_source)
        _, contract_tree = read_source("serverware/authority_contract.py", 2 * 1024 * 1024)
        material = named_assignment(contract_tree, "OPERATION_MANIFEST_DIGEST").value.args[1]
        fields = {key.value: value for key, value in zip(material.keys, material.values)}
        self.assert_shape(fields["revocationWriterRequestCustody"], "dict(REVOCATION_WRITER_REQUEST_CUSTODY_CONTRACT)")
        self.assertIn('"revocationWriterRequestCustody": dict(authority_contract.REVOCATION_WRITER_REQUEST_CUSTODY_CONTRACT)', self.schema_source)

    def test_writer_ack_contract_and_ddl_bind_one_global_original_to_exact_request_scope(self):
        columns = ("ack_envelope_id", "intent_envelope_id", "configuration_digest",
            "generation_sequence", "generation_digest", "writer_response_spki_digest",
            "exact_ack_base64url", "exact_ack_bytes_digest", "exact_ack_byte_count", "source_revision")
        scope = ("intent_envelope_id", "configuration_digest", "generation_sequence",
                 "generation_digest", "source_revision")
        table = "policy_authority_revocation_writer_acknowledgments"
        self.assertEqual(authority_contract.REVOCATION_WRITER_ACK_TABLE, table)
        self.assertEqual(authority_contract.REVOCATION_WRITER_ACK_COLUMNS, columns)
        contract = authority_contract.REVOCATION_WRITER_ACK_CUSTODY_CONTRACT
        self.assertIs(type(contract), MappingProxyType)
        self.assertEqual(dict(contract), {
            "schema": "serverware.policyAuthorityRevocationWriterAckCustody/v1",
            "operation": "webauthn.credential.revoke", "planProtocol": "revocation-v4",
            "postgresOnly": True, "sqliteAdmission": False, "publicExecutionEnabled": False,
            "ackTable": table, "ackColumns": columns, "primaryKey": ("ack_envelope_id",),
            "uniqueKeys": (("intent_envelope_id",),),
            "identityScope": "global-across-configuration-generation-and-key-rotations",
            "requestBinding": scope, "requestForeignKey": "deferred-no-action-composite-foreign-key",
            "maxAckBytes": 16384, "plannerPrivileges": ("SELECT", "INSERT"),
            "existingStoreMigration": "separately-reviewed-no-synthesis-or-cascade",
            "authorityExclusions": ("signature-verification", "commit-completion", "key-enrollment",
                "currentness", "semantic-replay", "execution", "witness", "globally-exactly-once-signing"),
        })
        with self.assertRaises(TypeError):
            contract["publicExecutionEnabled"] = True
        _, tree = read_source("serverware/authority_store/v9_schema_source.py", 2 * 1024 * 1024)
        ddl = named_function(tree, "authority_v9_schema_source").body[0].value.value
        start = ddl.index(table + " (")
        ack = ddl[start:ddl.index("\n            );", start)]
        declarations = re.findall(r"^                ([a-z_]+) (TEXT|BIGINT) (.+),$", ack, re.M)
        self.assertEqual(tuple(name for name, _, _ in declarations), columns)
        self.assertTrue(all("NOT NULL" in suffix or suffix == "PRIMARY KEY"
                            for _, _, suffix in declarations))
        self.assertIn("ack_envelope_id TEXT PRIMARY KEY", ack)
        self.assertIn("intent_envelope_id TEXT NOT NULL UNIQUE", ack)
        compact = " ".join(ack.split())
        key = "(" + ", ".join(scope) + ")"
        self.assertIn("FOREIGN KEY " + key + " REFERENCES policy_authority_revocation_writer_requests " + key,
                      compact)
        self.assertIn("UNIQUE " + key, " ".join(ddl[:start].split()))
        self.assertEqual(ack.count("DEFERRABLE INITIALLY DEFERRED"), 1)
        self.assertNotIn("CASCADE", ack)
        for name in ("ack_envelope_id", "intent_envelope_id", "configuration_digest",
                     "generation_digest", "writer_response_spki_digest", "exact_ack_bytes_digest"):
            self.assertIn("CHECK (" + name + " ~ '^sha256:[0-9a-f]{64}$')", ack)
        for spelling in ("CHECK (generation_sequence > 0)", "CHECK (exact_ack_byte_count BETWEEN 2 AND 16384)",
                "length(exact_ack_base64url) = (4 * exact_ack_byte_count + 2) / 3",
                "exact_ack_base64url ~ '^[A-Za-z0-9_-]+$'", "exact_ack_byte_count % 3 = 1",
                "exact_ack_byte_count % 3 = 2", "CHECK (source_revision = '" + authority_contract.SOURCE_REVISION + "')"):
            self.assertIn(spelling, ack)
        self.assertTrue(set(columns).isdisjoint({"status", "terminal_at_epoch_ns", "committed_at_epoch_ns",
            "exact_envelope_base64url", "evaluation_context_base64url", "historical_expectations_base64url"}))

    def test_writer_ack_storage_is_immutable_framework_only_sqlite_denied_and_not_synthesized(self):
        table = "policy_authority_revocation_writer_acknowledgments"
        immutable = named_assignment(self.db_tree, "_POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES").value
        self.assertEqual(sum(node.value == table for node in immutable.elts), 1)
        for name in ("_POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES", "_POLICY_CANDIDATE_AUTHORITY_REPLACEABLE_TABLES"):
            self.assertNotIn(table, [node.value for node in named_assignment(self.db_tree, name).value.elts])
        self.assertIn(table, authority_contract._FRAMEWORK_CUSTODY_TABLES)
        for spec in authority_contract.OPERATIONS.values():
            for name in ("businessReads", "businessWrites", "authorizationReads", "frameworkWrites",
                         "frameworkReadBeforeWrite", "frameworkPreconditions"):
                self.assertNotIn(table, spec[name])
        for grants in authority_contract.SQL_GRANT_MANIFEST.values():
            self.assertNotIn(table, grants["frameworkSelect"])
            self.assertNotIn(table, grants["frameworkMutate"])
        for name in ("_legacy_migrate_policy_candidate_authority_offline", "_prepare_policy_candidate_authority_schema"):
            body = ast.get_source_segment(self.db_source, named_function(self.db_tree, name))
            guard = body.index("_metadata_table_exists(conn, authority_contract.REVOCATION_WRITER_ACK_TABLE)")
            self.assertLess(guard, body.index('"DROP TABLE "', guard))
        _, migration = read_source("scripts/authority/migrate_v8_to_v9.py", 2 * 1024 * 1024)
        self.assertIn(table, [node.value for node in named_assignment(migration, "_V9_NEW_TABLES").value.args[0].elts])
        source, tree = read_source("serverware/authority_store/v9_schema_source.py", 2 * 1024 * 1024)
        sqlite = ast.get_source_segment(source, named_function(tree, "planner_retention_sqlite_guards_sql"))
        self.assertIn("BEFORE INSERT ON " + table, sqlite)
        self.assertIn("SQLite writer acknowledgment custody is disabled", sqlite)
        self.assertIn('"serverware_writer_ack_sqlite_insert_guard"', self.schema_source)
        _, contract_tree = read_source("serverware/authority_contract.py", 2 * 1024 * 1024)
        material = named_assignment(contract_tree, "OPERATION_MANIFEST_DIGEST").value.args[1]
        fields = {key.value: value for key, value in zip(material.keys, material.values)}
        self.assert_shape(fields["revocationWriterAckCustody"], "dict(REVOCATION_WRITER_ACK_CUSTODY_CONTRACT)")
        self.assertIn('"revocationWriterAckCustody": dict(authority_contract.REVOCATION_WRITER_ACK_CUSTODY_CONTRACT)',
                      self.schema_source)

    def test_capability_custody_contract_closes_original_bytes_and_declared_identity_fields(self):
        columns = ("capability_id", "capability_protocol", "capability_record_digest", "planner_transaction_id",
            "plan_protocol", "retained_record_digest", "execution_envelope_id", "capability_digest",
            "root_transition_digest", "authority_snapshot_digest", "exact_request_bytes_digest",
            "exact_capability_base64url", "exact_capability_bytes_digest", "exact_capability_byte_count",
            "signer_key_digest", "witness_key_digest", "exact_witness_request_base64url",
            "exact_witness_request_bytes_digest", "exact_witness_request_byte_count", "source_revision")
        identity = ("capability_id", "capability_protocol", "capability_record_digest", "capability_digest",
            "envelope_id", "operation", "operation_id", "handler_name", "request_digest",
            "operation_manifest_digest", "query_manifest_digest", "authority_root_set_digest",
            "authority_snapshot_digest", "approver_policy_digest", "webauthn_receipt_json",
            "webauthn_receipt_digest", "webauthn_trust_high_water_digest", "witness_reservation_digest",
            "witness_sequence", "witness_head_digest", "deadline_monotonic_ns", "fence",
            "issued_monotonic_ns", "issued_at_epoch_ns", "expires_at_epoch_ns", "issuer_session_identity_digest",
            "issuer_measurement_digest", "issuer_attestation_receipt_digest", "issuer_credential_issuance_digest",
            "expected_result_digest", "planner_transaction_id", "authorization_projection_digest",
            "selected_business_rows_digest", "mutation_plan_digest", "deadline_epoch_ns")
        reservation = ("writer_token_digest", "reserved_at_epoch_ns", "reserved_transaction_id")
        terminal = ("status", "writer_token_digest", "reserved_at_epoch_ns", "reserved_transaction_id",
            "result_digest", "commit_receipt_digest", "committed_at_epoch_ns", "failure_digest", "failed_at_epoch_ns")
        self.assertEqual(authority_contract.REVOCATION_RETAINED_CAPABILITY_COLUMNS, columns)
        self.assertEqual(authority_contract.WRITER_CAPABILITY_IMMUTABLE_COLUMNS, identity)
        self.assertEqual(authority_contract.WRITER_CAPABILITY_RESERVATION_COLUMNS, reservation)
        self.assertEqual(authority_contract.WRITER_CAPABILITY_TERMINAL_COLUMNS, terminal)
        self.assertEqual((len(identity), len(reservation), len(terminal)), (35, 3, 9))
        self.assertTrue(set(identity).isdisjoint(terminal))
        contract = authority_contract.REVOCATION_CAPABILITY_CUSTODY_CONTRACT
        self.assertIs(type(contract), MappingProxyType)
        self.assertEqual(dict(contract), {
            "schema": "serverware.policyAuthorityRevocationCapabilityCustody/v1",
            "operation": "webauthn.credential.revoke", "capabilityProtocol": "revocation-v4",
            "planProtocol": "revocation-v4", "postgresOnly": True, "sqliteAdmission": False,
            "installedSuccessorIssuer": True, "publicExecutionEnabled": False,
            "configuredServiceRoute": False, "issuerInterface": "private-load6-store8",
            "retainedTable": "policy_authority_revocation_retained_capabilities", "retainedColumns": columns,
            "identityImmutableColumns": identity, "reservationImmutableOnceSet": reservation,
            "terminalColumns": terminal, "maxSignedCapabilityBytes": 4194304, "maxSignedWitnessRequestBytes": 65536,
            "parentBinding": "symmetric-deferred-five-column-foreign-keys",
            "plannerBinding": "retained-plan-composite-foreign-key",
            "plannerCapabilityBinding": "genuine-verifier-and-private-issuer-comparison",
            "executionBinding": "primary-key-only-mutable-envelope", "issuerTablePrivileges": (),
            "existingStoreMigration": "separately-reviewed-no-synthesis-or-cascade",
            "authorityExclusions": ("signature-verification", "key-enrollment", "currentness", "execution", "witness"),
        })
        with self.assertRaises(TypeError):
            contract["installedSuccessorIssuer"] = True
        _, tree = read_source("serverware/authority_contract.py", 2 * 1024 * 1024)
        material = named_assignment(tree, "OPERATION_MANIFEST_DIGEST").value.args[1]
        fields = {key.value: value for key, value in zip(material.keys, material.values)}
        self.assert_shape(fields["revocationCapabilityCustody"], "dict(REVOCATION_CAPABILITY_CUSTODY_CONTRACT)")
        digest = named_function(self.schema_tree, "_policy_candidate_authority_source_contract_digest")
        self.assertIn('"revocationCapabilityCustody": dict(authority_contract.REVOCATION_CAPABILITY_CUSTODY_CONTRACT)',
                      ast.get_source_segment(self.schema_source, digest))

    def test_capability_sidecar_is_immutable_without_issuer_or_operation_grant_expansion(self):
        table = "policy_authority_revocation_retained_capabilities"
        self.assertEqual(authority_contract.REVOCATION_RETAINED_CAPABILITY_TABLE, table)
        immutable = named_assignment(self.db_tree, "_POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES").value
        self.assertEqual(sum(node.value == table for node in immutable.elts), 1)
        for name in ("_POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES", "_POLICY_CANDIDATE_AUTHORITY_REPLACEABLE_TABLES"):
            self.assertNotIn(table, [node.value for node in named_assignment(self.db_tree, name).value.elts])
        self.assertIn(table, authority_contract._FRAMEWORK_CUSTODY_TABLES)
        for spec in authority_contract.OPERATIONS.values():
            for field in ("businessReads", "businessWrites", "authorizationReads", "frameworkWrites",
                          "frameworkReadBeforeWrite", "frameworkPreconditions"):
                self.assertNotIn(table, spec[field])
        for grants in authority_contract.SQL_GRANT_MANIFEST.values():
            self.assertNotIn(table, grants["frameworkMutate"])
            self.assertNotIn(table, grants["frameworkSelect"])
        installer = named_function(self.db_tree, "_install_policy_candidate_authority_guards")
        text = ast.get_source_segment(self.db_source, installer)
        self.assertIn("BEFORE UPDATE OR DELETE ON {table}", text)
        self.assertIn("serverware_reject_policy_authority_mutation()", text)
        # The connector rejects effective table authority, including SELECT;
        # immutable/runtime inventories do not constitute an issuer grant.
        issuer = named_function(self.db_tree, "_policy_authority_capability_issuer_pg_connect_raw")
        query = named_assignment(issuer, "direct_authority", recursive=True)
        text = ast.get_source_segment(self.db_source, query)
        self.assertIn("pg_catalog.has_table_privilege(", text)
        self.assertIn("'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'", text)
        checks = [node for node in ast.walk(issuer) if isinstance(node, ast.If)
                  and "direct_authority is not None" in ast.get_source_segment(self.db_source, node.test)]
        self.assertEqual(len(checks), 1)
        self.assertIsInstance(checks[0].body[0], ast.Raise)

    def test_existing_capability_custody_denies_implicit_migration_before_any_drop(self):
        table = "policy_authority_revocation_retained_capabilities"
        for function in ("_legacy_migrate_policy_candidate_authority_offline", "_prepare_policy_candidate_authority_schema"):
            node = named_function(self.db_tree, function)
            source = ast.get_source_segment(self.db_source, node)
            guard = source.index("_metadata_table_exists(conn, authority_contract.REVOCATION_RETAINED_CAPABILITY_TABLE)")
            self.assertLess(guard, source.index('"DROP TABLE "', guard))
            self.assertIn("retained capability storage requires a separately reviewed migration", source)
            guards = [item for item in ast.walk(node) if isinstance(item, ast.If)
                      and "REVOCATION_RETAINED_CAPABILITY_TABLE" in ast.get_source_segment(self.db_source, item.test)]
            self.assertEqual(len(guards), 1)
            self.assertIsInstance(guards[0].body[0], ast.Raise)
        _, migration = read_source("scripts/authority/migrate_v8_to_v9.py", 2 * 1024 * 1024)
        new_tables = named_assignment(migration, "_V9_NEW_TABLES").value.args[0]
        self.assertEqual(sum(node.value == table for node in new_tables.elts), 1)

    def test_counted_custody_is_exact_postgres_only_and_excluded_from_primary_business(self):
        self.assertEqual(dict(authority_contract.POSTGRES_COUNTED_STORE_COLUMNS), COUNTED_COLUMNS)
        self.assertEqual(authority_contract.POSTGRES_COUNTED_STORE_TABLES, tuple(COUNTED_COLUMNS))
        with self.assertRaises(TypeError):
            authority_contract.POSTGRES_COUNTED_STORE_COLUMNS["extra"] = ()
        _, storage = read_source("serverware/authority_store/counted_store_sql.py", 128 * 1024)
        self.assert_shape(named_assignment(storage, "COUNTED_STORE_TABLES").value, repr(tuple(COUNTED_COLUMNS)))
        for name, table in (("COUNTED_HEAD_COLUMNS", "policy_authority_counted_index_heads"),
                ("COUNTED_LEAF_COLUMNS", "policy_authority_counted_index_leaves"),
                ("COUNTED_NODE_COLUMNS", "policy_authority_counted_index_nodes")):
            self.assert_shape(named_assignment(storage, name).value, repr(COUNTED_COLUMNS[table]))
        for spec in authority_contract.OPERATIONS.values():
            for field in ("businessReads", "businessWrites", "authorizationReads"):
                self.assertTrue(set(COUNTED_COLUMNS).isdisjoint(spec[field]))
        self.assertTrue(set(COUNTED_COLUMNS).issubset(authority_contract._FRAMEWORK_CUSTODY_TABLES))
        self.assertTrue(set(COUNTED_COLUMNS).isdisjoint(ADDITIONAL))
        for name in ("_POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES", "_POLICY_CANDIDATE_AUTHORITY_HEAD_TABLES"):
            value = named_assignment(self.db_tree, name).value
            self.assertTrue(set(COUNTED_COLUMNS).isdisjoint(node.value for node in value.elts))
        installer = named_function(self.db_tree, "_install_policy_candidate_authority_guards")
        tracked = named_assignment(installer, "tracked_authenticated_tables", recursive=True)
        self.assertNotIn("COUNTED", ast.get_source_segment(self.db_source, tracked))
        self.assert_shape(named_assignment(self.db_tree, "_POLICY_AUTHORITY_FRAMEWORK_CUSTODY_TABLES").value.args[0].right,
            "set(authority_contract.POSTGRES_COUNTED_STORE_TABLES)")

    def test_counted_eleven_function_signatures_and_security_match_actual_sql_declarations(self):
        self.assertEqual(dict(authority_contract.POSTGRES_COUNTED_FUNCTION_SIGNATURES), COUNTED_SIGNATURES)
        observed = {}
        for relative in ("counted_hash_sql.py", "counted_projection_sql.py", "counted_path_sql.py", "counted_maintenance_sql.py"):
            source, _ = read_source("serverware/authority_store/" + relative, 256 * 1024)
            declarations = re.findall(
                r"CREATE OR REPLACE FUNCTION \{namespace\}\.([a-z_]+)\((.*?)\)(.*?)AS \$counted_[a-z]+\$",
                source, re.DOTALL)
            self.assertTrue(declarations)
            for name, arguments, header in declarations:
                self.assertNotIn(name, observed)
                types = tuple(argument.strip().split()[1] for argument in arguments.split(","))
                observed[name] = types
                self.assertIn("LANGUAGE plpgsql", header)
                self.assertIn("SECURITY INVOKER", header)
                self.assertNotRegex(header, r"\bSTRICT\b")
                mutation = name in {
                    "serverware_policy_authority_counted_apply_index", "serverware_policy_authority_counted_apply_event"}
                projection = relative == "counted_projection_sql.py"
                self.assertIn("VOLATILE" if mutation else "IMMUTABLE", header)
                self.assertEqual(dict(authority_contract.POSTGRES_COUNTED_FUNCTION_CONTRACTS[name]), {
                    "argumentTypes": types, "language": "plpgsql", "securityDefiner": False,
                    "strict": False, "volatility": "v" if mutation else "i",
                    "searchPath": ("pg_catalog",) if projection else ("pg_catalog", "$metadata", "pg_temp"),
                })
                self.assertIn("SET search_path = pg_catalog" + ("\n" if projection else ", {namespace}, pg_temp\n"), header)
        self.assertEqual(observed, COUNTED_SIGNATURES)

    def test_counted_owner_checks_include_signatures_invoker_flags_and_no_new_execute_grants(self):
        owner = named_function(self.db_tree, "_validate_policy_authority_owner_apply_function")
        types = named_assignment(owner, "counted_functions", recursive=True)
        self.assert_shape(types.value, "authority_contract.POSTGRES_COUNTED_FUNCTION_CONTRACTS")
        checks = [node for node in ast.walk(owner) if call_named(node, "any")
            and 'counted_functions[row["proname"]]' in ast.get_source_segment(self.db_source, node)]
        self.assertEqual(len(checks), 1)
        self.assert_shape(checks[0],
            "any(str(row['argument_types']) != ', '.join(counted_functions[row['proname']]['argumentTypes']) "
            "or row['prosecdef'] is not counted_functions[row['proname']]['securityDefiner'] "
            "or row['proisstrict'] is not counted_functions[row['proname']]['strict'] "
            "or str(row['language_name']) != counted_functions[row['proname']]['language'] "
            "or str(row['provolatile']) != counted_functions[row['proname']]['volatility'] "
            "or list(row['proconfig'] or ()) != ['search_path=' + ', '.join("
            "_POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME if part == '$metadata' else part "
            "for part in counted_functions[row['proname']]['searchPath'])] "
            "for row in function_rows if row['proname'] in counted_functions)")
        for name in ("_POLICY_AUTHORITY_EXECUTOR_FUNCTION_SIGNATURES",
                "_POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTIONS",
                "_POLICY_AUTHORITY_PLANNER_WRITER_TABLE_PRIVILEGES"):
            self.assertNotIn("COUNTED", ast.get_source_segment(self.db_source, named_assignment(self.db_tree, name)))
        grant_check = named_assignment(owner, "unexpected_grant", recursive=True)
        self.assertNotIn("COUNTED", ast.get_source_segment(self.db_source, grant_check))
        for fragment in ("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ", " FROM PUBLIC"):
            self.assertIn(fragment, ast.get_source_segment(self.db_source, self.seal))
        guards = named_function(self.schema_tree, "_policy_candidate_authority_required_guard_names")
        self.assertTrue(any(isinstance(node, ast.Starred) and ast.dump(node.value) == ast.dump(
            ast.parse("authority_contract.POSTGRES_COUNTED_FUNCTION_SIGNATURES", mode="eval").body)
            for node in ast.walk(guards)))

    def test_counted_installation_is_on_actual_postgres_guard_and_shared_scratch_path(self):
        installer = named_function(self.db_tree, "_install_policy_candidate_authority_guards")
        calls = [node for node in ast.walk(installer) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "_counted_installation"]
        self.assertEqual({node.func.attr for node in calls}, {"prepare_counted_store", "counted_functions_sql"})
        prepare = next(node for node in calls if node.func.attr == "prepare_counted_store")
        functions = next(node for node in calls if node.func.attr == "counted_functions_sql")
        self.assert_shape(prepare, "_counted_installation.prepare_counted_store(conn, guard_namespace)")
        self.assert_shape(functions, "_counted_installation.counted_functions_sql(guard_namespace)")
        pg_blocks = [node for node in ast.walk(installer) if isinstance(node, ast.If)
            and ast.dump(node.test) == ast.dump(ast.parse("isinstance(conn, PostgresMetadataConnection)", mode="eval").body)
            and prepare in tuple(ast.walk(node))]
        self.assertEqual(len(pg_blocks), 1)
        namespace = named_assignment(installer, "guard_namespace", recursive=True)
        primary_calls = [node for node in ast.walk(installer) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "authenticated_tree_functions_sql"]
        self.assertEqual(len(primary_calls), 1)
        self.assertLess(namespace.lineno, prepare.lineno)
        self.assertLess(prepare.lineno, functions.lineno)
        self.assertLess(functions.lineno, primary_calls[0].lineno)
        scratch = named_function(self.schema_tree, "_policy_candidate_authority_expected_structure_manifest")
        shared = [node for node in ast.walk(scratch) if call_named(node, "_install_policy_candidate_authority_guards")]
        self.assertEqual(len(shared), 2)  # Real PG scratch and unchanged SQLite path.
        self.assertTrue(any(ast.dump(node) == ast.dump(ast.parse(
            "_install_policy_candidate_authority_guards(conn)", mode="eval").body) for node in shared))
        connection = named_function(self.db_tree, "_metadata_pg_connect_with_dsn")
        inventory = [node for node in ast.walk(connection) if call_named(node, "_policy_candidate_authority_schema_tables")]
        self.assertEqual(len(inventory), 1)
        self.assert_shape(inventory[0], "_policy_candidate_authority_schema_tables(postgres=True)")

    def test_counted_source_contract_pins_event_scope_without_activating_v3_queries(self):
        self.assertEqual(dict(authority_contract.POSTGRES_COUNTED_MAINTENANCE_CONTRACT), {
            "schema": "serverware.policyAuthorityCountedMaintenanceAdmission/v1",
            "maximumProfilesPerNormalizedEvent": 3,
            "workAccounting": "bounded-per-profile-not-whole-operation",
            "plannerCompleteQueryAdmission": False, "sqliteInstalled": False,
        })
        _, contract = read_source("serverware/authority_contract.py", 2 * 1024 * 1024)
        material = named_assignment(contract, "OPERATION_MANIFEST_DIGEST").value.args[1]
        fields = {key.value: value for key, value in zip(material.keys, material.values)}
        self.assert_shape(fields["postgresCountedStoreColumns"],
            "{table: list(columns) for table, columns in POSTGRES_COUNTED_STORE_COLUMNS.items()}")
        self.assert_shape(fields["postgresCountedFunctionContracts"],
            "{name: {field: list(value) if isinstance(value, tuple) else value "
            "for field, value in contract.items()} for name, contract in POSTGRES_COUNTED_FUNCTION_CONTRACTS.items()}")
        self.assert_shape(fields["postgresCountedMaintenance"], "dict(POSTGRES_COUNTED_MAINTENANCE_CONTRACT)")
        source, planner = read_source("serverware/authority_planner.py", 1024 * 1024)
        reader = named_function(planner, "_read_bounded_transition_rows")
        self.assertIn('raise AuthorityPlannerError("complete index query acquisition is not available")',
            ast.get_source_segment(source, reader))
        self.assert_shape(named_assignment(planner, "PLANNER_RESPONSE_SCHEMA").value,
            "'serverware.policyAuthorityPlannerResponse/v3'")
        validation = named_function(self.schema_tree, "_validate_policy_candidate_authority_structure")
        text = ast.get_source_segment(self.schema_source, validation)
        self.assertIn("if manifest != expected_manifest:", text)
        self.assertIn("if contract[field] != value:", text)
        self.assertIn("POSTGRES_COUNTED_STORE_COLUMNS.items()", text)


if __name__ == "__main__":
    unittest.main()
