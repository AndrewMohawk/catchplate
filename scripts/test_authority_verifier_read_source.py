#!/usr/bin/env python3
"""Pure parameterization and source controls for the verifier read contract.

Only the real pure contract/query helper is called. Bounded AST inspection
does not import db or the service, execute extracted functions, or replace
the registry. The authority_store package still loads inert schema/crypto
definitions. These are not PostgreSQL privilege, role, mTLS, migration or
whole-service admission tests; native prepared-role verification is required.
"""
from __future__ import annotations

import ast
import hashlib
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware.authority_store import verifier_read_sql as verifier


EVIDENCE_TABLES = frozenset({
    "webauthn_challenges", "webauthn_credentials",
    "webauthn_trust_publication_high_water", "webauthn_trust_publications",
})
TABLES = EVIDENCE_TABLES | frozenset({
    "policy_authority_authenticated_table_roots", "policy_authority_counted_index_heads",
})
CONTRACT = "serverware.policyAuthorityVerifierRead/v2"


def read_source(relative, maximum=2 * 1024 * 1024):
    path = ROOT / relative
    if path.stat().st_size > maximum:
        raise AssertionError("source exceeded the explicit fixture bound")
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source)


def function(tree, name):
    matches = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(matches) != 1:
        raise AssertionError("source function is not unique: " + name)
    return matches[0]


def assignment(node, name):
    matches = [item for item in ast.walk(node) if
        (isinstance(item, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name
            for target in item.targets)) or
        (isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name) and item.target.id == name)]
    if len(matches) != 1:
        raise AssertionError("source assignment is not unique: " + name)
    return matches[0]


def calls(node, name):
    return [item for item in ast.walk(node) if isinstance(item, ast.Call)
        and ((isinstance(item.func, ast.Name) and item.func.id == name)
             or (isinstance(item.func, ast.Attribute) and item.func.attr == name))]


def keyword(call, name):
    values = [item.value for item in call.keywords if item.arg == name]
    if len(values) != 1:
        raise AssertionError("source call keyword is not unique: " + name)
    return values[0]


def dict_value(node, key_name):
    if not isinstance(node, ast.Dict):
        raise AssertionError("source material is not a dictionary")
    values = [value for key, value in zip(node.keys, node.values)
              if isinstance(key, ast.Constant) and key.value == key_name]
    if len(values) != 1:
        raise AssertionError("source material key is not unique: " + key_name)
    return values[0]


def raising_guard(node, message):
    matches = [item for item in ast.walk(node) if isinstance(item, ast.If)
        and any(isinstance(statement, ast.Raise) and isinstance(statement.exc, ast.Call)
            and statement.exc.args and isinstance(statement.exc.args[0], ast.Constant)
            and statement.exc.args[0].value == message for statement in item.body)]
    if len(matches) != 1:
        raise AssertionError("source rejection guard is not unique: " + message)
    return matches[0]


class AuthorityVerifierReadSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db_source, cls.db = read_source("serverware/db.py", 16 * 1024 * 1024)
        cls.schema_source, cls.schema = read_source("serverware/authority_store/schema.py")
        cls.seal = function(cls.db, "_seal_postgres_schema_acl")

    def assert_shape(self, node, expression):
        # Parse fixed expected syntax only; never evaluate inspected source.
        self.assertEqual(ast.dump(node), ast.dump(ast.parse(expression, mode="eval").body))

    def test_source_contract_is_exact_four_table_frozen_inventory(self):
        # Preserve the approved historical ID; v2 has two additional root
        # tables while the actual WebAuthn evidence SQL remains four-table.
        self.assertEqual(authority_contract.VERIFIER_READ_CONTRACT, CONTRACT)
        self.assertIs(type(authority_contract.VERIFIER_READ_TABLES), frozenset)
        self.assertEqual(authority_contract.VERIFIER_READ_TABLES, TABLES)
        self.assertEqual(authority_contract.SOURCE_REVISION,
                         "serverware.policyCandidateAuthoritySource/2026-07-30.97")
        self.assertTrue(all(type(table) is str for table in authority_contract.VERIFIER_READ_TABLES))

    def test_real_helper_returns_fixed_sql_and_exact_separate_parameters(self):
        for role, namespace in (("verifier_reader", "serverware_metadata"),
                                ('quoted"reader', 'quoted"schema'),
                                ("lecteur_\u00e9", "schema_\U0001f600")):
            with self.subTest(role=role, namespace=namespace):
                statement, parameters = verifier.verifier_read_privilege_check(role=role, namespace=namespace)
                self.assertIs(type(statement), str)
                self.assertEqual(statement, verifier.VERIFIER_READ_PRIVILEGE_SQL)
                self.assertIs(type(parameters), tuple)
                self.assertEqual(parameters, (role, namespace, sorted(TABLES)))
                self.assertEqual(statement.count("%s"), 3)
                self.assertNotIn(role, statement)
                self.assertNotIn(namespace, statement)

    def test_real_helper_uses_utf8_bytes_not_codepoint_count_for_identifiers(self):
        accepted = ("a" * 63, "\u00e9" * 31 + "a", "\U0001f600" * 15 + "aaa")
        for value in accepted:
            self.assertEqual(len(value.encode("utf-8")), 63)
            self.assertEqual(verifier.verifier_read_privilege_check(role=value, namespace="n")[1][0], value)
            self.assertEqual(verifier.verifier_read_privilege_check(role="r", namespace=value)[1][1], value)
        for value in ("a" * 64, "\u00e9" * 32, "\U0001f600" * 16):
            self.assertEqual(len(value.encode("utf-8")), 64)
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    verifier.verifier_read_privilege_check(role=value, namespace="n")
                with self.assertRaises(ValueError):
                    verifier.verifier_read_privilege_check(role="r", namespace=value)

    def test_real_helper_rejects_bad_types_empty_nul_and_non_scalar_text(self):
        class StringSubclass(str):
            pass

        for value in (None, False, 0, 1, [], {}, b"reader", bytearray(b"reader"),
                      StringSubclass("reader"), "", "a\x00b", "\ud800", "\udfff"):
            with self.subTest(type=type(value).__name__, value=repr(value)):
                with self.assertRaises(ValueError):
                    verifier.verifier_read_privilege_check(role=value, namespace="n")
                with self.assertRaises(ValueError):
                    verifier.verifier_read_privilege_check(role="r", namespace=value)

    def test_returned_table_parameter_is_fresh_and_cannot_mutate_source_inventory(self):
        first = verifier.verifier_read_privilege_check(role="reader", namespace="metadata")
        second = verifier.verifier_read_privilege_check(role="reader", namespace="metadata")
        self.assertEqual(first, second)
        self.assertIsNot(first[1][2], second[1][2])
        first[1][2].append("credentials")
        first[1][2].remove("webauthn_challenges")
        self.assertEqual(second[1][2], sorted(TABLES))
        self.assertEqual(authority_contract.VERIFIER_READ_TABLES, TABLES)
        self.assertEqual(verifier.verifier_read_privilege_check(role="reader", namespace="metadata"), second)

    def test_query_digest_is_independent_sha256_of_exact_utf8_text(self):
        expected = "sha256:" + hashlib.sha256(verifier.VERIFIER_READ_PRIVILEGE_SQL.encode("utf-8")).hexdigest()
        self.assertEqual(verifier.VERIFIER_READ_PRIVILEGE_SQL_DIGEST, expected)
        altered = verifier.VERIFIER_READ_PRIVILEGE_SQL + "\n"
        self.assertNotEqual(expected, "sha256:" + hashlib.sha256(altered.encode("utf-8")).hexdigest())

    def test_fixed_query_has_closed_violation_branches_and_only_bound_identifiers(self):
        sql = verifier.VERIFIER_READ_PRIVILEGE_SQL
        self.assertEqual(set(re.findall(r"SELECT '([^']+)'", sql)), {
            "role-or-namespace", "schema-or-database-privilege", "role-membership",
            "required-table-select", "table-or-column-privilege", "sequence-privilege",
            "function-privilege", "public-schema-privilege", "public-relation-privilege",
            "public-column-privilege", "public-function-privilege",
        })
        self.assertTrue(sql.startswith("WITH requested AS ("))
        self.assertTrue(sql.endswith("SELECT violation FROM violations LIMIT 1"))
        self.assertIn("%s::pg_catalog.text AS role_name", sql)
        self.assertIn("%s::pg_catalog.text AS namespace_name", sql)
        self.assertIn("%s::pg_catalog.text[] AS required_tables", sql)
        self.assertNotIn("current_user", sql)
        self.assertNotIn("serverware_metadata", sql)
        self.assertNotIn("SET ROLE", sql)
        self.assertNotIn("EXECUTE ", sql)

    def test_missing_roles_namespaces_memberships_and_elevated_flags_deny_definitely(self):
        sql = verifier.VERIFIER_READ_PRIVILEGE_SQL
        for fragment in (
            "LEFT JOIN pg_catalog.pg_roles AS role_record",
            "ON role_record.rolname = requested.role_name",
            "LEFT JOIN pg_catalog.pg_namespace AS namespace",
            "ON namespace.nspname = requested.namespace_name",
            "role_oid IS NULL OR namespace_oid IS NULL", "rolcanlogin IS NOT TRUE",
            "rolsuper IS NOT FALSE", "rolcreaterole IS NOT FALSE", "rolcreatedb IS NOT FALSE",
            "rolreplication IS NOT FALSE", "rolbypassrls IS NOT FALSE",
            "ON membership.member = authority.role_oid", "OR membership.roleid = authority.role_oid",
            "CASE WHEN role_oid IS NOT NULL AND namespace_oid IS NOT NULL THEN",
            "role_oid, namespace_oid, 'USAGE') IS NOT TRUE",
            "role_oid, namespace_oid, 'CREATE') IS NOT FALSE",
            "'USAGE WITH GRANT OPTION,CREATE WITH GRANT OPTION') IS NOT FALSE",
            "'CREATE,TEMPORARY') IS NOT FALSE",
        ):
            self.assertIn(fragment, sql)
        schema_branch = sql.split("SELECT 'schema-or-database-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("ELSE TRUE END", schema_branch)

    def test_required_tables_must_exist_be_real_tables_and_have_full_select(self):
        branch = verifier.VERIFIER_READ_PRIVILEGE_SQL.split("SELECT 'required-table-select'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("pg_catalog.unnest(authority.required_tables)", branch)
        self.assertIn("LEFT JOIN pg_catalog.pg_class AS relation", branch)
        self.assertIn("relation.relnamespace = authority.namespace_oid", branch)
        self.assertIn("relation.relname = expected.table_name", branch)
        self.assertRegex(branch, r"CASE WHEN relation\.oid IS NOT NULL\s+AND relation\.relkind IN \('r', 'p'\) THEN")
        self.assertIn("authority.role_oid, relation.oid, 'SELECT') IS NOT TRUE", branch)
        self.assertIn("ELSE TRUE END", branch)
        self.assertNotIn("has_any_column_privilege", branch)

    def test_extra_reads_writes_and_grant_options_are_denied_for_table_like_objects(self):
        branch = verifier.VERIFIER_READ_PRIVILEGE_SQL.split("SELECT 'table-or-column-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f') THEN", branch)
        self.assertIn("ELSE FALSE END", branch)
        for fragment in (
            "'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') IS NOT FALSE",
            "role_oid, oid, 'INSERT,UPDATE,REFERENCES') IS NOT FALSE",
            "'SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,'",
            "'UPDATE WITH GRANT OPTION,DELETE WITH GRANT OPTION,'",
            "'TRUNCATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION,'",
            "'TRIGGER WITH GRANT OPTION') IS NOT FALSE",
            "'UPDATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION') IS NOT FALSE",
            "(relname::pg_catalog.text = ANY(required_tables)) IS NOT TRUE",
            "role_oid, oid, 'SELECT') IS NOT FALSE",
        ):
            self.assertIn(fragment, branch)
        self.assertEqual(branch.count("role_oid, oid, 'SELECT') IS NOT FALSE"), 2)
        self.assertIn("pg_catalog.has_any_column_privilege", branch)
        self.assertNotIn("has_sequence_privilege", branch)
        self.assertNotIn("has_function_privilege", branch)

    def test_sequence_and_public_acl_type_branches_never_use_table_privilege_on_indexes(self):
        sql = verifier.VERIFIER_READ_PRIVILEGE_SQL
        sequence = sql.split("SELECT 'sequence-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("CASE WHEN relkind = 'S' THEN", sequence)
        self.assertIn("role_oid, oid, 'SELECT,USAGE,UPDATE') IS NOT FALSE", sequence)
        self.assertIn("ELSE FALSE END", sequence)
        self.assertNotIn("has_table_privilege", sequence)
        function_branch = sql.split("SELECT 'function-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("FROM metadata_functions", function_branch)
        self.assertIn("role_oid, oid, 'EXECUTE') IS NOT FALSE", function_branch)
        relation = sql.split("SELECT 'public-relation-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f', 'S') THEN", relation)
        self.assertIn("CASE WHEN relkind = 'S' THEN 'S'::pg_catalog.\"char\"", relation)
        self.assertIn("ELSE 'r'::pg_catalog.\"char\" END, relowner", relation)
        self.assertIn("ELSE ARRAY[]::pg_catalog.aclitem[] END", relation)
        column = sql.split("SELECT 'public-column-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("attribute.attnum > 0", column)
        self.assertIn("attribute.attisdropped IS FALSE", column)
        self.assertIn("CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f') THEN", column)
        self.assertIn("ELSE ARRAY[]::pg_catalog.aclitem[] END", column)
        self.assertEqual(sql.count("WHERE grant_entry.grantee = 0"), 4)

    def test_helper_has_no_database_registry_or_dynamic_sql_dependency(self):
        _, tree = read_source("serverware/authority_store/verifier_read_sql.py", 64 * 1024)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend((None, alias.name, alias.asname) for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.extend((node.module, alias.name, alias.asname) for alias in node.names)
        self.assertEqual(set(imports), {
            ("__future__", "annotations", None), (None, "hashlib", None),
            ("serverware", "authority_contract", None),
        })
        helper = function(tree, "verifier_read_privilege_check")
        forbidden = {"open", "eval", "exec", "compile", "__import__", "connect", "execute", "cursor"}
        for name in forbidden:
            self.assertEqual(calls(helper, name), [])
        returns = [node for node in helper.body if isinstance(node, ast.Return)]
        self.assertEqual(len(returns), 1)
        self.assert_shape(returns[0].value,
            "(VERIFIER_READ_PRIVILEGE_SQL, (role, namespace, sorted(authority_contract.VERIFIER_READ_TABLES)))")

    def test_db_and_operation_manifest_use_the_exact_shared_inventory(self):
        aliases = [alias for node in self.db.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware.authority_store" for alias in node.names
                   if alias.name == "verifier_read_sql"]
        self.assertEqual([(alias.name, alias.asname) for alias in aliases],
                         [("verifier_read_sql", "_authority_verifier_read_sql")])
        self.assert_shape(assignment(self.db, "_POLICY_AUTHORITY_VERIFIER_READ_TABLES").value,
                          "authority_contract.VERIFIER_READ_TABLES")
        _, contract = read_source("serverware/authority_contract.py")
        digest = assignment(contract, "OPERATION_MANIFEST_DIGEST").value
        self.assert_shape(digest.func, "_digest")
        self.assert_shape(digest.args[0], "CONTRACT_SCHEMA")
        self.assert_shape(dict_value(digest.args[1], "verifierReadContract"), "VERIFIER_READ_CONTRACT")
        self.assert_shape(dict_value(digest.args[1], "verifierReadTables"), "sorted(VERIFIER_READ_TABLES)")

    def test_all_four_metadata_sealers_supply_dedicated_role_and_closed_set(self):
        migration_source, migration = read_source("scripts/authority/migrate_v8_to_v9.py")
        owners = (
            (self.db, "init_db", ""),
            (self.schema, "_policy_candidate_authority_expected_structure_manifest", ""),
            (self.schema, "repair_policy_candidate_authority_completed_v9_receipt", ""),
            (migration, "migrate", "db."),
        )
        metadata_calls = []
        for tree, name, prefix in owners:
            sites = calls(function(tree, name), "_seal_postgres_schema_acl")
            self.assertEqual(len(sites), 1, name)
            metadata_calls.extend(sites)
            self.assert_shape(keyword(sites[0], "authority_verifier_role"),
                              prefix + "_METADATA_STORE_AUTHORITY_VERIFIER_ROLE")
            self.assert_shape(keyword(sites[0], "authority_verifier_read_tables"),
                              prefix + "_POLICY_AUTHORITY_VERIFIER_READ_TABLES")
            self.assert_shape(keyword(sites[0], "runtime_read_only_tables"),
                              prefix + "_POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES")
        all_calls = [call for tree in (self.db, self.schema, migration)
                     for call in calls(tree, "_seal_postgres_schema_acl")]
        self.assertEqual(len(all_calls), 6)
        unrelated = [call for call in all_calls if call not in metadata_calls]
        self.assertEqual(len(unrelated), 2)
        for call in unrelated:
            self.assertTrue({item.arg for item in call.keywords}.isdisjoint(
                {"authority_verifier_role", "authority_verifier_read_tables"}))
        self.assertEqual({ast.dump(keyword(call, "schema")) for call in unrelated}, {
            ast.dump(ast.parse("_AUDIT_POSTGRES_SCHEMA", mode="eval").body),
            ast.dump(ast.parse("_RECOVERY_WITNESS_POSTGRES_SCHEMA", mode="eval").body),
        })
        # Source-only migration closure: neither retained sidecar is
        # adopted as a v8 input or through the historical receipt repair.
        new_tables = assignment(migration, "_V9_NEW_TABLES").value
        self.assertIsInstance(new_tables, ast.Call)
        for sidecar in ("policy_authority_revocation_retained_plans",
                        "policy_authority_webauthn_evidence_retained_plans"):
            self.assertEqual(sum(item.value == sidecar for item in new_tables.args[0].elts), 1)
        source_tables = ast.get_source_segment(migration_source,
            assignment(migration, "_MIGRATION_TABLES"))
        self.assertIn("- _V9_NEW_TABLES", source_tables)
        migrate = function(migration, "migrate")
        premature = assignment(migrate, "premature_v9_tables")
        self.assertIn("sorted(_V9_NEW_TABLES)", ast.get_source_segment(migration_source, premature))
        # That error includes the discovered names, so locate the guard by
        # its exact closed condition rather than evaluating any source.
        denied = next(node for node in ast.walk(migrate) if isinstance(node, ast.If)
                      and isinstance(node.test, ast.Name) and node.test.id == "premature_v9_tables")
        self.assert_shape(denied.test, "premature_v9_tables")
        self.assertIn('raise MigrationError(', ast.get_source_segment(migration_source, denied))
        extension = calls(migrate, "authority_v9_schema_source")
        self.assertEqual(len(extension), 1)
        self.assertLess(premature.lineno, denied.lineno)
        self.assertLess(denied.lineno, extension[0].lineno)
        repair = function(migration, "_completed_v9_repair_receipt")
        repair_source = ast.get_source_segment(migration_source, repair)
        guard = repair_source.index("retained revocation storage requires a separately reviewed migration")
        self.assertLess(repair_source.index("_TARGET_COMPLETED_V9_RECEIPT_COLUMNS"), guard)
        self.assertLess(repair_source.index("return None"), guard)
        self.assertLess(guard, repair_source.index("legacy_columns = tuple("))
        self.assertIn('retained is None or retained["present"] is not False', repair_source)
        retry = next(node for node in ast.walk(migrate) if isinstance(node, ast.If)
                     and isinstance(node.test, ast.Compare)
                     and isinstance(node.test.left, ast.Name) and node.test.left.id == "retry")
        validators = calls(retry, "_validate_policy_candidate_authority_structure")
        self.assertEqual(len(validators), 1)
        self.assert_shape(keyword(validators[0], "require_recorded_contract"), "True")
        self.assertEqual(calls(retry, "authority_v9_schema_source"), [])
        self.assertLess(retry.lineno, extension[0].lineno)

    def test_pre_sql_guard_covers_canonical_and_scratch_scopes_without_runtime_fallback(self):
        original, guard = self.seal.body[:2]
        self.assertIsInstance(original, ast.If)
        self.assertIsInstance(guard, ast.If)
        self.assert_shape(original.test,
            "schema == _POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME and "
            "(type(runtime_read_only_tables) is not frozenset or "
            "runtime_read_only_tables != _POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES)")
        self.assert_shape(guard.test,
            "schema in {_POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME, 'serverware_candidate_authority_expected_v9'} "
            "and (type(authority_verifier_role) is not str "
            "or re.fullmatch('[a-z][a-z0-9_]{0,62}', authority_verifier_role) is None "
            "or authority_verifier_role != _METADATA_STORE_AUTHORITY_VERIFIER_ROLE "
            "or authority_verifier_role in {runtime_role, authority_executor_role, authority_owner_role, "
            "authority_capability_issuer_role, authority_planner_writer_role} "
            "or type(authority_verifier_read_tables) is not frozenset "
            "or authority_verifier_read_tables != _POLICY_AUTHORITY_VERIFIER_READ_TABLES)")
        self.assertIsInstance(guard.body[0], ast.Raise)
        self.assert_shape(guard.body[0].exc,
            "error_type('metadata verifier role/read closure is not source exact')")
        self.assertEqual(guard.orelse, [])
        for call in calls(self.seal, "cursor") + calls(self.seal, "execute"):
            self.assertLess(guard.end_lineno, call.lineno)
        self.assertLess(guard.end_lineno, assignment(self.seal, "verifier_role").lineno)

    def test_actual_grants_and_expected_acl_use_only_the_verified_read_set(self):
        loops = [node for node in ast.walk(self.seal) if isinstance(node, ast.For)
                 and ast.dump(node.iter) == ast.dump(ast.parse("sorted(authority_verifier_read_tables)", mode="eval").body)]
        self.assertEqual(len(loops), 1)
        text = ast.get_source_segment(self.db_source, loops[0])
        self.assertIn('"GRANT SELECT ON "', text)
        self.assertIn("+ verifier_role_name", text)
        self.assertNotIn("GRANT ALL", text)
        expected_loops = [node for node in ast.walk(self.seal) if isinstance(node, ast.For)
                          and "actual_verifier_grants.get(name, set())" in ast.get_source_segment(self.db_source, node)]
        self.assertEqual(len(expected_loops), 1)
        self.assert_shape(assignment(expected_loops[0], "expected").value,
            "{'SELECT'} if kind in {'r', 'p'} and name in authority_verifier_read_tables else set()")
        self.assertIn("exact_verifier_acl = False", ast.get_source_segment(self.db_source, expected_loops[0]))

    def test_sealer_runs_shared_effective_check_after_existing_acl_denial_and_rejects_any_row(self):
        checked = assignment(self.seal, "verifier_privilege_violation")
        fetch = checked.value
        self.assertEqual(fetch.func.attr, "fetchone")
        query = fetch.func.value
        self.assert_shape(query.func, "cur.execute")
        self.assertEqual(len(query.args), 1)
        self.assertIsInstance(query.args[0], ast.Starred)
        self.assert_shape(query.args[0].value,
            "_authority_verifier_read_sql.verifier_read_privilege_check(role=verifier_role, namespace=schema)")
        denied = raising_guard(self.seal, "PostgreSQL verifier effective privileges are not source exact")
        self.assert_shape(denied.test, "verifier_privilege_violation is not None")
        holders = [node for node in ast.walk(self.seal) if isinstance(node, ast.If) and checked in node.body]
        self.assertEqual(len(holders), 1)
        self.assert_shape(holders[0].test, "verifier_role not in {runtime_role, executor_role}")
        blocks = [node for node in self.seal.body if isinstance(node, ast.With)]
        self.assertEqual(len(blocks), 1)
        self.assertIs(blocks[0].body[-1], holders[0])
        earlier = raising_guard(self.seal, "PostgreSQL object owner or ACL contains unexpected authority")
        self.assertIs(blocks[0].body[-3], earlier)
        self.assert_shape(blocks[0].body[-2].test,
            "planner_writer_role not in {runtime_role, executor_role, verifier_role, capability_issuer_role}")
        self.assertLess(earlier.end_lineno, checked.lineno)
        self.assertLess(checked.lineno, denied.lineno)

    def test_source_contract_and_owner_profile_bind_role_table_set_contract_and_query_bytes(self):
        aliases = [alias for node in self.schema.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware.authority_store.verifier_read_sql" for alias in node.names]
        self.assertEqual([(alias.name, alias.asname) for alias in aliases],
                         [("VERIFIER_READ_PRIVILEGE_SQL_DIGEST", None)])
        source_contract = function(self.schema, "_policy_candidate_authority_source_contract_digest")
        source_material = assignment(source_contract, "material").value
        self.assertIsInstance(source_material, ast.Call)
        self.assertIsInstance(source_material.func, ast.Attribute)
        self.assertEqual(source_material.func.attr, "encode")
        self.assertEqual(len(source_material.args), 1)
        self.assert_shape(source_material.args[0], repr("utf-8"))
        self.assert_shape(source_material.func.value.func, "dumps")
        source_mapping = source_material.func.value.args[0]
        profile = function(self.db, "_policy_authority_owner_verification_profile_digest")
        session = assignment(profile, "verifier_session_contract").value
        for mapping, table_expression, digest_expression in (
            (source_mapping, "sorted(authority_contract.VERIFIER_READ_TABLES)", "VERIFIER_READ_PRIVILEGE_SQL_DIGEST"),
            (session, "sorted(_POLICY_AUTHORITY_VERIFIER_READ_TABLES)",
             "_authority_verifier_read_sql.VERIFIER_READ_PRIVILEGE_SQL_DIGEST"),
        ):
            for key, expression in (
                ("verifierReadRole", "_METADATA_STORE_AUTHORITY_VERIFIER_ROLE"),
                ("verifierReadContract", "authority_contract.VERIFIER_READ_CONTRACT"),
                ("verifierReadTables", table_expression),
                ("verifierReadPrivilegeSqlDigest", digest_expression),
            ):
                self.assert_shape(dict_value(mapping, key), expression)
        source_returns = [node for node in source_contract.body if isinstance(node, ast.Return)]
        self.assertEqual(len(source_returns), 1)
        self.assert_shape(source_returns[0].value,
            "_policy_candidate_authority_framed_digest('serverware.policyCandidateAuthoritySourceContract/v1', material)")
        material = assignment(profile, "material").value
        self.assert_shape(material.func, "dumps")
        self.assert_shape(dict_value(material.args[0], "verifierSessionContract"), "verifier_session_contract")
        returned = [node for node in profile.body if isinstance(node, ast.Return)]
        self.assertEqual(len(returned), 1)
        self.assert_shape(returned[0].value,
            "_policy_candidate_authority_framed_digest('serverware.policyAuthorityOwnerVerificationProfile/v1', material.encode('ascii'))")

    def test_service_mtls_and_exact_boolean_identity_precede_effective_admission(self):
        _, tree = read_source("serverware/authority_service.py", 2 * 1024 * 1024)
        aliases = [alias for node in tree.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware.authority_store.verifier_read_sql" for alias in node.names]
        self.assertEqual([(alias.name, alias.asname) for alias in aliases],
                         [("verifier_read_privilege_check", None)])
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "AuthorityProcess"]
        self.assertEqual(len(classes), 1)
        reader = function(classes[0], "_read_webauthn_authority")
        identity = assignment(reader, "identity")
        identity_guard = raising_guard(reader, "WebAuthn authority read role changed")
        self.assert_shape(identity_guard.test,
            "identity is None or identity['role'] != self.role_config['databaseRole'] "
            "or identity.get('ssl') is not True or identity.get('rolcanlogin') is not True "
            "or identity['client_dn'] != self.role_config['tlsClientDn'] "
            "or identity['client_serial'] != self.role_config['tlsClientSerial'] "
            "or identity['issuer_dn'] != self.role_config['tlsIssuerDn'] "
            "or any(identity.get(field) is not False for field in "
            "('rolsuper', 'rolcreaterole', 'rolcreatedb', 'rolreplication', 'rolbypassrls', "
            "'schema_create', 'database_create', 'database_temporary'))")
        identity_sql = identity.value.func.value.args[0].value
        for fragment in ("FROM pg_catalog.pg_stat_ssl AS ssl", "role_record.rolcanlogin",
                         "current_user::pg_catalog.regrole::oid", "WHERE ssl.pid = pg_catalog.pg_backend_pid()"):
            self.assertIn(fragment, identity_sql)
        checked = assignment(reader, "forbidden_authority")
        query = checked.value.func.value
        self.assert_shape(query.func, "cursor.execute")
        self.assertEqual(len(query.args), 1)
        self.assertIsInstance(query.args[0], ast.Starred)
        self.assert_shape(query.args[0].value,
            "verifier_read_privilege_check(role=self.role_config['databaseRole'], namespace='serverware_metadata')")
        denial = raising_guard(reader, "WebAuthn authority read role is privileged")
        self.assert_shape(denial.test, "forbidden_authority is not None")
        self.assertLess(identity.lineno, identity_guard.lineno)
        self.assertLess(identity_guard.end_lineno, checked.lineno)
        self.assertLess(checked.lineno, denial.lineno)
        for name in ("challenge_row", "credential_row", "trust_rows", "pending_trust"):
            self.assertLess(denial.end_lineno, assignment(reader, name).lineno)

    def test_live_webauthn_reader_uses_exact_four_tables_without_granting_historical_helpers(self):
        _, tree = read_source("serverware/authority_service.py", 2 * 1024 * 1024)
        process = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "AuthorityProcess")
        reader = function(process, "_read_webauthn_authority")
        actual_tables = set()
        for call in calls(reader, "execute"):
            if not call.args:
                continue
            strings = [node.value for node in ast.walk(call.args[0])
                       if isinstance(node, ast.Constant) and type(node.value) is str]
            for text in strings:
                actual_tables.update(re.findall(r"(?:FROM|JOIN) serverware_metadata\.([a-z_]+)", text))
        self.assertEqual(actual_tables, EVIDENCE_TABLES)
        self.assertEqual(len(calls(reader, "verifier_read_privilege_check")), 1)
        evidence = function(process, "_build_v9_webauthn_evidence")
        self.assertEqual(len(calls(evidence, "_read_webauthn_authority")), 1)
        # Deliberately no assertion that retained historical root/outcome
        # methods have this read closure or that they are now authorized.
        self.assertTrue(EVIDENCE_TABLES.isdisjoint({"policy_authority_authenticated_table_roots",
                                                  "policy_authority_counted_index_heads"}))
        self.assertTrue(TABLES.isdisjoint({"policy_authority_writer_capabilities", "credentials",
            "policy_authority_authenticated_tree_nodes", "policy_authority_authenticated_leaves",
            "policy_authority_counted_index_nodes", "policy_authority_counted_index_leaves",
            "policy_authority_webauthn_evidence_retained_plans"}))


if __name__ == "__main__":
    unittest.main()
