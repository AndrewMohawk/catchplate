#!/usr/bin/env python3
"""Bounded source contracts for issuer signatures and transaction ownership.

Only the real inert operation contract is imported. AST inspection does not
import db/service/registry, evaluate extracted functions, open a connection or
substitute a successful ACL verdict. These authored controls are not native
GRANT/catalog, mTLS, effective-role, transaction or production admission proof.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re
import sys
from types import MappingProxyType
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract


SIGNATURES = {
    "serverware_policy_authority_issue_capability": ("text",) * 4,
    "serverware_policy_authority_issue_writer_capability": ("text",) * 5,
    "serverware_policy_authority_record_witness_receipt": ("text",) * 4,
}
ARGUMENTS = {
    "serverware_policy_authority_issue_capability": ("capability_json", "supplied_capability_digest",
        "supplied_issuer_measurement_digest", "supplied_issuer_attestation_receipt_digest"),
    "serverware_policy_authority_issue_writer_capability": ("capability_json", "supplied_capability_digest",
        "supplied_issuer_measurement_digest", "supplied_issuer_attestation_receipt_digest",
        "supplied_issuer_credential_issuance_digest"),
    "serverware_policy_authority_record_witness_receipt": ("witness_receipt_json", "supplied_witness_receipt_digest",
        "supplied_issuer_measurement_digest", "supplied_issuer_attestation_receipt_digest"),
}
TRANSACTION_SQL = "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE"
SEARCH_PATH_SQL = "SET search_path TO serverware_metadata, pg_catalog, pg_temp"


def read_source(relative, maximum=2 * 1024 * 1024):
    path = ROOT / relative
    if path.stat().st_size > maximum:
        raise AssertionError("issuer source exceeds the explicit inspection bound")
    value = path.read_text(encoding="utf-8")
    return value, ast.parse(value)


def named(node, kind, name):
    found = [item for item in node.body if isinstance(item, kind) and item.name == name]
    if len(found) != 1:
        raise AssertionError("issuer source definition is not unique: " + name)
    return found[0]


def assignment(node, name):
    found = [item for item in ast.walk(node) if isinstance(item, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in item.targets)]
    if len(found) != 1:
        raise AssertionError("issuer source assignment is not unique: " + name)
    return found[0]


def calls(node, expression):
    return sorted((item for item in ast.walk(node) if isinstance(item, ast.Call)
        and ast.unparse(item.func) == expression), key=lambda item: (item.lineno, item.col_offset))


def constant_sql(node, variable):
    call = calls(assignment(node, variable), "cur.execute")
    if len(call) != 1 or not call[0].args or not isinstance(call[0].args[0], ast.Constant):
        raise AssertionError("issuer catalog SQL is not one fixed string: " + variable)
    return call[0].args[0].value, call[0].args[1]


class AuthorityIssuerSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db_source, cls.db = read_source("serverware/db.py", 16 * 1024 * 1024)
        cls.schema_source, cls.schema = read_source("serverware/authority_store/schema.py")
        cls.service_source, cls.service = read_source("serverware/authority_service.py")
        cls.executor_source, cls.executor = read_source("serverware/authority_store/executor_v9.py")
        cls.migration_source, cls.migration = read_source("scripts/authority/migrate_v8_to_v9.py")
        cls.seal = named(cls.db, ast.FunctionDef, "_seal_postgres_schema_acl")
        cls.connector = named(cls.db, ast.FunctionDef, "_policy_authority_capability_issuer_pg_connect_raw")
        cls.owner = named(cls.db, ast.FunctionDef, "_validate_policy_authority_owner_apply_function")
        cls.process = named(cls.service, ast.ClassDef, "AuthorityProcess")

    def assert_shape(self, actual, expression):
        self.assertEqual(ast.dump(actual),
            ast.dump(ast.parse("(" + expression.strip() + ")", mode="eval").body))

    def test_existing_three_issuer_signatures_and_argument_names_are_immutable_exact_maps(self):
        self.assertIs(type(authority_contract.CAPABILITY_ISSUER_FUNCTION_SIGNATURES), MappingProxyType)
        self.assertIs(type(authority_contract.CAPABILITY_ISSUER_FUNCTION_ARGUMENTS), MappingProxyType)
        self.assertEqual(dict(authority_contract.CAPABILITY_ISSUER_FUNCTION_SIGNATURES), SIGNATURES)
        self.assertEqual(dict(authority_contract.CAPABILITY_ISSUER_FUNCTION_ARGUMENTS), ARGUMENTS)
        self.assertEqual(set(SIGNATURES), set(ARGUMENTS))
        self.assertEqual(tuple(len(SIGNATURES[name]) for name in sorted(SIGNATURES)), (4, 5, 4))
        for name in SIGNATURES:
            self.assertIs(type(authority_contract.CAPABILITY_ISSUER_FUNCTION_SIGNATURES[name]), tuple)
            self.assertIs(type(authority_contract.CAPABILITY_ISSUER_FUNCTION_ARGUMENTS[name]), tuple)
            self.assertEqual(len(SIGNATURES[name]), len(ARGUMENTS[name]))
        with self.assertRaises(TypeError):
            authority_contract.CAPABILITY_ISSUER_FUNCTION_SIGNATURES["caller_added_overload"] = ("text",)

    def test_actual_final_sql_producers_match_four_five_four_argument_inventory(self):
        guard = named(self.db, ast.FunctionDef, "_install_policy_candidate_authority_guards")
        installer = named(self.executor, ast.FunctionDef, "install_authority_v9_executor")
        for name in sorted(SIGNATURES):
            source = (ast.get_source_segment(self.db_source, guard)
                if name == "serverware_policy_authority_issue_capability"
                else ast.get_source_segment(self.executor_source, installer))
            matches = re.findall(r"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+\{\w+\}\.\s*"
                + re.escape(name) + r"\s*\((.*?)\)\s*RETURNS\s+text\s+LANGUAGE\s+plpgsql\s+SECURITY\s+DEFINER",
                source, re.S)
            self.assertEqual(len(matches), 1, name)
            actual = tuple(tuple(item.strip().split()) for item in matches[0].split(","))
            self.assertEqual(actual, tuple(zip(ARGUMENTS[name], SIGNATURES[name])))
        source = ast.get_source_segment(self.executor_source, installer)
        self.assertRegex(source, r"DROP FUNCTION IF EXISTS \{namespace\}\.\s*"
            r"serverware_policy_authority_issue_writer_capability\(\s*text, text, text, text\s*\)")

    def test_signature_tuple_and_all_four_authority_callers_derive_from_the_actual_contract(self):
        self.assert_shape(assignment(self.db,
            "_POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTION_SIGNATURES").value,
            "tuple((function_name, tuple(argument_types)) for function_name, argument_types "
            "in sorted({**authority_contract.CAPABILITY_ISSUER_FUNCTION_SIGNATURES, "
            "**authority_contract.REVOCATION_CAPABILITY_ISSUER_FUNCTION_SIGNATURES}.items()))")
        self.assert_shape(assignment(self.db,
            "_POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTIONS").value,
            "frozenset(function_name for function_name, _argument_types "
            "in _POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTION_SIGNATURES)")
        passed = []
        omitted = []
        for tree, function, prefix in ((self.db, "_seal_postgres_schema_acl", ""),
                (self.schema, "_seal_postgres_schema_acl", ""),
                (self.migration, "db._seal_postgres_schema_acl", "db.")):
            for call in calls(tree, function):
                keywords = {item.arg: item.value for item in call.keywords}
                self.assertNotIn("authority_capability_issuer_functions", keywords)
                argument = keywords.get("authority_capability_issuer_function_signatures")
                if argument is not None:
                    self.assert_shape(argument,
                        prefix + "_POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTION_SIGNATURES")
                    passed.append((function, ast.unparse(keywords["schema"])))
                else:
                    omitted.append(ast.unparse(keywords["schema"]))
        self.assertCountEqual(passed, [
            ("_seal_postgres_schema_acl", "_POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME"),
            ("_seal_postgres_schema_acl", "scratch_schema"),
            ("_seal_postgres_schema_acl", "_POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME"),
            ("db._seal_postgres_schema_acl", "db._POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME"),
        ])
        self.assertCountEqual(omitted, ["_RECOVERY_WITNESS_POSTGRES_SCHEMA", "_AUDIT_POSTGRES_SCHEMA"])

    def test_exact_signature_guard_precedes_cursor_and_permits_empty_only_outside_authority_schemas(self):
        defaults = {arg.arg: value for arg, value in
            zip(self.seal.args.kwonlyargs, self.seal.args.kw_defaults)}
        self.assertNotIn("authority_capability_issuer_functions", defaults)
        self.assert_shape(defaults["authority_capability_issuer_function_signatures"], "()")
        guards = [node for node in self.seal.body if isinstance(node, ast.If)
            and any(isinstance(item, ast.Raise) and isinstance(item.exc, ast.Call)
                and item.exc.args and isinstance(item.exc.args[0], ast.Constant)
                and item.exc.args[0].value == "capability issuer function closure is not source exact"
                for item in node.body)]
        self.assertEqual(len(guards), 1)
        # Pin the real complete predicate, not an evaluated copy of the guard.
        # Exact ordered equality rejects duplicates, reordering and wrong
        # arities; metadata and the expected-v9 scratch schema cannot omit it.
        self.assert_shape(guards[0].test, """
            type(authority_capability_issuer_function_signatures) is not tuple
            or len(authority_capability_issuer_function_signatures) not in
                {0, len(_POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTION_SIGNATURES)}
            or any(type(entry) is not tuple or len(entry) != 2
                or type(entry[0]) is not str or len(entry[0]) > 63
                or type(entry[1]) is not tuple or len(entry[1]) not in {4, 5, 6, 8}
                or any(type(argument) is not str or argument != 'text' for argument in entry[1])
                for entry in authority_capability_issuer_function_signatures)
            or ((authority_capability_issuer_function_signatures or schema in
                {_POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME, 'serverware_candidate_authority_expected_v9'})
                and authority_capability_issuer_function_signatures
                    != _POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTION_SIGNATURES)
        """)
        cursors = calls(self.seal, "conn.cursor")
        self.assertEqual(len(cursors), 1)
        self.assertLess(guards[0].end_lineno, cursors[0].lineno)
        self.assertLess(guards[0].end_lineno, calls(self.seal, "cur.execute")[0].lineno)
        self.assert_shape(assignment(self.seal, "issuer_function_types").value,
            "{name: ', '.join(types) for name, types in authority_capability_issuer_function_signatures}")
        self.assert_shape(assignment(self.seal, "issuer_function_identities").value,
            "sorted(name + '(' + types + ')' for name, types in issuer_function_types.items())")

    def test_real_grant_loop_uses_each_exact_signature_without_grant_option(self):
        loops = [node for node in ast.walk(self.seal) if isinstance(node, ast.For)
            and ast.unparse(node.iter) == "authority_capability_issuer_function_signatures"]
        self.assertEqual(len(loops), 1)
        self.assertEqual(ast.unparse(loops[0].target), "(function, argument_types)")
        self.assert_shape(assignment(loops[0], "function_name").value,
            "_policy_candidate_authority_identifier(function)")
        grant = calls(loops[0], "cur.execute")
        self.assertEqual(len(grant), 1)
        self.assertEqual(len(grant[0].args), 1)
        self.assert_shape(grant[0].args[0],
            "'GRANT EXECUTE ON FUNCTION ' + schema_name + '.' + function_name "
            "+ '(' + ', '.join(argument_types) + ') TO ' + capability_issuer_role_name")
        containers = [node for node in ast.walk(self.seal) if isinstance(node, ast.If)
            and loops[0] in node.body]
        self.assertEqual(len(containers), 1)
        self.assert_shape(containers[0].test,
            "capability_issuer_role not in {runtime_role, executor_role, verifier_role}")

    def test_sealer_catalog_matches_exact_types_acl_flags_and_search_path(self):
        unexpected, parameters = constant_sql(self.seal, "unexpected_function")
        self.assertEqual(unexpected.count("pg_catalog.oidvectortypes(function_record.proargtypes)"), 3)
        self.assertEqual(unexpected.count("grant_entry.privilege_type = 'EXECUTE'"), 3)
        self.assertEqual(unexpected.count("AND NOT grant_entry.is_grantable"), 3)
        self.assertIn("AND NOT COALESCE((", unexpected)
        self.assertTrue(unexpected.endswith("), FALSE) LIMIT 1"))
        self.assertNotIn("pg_get_function_identity_arguments", unexpected)
        self.assert_shape(parameters, "(schema, executor_role, sorted(authority_executor_function_identities), "
            "capability_issuer_role, issuer_function_identities, planner_writer_role, planner_function_identities)")
        query, parameters = constant_sql(self.seal, "capability_issuer_function_grants")
        self.assertIn("pg_catalog.oidvectortypes(function_record.proargtypes) AS argument_types", query)
        for fragment in ("function_record.prosecdef", "function_record.proconfig",
                "function_record.proisstrict", "function_record.provolatile",
                "grant_entry.privilege_type", "grant_entry.is_grantable"):
            self.assertIn(fragment, query)
        self.assert_shape(parameters, "(schema, capability_issuer_role)")
        self.assert_shape(assignment(self.seal, "exact_capability_issuer_functions").value, """
            len(capability_issuer_function_grants) == len(authority_capability_issuer_function_signatures)
            and {str(grant['proname']) + '(' + str(grant['argument_types']) + ')'
                for grant in capability_issuer_function_grants} == set(issuer_function_identities)
            and all(str(grant['privilege_type']) == 'EXECUTE'
                and grant['is_grantable'] is False
                and str(grant['argument_types']) == issuer_function_types[str(grant['proname'])]
                and grant['prosecdef'] is True and grant['proisstrict'] is False
                and str(grant['provolatile']) == 'v'
                and list(grant['proconfig'] or ()) == [expected_function_search_path]
                for grant in capability_issuer_function_grants)
        """)
        self.assert_shape(assignment(self.seal, "expected_function_search_path").value,
            "'search_path=pg_catalog, ' + schema + ', pg_temp'")
        failures = [node for node in ast.walk(self.seal) if isinstance(node, ast.If)
            and any(isinstance(item, ast.Raise) for item in node.body)
            and "not exact_capability_issuer_functions" in ast.unparse(node.test)]
        self.assertEqual(len(failures), 1)

    def test_owner_admission_denies_overloads_and_binds_exact_issuer_types_and_acl(self):
        query, parameters = constant_sql(self.owner, "function_rows")
        self.assertIn("pg_catalog.oidvectortypes(function_record.proargtypes) AS argument_types", query)
        self.assert_shape(parameters, "(_POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME, closure_function_names)")
        closure = [node for node in self.owner.body if isinstance(node, ast.If)
            and any(isinstance(item, ast.Raise) and isinstance(item.exc, ast.Call)
                and item.exc.args and isinstance(item.exc.args[0], ast.Constant)
                and item.exc.args[0].value == "owner policy-authority implementation closure is incomplete"
                for item in node.body)]
        self.assertEqual(len(closure), 1)
        self.assert_shape(closure[0].test, "len(function_rows) != len(closure_function_names) "
            "or [str(row['proname']) for row in function_rows] != closure_function_names")
        query, parameters = constant_sql(self.owner, "unexpected_grant")
        self.assertLess(closure[0].end_lineno, assignment(self.owner, "unexpected_grant").lineno)
        self.assertEqual(query.count("pg_catalog.oidvectortypes(function_record.proargtypes)"), 3)
        self.assertEqual(query.count("grant_entry.privilege_type = 'EXECUTE'"), 3)
        self.assertEqual(query.count("AND NOT grant_entry.is_grantable"), 3)
        self.assertIn("AND NOT COALESCE((", query)
        self.assertTrue(query.endswith("), FALSE) LIMIT 1"))
        self.assertNotIn("pg_get_function_identity_arguments", query)
        self.assertEqual(len(parameters.elts), 7)
        self.assert_shape(parameters.elts[3], "sorted(name + '(' + ', '.join(types) + ')' "
            "for name, types in _POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTION_SIGNATURES)")
        self.assert_shape(parameters.elts[4], "_METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE")
        self.assert_shape(assignment(self.owner, "issuer_function_types").value,
            "{name: ', '.join(types) for name, types in _POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTION_SIGNATURES}")
        issuer = [call for call in calls(self.owner, "any")
            if call.args and isinstance(call.args[0], ast.GeneratorExp)
            and any(ast.unparse(clause) == "row['proname'] in issuer_function_types"
                for generator in call.args[0].generators for clause in generator.ifs)]
        self.assertEqual(len(issuer), 1)
        self.assert_shape(issuer[0], """any(
            str(row['argument_types']) != issuer_function_types[row['proname']]
            or row['prosecdef'] is not True or row['proisstrict'] is not False
            or str(row['provolatile']) != 'v'
            or list(row['proconfig'] or ()) != [expected_search_path]
            for row in function_rows if row['proname'] in issuer_function_types)
        """)
        denying = [node for node in self.owner.body if isinstance(node, ast.If)
            and any(item is issuer[0] for item in ast.walk(node.test))]
        self.assertEqual(len(denying), 1)
        self.assertIn("unexpected_grant is not None", ast.unparse(denying[0].test))
        self.assertTrue(any(isinstance(item, ast.Raise) for item in denying[0].body))

    def test_owner_dependency_order_collates_expressions_and_retains_output_fields(self):
        # PostgreSQL cannot resolve SELECT aliases inside COLLATE expressions.
        # Inspect the actual fixed query only; this is not catalog/SQL proof.
        query, parameters = constant_sql(self.owner, "dependency_rows")
        projection, ordering = query.rsplit(") SELECT ", 1)[1].split(" FROM dependency_graph ORDER BY ")
        self.assertEqual(projection,
            "classid::pg_catalog.regclass::text AS catalog, objid, objsubid, "
            "pg_catalog.pg_describe_object(classid, objid, objsubid) AS object_description")
        self.assertEqual(ordering,
            'classid::pg_catalog.regclass::text COLLATE "C", '
            'pg_catalog.pg_describe_object(classid, objid, objsubid) COLLATE "C", '
            "objid, objsubid")
        self.assertEqual(query.count('COLLATE "C"'), 2)
        self.assertEqual(query.count("%s"), 1)
        self.assert_shape(parameters, "([row['oid'] for row in function_rows],)")

    def test_raw_connector_sets_exact_writer_transaction_before_any_other_sql(self):
        connect = calls(self.connector, "psycopg.connect")
        self.assertEqual(len(connect), 1)
        keywords = {item.arg: item.value for item in connect[0].keywords}
        self.assertEqual(set(keywords), {"connect_timeout", "row_factory", "options", "autocommit"})
        self.assert_shape(keywords["autocommit"], "False")
        self.assert_shape(keywords["options"], "'-c search_path=pg_catalog'")
        self.assert_shape(keywords["connect_timeout"], "METADATA_STORE_CONNECT_TIMEOUT_SECONDS")
        self.assert_shape(keywords["row_factory"], "dict_row")
        self.assert_shape(connect[0].args[0], "dsn")
        statements = calls(self.connector, "cur.execute")
        self.assertEqual(len(statements), 5)
        self.assertEqual([item.args[0].value for item in statements[:2]], [TRANSACTION_SQL, SEARCH_PATH_SQL])
        self.assertLess(connect[0].lineno, statements[0].lineno)
        cursor_scopes = [node for node in ast.walk(self.connector) if isinstance(node, ast.With)
            and any(isinstance(item.context_expr, ast.Call)
                    and ast.unparse(item.context_expr.func) == "conn.cursor" for item in node.items)]
        self.assertEqual(len(cursor_scopes), 1)
        self.assertIs(cursor_scopes[0].body[0].value, statements[0])
        self.assertFalse(calls(self.connector, "conn.transaction"))
        self.assertFalse(calls(self.connector, "conn.commit"))
        self.assertFalse(calls(self.connector, "conn.rollback"))

    def test_connector_readback_requires_serializable_read_write_not_deferrable_and_original_identity(self):
        # This query has no parameters; use the actual unique execute rather
        # than pretending that its returned row proves a live PostgreSQL role.
        query = calls(assignment(self.connector, "identity"), "cur.execute")
        self.assertEqual(len(query), 1)
        self.assertEqual(len(query[0].args), 1)
        identity = query[0].args[0].value
        for fragment in ("current_setting('transaction_isolation') AS transaction_isolation",
                "current_setting('transaction_read_only') AS read_only",
                "current_setting('transaction_deferrable') AS deferrable",
                "current_user = session_user AS exact_session", "ssl.client_dn",
                "ssl.client_serial::text AS client_serial", "ssl.issuer_dn"):
            self.assertIn(fragment, identity)
        guard = next(node for node in ast.walk(self.connector) if isinstance(node, ast.If)
            and any(isinstance(statement, ast.Raise) and isinstance(statement.exc, ast.Call)
                and statement.exc.args and isinstance(statement.exc.args[0], ast.Constant)
                and statement.exc.args[0].value == "policy-authority capability issuer session is not exact"
                for statement in node.body))
        conditions = {ast.dump(node) for node in ast.walk(guard.test)}
        for expression in ("identity['transaction_isolation'] != 'serializable'",
                "identity['read_only'] != 'off'", "identity['deferrable'] != 'off'",
                "identity['current_role'] != _METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE",
                "direct_authority is not None", "inherited_authority is not None"):
            self.assertIn(ast.dump(ast.parse(expression, mode="eval").body), conditions)
        self.assertLess(query[0].lineno, guard.lineno)
        for name, fragment in (("direct_authority", "has_table_privilege"),
                               ("inherited_authority", "pg_catalog.pg_auth_members")):
            query = calls(assignment(self.connector, name), "cur.execute")
            self.assertEqual(len(query), 1)
            self.assertIn(fragment, query[0].args[0].value)
            self.assertLess(query[0].lineno, guard.lineno)

    def test_connector_closes_only_failed_admission_and_preserves_the_original_base_exception(self):
        body = [node for node in self.connector.body if isinstance(node, ast.Try)]
        self.assertEqual(len(body), 1)
        failure = body[0].handlers
        self.assertEqual(len(failure), 1)
        self.assert_shape(failure[0].type, "BaseException")
        cleanup, reraise = failure[0].body
        self.assertIsInstance(cleanup, ast.Try)
        self.assertEqual(len(cleanup.body), 1)
        self.assert_shape(cleanup.body[0].value, "conn.close()")
        self.assertEqual(len(cleanup.handlers), 1)
        self.assert_shape(cleanup.handlers[0].type, "BaseException")
        self.assertEqual(len(cleanup.handlers[0].body), 1)
        self.assertIsInstance(cleanup.handlers[0].body[0], ast.Pass)
        self.assertIsInstance(reraise, ast.Raise)
        self.assertIsNone(reraise.exc)
        self.assertFalse(body[0].finalbody)
        self.assertFalse(body[0].orelse)
        self.assertEqual(len(calls(self.connector, "conn.close")), 1)
        self.assertIsInstance(self.connector.body[-1], ast.Return)
        self.assert_shape(self.connector.body[-1].value, "conn")

    def test_both_real_service_callers_check_results_before_caller_owned_transaction_exit(self):
        cases = (("_handle_issue", "database capability issuance failed",
                  "serverware_policy_authority_issue_writer_capability", 5),
                 ("_handle_record_witness_receipt", "database witness receipt persistence failed",
                  "serverware_policy_authority_record_witness_receipt", 4))
        for name, message, function_name, count in cases:
            with self.subTest(handler=name):
                method = named(self.process, ast.FunctionDef, name)
                outer = [node for node in method.body if isinstance(node, ast.With)]
                self.assertEqual(len(outer), 1)
                self.assert_shape(outer[0].items[0].context_expr,
                    "db._policy_authority_capability_issuer_pg_connect_raw()")
                self.assertEqual(ast.unparse(outer[0].items[0].optional_vars), "connection")
                self.assertEqual(len(outer[0].body), 1)
                transaction = outer[0].body[0]
                self.assertIsInstance(transaction, ast.With)
                self.assert_shape(transaction.items[0].context_expr, "connection.transaction()")
                cursor, check = transaction.body
                self.assertIsInstance(cursor, ast.With)
                self.assert_shape(cursor.items[0].context_expr, "connection.cursor()")
                self.assertIsInstance(check, ast.If)
                self.assertEqual(len(check.body), 1)
                self.assertIsInstance(check.body[0], ast.Raise)
                self.assertEqual(check.body[0].exc.args[0].value, message)
                actual = calls(cursor, "cursor.execute")
                self.assertEqual(len(actual), 1)
                # The issue handler retains its existing literal '+' join.
                literals = [node.value for node in ast.walk(actual[0].args[0])
                    if isinstance(node, ast.Constant) and type(node.value) is str]
                sql = "".join(literals)
                self.assertIn(function_name, sql)
                self.assertEqual(sql.count("%s"), count)
                self.assertIsInstance(actual[0].args[1], ast.Tuple)
                self.assertEqual(len(actual[0].args[1].elts), count)
                self.assertLess(actual[0].lineno, check.lineno)
                self.assertFalse(calls(method, "connection.commit"))
                self.assertFalse(calls(method, "connection.rollback"))
                self.assertIsInstance(method.body[-1], ast.Return)
                self.assertGreater(method.body[-1].lineno, transaction.end_lineno)


if __name__ == "__main__":
    unittest.main()
