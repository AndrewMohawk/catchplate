#!/usr/bin/env python3
"""Pure planner-writer privilege SQL and nonimporting integration controls.

Call the real inert SQL builder and inspect bounded source ASTs. Cursor
lifecycle regressions execute actual persistence suffixes with synthetic
cursors; they exclude the preceding plan/connection admission.
No db/service import, registry replacement or successful catalog result is
supplied. These controls are not PostgreSQL ACL, TLS, role, migration,
transaction or whole-service admission evidence.
"""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import re
import sys
import unittest
from pathlib import Path
from types import MappingProxyType


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.authority_store import planner_writer_sql as writer


TABLE_PRIVILEGES = {
    "policy_authority_authorization_dependency_manifests": frozenset({"SELECT"}),
    "policy_authority_authorization_projections": frozenset({"SELECT", "INSERT"}),
    "policy_authority_execution_envelopes": frozenset({"SELECT", "INSERT", "UPDATE"}),
    "policy_authority_fence_heads": frozenset({"SELECT"}),
    "policy_authority_operation_mutation_templates": frozenset({"SELECT"}),
    "policy_authority_planner_transactions": frozenset({"SELECT", "INSERT", "UPDATE"}),
    "policy_authority_revocation_retained_plans": frozenset({"SELECT", "INSERT"}),
    "policy_authority_recovery_invalidation_retained_plans": frozenset({"SELECT", "INSERT"}),
    "policy_authority_recovery_history_pages": frozenset({"SELECT", "INSERT"}),
    "policy_authority_challenge_maintenance_pages": frozenset({"SELECT", "INSERT"}),
    "policy_authority_jit_original_pages": frozenset({"SELECT", "INSERT"}),
    "policy_authority_revocation_writer_requests": frozenset({"SELECT", "INSERT"}),
    "policy_authority_revocation_writer_acknowledgments": frozenset({"SELECT", "INSERT"}),
    "policy_authority_query_dependency_manifests": frozenset({"SELECT"}),
    "policy_authority_authenticated_table_roots": frozenset({"SELECT"}),
    "policy_authority_webauthn_assertion_evidence": frozenset({"SELECT", "INSERT"}),
    "policy_authority_webauthn_evidence_retained_plans": frozenset({"SELECT", "INSERT"}),
    "policy_authority_webauthn_transition_retained_plans": frozenset({"SELECT", "INSERT"}),
    "policy_authority_writer_capabilities": frozenset({"SELECT", "UPDATE"}),
}
FUNCTION_SIGNATURES = (
    ("serverware_policy_authority_assert_audit_capacity", ("text", "jsonb", "jsonb", "bigint")),
    ("serverware_policy_authority_domain_digest", ("text", "text[]")),
    ("serverware_policy_authority_wire_json", ("jsonb",)),
    ("serverware_policy_authority_wire_string", ("text", "boolean", "bigint")),
    ("serverware_policy_authority_wire_walk", ("jsonb", "integer", "bigint", "bigint", "boolean")),
)


def source(relative, maximum=2 * 1024 * 1024):
    path = ROOT / relative
    if path.stat().st_size > maximum:
        raise AssertionError("source exceeds the explicit fixture bound")
    text = path.read_text(encoding="utf-8")
    return text, ast.parse(text)


def function(tree, name):
    matches = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(matches) != 1:
        raise AssertionError("source function is not unique: " + name)
    return matches[0]


def assigned(tree, name):
    matches = [node.value for node in ast.walk(tree) if
        isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
            and target.id == name for target in node.targets)]
    if len(matches) != 1:
        raise AssertionError("source assignment is not unique: " + name)
    return matches[0]


def calls(tree, name):
    return sorted((node for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and ast.unparse(node.func) == name), key=lambda node: node.lineno)


def call(tree, name):
    matches = calls(tree, name)
    if len(matches) != 1:
        raise AssertionError("source call is not unique: " + name)
    return matches[0]


def entries(node):
    if not isinstance(node, ast.Dict) or any(not isinstance(key, ast.Constant)
            or type(key.value) is not str for key in node.keys):
        raise AssertionError("source material is not a literal-key mapping")
    names = [key.value for key in node.keys]
    if len(names) != len(set(names)):
        raise AssertionError("source material repeats a key")
    return dict(zip(names, node.values))


def raising_guard(tree, message):
    matches = [node for node in ast.walk(tree) if isinstance(node, ast.If)
               and any(isinstance(statement, ast.Raise) and isinstance(statement.exc, ast.Call)
                       and statement.exc.args and isinstance(statement.exc.args[0], ast.Constant)
                       and statement.exc.args[0].value == message for statement in node.body)]
    if len(matches) != 1:
        raise AssertionError("source rejection guard is not unique: " + message)
    return matches[0]


class AuthorityPlannerWriterSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module_source, cls.module = source("serverware/authority_store/planner_writer_sql.py", 128 * 1024)
        cls.db_source, cls.db = source("serverware/db.py", 16 * 1024 * 1024)
        cls.schema_source, cls.schema = source("serverware/authority_store/schema.py")
        cls.seal = function(cls.db, "_seal_postgres_schema_acl")

    def assert_shape(self, node, expression):
        # Fixed expected syntax is parsed, never evaluated or extracted.
        self.assertEqual(ast.dump(node), ast.dump(ast.parse(expression, mode="eval").body))

    def test_completion_cas_snapshots_update_count_before_cursor_reuse_and_close(self):
        from collections.abc import Mapping
        from typing import Any
        from serverware import authority_transition_registry
        from serverware.authority_store.audit_capacity_sql import AUDIT_CAPACITY_FUNCTION_NAME

        # Execute the actual persistence suffix only, not fabricated admission.
        # The SQL boundary double follows psycopg: execute returns self, SELECT
        # replaces rowcount, and cursor close resets it to -1.
        _, module = source("serverware/authority_store/executor_v9.py")
        completion = function(module, "complete_authority_planner_transaction")
        start = next(i for i, node in enumerate(completion.body)
                     if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                         and target.id == "plan_base64url" for target in node.targets))
        self.assertEqual(ast.unparse(completion.body[start - 1]),
                         "raw = _require_planner_writer(connection)")
        wrapper = ast.parse("def persistence_tail(*, raw, exact_plan_bytes, planner_transaction_id, "
            "authorization_projection_digest, planned_at_epoch_ns, plan, selected_json, mutation_json, "
            "planner_identity):\n    pass\n").body[0]
        wrapper.body = copy.deepcopy(completion.body[start:])

        class StoreError(Exception):
            pass

        namespace = dict(base64=base64, hashlib=hashlib, Mapping=Mapping, Any=Any,
            authority_transition_registry=authority_transition_registry,
            AUDIT_CAPACITY_FUNCTION_NAME=AUDIT_CAPACITY_FUNCTION_NAME,
            _db_value={"MetadataStoreError": StoreError}.__getitem__)
        component = ast.Module(body=[copy.deepcopy(function(module, "_b64url")),
            copy.deepcopy(function(module, "_require_v3_planner_row")), wrapper], type_ignores=[])
        exec(compile(ast.fix_missing_locations(component), "<actual-completion-persistence-suffix>", "exec"), namespace)

        plan_to_row = {
            "operation": "operation", "operationId": "operation_id",
            "requestDigest": "request_digest", "capabilityId": "capability_id",
            "operationContractDigest": "operation_contract_digest",
            "queryManifestDigest": "query_manifest_digest",
            "selectedBusinessRowsDigest": "selected_business_rows_digest",
            "mutationPlanDigest": "mutation_plan_digest", "workUnits": "work_units",
            "authorityRootSetBeforeDigest": "authority_root_set_before_digest",
            "deadlineMonotonicNs": "deadline_monotonic_ns", "deadlineEpochNs": "deadline_epoch_ns",
            "fence": "fence",
        }
        plan = {key: "sha256:" + "1" * 64 for key in plan_to_row}
        plan.update(operation="webauthn.challenge.create", workUnits=1,
                    deadlineMonotonicNs=2, deadlineEpochNs=3, fence=4,
                    authoritySnapshotDigest="sha256:" + "2" * 64)
        identity = dict(sessionIdentityDigest="sha256:" + "3" * 64,
                        measurementDigest="sha256:" + "4" * 64,
                        attestationReceiptDigest="sha256:" + "5" * 64)
        exact = b'{"syntheticPersistenceSuffix":true}'
        row = {field: plan[key] for key, field in plan_to_row.items()}
        row.update(plan_protocol="v3", retained_record_digest=None, status="planned",
            authorization_projection_digest="sha256:" + "6" * 64,
            authority_snapshot_digest=plan["authoritySnapshotDigest"],
            exact_plan_base64url=base64.urlsafe_b64encode(exact).rstrip(b"=").decode("ascii"),
            exact_plan_bytes_digest="sha256:" + hashlib.sha256(exact).hexdigest(),
            exact_plan_byte_count=len(exact), planned_at_epoch_ns=10,
            selected_business_rows_json="[]", mutation_plan_json="[]",
            planner_session_identity_digest=identity["sessionIdentityDigest"],
            planner_measurement_digest=identity["measurementDigest"],
            planner_attestation_receipt_digest=identity["attestationReceiptDigest"])
        arguments = dict(exact_plan_bytes=exact, planner_transaction_id="sha256:" + "7" * 64,
            authorization_projection_digest=row["authorization_projection_digest"],
            planned_at_epoch_ns=10, plan=plan, selected_json="[]", mutation_json="[]",
            planner_identity=identity)

        class Cursor:
            def __init__(self, count, returned_row):
                self.update_count = count
                self.returned_row = returned_row
                self.rowcount = -1
                self.steps = 0
                self.closed = False

            def cursor(self):
                return self

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                self.rowcount = -1
                self.closed = True

            def execute(self, statement, parameters):
                self.steps += 1
                if self.steps in (1, 4):
                    expected = "SELECT * FROM serverware_metadata.policy_authority_planner_transactions "
                    if not statement.startswith(expected) or parameters != (arguments["planner_transaction_id"],):
                        raise AssertionError("unexpected synthetic planner-row read")
                    self.rowcount = 1
                elif self.steps == 2:
                    if not statement.startswith("SELECT serverware_metadata." + AUDIT_CAPACITY_FUNCTION_NAME + "("):
                        raise AssertionError("unexpected synthetic capacity call")
                    self.rowcount = 1
                elif self.steps == 3:
                    if not statement.startswith("UPDATE serverware_metadata.policy_authority_planner_transactions "):
                        raise AssertionError("unexpected synthetic completion update")
                    self.rowcount = self.update_count
                else:
                    raise AssertionError("unexpected synthetic SQL step")
                return self

            def fetchone(self):
                return dict(row) if self.steps == 1 else copy.deepcopy(self.returned_row)

        cases = [(0, row, None), (1, row, None), (-1, row, "completion CAS failed"),
                 (2, row, "completion CAS failed"), (1, None, "requires v3 protocol"),
                 (0, {**row, "status": "reserved"}, "completion retry is not exact"),
                 (1, {**row, "operation_id": "changed"}, "differs from its reservation")]
        for count, returned_row, error in cases:
            with self.subTest(update_count=count, refusal=error):
                cursor = Cursor(count, returned_row)
                if error is None:
                    self.assertEqual(namespace["persistence_tail"](raw=cursor, **arguments), row)
                else:
                    with self.assertRaisesRegex(StoreError, error):
                        namespace["persistence_tail"](raw=cursor, **arguments)
                self.assertTrue(cursor.closed)
                self.assertEqual(cursor.rowcount, -1)
                self.assertEqual(cursor.steps, 4)

    def test_failure_cas_retains_each_update_count_before_reuse_and_close(self):
        from collections.abc import Mapping
        from typing import Any
        from serverware import authority_transition_registry

        _, module = source("serverware/authority_store/executor_v9.py")
        failure = function(module, "fail_authority_v9_transaction")
        start = next(i for i, node in enumerate(failure.body) if isinstance(node, ast.With))
        self.assertEqual(ast.unparse(failure.body[start - 1]),
                         "raw = _require_planner_writer(connection)")
        wrapper = ast.parse("def failure_tail(*, raw, capability_id, envelope_id, planner_transaction_id, "
            "failure_code, exact_response_bytes, terminal_at_epoch_ns, response_base64url, "
            "response_digest, failure_digest):\n    pass\n").body[0]
        wrapper.body = copy.deepcopy(failure.body[start:])

        class StoreError(Exception):
            pass

        namespace = dict(Mapping=Mapping, Any=Any,
            authority_transition_registry=authority_transition_registry,
            _db_value={"MetadataStoreError": StoreError}.__getitem__)
        component = ast.Module(body=[copy.deepcopy(function(module, "_require_v3_planner_row")), wrapper],
                               type_ignores=[])
        exec(compile(ast.fix_missing_locations(component), "<actual-failure-persistence-suffix>", "exec"), namespace)
        response = b'{"syntheticFailureSuffix":true}'
        arguments = dict(capability_id="sha256:" + "1" * 64, envelope_id="synthetic-envelope",
            planner_transaction_id="sha256:" + "2" * 64, failure_code="synthetic-refusal",
            exact_response_bytes=response, terminal_at_epoch_ns=10,
            response_base64url=base64.urlsafe_b64encode(response).rstrip(b"=").decode("ascii"),
            response_digest="sha256:" + hashlib.sha256(response).hexdigest(),
            failure_digest="sha256:" + "3" * 64)
        binding = dict(capability_id=arguments["capability_id"], envelope_id=arguments["envelope_id"],
                       planner_transaction_id=arguments["planner_transaction_id"])
        rows = [dict(binding, status="issued", capability_protocol="v3", capability_record_digest=None,
                     operation="webauthn.challenge.create"),
                dict(binding, status="reserved"),
                dict(binding, status="planned", plan_protocol="v3", retained_record_digest=None,
                     operation="webauthn.challenge.create")]
        terminal_rows = copy.deepcopy(rows)
        for row in terminal_rows:
            row.update(status="failed", failure_digest=arguments["failure_digest"],
                failure_code=arguments["failure_code"], exact_response_base64url=arguments["response_base64url"],
                exact_response_bytes_digest=arguments["response_digest"],
                terminal_at_epoch_ns=arguments["terminal_at_epoch_ns"],
                failed_at_epoch_ns=arguments["terminal_at_epoch_ns"])

        class Cursor:
            def __init__(self, counts, returned_rows):
                self.counts = counts
                self.rows = returned_rows
                self.rowcount = -1
                self.steps = 0
                self.closed = False

            def cursor(self):
                return self

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                self.rowcount = -1
                self.closed = True

            def execute(self, statement, parameters=None):
                self.steps += 1
                tables = ("policy_authority_fence_heads", "policy_authority_writer_capabilities",
                          "policy_authority_execution_envelopes", "policy_authority_planner_transactions")
                if self.steps <= 4:
                    expected = "SELECT * FROM serverware_metadata." + tables[self.steps - 1] + " "
                    self.rowcount = 1
                elif self.steps <= 7:
                    expected = "UPDATE serverware_metadata." + tables[self.steps - 4] + " "
                    self.rowcount = self.counts[self.steps - 5]
                else:
                    raise AssertionError("unexpected synthetic SQL step")
                if not statement.startswith(expected):
                    raise AssertionError("unexpected synthetic failure transaction statement")
                return self

            def fetchone(self):
                return {} if self.steps == 1 else copy.deepcopy(self.rows[self.steps - 2])

        expected = dict(status="failed", failureDigest=arguments["failure_digest"], exactResponseBytes=response)
        cases = [((1, 1, 1), rows, None, 7), ((0, 0, 0), terminal_rows, None, 4)]
        for index in range(3):
            for refused in (0, -1, 2):
                counts = [1, 1, 1]
                counts[index] = refused
                cases.append((tuple(counts), rows, "atomic failure CAS failed", 7))
        changed_terminal = copy.deepcopy(terminal_rows)
        changed_terminal[1]["terminal_at_epoch_ns"] += 1
        cases.append(((1, 1, 1), changed_terminal, "failure retry is not exact", 4))
        for counts, returned_rows, error, steps in cases:
            with self.subTest(update_counts=counts, refusal=error, steps=steps):
                cursor = Cursor(counts, returned_rows)
                if error is None:
                    self.assertEqual(namespace["failure_tail"](raw=cursor, **arguments), expected)
                else:
                    with self.assertRaisesRegex(StoreError, error):
                        namespace["failure_tail"](raw=cursor, **arguments)
                self.assertTrue(cursor.closed)
                self.assertEqual(cursor.rowcount, -1)
                self.assertEqual(cursor.steps, steps)

    def test_exact_nineteen_table_privileges_are_immutable_and_do_not_grant_business_writes(self):
        self.assertIs(type(writer.PLANNER_WRITER_TABLE_PRIVILEGES), MappingProxyType)
        self.assertEqual(dict(writer.PLANNER_WRITER_TABLE_PRIVILEGES), TABLE_PRIVILEGES)
        # The existing 15-table roster plus recovery invalidation/history,
        # challenge maintenance and JIT originals retain no business writes.
        self.assertEqual(len(TABLE_PRIVILEGES), 19)
        self.assertTrue(all(type(name) is str and type(value) is frozenset
                            for name, value in writer.PLANNER_WRITER_TABLE_PRIVILEGES.items()))
        with self.assertRaises(TypeError):
            writer.PLANNER_WRITER_TABLE_PRIVILEGES["credentials"] = frozenset({"SELECT"})
        with self.assertRaises(AttributeError):
            writer.PLANNER_WRITER_TABLE_PRIVILEGES["policy_authority_writer_capabilities"].add("INSERT")
        self.assertTrue(set(TABLE_PRIVILEGES).isdisjoint({
            "credentials", "control_plane_approvals", "webauthn_challenges", "webauthn_credentials",
            "metadata_audit_outbox", "policy_authority_counted_index_heads",
            "policy_authority_counted_index_leaves", "policy_authority_counted_index_nodes",
        }))

    def test_real_builder_returns_fixed_sql_and_only_two_separate_identifier_parameters(self):
        for role, namespace in (("planner_writer", "metadata"),
                                ('writer"; DROP SCHEMA x; --', 'metadata"; SELECT 1; --'),
                                ("\u00e9crivain", "schema_\U0001f600")):
            with self.subTest(role=role, namespace=namespace):
                statement, parameters = writer.planner_writer_privilege_check(role=role, namespace=namespace)
                self.assertEqual(statement, writer.PLANNER_WRITER_PRIVILEGE_SQL)
                self.assertIs(type(statement), str)
                self.assertIs(type(parameters), tuple)
                self.assertEqual(parameters, (role, namespace))
                self.assertEqual(statement.count("%s"), 2)
                # Exact argument strings, including punctuation, never become SQL.
                if role not in ("planner_writer",):
                    self.assertNotIn(role, statement)
                if namespace != "metadata":
                    self.assertNotIn(namespace, statement)
        self.assertEqual(writer.planner_writer_privilege_check(role="r", namespace="n"),
                         writer.planner_writer_privilege_check(role="r", namespace="n"))

    def test_real_builder_checks_exact_types_utf8_byte_bounds_nul_and_surrogates(self):
        class TextSubclass(str):
            pass

        for value in ("a" * 63, "\u00e9" * 31 + "a", "\U0001f600" * 15 + "aaa"):
            self.assertEqual(len(value.encode("utf-8")), 63)
            self.assertEqual(writer.planner_writer_privilege_check(role=value, namespace=value)[1], (value, value))
        invalid = (None, False, 0, 1, [], {}, b"r", bytearray(b"r"), TextSubclass("r"),
                   "", "a\x00b", "\ud800", "\udfff", "a" * 64, "\u00e9" * 32, "\U0001f600" * 16)
        for value in invalid:
            with self.subTest(value=repr(value), type=type(value).__name__):
                with self.assertRaises(ValueError):
                    writer.planner_writer_privilege_check(role=value, namespace="n")
                with self.assertRaises(ValueError):
                    writer.planner_writer_privilege_check(role="r", namespace=value)

    def test_query_digest_commits_the_exact_utf8_sql_not_only_its_inventory(self):
        original = writer.PLANNER_WRITER_PRIVILEGE_SQL.encode("utf-8")
        expected = "sha256:" + hashlib.sha256(original).hexdigest()
        self.assertEqual(writer.PLANNER_WRITER_PRIVILEGE_SQL_DIGEST, expected)
        self.assertNotEqual(expected, "sha256:" + hashlib.sha256(original + b"\n").hexdigest())
        self.assert_shape(assigned(self.module, "PLANNER_WRITER_PRIVILEGE_SQL_DIGEST"),
            "'sha256:' + hashlib.sha256(PLANNER_WRITER_PRIVILEGE_SQL.encode('utf-8')).hexdigest()")

    def test_exact_five_function_signatures_and_metadata_are_deeply_immutable(self):
        self.assertEqual(writer.AUDIT_CAPACITY_FUNCTION_NAME, FUNCTION_SIGNATURES[0][0])
        self.assertIs(type(writer.PLANNER_WRITER_FUNCTION_SIGNATURES), tuple)
        self.assertEqual(writer.PLANNER_WRITER_FUNCTION_SIGNATURES, FUNCTION_SIGNATURES)
        self.assertTrue(all(type(item) is tuple and type(item[1]) is tuple
                            for item in writer.PLANNER_WRITER_FUNCTION_SIGNATURES))
        self.assertIs(type(writer.PLANNER_WRITER_FUNCTION_CONTRACTS), MappingProxyType)
        expected = {}
        for name, arguments in FUNCTION_SIGNATURES:
            expected[name] = {
                "argumentTypes": arguments, "securityDefiner": False,
                "strict": name != FUNCTION_SIGNATURES[0][0],
                "volatility": "v" if name == FUNCTION_SIGNATURES[0][0] else "i",
                "language": "plpgsql",
                "searchPath": (("pg_catalog",) if name in {item[0] for item in FUNCTION_SIGNATURES[2:]}
                               else ("pg_catalog", "$metadata", "pg_temp")),
            }
        self.assertEqual(dict(writer.PLANNER_WRITER_FUNCTION_CONTRACTS), expected)
        for contract in writer.PLANNER_WRITER_FUNCTION_CONTRACTS.values():
            self.assertIs(type(contract), MappingProxyType)
            with self.assertRaises(TypeError):
                contract["securityDefiner"] = True
        with self.assertRaises(TypeError):
            writer.PLANNER_WRITER_FUNCTION_CONTRACTS["extra"] = {}
        _, audit = source("serverware/authority_store/audit_capacity_sql.py")
        aliases = [alias for node in audit.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware.authority_store.planner_writer_sql" for alias in node.names]
        self.assertEqual([(item.name, item.asname) for item in aliases], [
            ("AUDIT_CAPACITY_FUNCTION_NAME", None),
            ("PLANNER_WRITER_FUNCTION_SIGNATURES", None),
        ])
        self.assert_shape(assigned(audit, "AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES"),
                          "PLANNER_WRITER_FUNCTION_SIGNATURES")

    def test_sql_values_are_exact_source_inventories_not_caller_parameters(self):
        table_values = ",\n        ".join(
            "('" + name + "', ARRAY[" + ", ".join("'" + item + "'" for item in sorted(privileges))
            + "]::pg_catalog.text[])" for name, privileges in sorted(TABLE_PRIVILEGES.items()))
        function_values = ",\n        ".join(
            "('" + name + "', '" + ", ".join(arguments) + "', "
            + ("FALSE, 'v', FALSE" if index == 0 else
               "TRUE, 'i', FALSE" if index == 1 else "TRUE, 'i', TRUE") + ")"
            for index, (name, arguments) in enumerate(FUNCTION_SIGNATURES))
        self.assertEqual(writer._TABLE_VALUES, table_values)
        self.assertEqual(writer._FUNCTION_VALUES, function_values)
        self.assertIn("expected_tables(table_name, privileges) AS (\n    VALUES " + table_values,
                      writer.PLANNER_WRITER_PRIVILEGE_SQL)
        self.assertIn("expected_functions(function_name, argument_types, strict, volatility, catalog_only) AS (\n    VALUES "
                      + function_values, writer.PLANNER_WRITER_PRIVILEGE_SQL)
        builder = function(self.module, "planner_writer_privilege_check")
        self.assertFalse(builder.args.args)
        self.assertEqual([item.arg for item in builder.args.kwonlyargs], ["role", "namespace"])
        self.assertIsNone(builder.args.kwarg)
        self.assert_shape(builder.body[-1].value, "(PLANNER_WRITER_PRIVILEGE_SQL, (role, namespace))")

    def test_closed_violation_inventory_and_read_only_parameterized_query(self):
        sql = writer.PLANNER_WRITER_PRIVILEGE_SQL
        self.assertEqual(re.findall(r"SELECT '([^']+)'", sql), [
            "role-or-namespace", "schema-or-database-privilege", "role-membership",
            "required-table", "table-privilege", "column-privilege", "sequence-privilege",
            "required-function", "function-privilege", "function-metadata",
            "public-schema-privilege", "public-relation-privilege", "public-function-privilege",
        ])
        self.assertTrue(sql.startswith("WITH requested AS ("))
        self.assertTrue(sql.endswith("SELECT violation FROM violations LIMIT 1"))
        self.assertIn("%s::pg_catalog.text AS role_name", sql)
        self.assertIn("%s::pg_catalog.text AS namespace_name", sql)
        self.assertEqual(sql.count("%s"), 2)
        for forbidden in ("current_user", "session_user", "serverware_metadata"):
            self.assertNotIn(forbidden, sql)
        # Privilege names such as 'UPDATE WITH GRANT OPTION' are data in
        # the read query, not executable DML or GRANT statements.
        self.assertIsNone(re.search(
            r"(?m)^\s*(?:SET ROLE|GRANT|REVOKE|INSERT INTO|UPDATE|DELETE FROM|EXECUTE)\b", sql))
        self.assertNotIn("pg_get_function_identity_arguments", sql)

    def test_role_namespace_membership_and_database_authority_fail_closed(self):
        sql = writer.PLANNER_WRITER_PRIVILEGE_SQL
        for expression in (
            "role_oid IS NULL OR namespace_oid IS NULL", "rolcanlogin IS NOT TRUE",
            "rolsuper IS NOT FALSE", "rolcreaterole IS NOT FALSE", "rolcreatedb IS NOT FALSE",
            "rolreplication IS NOT FALSE", "rolbypassrls IS NOT FALSE",
            "has_schema_privilege(role_oid, namespace_oid, 'USAGE') IS NOT TRUE",
            "has_schema_privilege(role_oid, namespace_oid, 'CREATE') IS NOT FALSE",
            "'USAGE WITH GRANT OPTION,CREATE WITH GRANT OPTION'",
            "has_database_privilege(role_oid, pg_catalog.current_database(),",
            "'CREATE,TEMPORARY') IS NOT FALSE",
            "membership.member = authority.role_oid OR membership.roleid = authority.role_oid",
        ):
            self.assertIn(expression, sql)
        schema_branch = sql.split("SELECT 'schema-or-database-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("CASE WHEN role_oid IS NOT NULL AND namespace_oid IS NOT NULL THEN", schema_branch)
        self.assertIn("ELSE TRUE END", schema_branch)

    def test_required_tables_are_owner_bound_and_effective_dml_is_exact(self):
        sql = writer.PLANNER_WRITER_PRIVILEGE_SQL
        required = sql.split("SELECT 'required-table'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("FROM authority CROSS JOIN expected_tables", required)
        self.assertIn("relation.oid IS NULL OR relation.relkind NOT IN ('r', 'p')", required)
        self.assertIn("relation.relowner IS DISTINCT FROM authority.nspowner", required)
        effective = sql.split("SELECT 'table-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("'SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'", effective)
        self.assertIn("CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f') THEN", effective)
        self.assertIn("has_table_privilege(role_oid, oid, privilege) IS DISTINCT FROM", effective)
        self.assertIn("(relkind IN ('r', 'p') AND privilege = ANY(COALESCE(privileges, ARRAY[]::pg_catalog.text[])))", effective)
        self.assertIn("has_table_privilege(role_oid, oid, privilege || ' WITH GRANT OPTION') IS NOT FALSE", effective)
        self.assertIn("ELSE FALSE END", effective)
        # Views/foreign tables can never stand in for a required table or gain
        # the table's allowlist simply by using its name.
        self.assertNotIn("has_any_column_privilege", required + effective)

    def test_explicit_columns_sequences_and_public_acl_are_all_denied(self):
        sql = writer.PLANNER_WRITER_PRIVILEGE_SQL
        columns = sql.split("SELECT 'column-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("attribute.attnum > 0 AND attribute.attisdropped IS FALSE", columns)
        self.assertIn("CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f') THEN", columns)
        self.assertIn("THEN\n            attribute.attacl\n        ELSE NULL::pg_catalog.aclitem[] END", columns)
        self.assertIn("grant_entry.grantee = role_oid OR grant_entry.grantee = 0", columns)
        sequences = sql.split("SELECT 'sequence-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("CASE WHEN relkind = 'S' THEN", sequences)
        self.assertIn("'SELECT,USAGE,UPDATE'", sequences)
        self.assertIn("'SELECT WITH GRANT OPTION,USAGE WITH GRANT OPTION,UPDATE WITH GRANT OPTION'", sequences)
        for label, default in (("public-schema-privilege", "'n'"), ("public-function-privilege", "'f'")):
            branch = sql.split("SELECT '" + label + "'", 1)[1].split("UNION ALL", 1)[0]
            self.assertIn("pg_catalog.aclexplode(COALESCE(", branch)
            self.assertIn("pg_catalog.acldefault(" + default, branch)
            self.assertIn("grant_entry.grantee = 0", branch)
        relations = sql.split("SELECT 'public-relation-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f', 'S') THEN", relations)
        self.assertIn("CASE WHEN relkind = 'S' THEN 'S'::pg_catalog.\"char\"", relations)
        self.assertIn("ELSE 'r'::pg_catalog.\"char\" END, relowner)", relations)
        self.assertIn("ELSE NULL::pg_catalog.aclitem[] END", relations)
        self.assertIn("grant_entry.grantee = 0", relations)

    def test_acl_expansion_preserves_real_grants_and_strict_null_inputs(self):
        # Exact source-query controls only. PostgreSQL strict-NULL behavior and
        # rejection of zero-dimensional ACL arrays require separate SQL proof.
        _, verifier_tree = source("serverware/authority_store/verifier_read_sql.py")
        _, initialization_tree = source("serverware/authority_store/initialization_store_access.py")
        planner_sql, _ = writer.planner_writer_privilege_check(role="planner", namespace="metadata")
        verifier_sql = ast.literal_eval(assigned(verifier_tree, "VERIFIER_READ_PRIVILEGE_SQL"))
        initialization_sql = ast.literal_eval(assigned(initialization_tree, "_RAW_ACL_SQL"))

        def compact(value):
            return " ".join(value.split())

        for sql in (planner_sql, verifier_sql, initialization_sql):
            self.assertNotRegex(sql, r"ARRAY\s*\[\s*\]\s*::\s*(?:pg_catalog\.)?aclitem\[\]")
        for sql, label, grantees in (
            (planner_sql, "column-privilege", "grant_entry.grantee = role_oid OR grant_entry.grantee = 0"),
            (verifier_sql, "public-column-privilege", "grant_entry.grantee = 0"),
        ):
            with self.subTest(branch=label):
                column = sql.split("SELECT '" + label + "'", 1)[1].split("UNION ALL", 1)[0]
                self.assertIn("attribute.attnum > 0", column)
                self.assertIn("attribute.attisdropped IS FALSE", column)
                self.assertEqual(compact(column.split("CROSS JOIN LATERAL ", 1)[1]),
                    "pg_catalog.aclexplode( CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f') THEN "
                    "attribute.attacl ELSE NULL::pg_catalog.aclitem[] END ) AS grant_entry WHERE " + grantees)
                relation = sql.split("SELECT 'public-relation-privilege'", 1)[1].split("UNION ALL", 1)[0]
                self.assertEqual(compact(relation.split("CROSS JOIN LATERAL ", 1)[1]),
                    "pg_catalog.aclexplode( CASE WHEN relkind IN ('r', 'p', 'v', 'm', 'f', 'S') THEN "
                    "COALESCE(relacl, pg_catalog.acldefault( CASE WHEN relkind = 'S' THEN "
                    "'S'::pg_catalog.\"char\" ELSE 'r'::pg_catalog.\"char\" END, relowner)) "
                    "ELSE NULL::pg_catalog.aclitem[] END ) AS grant_entry WHERE grant_entry.grantee = 0")
                for branch, acl, kind, owner in (("public-schema-privilege", "nspacl", "n", "nspowner"),
                                                 ("public-function-privilege", "proacl", "f", "proowner")):
                    selected = sql.split("SELECT '" + branch + "'", 1)[1].split("UNION ALL", 1)[0]
                    self.assertIn("COALESCE( " + acl + ", pg_catalog.acldefault('" + kind
                        + "'::pg_catalog.\"char\", " + owner + ") )", compact(selected))
                    self.assertIn("WHERE grant_entry.grantee = 0", selected)
        initialization_column = initialization_sql.split("SELECT 'column',", 1)[1]
        self.assertEqual(compact(initialization_column.split("CROSS JOIN LATERAL ", 1)[1]),
            "pg_catalog.aclexplode(attribute.attacl) AS grant_entry ) SELECT scope, object_name, "
            "column_name, grantor::pg_catalog.int8 AS grantor, grantee::pg_catalog.int8 AS grantee, "
            "privilege_type, is_grantable FROM grants LIMIT 23")
        for acl, kind, owner in (("namespace.nspacl", "n", "namespace.nspowner"),
                                 ("relation.relacl", "r", "relation.relowner")):
            self.assertIn("pg_catalog.aclexplode(COALESCE(" + acl + ", pg_catalog.acldefault('"
                + kind + "'::pg_catalog.\"char\", " + owner + "))) AS grant_entry", compact(initialization_sql))

    def test_only_exact_typed_invoker_functions_have_execute_and_exact_metadata(self):
        sql = writer.PLANNER_WRITER_PRIVILEGE_SQL
        self.assertEqual(sql.count("pg_catalog.oidvectortypes(function_record.proargtypes)"), 2)
        self.assertIn("expected_functions.argument_types = pg_catalog.oidvectortypes(function_record.proargtypes)", sql)
        required = sql.split("SELECT 'required-function'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("FROM authority CROSS JOIN expected_functions", required)
        self.assertIn("function_record.oid IS NULL OR function_record.prokind IS DISTINCT FROM 'f'", required)
        effective = sql.split("SELECT 'function-privilege'", 1)[1].split("UNION ALL", 1)[0]
        self.assertIn("has_function_privilege(role_oid, oid, 'EXECUTE') IS DISTINCT FROM", effective)
        self.assertIn("(function_name IS NOT NULL)", effective)
        self.assertIn("'EXECUTE WITH GRANT OPTION') IS NOT FALSE", effective)
        metadata = sql.split("SELECT 'function-metadata'", 1)[1].split("UNION ALL", 1)[0]
        for expression in (
            "function_name IS NOT NULL AND (", "prokind IS DISTINCT FROM 'f'",
            "proowner IS DISTINCT FROM nspowner", "prosecdef IS NOT FALSE",
            "proisstrict IS DISTINCT FROM strict", "provolatile::pg_catalog.text IS DISTINCT FROM volatility",
            "lanname::pg_catalog.text IS DISTINCT FROM 'plpgsql'", "proconfig IS DISTINCT FROM CASE WHEN catalog_only THEN",
            "ARRAY['search_path=pg_catalog']::pg_catalog.text[]",
            "ARRAY['search_path=pg_catalog, ' || pg_catalog.quote_ident(namespace_name)",
            "|| ', pg_temp']::pg_catalog.text[] END",
        ):
            self.assertIn(expression, metadata)

    def test_pure_module_and_database_inventory_have_one_inert_source_owner(self):
        imports = []
        for node in self.module.body:
            if isinstance(node, ast.Import):
                imports.extend(item.name for item in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module)
        self.assertEqual(imports, ["__future__", "hashlib", "types"])
        for name in ("eval", "exec", "compile", "open", "__import__", "importlib.import_module"):
            self.assertFalse(calls(self.module, name))
        self.assert_shape(assigned(self.db, "_POLICY_AUTHORITY_PLANNER_WRITER_TABLE_PRIVILEGES"),
                          "_authority_planner_writer_sql.PLANNER_WRITER_TABLE_PRIVILEGES")
        aliases = [alias for node in self.db.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware.authority_store" for alias in node.names
                   if alias.name == "planner_writer_sql"]
        self.assertEqual([(item.name, item.asname) for item in aliases],
                         [("planner_writer_sql", "_authority_planner_writer_sql")])
        # The checker is read-only metadata admission, not an invocation of
        # any one of the five admitted functions or a new business executor.
        self.assertFalse(any(isinstance(node, (ast.AsyncFunctionDef, ast.ClassDef)) for node in self.module.body))
        self.assertEqual([node.name for node in self.module.body if isinstance(node, ast.FunctionDef)],
                         ["_literal", "planner_writer_privilege_check"])

    def test_distinct_writer_source_closure_is_required_before_any_cursor(self):
        guard = raising_guard(self.seal, "planner writer privilege closure is not source exact")
        self.assert_shape(guard.test,
            "planner_writer_role not in {runtime_role, executor_role, verifier_role, capability_issuer_role} "
            "and (authority_planner_writer_table_privileges != _POLICY_AUTHORITY_PLANNER_WRITER_TABLE_PRIVILEGES "
            "or type(authority_planner_writer_function_signatures) is not tuple "
            "or authority_planner_writer_function_signatures != AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES)")
        self.assertLess(guard.lineno, call(self.seal, "conn.cursor").lineno)
        self.assertEqual(len(guard.body), 1)
        self.assert_shape(guard.body[0].exc,
                          "error_type('planner writer privilege closure is not source exact')")

    def test_sealer_calls_actual_query_after_general_checks_and_rejects_every_returned_row(self):
        helper = call(self.seal, "_authority_planner_writer_sql.planner_writer_privilege_check")
        self.assert_shape(helper,
            "_authority_planner_writer_sql.planner_writer_privilege_check(role=planner_writer_role, namespace=schema)")
        queried = assigned(self.seal, "planner_writer_privilege_violation")
        self.assert_shape(queried,
            "cur.execute(*_authority_planner_writer_sql.planner_writer_privilege_check("
            "role=planner_writer_role, namespace=schema)).fetchone()")
        enclosing = [node for node in ast.walk(self.seal) if isinstance(node, ast.If)
                     and any(item is helper for item in ast.walk(node))]
        self.assertEqual(len(enclosing), 1)
        self.assert_shape(enclosing[0].test,
            "planner_writer_role not in {runtime_role, executor_role, verifier_role, capability_issuer_role}")
        denied = raising_guard(self.seal,
            "PostgreSQL planner writer effective privileges are not source exact")
        self.assert_shape(denied.test, "planner_writer_privilege_violation is not None")
        self.assertEqual(len(denied.body), 1)
        self.assert_shape(denied.body[0].exc,
            "error_type('PostgreSQL planner writer effective privileges are not source exact')")
        general = raising_guard(self.seal, "PostgreSQL object owner or ACL contains unexpected authority")
        self.assertLess(general.end_lineno, helper.lineno)
        self.assertLess(helper.lineno, denied.lineno)
        self.assertLess(denied.end_lineno,
                        call(self.seal, "_authority_verifier_read_sql.verifier_read_privilege_check").lineno)
        self.assertFalse(calls(self.seal, "eval"))

    def test_source_contract_and_owner_profile_bind_role_inventory_functions_and_query_digest(self):
        source_contract = function(self.schema, "_policy_candidate_authority_source_contract_digest")
        material = assigned(source_contract, "material")
        self.assertIsInstance(material, ast.Call)
        self.assertIsInstance(material.func, ast.Attribute)
        self.assertEqual(material.func.attr, "encode")
        self.assert_shape(material.args[0], "'utf-8'")
        source_fields = entries(material.func.value.args[0])
        self.assert_shape(source_fields["plannerWriterRole"], "_METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE")
        privileges_expression = (
            "{table: sorted(privileges) for table, privileges in "
            "sorted(_POLICY_AUTHORITY_PLANNER_WRITER_TABLE_PRIVILEGES.items())}")
        self.assert_shape(source_fields["plannerWriterTablePrivileges"], privileges_expression)
        self.assert_shape(source_fields["plannerWriterPrivilegeSqlDigest"], "PLANNER_WRITER_PRIVILEGE_SQL_DIGEST")
        self.assert_shape(source_fields["authorityPlannerWriterFunctionSignatures"],
            "{name: list(argument_types) for name, argument_types in AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES}")
        digest_imports = [alias for node in self.schema.body if isinstance(node, ast.ImportFrom)
                         and node.module == "serverware.authority_store.planner_writer_sql" for alias in node.names]
        self.assertEqual([(item.name, item.asname) for item in digest_imports],
                         [("PLANNER_WRITER_PRIVILEGE_SQL_DIGEST", None)])
        self.assert_shape(source_contract.body[-1].value,
            "_policy_candidate_authority_framed_digest('serverware.policyCandidateAuthoritySourceContract/v1', material)")

        profile = function(self.db, "_policy_authority_owner_verification_profile_digest")
        profile_fields = entries(assigned(profile, "planner_writer_privilege_contract"))
        self.assertEqual(set(profile_fields), {"plannerWriterRole", "plannerWriterTablePrivileges",
            "plannerWriterFunctionSignatures", "plannerWriterPrivilegeSqlDigest"})
        self.assert_shape(profile_fields["plannerWriterRole"], "_METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE")
        self.assert_shape(profile_fields["plannerWriterTablePrivileges"], privileges_expression)
        self.assert_shape(profile_fields["plannerWriterFunctionSignatures"],
            "{name: list(argument_types) for name, argument_types in "
            "_authority_planner_writer_sql.PLANNER_WRITER_FUNCTION_SIGNATURES}")
        self.assert_shape(profile_fields["plannerWriterPrivilegeSqlDigest"],
                          "_authority_planner_writer_sql.PLANNER_WRITER_PRIVILEGE_SQL_DIGEST")
        serialized = assigned(profile, "material")
        self.assertEqual(ast.unparse(serialized.func), "dumps")
        self.assert_shape(entries(serialized.args[0])["plannerWriterPrivilegeContract"],
                          "planner_writer_privilege_contract")
        self.assert_shape(profile.body[-1].value,
            "_policy_candidate_authority_framed_digest('serverware.policyAuthorityOwnerVerificationProfile/v1', "
            "material.encode('ascii'))")


if __name__ == "__main__":
    unittest.main()
