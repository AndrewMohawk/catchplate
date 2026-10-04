#!/usr/bin/env python3
"""Pure role-plan and mocked SQL sequencing tests; no PostgreSQL admission proof."""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import authority_contract
from serverware import db as database
from serverware.authority_store import planner_read_sql, policy_file_read_sql, policy_file_genesis_sql

spec = importlib.util.spec_from_file_location("provision_metadata_roles", Path(__file__).with_name("provision_metadata_roles.py"))
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def fixture():
    return SimpleNamespace(
        _METADATA_STORE_RUNTIME_ROLE="pilot_metadata_runtime",
        _AUDIT_STORE_RUNTIME_ROLE="pilot_audit_runtime",
        _METADATA_STORE_AUTHORITY_EXECUTOR_ROLE="pilot_authority_executor",
        _METADATA_STORE_AUTHORITY_VERIFIER_ROLE="pilot_authority_verifier",
        _METADATA_STORE_AUTHORITY_OWNER_ROLE="serverware_policy_authority_owner",
        _METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE="serverware_policy_capability_issuer",
        _METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE="serverware_policy_authority_planner_writer",
        _METADATA_STORE_AUTHORITY_COMPLETION_READER_ROLE=authority_contract.COMPLETION_READER_ROLE,
        authority_contract=authority_contract, _policy_file_read_sql=policy_file_read_sql,
        _policy_file_genesis_sql=policy_file_genesis_sql,
        _policy_candidate_authority_identifier=database._policy_candidate_authority_identifier,
        _POLICY_AUTHORITY_OWNER_POSTGRES_MAJOR=16,
        recovery_witness_uses_postgres=lambda: False,
        _reject_runtime_metadata_admin_dsn=Mock(),
    )


def environment():
    return {**{name: "explicit_test_role" for name in cli.REQUIRED_ROLES},
            "SERVERWARE_PROCESS_MODE": "metadata-bootstrap",
            "SERVERWARE_METADATA_STORE_BACKEND": "postgres",
            "SERVERWARE_AUDIT_STORE_BACKEND": "postgres",
            "SERVERWARE_METADATA_STORE_ADMIN_POSTGRES_DSN": "secret-test-dsn"}


class MetadataRoleProvisioningTests(unittest.TestCase):
    def test_closed_plan_is_fourteen_roles_with_only_owner_nologin(self):
        db = fixture()
        plan = cli.role_plan(db)
        self.assertEqual(len(plan), 14)
        self.assertIn((planner_read_sql.ROLE, True), plan)
        self.assertNotEqual(planner_read_sql.ROLE, db._METADATA_STORE_RUNTIME_ROLE)
        self.assertEqual([name for name, login in plan if not login], [db._METADATA_STORE_AUTHORITY_OWNER_ROLE])
        self.assertIn((authority_contract.SUCCESSOR_ISSUER_ROLE, True), plan)
        self.assertIn((policy_file_genesis_sql.ROLE, True), plan)

    def test_role_aliases_and_invalid_identifiers_refuse(self):
        for field, value in (("_METADATA_STORE_AUTHORITY_EXECUTOR_ROLE", "pilot_metadata_runtime"),
                             ("_METADATA_STORE_RUNTIME_ROLE", planner_read_sql.ROLE),
                             ("_AUDIT_STORE_RUNTIME_ROLE", "serverware_policy_authority_owner"),
                             ("_METADATA_STORE_RUNTIME_ROLE", 'bad";SELECT 1')):
            db = fixture()
            setattr(db, field, value)
            with self.subTest(field=field), self.assertRaises((ValueError, database.PolicyCandidateAuthorityError)):
                cli.role_plan(db)
        db = fixture()
        db._AUDIT_STORE_RUNTIME_ROLE = db._METADATA_STORE_RUNTIME_ROLE
        self.assertEqual(len(cli.role_plan(db)), 13)

    def test_help_plan_and_apply_are_explicit_and_do_not_echo_secrets(self):
        for arguments, expected, connects in ((["--help"], 0, False), (["--plan"], 0, False),
                                               (["--apply"], 0, True), (["secret-test-dsn"], 2, False)):
            out, err = io.StringIO(), io.StringIO()
            with patch.dict(cli.os.environ, environment(), clear=True), patch.object(cli, "_load_db", return_value=fixture()), \
                    patch.object(cli, "_apply") as apply, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(cli.main(arguments), expected)
            self.assertEqual(apply.called, connects)
            self.assertNotIn("secret-test-dsn", out.getvalue() + err.getvalue())
            if arguments == ["--plan"]:
                self.assertFalse(json.loads(out.getvalue())["credentialsIssued"])

    def test_wrong_mode_backend_or_missing_role_refuses_before_import(self):
        for key, value in (("SERVERWARE_PROCESS_MODE", ""), ("SERVERWARE_METADATA_STORE_BACKEND", "sqlite"),
                           (cli.REQUIRED_ROLES[0], "")):
            selected = environment()
            selected[key] = value
            with patch.dict(cli.os.environ, selected, clear=True), patch.object(cli, "_load_db") as loader, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["--apply"]), 1)
                loader.assert_not_called()

    def connection(self, db, *, collision=False, superuser=True):
        roles = cli.role_plan(db)
        connection = Mock()
        def execute(query, parameters=None):
            if "AS same_session" in query:
                return SimpleNamespace(fetchone=lambda: {"same_session": True, "superuser": superuser, "major": 16})
            if query.startswith("SELECT rolname FROM"):
                return SimpleNamespace(fetchall=lambda: [{"rolname": roles[0][0]}] if collision else [])
            if query.startswith("SELECT rolname, rolcanlogin"):
                return SimpleNamespace(fetchall=lambda: [{"rolname": name, "rolcanlogin": login, "unexpected": False}
                                                        for name, login in roles])
            return None
        connection.execute.side_effect = execute
        return connection, roles

    def test_collision_and_unprivileged_admin_cannot_reach_create(self):
        db = fixture()
        for options in ({"collision": True}, {"superuser": False}):
            connection, roles = self.connection(db, **options)
            with self.assertRaises(ValueError):
                cli.create_roles(connection, db, roles, float("inf"))
            self.assertFalse(any(call.args[0].startswith("CREATE ROLE") for call in connection.execute.call_args_list))

    def test_all_preflight_queries_precede_fixed_passwordless_create_statements(self):
        db = fixture()
        connection, roles = self.connection(db)
        cli.create_roles(connection, db, roles, float("inf"))
        statements = [call.args[0] for call in connection.execute.call_args_list]
        self.assertTrue(all(value.startswith("SELECT") for value in statements[:2]))
        self.assertEqual(sum(value.startswith("CREATE ROLE") for value in statements), len(roles))
        for query in statements[2:-1]:
            self.assertIn(" NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL", query)
            self.assertNotIn("GRANT", query)
            self.assertNotIn("ALTER", query)
        self.assertIn("membership.member = role_record.oid OR membership.roleid = role_record.oid", statements[-1])

    def test_actual_apply_owns_one_connection_transaction_without_autocommit(self):
        tree = ast.parse(Path(cli.__file__).read_text())
        apply = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_apply")
        scope = next(node for node in apply.body if isinstance(node, ast.With))
        connect = scope.items[0].context_expr
        self.assertEqual(ast.unparse(connect.func), "psycopg.connect")
        self.assertNotIn("autocommit", {item.arg for item in connect.keywords})
        self.assertEqual(ast.unparse(scope.body[0].value), "create_roles(connection, db, roles, deadline)")
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                             and node.func.attr == "commit" for node in ast.walk(apply)))


if __name__ == "__main__":
    unittest.main()
