#!/usr/bin/env python3
"""Source-extracted bootstrap routing controls; no DB import, DDL or readiness proof."""
from __future__ import annotations

import ast
from pathlib import Path
import re
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "serverware.metadataStoreBootstrap/v1"


class BootstrapError(RuntimeError):
    pass


def route(*, metadata="postgres", audit="postgres", grant="postgres",
          metadata_dsn="fixed-runtime-dsn", grant_dsn="fixed-runtime-dsn",
          mode="metadata-bootstrap", contract=CONTRACT, borrowed=None):
    tree = ast.parse((ROOT / "serverware/db.py").read_text())
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "init_db")
    # Execute only the genuine source prefix through grant/audit routing.
    # Stop before any connection, schema execution or crypto inspection.
    stop = next(index for index, node in enumerate(function.body)
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "crypto_required"
                        for target in node.targets))
    function.body = function.body[:stop]
    function.decorator_list = []
    calls = []
    namespace = {
        "Path": Path, "DB_PATH": Path("unused"), "MetadataStoreError": BootstrapError,
        "METADATA_STORE_POSTGRES_DSN": metadata_dsn,
        "_METADATA_STORE_BOOTSTRAP_CONTRACT_ID": CONTRACT,
        "metadata_store_backend_name": lambda: metadata,
        "audit_store_backend_name": lambda: audit,
        "metadata_uses_postgres": lambda: metadata == "postgres",
        "audit_uses_postgres": lambda: audit == "postgres",
        "_policy_candidate_offline_connection": SimpleNamespace(get=lambda: borrowed),
        "os": SimpleNamespace(environ={"SERVERWARE_PROCESS_MODE": mode}),
        "ensure_data_dirs": lambda: calls.append("directories"),
        "_reject_runtime_metadata_admin_dsn": lambda: calls.append("runtime-admin-guard"),
        "_assert_postgres_metadata_runtime_ready": lambda: calls.append("runtime-readiness"),
        "grants": SimpleNamespace(
            GRANT_STORE_POSTGRES_DSN=grant_dsn,
            uses_postgres=lambda: grant == "postgres",
            init_grant_store=lambda: calls.append("standalone-grants")),
        "init_audit_store": lambda **kwargs: calls.append(("audit", kwargs)),
        "_bootstrap_sqlite_audit_store": lambda: calls.append("sqlite-audit"),
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]), "bootstrap-routing", "exec"), namespace)
    namespace["init_db"](bootstrap_contract_id=contract)
    return calls


class PostgresBootstrapGrantTests(unittest.TestCase):
    def test_exact_shared_offline_bootstrap_skips_only_standalone_grants(self):
        self.assertEqual(route(), ["directories", ("audit", {"bootstrap_contract_id": CONTRACT})])

    def test_distinct_empty_or_whitespace_dsn_is_not_an_implicit_shared_selection(self):
        for metadata, grant in (("fixed-runtime-dsn", "other"), ("", ""),
                                (" ", " "), ("fixed-runtime-dsn", " fixed-runtime-dsn")):
            with self.subTest(metadata=metadata, grant=grant):
                self.assertIn("standalone-grants", route(metadata_dsn=metadata, grant_dsn=grant))

    def test_other_mode_or_grant_backend_preserves_legacy_routing(self):
        for options in ({"mode": ""}, {"mode": "serverware"}, {"grant": "sqlite"}):
            with self.subTest(options=options):
                self.assertIn("standalone-grants", route(**options))

    def test_ordinary_postgres_runtime_never_initializes_either_store(self):
        self.assertEqual(route(contract=None, mode="serverware"),
                         ["runtime-admin-guard", "directories", "runtime-readiness"])

    def test_sqlite_and_borrowed_owner_behavior_are_unchanged(self):
        self.assertEqual(route(metadata="sqlite", audit="sqlite", contract=None),
                         ["runtime-admin-guard", "directories", "standalone-grants",
                          ("audit", {"bootstrap_contract_id": None}), "sqlite-audit"])
        self.assertEqual(route(borrowed=object()), ["directories"])

    def test_wrong_contract_or_mixed_backend_refuses_before_store_initialization(self):
        for options in ({"contract": "wrong"}, {"audit": "sqlite"}):
            with self.subTest(options=options), self.assertRaises(BootstrapError):
                route(**options)

    def test_source_owned_metadata_schema_contains_authority_grant_fields(self):
        tree = ast.parse((ROOT / "serverware/authority_store/metadata_schema_source.py").read_text())
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "metadata_base_schema_source")
        ddl = ast.literal_eval(function.body[0].value)
        for name in ("approval_grants", "approval_grant_consumptions"):
            self.assertIn("CREATE TABLE IF NOT EXISTS " + name + " (", ddl)
        for field in ("approver_policy_json", "approver_policy_digest", "authority_capability_id"):
            self.assertIn(field, ddl)

    def test_runtime_identity_queries_compare_regrole_to_regrole(self):
        # Source-only SQL/type regression, not database execution or readiness.
        tree = ast.parse((ROOT / "serverware/db.py").read_text())
        for name, parameter in (("_pinned_auxiliary_pg_connect", "runtime_role"),
                                ("_metadata_pg_connect_with_dsn", "_METADATA_STORE_RUNTIME_ROLE")):
            with self.subTest(builder=name):
                function = next(node for node in tree.body
                                if isinstance(node, ast.FunctionDef) and node.name == name)
                queries = [node for node in ast.walk(function)
                           if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                           and node.func.attr == "execute" and node.args
                           and isinstance(node.args[0], ast.Constant)
                           and isinstance(node.args[0].value, str)
                           and " AS current_is_runtime" in node.args[0].value]
                self.assertEqual(len(queries), 1)
                sql = queries[0].args[0].value
                self.assertIn("current_user::pg_catalog.regrole = %s::pg_catalog.regrole AS current_is_runtime", sql)
                self.assertNotIn("current_user = %s::pg_catalog.regrole", sql)
                self.assertEqual(ast.unparse(queries[0].args[1].elts[0]), parameter)

    def test_index_names_are_unqualified_and_bootstrap_tables_stay_qualified(self):
        # Source shape only; actual PostgreSQL parsing is a separate control.
        tree = ast.parse((ROOT / "serverware/db.py").read_text())
        identifier = r"[a-z_][a-z_0-9]*(?:\s*\.\s*[a-z_][a-z_0-9]*)*"
        index = re.compile(r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+"
            r"(?:IF\s+NOT\s+EXISTS\s+)?(" + identifier + r")\s+ON\s+("
            + identifier + r")\s*\(([^)]+)\)", re.IGNORECASE)
        expected = {
            "serverware_audit_events_created_at_desc": (
                "serverware_audit.serverware_audit_events", "created_at DESC, sequence DESC"),
            "serverware_audit_events_type_created_at": (
                "serverware_audit.serverware_audit_events", "event_type, created_at DESC"),
            "serverware_recovery_claims_user_sequence": (
                "serverware_recovery_witness.serverware_recovery_authorization_claims",
                "root_key_id, user_id, root_sequence"),
        }
        actual = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            for name, table, columns in index.findall(node.value):
                self.assertNotIn(".", name, "PostgreSQL CREATE INDEX name cannot be qualified")
                if name in expected:
                    self.assertNotIn(name, actual)
                    actual[name] = (re.sub(r"\s+", "", table), " ".join(columns.split()))
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
