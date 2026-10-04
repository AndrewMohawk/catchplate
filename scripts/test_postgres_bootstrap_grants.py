#!/usr/bin/env python3
"""Source-extracted bootstrap routing controls; no DB import, DDL or readiness proof."""
from __future__ import annotations

import ast
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest import mock


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


def initialization_locks(timeout_ms):
    tree = ast.parse((ROOT / "serverware/db.py").read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_lock_postgres_metadata_initialization_authorities")
    calls = []

    class Connection:
        def execute(self, sql, params=None):
            calls.append((sql, params))
            return SimpleNamespace(fetchone=lambda: {"timeout_ms": timeout_ms})

    namespace = {
        "Any": object, "PostgresMetadataConnection": Connection,
        "MetadataStoreError": BootstrapError,
        "_lock_policy_candidate_authority": lambda conn: calls.append("candidate-lock"),
        "_lock_policy_high_water": lambda conn: calls.append("high-water-lock"),
    }
    exec(compile(ast.Module(body=[function], type_ignores=[]),
                 "bootstrap-lock-budget", "exec"), namespace)
    namespace[function.name](Connection())
    return calls


@lru_cache(maxsize=1)
def connector_source():
    # Test-local immutable source snapshot for this one focused process only.
    return ast.parse((ROOT / "serverware/db.py").read_text())


def connector_options(connector, options, *, contract=CONTRACT,
                      mode="metadata-bootstrap"):
    """Execute real connector routing, stopping before any connection or SQL."""
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    tree = connector_source()
    names = {connector, "_postgres_bootstrap_options"}
    functions = [node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(functions) == 2

    class ConnectObserved(BaseException):
        pass

    calls, guards = [], []

    def connect(*args, **kwargs):
        calls.append((args, kwargs))
        raise ConnectObserved()  # No synthetic successful admission or connection.

    psycopg = SimpleNamespace(connect=connect)
    namespace = {
        "re": re, "os": SimpleNamespace(environ={"SERVERWARE_PROCESS_MODE": mode}),
        "MetadataStoreError": BootstrapError, "AuditStoreError": BootstrapError,
        "RecoveryWitnessError": BootstrapError,
        "_METADATA_STORE_BOOTSTRAP_CONTRACT_ID": CONTRACT,
        "METADATA_STORE_CONNECT_TIMEOUT_SECONDS": 5,
        "_METADATA_STORE_RUNTIME_ROLE": "synthetic_runtime",
        "_METADATA_STORE_AUTHORITY_EXECUTOR_ROLE": "synthetic_executor",
        "_METADATA_STORE_AUTHORITY_VERIFIER_ROLE": "synthetic_verifier",
        "_METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE": "synthetic_issuer",
        "_METADATA_STORE_AUTHORITY_OWNER_ROLE": "synthetic_owner",
        "_METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE": "synthetic_writer",
        "_metadata_psycopg": lambda: (psycopg, "synthetic-row-factory"),
        "_audit_psycopg": lambda: (psycopg, "synthetic-row-factory"),
        "_reject_runtime_metadata_admin_dsn": lambda: guards.append("runtime-admin"),
    }
    exec(compile(ast.Module(body=functions, type_ignores=[]),
                 "bootstrap-connect-options-routing", "exec"), namespace)
    dsn = make_conninfo(dbname="synthetic", **({} if options is None else {"options": options}))
    arguments = dict(dsn=dsn, bootstrap_contract_id=contract)
    if connector == "_pinned_auxiliary_pg_connect":
        arguments.update(schema="synthetic_audit", connect_timeout=5,
                         runtime_role="synthetic_runtime", label="synthetic",
                         error_type=BootstrapError)
    try:
        namespace[connector](**arguments)
    except ConnectObserved:
        assert len(calls) == 1 and calls[0][0] == (dsn,)
        assert calls[0][1]["connect_timeout"] == 5
        # Exercise real libpq conninfo composition, not a synthetic DSN parser.
        effective = conninfo_to_dict(make_conninfo(dsn, options=calls[0][1]["options"]))
        assert effective["dbname"] == "synthetic"
        return effective["options"], guards
    raise AssertionError("connector did not reach the intercepted connect call")


class PostgresBootstrapGrantTests(unittest.TestCase):
    def test_local_reader_profile_refuses_without_original_development_authorization(self):
        # Actual validators and init_db prefix only; no DB import or connection.
        from serverware import authority_local_audit_reader as reader
        from serverware import authority_local_rbac_bootstrap as rbac
        function = deepcopy(next(node for node in connector_source().body
            if isinstance(node, ast.FunctionDef) and node.name == "init_db"))
        end = next(index for index, node in enumerate(function.body) if isinstance(node, ast.If)
            and ast.unparse(node.test) == "local_audit_reader_profile is not None")
        function.body = function.body[:end + 1]
        function.decorator_list = []
        namespace = dict(Path=Path, DB_PATH=Path("unused"), MetadataStoreError=BootstrapError,
            metadata_store_backend_name=lambda: "postgres", audit_store_backend_name=lambda: "postgres",
            _policy_candidate_offline_connection=SimpleNamespace(get=lambda: None),
            _METADATA_STORE_BOOTSTRAP_CONTRACT_ID=CONTRACT)
        exec(compile(ast.Module(body=[function], type_ignores=[]), "reader-profile-admission-prefix", "exec"), namespace)
        selection = dict(initialRbacTimestamp=100_000_000_000,
            issuedAtUnixNanos=100_000_000_000, expiresAtUnixNanos=200_000_000_000)
        cases = ((reader.PROFILE_ID, None, False), (reader.PROFILE_ID, selection, True),
                 ("unknown-profile", selection, False), (True, selection, False))
        for profile, original, production in cases:
            with self.subTest(profile=profile, production=production), \
                    mock.patch.object(rbac.config, "PRODUCTION_IMAGE", production), \
                    mock.patch.object(rbac.config, "_production_release", return_value=production), \
                    mock.patch.dict(rbac.os.environ, {"SERVERWARE_PRODUCTION_IMAGE": "0",
                        "SERVERWARE_RELEASE_CHANNEL": "dev", "SERVERWARE_PROCESS_MODE": "metadata-bootstrap"}), \
                    mock.patch.object(rbac.time, "time_ns", return_value=150_000_000_000):
                with self.assertRaises((ValueError, BootstrapError)):
                    namespace["init_db"](bootstrap_contract_id=CONTRACT,
                        local_initial_rbac=original, local_audit_reader_profile=profile)

    def test_local_reader_actual_and_reference_grants_precede_first_manifest(self):
        # Source control flow, not proof that the SQL or role admission succeeded.
        tree = connector_source()
        init = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "init_db")
        calls = {name: [node for node in ast.walk(init) if isinstance(node, ast.Call)
            and ast.unparse(node.func) == name] for name in
            ("_seal_postgres_schema_acl", "local_reader.provision", "_record_policy_candidate_authority_migration")}
        self.assertTrue(all(len(nodes) == 1 for nodes in calls.values()))
        seal, provision, record = (nodes[0] for nodes in calls.values())
        self.assertLess(seal.lineno, provision.lineno)
        self.assertLess(provision.lineno, record.lineno)
        self.assertEqual(ast.unparse(provision.args[0]), "conn.raw_connection")
        self.assertEqual(ast.unparse(next(arg.value for arg in record.keywords
            if arg.arg == "local_audit_reader_profile")), "local_audit_reader_profile")
        initial_source = ast.unparse(init)
        self.assertIn("_policy_candidate_authority_migration_version(conn) != 0", initial_source)
        self.assertIn("SELECT pg_catalog.to_regrole(?) AS role", initial_source)
        recorded = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name == "_record_policy_candidate_authority_migration")
        self.assertIn("local_audit_reader_profile is not None and prior_contract", ast.unparse(recorded))
        schema = ast.parse((ROOT / "serverware/authority_store/schema.py").read_text())
        expected = next(node for node in schema.body if isinstance(node, ast.FunctionDef)
            and node.name == "_policy_candidate_authority_expected_structure_manifest")
        reference_calls = {name: [node for node in ast.walk(expected) if isinstance(node, ast.Call)
            and ast.unparse(node.func) == name] for name in
            ("_seal_postgres_schema_acl", "authority_local_audit_reader.grant_reference_profile",
             "_policy_candidate_authority_structure_manifest")}
        reference_seal = reference_calls["_seal_postgres_schema_acl"][0]
        grant = reference_calls["authority_local_audit_reader.grant_reference_profile"][0]
        manifest = min(reference_calls["_policy_candidate_authority_structure_manifest"], key=lambda node: node.lineno)
        self.assertLess(reference_seal.lineno, grant.lineno)
        self.assertLess(grant.lineno, manifest.lineno)
        self.assertEqual(ast.unparse(grant.args[0]), "conn.raw_connection")
        self.assertIn("profile=local_audit_reader_profile", ast.unparse(grant))

    def test_bootstrap_connectors_preserve_selected_finite_options(self):
        # Synthetic connect interception, not PostgreSQL or bootstrap proof.
        selections = (
            ("-c statement_timeout=30000", {"statement_timeout": "30000ms"}),
            ("-cstatement_timeout=30s -c lock_timeout=2s "
             "--idle_in_transaction_session_timeout=1min -c search_path=public",
             {"statement_timeout": "30000ms", "lock_timeout": "2000ms",
              "idle_in_transaction_session_timeout": "60000ms"}),
            ("--statement_timeout=30\\ s\t-c lock_timeout=1ms",
             {"statement_timeout": "30000ms", "lock_timeout": "1ms"}),
        )
        for connector in ("_metadata_pg_connect_with_dsn", "_pinned_auxiliary_pg_connect"):
            for selected, expected in selections:
                with self.subTest(connector=connector, selected=selected):
                    actual, guards = connector_options(connector, selected)
                    tokens = actual.split()
                    self.assertEqual(tokens[::2], ["-c"] * (len(expected) + 1))
                    self.assertEqual(dict(token.split("=", 1) for token in tokens[1::2]),
                                     {**expected, "search_path": "pg_catalog"})
                    self.assertEqual(tokens[-2:], ["-c", "search_path=pg_catalog"])
                    self.assertEqual(guards, [])

    def test_runtime_connectors_preserve_selected_finite_options(self):
        # Exact runtime connector prefix plus real conninfo; no DB connection.
        selections = (
            ("-c statement_timeout=5000", {"statement_timeout": "5000ms"}),
            ("-cstatement_timeout=5s -c lock_timeout=250ms "
             "--idle_in_transaction_session_timeout=1min -c search_path=public",
             {"statement_timeout": "5000ms", "lock_timeout": "250ms",
              "idle_in_transaction_session_timeout": "60000ms"}),
        )
        for connector in ("_metadata_pg_connect_with_dsn", "_pinned_auxiliary_pg_connect"):
            for selected, expected in selections:
                with self.subTest(connector=connector, selected=selected):
                    actual, guards = connector_options(connector, selected,
                        contract=None, mode="serverware-control-plane")
                    tokens = actual.split()
                    self.assertEqual(tokens[::2], ["-c"] * (len(expected) + 1))
                    self.assertEqual(dict(token.split("=", 1) for token in tokens[1::2]),
                                     {**expected, "search_path": "pg_catalog"})
                    self.assertEqual(tokens[-2:], ["-c", "search_path=pg_catalog"])
                    self.assertEqual(guards, ["runtime-admin"]
                                     if connector == "_metadata_pg_connect_with_dsn" else [])

    def test_runtime_and_bootstrap_unselected_connect_options_remain_unchanged(self):
        for connector in ("_metadata_pg_connect_with_dsn", "_pinned_auxiliary_pg_connect"):
            for selected in (None, ""):
                with self.subTest(connector=connector, runtime=selected):
                    actual, guards = connector_options(connector, selected,
                                                       contract=None, mode="serverware-control-plane")
                    self.assertEqual(actual, "-c search_path=pg_catalog")
                    self.assertEqual(guards, ["runtime-admin"]
                                     if connector == "_metadata_pg_connect_with_dsn" else [])
            for selected in (None, ""):
                with self.subTest(connector=connector, bootstrap=selected):
                    self.assertEqual(connector_options(connector, selected),
                                     ("-c search_path=pg_catalog", []))

    def test_runtime_connectors_refuse_unbounded_or_unsafe_options_before_connect(self):
        rejected = ("-c statement_timeout=0", "-c lock_timeout=0",
                    "-c idle_in_transaction_session_timeout=0", "-c statement_timeout=-1",
                    "-c statement_timeout=2147483648", "-c statement_timeout=25d",
                    "-c statement_timeout=1.5s", "-c statement_timeout=infinite",
                    "-c statement_timeout=", "-c", "--statement_timeout",
                    "-c role=synthetic_owner", "-c unknown_setting=1", "--",
                    "-c statement_timeout=1\\")
        for connector in ("_metadata_pg_connect_with_dsn", "_pinned_auxiliary_pg_connect"):
            for selected in rejected:
                with self.subTest(connector=connector, selected=selected), self.assertRaises(BootstrapError):
                    connector_options(connector, selected,
                        contract=None, mode="serverware-control-plane")

    def test_bootstrap_connectors_refuse_unsafe_options_and_wrong_authority(self):
        rejected = ("-c statement_timeout=0", "-c lock_timeout=0",
                    "-c idle_in_transaction_session_timeout=0", "-c statement_timeout=-1",
                    "-c statement_timeout=2147483648", "-c statement_timeout=25d",
                    "-c statement_timeout=1.5s", "-c statement_timeout=1week",
                    "-c statement_timeout=", "-c", "--statement_timeout",
                    "-c role=synthetic_owner", "-c unknown_setting=1", "--", "-c statement_timeout=1\\")
        for connector in ("_metadata_pg_connect_with_dsn", "_pinned_auxiliary_pg_connect"):
            for selected in rejected:
                with self.subTest(connector=connector, selected=selected), self.assertRaises(BootstrapError):
                    connector_options(connector, selected)
            for authority in ({"contract": "wrong"}, {"mode": "serverware-control-plane"}):
                with self.subTest(connector=connector, authority=authority), self.assertRaises(BootstrapError):
                    connector_options(connector, "-c statement_timeout=30000", **authority)

    def test_initialization_restores_selected_finite_statement_budget_after_locks(self):
        # Source routing only; the PostgreSQL DDL control runs independently.
        for timeout_ms in (1000, 30000):
            with self.subTest(timeout_ms=timeout_ms):
                calls = initialization_locks(timeout_ms)
                self.assertEqual(calls[1:3], ["candidate-lock", "high-water-lock"])
                self.assertEqual(calls[3:], [(
                    "SELECT pg_catalog.set_config('statement_timeout', ?, true)",
                    (str(timeout_ms) + "ms",),
                )])
        tree = ast.parse((ROOT / "serverware/db.py").read_text())
        initialize = next(node for node in tree.body
                          if isinstance(node, ast.FunctionDef) and node.name == "init_db")
        calls = [node.func.id for node in ast.walk(initialize)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertEqual(calls.count("_lock_postgres_metadata_initialization_authorities"), 1)
        self.assertNotIn("_lock_policy_candidate_authority", calls)

    def test_unbounded_initialization_retains_finite_runtime_fallback(self):
        self.assertEqual(initialization_locks(0)[1:], ["candidate-lock", "high-water-lock"])

    def test_invalid_initialization_timeout_is_refused(self):
        for value in (None, True, -1, "30000"):
            with self.subTest(value=value), self.assertRaises(BootstrapError):
                initialization_locks(value)

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

    def test_acl_owner_query_uses_nonreserved_role_table_alias(self):
        # Source-only regression; actual PostgreSQL parsing is a separate control.
        tree = ast.parse((ROOT / "serverware/db.py").read_text())
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef)
                        and node.name == "_seal_postgres_schema_acl")
        queries = [node for node in ast.walk(function)
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                   and node.func.attr == "execute" and node.args
                   and isinstance(node.args[0], ast.Constant)
                   and isinstance(node.args[0].value, str)
                   and " AS current_is_superuser " in node.args[0].value]
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0].args[0].value,
            "SELECT namespace.nspowner = "
            "current_user::pg_catalog.regrole::oid AS is_owner, "
            "owner_role.rolname AS owner_role, "
            "current_role_record.rolsuper AS current_is_superuser "
            "FROM pg_catalog.pg_namespace AS namespace "
            "JOIN pg_catalog.pg_roles AS owner_role "
            "ON owner_role.oid = namespace.nspowner "
            "JOIN pg_catalog.pg_roles AS current_role_record "
            "ON current_role_record.oid = "
            "current_user::pg_catalog.regrole::oid "
            "WHERE namespace.nspname = %s")
        self.assertEqual(ast.unparse(queries[0].args[1]), "(schema,)")
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.assertNotRegex(node.value, r"\bcurrent_role\s*\.")
                self.assertNotRegex(node.value,
                    r"(?i)\b(?:FROM|JOIN)\s+pg_catalog\.pg_roles\s+AS\s+current_role\b")


if __name__ == "__main__":
    unittest.main()
