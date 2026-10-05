"""Execute actual connector code with driver doubles, not PostgreSQL admission.

This regression covers the missing measured-to-database pin handoff. It does
not import the database application, use credentials, or execute native SQL.
"""
from __future__ import annotations

import ast
from functools import cache
from pathlib import Path
import re
from types import SimpleNamespace
import unittest


ROLE = "serverware_policy_capability_issuer"
PINS = (ROLE, "/CN=component-issuer", "123", "/CN=component-ca", 5)


class SessionDouble:
    def __init__(self, **changes):
        self.identity = dict(current_role=ROLE, exact_session=True,
            transaction_isolation="serializable", read_only="off", deferrable="off",
            rolsuper=False, rolcreaterole=False, rolcreatedb=False,
            rolreplication=False, rolbypassrls=False, schema_create=False,
            database_create=False, database_temporary=False,
            ssl=True, client_dn=PINS[1], client_serial=PINS[2], issuer_dn=PINS[3])
        self.identity.update(changes)
        self.sql, self.closes, self.result = [], 0, None

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql):
        self.sql.append(sql)
        self.result = self.identity if sql.startswith("SELECT current_user AS current_role") else None
        return self

    def fetchone(self):
        return self.result

    def close(self):
        self.closes += 1


@cache
def actual_code():
    path = Path(__file__).resolve().parents[1] / "serverware/db.py"
    tree = ast.parse(path.read_bytes(), filename=str(path))
    names = {"_authority_database_pins", "_policy_authority_capability_issuer_pg_connect_raw"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in functions} != names or len(functions) != 2:
        raise AssertionError("actual source functions are not unique")
    return compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec")


def actual_connector(session):
    calls = []
    def connect(dsn, **kwargs):
        calls.append((dsn, kwargs))
        return session
    def descriptor(name):
        calls.append(name)
        return "component-only-dsn"
    namespace = dict(re=re, MetadataStoreError=ValueError,
        os=SimpleNamespace(environ={"SERVERWARE_PROCESS_MODE": "policy-authority-issuer",
            "SERVERWARE_POLICY_AUTHORITY_CAPABILITY_ISSUER_TLS_CLIENT_DN": "wrong-ambient-pin"}),
        _POLICY_AUTHORITY_ISSUER_PROCESS_MODE="policy-authority-issuer",
        _METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE=ROLE,
        _policy_authority_dsn_from_descriptor=descriptor,
        _metadata_psycopg=lambda: (SimpleNamespace(connect=connect), "component-dict-row"),
        _postgres_bootstrap_options=lambda dsn, **kwargs: "component-options")
    exec(actual_code(), namespace)
    return namespace["_policy_authority_capability_issuer_pg_connect_raw"], calls


class IssuerDatabasePinTests(unittest.TestCase):
    def test_measured_pins_work_without_ambient_tls_and_keep_transaction_owned(self):
        session = SessionDouble()
        connector, calls = actual_connector(session)
        self.assertIs(connector(database_pins=PINS), session)
        self.assertEqual(session.closes, 0)
        self.assertEqual(len(session.sql), 5)
        self.assertEqual(session.sql[0],
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE")
        self.assertEqual(calls[1][1], dict(connect_timeout=5, row_factory="component-dict-row",
            options="component-options", autocommit=False))

    def test_real_connector_comparisons_still_refuse_mismatched_sessions(self):
        for field, value in (("client_dn", "/CN=other"), ("client_serial", "124"),
                ("issuer_dn", "/CN=other-ca"), ("current_role", "other_role"),
                ("ssl", False), ("rolsuper", True), ("database_temporary", True),
                ("transaction_isolation", "read committed"), ("read_only", "on"),
                ("deferrable", "on")):
            with self.subTest(field=field):
                session = SessionDouble(**{field: value})
                connector, _ = actual_connector(session)
                with self.assertRaisesRegex(ValueError, "session is not exact"):
                    connector(database_pins=PINS)
                self.assertEqual(session.closes, 1)

    def test_bad_pins_refuse_before_descriptor_read_or_database_connection(self):
        for pins in (None, list(PINS), PINS[:-1], ("other", *PINS[1:]),
                (*PINS[:4], True), (*PINS[:4], float("nan")), (*PINS[:4], 0),
                (ROLE, "", *PINS[2:]), (ROLE, PINS[1], "not-a-serial", *PINS[3:])):
            with self.subTest(pins_type=type(pins).__name__):
                session = SessionDouble()
                connector, calls = actual_connector(session)
                with self.assertRaises(ValueError):
                    connector(database_pins=pins)
                self.assertEqual((calls, session.sql, session.closes), ([], [], 0))


if __name__ == "__main__":
    unittest.main()
