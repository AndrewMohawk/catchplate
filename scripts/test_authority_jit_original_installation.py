#!/usr/bin/env python3
"""Source inventory and guarded installer control flow, not live PG ACL proof."""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_contract as contract
from serverware import db
from serverware.authority_store import jit_original_pages as pages
from serverware.authority_store import planner_writer_sql, schema


SOURCES = (
    "policy_authority_planner_transactions", "policy_authority_schema_contracts",
    "approval_requests", "webauthn_challenges", "webauthn_credentials",
    "jit_webauthn_assertion_receipts", "policy_high_water", "rbac_role_bindings",
    "webauthn_trust_publication_high_water", "webauthn_trust_publications",
)


class ConnectionDouble:
    def __init__(self, *, namespace="serverware_metadata", transaction=True, nonempty=None):
        self.namespace, self.in_transaction, self.nonempty = namespace, transaction, nonempty
        self.statements, self.result = [], None

    def execute(self, statement):
        self.statements.append(statement)
        if statement.startswith("SELECT pg_catalog.current_schema()"):
            self.result = {"schema_name": self.namespace}
        elif statement.startswith("SELECT 1 AS present FROM ONLY "):
            self.result = {"present": 1} if self.nonempty and ('"' + self.nonempty + '"') in statement else None
        else:
            self.result = None
        return self

    def fetchone(self):
        return self.result


class JitOriginalInstallationControls(unittest.TestCase):
    def install(self, conn, *, exists=False, version=0, validator=None):
        with ExitStack() as stack:
            stack.enter_context(patch.object(db, "PostgresMetadataConnection", ConnectionDouble))
            stack.enter_context(patch.object(db, "_metadata_table_exists", return_value=exists))
            stack.enter_context(patch.object(db, "_policy_candidate_authority_migration_version", return_value=version))
            replay = stack.enter_context(patch.object(db, "_validate_policy_candidate_authority_structure",
                side_effect=validator))
            db._install_policy_authority_jit_original_pages(conn)
            return replay.call_args_list

    def test_exact_contract_roles_and_no_business_or_sqlite_admission(self):
        table = contract.JIT_ORIGINAL_PAGE_TABLE
        self.assertEqual(pages.TABLE, "serverware_metadata." + table)
        self.assertEqual(pages.COLUMNS, contract.JIT_ORIGINAL_PAGE_COLUMNS)
        self.assertEqual(len(pages.COLUMNS), 13)
        self.assertEqual(pages._KEY_FIELDS, contract.JIT_ORIGINAL_PAGE_CONTRACT["primaryKey"])
        self.assertEqual(len(pages._KEY_FIELDS), 4)
        self.assertIn(table, contract.POSTGRES_IMMUTABLE_CUSTODY_TABLES)
        self.assertIn(table, contract._FRAMEWORK_CUSTODY_TABLES)
        self.assertIn(table, db._POLICY_AUTHORITY_FRAMEWORK_CUSTODY_TABLES)
        self.assertIn(table, db._POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES)
        self.assertNotIn(table, db._POLICY_AUTHORITY_CONTROLLED_WRITER_TABLES)
        self.assertNotIn(table, db._POLICY_AUTHORITY_VERIFIER_READ_TABLES)
        self.assertEqual(planner_writer_sql.PLANNER_WRITER_TABLE_PRIVILEGES[table], {"SELECT", "INSERT"})
        self.assertIn("('" + table + "', ARRAY['INSERT', 'SELECT']", planner_writer_sql.PLANNER_WRITER_PRIVILEGE_SQL)
        self.assertIn(table, schema._policy_candidate_authority_schema_tables(postgres=True))
        self.assertNotIn(table, schema._policy_candidate_authority_schema_tables(postgres=False))
        self.assertEqual(contract.operation_contract_document()["jitOriginalPageCustody"],
            dict(contract.JIT_ORIGINAL_PAGE_CONTRACT))
        self.assertIs(contract.JIT_ORIGINAL_PAGE_CONTRACT["publicExecutionEnabled"], False)
        triggers, _functions = schema._policy_candidate_authority_required_guard_names(postgres=True)
        for suffix in (("canonical", "insert"), ("immutable",)):
            self.assertIn(db._policy_candidate_authority_object_name("serverware", table, *suffix), triggers)

    def test_ddl_is_source_exact_and_namespace_bounded(self):
        for namespace in ('"serverware_metadata"', '"serverware_candidate_authority_expected_v9"'):
            ddl = db._policy_authority_jit_original_page_ddl(namespace)
            self.assertEqual(ddl, pages.installation_sql().replace(pages.TABLE,
                namespace + '."' + contract.JIT_ORIGINAL_PAGE_TABLE + '"'))
            self.assertNotIn("GRANT ", ddl)
        with self.assertRaises(db.PolicyCandidateAuthorityError):
            db._policy_authority_jit_original_page_ddl('"other"')
        with patch.object(pages, "COLUMNS", pages.COLUMNS[:-1]):
            with self.assertRaises(db.PolicyCandidateAuthorityError):
                db._policy_authority_jit_original_page_ddl('"serverware_metadata"')

    def test_every_source_is_locked_before_any_empty_check_or_creation(self):
        conn = ConnectionDouble()
        self.install(conn)
        statements = conn.statements
        self.assertEqual(len(statements), 2 + 2 * len(SOURCES))
        for position, table in enumerate(SOURCES, 1):
            self.assertEqual(statements[position],
                f'LOCK TABLE ONLY "serverware_metadata"."{table}" IN SHARE ROW EXCLUSIVE MODE')
            self.assertEqual(statements[len(SOURCES) + position],
                f'SELECT 1 AS present FROM ONLY "serverware_metadata"."{table}" LIMIT 1')
        self.assertIn("CREATE TABLE IF NOT EXISTS", statements[-1])

    def test_nonempty_source_old_version_or_wrong_transaction_cannot_create(self):
        cases = [(ConnectionDouble(nonempty=table), 0) for table in SOURCES]
        cases += [(ConnectionDouble(), 1), (ConnectionDouble(transaction=False), 0),
                  (ConnectionDouble(namespace="untrusted"), 0)]
        for conn, version in cases:
            with self.subTest(nonempty=conn.nonempty, version=version, namespace=conn.namespace):
                with self.assertRaises(db.PolicyCandidateAuthorityError): self.install(conn, version=version)
                self.assertFalse(any("CREATE TABLE" in statement for statement in conn.statements))

    def test_existing_real_table_requires_recorded_contract_and_scratch_must_be_absent(self):
        conn = ConnectionDouble()
        calls = self.install(conn, exists=True)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].kwargs, {"require_recorded_contract": True})
        self.assertIs(calls[0].args[0], conn)
        self.assertEqual(len(conn.statements), 1)
        with self.assertRaises(db.PolicyCandidateAuthorityError):
            self.install(ConnectionDouble(), exists=True,
                validator=db.PolicyCandidateAuthorityError("recorded source differs"))
        with self.assertRaises(db.PolicyCandidateAuthorityError):
            self.install(ConnectionDouble(namespace="serverware_candidate_authority_expected_v9"), exists=True)

    def test_schema_contract_digest_binds_actual_jit_ddl(self):
        original = schema._policy_candidate_authority_source_contract_digest()
        ddl = schema._policy_authority_jit_original_page_ddl
        with patch.object(schema, "_policy_authority_jit_original_page_ddl",
                side_effect=lambda namespace: ddl(namespace) + "\n-- changed-source"):
            changed = schema._policy_candidate_authority_source_contract_digest()
        self.assertNotEqual(original, changed)


if __name__ == "__main__":
    unittest.main()
