#!/usr/bin/env python3
"""Pure query/source controls, not real PostgreSQL role or owner admission."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_contract as authority
from serverware.authority_store import challenge_execution_privileges as source


class ChallengeExecutionPrivilegeControls(unittest.TestCase):
    def test_only_two_source_rosters_have_exact_five_parameter_queries(self):
        cases = ((source.contract.ISSUER_ROLE,
            [source.contract.STEP_FUNCTION, source.contract.SEAL_FUNCTION],
            ["text, integer, text, text, bigint", "text, text, text"]),
            (source.contract.EXECUTOR_ROLE, [source.contract.EXECUTE_FUNCTION], ["text, text"]))
        for role, names, signatures in cases:
            with self.subTest(role=role):
                sql, parameters = source.challenge_execution_privilege_check(role=role, namespace='quoted"schema')
                self.assertIs(sql, source.CHALLENGE_EXECUTION_PRIVILEGE_SQL)
                self.assertEqual(parameters, (role, 'quoted"schema', [], names, signatures))
                self.assertEqual(sql.count("%s"), 5)
                self.assertNotIn(role, sql)
                self.assertNotIn('quoted"schema', sql)
                for name in names:
                    self.assertNotIn(name, sql)
        self.assertNotEqual(source.contract.ISSUER_ROLE, authority.SUCCESSOR_ISSUER_ROLE)
        self.assertNotEqual(source.contract.EXECUTOR_ROLE, authority.SUCCESSOR_EXECUTOR_ROLE)

    def test_original_generic_guards_are_literal_unchanged_except_function_contract(self):
        expected = source.generic.VERIFIER_READ_PRIVILEGE_SQL
        for old, new in ((source.shared._REQUESTED, source._REQUESTED),
                (source.shared._FUNCTIONS, source._FUNCTIONS),
                (source.shared._FUNCTION_PRIVILEGE, source._FUNCTION_PRIVILEGE)):
            self.assertEqual(expected.count(old), 1)
            expected = source.shared._replace_once(expected, old, new)
        self.assertEqual(source.CHALLENGE_EXECUTION_PRIVILEGE_SQL, expected)
        generic_branches = set(re.findall(r"SELECT '([^']+)'", source.generic.VERIFIER_READ_PRIVILEGE_SQL))
        actual = set(re.findall(r"SELECT '([^']+)'", expected))
        self.assertEqual(actual, generic_branches | {"required-function", "function-overload", "function-metadata"})
        for guard in ("has_any_column_privilege", "SELECT WITH GRANT OPTION", "role-membership",
                "rolbypassrls IS NOT FALSE", "CREATE,TEMPORARY", "SELECT,USAGE,UPDATE",
                "public-column-privilege", "public-function-privilege"):
            self.assertIn(guard, expected)
        self.assertTrue(expected.endswith("SELECT violation FROM violations LIMIT 1"))

    def test_each_required_signature_is_unique_and_every_other_execute_denies(self):
        sql = source.CHALLENGE_EXECUTION_PRIVILEGE_SQL
        for fragment in ("pg_catalog.oidvectortypes(function_record.proargtypes)",
                "AS argument_signature", "candidate.argument_signature COLLATE \"C\"",
                "expected_function_arguments[wanted.position]", ") <> 1",
                "has_function_privilege(role_oid, oid, 'EXECUTE') IS DISTINCT FROM expected",
                "has_function_privilege(role_oid, oid, 'EXECUTE WITH GRANT OPTION') IS NOT FALSE",
                "WHERE expected_name AND NOT expected"):
            self.assertIn(fragment, sql)
        # The overload branch does not disappear merely because EXECUTE was revoked.
        overload = sql.split("SELECT 'function-overload'", 1)[1].split("UNION ALL", 1)[0]
        self.assertNotIn("has_function_privilege", overload)
        for metadata in ("prokind IS DISTINCT FROM 'f'", "proowner IS DISTINCT FROM nspowner",
                "prosecdef IS NOT TRUE", "proisstrict IS NOT FALSE",
                "provolatile::pg_catalog.text IS DISTINCT FROM 'v'",
                "lanname::pg_catalog.text IS DISTINCT FROM 'plpgsql'", "proconfig IS DISTINCT FROM ARRAY["):
            self.assertIn(metadata, sql)

    def test_exact_scalars_reject_aliases_and_preserve_utf8_byte_bound(self):
        class Subclass(str):
            pass
        for role in (None, True, b"issuer", Subclass(source.contract.ISSUER_ROLE),
                authority.SUCCESSOR_ISSUER_ROLE, authority.SUCCESSOR_EXECUTOR_ROLE,
                authority.SUCCESSOR_RECOVERY_ROLE, "serverware_policy_authority_planner_writer"):
            with self.subTest(role=role), self.assertRaises(ValueError):
                source.challenge_execution_privilege_check(role=role, namespace="metadata")
        for namespace in (None, True, b"metadata", Subclass("metadata"), "", "a\x00b", "\ud800",
                "a" * 64, "é" * 32, "😀" * 16):
            with self.subTest(namespace=repr(namespace)), self.assertRaises(ValueError):
                source.challenge_execution_privilege_check(role=source.contract.ISSUER_ROLE, namespace=namespace)
        for namespace in ("a" * 63, "é" * 31 + "a", "😀" * 15 + "aaa"):
            self.assertEqual(source.challenge_execution_privilege_check(
                role=source.contract.ISSUER_ROLE, namespace=namespace)[1][1], namespace)

    def test_parameter_lists_are_fresh_and_source_roster_changes_refuse(self):
        kwargs = dict(role=source.contract.ISSUER_ROLE, namespace="metadata")
        first, second = (source.challenge_execution_privilege_check(**kwargs)[1] for _ in range(2))
        for position in (2, 3, 4):
            self.assertIsNot(first[position], second[position])
            first[position].append("untrusted")
        self.assertEqual(source.challenge_execution_privilege_check(**kwargs)[1], second)
        changed = dict(source.contract.ROLE_FUNCTIONS)
        changed[source.contract.ISSUER_ROLE] = (source.contract.STEP_FUNCTION, source.contract.EXECUTE_FUNCTION)
        with mock.patch.object(source.contract, "ROLE_FUNCTIONS", changed), self.assertRaises(ValueError):
            source.challenge_execution_privilege_check(**kwargs)
        changed = dict(source.contract.FUNCTION_SIGNATURES)
        changed[source.contract.STEP_FUNCTION] = ("text", "text")
        with mock.patch.object(source.contract, "FUNCTION_SIGNATURES", changed), self.assertRaises(ValueError):
            source.challenge_execution_privilege_check(**kwargs)
        with self.assertRaises(ValueError):
            source.shared._replace_once("duplicated duplicated", "duplicated", "replacement")

    def test_digest_and_old_successor_query_are_independent_no_installer(self):
        sql = source.CHALLENGE_EXECUTION_PRIVILEGE_SQL
        expected = "sha256:" + hashlib.sha256(sql.encode("utf-8")).hexdigest()
        self.assertEqual(source.CHALLENGE_EXECUTION_PRIVILEGE_SQL_DIGEST, expected)
        self.assertNotEqual(expected, source.shared.SUCCESSOR_EXECUTION_PRIVILEGE_SQL_DIGEST)
        old, parameters = source.shared.successor_execution_privilege_check(
            role=authority.SUCCESSOR_ISSUER_ROLE, namespace="metadata")
        self.assertEqual(parameters, (authority.SUCCESSOR_ISSUER_ROLE, "metadata", [], authority.SUCCESSOR_ISSUE_FUNCTION))
        self.assertEqual(old.count("%s"), 4)
        self.assertNotIn("expected_function_names", old)
        self.assertNotRegex(sql, r"(?im)^\s*(CREATE|GRANT|REVOKE|INSERT|DELETE|UPDATE)\b")
        for forbidden in ("SET ROLE", "set_config(", "COMMIT", "ROLLBACK"):
            self.assertNotIn(forbidden, sql)


if __name__ == "__main__":
    unittest.main()
