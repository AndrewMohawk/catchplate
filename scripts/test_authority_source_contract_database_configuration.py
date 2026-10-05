#!/usr/bin/env python3
"""Actual source digest and recorded-contract guard, not PostgreSQL admission.

Use the genuine fully populated db/schema source and immutable configuration
type. The existing synthetic measured-projection fixture supplies public pins;
it is not launch/key admission. A recording cursor returns only the source
contract row, then stops at the next catalog query. No successful owner/TLS/ACL
verdict, database connection or production startup is substituted or claimed.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_database_configuration as configuration
from serverware import db
from serverware.authority_store import schema
from test_authority_executor_database_configuration import captured


class NextCatalogQuery(BaseException):
    """Stop after the genuine source gate, not a successful owner validation."""


class ContractCursor:
    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def execute(self, statement, parameters=None):
        self.calls.append((statement, parameters))
        if len(self.calls) != 1:
            raise NextCatalogQuery()
        if statement != ("SELECT source_revision, source_contract_digest, structural_manifest_digest "
                "FROM serverware_metadata.policy_authority_schema_contracts "
                "WHERE schema_version = %s LIMIT 2"):
            raise AssertionError("first physical query is not the original bounded source-contract read")
        return self

    def fetchall(self):
        return self.rows


@contextmanager
def ambient(*, verifier, owner=configuration.OWNER_ROLE):
    # Change only the actual schema's already-captured import globals, as two
    # separately configured processes would observe. Never mutate os.environ.
    with patch.multiple(schema, _METADATA_STORE_AUTHORITY_VERIFIER_ROLE=verifier,
            _METADATA_STORE_AUTHORITY_OWNER_ROLE=owner):
        yield


def actual_material(*, selected=None):
    recorded = []
    encode = schema.dumps
    def observe(value):
        recorded.append(value)
        return encode(value)
    with patch.object(schema, "dumps", side_effect=observe):
        digest = db._policy_candidate_authority_source_contract_digest(database_configuration=selected)
    if len(recorded) != 1:
        raise AssertionError("actual full source material was not encoded exactly once")
    return digest, recorded[0]


def recorded_contract(selected):
    with ambient(verifier=selected.verifier_pins[0]):
        digest = db._policy_candidate_authority_source_contract_digest()
    return dict(source_revision=db._POLICY_CANDIDATE_AUTHORITY_SOURCE_REVISION,
        source_contract_digest=digest, structural_manifest_digest="sha256:" + "a" * 64)


class SourceContractDatabaseConfigurationControls(unittest.TestCase):
    def test_full_configured_bootstrap_digest_equals_measured_empty_ambient(self):
        selected = captured()
        with ambient(verifier=selected.verifier_pins[0]):
            bootstrap, original = actual_material()
        with ambient(verifier=""):
            measured, actual = actual_material(selected=selected)
            unconfigured, _ = actual_material()
        self.assertEqual(measured, bootstrap)
        self.assertEqual(actual, original)
        self.assertNotEqual(unconfigured, bootstrap)
        self.assertEqual(actual["verifierReadRole"], selected.verifier_pins[0])
        self.assertEqual(actual["authorityOwnerRole"], configuration.OWNER_ROLE)
        # All source inventory/SQL/manifest material remains inside the actual
        # framed digest, not an isolated two-role substitute or supplied hash.
        self.assertEqual(measured, schema._policy_candidate_authority_framed_digest(
            "serverware.policyCandidateAuthoritySourceContract/v1", schema.dumps(actual).encode("utf-8")))
        self.assertIn("sqlGrantManifest", actual)
        self.assertIn("metadataSchemaProgramDigest", actual)

    def test_typed_roles_ignore_hostile_ambient_without_mutating_it(self):
        selected = captured()
        expected = recorded_contract(selected)["source_contract_digest"]
        environment = dict(os.environ)
        with ambient(verifier="foreign_verifier", owner="foreign_owner"):
            self.assertEqual(db._policy_candidate_authority_source_contract_digest(
                database_configuration=selected), expected)
            self.assertEqual(schema._METADATA_STORE_AUTHORITY_VERIFIER_ROLE, "foreign_verifier")
            self.assertEqual(schema._METADATA_STORE_AUTHORITY_OWNER_ROLE, "foreign_owner")
            changed = replace(selected, verifier_pins=("other_verifier", *selected.verifier_pins[1:]))
            self.assertNotEqual(db._policy_candidate_authority_source_contract_digest(
                database_configuration=changed), expected)
        self.assertEqual(dict(os.environ), environment)

    def test_actual_owner_guard_passes_matching_record_but_refuses_role_revision_and_count(self):
        selected = captured()
        record = recorded_contract(selected)
        with ambient(verifier=""):
            cursor = ContractCursor([record])
            with self.assertRaises(NextCatalogQuery):
                db._validate_policy_authority_owner_apply_function(cursor, database_configuration=selected)
            self.assertEqual(len(cursor.calls), 2)
            self.assertEqual(cursor.calls[0][1], (db._POLICY_CANDIDATE_AUTHORITY_SCHEMA_VERSION,))
            mismatched = replace(selected, verifier_pins=("other_verifier", *selected.verifier_pins[1:]))
            cases = (([record], mismatched), ([], selected), ([record, record], selected),
                ([{**record, "source_revision": "wrong-source"}], selected),
                ([{**record, "source_contract_digest": "sha256:" + "f" * 64}], selected))
            for rows, context in cases:
                cursor = ContractCursor(rows)
                with self.subTest(rows=len(rows)), self.assertRaisesRegex(db.MetadataStoreError,
                        "owner policy-authority source manifest is unavailable"):
                    db._validate_policy_authority_owner_apply_function(cursor, database_configuration=context)
                self.assertEqual(len(cursor.calls), 1)

    def test_invalid_typed_context_refuses_before_any_source_query_or_ambient_fallback(self):
        selected = captured()
        for invalid in (object(), {}, replace(selected, verifier_pins=list(selected.verifier_pins)),
                replace(selected, configuration_digest="not-a-digest")):
            with self.subTest(kind=type(invalid).__name__), ambient(verifier=selected.verifier_pins[0]):
                with self.assertRaises(configuration.AuthorityDatabaseConfigurationError):
                    db._policy_candidate_authority_source_contract_digest(database_configuration=invalid)
                cursor = ContractCursor([recorded_contract(selected)])
                with self.assertRaises(configuration.AuthorityDatabaseConfigurationError):
                    db._validate_policy_authority_owner_apply_function(cursor, database_configuration=invalid)
                self.assertEqual(cursor.calls, [])

    def test_both_actual_validator_digest_uses_hold_the_same_explicit_context(self):
        path = ROOT / "serverware/db.py"
        self.assertLess(path.stat().st_size, 16 * 1024 * 1024)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name == "_validate_policy_authority_owner_apply_function")
        calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_policy_candidate_authority_source_contract_digest"]
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertEqual(call.args, [])
            self.assertEqual(len(call.keywords), 1)
            self.assertEqual(call.keywords[0].arg, "database_configuration")
            self.assertIsInstance(call.keywords[0].value, ast.Name)
            self.assertEqual(call.keywords[0].value.id, "database_configuration")
        closure = [node for node in ast.walk(function) if isinstance(node, ast.Dict)
            and any(isinstance(key, ast.Constant) and key.value == "sourceContractDigest" for key in node.keys)]
        self.assertEqual(len(closure), 1)
        value = next(value for key, value in zip(closure[0].keys, closure[0].values)
            if isinstance(key, ast.Constant) and key.value == "sourceContractDigest")
        self.assertIn(value, calls)


if __name__ == "__main__":
    unittest.main()
