#!/usr/bin/env python3
"""Pure source-contract and fetched-manifest admission tests; no live proof.

The DDL checks below are textual drift controls on committed declarations.
They do not execute SQL or turn a source parser into schema/authentication
authority. Production contracts are the explicit reviewed map, never this
test's extraction result. Real PostgreSQL admission remains separately required.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import textwrap
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_primary_contract as primary


def independent_digest(domain: str, value: object) -> str:
    encoded_domain = domain.encode("ascii")
    payload = json.dumps(value, ensure_ascii=True, allow_nan=False,
                         separators=(",", ":"), sort_keys=True).encode("ascii")
    material = (len(encoded_domain).to_bytes(8, "big") + encoded_domain
                + len(payload).to_bytes(8, "big") + payload)
    return "sha256:" + hashlib.sha256(material).hexdigest()


def manifest_row_fixture(operation: str, *, authorization: bool) -> tuple[list[dict], list[dict]]:
    """Spell the SQL row encoding independently from the admission helper."""
    manifest = (primary.source_authorization_manifest() if authorization
                else primary.source_query_manifest())
    domain = ("serverware.policyAuthorityAuthorizationManifest" if authorization
              else "serverware.policyAuthorityQueryManifest")
    manifest_digest = independent_digest(domain + "/v1", manifest)
    entries = [entry for entry in manifest if entry["operation"] == operation]
    rows = []
    for entry in entries:
        row = {
            "ordinal": entry["ordinal"], "table_name": entry["table"],
            "key_columns_json": json.dumps(entry["keyColumns"], sort_keys=True, separators=(",", ":")),
            "predicate_kind": entry["predicateKind"], "exact_absence": 1,
            "entry_digest": independent_digest(domain + "Entry/v1", entry),
            "manifest_digest": manifest_digest, "source_revision": authority_contract.SOURCE_REVISION,
        }
        if not authorization:
            row.update({
                "predicate_id": entry["predicateId"], "handler_digest": entry["handlerDigest"],
                "write_access": 1 if entry["writeAccess"] else 0,
                "selector_paths_json": json.dumps(entry["selectorPaths"], sort_keys=True, separators=(",", ":")),
                "proof_kind": entry["proofKind"], "maximum_rows": entry["maximumRows"],
                "index_contract": entry["indexContract"], "selector_source": entry["selectorSource"],
            })
        rows.append(row)
    return rows, entries


def committed_schema_literals() -> str:
    """Read only the existing literal schema programs, without importing them."""
    path = ROOT / "serverware/db.py"
    if path.stat().st_size > 16 * 1024 * 1024:
        raise AssertionError("database source exceeded the bounded source fixture")
    source = path.read_text(encoding="utf-8")
    start_marker = '        metadata_schema_source = """'
    end_marker = "        metadata_schema_source += ("
    if source.count(start_marker) != 1 or source.count(end_marker) != 1:
        raise AssertionError("database literal schema markers changed")
    start, end = source.index(start_marker), source.index(end_marker)
    assignment = ast.parse(textwrap.dedent(source[start:end]))
    if (len(assignment.body) != 1 or not isinstance(assignment.body[0], ast.Assign)
            or not isinstance(assignment.body[0].value, ast.Constant)
            or type(assignment.body[0].value.value) is not str):
        raise AssertionError("database schema is not the expected source literal")
    database_sql = assignment.body[0].value.value
    # The pre-v2 table declarations are deliberately inert, including the old
    # artifact_digest key. They must not be mistaken for current source DDL.
    retired_marker = "/*\n             * Retired pre-v2 candidate tables."
    if database_sql.count(retired_marker) != 1:
        raise AssertionError("retired source DDL comment boundary changed")
    retired_start = database_sql.index(retired_marker)
    retired_end = database_sql.index("*/", retired_start) + 2
    database_sql = database_sql[:retired_start] + database_sql[retired_end:]

    executor_path = ROOT / "serverware/authority_store/executor_v9.py"
    if executor_path.stat().st_size > 2 * 1024 * 1024:
        raise AssertionError("executor source exceeded the bounded source fixture")
    executor = ast.parse(executor_path.read_text(encoding="utf-8"))
    functions = [node for node in executor.body if isinstance(node, ast.FunctionDef)
                 and node.name == "authority_v9_schema_source"]
    if len(functions) != 1:
        raise AssertionError("v9 schema source function is not unique")
    returns = [node for node in functions[0].body if isinstance(node, ast.Return)]
    if len(returns) != 1:
        raise AssertionError("v9 schema source is not one closed return")
    value = returns[0].value
    # Only the two named final-plan limits may replace source-literal tokens.
    # Inspect the exact AST; do not import, compile or evaluate the executor.
    substitutions = (
        ("__MAX_PLAN_WORK_UNITS__", "MAX_PLAN_WORK_UNITS", authority_contract.MAX_PLAN_WORK_UNITS),
        ("__MAX_PLAN_SELECTED_BYTES__", "MAX_PLAN_SELECTED_BYTES", authority_contract.MAX_PLAN_SELECTED_BYTES),
    )
    for token, attribute, _ in substitutions:
        if (not isinstance(value, ast.Call) or value.keywords or len(value.args) != 2
                or not isinstance(value.func, ast.Attribute) or value.func.attr != "replace"
                or not isinstance(value.args[0], ast.Constant) or value.args[0].value != token):
            raise AssertionError("v9 schema budget substitution is not source exact")
        expected = ast.parse(f"str(authority_contract.{attribute})", mode="eval").body
        if ast.dump(value.args[1]) != ast.dump(expected):
            raise AssertionError("v9 schema budget value is not source owned")
        value = value.func.value
    if not isinstance(value, ast.Constant) or type(value.value) is not str:
        raise AssertionError("v9 schema source is not a fixed literal")
    executor_sql = value.value
    for token, _, limit in substitutions:
        if executor_sql.count(token) != 1:
            raise AssertionError("v9 schema budget token is not unique")
        executor_sql = executor_sql.replace(token, str(limit))
    return database_sql + "\n" + executor_sql


class AuthorityPrimaryContractTests(unittest.TestCase):
    def test_inventory_exactly_covers_source_operation_relations(self) -> None:
        required = {
            table for spec in authority_contract.OPERATIONS.values()
            for category in ("businessReads", "businessWrites", "authorizationReads")
            for table in spec[category]
        }
        self.assertEqual(set(primary.PRIMARY_KEY_COLUMNS), required)
        self.assertNotIn("policies", required)
        for table, columns in primary.PRIMARY_KEY_COLUMNS.items():
            with self.subTest(table=table):
                self.assertIs(type(columns), tuple)
                self.assertTrue(columns)
                self.assertEqual(len(columns), len(set(columns)))

    def test_every_committed_key_matches_its_active_source_ddl(self) -> None:
        declarations: dict[str, list[tuple[str, ...]]] = {}
        for table, body in re.findall(
            r"CREATE TABLE IF NOT EXISTS\s+([a-z][a-z0-9_]*)\s*\((.*?)\n\s*\);",
            committed_schema_literals(), flags=re.DOTALL,
        ):
            if table not in primary.PRIMARY_KEY_COLUMNS:
                continue
            inline = re.findall(
                r"^\s*([a-z][a-z0-9_]*)\s+(?:TEXT|INTEGER|BIGINT)\s+PRIMARY KEY\b",
                body, flags=re.MULTILINE,
            )
            composites = re.findall(r"\bPRIMARY KEY\s*\(([^()]*)\)", body)
            keys = [(column,) for column in inline]
            keys.extend(tuple(column.strip() for column in value.split(","))
                        for value in composites)
            self.assertEqual(len(keys), 1, f"source PRIMARY KEY is ambiguous: {table}")
            declarations.setdefault(table, []).extend(keys)
        self.assertEqual(set(declarations), set(primary.PRIMARY_KEY_COLUMNS))
        for table, expected in primary.PRIMARY_KEY_COLUMNS.items():
            self.assertEqual(declarations[table], [expected], table)

    def test_nontrivial_keys_and_current_artifact_identity_are_explicit(self) -> None:
        expected = {
            "credential_lease_nonces": ("recipient_key_id", "nonce_sha256"),
            "approval_request_decisions": ("approval_request_id", "approver_id"),
            "policy_activation_prepared_transitions": ("preparation_digest", "transition_ordinal"),
            "policy_activation_export_authorization_receipts": (
                "export_id", "authorization_revision", "page_ordinal",
            ),
            "policy_authority_trusted_keys": ("evidence_kind", "key_revision"),
            "policy_candidate_artifacts": ("artifact_envelope_digest",),
            "webauthn_trust_publication_high_water": ("authority_scope",),
        }
        for table, columns in expected.items():
            self.assertEqual(primary.PRIMARY_KEY_COLUMNS[table], columns)

    def test_root_classes_and_write_access_come_from_each_operation(self) -> None:
        for operation, spec in authority_contract.OPERATIONS.items():
            contracts = primary.primary_table_contracts(operation)
            business = set(spec["businessReads"]) | set(spec["businessWrites"])
            authorization = set(spec["authorizationReads"])
            self.assertEqual([entry.table for entry in contracts], sorted(business | authorization))
            for entry in contracts:
                self.assertEqual(entry.key_columns, primary.PRIMARY_KEY_COLUMNS[entry.table])
                self.assertEqual(entry.root_class, "business" if entry.table in business else "authorization")
                self.assertIs(entry.write_access, entry.table in spec["businessWrites"])
        counter = {entry.table: entry for entry in primary.primary_table_contracts("webauthn.counter.cas")}
        challenge = {entry.table: entry for entry in primary.primary_table_contracts("webauthn.challenge.create")}
        self.assertEqual(counter["webauthn_credentials"].root_class, "business")
        self.assertTrue(counter["webauthn_credentials"].write_access)
        self.assertEqual(challenge["webauthn_credentials"].root_class, "authorization")
        self.assertFalse(challenge["webauthn_credentials"].write_access)

    def test_inventory_and_returned_contracts_are_immutable(self) -> None:
        with self.assertRaises(TypeError):
            primary.PRIMARY_KEY_COLUMNS["routes"] = ("untrusted",)
        entry = primary.primary_table_contracts("webauthn.counter.cas")[0]
        with self.assertRaises(FrozenInstanceError):
            entry.write_access = False
        projection = entry.json_projection()
        projection["keyColumns"].append("untrusted")
        self.assertEqual(entry.key_columns, ("id",))

    def test_missing_or_extra_source_relation_fails_closed(self) -> None:
        incomplete = dict(primary.PRIMARY_KEY_COLUMNS)
        incomplete.pop("routes")
        extra = {**primary.PRIMARY_KEY_COLUMNS, "unexpected_table": ("id",)}
        for changed in (incomplete, extra):
            with patch.object(primary, "PRIMARY_KEY_COLUMNS", MappingProxyType(changed)):
                for operation in (primary.source_query_manifest, primary.source_authorization_manifest):
                    with self.assertRaisesRegex(ValueError, "relation closure"):
                        operation()
                with self.assertRaisesRegex(ValueError, "relation closure"):
                    primary.primary_table_contracts("webauthn.counter.cas")
        with self.assertRaisesRegex(ValueError, "closed authority contract"):
            primary.primary_table_contracts("unknown.operation")

    def test_business_manifest_preserves_source_array_order_and_exact_fields(self) -> None:
        manifest = primary.source_query_manifest()
        self.assertEqual(list(dict.fromkeys(entry["operation"] for entry in manifest)),
                         list(authority_contract.OPERATIONS))
        fields = {"ordinal", "predicateId", "table", "handlerDigest", "indexContract",
                  "predicateKind", "selectorSource", "selectorPaths", "proofKind",
                  "exactAbsence", "maximumRows", "operation", "keyColumns", "writeAccess"}
        for operation, spec in authority_contract.OPERATIONS.items():
            entries = [entry for entry in manifest if entry["operation"] == operation]
            tables = sorted(set(spec["businessReads"]) | set(spec["businessWrites"]))
            self.assertEqual([entry["table"] for entry in entries], tables)
            for ordinal, entry in enumerate(entries, start=1):
                self.assertEqual(set(entry), fields)
                self.assertEqual(entry["ordinal"], ordinal)
                self.assertEqual(entry["predicateId"],
                                 f"serverware.policyAuthorityQuery/{operation}/{ordinal}/{entry['table']}/v3")
                self.assertEqual(entry["handlerDigest"], authority_contract.handler_contract_digest(operation))
                self.assertEqual(entry["keyColumns"], list(primary.PRIMARY_KEY_COLUMNS[entry["table"]]))
                self.assertEqual(entry["selectorPaths"], [list(path) for path in spec["selectors"].get(entry["table"], ())])
                self.assertIs(entry["writeAccess"], entry["table"] in spec["businessWrites"])
                self.assertIs(entry["exactAbsence"], True)
                self.assertEqual(entry["indexContract"], "incremental-authenticated-relation-root-v3")
                self.assertEqual(entry["predicateKind"], "relation-root-and-explicit-key-set")
                self.assertEqual(entry["selectorSource"], "closed-operation-argument-path-v1")
                self.assertEqual(entry["proofKind"], "radix16-canonical-multiproof-v2")
                self.assertEqual(entry["maximumRows"], authority_contract.MAX_SELECTORS_PER_OPERATION)

    def test_authorization_manifest_has_separate_complete_sorted_projection(self) -> None:
        manifest = primary.source_authorization_manifest()
        expected = [
            {"operation": operation, "ordinal": ordinal, "table": table,
             "keyColumns": list(primary.PRIMARY_KEY_COLUMNS[table]),
             "predicateKind": "primary-key-full-row-and-authenticated-root-v1", "exactAbsence": True}
            for operation, spec in sorted(authority_contract.OPERATIONS.items())
            for ordinal, table in enumerate(sorted(spec["authorizationReads"]), start=1)
        ]
        self.assertEqual(manifest, expected)

    def test_manifest_and_entry_digests_keep_existing_length_framing(self) -> None:
        for manifest, domain, digest, entry_digest in (
            (primary.source_query_manifest(), "serverware.policyAuthorityQueryManifest",
             primary.source_query_manifest_digest(), primary.query_manifest_entry_digest),
            (primary.source_authorization_manifest(), "serverware.policyAuthorityAuthorizationManifest",
             primary.source_authorization_manifest_digest(), primary.authorization_manifest_entry_digest),
        ):
            self.assertEqual(digest, independent_digest(domain + "/v1", manifest))
            self.assertNotEqual(digest, independent_digest(domain + "/v1", list(reversed(manifest))))
            entry = manifest[0]
            self.assertEqual(entry_digest(entry), independent_digest(domain + "Entry/v1", entry))
            substituted = {**entry, "keyColumns": ["attacker_chosen_key"]}
            self.assertNotEqual(entry_digest(entry), entry_digest(substituted))
            payload = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("ascii")
            wrong = ((domain + "/v1").encode("ascii") + b"\0"
                     + len(payload).to_bytes(8, "big") + payload)
            self.assertNotEqual(digest, "sha256:" + hashlib.sha256(wrong).hexdigest())

    def test_manifest_results_are_fresh_not_mutable_global_authority(self) -> None:
        for factory, digest in (
            (primary.source_query_manifest, primary.source_query_manifest_digest),
            (primary.source_authorization_manifest, primary.source_authorization_manifest_digest),
        ):
            expected_digest = digest()
            first = factory()
            expected_first = json.loads(json.dumps(first))
            first[0]["keyColumns"].append("changed")
            first[0]["table"] = "changed"
            if "selectorPaths" in first[0]:
                first[0]["selectorPaths"].append(["untrusted"])
            first.clear()
            self.assertEqual(factory(), expected_first)
            self.assertEqual(digest(), expected_digest)

    def test_planner_admits_real_source_business_and_authorization_rows(self) -> None:
        operation = "webauthn.challenge.consume"
        for authorization in (False, True):
            rows, entries = manifest_row_fixture(operation, authorization=authorization)
            self.assertTrue(rows)
            admitted = primary.validate_planner_manifest_rows(operation, rows, authorization=authorization)
            self.assertIs(type(admitted), tuple)
            self.assertEqual(admitted, primary.validate_planner_manifest_rows(
                operation, tuple(rows), authorization=authorization))
            expected = tuple({
                "ordinal": entry["ordinal"],
                "predicateId": (
                    f"serverware.policyAuthorityAuthorizationQuery/{operation}/{entry['ordinal']}/{entry['table']}/v1"
                    if authorization else entry["predicateId"]
                ),
                "table": entry["table"], "keyColumns": entry["keyColumns"],
                "writeAccess": False if authorization else entry["writeAccess"],
                "selectorPaths": [] if authorization else entry["selectorPaths"],
                "maximumRows": authority_contract.MAX_QUERY_PROOFS if authorization else entry["maximumRows"],
                "entryDigest": row["entry_digest"],
            } for row, entry in zip(rows, entries))
            self.assertEqual(admitted, expected)
            admitted[0]["keyColumns"].append("mutated-return")
            admitted[0]["selectorPaths"].append(["mutated-return"])
            self.assertEqual(primary.validate_planner_manifest_rows(
                operation, rows, authorization=authorization), expected)
        self.assertEqual(primary.validate_planner_manifest_rows(
            "webauthn.counter.cas", [], authorization=True), ())

    def test_planner_rejects_coherent_key_and_entry_digest_with_copied_manifest_label(self) -> None:
        operation = "webauthn.challenge.consume"
        for authorization in (False, True):
            rows, entries = manifest_row_fixture(operation, authorization=authorization)
            primary.validate_planner_manifest_rows(operation, rows, authorization=authorization)
            copied_manifest_label = rows[0]["manifest_digest"]
            changed_entry = {**entries[0], "keyColumns": ["untrusted_primary_key"]}
            domain = ("serverware.policyAuthorityAuthorizationManifestEntry/v1" if authorization
                      else "serverware.policyAuthorityQueryManifestEntry/v1")
            rows[0] = {**rows[0], "key_columns_json": '["untrusted_primary_key"]',
                       "entry_digest": independent_digest(domain, changed_entry)}
            self.assertEqual(rows[0]["manifest_digest"], copied_manifest_label)
            self.assertNotEqual(rows[0]["entry_digest"], independent_digest(domain, entries[0]))
            with self.assertRaisesRegex(ValueError, "row differs from measured source"):
                primary.validate_planner_manifest_rows(operation, rows, authorization=authorization)

    def test_planner_rejects_each_metadata_substitution_missing_field_and_extra_field(self) -> None:
        operation = "webauthn.challenge.consume"
        for authorization in (False, True):
            rows, _ = manifest_row_fixture(operation, authorization=authorization)
            primary.validate_planner_manifest_rows(operation, rows, authorization=authorization)
            for field, value in rows[0].items():
                replacement = value + 1 if type(value) is int else value + "-changed"
                for changed in ({**rows[0], field: replacement},
                                {key: item for key, item in rows[0].items() if key != field}):
                    with self.subTest(authorization=authorization, field=field, missing=field not in changed):
                        with self.assertRaisesRegex(ValueError, "row differs from measured source"):
                            primary.validate_planner_manifest_rows(
                                operation, [changed, *rows[1:]], authorization=authorization)
            with self.assertRaisesRegex(ValueError, "row differs from measured source"):
                primary.validate_planner_manifest_rows(
                    operation, [{**rows[0], "unrequested_column": 1}, *rows[1:]], authorization=authorization)

    def test_planner_numeric_flags_do_not_accept_python_equality_coercions(self) -> None:
        for operation, authorization in (("webauthn.counter.cas", False),
                                         ("jit.request", False),
                                         ("webauthn.challenge.consume", True)):
            rows, _ = manifest_row_fixture(operation, authorization=authorization)
            primary.validate_planner_manifest_rows(operation, rows, authorization=authorization)
            if operation == "jit.request":
                self.assertEqual(rows[0]["write_access"], 0)
            for field, value in rows[0].items():
                if type(value) is not int:
                    continue
                replacements = [float(value), str(value)]
                if value in (0, 1):
                    replacements.append(bool(value))
                for replacement in replacements:
                    with self.subTest(authorization=authorization, field=field, replacement=replacement):
                        self.assertNotEqual(type(value), type(replacement))
                        with self.assertRaisesRegex(ValueError, "row differs from measured source"):
                            primary.validate_planner_manifest_rows(
                                operation, [{**rows[0], field: replacement}, *rows[1:]],
                                authorization=authorization)

    def test_planner_requires_exact_canonical_json_spelling(self) -> None:
        operation = "webauthn.challenge.consume"
        for authorization in (False, True):
            rows, _ = manifest_row_fixture(operation, authorization=authorization)
            primary.validate_planner_manifest_rows(operation, rows, authorization=authorization)
            fields = (("key_columns_json",) if authorization
                      else ("key_columns_json", "selector_paths_json"))
            for field in fields:
                changed = " " + rows[0][field]
                self.assertEqual(json.loads(changed), json.loads(rows[0][field]))
                with self.assertRaisesRegex(ValueError, "row differs from measured source"):
                    primary.validate_planner_manifest_rows(
                        operation, [{**rows[0], field: changed}, *rows[1:]], authorization=authorization)

    def test_planner_inventory_mode_and_row_shapes_are_bounded_and_closed(self) -> None:
        operation = "webauthn.challenge.consume"
        for authorization in (False, True):
            rows, _ = manifest_row_fixture(operation, authorization=authorization)
            primary.validate_planner_manifest_rows(operation, rows, authorization=authorization)
            for changed in (rows[:-1], rows + [rows[0]]):
                with self.assertRaisesRegex(ValueError, "source coverage changed"):
                    primary.validate_planner_manifest_rows(operation, changed, authorization=authorization)
            for malformed_row in (None, [], tuple(rows[0].items()), MappingProxyType(rows[0])):
                with self.assertRaisesRegex(ValueError, "row differs from measured source"):
                    primary.validate_planner_manifest_rows(
                        operation, [malformed_row, *rows[1:]], authorization=authorization)
            for malformed_rows in (None, {}, iter(rows), rows * (authority_contract.MAX_QUERY_PROOFS + 1)):
                with self.assertRaisesRegex(ValueError, "arguments are not bounded and exact"):
                    primary.validate_planner_manifest_rows(operation, malformed_rows, authorization=authorization)
            for malformed_mode in (0, 1, "authorization", None):
                with self.assertRaisesRegex(ValueError, "arguments are not bounded and exact"):
                    primary.validate_planner_manifest_rows(operation, rows, authorization=malformed_mode)
        auth_rows, _ = manifest_row_fixture(operation, authorization=True)
        self.assertGreater(len(auth_rows), 1)
        with self.assertRaisesRegex(ValueError, "row differs from measured source"):
            primary.validate_planner_manifest_rows(operation, list(reversed(auth_rows)), authorization=True)
        with self.assertRaisesRegex(ValueError, "row differs from measured source"):
            primary.validate_planner_manifest_rows(operation, [auth_rows[0]] * len(auth_rows), authorization=True)
        with self.assertRaisesRegex(ValueError, "source coverage changed"):
            primary.validate_planner_manifest_rows("webauthn.counter.cas", auth_rows, authorization=True)
        with self.assertRaisesRegex(ValueError, "closed authority contract"):
            primary.validate_planner_manifest_rows("unknown.operation", [], authorization=True)
        with self.assertRaisesRegex(ValueError, "arguments are not bounded and exact"):
            primary.validate_planner_manifest_rows([], [], authorization=True)

    def test_source_manifest_row_limit_matches_active_ddl(self) -> None:
        # Textual source drift only: no SQL parser, engine or installer ran.
        declarations = [body for table, body in re.findall(
            r"CREATE TABLE IF NOT EXISTS\s+([a-z][a-z0-9_]*)\s*\((.*?)\n\s*\);",
            committed_schema_literals(), flags=re.DOTALL,
        ) if table == "policy_authority_query_dependency_manifests"]
        self.assertEqual(len(declarations), 1)
        limits = re.findall(r"CHECK\s*\(maximum_rows BETWEEN 1 AND ([0-9]+)\)", declarations[0])
        self.assertEqual(limits, [str(authority_contract.MAX_SELECTORS_PER_OPERATION)])

    def test_both_live_loaders_use_the_directly_tested_manifest_admission(self) -> None:
        # Source wiring is distinct from the real pure admission calls above;
        # this does not import or bypass the deliberately closed registry.
        path = ROOT / "serverware/authority_planner.py"
        self.assertLess(path.stat().st_size, 2 * 1024 * 1024)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for name, authorization in (("_load_manifest", False), ("_load_authorization_manifest", True)):
            functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
            self.assertEqual(len(functions), 1)
            admission = [node for node in ast.walk(functions[0]) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Attribute)
                         and isinstance(node.func.value, ast.Name)
                         and node.func.value.id == "authority_primary_contract"
                         and node.func.attr == "validate_planner_manifest_rows"]
            self.assertEqual(len(admission), 1)
            self.assertEqual([ast.unparse(arg) for arg in admission[0].args], ["operation", "rows"])
            self.assertEqual(len(admission[0].keywords), 1)
            self.assertEqual(admission[0].keywords[0].arg, "authorization")
            self.assertIs(ast.literal_eval(admission[0].keywords[0].value), authorization)

    def test_production_module_has_no_database_registry_or_source_file_reader(self) -> None:
        tree = ast.parse((ROOT / "serverware/authority_primary_contract.py").read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(node.func.id, {"open", "exec", "eval", "__import__"})
        self.assertFalse(any("db" == name or "registry" in name or "psycopg" in name
                             or "authority_store" in name for name in imports))


if __name__ == "__main__":
    unittest.main()
