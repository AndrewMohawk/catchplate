#!/usr/bin/env python3
"""Pure production schema construction/admission and source-linkage controls.

Call only the actual pure schema producers and validators. Bounded AST reads
pin their production consumers without importing db, migrations or the blocked
registry, and without executing extracted source. The existing authority_store
package imports inert schema/crypto definitions; this is not a stdlib-only
package-isolation claim. These tests do not
prove PostgreSQL syntax, structural manifests, DDL/ACL installation, migration
locking, signed receipts, or successful production startup.
"""
from __future__ import annotations

import ast
import json
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_contract, authority_native_activation_schema, authority_native_jit_retention_schema
from catchplate.authority_store import schema as schema_module
from catchplate.authority_store import successor_execution_sql, successor_execution_privileges
from catchplate.authority_store import policy_file_read_sql, policy_file_genesis_sql, planner_read_sql
from catchplate.authority_store.completed_v9_schema_source import (
    COMPLETED_V9_RECEIPT_TABLE,
    completed_v9_schema_programs,
    require_metadata_schema_program,
)
from catchplate.authority_store.metadata_schema_source import (
    metadata_base_schema_source,
    metadata_initialization_index_source,
    metadata_schema_source,
)
from catchplate.authority_store.v9_schema_source import (
    authority_v9_schema_source, planner_retention_guard_sql, planner_retention_sqlite_guards_sql,
    capability_retention_guard_sql, capability_retention_sqlite_guards_sql,
)


RECEIPT = "policy_authority_v9_offline_migration_receipts"
SUCCESSOR = "policy_authority_authorization_dependency_manifests"
START = "CREATE TABLE IF NOT EXISTS\n            " + RECEIPT + " ("
END = "CREATE TABLE IF NOT EXISTS\n            " + SUCCESSOR + " ("

# Independently spell the one admitted historical table, not a production
# private constant or a permissive deletion of whichever new columns appear.
LEGACY_RECEIPT = """
        CREATE TABLE IF NOT EXISTS
            policy_authority_v9_offline_migration_receipts (
                contract_id TEXT PRIMARY KEY,
                source_version BIGINT NOT NULL,
                target_version BIGINT NOT NULL,
                before_manifest_json TEXT NOT NULL,
                before_manifest_digest TEXT NOT NULL,
                before_row_counts_json TEXT NOT NULL,
                before_row_counts_digest TEXT NOT NULL,
                after_manifest_json TEXT NOT NULL,
                after_manifest_digest TEXT NOT NULL,
                after_row_counts_json TEXT NOT NULL,
                after_row_counts_digest TEXT NOT NULL,
                operation_contract_digest TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                receipt_digest TEXT NOT NULL UNIQUE,
                signer_identity_digest TEXT,
                signature_algorithm TEXT,
                detached_signature TEXT,
                detached_signature_digest TEXT UNIQUE,
                status TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                CHECK (
                    contract_id =
                    'catchplate.policyCandidateAuthorityOfflineMigration/v2:v8-to-v9'
                ),
                CHECK (source_version = 8),
                CHECK (target_version = 9),
                CHECK (status = 'completed'),
                CHECK (length(before_manifest_json) BETWEEN 2 AND 67108864),
                CHECK (length(after_manifest_json) BETWEEN 2 AND 67108864),
                CHECK (length(before_row_counts_json) BETWEEN 2 AND 4194304),
                CHECK (length(after_row_counts_json) BETWEEN 2 AND 4194304),
                CHECK (length(receipt_json) BETWEEN 2 AND 67108864),
                CHECK (
                    signer_identity_digest IS NOT NULL
                    AND signature_algorithm = 'Ed25519'
                    AND detached_signature IS NOT NULL
                    AND detached_signature_digest IS NOT NULL
                )
            );
"""


def read_source(relative: str, maximum: int = 2 * 1024 * 1024):
    path = ROOT / relative
    if path.stat().st_size > maximum:
        raise AssertionError("source fixture exceeded its explicit file bound")
    source = path.read_text(encoding="utf-8")
    return source, ast.parse(source)


def function(tree, name):
    matches = [node for node in tree.body
               if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(matches) != 1:
        raise AssertionError("source function is not unique: " + name)
    return matches[0]


def calls(node, name):
    return [item for item in ast.walk(node) if isinstance(item, ast.Call)
            and ((isinstance(item.func, ast.Name) and item.func.id == name)
                 or (isinstance(item.func, ast.Attribute) and item.func.attr == name))]


def keyword(call, name):
    values = [item.value for item in call.keywords if item.arg == name]
    if len(values) != 1:
        raise AssertionError("source call keyword is not unique: " + name)
    return values[0]


def assignment(node, name):
    matches = [item for item in ast.walk(node) if isinstance(item, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == name for target in item.targets)]
    if len(matches) != 1:
        raise AssertionError("source assignment is not unique: " + name)
    return matches[0]


class AuthoritySchemaSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = metadata_base_schema_source()
        cls.extension = authority_v9_schema_source()
        cls.initial = (cls.base + authority_native_activation_schema.source()
                       + authority_native_jit_retention_schema.source() + cls.extension)
        cls.initialization_indexes = metadata_initialization_index_source()
        cls.complete = metadata_schema_source()

    def assert_shape(self, node, expression):
        # Fixed expressions are parsed for comparison, never evaluated.
        self.assertEqual(ast.dump(node), ast.dump(ast.parse(expression, mode="eval").body))

    def assert_rejected(self, value):
        with self.assertRaises(ValueError):
            completed_v9_schema_programs(value)
        with self.assertRaises(ValueError):
            require_metadata_schema_program(value)
        with self.assertRaises(ValueError):
            require_metadata_schema_program(value, legacy_completed_v9_receipt=True)

    def test_postgres_namespace_canonicalization_preserves_complete_definition(self):
        scratch = "catchplate_candidate_authority_expected_v9"
        canonical = "catchplate_metadata"
        definition = (
            f"CREATE FUNCTION {scratch}.guard() RETURNS void LANGUAGE plpgsql "
            f"SET search_path TO 'pg_catalog', '{scratch}', 'pg_temp' "
            "AS $function$ BEGIN "
            f"PERFORM 1 FROM pg_catalog.pg_namespace WHERE nspname = '{scratch}'; "
            "EXECUTE pg_catalog.format('SELECT * FROM %I.%I', "
            f"'{scratch}', 'credentials'); "
            f'PERFORM * FROM "{scratch}".credentials; '
            "END $function$"
        )
        expected = definition.replace(scratch, canonical)
        actual = schema_module._policy_candidate_authority_canonicalize_namespace(
            definition, actual_namespace=scratch, canonical_namespace=canonical,
        )
        self.assertEqual(actual, expected)
        self.assertEqual(
            schema_module._policy_candidate_authority_object_definition(
                name="guard", definition=actual,
            ),
            schema_module._policy_candidate_authority_object_definition(
                name="guard", definition=expected,
            ),
        )

    def test_postgres_namespace_canonicalization_preserves_unauthorized_differences(self):
        scratch = "catchplate_candidate_authority_expected_v9"
        canonical = "catchplate_metadata"

        def normalize(value, namespace=scratch):
            return schema_module._policy_candidate_authority_canonicalize_namespace(
                value, actual_namespace=namespace, canonical_namespace=canonical,
            )

        original = f"SET search_path TO 'pg_catalog', '{scratch}', 'pg_temp' BEGIN RETURN 1; END"
        expected = normalize(original)
        for changed in (
            original.replace("'pg_catalog', ", ""),
            original.replace("'pg_catalog', ", "'public', 'pg_catalog', "),
            original.replace(f"'pg_catalog', '{scratch}'", f"'{scratch}', 'pg_catalog'"),
            original.replace(scratch, "foreign_namespace"),
            original.replace(scratch, "prefix_" + scratch),
            original.replace(scratch, scratch + "_suffix"),
            original.replace("RETURN 1", "RETURN 2"),
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(normalize(changed), expected)
        for literal in (
            "'prefix''" + scratch + "'",
            "'" + scratch + "''suffix'",
            "'''" + scratch + "'''",
            "'prefix_" + scratch + "'",
            "'" + scratch + "_suffix'",
        ):
            with self.subTest(literal=literal):
                self.assertEqual(normalize(literal), literal)
        # Actual target definitions are never translated into a reference view.
        self.assertEqual(normalize(original, canonical), original)

    def test_postgres_required_guards_include_complete_schema_inventory(self):
        # Source-linkage control only. The disposable full-schema fixture proves
        # real business-table guard acceptance and a dropped guard's refusal.
        _, tree = read_source("catchplate/authority_store/schema.py")
        validator = function(tree, "_validate_policy_candidate_authority_structure")
        updates = [node for node in calls(validator, "update")
                   if isinstance(node.func, ast.Attribute)
                   and isinstance(node.func.value, ast.Name)
                   and node.func.value.id == "actual_trigger_names"]
        self.assertEqual(len(updates), 1)
        branches = [node for node in ast.walk(validator) if isinstance(node, ast.If)
                    and any(isinstance(item, ast.Expr) and item.value is updates[0]
                            for item in node.body)]
        self.assertEqual(len(branches), 1)
        self.assert_shape(branches[0].test, "isinstance(conn, PostgresMetadataConnection)")
        self.assertEqual(len(updates[0].args), 1)
        self.assert_shape(updates[0].args[0],
            '(str(trigger["name"]) for trigger in manifest["objectAuthority"]["triggers"])')
        self.assert_shape(assignment(validator, "missing_triggers").value,
                          "sorted(required_triggers - actual_trigger_names)")
        refusal = [node for node in ast.walk(validator) if isinstance(node, ast.If)
                   and ast.dump(node.test) == ast.dump(ast.parse(
                       "missing_triggers or missing_functions", mode="eval").body)]
        self.assertEqual(len(refusal), 1)
        self.assertTrue(any(isinstance(node, ast.Raise) for node in refusal[0].body))
        equality = [node for node in ast.walk(validator) if isinstance(node, ast.If)
                    and ast.dump(node.test) == ast.dump(ast.parse(
                        "manifest != expected_manifest", mode="eval").body)]
        self.assertEqual(len(equality), 1)
        self.assertTrue(any(isinstance(node, ast.Raise) for node in equality[0].body))

    def test_composite_foreign_keys_have_exact_active_unique_targets(self):
        # Six confirmed PostgreSQL target-key regressions, not a SQL parser or
        # execution proof. Retired commented DDL must not satisfy the controls.
        active = re.sub(r"/\*.*?\*/|--[^\n]*", "", self.complete, flags=re.DOTALL)

        def table(name):
            bodies = re.findall(r"\bCREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+"
                + re.escape(name) + r"\s*\((.*?)\)\s*;", active, re.DOTALL)
            self.assertEqual(len(bodies), 1, name)
            return bodies[0]

        def columns(names):
            return r"\s*,\s*".join(re.escape(name) for name in names)

        assignment = ("assignment_envelope_digest", "assignment_payload_digest")
        artifact = ("artifact_envelope_digest", "artifact_payload_digest", "candidate_policy_hash",
            "compiler_digest", "compiler_config_digest", "policy_schema_digest", "semantic_model_digest",
            "evaluator_abi_digest", "policy_bundle_digest", "runtime_digest")
        assignment_identity = ("canary_id",) + assignment + artifact
        instance_identity = ("canary_id", "instance_id", "boot_id") + assignment + artifact + (
            "boot_public_key_digest", "boot_signing_key_id")
        custody = ("custody_evidence_envelope_digest", "verification_receipt_digest")
        cases = (
            ("policy_canary_assignments", assignment,
                ("policy_runtime_attestations", "policy_canary_assignment_members", "policy_compiler_authority_analyses")),
            ("policy_canary_assignments", ("canary_id",) + assignment, ("policy_canary_revisions",)),
            ("policy_canary_assignments", assignment_identity, ("policy_canary_instances", "policy_canary_readiness")),
            ("policy_canary_instances", instance_identity, ("policy_canary_load_receipts",)),
            ("policy_canary_custody_evidence", custody,
                ("policy_canary_active_decisions", "policy_canary_shadow_observations")),
            ("policy_activation_export_issuances", ("export_id", "export_revision"), ("policy_activation_export_pages",)),
        )
        for parent, target, children in cases:
            with self.subTest(parent=parent, target=target):
                self.assertRegex(table(parent), r"\bUNIQUE\s*\(\s*" + columns(target) + r"\s*\)")
                local = ("custody_evidence_envelope_digest", "custody_verification_receipt_digest") \
                    if target == custody else target
                for child in children:
                    with self.subTest(child=child):
                        self.assertRegex(table(child), r"\bFOREIGN\s+KEY\s*\(\s*" + columns(local)
                            + r"\s*\)\s*REFERENCES\s+" + re.escape(parent) + r"\s*\(\s*"
                            + columns(target) + r"\s*\)\s*ON\s+DELETE\s+RESTRICT\b")

    def test_active_authority_source_revisions_match_canonical_contract(self):
        # Check the emitted SQL, excluding retired commented definitions. This
        # source control does not claim PostgreSQL execution or store migration.
        # The retained-native table contributes the one composed-only check;
        # all 33 base/extension checks are active current-source constraints,
        # not historical migration input that may preserve an older revision.
        for name, source, count in (("base", self.base, 9),
                ("v9 extension", self.extension, 24), ("composed", self.complete, 34)):
            with self.subTest(source=name):
                active = re.sub(r"/\*.*?\*/|--[^\n]*", "", source, flags=re.DOTALL)
                revisions = re.findall(
                    r"'(catchplate\.policyCandidateAuthoritySource/[^']*)'", active)
                self.assertEqual(len(revisions), count)
                self.assertEqual(set(revisions), {authority_contract.SOURCE_REVISION})

    def test_current_root_operation_inventories_cover_oidc_execution(self):
        # Source rendering only: no database, signature, custody or execution
        # admission is supplied by matching these inventories.
        from catchplate.authority_store import current_root_execution_sql as effects

        installed = ("oidc.session.activate", "oidc.session.activation-delivery.consume",
            "webauthn.credential.revoke", "webauthn.registration.evidence.admit",
            "webauthn.registration.finalize", "webauthn.trust.complete",
            "webauthn.trust.installation.admit", "webauthn.trust.stage")
        declared = ("oidc.session.activate", "oidc.session.activation-delivery.consume",
            "jit.review-open.receipt.issue", "webauthn.credential.revoke",
            "webauthn.registration.evidence.admit", "webauthn.registration.finalize",
            "webauthn.trust.complete", "webauthn.trust.installation.admit", "webauthn.trust.stage")
        typed = ("jit.assertion.issue", "jit.review-open.authorize", "jit.review-open.receipt.issue",
            "oidc.session.activate", "oidc.session.activation-delivery.consume",
            "webauthn.challenge.maintain", "webauthn.credential.revoke",
            "webauthn.registration.evidence.admit", "webauthn.registration.finalize",
            "webauthn.trust.complete", "webauthn.trust.installation.admit", "webauthn.trust.stage")
        dedicated = ("jit.assertion.issue", "webauthn.challenge.maintain", "jit.review-open.authorize")
        components = {"jit.review-open.authorize", "jit.review-open.receipt.issue"}
        planned = tuple(sorted(operation for operation, spec in authority_contract.OPERATIONS.items()
            if spec["planningMode"] == "typed-successor-planning"))
        self.assertEqual(planned, typed)
        self.assertEqual(authority_contract.CURRENT_ROOT_COMMIT_MARKER_CONTRACT["operations"], declared)
        self.assertEqual(effects.OPERATIONS, declared)
        self.assertEqual(effects._DEDICATED_PLANNING_OPERATIONS, dedicated)
        self.assertTrue(set(declared).isdisjoint(dedicated))
        self.assertEqual(set(typed), set(declared) | set(dedicated))
        self.assertEqual(set(typed) - components,
            set(installed) | {"jit.assertion.issue", "webauthn.challenge.maintain"})
        active = re.sub(r"/\*.*?\*/|--[^\n]*", "", self.complete, flags=re.DOTALL)
        tables = re.findall(r"\bCREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+"
            r"policy_authority_current_root_commit_markers\s*\((.*?)\)\s*;", active, re.DOTALL)
        self.assertEqual(len(tables), 1)
        checks = re.findall(r"\bCHECK\s*\(\s*operation\s+IN\s*\(([^)]*)\)\s*\)", tables[0])
        self.assertEqual(len(checks), 1)
        self.assertEqual(tuple(re.findall(r"'([^']*)'", checks[0])), installed)
        # The native receipt's bridge is intentionally unfinished. Do not
        # pretend its declared marker is installed, widen the existing DDL,
        # or mistake a read/replay component for a plannable operation.
        self.assertEqual(set(declared) - set(installed), {"jit.review-open.receipt.issue"})
        self.assertEqual(set(installed) - set(declared), set())
        _, registry = read_source("catchplate/authority_transition_registry.py")
        def registry_value(name):
            matches = [node.value for node in registry.body if isinstance(node, ast.AnnAssign)
                       and isinstance(node.target, ast.Name) and node.target.id == name]
            self.assertEqual(len(matches), 1)
            return matches[0]
        self.assert_shape(registry_value("COMPONENT_ONLY_SUCCESSOR_OPERATIONS"),
            "frozenset({'jit.review-open.authorize', 'jit.review-open.receipt.issue'})")
        self.assert_shape(registry_value("SUCCESSOR_PLANNABLE_OPERATIONS"),
            "frozenset(set(SUCCESSOR_PROGRAMS) - COMPONENT_ONLY_SUCCESSOR_OPERATIONS)")
        self.assert_shape(registry_value("LEGACY_PLANNABLE_OPERATIONS"),
            "frozenset(set(KERNELS) | set(WEBAUTHN_CHALLENGE_OPERATIONS))")
        self.assert_shape(registry_value("PLANNABLE_OPERATIONS"),
            "LEGACY_PLANNABLE_OPERATIONS | SUCCESSOR_PLANNABLE_OPERATIONS")
        closure = function(registry, "_registry_closure_errors")
        blocked = [node for node in ast.walk(closure) if isinstance(node, ast.Tuple)
                   and len(node.elts) == 2 and isinstance(node.elts[0], ast.Constant)
                   and node.elts[0].value == "component-only operations are plannable"]
        self.assertEqual(len(blocked), 1)
        self.assert_shape(blocked[0].elts[1], "COMPONENT_ONLY_SUCCESSOR_OPERATIONS & PLANNABLE_OPERATIONS")
        self.assert_shape(assignment(registry, "_CLOSURE_ERRORS").value, "_registry_closure_errors()")
        closure_guards = [node for node in registry.body if isinstance(node, ast.If)
                          and isinstance(node.test, ast.Name) and node.test.id == "_CLOSURE_ERRORS"]
        self.assertEqual(len(closure_guards), 1)
        self.assertEqual(len(closure_guards[0].body), 1)
        self.assertIsInstance(closure_guards[0].body[0], ast.Raise)
        select = function(registry, "successor_program")
        selection_guards = [node for node in select.body if isinstance(node, ast.If)]
        self.assertEqual(len(selection_guards), 1)
        self.assert_shape(selection_guards[0].test,
            "type(operation) is not str or operation not in SUCCESSOR_PLANNABLE_OPERATIONS")
        self.assertIsInstance(selection_guards[0].body[0], ast.Raise)
        _, programs = read_source("catchplate/authority_successor_programs.py")
        program = function(programs, "_program")
        self.assertEqual(program.args.args[-1].arg, "plan_factory")
        self.assert_shape(program.args.defaults[-1], "None")
        returned = [node for node in program.body if isinstance(node, ast.Return)]
        self.assertEqual(len(returned), 1)
        self.assert_shape(keyword(returned[0].value, "plan_factory"), "plan_factory")
        for operation, reader, kernel in (
            ("jit.review-open.authorize", "_native_review_authorize", "_native_review_authorize_kernel"),
            ("jit.review-open.receipt.issue", "_native_review_receipt", "_native_review_receipt_kernel"),
        ):
            sites = [call for call in calls(programs, "_program")
                     if call.args and isinstance(call.args[0], ast.Constant)
                     and call.args[0].value == operation]
            self.assertEqual(len(sites), 1)
            self.assert_shape(sites[0], "_program(" + repr(operation) + ", " + reader
                + ", 'read-replay-components', kernel_factory=" + kernel + ")")
        rendered = effects.current_root_execution_apply_body_sql('"catchplate_metadata"')
        sources = re.findall(r"crx_source\s*:=\s*'((?:[^']|'')*)'::jsonb->crx_operation;", rendered)
        self.assertEqual(len(sources), 1)
        operations = json.loads(sources[0].replace("''", "'"))
        self.assertEqual(tuple(sorted(operations)), tuple(sorted(declared)))
        for operation, writes in (
            ("oidc.session.activate", {"oidc_browser_sessions", "oidc_session_activation_deliveries",
                "webauthn_credentials", "webauthn_challenges", "metadata_audit_outbox",
                "policy_authority_bounded_aggregate_states"}),
            ("oidc.session.activation-delivery.consume", {"oidc_session_activation_deliveries",
                "metadata_audit_outbox", "policy_authority_bounded_aggregate_states"}),
        ):
            with self.subTest(operation=operation):
                self.assertEqual(set(operations[operation]["writes"]), writes)
                self.assertTrue(writes <= set(operations[operation]["keys"]))

    def test_bootstrap_crypto_reads_only_the_supplied_transaction(self):
        _, tree = read_source("catchplate/db.py", 16 * 1024 * 1024)
        reader = function(tree, "_postgres_metadata_crypto_required")
        self.assertEqual([arg.arg for arg in reader.args.args], ["conn"])
        self.assertEqual(reader.args.defaults, [])
        self.assert_shape(reader.body[1].test, "not isinstance(conn, PostgresMetadataConnection)")
        self.assertIsInstance(reader.body[1].body[0], ast.Raise)
        for forbidden in ("connect", "_metadata_pg_connect_raw", "_metadata_pg_bootstrap_connect_raw",
                          "commit", "rollback", "close", "load_bound_secret_keyring"):
            self.assertEqual(calls(reader, forbidden), [])
        self.assertEqual(len(calls(reader, "execute")), 3)
        for call in calls(reader, "execute"):
            self.assert_shape(call.func.value, "conn")

    def test_bootstrap_crypto_runs_under_the_existing_installation_locks(self):
        _, tree = read_source("catchplate/db.py", 16 * 1024 * 1024)
        init = function(tree, "init_db")
        transaction = next(node for node in init.body if isinstance(node, ast.With)
                           and isinstance(node.items[0].context_expr, ast.Name)
                           and node.items[0].context_expr.id == "initialization_connection")
        self.assertIsInstance(transaction.items[0].optional_vars, ast.Name)
        self.assertEqual(transaction.items[0].optional_vars.id, "conn")
        postgres = transaction.body[0]
        self.assert_shape(postgres.test, "isinstance(conn, PostgresMetadataConnection)")
        crypto = calls(init, "_postgres_metadata_crypto_required")
        self.assertEqual(len(crypto), 1)
        self.assertIn(crypto[0], list(ast.walk(postgres)))
        self.assert_shape(crypto[0], "_postgres_metadata_crypto_required(conn)")
        locking = calls(postgres, "_lock_postgres_metadata_initialization_authorities")
        self.assertEqual(len(locking), 1)
        self.assert_shape(locking[0], "_lock_postgres_metadata_initialization_authorities(conn)")
        self.assertLess(locking[0].lineno, crypto[0].lineno)
        migration_lock = [call for call in calls(postgres, "execute")
                          if call.args and isinstance(call.args[0], ast.Constant)
                          and call.args[0].value == "SELECT pg_advisory_xact_lock(?)"]
        self.assertEqual(len(migration_lock), 1)
        self.assert_shape(migration_lock[0].func, "conn.execute")
        self.assert_shape(migration_lock[0].args[1], "(_METADATA_MIGRATION_LOCK_KEY,)")
        self.assertLess(migration_lock[0].lineno, locking[0].lineno)
        lock_owner = function(tree, "_lock_postgres_metadata_initialization_authorities")
        held = []
        for lock in ("_lock_policy_candidate_authority", "_lock_policy_high_water"):
            sites = calls(lock_owner, lock)
            self.assertEqual(len(sites), 1)
            self.assert_shape(sites[0], lock + "(conn)")
            held.append(sites[0])
        self.assertLess(held[0].lineno, held[1].lineno)
        for forbidden in ("connect", "_metadata_pg_connect_raw", "_metadata_pg_bootstrap_connect_raw",
                          "commit", "rollback", "close"):
            self.assertEqual(calls(lock_owner, forbidden), [])
        needed = next(node for node in postgres.body if isinstance(node, ast.If)
                      and node.test is crypto[0])
        self.assertEqual(len(calls(needed, "load_bound_secret_keyring")), 1)
        self.assertLess(calls(init, "_metadata_pg_bootstrap_connect_raw")[0].lineno,
                        transaction.lineno)

    def test_runtime_readiness_and_offline_contract_guards_are_not_bypassed(self):
        _, tree = read_source("catchplate/db.py", 16 * 1024 * 1024)
        init = function(tree, "init_db")
        readiness = next(node for node in init.body if isinstance(node, ast.If)
                         and calls(node, "_assert_postgres_metadata_runtime_ready"))
        self.assert_shape(readiness.test,
                          "metadata_uses_postgres() and borrowed_offline_connection is None "
                          "and bootstrap_contract_id is None")
        self.assertIsInstance(readiness.body[-1], ast.Return)
        bootstrap = calls(init, "_metadata_pg_bootstrap_connect_raw")[0]
        self.assert_shape(keyword(bootstrap, "contract_id"), "str(bootstrap_contract_id)")
        self.assertLess(readiness.end_lineno, bootstrap.lineno)
        admission = function(tree, "_metadata_pg_bootstrap_connect_raw")
        self.assert_shape(admission.body[0].test,
                          "contract_id != _METADATA_STORE_BOOTSTRAP_CONTRACT_ID or "
                          "os.environ.get('CATCHPLATE_PROCESS_MODE', '').strip() != 'metadata-bootstrap'")
        self.assertIsInstance(admission.body[0].body[0], ast.Raise)

    def test_complete_program_includes_final_initialization_indexes(self):
        for value in (self.base, self.extension, self.complete):
            self.assertIs(type(value), str)
            self.assertTrue(value)
        self.assertEqual(
            metadata_schema_source(include_initialization_indexes=False), self.initial,
        )
        self.assertEqual(self.complete, self.initial + self.initialization_indexes)
        self.assertEqual(metadata_schema_source(), self.complete)
        self.assertNotIn(START, self.base)
        self.assertNotIn("CREATE TABLE IF NOT EXISTS credentials (", self.extension)
        self.assertTrue(self.complete.startswith(self.base))
        self.assertTrue(self.complete.endswith(self.initialization_indexes))

    def test_complete_inventory_and_receipt_boundaries_are_unique(self):
        for table in (
            "catchplate_store_migrations", "credentials",
            "policy_authority_schema_contracts", "policy_activation_revisions",
            "policy_authority_fence_heads", RECEIPT,
            *authority_contract.V9_ADDITIONAL_PROTECTED_TABLES,
        ):
            with self.subTest(table=table):
                pattern = r"CREATE TABLE IF NOT EXISTS\s+" + re.escape(table) + r"\s*\("
                self.assertEqual(len(re.findall(pattern, self.complete)), 1)
        self.assertEqual(COMPLETED_V9_RECEIPT_TABLE, RECEIPT)
        self.assertEqual(self.complete.count(START), 1)
        self.assertEqual(self.complete.count(END), 1)
        self.assertLess(self.complete.index(START), self.complete.index(END))

    def test_v9_source_has_only_two_named_source_owned_substitutions(self):
        # Preserve this test ID; the closed source now has a third bounded
        # substitution for the successor frame ordinal.
        _, tree = read_source("catchplate/authority_store/v9_schema_source.py")
        body = function(tree, "authority_v9_schema_source").body
        self.assertEqual(len(body), 1)
        self.assertIsInstance(body[0], ast.Return)
        value = body[0].value
        substitutions = (
            ("__SUCCESSOR_MAX_FRAME_ORDINAL__",
                "str(authority_contract.SUCCESSOR_EXECUTION_FRAME_CONTRACT['maximumFrames'] - 1)"),
            ("__MAX_PLAN_WORK_UNITS__", "str(authority_contract.MAX_PLAN_WORK_UNITS)"),
            ("__MAX_PLAN_SELECTED_BYTES__", "str(authority_contract.MAX_PLAN_SELECTED_BYTES)"),
        )
        for token, expression in substitutions:
            self.assertIsInstance(value, ast.Call)
            self.assertIsInstance(value.func, ast.Attribute)
            self.assertEqual(value.func.attr, "replace")
            self.assertEqual(value.keywords, [])
            self.assertEqual(len(value.args), 2)
            self.assert_shape(value.args[0], repr(token))
            self.assert_shape(value.args[1], expression)
            value = value.func.value
        self.assertIsInstance(value, ast.Constant)
        self.assertIs(type(value.value), str)
        for token, _ in substitutions:
            self.assertEqual(value.value.count(token), 1)
            self.assertNotIn(token, self.extension)
        self.assertIn("CHECK (work_units BETWEEN 1 AND "
                      + str(authority_contract.MAX_PLAN_WORK_UNITS) + ")", self.extension)
        self.assertIn("BETWEEN 2 AND " + str(authority_contract.MAX_PLAN_SELECTED_BYTES),
                      self.extension)
        self.assertIn("CHECK (frame_ordinal BETWEEN 0 AND "
                      + str(authority_contract.SUCCESSOR_EXECUTION_FRAME_CONTRACT["maximumFrames"] - 1)
                      + ")", self.extension)

    def test_current_and_legacy_variants_require_the_exact_explicit_selection(self):
        _, legacy = completed_v9_schema_programs(self.complete)
        self.assertIsNone(require_metadata_schema_program(self.complete))
        self.assertIsNone(require_metadata_schema_program(
            self.complete, legacy_completed_v9_receipt=False))
        self.assertIsNone(require_metadata_schema_program(
            legacy, legacy_completed_v9_receipt=True))
        with self.assertRaises(ValueError):
            require_metadata_schema_program(legacy)
        with self.assertRaises(ValueError):
            require_metadata_schema_program(self.complete, legacy_completed_v9_receipt=True)
        with self.assertRaises(ValueError):
            completed_v9_schema_programs(legacy)

    def test_source_and_variant_types_are_exact_not_coerced(self):
        class StringSubclass(str):
            pass

        for value in (None, True, 1, b"", self.complete.encode("utf-8"),
                      bytearray(self.complete.encode("utf-8")), [], {}, StringSubclass(self.complete)):
            with self.subTest(type=type(value).__name__):
                self.assert_rejected(value)
        for flag in (None, 0, 1, "false", "true", [], {}):
            with self.subTest(flag=repr(flag)):
                with self.assertRaises(ValueError):
                    require_metadata_schema_program(self.complete, legacy_completed_v9_receipt=flag)

    def test_partial_truncated_duplicate_and_reordered_programs_are_rejected(self):
        target, _ = completed_v9_schema_programs(self.complete)
        for value in (
            "", self.base, self.extension, target,
            self.complete[1:], self.complete[:-1], self.complete.strip(),
            self.extension + self.base, self.complete + self.extension,
            self.complete + target, self.complete + self.complete,
        ):
            with self.subTest(length=len(value), prefix=value[:32]):
                self.assert_rejected(value)

    def test_base_extension_and_whitespace_tampering_are_rejected(self):
        for old, new in (
            ("CREATE TABLE IF NOT EXISTS credentials (", "CREATE TABLE IF NOT EXISTS other_credentials ("),
            ("migration_name TEXT NOT NULL", "migration_name TEXT"),
            ("signer_public_key_base64url TEXT NOT NULL", "signer_public_key_base64url TEXT"),
            (authority_contract.SOURCE_REVISION, authority_contract.SOURCE_REVISION + ".tampered"),
        ):
            self.assertIn(old, self.complete)
            with self.subTest(old=old):
                self.assert_rejected(self.complete.replace(old, new, 1))
        self.assert_rejected(self.complete + "\n")

    def test_legacy_changes_only_the_exact_receipt_slice_preserving_complete_surroundings(self):
        target, legacy = completed_v9_schema_programs(self.complete)
        start, end = self.complete.index(START), self.complete.index(END)
        prefix, suffix = self.complete[:start], self.complete[end:]
        self.assertEqual(target, self.complete[start:end])
        self.assertEqual(legacy, prefix + LEGACY_RECEIPT + "\n        " + suffix)
        self.assertTrue(prefix.startswith(self.base))
        self.assertTrue(legacy.startswith(prefix))
        self.assertTrue(legacy.endswith(suffix))
        self.assertEqual(legacy.count(START), 1)
        self.assertEqual(legacy.count(END), 1)
        self.assertEqual(target.count("CREATE TABLE IF NOT EXISTS"), 1)
        for field in ("migration_name", "migration_sha256", "source_revision", "signer_public_key_base64url"):
            self.assertIn(field + " TEXT NOT NULL", target)
            self.assertNotIn(field + " TEXT", LEGACY_RECEIPT)
        self.assertIn("signer_identity_digest TEXT NOT NULL", target)
        self.assertIn("signer_identity_digest TEXT,", LEGACY_RECEIPT)

    def test_legacy_admission_is_not_a_receipt_only_or_arbitrary_historical_schema_waiver(self):
        _, legacy = completed_v9_schema_programs(self.complete)
        for value in (
            LEGACY_RECEIPT,
            legacy[len(self.base):],
            legacy + LEGACY_RECEIPT,
            legacy.replace("signer_identity_digest TEXT,", "signer_identity_digest TEXT NOT NULL,", 1),
            legacy.replace("CREATE TABLE IF NOT EXISTS credentials (", "CREATE TABLE IF NOT EXISTS stale_credentials (", 1),
            legacy + "\n",
        ):
            with self.subTest(length=len(value), prefix=value[:32]):
                self.assert_rejected(value)

    def test_pure_modules_have_closed_imports_and_no_runtime_or_io_calls(self):
        expected = {
            "metadata_schema_source.py": {
                ("__future__", "annotations", None),
                ("catchplate.authority_store.v9_schema_source", "authority_v9_schema_source", None),
                ("catchplate", "authority_native_activation_schema", None),
                ("catchplate", "authority_native_jit_retention_schema", None),
            },
            "v9_schema_source.py": {
                ("__future__", "annotations", None), ("catchplate", "authority_contract", None),
            },
            "completed_v9_schema_source.py": {
                ("__future__", "annotations", None),
                ("catchplate.authority_store.metadata_schema_source", "metadata_schema_source", None),
            },
        }
        for filename, bindings in expected.items():
            with self.subTest(filename=filename):
                _, tree = read_source("catchplate/authority_store/" + filename, 16 * 1024 * 1024)
                imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
                self.assertTrue(all(isinstance(node, ast.ImportFrom) for node in imports))
                actual = [(node.module, alias.name, alias.asname)
                          for node in imports for alias in node.names]
                self.assertEqual(len(actual), len(bindings))
                self.assertEqual(set(actual), bindings)
                names = {node.func.id for node in ast.walk(tree)
                         if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
                self.assertTrue(names.isdisjoint({"open", "eval", "exec", "compile", "__import__"}))

    def test_db_initialization_preserves_late_indexes_and_compares_complete_program(self):
        _, tree = read_source("catchplate/db.py", 16 * 1024 * 1024)
        aliases = [alias for node in tree.body if isinstance(node, ast.ImportFrom)
                   and node.module == "catchplate.authority_store" for alias in node.names
                   if alias.name == "metadata_schema_source"]
        self.assertEqual([(alias.name, alias.asname) for alias in aliases],
                         [("metadata_schema_source", "_metadata_schema_source")])
        init = function(tree, "init_db")
        assignments = [node for node in ast.walk(init) if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "metadata_schema_source"
                               for target in node.targets)]
        self.assertEqual(len(assignments), 1)
        self.assert_shape(assignments[0].value, "_metadata_schema_source.metadata_schema_source()")
        self.assertEqual(len(calls(init, "metadata_schema_source")), 2)
        self.assertEqual(calls(init, "authority_v9_schema_source"), [])
        prepare = calls(init, "_prepare_policy_candidate_authority_schema")
        apply = calls(init, "_execute_metadata_schema_statements")
        record = calls(init, "_record_policy_candidate_authority_migration")
        self.assertEqual((len(prepare), len(apply), len(record)), (1, 2, 1))
        apply.sort(key=lambda call: call.lineno)
        for call in (prepare[0], record[0]):
            self.assert_shape(keyword(call, "source_schema_program"), "metadata_schema_source")
        self.assertEqual(len(apply[0].args), 2)
        self.assert_shape(
            apply[0].args[1],
            "_metadata_schema_source.metadata_schema_source(include_initialization_indexes=False)",
        )
        sqlite_branch = next(
            node for node in ast.walk(init)
            if isinstance(node, ast.If) and apply[1] in calls(node, "_execute_metadata_schema_statements")
        )
        self.assert_shape(sqlite_branch.test, "not isinstance(conn, PostgresMetadataConnection)")
        self.assertIsInstance(apply[1].args[1], ast.Constant)
        self.assertIn("CREATE TRIGGER IF NOT EXISTS audit_events_event_json_size_insert", apply[1].args[1].value)
        self.assertIn("CREATE TRIGGER IF NOT EXISTS audit_events_event_json_size_update", apply[1].args[1].value)
        self.assertLess(assignments[0].lineno, prepare[0].lineno)
        self.assertLess(prepare[0].lineno, apply[0].lineno)
        self.assertLess(apply[0].lineno, record[0].lineno)
        # Fresh SQLite and the explicitly admitted PostgreSQL bootstrap both
        # reach this actual writer after applying the active source program.
        # An older literal CHECK would reject its current-revision INSERT.
        revision = assignment(tree, "_POLICY_CANDIDATE_AUTHORITY_SOURCE_REVISION")
        self.assert_shape(revision.value, "authority_contract.SOURCE_REVISION")
        recorder = function(tree, "_record_policy_candidate_authority_migration")
        inserts = [call for call in calls(recorder, "execute")
            if call.args and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str)
            and call.args[0].value.startswith("INSERT INTO policy_authority_schema_contracts (")]
        self.assertEqual(len(inserts), 1)
        self.assertTrue(inserts[0].args[0].value.startswith(
            "INSERT INTO policy_authority_schema_contracts (schema_version, contract_id, source_revision, "))
        self.assertIsInstance(inserts[0].args[1], ast.Tuple)
        self.assert_shape(inserts[0].args[1].elts[2], "_POLICY_CANDIDATE_AUTHORITY_SOURCE_REVISION")

    def test_migration_compares_complete_source_but_applies_only_the_extension(self):
        _, tree = read_source("scripts/authority/migrate_v8_to_v9.py")
        migrate = function(tree, "migrate")
        repair = calls(migrate, "repair_policy_candidate_authority_completed_v9_receipt")
        validation = calls(migrate, "_validate_policy_candidate_authority_structure")
        self.assertEqual((len(repair), len(validation)), (1, 3))
        for call in (*repair, *validation):
            self.assert_shape(keyword(call, "source_schema_program"),
                              "metadata_schema_source.metadata_schema_source()")
        self.assertEqual(len(calls(migrate, "metadata_schema_source")), 4)
        extension = calls(migrate, "authority_v9_schema_source")
        self.assertEqual(len(extension), 1)
        self.assert_shape(extension[0], "executor_v9.authority_v9_schema_source()")
        apply = [call for call in calls(migrate, "execute")
                 if len(call.args) == 1 and call.args[0] is extension[0]]
        self.assertEqual(len(apply), 1)
        self.assert_shape(apply[0].func, "cursor.execute")
        self.assertLess(repair[0].lineno, apply[0].lineno)
        ordered = sorted(validation, key=lambda node: node.lineno)
        for call, expected in zip(ordered, (True, False, True)):
            self.assert_shape(keyword(call, "require_recorded_contract"), repr(expected))
        self.assertLess(ordered[0].lineno, apply[0].lineno)
        self.assertLess(apply[0].lineno, ordered[1].lineno)
        self.assertLess(ordered[1].lineno, ordered[2].lineno)

    def test_expected_schema_validates_exact_variant_before_any_engine_work(self):
        _, tree = read_source("catchplate/authority_store/schema.py")
        expected = function(tree, "_policy_candidate_authority_expected_structure_manifest")
        defaults = dict(zip((arg.arg for arg in expected.args.kwonlyargs), expected.args.kw_defaults))
        self.assert_shape(defaults["legacy_completed_v9_receipt"], "False")
        self.assert_shape(defaults["local_audit_reader_profile"], "None")
        profile_guard = expected.body[0]
        self.assertIsInstance(profile_guard, ast.If)
        self.assert_shape(profile_guard.test, "local_audit_reader_profile is not None")
        self.assert_shape(profile_guard.body[0].value,
                          "authority_local_audit_reader.require_profile(local_audit_reader_profile)")
        profile_refusal = profile_guard.body[1]
        self.assert_shape(profile_refusal.test,
                          "legacy_completed_v9_receipt or not isinstance(conn, PostgresMetadataConnection)")
        self.assertIsInstance(profile_refusal.body[0], ast.Raise)
        self.assert_shape(profile_refusal.body[0].exc,
            "PolicyCandidateAuthorityError('local audit reader profile requires fresh PostgreSQL source derivation')")
        self.assertEqual(profile_guard.orelse, [])
        validation = expected.body[1]
        self.assertIsInstance(validation, ast.Try)
        checked = calls(expected, "require_metadata_schema_program")
        self.assertEqual(len(checked), 1)
        self.assertIn(checked[0], list(ast.walk(validation)))
        self.assert_shape(checked[0].args[0], "source_schema_program")
        self.assert_shape(keyword(checked[0], "legacy_completed_v9_receipt"),
                          "legacy_completed_v9_receipt")
        handlers = validation.handlers
        self.assertEqual(len(handlers), 1)
        self.assert_shape(handlers[0].type, "ValueError")
        self.assertIsInstance(handlers[0].body[0], ast.Raise)
        self.assert_shape(handlers[0].body[0].exc.func, "PolicyCandidateAuthorityError")
        engine_calls = calls(expected, "execute") + calls(expected, "_execute_metadata_schema_statements")
        self.assertTrue(engine_calls)
        self.assertTrue(all(checked[0].lineno < call.lineno for call in engine_calls))

    def test_completed_repair_delegates_to_pure_helper_and_only_legacy_comparison_opts_in(self):
        _, tree = read_source("catchplate/authority_store/schema.py")
        wrapper = function(tree, "_completed_v9_receipt_schema_programs")
        prepared = calls(wrapper, "completed_v9_schema_programs")
        self.assertEqual(len(prepared), 1)
        self.assert_shape(prepared[0].args[0], "source_schema_program")
        self.assertEqual(calls(wrapper, "authority_v9_schema_source"), [])
        self.assertEqual(calls(wrapper, "index"), [])
        self.assertIsInstance(wrapper.body[0], ast.Try)
        self.assertIn(prepared[0], list(ast.walk(wrapper.body[0])))
        self.assert_shape(wrapper.body[0].handlers[0].type, "ValueError")
        compared = sorted(calls(wrapper, "_policy_candidate_authority_expected_structure_manifest"),
                          key=lambda node: node.lineno)
        self.assertEqual(len(compared), 2)
        self.assert_shape(keyword(compared[0], "source_schema_program"), "source_schema_program")
        self.assertFalse(any(item.arg == "legacy_completed_v9_receipt" for item in compared[0].keywords))
        self.assert_shape(keyword(compared[1], "source_schema_program"), "legacy_schema_program")
        self.assert_shape(keyword(compared[1], "legacy_completed_v9_receipt"), "True")
        opted_in = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and any(item.arg == "legacy_completed_v9_receipt"
                            and isinstance(item.value, ast.Constant) and item.value.value is True
                            for item in node.keywords)]
        self.assertEqual(opted_in, [compared[1]])
        self.assertLess(prepared[0].lineno, compared[0].lineno)

    def test_source_contract_digest_binds_exact_complete_utf8_program(self):
        _, tree = read_source("catchplate/authority_store/schema.py")
        digest = function(tree, "_policy_candidate_authority_source_contract_digest")
        material = [node for node in digest.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "material" for target in node.targets)]
        self.assertEqual(len(material), 1)
        encoded = material[0].value
        self.assertIsInstance(encoded, ast.Call)
        self.assertIsInstance(encoded.func, ast.Attribute)
        self.assertEqual(encoded.func.attr, "encode")
        self.assertEqual(len(encoded.args), 1)
        self.assert_shape(encoded.args[0], repr("utf-8"))
        serialized = encoded.func.value
        self.assertIsInstance(serialized, ast.Call)
        self.assert_shape(serialized.func, "dumps")
        self.assertEqual(len(serialized.args), 1)
        mapping = serialized.args[0]
        self.assertIsInstance(mapping, ast.Dict)
        values = [value for key, value in zip(mapping.keys, mapping.values)
                  if isinstance(key, ast.Constant) and key.value == "metadataSchemaProgramDigest"]
        self.assertEqual(len(values), 1)
        self.assert_shape(values[0],
            "_policy_candidate_authority_framed_digest('catchplate.metadataSchemaProgram/v1', "
            "metadata_schema_source.metadata_schema_source().encode('utf-8'))")
        for key_name, expression in (
            ("objectOwnershipContract", repr("catchplate.policyAuthorityObjectOwnership/v1")),
            ("authorityOwnerRole", "owner_role"),
        ):
            bindings = [value for key, value in zip(mapping.keys, mapping.values)
                        if isinstance(key, ast.Constant) and key.value == key_name]
            self.assertEqual(len(bindings), 1)
            self.assert_shape(bindings[0], expression)
        default_roles = [node for node in digest.body if isinstance(node, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == "owner_role"
                                 for target in node.targets)]
        self.assertEqual(len(default_roles), 1)
        self.assert_shape(default_roles[0].value, "_METADATA_STORE_AUTHORITY_OWNER_ROLE")
        selected_scopes = [node for node in digest.body if isinstance(node, ast.If)
                           and calls(node, "require")]
        self.assertEqual(len(selected_scopes), 1)
        selected_scope = selected_scopes[0]
        self.assert_shape(selected_scope.test, "database_configuration is not None")
        admission = assignment(selected_scope, "database_configuration")
        self.assert_shape(admission.value, "require(database_configuration)")
        owner = assignment(selected_scope, "owner_role")
        self.assert_shape(owner.value, "OWNER_ROLE")
        imports = [node for node in selected_scope.body if isinstance(node, ast.ImportFrom)]
        self.assertEqual(len(imports), 1)
        self.assertEqual(imports[0].module, "catchplate.authority_database_configuration")
        self.assertEqual([(alias.name, alias.asname) for alias in imports[0].names],
                         [("OWNER_ROLE", None), ("require", None)])
        _, configuration = read_source("catchplate/authority_database_configuration.py")
        self.assert_shape(assignment(configuration, "OWNER_ROLE").value,
                          "'catchplate_policy_authority_owner'")
        self.assertLess(default_roles[0].lineno, selected_scope.lineno)
        self.assertLess(admission.lineno, owner.lineno)
        self.assertLess(selected_scope.end_lineno, material[0].lineno)
        returns = [node for node in digest.body if isinstance(node, ast.Return)]
        self.assertEqual(len(returns), 1)
        self.assert_shape(returns[0].value.args[-1], "material")

    def test_fresh_migration_seals_and_compares_before_signing_and_records_validated_manifest(self):
        _, tree = read_source("scripts/authority/migrate_v8_to_v9.py")
        migrate = function(tree, "migrate")
        seal = calls(migrate, "_seal_postgres_schema_acl")
        installed = calls(migrate, "_install_policy_candidate_authority_guards")
        validation = sorted(calls(migrate, "_validate_policy_candidate_authority_structure"),
                            key=lambda node: node.lineno)
        self.assertEqual((len(seal), len(installed), len(validation)), (1, 1, 3))
        fresh, final = validation[1:]
        self.assert_shape(seal[0].func, "db._seal_postgres_schema_acl")
        self.assert_shape(seal[0].args[0], "connection")
        expected_keywords = {
            "schema": "db._POLICY_CANDIDATE_AUTHORITY_SCHEMA_NAME",
            "runtime_role": "db._METADATA_STORE_RUNTIME_ROLE",
            "table_privileges": "('SELECT', 'INSERT', 'UPDATE', 'DELETE')",
            "authority_executor_role": "db._METADATA_STORE_AUTHORITY_EXECUTOR_ROLE",
            "authority_verifier_role": "db._METADATA_STORE_AUTHORITY_VERIFIER_ROLE",
            "authority_owner_role": "db._METADATA_STORE_AUTHORITY_OWNER_ROLE",
            "authority_capability_issuer_role": "db._METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE",
            "authority_planner_writer_role": "db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE",
            "runtime_read_only_tables": "db._POLICY_AUTHORITY_RUNTIME_READ_ONLY_TABLES",
            "authority_verifier_read_tables": "db._POLICY_AUTHORITY_VERIFIER_READ_TABLES",
            "authority_executor_function_signatures": "db._POLICY_AUTHORITY_EXECUTOR_FUNCTION_SIGNATURES",
            "authority_capability_issuer_function_signatures": "db._POLICY_AUTHORITY_CAPABILITY_ISSUER_FUNCTION_SIGNATURES",
            "authority_planner_writer_table_privileges": "db._POLICY_AUTHORITY_PLANNER_WRITER_TABLE_PRIVILEGES",
            "authority_planner_writer_function_signatures": "db.AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES",
        }
        self.assertEqual({item.arg for item in seal[0].keywords}, set(expected_keywords))
        for name, expression in expected_keywords.items():
            self.assert_shape(keyword(seal[0], name), expression)
        validated = [node for node in ast.walk(migrate) if isinstance(node, ast.Assign)
                     and node.value is fresh]
        self.assertEqual(len(validated), 1)
        self.assertEqual(len(validated[0].targets), 1)
        target = validated[0].targets[0]
        self.assertIsInstance(target, ast.Tuple)
        self.assertEqual([element.id for element in target.elts],
                         ["structural_manifest_json", "structural_manifest_digest"])
        self.assertEqual(calls(migrate, "_policy_candidate_authority_structure_manifest"), [])
        after = [node for node in ast.walk(migrate) if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "after_manifest"
                         for target in node.targets)]
        self.assertEqual(len(after), 1)
        self.assert_shape(after[0].value, "_schema_manifest(cursor, all_v9_tables)")
        signed = [call for call in calls(migrate, "_signature_material") if call.lineno > fresh.lineno]
        receipt = calls(migrate, "record_policy_candidate_authority_v8_to_v9_receipt")
        self.assertEqual((len(signed), len(receipt)), (1, 1))
        schema_inserts = [call for call in calls(migrate, "execute") if call.args
                          and isinstance(call.args[0], ast.Constant)
                          and type(call.args[0].value) is str
                          and call.args[0].value.startswith(
                              "INSERT INTO catchplate_metadata.policy_authority_schema_contracts (")]
        owner_inserts = [call for call in calls(migrate, "execute") if call.args
                         and isinstance(call.args[0], ast.Constant)
                         and type(call.args[0].value) is str
                         and call.args[0].value.startswith(
                             "INSERT INTO catchplate_metadata.policy_authority_owner_contracts (")]
        self.assertEqual((len(schema_inserts), len(owner_inserts)), (1, 1))
        self.assert_shape(schema_inserts[0].args[1],
            "('catchplate.policyCandidateAuthoritySchema/v9', _NEW_SOURCE_REVISION, "
            "db._policy_candidate_authority_source_contract_digest(), structural_manifest_json, "
            "structural_manifest_digest, receipt_digest, str(completed_at))")
        terminal = sorted(calls(migrate, "_terminal_response"), key=lambda node: node.lineno)[-1]
        sequence = (installed[0], seal[0], fresh, after[0], signed[0], receipt[0],
                    schema_inserts[0], owner_inserts[0], final, terminal)
        for before, following in zip(sequence, sequence[1:]):
            self.assertLess(before.lineno, following.lineno)

    def test_object_authority_pins_configured_no_login_owner_before_acl_collection(self):
        source, tree = read_source("catchplate/authority_store/schema.py")
        authority = function(tree, "_policy_candidate_authority_postgres_object_authority")
        text = ast.get_source_segment(source, authority)
        self.assertNotIn("current_user", text)
        self.assertNotIn("SET ROLE", text)
        selected = assignment(authority, "namespace_row")
        self.assertIs(authority.body[0], selected)
        fetch = selected.value
        self.assertIsInstance(fetch, ast.Call)
        self.assertIsInstance(fetch.func, ast.Attribute)
        self.assertEqual(fetch.func.attr, "fetchone")
        query = fetch.func.value
        self.assertIsInstance(query, ast.Call)
        self.assert_shape(query.func, "conn.execute")
        self.assertEqual(len(query.args), 2)
        self.assert_shape(query.args[1], "(namespace,)")
        self.assertIsInstance(query.args[0], ast.Constant)
        sql = query.args[0].value
        for clause in (
            "namespace.nspowner AS owner_oid", "owner_role.rolname AS owner_role",
            "FROM pg_catalog.pg_namespace AS namespace",
            "JOIN pg_catalog.pg_roles AS owner_role",
            "ON owner_role.oid = namespace.nspowner", "WHERE namespace.nspname = ?",
        ):
            self.assertIn(clause, sql)
        for field in ("rolcanlogin", "rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls"):
            self.assertIn("owner_role." + field, sql)
        guard = authority.body[1]
        self.assertIsInstance(guard, ast.If)
        self.assert_shape(guard.test,
            "namespace_row is None or type(_METADATA_STORE_AUTHORITY_OWNER_ROLE) is not str "
            "or not _METADATA_STORE_AUTHORITY_OWNER_ROLE "
            "or type(namespace_row.get('owner_role')) is not str "
            "or namespace_row['owner_role'] != _METADATA_STORE_AUTHORITY_OWNER_ROLE "
            "or type(namespace_row.get('owner_oid')) is not int "
            "or not 0 < namespace_row['owner_oid'] <= 2**32 - 1 "
            "or any(namespace_row.get(field) is not False for field in "
            "('rolcanlogin', 'rolsuper', 'rolcreaterole', 'rolcreatedb', 'rolreplication', 'rolbypassrls'))")
        self.assertIsInstance(guard.body[0], ast.Raise)
        self.assert_shape(guard.body[0].exc,
            "PolicyCandidateAuthorityError('metadata namespace authority owner is not source exact')")
        owner = assignment(authority, "owner_oid")
        self.assert_shape(owner.value, "namespace_row['owner_oid']")
        acl = assignment(authority, "namespace_acl")
        self.assertLess(guard.lineno, owner.lineno)
        self.assertLess(owner.lineno, acl.lineno)
        for call in calls(authority, "execute"):
            if call is not query:
                self.assertLess(owner.lineno, call.lineno)

    def test_relations_and_functions_share_the_validated_owner_oid_with_strict_boolean_denial(self):
        _, tree = read_source("catchplate/authority_store/schema.py")
        authority = function(tree, "_policy_candidate_authority_postgres_object_authority")
        owner = assignment(authority, "owner_oid")
        for kind, rows_name, owner_expression, acl_name in (
            ("relation", "relation_rows", "relation.relowner", "relation_acl"),
            ("function", "function_rows", "function_record.proowner", "function_acl"),
        ):
            with self.subTest(kind=kind):
                rows = assignment(authority, rows_name)
                fetch = rows.value
                self.assertIsInstance(fetch, ast.Call)
                self.assertIsInstance(fetch.func, ast.Attribute)
                self.assertEqual(fetch.func.attr, "fetchall")
                query = fetch.func.value
                self.assert_shape(query.func, "conn.execute")
                self.assert_shape(query.args[1], "(owner_oid, namespace)")
                self.assertIsInstance(query.args[0], ast.Constant)
                self.assertIn(owner_expression + " = ?::pg_catalog.oid", query.args[0].value)
                self.assertIn("AS owner_is_source", query.args[0].value)
                self.assertIn("WHERE namespace_record.nspname = ?", query.args[0].value)
                self.assertLess(owner.lineno, rows.lineno)
                loops = [node for node in authority.body if isinstance(node, ast.For)
                         and isinstance(node.iter, ast.Name) and node.iter.id == rows_name]
                self.assertEqual(len(loops), 1)
                guard = loops[0].body[0]
                self.assertIsInstance(guard, ast.If)
                self.assert_shape(guard.test, "row.get('owner_is_source') is not True")
                self.assertIsInstance(guard.body[0], ast.Raise)
                self.assert_shape(guard.body[0].exc,
                    "PolicyCandidateAuthorityError(" + repr(
                        "metadata " + kind + " is not owned by the source authority owner") + ")")
                acl = assignment(loops[0], acl_name)
                self.assertLess(guard.lineno, acl.lineno)
                self.assertTrue(calls(acl, "execute"))

    def test_retained_parent_and_sidecar_have_exact_columns_and_closed_protocol_lifecycle(self):
        parent = self.extension.split("policy_authority_planner_transactions (", 1)[1].split(");", 1)[0]
        sidecar = self.extension.split("policy_authority_revocation_retained_plans (", 1)[1].split(");", 1)[0]
        columns = lambda value: re.findall(r"^                ([a-z][a-z0-9_]*) (?:TEXT|BIGINT)\b", value, re.MULTILINE)
        self.assertEqual(len(columns(parent)), 36)
        self.assertEqual(columns(parent)[:3], ["planner_transaction_id", "plan_protocol", "retained_record_digest"])
        self.assertEqual(columns(sidecar), [
            "planner_transaction_id", "plan_protocol", "exact_envelope_base64url",
            "exact_envelope_bytes_digest", "exact_envelope_byte_count", "evaluation_context_base64url",
            "evaluation_context_bytes_digest", "evaluation_context_byte_count", "planner_key_digest",
            "verifier_key_digest", "retained_record_digest", "source_revision",
        ])
        for fragment in ("plan_protocol TEXT NOT NULL DEFAULT 'v3'",
                "plan_protocol IN ('v3', 'revocation-v4')",
                "plan_protocol = 'v3' AND retained_record_digest IS NULL",
                "operation = 'webauthn.credential.revoke'",
                "retained_record_digest IS NULL\n                                AND status IN ('reserved', 'failed')",
                "retained_record_digest IS NOT NULL\n                                AND status IN ('planned', 'consumed', 'failed')",
                "exact_plan_byte_count IS NOT NULL", "planned_at_epoch_ns IS NOT NULL"):
            self.assertIn(fragment, parent)
        identity = "(planner_transaction_id, plan_protocol, retained_record_digest)"
        self.assertIn("UNIQUE " + identity, parent)
        self.assertIn("UNIQUE " + identity, sidecar)
        self.assertIn("CONSTRAINT catchplate_revocation_retained_parent_fk", sidecar)
        self.assertIn("FOREIGN KEY " + identity, sidecar)
        self.assertIn("REFERENCES policy_authority_planner_transactions", sidecar)
        self.assertIn("DEFERRABLE INITIALLY DEFERRED", sidecar)
        self.assertNotIn("CASCADE", sidecar)
        for fragment in ("exact_envelope_byte_count BETWEEN 2 AND 67108864",
                "evaluation_context_byte_count BETWEEN 2 AND 524288",
                "length(exact_envelope_base64url) = (4 * exact_envelope_byte_count + 2) / 3",
                "length(evaluation_context_base64url) = (4 * evaluation_context_byte_count + 2) / 3",
                "exact_envelope_base64url ~ '^[A-Za-z0-9_-]+$'",
                "evaluation_context_base64url ~ '^[A-Za-z0-9_-]+$'"):
            self.assertIn(fragment, sidecar)
        for prefix in ("exact_envelope", "evaluation_context"):
            self.assertIn(prefix + "_byte_count % 3 = 0", sidecar)
            self.assertIn(prefix + "_byte_count % 3 = 1", sidecar)
            self.assertIn(prefix + "_byte_count % 3 = 2", sidecar)
            self.assertIn("substr(" + prefix + "_base64url, length(" + prefix + "_base64url), 1)", sidecar)
        self.assertEqual(sidecar.count(authority_contract.SOURCE_REVISION), 1)

    def test_actual_post_table_guard_renders_deferred_reverse_fk_and_immutable_update_checks(self):
        namespace = '"retention_fixture"'
        sql = planner_retention_guard_sql(namespace)
        parent = namespace + ".policy_authority_planner_transactions"
        sidecar = namespace + ".policy_authority_revocation_retained_plans"
        for fragment in ("ALTER TABLE " + parent,
                "ADD CONSTRAINT catchplate_planner_retained_record_fk",
                "REFERENCES " + sidecar + " (planner_transaction_id, plan_protocol, retained_record_digest)",
                "DEFERRABLE INITIALLY DEFERRED", "RETURNS trigger LANGUAGE plpgsql",
                "SET search_path = pg_catalog, " + namespace + ", pg_temp",
                "BEFORE UPDATE ON " + parent, "catchplate_guard_planner_retention()",
                "OLD.exact_plan_base64url IS NOT NULL", "OLD.status IN ('consumed', 'failed')",
                "OLD.status = 'reserved' AND NEW.status NOT IN ('reserved', 'planned', 'failed')",
                "OLD.status = 'planned' AND NEW.status = 'reserved'"):
            self.assertIn(fragment, sql)
        self.assertNotIn("CASCADE", sql)
        self.assertNotIn("SECURITY DEFINER", sql)
        self.assertIn("VOLATILE SECURITY INVOKER", sql)
        self.assertNotIn("UPDATE " + parent + " SET", sql)
        for fields in (authority_contract.PLANNER_RESERVATION_IMMUTABLE_COLUMNS,
                       authority_contract.PLANNER_PAYLOAD_IMMUTABLE_COLUMNS,
                       authority_contract.PLANNER_TERMINAL_IMMUTABLE_COLUMNS):
            expected = "ROW(" + ", ".join("NEW." + field for field in fields) + ") IS DISTINCT FROM ROW(" + ", ".join("OLD." + field for field in fields) + ")"
            self.assertIn(expected, sql)
        for bad in (None, "metadata", '""', '"metadata"; DROP TABLE x; --', '"a"b"', '"a\x00b"'):
            with self.subTest(namespace=bad), self.assertRaises(ValueError):
                planner_retention_guard_sql(bad)
        quoted = planner_retention_guard_sql('"a\'b"')
        self.assertIn("'\"a''b\".policy_authority_planner_transactions'::pg_catalog.regclass", quoted)

    def test_sqlite_retained_protocol_is_denied_while_v3_identity_stays_immutable(self):
        sql = planner_retention_sqlite_guards_sql()
        self.assertEqual(sql.count("CREATE TRIGGER IF NOT EXISTS"), 10)
        for name in ("catchplate_planner_retention_insert_guard", "catchplate_planner_retention_guard",
                     "catchplate_retained_sqlite_insert_guard", "catchplate_writer_request_sqlite_insert_guard",
                     "catchplate_writer_ack_sqlite_insert_guard",
                     "catchplate_webauthn_evidence_retained_sqlite_insert_guard",
                     "catchplate_webauthn_transition_retained_sqlite_insert_guard",
                     "catchplate_current_root_marker_sqlite_insert_guard",
                     "catchplate_successor_custody_sqlite_insert_guard",
                     "catchplate_successor_frames_sqlite_insert_guard"):
            self.assertIn(name, sql)
        self.assertIn("NEW.plan_protocol <> 'v3' OR NEW.retained_record_digest IS NOT NULL", sql)
        self.assertIn("BEFORE INSERT ON policy_authority_revocation_retained_plans", sql)
        self.assertIn("BEFORE INSERT ON policy_authority_revocation_writer_requests", sql)
        self.assertIn("SQLite writer request custody is disabled", sql)
        self.assertIn("BEFORE INSERT ON policy_authority_revocation_writer_acknowledgments", sql)
        self.assertIn("SQLite writer acknowledgment custody is disabled", sql)
        self.assertIn("BEFORE INSERT ON policy_authority_webauthn_evidence_retained_plans", sql)
        self.assertIn("SQLite retained WebAuthn evidence admission is disabled", sql)
        self.assertIn("BEFORE INSERT ON policy_authority_webauthn_transition_retained_plans", sql)
        self.assertIn("SQLite retained WebAuthn transition admission is disabled", sql)
        self.assertIn("BEFORE INSERT ON policy_authority_current_root_commit_markers", sql)
        self.assertIn("SQLite current-root commit marker admission is disabled", sql)
        self.assertIn("BEFORE INSERT ON policy_authority_successor_execution_custody", sql)
        self.assertIn("SQLite successor execution custody admission is disabled", sql)
        self.assertIn("BEFORE INSERT ON policy_authority_successor_execution_frames", sql)
        self.assertIn("SQLite successor execution frame admission is disabled", sql)
        for field in (*authority_contract.PLANNER_RESERVATION_IMMUTABLE_COLUMNS,
                      *authority_contract.PLANNER_PAYLOAD_IMMUTABLE_COLUMNS,
                      *authority_contract.PLANNER_TERMINAL_IMMUTABLE_COLUMNS):
            self.assertIn("NEW." + field + " IS NOT OLD." + field, sql)
        self.assertNotIn("ALTER TABLE", sql)
        self.assertNotIn("COMMIT", sql)

    def test_retention_guards_are_installed_by_actual_shared_bootstrap_and_bound_into_schema_contract(self):
        source, tree = read_source("catchplate/db.py", 16 * 1024 * 1024)
        installer = function(tree, "_install_policy_candidate_authority_guards")
        pg = calls(installer, "planner_retention_guard_sql")
        sqlite = calls(installer, "planner_retention_sqlite_guards_sql")
        self.assertEqual((len(pg), len(sqlite)), (1, 1))
        self.assert_shape(pg[0], "_authority_v9_schema_source.planner_retention_guard_sql(guard_namespace)")
        self.assert_shape(sqlite[0], "_authority_v9_schema_source.planner_retention_sqlite_guards_sql()")
        namespace = assignment(installer, "guard_namespace")
        self.assertLess(namespace.lineno, pg[0].lineno)
        blocks = [node for node in ast.walk(installer) if isinstance(node, ast.If)
            and pg[0] in tuple(ast.walk(node))
            and ast.dump(node.test) == ast.dump(ast.parse("isinstance(conn, PostgresMetadataConnection)", mode="eval").body)]
        self.assertEqual(len(blocks), 1)
        self.assertNotIn(sqlite[0], tuple(ast.walk(blocks[0])))
        _, schema = read_source("catchplate/authority_store/schema.py")
        digest = function(schema, "_policy_candidate_authority_source_contract_digest")
        self.assertTrue(calls(digest, "planner_retention_guard_sql"))
        self.assertTrue(calls(digest, "planner_retention_sqlite_guards_sql"))
        required = function(schema, "_policy_candidate_authority_required_guard_names")
        literals = {node.value for node in ast.walk(required) if isinstance(node, ast.Constant) and type(node.value) is str}
        self.assertTrue({"catchplate_guard_planner_retention", "catchplate_planner_retention_guard",
                        "catchplate_planner_retention_insert_guard", "catchplate_retained_sqlite_insert_guard",
                        "catchplate_webauthn_evidence_retained_sqlite_insert_guard"}.issubset(literals))

    def test_capability_custody_has_exact_columns_protocols_transport_and_minimal_foreign_keys(self):
        parent = self.base.split("policy_authority_writer_capabilities (", 1)[1].split(");", 1)[0]
        sidecar = self.extension.split("policy_authority_revocation_retained_capabilities (", 1)[1].split(");", 1)[0]
        parent_columns = re.findall(r"^                    ([a-z][a-z0-9_]*) (?:TEXT|BIGINT)\b", parent, re.MULTILINE)
        self.assertEqual(parent_columns, [
            "capability_id", "capability_protocol", "capability_record_digest", "capability_digest",
            "envelope_id", "operation", "operation_id", "handler_name", "request_digest",
            "operation_manifest_digest", "query_manifest_digest", "authority_root_set_digest",
            "authority_snapshot_digest", "approver_policy_digest", "webauthn_receipt_json",
            "webauthn_receipt_digest", "webauthn_trust_high_water_digest", "witness_reservation_digest",
            "witness_sequence", "witness_head_digest", "deadline_monotonic_ns", "fence",
            "issued_monotonic_ns", "issued_at_epoch_ns", "expires_at_epoch_ns",
            "issuer_session_identity_digest", "issuer_measurement_digest", "issuer_attestation_receipt_digest",
            "issuer_credential_issuance_digest", "status", "writer_token_digest", "reserved_at_epoch_ns",
            "reserved_transaction_id", "result_digest", "commit_receipt_digest", "committed_at_epoch_ns",
            "failure_digest", "failed_at_epoch_ns", "expected_result_digest", "planner_transaction_id",
            "authorization_projection_digest", "selected_business_rows_digest", "mutation_plan_digest",
            "deadline_epoch_ns",
        ])
        self.assertEqual(re.findall(r"^                ([a-z][a-z0-9_]*) (?:TEXT|BIGINT)\b", sidecar, re.MULTILINE), [
            "capability_id", "capability_protocol", "capability_record_digest", "planner_transaction_id",
            "plan_protocol", "retained_record_digest", "execution_envelope_id", "capability_digest",
            "root_transition_digest", "authority_snapshot_digest", "exact_request_bytes_digest",
            "exact_capability_base64url", "exact_capability_bytes_digest", "exact_capability_byte_count",
            "signer_key_digest", "witness_key_digest", "exact_witness_request_base64url",
            "exact_witness_request_bytes_digest", "exact_witness_request_byte_count", "source_revision",
        ])
        for fragment in ("capability_protocol TEXT NOT NULL DEFAULT 'v3'",
                "capability_protocol IN ('v3', 'revocation-v4')",
                "capability_protocol = 'v3' AND capability_record_digest IS NULL",
                "capability_protocol = 'revocation-v4'", "operation = 'webauthn.credential.revoke'",
                "capability_record_digest IS NOT NULL", "capability_record_digest ~ '^sha256:[0-9a-f]{64}$'"):
            self.assertIn(fragment, parent)
        compact_parent, compact_sidecar = " ".join(parent.split()), " ".join(sidecar.split())
        five = "(capability_id, capability_protocol, capability_record_digest, planner_transaction_id, "
        self.assertIn("UNIQUE " + five + "envelope_id)", compact_parent)
        self.assertIn("UNIQUE " + five + "execution_envelope_id)", compact_sidecar)
        self.assertIn("FOREIGN KEY " + five + "execution_envelope_id) REFERENCES policy_authority_writer_capabilities "
                      + five + "envelope_id) DEFERRABLE INITIALLY DEFERRED", compact_sidecar)
        self.assertIn("FOREIGN KEY (planner_transaction_id, plan_protocol, retained_record_digest) "
                      "REFERENCES policy_authority_revocation_retained_plans "
                      "(planner_transaction_id, plan_protocol, retained_record_digest) DEFERRABLE INITIALLY DEFERRED", compact_sidecar)
        self.assertIn("FOREIGN KEY (execution_envelope_id) REFERENCES policy_authority_execution_envelopes "
                      "(envelope_id) DEFERRABLE INITIALLY DEFERRED", compact_sidecar)
        self.assertEqual(sidecar.count("FOREIGN KEY"), 3)
        self.assertNotIn("REFERENCES policy_authority_planner_transactions", sidecar)
        self.assertNotIn("CASCADE", sidecar)
        self.assertIn("capability_protocol = 'revocation-v4' AND plan_protocol = 'revocation-v4'", sidecar)
        for prefix, maximum in (("exact_capability", 4194304), ("exact_witness_request", 65536)):
            self.assertIn(prefix + "_byte_count BETWEEN 2 AND " + str(maximum), sidecar)
            self.assertIn("length(" + prefix + "_base64url) = (4 * " + prefix + "_byte_count + 2) / 3", sidecar)
            self.assertIn(prefix + "_base64url ~ '^[A-Za-z0-9_-]+$'", sidecar)
            for remainder in (0, 1, 2):
                self.assertIn(prefix + "_byte_count % 3 = " + str(remainder), sidecar)
            self.assertIn("substr(" + prefix + "_base64url, length(" + prefix + "_base64url), 1) IN ('A', 'Q', 'g', 'w')", sidecar)
        self.assertEqual(sidecar.count("('A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c', 'g', 'k', 'o', 's', 'w', '0', '4', '8')"), 2)
        self.assertEqual(sidecar.count(authority_contract.SOURCE_REVISION), 1)
        for predecessor in ("policy_authority_planner_transactions (", "policy_authority_execution_envelopes (",
                            "policy_authority_revocation_retained_plans ("):
            self.assertLess(self.extension.index(predecessor), self.extension.index("policy_authority_revocation_retained_capabilities ("))

    def test_capability_guard_binds_deferred_identity_and_successor_only_lifecycle(self):
        namespace = '"capability_fixture"'
        sql = capability_retention_guard_sql(namespace)
        compact = " ".join(sql.split())
        parent = namespace + ".policy_authority_writer_capabilities"
        sidecar = namespace + ".policy_authority_revocation_retained_capabilities"
        for fragment in ("ALTER TABLE " + parent, "ADD CONSTRAINT catchplate_writer_capability_retained_fk",
                "FOREIGN KEY (capability_id, capability_protocol, capability_record_digest, planner_transaction_id, envelope_id)",
                "REFERENCES " + sidecar + " (capability_id, capability_protocol, capability_record_digest, planner_transaction_id, execution_envelope_id)",
                "DEFERRABLE INITIALLY DEFERRED", "RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER",
                "SET search_path = pg_catalog, " + namespace + ", pg_temp", "BEFORE UPDATE ON " + parent,
                "IF NEW.capability_protocol IS DISTINCT FROM OLD.capability_protocol OR (OLD.capability_protocol = 'revocation-v4' AND (",
                "OLD.writer_token_digest IS NOT NULL OR OLD.reserved_at_epoch_ns IS NOT NULL OR OLD.reserved_transaction_id IS NOT NULL",
                "OLD.status IN ('reconciled', 'expired', 'failed')",
                "OLD.status = 'committed' AND (NEW.status NOT IN ('committed', 'reconciled')",
                "OLD.status = 'issued' AND NEW.status NOT IN ('issued', 'reserved', 'committed', 'expired', 'failed')",
                "OLD.status = 'reserved' AND NEW.status NOT IN ('reserved', 'committed', 'expired')"):
            self.assertIn(fragment, compact)
        for fields in (authority_contract.WRITER_CAPABILITY_IMMUTABLE_COLUMNS,
                       authority_contract.WRITER_CAPABILITY_RESERVATION_COLUMNS,
                       authority_contract.WRITER_CAPABILITY_TERMINAL_COLUMNS,
                       authority_contract.WRITER_CAPABILITY_TERMINAL_COLUMNS[1:]):
            self.assertIn("ROW(" + ", ".join("NEW." + field for field in fields) + ") IS DISTINCT FROM ROW(" +
                          ", ".join("OLD." + field for field in fields) + ")", sql)
        for forbidden in ("CASCADE", "SECURITY DEFINER", "GRANT ", "UPDATE " + parent + " SET"):
            self.assertNotIn(forbidden, sql)
        for bad in (None, "metadata", '""', '"metadata"; DROP TABLE x; --', '"a"b"', '"a\x00b"'):
            with self.subTest(namespace=bad), self.assertRaises(ValueError):
                capability_retention_guard_sql(bad)
        self.assertIn("'\"a''b\".policy_authority_writer_capabilities'::pg_catalog.regclass",
                      capability_retention_guard_sql('"a\'b"'))

    def test_sqlite_capability_guard_denies_successor_without_freezing_v3_recovery(self):
        sql = capability_retention_sqlite_guards_sql()
        self.assertEqual(sql.count("CREATE TRIGGER IF NOT EXISTS"), 3)
        for name in ("catchplate_capability_retention_insert_guard", "catchplate_capability_retention_guard",
                     "catchplate_capability_sidecar_sqlite_insert_guard"):
            self.assertIn(name, sql)
        self.assertEqual(sql.count("NEW.capability_protocol <> 'v3' OR NEW.capability_record_digest IS NOT NULL"), 2)
        self.assertIn("NEW.capability_protocol IS NOT OLD.capability_protocol", sql)
        self.assertIn("BEFORE INSERT ON policy_authority_revocation_retained_capabilities", sql)
        for forbidden in ("OLD.status", "NEW.writer_token_digest", "ALTER TABLE", "COMMIT"):
            self.assertNotIn(forbidden, sql)

    def test_capability_guards_reach_actual_installers_and_source_object_admission(self):
        _, tree = read_source("catchplate/db.py", 16 * 1024 * 1024)
        installer = function(tree, "_install_policy_candidate_authority_guards")
        pg = calls(installer, "capability_retention_guard_sql")
        sqlite = calls(installer, "capability_retention_sqlite_guards_sql")
        self.assertEqual((len(pg), len(sqlite)), (1, 1))
        self.assert_shape(pg[0], "_authority_v9_schema_source.capability_retention_guard_sql(guard_namespace)")
        self.assert_shape(sqlite[0], "_authority_v9_schema_source.capability_retention_sqlite_guards_sql()")
        self.assertLess(assignment(installer, "guard_namespace").lineno, pg[0].lineno)
        blocks = [node for node in ast.walk(installer) if isinstance(node, ast.If)
            and pg[0] in tuple(ast.walk(node))
            and ast.dump(node.test) == ast.dump(ast.parse("isinstance(conn, PostgresMetadataConnection)", mode="eval").body)]
        self.assertEqual(len(blocks), 1)
        self.assertNotIn(sqlite[0], tuple(ast.walk(blocks[0])))
        _, tree = read_source("catchplate/authority_store/schema.py")
        digest = function(tree, "_policy_candidate_authority_source_contract_digest")
        self.assertEqual(len(calls(digest, "capability_retention_guard_sql")), 1)
        self.assertEqual(len(calls(digest, "capability_retention_sqlite_guards_sql")), 1)
        required = function(tree, "_policy_candidate_authority_required_guard_names")
        literals = {node.value for node in ast.walk(required) if isinstance(node, ast.Constant) and type(node.value) is str}
        self.assertTrue({"catchplate_guard_capability_retention", "catchplate_capability_retention_guard",
                        "catchplate_capability_retention_insert_guard", "catchplate_capability_sidecar_sqlite_insert_guard"}.issubset(literals))

    def test_native_successor_frame_schema_is_bounded_immutable_framework_custody(self):
        contract = authority_contract.SUCCESSOR_EXECUTION_FRAME_CONTRACT
        table = authority_contract.SUCCESSOR_EXECUTION_FRAME_TABLE
        self.assertEqual(contract["maximumFrameBytes"], 131072)
        self.assertEqual(contract["maximumStreamBytes"], 100663296)
        self.assertEqual(contract["maximumFrames"], 1068)
        self.assertEqual(contract["primaryKey"], ("pending_decision_digest", "frame_ordinal"))
        self.assertEqual(contract["parentKey"], ("pending_decision_digest", "packet_digest"))
        self.assertIn(table, authority_contract.POSTGRES_IMMUTABLE_CUSTODY_TABLES)
        self.assertIn(table, authority_contract.V9_ADDITIONAL_PROTECTED_TABLES)
        self.assertIn(table, authority_contract._FRAMEWORK_CUSTODY_TABLES)
        self.assertIn(table, planner_read_sql.EXCLUDED_TABLES)
        self.assertFalse(contract["publicExecutionEnabled"])
        self.assertFalse(contract["sqliteAdmission"])
        ddl = self.extension.split("CREATE TABLE IF NOT EXISTS " + table + " (", 1)[1].split("\n        );", 1)[0]
        for fragment in ("frame_bytes BYTEA NOT NULL", "PRIMARY KEY (pending_decision_digest, frame_ordinal)",
                "FOREIGN KEY (pending_decision_digest, packet_digest)",
                "REFERENCES policy_authority_successor_execution_custody",
                "DEFERRABLE INITIALLY DEFERRED", "frame_ordinal BETWEEN 0 AND 1067",
                "byte_count BETWEEN 1 AND 131072", "length(frame_bytes) = byte_count"):
            self.assertIn(fragment, ddl)
        for forbidden in ("CASCADE", "session_token", "__SUCCESSOR_"):
            self.assertNotIn(forbidden, ddl)

    def test_native_successor_frame_renderer_closes_stream_before_issue_and_execution(self):
        digest = "sha256:" + "1" * 64
        sql = successor_execution_sql.successor_execution_functions_sql('"metadata"',
            issuer_role=authority_contract.SUCCESSOR_ISSUER_ROLE,
            executor_role=authority_contract.SUCCESSOR_EXECUTOR_ROLE,
            recovery_role=authority_contract.SUCCESSOR_RECOVERY_ROLE, owner_role="metadata_owner",
            issuer_pins=(digest, digest, digest, "CN=issuer", "11", "CN=CA"),
            executor_pins=(digest, digest, digest, "CN=executor", "12", "CN=CA"),
            recovery_pins=(digest, digest, digest, "CN=recovery", "13", "CN=CA"))
        self.assertEqual(sql.count("CREATE OR REPLACE FUNCTION"), 4)
        function_name = authority_contract.SUCCESSOR_FRAME_FUNCTION
        self.assertEqual(authority_contract.SUCCESSOR_EXECUTION_FUNCTION_SIGNATURES[function_name],
            ("text", "text", "bigint", "bytea"))
        append = sql.split('"metadata".' + function_name + "(", 1)[1].split("CREATE OR REPLACE FUNCTION", 1)[0]
        for fragment in ("supplied_pending_decision_digest text, supplied_packet_digest text, supplied_frame_ordinal bigint, supplied_frame bytea",
                "RETURNS TABLE(frame_ordinal bigint, byte_count bigint, bytes_digest text)",
                "sxf_stored_count IS DISTINCT FROM supplied_frame_ordinal",
                "sxf_stored_bytes + sxf_byte_count > 100663296",
                "successor native stream is already closed",
                "pg_catalog.sha256(supplied_frame)", "session_user IS DISTINCT FROM 'catchplate_policy_authority_successor_issuer'"):
            self.assertIn(fragment, append)
        self.assertNotIn("ON CONFLICT", append)
        for operation in (authority_contract.SUCCESSOR_ISSUE_FUNCTION, authority_contract.SUCCESSOR_EXECUTE_FUNCTION):
            body = sql.split('"metadata".' + operation + "(", 1)[1].split("CREATE OR REPLACE FUNCTION", 1)[0]
            for fragment in ("pg_catalog.jsonb_array_length(sxf_manifest->'rowChunkCounts') <> 13",
                    "sxf_leaf_size > sxf_maxima[sxf_leaf_index]",
                    "pg_catalog.sha256(sxf_row.frame_bytes)", "pg_catalog.sha256(sxf_leaf)",
                    "sxf_ordinal IS DISTINCT FROM sxf_stored_count", "sxf_leaf := NULL;"):
                self.assertIn(fragment, body)
            self.assertNotIn("string_agg(stored.frame_bytes", body)
            self.assertNotIn("array_agg(stored.frame_bytes", body)
        self.assertLess(sql.index("successor native stream has missing or extra frames"),
            sql.index('INSERT INTO "metadata".policy_authority_successor_execution_custody'))
        self.assertIn("native successor historical completion is not available", sql)

    def test_native_successor_privilege_extension_preserves_existing_scalar_consumers(self):
        sql, parameters = successor_execution_privileges.successor_execution_privilege_check(
            role=authority_contract.SUCCESSOR_ISSUER_ROLE, namespace="metadata")
        self.assertEqual(parameters, (authority_contract.SUCCESSOR_ISSUER_ROLE, "metadata", [],
            authority_contract.SUCCESSOR_ISSUE_FUNCTION))
        self.assertEqual(sql.count("%s"), 4)
        self.assertIn("%s::pg_catalog.text AS expected_function", sql)
        self.assertIn("'text, text, bigint, bytea'", sql)
        self.assertIn("THEN 2 ELSE 1 END", sql)
        for module in (policy_file_read_sql, policy_file_genesis_sql):
            actual_sql, actual_parameters = module.privilege_check(namespace="metadata")
            self.assertIs(actual_sql, sql)
            self.assertEqual(actual_parameters, (module.ROLE, "metadata", [], module.FUNCTION))
        self.assertNotIn("expected_functions", sql)

    def test_native_successor_frame_bindings_reach_existing_install_and_acl_owners(self):
        source, tree = read_source("catchplate/db.py", 16 * 1024 * 1024)
        seal = function(tree, "_seal_postgres_schema_acl")
        roster = assignment(seal, "successor_functions")
        self.assertIn("authority_contract.SUCCESSOR_FRAME_FUNCTION", ast.get_source_segment(source, roster))
        for name in ("_seal_postgres_schema_acl", "_validate_policy_authority_owner_apply_function"):
            text = ast.get_source_segment(source, function(tree, name))
            self.assertIn("authority_contract.SUCCESSOR_EXECUTION_FUNCTION_SIGNATURES[", text)
            self.assertIn("authority_contract.SUCCESSOR_FRAME_FUNCTION", text)
        for name in ("_POLICY_AUTHORITY_RUNTIME_INACCESSIBLE_TABLES", "_POLICY_AUTHORITY_FRAMEWORK_CUSTODY_TABLES"):
            self.assertIn("authority_contract.SUCCESSOR_EXECUTION_FRAME_TABLE",
                ast.get_source_segment(source, assignment(tree, name)))


if __name__ == "__main__":
    unittest.main()
