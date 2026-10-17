#!/usr/bin/env python3
"""Real PostgreSQL native-pending storage components, not full admission.

The external owner supplies a fresh private Unix-socket cluster. The complete
production schema, exact source immutability triggers, pending kernel, SQL
payload-key guard, application order and CAS renderer execute unchanged. Crypto and selected trust
use explicitly synthetic fixtures/clocks. Capability admission, authenticated
roots, role ACLs, witnesses, native hardware, review opening and deployed restart
are NOT established. No engine is started by this test.
"""
from __future__ import annotations

import argparse
import ast
import copy
from dataclasses import replace
import os
from pathlib import Path
import re
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["CATCHPLATE_PROCESS_MODE"] = "metadata-bootstrap"
os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from scripts import test_authority_native_jit_pending as fixture_source
from scripts import test_authority_executor_optional_evidence as source_reader
from scripts.test_webauthn_trust_projection_postgres import local_connection_parameters
from catchplate import authority_audit_capacity as audit_capacity
from catchplate import authority_contract as contract
from catchplate import authority_native_jit_retention_contract as storage
from catchplate import authority_transition_core as core
from catchplate.authority_primary_contract import PRIMARY_KEY_COLUMNS
from catchplate.authority_store.metadata_schema_source import metadata_schema_source
from catchplate.authority_store.mutation_sql import apply_mutation_sql, closed_record_sql
from catchplate.authority_store.root_transition_sql import _exact_payload_keys
from catchplate.authority_store.schema import _policy_candidate_authority_object_name

PARAMETERS = None
AGGREGATES = "policy_authority_bounded_aggregate_states"
CHANGED_TABLES = ("routes", "approval_requests", "metadata_audit_outbox", AGGREGATES, storage.TABLE)
UNTOUCHED_TABLES = ("approval_grants", "release_authorization_attempts",
    "release_authorization_quota_reservations", "release_authorization_events",
    "rate_limit_counters", "durable_budget_events", "traversal_budget_page_reservations")
canonical = fixture_source.canonical
# Independent literal roster, not copied from the guard under test. Values of
# unrelated fields below are placeholders: only this SQL shape gate is tested.
PAYLOAD_FIELDS = ("schema", "measuredPlan", "typedRequest", "selectedBusinessRows",
    "mutationPlan", "queryMultiproofs", "queryMultiproofsDigest", "plannerTrace",
    "plannerTraceDigest", "authorizationProjection", "webauthnEvidence",
    "expectedResult", "expectedResultDigest", "plannerIdentity", "rootTransition")


def actual_application_select() -> str:
    """Retain the actual executor ordering, including its scoped route priority."""
    tree = source_reader._read("catchplate/authority_store/executor_v9.py")
    owner = source_reader._one([node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "install_authority_v9_executor"])
    template = source_reader._one([source_reader._template(node) for node in ast.walk(owner)
        if isinstance(node, ast.JoinedStr) and any(isinstance(part, ast.Constant)
            and isinstance(part.value, str) and "IF fence_head.fence <> capability.fence" in part.value
            for part in node.values)])
    selected = source_reader._one(re.findall(
        r"\bFOR mutation IN\s+(SELECT planned\.value\b.*?)(?=\n\s*LOOP\b)", template, re.S))
    if "{" in selected or "}" in selected or storage.TABLE not in selected:
        raise ValueError("actual native pending application order is not closed")
    return selected


def install_actual_pair_guards(connection) -> None:
    """Execute selected original installer statements, not replacement guards.

    This does not invoke or fake the installer's offline owner/pin admission.
    Only the two source functions and exact registered-table trigger loops are
    selected; all table declarations have already been installed unchanged.
    """
    if storage.TABLE not in contract.POSTGRES_IMMUTABLE_CUSTODY_TABLES:
        raise ValueError("native pair lost its source immutable registration")
    tree = source_reader._read("catchplate/db.py")
    owner = source_reader._one([node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_install_policy_candidate_authority_guards"])
    postgres = source_reader._one([node for node in owner.body if isinstance(node, ast.If)
        and ast.unparse(node.test) == "isinstance(conn, PostgresMetadataConnection)"])
    for function in ("catchplate_reject_policy_authority_mutation", "catchplate_validate_policy_authority_insert"):
        statement = source_reader._one([node.args[0].value for node in ast.walk(postgres)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute" and node.args and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and "CREATE OR REPLACE FUNCTION " + function + "()" in node.args[0].value])
        connection.execute(statement)
    namespace = {"conn": connection, "authority_tables": (storage.TABLE,),
        "immutable_tables": (storage.TABLE,),
        "_policy_candidate_authority_object_name": _policy_candidate_authority_object_name}
    for inventory in ("authority_tables", "immutable_tables"):
        loop = source_reader._one([node for node in ast.walk(postgres)
            if isinstance(node, ast.For) and isinstance(node.iter, ast.Name) and node.iter.id == inventory])
        exec(compile(ast.Module(body=[loop], type_ignores=[]), str(ROOT / "catchplate/db.py"), "exec"), namespace)


class NativeJitRetentionPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if PARAMETERS is None:
            raise RuntimeError("an externally owned disposable PostgreSQL cluster is required")
        cls.db = psycopg.connect(**PARAMETERS, autocommit=True, row_factory=dict_row)
        cls.addClassCleanup(cls.db.close)
        cls.db.isolation_level = psycopg.IsolationLevel.SERIALIZABLE
        facts = cls.db.execute("SELECT current_setting('server_version_num')::int AS version, "
            "inet_server_addr() AS address").fetchone()
        if facts["version"] // 10000 not in (16, 17) or facts["address"] is not None:
            raise RuntimeError("storage component requires local PostgreSQL 16/17")
        cls.schema = "native_jit_storage_" + uuid.uuid4().hex
        cls.ns = '"' + cls.schema + '"'
        cls.db.execute(f"CREATE SCHEMA {cls.ns}")
        cls.addClassCleanup(cls.db.execute, f"DROP SCHEMA {cls.ns} CASCADE")
        cls.db.execute(f"SET search_path = {cls.ns}, pg_catalog")
        # No table extraction, replacement, FK deferral override or DDL fallback.
        cls.db.execute(metadata_schema_source())
        install_actual_pair_guards(cls.db)
        cls.db.execute(f"""CREATE FUNCTION {cls.ns}.payload_shape(original text)
            RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog AS $shape$
            DECLARE payload_json pg_catalog.json;
            BEGIN
                payload_json := original::pg_catalog.json;
                RETURN {_exact_payload_keys('payload_json')};
            END; $shape$""")
        cls.order = actual_application_select()
        cls.db.execute(f"""CREATE FUNCTION {cls.ns}.apply_component(plan jsonb, keys jsonb, fail_after int)
            RETURNS int LANGUAGE plpgsql SET search_path=pg_catalog AS $component$
            DECLARE capability record; planner record; mutation jsonb; key_columns jsonb;
                key_predicate text; update_columns text; current_row jsonb; post_row jsonb;
                key_names text[]; supplied_key_names text[]; matched_count bigint; applied int := 0;
            BEGIN
                SELECT 'release.reserve'::text AS operation INTO capability;
                SELECT plan::text AS mutation_plan_json INTO planner;
                FOR mutation IN {cls.order} LOOP
                    IF NOT {closed_record_sql('mutation')} THEN RAISE EXCEPTION 'closed mutation'; END IF;
                    key_columns := keys->(mutation->>'table');
                    {apply_mutation_sql(cls.ns)}
                    applied := applied + 1;
                    IF applied = fail_after THEN RAISE EXCEPTION 'injected component rollback'; END IF;
                END LOOP;
                RETURN applied;
            END; $component$""")
        cls.pki = fixture_source.crypto.SyntheticNitro()

    def setUp(self):
        # Test-owned cleanup only, with source guards left installed. This is
        # not a production role, authorized migration or retention deletion API.
        self.db.execute(sql.SQL("TRUNCATE {} CASCADE").format(sql.SQL(",").join(
            sql.Identifier(self.schema, name) for name in CHANGED_TABLES)))
        self.fixture = fixture_source.Fixture(self.pki)
        self.assertIsNone(self.fixture.verify())  # Genuine crypto, synthetic PKI/time.
        for selected in self.fixture.rows:
            if selected["present"]:
                self.insert(selected["table"], selected["row"])

    def insert(self, table, value):
        self.db.execute(sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
            sql.Identifier(self.schema, table), sql.SQL(",").join(map(sql.Identifier, value)),
            sql.SQL(",").join(sql.Placeholder() for _ in value)), tuple(value.values()))

    def inventory(self):
        return {table: sorted(self.db.execute(sql.SQL("SELECT * FROM {}").format(
            sql.Identifier(self.schema, table))).fetchall(), key=canonical)
            for table in CHANGED_TABLES + UNTOUCHED_TABLES}

    def transition(self):
        # Capture real table rows for the actual bounded kernel queries. These
        # reads are not authenticated root/predicate-completeness proofs.
        queries = audit_capacity.add_capacity_query("release.reserve", self.fixture.queries)
        selected = {}
        for query in queries:
            comparisons = {"eq": "=", "gt": ">"}
            if any(predicate.operator not in comparisons for predicate in query.predicates):
                raise ValueError("native fixture acquired an unreviewed query operator")
            terms = [sql.SQL("{} {} %s").format(sql.Identifier(item.column), sql.SQL(comparisons[item.operator]))
                for item in query.predicates]
            order = [sql.SQL("{} {}").format(sql.Identifier(item.column), sql.SQL("DESC" if item.descending else "ASC"))
                for item in query.order_by]
            statement = sql.SQL("SELECT * FROM {} WHERE {} ORDER BY {} LIMIT %s").format(
                sql.Identifier(self.schema, query.table), sql.SQL(" AND ").join(terms), sql.SQL(",").join(order))
            rows = self.db.execute(statement,
                tuple(item.value for item in query.predicates) + (query.maximum_rows,)).fetchall()
            observations = [fixture_source.selection(query.table,
                {name: row[name] for name in PRIMARY_KEY_COLUMNS[query.table]}, row) for row in rows]
            if not rows and query.absent_key is not None:
                observations = [fixture_source.selection(query.table, dict(query.absent_key))]
            for observation in observations:
                address = (observation["table"], observation["keyDigest"])
                if address in selected and selected[address] != observation:
                    raise ValueError("native fixture observed conflicting rows")
                selected[address] = observation
        context = replace(self.fixture.context(), selected_rows=tuple(selected.values()))
        transition = self.fixture.kernel.transition(context)
        finalized = audit_capacity.finalize_capacity(context, transition.mutations)
        # Canonical plan ordering stays unchanged. The SQL selects its actual
        # application order; Python never gives routes a test-only priority.
        mutations = sorted(finalized, key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
        return transition, mutations

    def apply(self, mutations, *, fail_after=0):
        keys = {item["table"]: list(PRIMARY_KEY_COLUMNS[item["table"]]) for item in mutations}
        return self.db.execute(f"SELECT {self.ns}.apply_component(%s,%s,%s) AS applied",
            (Jsonb(mutations), Jsonb(keys), fail_after)).fetchone()["applied"]

    def commit(self, *, fail_after=0):
        with self.db.transaction():
            transition, mutations = self.transition()
            self.assertEqual(self.apply(mutations, fail_after=fail_after), len(mutations))
        return transition, mutations

    def existing_route(self):
        _transition, mutations = self.transition()
        row = next(item["row"] for item in mutations if item["table"] == "routes")
        row = {**row, "name": "Existing fixture route", "enabled": 1}
        self.insert("routes", row)
        return row

    def native_payload(self):
        return {**dict.fromkeys(PAYLOAD_FIELDS),
            "schema": "catchplate.policyAuthorityPlannerResponse/v3",
            "measuredPlan": {"operation": "release.reserve"},
            "typedRequest": copy.deepcopy(self.fixture.parent),
            "nativeJitPending": copy.deepcopy(self.fixture.retained)}

    def payload_shape(self, value):
        original = value if isinstance(value, str) else canonical(value).decode("ascii")
        return self.db.execute(f"SELECT {self.ns}.payload_shape(%s) AS accepted",
            (original,)).fetchone()["accepted"]

    def test_actual_payload_key_gate_admits_native_and_preserves_legacy_rosters(self):
        payload = self.native_payload()
        self.assertIs(self.payload_shape(payload), True)
        legacy = copy.deepcopy(payload)
        legacy["typedRequest"]["arguments"]["schema"] = "ordinary-legacy-profile"
        self.assertIs(self.payload_shape(legacy), False)
        del legacy["nativeJitPending"]
        self.assertIs(self.payload_shape(legacy), True)
        for operation, field in (("credential.static.create", "staticCredentialCustodyEvidence"),
                ("credential.static.rotate", "staticCredentialRotationEvidence")):
            static = copy.deepcopy(legacy)
            static["measuredPlan"]["operation"] = operation
            with self.subTest(operation=operation):
                self.assertIs(self.payload_shape(static), False)
                static[field] = {}
                self.assertIs(self.payload_shape(static), True)
                static["nativeJitPending"] = payload["nativeJitPending"]
                self.assertIs(self.payload_shape(static), False)

    def test_actual_payload_key_gate_rejects_malformed_and_duplicate_json_members(self):
        payload = self.native_payload()
        for record in ((), ("typedRequest",), ("typedRequest", "arguments"), ("nativeJitPending",)):
            for change in ("missing", "extra"):
                changed = copy.deepcopy(payload)
                target = changed
                for field in record:
                    target = target[field]
                if change == "missing":
                    del target[next(iter(target))]
                else:
                    target["unexpected"] = None
                with self.subTest(record=record, change=change):
                    self.assertIs(self.payload_shape(changed), False)
        cases = [(("nativeJitPending",), None), (("nativeJitPending",), []),
            (("measuredPlan", "operation"), "jit.request"),
            (("typedRequest", "operation"), "jit.request"),
            (("typedRequest", "schema"), "wrong-schema"),
            (("typedRequest", "handler"), "wrong-handler"),
            (("typedRequest", "operationManifestDigest"), "sha256:" + "0" * 64)]
        for field, values in {"native_profile": (False, "true"),
                "policy_aware_profile": (True, "false"),
                "require_jit_grant": (False, "true"), "now_epoch_ms": (0, "null")}.items():
            cases.extend((("typedRequest", "arguments", field), value) for value in values)
        for field, column in (("parentOriginal", "parent_request_original"),
                ("childOriginal", "child_request_original"), ("pairOriginal", "pair_original"),
                ("evidenceOriginal", "proof_original")):
            cases.extend((("nativeJitPending", field), value)
                for value in (None, {}, 1, "", "\u00e9", "x" * (storage.ORIGINAL_LIMITS[column] + 1)))
        for path, value in cases:
            changed = copy.deepcopy(payload)
            target = changed
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = value
            with self.subTest(path=path, value_type=type(value).__name__):
                self.assertIs(self.payload_shape(changed), False)
        # Pass literal valid JSON with repeated members directly to PostgreSQL.
        # A Python dict or jsonb round-trip would erase these negative controls.
        original = canonical(payload).decode("ascii")
        for path, duplicate in (((), "nativeJitPending"), (("typedRequest",), "handler"),
                (("typedRequest", "arguments"), "native_profile"), (("nativeJitPending",), "pairOriginal")):
            target = payload
            for field in path:
                target = target[field]
            target_original = canonical(target).decode("ascii")
            repeated = target_original[:-1] + "," + canonical(duplicate).decode("ascii") + ":" \
                + canonical(target[duplicate]).decode("ascii") + "}"
            if path:
                needle = canonical(path[-1]).decode("ascii") + ":" + target_original
                self.assertEqual(original.count(needle), 1)
                changed = original.replace(needle, canonical(path[-1]).decode("ascii") + ":" + repeated, 1)
            else:
                changed = repeated
            with self.subTest(duplicate_record=path):
                self.assertIs(self.payload_shape(changed), False)

    def test_complete_schema_catalog_and_insert_only_registration(self):
        columns = self.db.execute("SELECT column_name FROM information_schema.columns "
            "WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position", (self.schema, storage.TABLE)).fetchall()
        self.assertEqual(tuple(row["column_name"] for row in columns), storage.COLUMNS)
        references = self.db.execute("SELECT condeferrable, condeferred FROM pg_constraint "
            "WHERE conrelid=%s::regclass AND contype='f'", (self.ns + "." + storage.TABLE,)).fetchall()
        self.assertEqual(references, [{"condeferrable": True, "condeferred": True}])
        route_fk = self.db.execute("SELECT condeferrable FROM pg_constraint WHERE conrelid=%s::regclass "
            "AND confrelid=%s::regclass AND contype='f'",
            (self.ns + ".approval_requests", self.ns + ".routes")).fetchall()
        self.assertEqual(route_fk, [{"condeferrable": False}])
        triggers = self.db.execute("SELECT tgenabled FROM pg_trigger WHERE tgrelid=%s::regclass "
            "AND NOT tgisinternal", (self.ns + "." + storage.TABLE,)).fetchall()
        self.assertEqual(triggers, [{"tgenabled": "O"}, {"tgenabled": "O"}])
        templates = [item for item in contract.operation_spec("release.reserve")["mutationTemplates"]
            if item["table"] == storage.TABLE]
        self.assertEqual([item["mutation"] for item in templates], ["INSERT"])

    def test_missing_route_commits_complete_pending_transition(self):
        transition, mutations = self.commit()
        self.assertEqual(len(mutations), 6)
        rows = self.inventory()
        self.assertEqual([len(rows[table]) for table in CHANGED_TABLES], [1, 1, 1, 2, 1])
        expected = next(item["row"] for item in mutations if item["table"] == storage.TABLE)
        self.assertEqual(rows[storage.TABLE], [expected])
        self.assertEqual(rows["approval_requests"][0]["id"], transition.result["approval_request_id"])
        self.assertFalse(transition.result["authorized"])
        self.assertEqual(transition.result["durable_policy"]["state"], "denied")
        self.assertTrue(all(not rows[table] for table in UNTOUCHED_TABLES))
        self.assertTrue(all(row["live_count"] == 1 for row in rows[AGGREGATES]))

    def test_existing_route_is_unchanged_and_all_other_effects_commit(self):
        route = self.existing_route()
        _transition, mutations = self.commit()
        self.assertEqual(len(mutations), 5)
        self.assertNotIn("routes", {item["table"] for item in mutations})
        self.assertEqual(self.inventory()["routes"], [route])
        self.assertEqual(len(self.inventory()[storage.TABLE]), 1)

    def test_failure_after_each_actual_sql_mutation_rolls_back_all_tables(self):
        for existing in (False, True):
            if existing:
                self.existing_route()
            before = self.inventory()
            _transition, mutations = self.transition()
            for ordinal in range(1, len(mutations) + 1):
                with self.subTest(existing_route=existing, after=ordinal):
                    with self.assertRaisesRegex(psycopg.errors.RaiseException, "injected component rollback"):
                        self.commit(fail_after=ordinal)
                    self.assertEqual(self.inventory(), before)

    def test_deferred_parent_fk_rejects_orphan_at_commit_and_rolls_back(self):
        _transition, mutations = self.transition()
        pair = next(item for item in mutations if item["table"] == storage.TABLE)
        before = self.inventory()
        reached_commit = False
        with self.assertRaises(psycopg.errors.ForeignKeyViolation):
            with self.db.transaction():
                self.assertEqual(self.apply([pair]), 1)
                reached_commit = True
        self.assertTrue(reached_commit, "FK was not deferred to the transaction boundary")
        self.assertEqual(self.inventory(), before)

    def test_committed_pair_cannot_be_updated_deleted_or_reinserted(self):
        _transition, mutations = self.commit()
        before = self.inventory()
        pair = next(item for item in mutations if item["table"] == storage.TABLE)
        for statement in (f"UPDATE {self.ns}.{storage.TABLE} SET recorded_at_epoch_ns=recorded_at_epoch_ns",
                f"DELETE FROM {self.ns}.{storage.TABLE}"):
            with self.subTest(statement=statement.split()[0]), self.assertRaisesRegex(
                    psycopg.errors.RaiseException, "history is immutable"):
                with self.db.transaction():
                    self.db.execute(statement)
            self.assertEqual(self.inventory(), before)
        with self.assertRaises(psycopg.errors.UniqueViolation):
            with self.db.transaction():
                self.insert(storage.TABLE, pair["row"])
        with self.assertRaises(core.TransitionKernelError):
            self.transition()  # A new execution owner is not committed replay.
        self.assertEqual(self.inventory(), before)

    def test_parent_and_child_request_uniqueness_never_overwrites_originals(self):
        _transition, mutations = self.commit()
        original = next(item["row"] for item in mutations if item["table"] == storage.TABLE)
        before = self.inventory()
        for duplicate in ("parent_request_digest", "child_request_digest"):
            row = {**original, "approval_request_id": str(uuid.uuid4()),
                "parent_request_digest": "sha256:" + "6" * 64, "child_request_digest": "sha256:" + "7" * 64}
            row[duplicate] = original[duplicate]
            with self.subTest(duplicate=duplicate), self.assertRaises(psycopg.errors.UniqueViolation):
                with self.db.transaction():
                    self.insert(storage.TABLE, row)
            self.assertEqual(self.inventory(), before)

    def test_literal_limits_and_lifetime_checks_reject_before_any_retention(self):
        _transition, mutations = self.transition()
        pair = next(item for item in mutations if item["table"] == storage.TABLE)
        row = pair["row"]
        cases = {"zero issued": {"issued_at_epoch_ns": 0},
            "recorded before issuance": {"recorded_at_epoch_ns": row["issued_at_epoch_ns"] - 1},
            "recorded at expiry": {"recorded_at_epoch_ns": row["seal_expires_at_epoch_ns"]},
            "seal beyond document": {"document_expires_at_epoch_ns": row["seal_expires_at_epoch_ns"] - 1},
            "seal interval": {"seal_expires_at_epoch_ns": row["issued_at_epoch_ns"] + storage.MAX_SEAL_INTERVAL_NS + 1},
            "foreign source": {"source_revision": "unreviewed-source"},
            "zero commitment": {"pair_sha256": storage.ZERO_DIGEST},
            "invalid KEK": {"secret_kek_id": "host-key"}}
        for column, limit in storage.ORIGINAL_LIMITS.items():
            cases[column + " overflow"] = {column: "x" * (limit + 1)}
            cases[column + " newline"] = {column: "{}\n"}
            cases[column + " Unicode"] = {column: '"\u00e9"'}
        before = self.inventory()
        for label, changed in cases.items():
            with self.subTest(case=label), self.assertRaises(psycopg.errors.CheckViolation):
                with self.db.transaction():
                    self.insert(storage.TABLE, {**row, **changed})
            self.assertEqual(self.inventory(), before)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-dsn", required=True)
    arguments = parser.parse_args()
    global PARAMETERS
    PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeJitRetentionPostgresTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() and result.testsRun == 10 and not result.skipped else 1


if __name__ == "__main__":
    raise SystemExit(main())
