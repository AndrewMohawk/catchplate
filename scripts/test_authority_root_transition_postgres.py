#!/usr/bin/env python3
"""Real PostgreSQL tests of the shared persisted-root-transition SQL boundary.

The caller must prepare a disposable private Unix-socket PostgreSQL cluster.
This file never starts an engine, imports db/registry, or creates authority.
Fixture records deliberately stand in for already admitted planner/capability
rows and opaque root heads. These are NOT valid full planner or witness inputs.
The exact production SQL guards, and the production canonical/digest functions,
run against a real engine; data/root/publication rollback is observed directly.
Pure radix calculation and signature admission have separate test boundaries.
"""
from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import json
import re
import sys
import textwrap
import unittest
import uuid
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.native_postgres_results import run_native_fixture

from serverware import authority_contract
from serverware.authority_store.primary_tree_sql import canonical_json_function_sql
from serverware.authority_store.root_transition_sql import (
    TRANSITION_PROFILE,
    TRANSITION_SCHEMA,
    assert_root_transition_after_sql,
    assert_root_transition_before_sql,
    assert_root_transition_payload_sql,
    assert_root_transition_replay_sql,
    load_root_transition_sql,
    root_transition_declarations_sql,
)
from serverware.authority_store.wire_json_sql import wire_json_function_sql
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
OPERATION = "webauthn.counter.cas"
PLANNER_COLUMNS = {
    "planner_transaction_id": "text", "operation": "text", "operation_id": "text",
    "request_digest": "text", "capability_id": "text", "operation_contract_digest": "text",
    "query_manifest_digest": "text", "selected_business_rows_json": "text",
    "selected_business_rows_digest": "text", "mutation_plan_json": "text",
    "mutation_plan_digest": "text", "work_units": "bigint",
    "authority_root_set_before_digest": "text", "authorization_projection_digest": "text",
    "authority_snapshot_digest": "text", "deadline_monotonic_ns": "bigint",
    "deadline_epoch_ns": "bigint", "fence": "bigint", "source_revision": "text",
    "planner_session_identity_digest": "text", "planner_measurement_digest": "text",
    "planner_attestation_receipt_digest": "text", "exact_plan_base64url": "text",
    "exact_plan_bytes_digest": "text", "exact_plan_byte_count": "bigint",
}
CAPABILITY_COLUMNS = {
    "capability_id": "text", "planner_transaction_id": "text", "operation": "text",
    "operation_id": "text", "request_digest": "text", "authority_root_set_digest": "text",
    "query_manifest_digest": "text", "selected_business_rows_digest": "text",
    "mutation_plan_digest": "text", "authorization_projection_digest": "text",
    "expected_result_digest": "text", "authority_snapshot_digest": "text",
}


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(domain: str, *frames: bytes) -> str:
    # Independent spelling of the wire framing, not the production hash helper.
    material = domain.encode("ascii") + b"\0"
    for frame in frames:
        material += len(frame).to_bytes(8, "big") + frame
    return "sha256:" + hashlib.sha256(material).hexdigest()


def token(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def production_digest_functions(namespace: str) -> list[str]:
    """Use shared tree JSON and extract the remaining wire-domain SQL literal.

    Never import db.py or replace either implementation with fixture SQL.
    The tree's separate length-framed digest is not the wire-domain function.
    """
    path = ROOT / "serverware/db.py"
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("database source exceeds component fixture bound")
    source = path.read_text(encoding="utf-8")
    marker = '        conn.execute(\n            f"""\n            CREATE OR REPLACE FUNCTION {guard_namespace}.\n                '
    declarations = []
    for function_name, delimiter in (("serverware_policy_authority_domain_digest", "serverware_digest"),):
        start = source.index(marker + function_name + "(")
        closing = f'            ${delimiter}$\n            """\n        )'
        end = source.index(closing, start) + len(closing)
        declarations.extend(ast.parse(textwrap.dedent(source[start:end])).body)
    maximum = re.search(r"^_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_BYTES = ([0-9 *]+)$",
                        source, re.MULTILINE)
    if maximum is None:
        raise ValueError("database canonical byte bound is not a literal product")
    maximum_bytes = 1
    for part in maximum.group(1).split("*"):
        maximum_bytes *= int(part.strip())
    substitutions = {
        "guard_namespace": namespace,
        "_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_BYTES": str(maximum_bytes),
    }
    statements = [canonical_json_function_sql(namespace)]
    for node in declarations:
        if (not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call)
                or not isinstance(node.value.func, ast.Attribute)
                or node.value.func.attr != "execute" or len(node.value.args) != 1
                or not isinstance(node.value.args[0], ast.JoinedStr)):
            raise ValueError("database digest SQL literal boundary changed")
        fragments = []
        for fragment in node.value.args[0].values:
            if isinstance(fragment, ast.Constant) and isinstance(fragment.value, str):
                fragments.append(fragment.value)
            elif (isinstance(fragment, ast.FormattedValue) and isinstance(fragment.value, ast.Name)
                  and fragment.value.id in substitutions and fragment.conversion == -1
                  and fragment.format_spec is None):
                fragments.append(substitutions[fragment.value.id])
            else:
                raise ValueError("database digest SQL interpolation changed")
        statements.append("".join(fragments))
    if len(statements) != 2:
        raise ValueError("database digest support functions are not exact")
    return statements


def fixture_payload() -> dict:
    before = {"table": "items", "rootRevision": 7, "rootDigest": token("before"), "leafCount": 3}
    after = {**before, "rootRevision": 8, "rootDigest": token("after")}
    authorization = {"table": "auth_items", "rootRevision": 2, "rootDigest": token("auth"), "leafCount": 1}
    # These shapes start after planner admission: the component does not claim
    # this synthetic manifest, row or opaque proof is an actual operation plan.
    key = {"id": "clé-雪😀"}
    key_digest = digest("serverware.policyAuthorityBusinessKey/v1", b"items", canonical(key))
    selected = [{"table": "items", "key": key, "keyDigest": key_digest,
                 "present": True, "row": {**key, "value": "caf\u00e9"}, "contractSelector": None}]
    mutations = [{"templateId": "fixture-not-authority", "operation": "UPDATE", "table": "items",
                  "key": key, "keyDigest": key_digest,
                  "expectedRow": selected[0]["row"], "row": {**key, "value": "apr\u00e8s"}}]
    request_digest = token("request")
    plan = {
        "schema": "serverware.policyAuthorityMeasuredPlan/v3",
        "plannerTransactionId": token("planner"), "operation": OPERATION,
        "operationId": digest("serverware.policyAuthorityOperation/v2", OPERATION.encode(), request_digest.encode()),
        "requestDigest": request_digest, "capabilityId": token("capability"),
        "sourceRevision": authority_contract.SOURCE_REVISION,
        "authoritySchemaVersion": authority_contract.SCHEMA_VERSION,
        "operationContractDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "handlerContractDigest": authority_contract.handler_contract_digest(OPERATION),
        "queryManifestDigest": token("manifest"),
        "selectedBusinessRowsDigest": digest("serverware.policyAuthoritySelectedBusinessRows/v1", canonical(selected)),
        "mutationPlanDigest": digest("serverware.policyAuthorityMutationPlan/v3", canonical(mutations)),
        "workUnits": 1, "authorityRootSetBeforeDigest": "filled-by-seal",
        "authorizationProjectionDigest": token("projection"), "authoritySnapshotDigest": "filled-by-seal",
        "deadlineMonotonicNs": 1000000000000, "deadlineEpochNs": 2000000000000,
        "fence": 1, "rootTransitionDigest": "filled-by-seal",
    }
    return {
        "schema": "serverware.policyAuthorityPlannerResponse/v3", "measuredPlan": plan,
        "typedRequest": {"component": "requête-雪😀", "control": "\n\t\x01"}, "selectedBusinessRows": selected,
        "mutationPlan": mutations, "queryMultiproofs": [{"component": "opaque before proof"}],
        "queryMultiproofsDigest": token("proofs"), "plannerTrace": {"component": "trace"},
        "plannerTraceDigest": token("trace"),
        "authorizationProjection": {"component": "projection", "subject": "utilisateur-雪😀"},
        "webauthnEvidence": None, "expectedResult": {"ok": True, "label": "résultat-雪😀"},
        "expectedResultDigest": "filled-by-seal",
        "plannerIdentity": {"sessionIdentityDigest": token("session"), "measurementDigest": token("measurement"),
                            "attestationReceiptDigest": token("attestation")},
        "rootTransition": {"schema": TRANSITION_SCHEMA, "profile": TRANSITION_PROFILE,
                           "businessBeforeRoots": [before], "authorizationBeforeRoots": [authorization],
                           "businessAfterRoots": [after], "authorizationAfterRoots": [copy.deepcopy(authorization)],
                           "metrics": {"selectedRows": 1, "mutations": 1, "proofVectors": 64,
                                       "proofChildSlots": 1024, "recomputedAncestors": 64,
                                       "hashWork": 136, "inputBytes": 4096, "jsonNodes": 100}},
    }


def seal(payload: dict) -> tuple[dict, dict, dict]:
    payload = copy.deepcopy(payload)
    plan = payload["measuredPlan"]
    transition = payload["rootTransition"]
    payload["expectedResultDigest"] = digest("serverware.policyAuthorityControlledWriterResult/v2",
                                           canonical(payload["expectedResult"]))
    plan["authorizationProjectionDigest"] = digest("serverware.policyAuthorityAuthorizationProjection/v1",
                                                   canonical(payload["authorizationProjection"]))
    plan["rootTransitionDigest"] = digest(TRANSITION_SCHEMA, canonical(transition))
    plan["authorityRootSetBeforeDigest"] = digest("serverware.policyAuthorityRootSet/v1", canonical(transition["businessBeforeRoots"]))
    plan["authoritySnapshotDigest"] = digest("serverware.policyAuthoritySnapshot/v3", *[
        plan[field].encode("ascii") for field in (
            "operation", "operationId", "requestDigest", "queryManifestDigest", "authorityRootSetBeforeDigest",
            "authorizationProjectionDigest", "selectedBusinessRowsDigest", "mutationPlanDigest", "rootTransitionDigest")])
    mapping = {
        "planner_transaction_id": "plannerTransactionId", "operation": "operation", "operation_id": "operationId",
        "request_digest": "requestDigest", "capability_id": "capabilityId", "operation_contract_digest": "operationContractDigest",
        "query_manifest_digest": "queryManifestDigest", "selected_business_rows_digest": "selectedBusinessRowsDigest",
        "mutation_plan_digest": "mutationPlanDigest", "work_units": "workUnits",
        "authority_root_set_before_digest": "authorityRootSetBeforeDigest", "authorization_projection_digest": "authorizationProjectionDigest",
        "authority_snapshot_digest": "authoritySnapshotDigest", "deadline_monotonic_ns": "deadlineMonotonicNs",
        "deadline_epoch_ns": "deadlineEpochNs", "fence": "fence", "source_revision": "sourceRevision",
    }
    planner = {column: plan[field] for column, field in mapping.items()}
    planner.update({"selected_business_rows_json": canonical(payload["selectedBusinessRows"]).decode(),
                    "mutation_plan_json": canonical(payload["mutationPlan"]).decode(),
                    "planner_session_identity_digest": payload["plannerIdentity"]["sessionIdentityDigest"],
                    "planner_measurement_digest": payload["plannerIdentity"]["measurementDigest"],
                    "planner_attestation_receipt_digest": payload["plannerIdentity"]["attestationReceiptDigest"]})
    set_plan_bytes(planner, canonical(payload))
    capability = {column: planner[column] for column in CAPABILITY_COLUMNS
                  if column in planner}
    capability.update({"authority_root_set_digest": plan["authorityRootSetBeforeDigest"],
                       "expected_result_digest": payload["expectedResultDigest"]})
    return payload, planner, capability


def set_plan_bytes(planner: dict, raw: bytes) -> None:
    planner.update({"exact_plan_base64url": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
                    "exact_plan_bytes_digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                    "exact_plan_byte_count": len(raw)})


class AuthorityRootTransitionPostgresTests(unittest.TestCase):
    @classmethod
    def connection(cls) -> psycopg.Connection:
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("this real-engine component requires --postgres-dsn")
        connection = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=True)
        connection.isolation_level = psycopg.IsolationLevel.SERIALIZABLE
        return connection

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = "serverware_root_transition_" + uuid.uuid4().hex
        cls.namespace = '"' + cls.schema + '"'
        with cls.connection() as connection:
            if connection.execute("SELECT inet_server_addr()").fetchone() != (None,):
                raise RuntimeError("component fixture must use a Unix socket")
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(cls.schema)))
        cls.addClassCleanup(cls.drop_schema)
        with cls.connection() as connection:
            for statement in production_digest_functions(cls.namespace):
                connection.execute(statement)
            connection.execute(wire_json_function_sql(cls.namespace))
            connection.execute(f"""
                CREATE TYPE {cls.namespace}.fixture_planner AS ({', '.join(name + ' ' + kind for name, kind in PLANNER_COLUMNS.items())});
                CREATE TYPE {cls.namespace}.fixture_capability AS ({', '.join(name + ' ' + kind for name, kind in CAPABILITY_COLUMNS.items())});
                CREATE TABLE {cls.namespace}.fixture_state (id integer PRIMARY KEY, planner_json jsonb, capability_json jsonb,
                    terminal_receipt_json text, exact_request_base64url text, exact_request_bytes_digest text,
                    exact_request_byte_count bigint);
                CREATE TABLE {cls.namespace}.items (id integer PRIMARY KEY, value integer NOT NULL);
                CREATE TABLE {cls.namespace}.publications (id integer PRIMARY KEY);
                CREATE TABLE {cls.namespace}.policy_authority_query_dependency_manifests (operation text, table_name text);
                CREATE TABLE {cls.namespace}.policy_authority_authorization_dependency_manifests (operation text, table_name text);
                CREATE TABLE {cls.namespace}.policy_authority_authenticated_table_roots
                    (table_name text PRIMARY KEY, root_revision bigint, root_digest text, leaf_count bigint);
                CREATE FUNCTION {cls.namespace}.component(actual_after jsonb, request_payload bytea, result_payload bytea,
                    supplied_projection_json text, replay boolean DEFAULT false)
                RETURNS text LANGUAGE plpgsql SET search_path = pg_catalog AS $component$
                DECLARE
                    planner {cls.namespace}.fixture_planner;
                    capability {cls.namespace}.fixture_capability;
                    execution_envelope record;
                    authorization_projection record;
                    fixture_record record;
                    root_set_before_json text;
                    authorization_root_set_json text;
                    root_set_after_json text;
                    root_set_after_digest text;
                    request_bytes bytea;
                    result_bytes bytea;
                    canonical_result text;
                    supplied_exact_request_base64url text;
                    {root_transition_declarations_sql()}
                BEGIN
                    SELECT * INTO STRICT fixture_record FROM {cls.namespace}.fixture_state WHERE id=1 FOR UPDATE;
                    planner := pg_catalog.jsonb_populate_record(NULL::{cls.namespace}.fixture_planner, fixture_record.planner_json);
                    capability := pg_catalog.jsonb_populate_record(NULL::{cls.namespace}.fixture_capability, fixture_record.capability_json);
                    SELECT fixture_record.terminal_receipt_json AS terminal_receipt_json,
                        fixture_record.exact_request_base64url AS exact_request_base64url,
                        fixture_record.exact_request_bytes_digest AS exact_request_bytes_digest,
                        fixture_record.exact_request_byte_count AS exact_request_byte_count INTO execution_envelope;
                    {load_root_transition_sql(cls.namespace)}
                    IF replay THEN
                        {assert_root_transition_replay_sql(cls.namespace)}
                        RETURN 'historical';
                    END IF;
                    request_bytes := request_payload;
                    result_bytes := result_payload;
                    supplied_exact_request_base64url := pg_catalog.translate(
                        pg_catalog.encode(request_payload, 'base64'), E'+/=\\n\\r', '-_');
                    SELECT supplied_projection_json AS projection_json INTO authorization_projection;
                    {assert_root_transition_payload_sql(cls.namespace)}
                    SELECT {cls.namespace}.serverware_policy_authority_wire_json(pg_catalog.jsonb_agg(
                        pg_catalog.jsonb_build_object('table',table_name,'rootRevision',root_revision,'rootDigest',root_digest,'leafCount',leaf_count)
                        ORDER BY table_name COLLATE "C")) INTO root_set_before_json
                    FROM {cls.namespace}.policy_authority_authenticated_table_roots WHERE table_name='items';
                    SELECT {cls.namespace}.serverware_policy_authority_wire_json(pg_catalog.jsonb_agg(
                        pg_catalog.jsonb_build_object('table',table_name,'rootRevision',root_revision,'rootDigest',root_digest,'leafCount',leaf_count)
                        ORDER BY table_name COLLATE "C")) INTO authorization_root_set_json
                    FROM {cls.namespace}.policy_authority_authenticated_table_roots WHERE table_name='auth_items';
                    {assert_root_transition_before_sql(cls.namespace)}
                    UPDATE {cls.namespace}.items SET value=value+1 WHERE id=1;
                    UPDATE {cls.namespace}.policy_authority_authenticated_table_roots AS stored
                    SET root_revision=(changed.value->>'rootRevision')::bigint,
                        root_digest=changed.value->>'rootDigest', leaf_count=(changed.value->>'leafCount')::bigint
                    FROM pg_catalog.jsonb_array_elements(actual_after) AS changed(value)
                    WHERE stored.table_name=changed.value->>'table';
                    SELECT {cls.namespace}.serverware_policy_authority_wire_json(pg_catalog.jsonb_agg(
                        pg_catalog.jsonb_build_object('table',table_name,'rootRevision',root_revision,'rootDigest',root_digest,'leafCount',leaf_count)
                        ORDER BY table_name COLLATE "C")) INTO root_set_after_json
                    FROM {cls.namespace}.policy_authority_authenticated_table_roots WHERE table_name='items';
                    root_set_after_digest := {cls.namespace}.serverware_policy_authority_domain_digest(
                        'serverware.policyAuthorityRootSet/v1', root_set_after_json);
                    {assert_root_transition_after_sql(cls.namespace)}
                    INSERT INTO {cls.namespace}.publications VALUES (1);
                    RETURN root_set_after_digest;
                END;
                $component$;
            """)

    @classmethod
    def drop_schema(cls) -> None:
        with cls.connection() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(cls.schema)))

    def setUp(self) -> None:
        self.payload, self.planner, self.capability = seal(fixture_payload())
        transition = self.payload["rootTransition"]
        self.actual_after = copy.deepcopy(transition["businessAfterRoots"] + transition["authorizationAfterRoots"])
        with self.connection() as connection:
            connection.execute(f"TRUNCATE {self.namespace}.fixture_state, {self.namespace}.items, {self.namespace}.publications, "
                               f"{self.namespace}.policy_authority_query_dependency_manifests, "
                               f"{self.namespace}.policy_authority_authorization_dependency_manifests, "
                               f"{self.namespace}.policy_authority_authenticated_table_roots")
            connection.execute(f"INSERT INTO {self.namespace}.items VALUES (1,0)")
            for table, relation in (("items", "query"), ("auth_items", "authorization")):
                connection.execute(f"INSERT INTO {self.namespace}.policy_authority_{relation}_dependency_manifests VALUES (%s,%s)",
                                   (OPERATION, table))
            for root in transition["businessBeforeRoots"] + transition["authorizationBeforeRoots"]:
                connection.execute(f"INSERT INTO {self.namespace}.policy_authority_authenticated_table_roots VALUES (%s,%s,%s,%s)",
                                   (root["table"], root["rootRevision"], root["rootDigest"], root["leafCount"]))
        self.store()

    def store(self, receipt: dict | None = None, *, request_binding: bytes | None = None) -> None:
        request = canonical(self.payload["typedRequest"]) if request_binding is None else request_binding
        with self.connection() as connection:
            connection.execute(f"INSERT INTO {self.namespace}.fixture_state VALUES (1,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) "
                               "DO UPDATE SET planner_json=EXCLUDED.planner_json, capability_json=EXCLUDED.capability_json, "
                               "terminal_receipt_json=EXCLUDED.terminal_receipt_json, "
                               "exact_request_base64url=EXCLUDED.exact_request_base64url, "
                               "exact_request_bytes_digest=EXCLUDED.exact_request_bytes_digest, "
                               "exact_request_byte_count=EXCLUDED.exact_request_byte_count",
                               (Jsonb(self.planner), Jsonb(self.capability), canonical(receipt).decode() if receipt is not None else None,
                                base64.urlsafe_b64encode(request).rstrip(b"=").decode("ascii"),
                                "sha256:" + hashlib.sha256(request).hexdigest(), len(request)))

    def reseal(self) -> None:
        self.payload, self.planner, self.capability = seal(self.payload)
        self.store()

    def state(self) -> tuple:
        with self.connection() as connection:
            value = connection.execute(f"SELECT value FROM {self.namespace}.items WHERE id=1").fetchone()[0]
            heads = connection.execute(f"SELECT * FROM {self.namespace}.policy_authority_authenticated_table_roots ORDER BY table_name").fetchall()
            publications = connection.execute(f"SELECT * FROM {self.namespace}.publications").fetchall()
        return value, heads, publications

    def run_component(self, *, replay: bool = False, request_bytes: bytes | None = None,
                      result_bytes: bytes | None = None, projection: dict | None = None) -> str:
        with self.connection() as connection:
            with connection.transaction():
                connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                return connection.execute(f"SELECT {self.namespace}.component(%s,%s,%s,%s,%s)",
                                          (Jsonb(self.actual_after),
                                           canonical(self.payload["typedRequest"]) if request_bytes is None else request_bytes,
                                           canonical(self.payload["expectedResult"]) if result_bytes is None else result_bytes,
                                           canonical(self.payload["authorizationProjection"] if projection is None else projection).decode("ascii"),
                                           replay)).fetchone()[0]

    def reject(self, message: str, *, replay: bool = False) -> None:
        before = self.state()
        with self.assertRaisesRegex(psycopg.errors.RaiseException, message):
            self.run_component(replay=replay)
        self.assertEqual(self.state(), before)

    def test_real_shared_sql_accepts_ascii_plan_with_escaped_unicode(self) -> None:
        raw = base64.urlsafe_b64decode(self.planner["exact_plan_base64url"] + "==")
        self.assertIn(b"caf\\u00e9", raw)
        self.assertEqual(self.run_component(), digest("serverware.policyAuthorityRootSet/v1",
                                                     canonical(self.payload["rootTransition"]["businessAfterRoots"])))
        self.assertEqual(self.state()[0], 1)
        self.assertEqual(self.state()[2], [(1,)])
        # The same Unicode data is supported; only a non-ASCII transport that
        # the actual canonical Python writer never emits is refused.
        set_plan_bytes(self.planner, json.dumps(self.payload, ensure_ascii=False,
                                               sort_keys=True, separators=(",", ":")).encode("utf-8"))
        self.store()
        self.reject("plan transport is not ASCII")

    def test_request_and_result_canonical_spelling_is_not_replaced_by_reserialization(self) -> None:
        for field, member in (("typedRequest", "component"), ("expectedResult", "ok")):
            value = self.payload[field]
            raw = canonical(value)
            alternatives = (
                json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                b" " + raw,
                b'{"' + member.encode("ascii") + b'":null,' + raw[1:],
                raw.replace(b"\\u96ea", b"\\u96EA"),
            )
            for changed in alternatives:
                with self.subTest(field=field, changed=changed):
                    self.assertNotEqual(changed, raw)
                    self.assertEqual(json.loads(changed), value)
                    # Refresh even the persisted request byte anchors: the
                    # canonical-wire guard must still refuse this spelling.
                    self.store(request_binding=changed if field == "typedRequest" else None)
                    before = self.state()
                    supplied = {"request_bytes" if field == "typedRequest" else "result_bytes": changed}
                    with self.assertRaisesRegex(psycopg.errors.RaiseException,
                                                "authority v9 exact request or result bytes changed"):
                        self.run_component(**supplied)
                    self.assertEqual(self.state(), before)

    def test_exact_payload_value_join_denies_changed_request_result_and_projection(self) -> None:
        for parameter, changed in (
            ("request_bytes", canonical({**self.payload["typedRequest"], "component": "other-雪"})),
            ("result_bytes", canonical({**self.payload["expectedResult"], "label": "other-雪"})),
            ("projection", {**self.payload["authorizationProjection"], "subject": "other-雪"}),
        ):
            with self.subTest(parameter=parameter):
                before = self.state()
                with self.assertRaisesRegex(psycopg.errors.RaiseException,
                                            "authority root transition exact payload changed"):
                    self.run_component(**{parameter: changed})
                self.assertEqual(self.state(), before)

    def test_exact_request_persisted_byte_anchors_are_independent(self) -> None:
        for column, changed in (
            ("exact_request_base64url", "e30"),
            ("exact_request_bytes_digest", token("different-request-bytes")),
            ("exact_request_byte_count", len(canonical(self.payload["typedRequest"])) + 1),
        ):
            self.store()
            with self.connection() as connection:
                connection.execute(sql.SQL("UPDATE {}.fixture_state SET {}=%s WHERE id=1").format(
                    sql.Identifier(self.schema), sql.Identifier(column)), (changed,))
            with self.subTest(column=column):
                self.reject("authority v9 exact request or result bytes changed")

    def test_wire_unicode_key_row_projection_and_result_domains_match_python(self) -> None:
        # These are real SQL serializer/domain calls, not the complete executor
        # selected-row/authentication loops or authenticated-tree mutations.
        selected = self.payload["selectedBusinessRows"][0]
        key, row = selected["key"], selected["row"]
        with self.connection() as connection:
            actual = connection.execute(f"""
                SELECT
                    {self.namespace}.serverware_policy_authority_domain_digest(
                        'serverware.policyAuthorityBusinessKey/v1', 'items',
                        {self.namespace}.serverware_policy_authority_wire_json(%s::jsonb)),
                    {self.namespace}.serverware_policy_authority_domain_digest(
                        'serverware.policyAuthorityAuthorizationRow/v1', 'items',
                        {self.namespace}.serverware_policy_authority_wire_json(%s::jsonb), 'present',
                        {self.namespace}.serverware_policy_authority_wire_json(%s::jsonb)),
                    {self.namespace}.serverware_policy_authority_domain_digest(
                        'serverware.policyAuthorityAuthorizationProjection/v1',
                        {self.namespace}.serverware_policy_authority_wire_json(%s::jsonb)),
                    {self.namespace}.serverware_policy_authority_domain_digest(
                        'serverware.policyAuthorityControlledWriterResult/v2',
                        {self.namespace}.serverware_policy_authority_wire_json(%s::jsonb))
                """, (Jsonb(key), Jsonb(key), Jsonb(row), Jsonb(self.payload["authorizationProjection"]),
                       Jsonb(self.payload["expectedResult"]))).fetchone()
        self.assertEqual(actual, (
            selected["keyDigest"],
            digest("serverware.policyAuthorityAuthorizationRow/v1", b"items", canonical(key), b"present", canonical(row)),
            self.payload["measuredPlan"]["authorizationProjectionDigest"], self.payload["expectedResultDigest"],
        ))

    def test_persisted_tree_utf8_serializer_remains_distinct_and_does_not_normalize(self) -> None:
        composed, decomposed = {"clé": "é-雪😀"}, {"clé": "e\u0301-雪😀"}
        with self.connection() as connection:
            for value in (composed, decomposed):
                actual = connection.execute(f"SELECT "
                    f"{self.namespace}.serverware_policy_authority_canonical_json(%s::jsonb), "
                    f"{self.namespace}.serverware_policy_authority_wire_json(%s::jsonb)",
                    (Jsonb(value), Jsonb(value))).fetchone()
                self.assertEqual(actual, (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                                          canonical(value).decode("ascii")))
                self.assertNotEqual(actual[0], actual[1])
        self.assertNotEqual(canonical(composed), canonical(decomposed))

    def test_exact_plan_hash_length_and_base64_are_mandatory(self) -> None:
        for column, value in (("exact_plan_byte_count", self.planner["exact_plan_byte_count"] + 1),
                              ("exact_plan_bytes_digest", token("wrong")),
                              ("exact_plan_base64url", self.planner["exact_plan_base64url"] + "=")):
            with self.subTest(column=column):
                original = self.planner[column]
                self.planner[column] = value
                self.store()
                self.reject("exact plan bytes")
                self.planner[column] = original

    def test_invalid_json_and_invalid_utf8_bytes_abort_without_writes(self) -> None:
        for raw in (b'{"schema":', b'{"schema":"\xff"}'):
            set_plan_bytes(self.planner, raw)
            self.store()
            before = self.state()
            with self.assertRaises(psycopg.DataError):
                self.run_component()
            self.assertEqual(self.state(), before)

    def test_old_missing_and_extra_plan_fields_are_denied(self) -> None:
        for changed in ("old", "missing", "extra"):
            self.payload, self.planner, self.capability = seal(fixture_payload())
            if changed == "old": self.payload["schema"] = "serverware.policyAuthorityPlannerResponse/v2"
            elif changed == "missing": del self.payload["rootTransition"]
            else: self.payload["unexpected"] = None
            set_plan_bytes(self.planner, canonical(self.payload))
            self.store()
            self.reject("plan payload is not closed v3")

    def test_duplicate_closed_members_are_not_hidden_by_jsonb(self) -> None:
        for name, message in (("rootTransition", "plan payload"), ("rootTransitionDigest", "measured plan"),
                              ("profile", "profile"), ("hashWork", "metrics")):
            raw = canonical(self.payload).decode()
            location = raw.index('"' + name + '":')
            # Duplicate with an arbitrary first value; last-value JSONB alone
            # would erase it and incorrectly accept the original value.
            raw = raw[:location] + '"' + name + '":null,' + raw[location:]
            set_plan_bytes(self.planner, raw.encode())
            self.store()
            self.reject(message)

    def test_profile_and_metric_type_bounds_and_counts_are_closed(self) -> None:
        for name, value, message in (("profile", "legacy", "profile"),
                                    ("hashWork", True, "unsigned integer"),
                                    ("inputBytes", 67108865, "exceeds its profile"),
                                    ("proofVectors", 63, "metric binding"),
                                    ("hashWork", 65, "metric binding")):
            self.payload = fixture_payload()
            if name == "profile": self.payload["rootTransition"][name] = value
            else: self.payload["rootTransition"]["metrics"][name] = value
            self.reseal()
            self.reject(message)

    def test_metric_exponent_and_fraction_tokens_are_not_integer_aliases(self) -> None:
        for token_text in ("1.36e2", "136.0"):
            raw = canonical(self.payload).replace(b'"hashWork":136', ('"hashWork":' + token_text).encode())
            set_plan_bytes(self.planner, raw)
            self.store()
            self.reject("metric is not an unsigned integer")

    def test_root_descriptor_types_order_and_manifest_inventory_are_exact(self) -> None:
        for mode, message in (("bool", "descriptor is invalid"), ("extra", "descriptor is invalid"),
                              ("duplicate", "order or bound"), ("missing", "inventory escaped")):
            self.payload = fixture_payload()
            roots = self.payload["rootTransition"]["businessBeforeRoots"]
            if mode == "bool": roots[0]["rootRevision"] = True
            elif mode == "extra": roots[0]["unexpected"] = 1
            elif mode == "duplicate": roots.append(copy.deepcopy(roots[0]))
            else: roots.clear()
            self.reseal()
            self.reject(message)

    def test_locked_row_identity_and_snapshot_are_not_selected_by_payload(self) -> None:
        self.payload["measuredPlan"]["fence"] = 2
        set_plan_bytes(self.planner, canonical(self.payload))
        self.store()
        self.reject("locked plan binding")
        self.payload, self.planner, self.capability = seal(fixture_payload())
        self.capability["authority_snapshot_digest"] = token("wrong-snapshot")
        self.store()
        self.reject("snapshot binding")

    def test_transition_digest_must_match_even_with_fresh_byte_digest(self) -> None:
        self.payload["measuredPlan"]["rootTransitionDigest"] = token("wrong-transition")
        set_plan_bytes(self.planner, canonical(self.payload))
        self.store()
        self.reject("transition digest changed")

    def test_changed_before_roots_are_rejected_without_writes(self) -> None:
        self.payload["rootTransition"]["businessBeforeRoots"][0]["rootRevision"] += 1
        self.reseal()
        self.reject("before roots changed")

    def test_business_after_digest_revision_and_count_mismatch_roll_back(self) -> None:
        for field, value in (("rootDigest", token("wrong-after")), ("rootRevision", 9), ("leafCount", 4)):
            changed = copy.deepcopy(self.actual_after)
            changed[0][field] = value
            original, self.actual_after = self.actual_after, changed
            self.reject("after roots changed")
            self.actual_after = original

    def test_authorization_after_tamper_rolls_back_business_write(self) -> None:
        self.actual_after[1]["rootRevision"] += 1
        self.reject("after roots changed")

    def test_historical_replay_ignores_later_current_heads(self) -> None:
        receipt = {"authoritySnapshotDigest": self.payload["measuredPlan"]["authoritySnapshotDigest"],
                   "authorityRootSetBeforeDigest": self.payload["measuredPlan"]["authorityRootSetBeforeDigest"],
                   "authorityRootSetAfterDigest": digest("serverware.policyAuthorityRootSet/v1", canonical(self.payload["rootTransition"]["businessAfterRoots"]))}
        self.store(receipt)
        with self.connection() as connection:
            connection.execute(f"UPDATE {self.namespace}.policy_authority_authenticated_table_roots SET root_revision=root_revision+20")
        before = self.state()
        self.assertEqual(self.run_component(replay=True), "historical")
        self.assertEqual(self.state(), before)
        for field in receipt:
            self.store({**receipt, field: token("wrong-terminal")})
            self.reject("historical receipt changed", replay=True)

    def test_ninth_digest_frame_is_reserved_for_snapshot_v3(self) -> None:
        with self.connection() as connection:
            frames = ["frame"] * 9
            actual = connection.execute(f"SELECT {self.namespace}.serverware_policy_authority_domain_digest(%s,VARIADIC %s::text[])",
                                        ("serverware.policyAuthoritySnapshot/v3", frames)).fetchone()[0]
            self.assertEqual(actual, digest("serverware.policyAuthoritySnapshot/v3", *[b"frame"] * 9))
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "framing is outside"):
                connection.execute(f"SELECT {self.namespace}.serverware_policy_authority_domain_digest(%s,VARIADIC %s::text[])",
                                   ("serverware.policyAuthoritySnapshot/v2", frames))
            for count in (8, 10):
                with self.assertRaisesRegex(psycopg.errors.RaiseException, "framing is outside"):
                    connection.execute(f"SELECT {self.namespace}.serverware_policy_authority_domain_digest(%s,VARIADIC %s::text[])",
                                       ("serverware.policyAuthoritySnapshot/v3", ["frame"] * count))
            previous = connection.execute(f"SELECT {self.namespace}.serverware_policy_authority_domain_digest(%s,VARIADIC %s::text[])",
                                          ("serverware.policyAuthoritySnapshot/v2", ["frame"] * 8)).fetchone()[0]
            self.assertEqual(previous, digest("serverware.policyAuthoritySnapshot/v2", *[b"frame"] * 8))

    def test_source_wiring_keeps_load_before_replay_and_after_guard_before_publication(self) -> None:
        # Source-only ordering, not a fabricated full executor invocation.
        source = (ROOT / "serverware/authority_store/executor_v9.py").read_text(encoding="utf-8")
        start = source.index("        CREATE OR REPLACE FUNCTION {namespace}.\n"
                             "            serverware_policy_authority_execute_v9(")
        end = source.index("$serverware_execute_v9$;", start)
        body = source[start:end]
        self.assertLess(body.index("{load_root_transition_sql(namespace)}"), body.index("IF capability.status = 'committed'"))
        self.assertLess(body.index("{assert_root_transition_replay_sql(namespace)}"), body.index("RETURN execution_envelope.terminal_receipt_json"))
        self.assertLess(body.index("{assert_root_transition_after_sql(namespace)}"), body.index("receipt_value := pg_catalog.jsonb_build_object"))
        self.assertLess(body.index("{assert_root_transition_payload_sql(namespace)}"), body.index("computed_result_digest :="))
        self.assertNotIn("serverware_policy_authority_canonical_json", source)
        self.assertIn("serverware_policy_authority_wire_json", source)
        self.assertNotIn("canonical_json(rt_payload)", body)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    run_native_fixture("scripts/test_authority_root_transition_postgres.py",
        argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
