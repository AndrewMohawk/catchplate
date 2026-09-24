#!/usr/bin/env python3
"""Real PostgreSQL tests of the shared persisted-root-transition SQL boundary.

The caller must prepare a disposable private Unix-socket PostgreSQL cluster.
This file never starts an engine, imports db/registry, or creates authority.
The legacy class records deliberately stand in for already admitted planner/
capability rows and opaque root heads. They are NOT valid full planner or
witness inputs.
The exact production SQL guards, and the production canonical/digest functions,
run against a real engine; data/root/publication rollback is observed directly.
Pure radix calculation and signature admission have separate test boundaries.

The separate retention class installs the actual v9 custody schema and guards
inside a rollback-owned namespace. Its small opaque byte strings are structural
storage inputs, not signed plans. Deferred constraints are forced explicitly;
these cases do not claim top-level commit, role/ACL or replay verification.

The separate v4 integrity-binding class starts with genuinely signed/proved
fixture bytes and actual Python raw replay under synthetic independent pins.
Its SQL checks bind stored bytes and commitments only, not signatures, current
roots/time, execution or public activation. Its schemas are rollback-owned.

The counted-transition component adds actual counted-store guards and genuine
SQL maintenance between them. Primary live-root locking, business writes and
full executor admission remain preceding caller responsibilities, not proofs
supplied by this component fixture.
"""
from __future__ import annotations

import argparse
import ast
import base64
import copy
from contextlib import contextmanager
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
from serverware import authority_query_read_work as query_work
from serverware import authority_revocation_retention as retained_record
from serverware.authority_store.primary_tree_sql import canonical_json_function_sql, framed_digest_function_sql
from serverware.authority_store.counted_store_sql import counted_store_ddl
from serverware.authority_store.counted_hash_sql import counted_hash_functions_sql
from serverware.authority_store.counted_projection_sql import counted_projection_functions_sql
from serverware.authority_store.counted_path_sql import counted_path_functions_sql
from serverware.authority_store.counted_maintenance_sql import counted_maintenance_functions_sql
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
from serverware.authority_store.revocation_retained_sql import (
    load_revocation_retained_sql,
    revocation_retained_declarations_sql,
)
from serverware.authority_store.revocation_counted_sql import (
    revocation_counted_declarations_sql,
    prepare_revocation_counted_transition_sql,
    lock_and_assert_revocation_counted_before_sql,
    assert_revocation_counted_after_sql,
)
from serverware.authority_store.v9_schema_source import (
    authority_v9_schema_source,
    capability_retention_guard_sql,
    planner_retention_guard_sql,
)
from serverware.authority_store.metadata_schema_source import metadata_base_schema_source
from test_webauthn_trust_projection_postgres import local_connection_parameters
import test_authority_revocation_plan as revocation_oracle
import test_authority_revocation_retention as retained_oracle
import test_authority_revocation_persistence as persistence_oracle
import test_authority_counted_store_postgres as counted_store_oracle
import test_authority_index_join as counted_profile_oracle
import test_authority_index_range as counted_tree_oracle
import test_authority_indexed_mutation as counted_mutation_oracle


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
    "plan_protocol": "text", "retained_record_digest": "text",
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


def production_retained_immutable_sql(
        table="policy_authority_revocation_retained_plans") -> tuple[str, str]:
    """Extract the real immutable function and attachment, without db imports."""
    if type(table) is not str or table not in {
            "policy_authority_revocation_retained_plans",
            "policy_authority_revocation_retained_capabilities",
            "policy_authority_webauthn_assertion_evidence",
            "policy_authority_authorization_projections"}:
        raise ValueError("custody fixture immutable target is not source-fixed")
    path = ROOT / "serverware/db.py"
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("database source exceeds component fixture bound")
    source = path.read_text(encoding="utf-8")
    inventory_start = source.index("_POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES = (\n")
    inventory_end = source.index("\n)\n", inventory_start) + 2
    declaration = ast.parse(source[inventory_start:inventory_end]).body
    if (len(declaration) != 1 or not isinstance(declaration[0], ast.Assign)
            or ast.literal_eval(declaration[0].value).count(table) != 1):
        raise ValueError("custody table is not in the actual immutable inventory")
    marker = ('        conn.execute(\n            """\n'
              '            CREATE OR REPLACE FUNCTION serverware_reject_policy_authority_mutation()')
    start = source.index(marker)
    end = source.index('            """\n        )', start) + len('            """\n        )')
    function = ast.parse(textwrap.dedent(source[start:end])).body[0].value
    loop = source.index("        for table in _POLICY_CANDIDATE_AUTHORITY_IMMUTABLE_TABLES:")
    start = source.index("            conn.execute(\n", loop)
    end = source.index("\n            )", start) + len("\n            )")
    attachment = ast.parse(textwrap.dedent(source[start:end])).body[0].value
    for call in (function, attachment):
        if (not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute)
                or not isinstance(call.func.value, ast.Name) or call.func.value.id != "conn"
                or call.func.attr != "execute" or len(call.args) != 1 or call.keywords):
            raise ValueError("immutable guard SQL literal boundary changed")
    if not isinstance(function.args[0], ast.Constant) or type(function.args[0].value) is not str:
        raise ValueError("immutable guard function is not the actual static SQL")
    if not isinstance(attachment.args[0], ast.JoinedStr):
        raise ValueError("immutable guard attachment is not the actual source template")
    bindings = {"table": table,
                "trigger": "fixture_retained_immutable"}
    fragments = []
    for fragment in attachment.args[0].values:
        if isinstance(fragment, ast.Constant) and type(fragment.value) is str:
            fragments.append(fragment.value)
        elif (isinstance(fragment, ast.FormattedValue) and isinstance(fragment.value, ast.Name)
                and fragment.value.id in bindings and fragment.conversion == -1
                and fragment.format_spec is None):
            fragments.append(bindings[fragment.value.id])
        else:
            raise ValueError("immutable guard attachment interpolation changed")
    return function.args[0].value, "".join(fragments)


def production_writer_capability_table_sql() -> str:
    """Use the exact base-table DDL needed by the v9 custody extension.

    The native component does not install the unrelated application tables or
    rewrite column definitions. The original base producer remains authoritative.
    """
    source = metadata_base_schema_source()
    marker = "CREATE TABLE IF NOT EXISTS\n                policy_authority_writer_capabilities ("
    if source.count(marker) != 1:
        raise ValueError("writer-capability base table is not a unique source declaration")
    start = source.index(marker)
    return source[start:source.index(";", start) + 1]


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
                    "planner_attestation_receipt_digest": payload["plannerIdentity"]["attestationReceiptDigest"],
                    "plan_protocol": "v3", "retained_record_digest": None})
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
            connection.execute(framed_digest_function_sql(cls.namespace))
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
        # CredentialBinding/v1 is a different, historical length-domain
        # protocol. Both service and SQL consumers must preserve it; accepting
        # either recipe would hide a producer/consumer compatibility defect.
        credential = {"id": "credential-雪", "credential_id": "credential-id", "user_id": "user-é",
            "public_key_cose": "e30", "sign_count": 7, "aaguid": None,
            "authenticator_class": "hardware", "attestation_trusted": 1,
            "attestation_leaf_sha256": None, "attestation_root_sha256": None,
            "attestation_trust_bundle_digest": token("trust"),
            "attestation_trust_bundle_sequence": 3, "revoked_at": None}
        domain = "serverware.policyAuthorityWebAuthnCredentialBinding/v1"
        encoded_domain, encoded_row = domain.encode("ascii"), canonical(credential)
        expected = "sha256:" + hashlib.sha256(len(encoded_domain).to_bytes(8, "big") + encoded_domain
            + len(encoded_row).to_bytes(8, "big") + encoded_row).hexdigest()
        self.assertNotEqual(expected, digest(domain, encoded_row))
        with self.connection() as connection:
            actual = connection.execute(f"SELECT {self.namespace}.serverware_policy_authority_framed_digest("
                f"%s, {self.namespace}.serverware_policy_authority_wire_json(%s::jsonb))",
                (domain, Jsonb(credential))).fetchone()
        self.assertEqual(actual, (expected,))
        for path, helper in (("serverware/authority_service.py", "_framed_digest"),
                             ("serverware/authority_store/executor_v9.py", "serverware_policy_authority_framed_digest"),
                             ("serverware/db.py", "serverware_policy_authority_framed_digest")):
            source_path = ROOT / path
            self.assertLessEqual(source_path.stat().st_size, 16 * 1024 * 1024)
            source = source_path.read_text(encoding="utf-8")
            self.assertRegex(source, re.escape(helper) + r"\(\s*['\"]" + re.escape(domain) + r"['\"]")
            self.assertNotRegex(source, r"(?:_domain_digest|serverware_policy_authority_domain_digest)\(\s*['\"]"
                + re.escape(domain) + r"['\"]")

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
        # The real legacy SQL must reject the lifecycle protocol before even
        # attempting its byte decoder; these records deliberately bypass the
        # separate table constraints to exercise the consumer guard itself.
        original_planner = copy.deepcopy(self.planner)
        for protocol, retained in (("revocation-v4", token("retained")),
                                   ("revocation-v4", None), ("unknown", None),
                                   (None, None), ("v3", token("retained"))):
            with self.subTest(protocol=protocol, retained=retained):
                self.planner = {**original_planner, "plan_protocol": protocol,
                                "retained_record_digest": retained,
                                "exact_plan_base64url": "not/base64"}
                self.store()
                self.reject("requires legacy v3 protocol")
        self.planner = original_planner
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
        original_planner = copy.deepcopy(self.planner)
        for protocol, retained in (("revocation-v4", token("retained")),
                                   ("revocation-v4", None), (None, None),
                                   ("v3", token("retained"))):
            with self.subTest(protocol=protocol, retained=retained):
                self.planner = {**original_planner, "plan_protocol": protocol,
                                "retained_record_digest": retained,
                                "exact_plan_base64url": "not/base64"}
                self.store(receipt)
                self.reject("requires legacy v3 protocol", replay=True)
        self.planner = original_planner
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
        loaded = load_root_transition_sql('"fixture"')
        protocol_guard = loaded.index("IF planner.plan_protocol IS DISTINCT FROM 'v3'")
        self.assertIn("OR planner.retained_record_digest IS NOT NULL", loaded)
        self.assertLess(protocol_guard, loaded.index("IF planner.exact_plan_base64url IS NULL"))
        self.assertLess(protocol_guard, loaded.index("rt_plan_bytes := pg_catalog.decode("))
        self.assertLess(protocol_guard, loaded.index("rt_payload_json := rt_plan_text::pg_catalog.json"))


class AuthorityRevocationRetentionPostgresTests(unittest.TestCase):
    """Real structural custody, not cryptographic admission or role authority."""

    PARENT = "policy_authority_planner_transactions"
    CHILD = "policy_authority_revocation_retained_plans"
    ASSERTION = "policy_authority_webauthn_assertion_evidence"
    PROJECTION = "policy_authority_authorization_projections"
    RESERVATION = (
        "planner_transaction_id", "plan_protocol", "operation", "operation_id", "request_digest",
        "capability_id", "operation_contract_digest", "query_manifest_digest",
        "selected_business_rows_json", "selected_business_rows_digest", "mutation_plan_json",
        "mutation_plan_digest", "work_units", "authority_root_set_before_digest",
        "planner_session_identity_digest", "planner_measurement_digest",
        "planner_attestation_receipt_digest", "deadline_monotonic_ns", "deadline_epoch_ns",
        "fence", "reserved_at_epoch_ns", "source_revision",
    )
    PAYLOAD = (
        "authorization_projection_digest", "authority_snapshot_digest", "exact_plan_base64url",
        "exact_plan_bytes_digest", "exact_plan_byte_count", "planned_at_epoch_ns", "retained_record_digest",
    )
    TERMINAL = (
        "status", "exact_response_base64url", "exact_response_bytes_digest", "exact_response_byte_count",
        "terminal_receipt_json", "terminal_receipt_digest", "terminal_at_epoch_ns",
    )

    def setUp(self):
        self.connection = AuthorityRootTransitionPostgresTests.connection()
        self.addCleanup(self.connection.close)
        self.assertEqual(self.connection.execute("SELECT inet_server_addr()").fetchone(), (None,))
        self.schema = "serverware_retained_" + uuid.uuid4().hex
        self.namespace = '"' + self.schema + '"'
        self.connection.execute("BEGIN ISOLATION LEVEL SERIALIZABLE")
        self.addCleanup(self.rollback_owned_schema)
        # Plain CREATE refuses a collision. No production namespace or SQL
        # rewriting is involved; even the fixture DDL is rolled back at cleanup.
        self.connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.connection.execute(sql.SQL("SET LOCAL search_path TO {}, pg_catalog").format(
            sql.Identifier(self.schema)))
        self.connection.execute(production_writer_capability_table_sql())
        self.connection.execute(authority_v9_schema_source())
        self.connection.execute(planner_retention_guard_sql(self.namespace))
        for table in (self.CHILD, self.ASSERTION, self.PROJECTION):
            for statement in production_retained_immutable_sql(table):
                self.connection.execute(statement)

    def rollback_owned_schema(self):
        self.connection.rollback()
        self.assertEqual(self.connection.execute(
            "SELECT pg_catalog.to_regnamespace(%s)", (self.schema,)).fetchone(), (None,))

    def rows(self, table):
        key = "assertion_evidence_digest" if table == self.ASSERTION else "planner_transaction_id"
        return tuple(row[0] for row in self.connection.execute(sql.SQL(
            'SELECT pg_catalog.to_jsonb(t) FROM {} AS t '
            'ORDER BY {} COLLATE "C"').format(
                sql.Identifier(self.schema, table), sql.Identifier(key))).fetchall())

    def snapshot(self):
        return self.rows(self.PARENT), self.rows(self.CHILD)

    def custody_snapshot(self):
        return (*self.snapshot(), self.rows(self.ASSERTION), self.rows(self.PROJECTION))

    def authorization_rows(self, label="one"):
        """Independent complete DDL rows, not valid cryptographic receipts."""
        parent, _, _ = self.records(label)
        evidence = {
            "assertion_evidence_digest": token("assertion-" + label),
            "operation": parent["operation"], "operation_id": parent["operation_id"],
            "request_digest": parent["request_digest"], "capability_id": parent["capability_id"],
            "challenge_id": "challenge-" + label, "challenge_digest": token("challenge-" + label),
            "client_challenge_digest": token("client-challenge-" + label),
            "credential_record_id": "credential-record-" + label, "credential_id": "credential-" + label,
            "credential_policy_digest": token("credential-policy"),
            "authenticator_data_base64url": "eA", "authenticator_data_digest": token("authenticator"),
            "client_data_json_base64url": "e30", "client_data_json_digest": token("client-data"),
            "signature_base64url": "eA", "signature_digest": token("signature"),
            "rp_id": "fixture.invalid", "rp_id_hash_digest": token("rp-id"),
            "origin": "https://fixture.invalid", "flags": 5, "user_present": 1,
            "user_verified": 1, "prior_counter": 0, "counter": 1,
            "trust_high_water_digest": token("trust-water"), "metadata_publication_sequence": 1,
            "verifier_session_identity_digest": token("verifier-session"),
            "verifier_measurement_digest": token("verifier-measurement"),
            "verifier_attestation_receipt_digest": token("verifier-attestation"),
            "verified_assertion_receipt_digest": token("receipt-" + label),
            "evidence_json": "{}", "verified_at_epoch_ns": 1000, "expires_at_epoch_ns": 2000,
            "source_revision": authority_contract.SOURCE_REVISION,
        }
        projection = {
            "authorization_projection_digest": token("projection-" + label),
            "planner_transaction_id": parent["planner_transaction_id"],
            "operation": parent["operation"], "operation_id": parent["operation_id"],
            "request_digest": parent["request_digest"], "capability_id": parent["capability_id"],
            "operation_contract_digest": parent["operation_contract_digest"],
            "authorization_reads_json": "[]", "authorization_reads_digest": token("reads"),
            "source_rows_json": "[]", "source_rows_digest": token("source-rows"),
            "source_high_water_digest": token("source-water"), "approver_policy_digest": None,
            "assertion_evidence_digest": evidence["assertion_evidence_digest"],
            "projection_json": "{}", "verifier_session_identity_digest": token("verifier-session"),
            "verifier_measurement_digest": token("verifier-measurement"),
            "verifier_attestation_receipt_digest": token("verifier-attestation"),
            "created_at_epoch_ns": 1000, "expires_at_epoch_ns": 2000,
            "source_revision": authority_contract.SOURCE_REVISION,
        }
        self.assertEqual((len(evidence), len(projection)), (35, 21))
        return evidence, projection

    def unique_constraint(self, table, columns):
        # PostgreSQL may truncate generated compound constraint names. Bind
        # the actual name to independent exact column order, not a guessed name.
        rows = self.connection.execute(
            "SELECT constraint_record.conname, ARRAY("
            "SELECT attribute.attname::text FROM pg_catalog.unnest(constraint_record.conkey) "
            "WITH ORDINALITY AS key_column(attnum, ordinal) "
            "JOIN pg_catalog.pg_attribute AS attribute "
            "ON attribute.attrelid = constraint_record.conrelid AND attribute.attnum = key_column.attnum "
            "ORDER BY key_column.ordinal) FROM pg_catalog.pg_constraint AS constraint_record "
            "WHERE constraint_record.conrelid = %s::regclass "
            "AND constraint_record.contype IN ('p', 'u')",
            (self.namespace + "." + table,)).fetchall()
        matching = [name for name, actual in rows if actual == list(columns)]
        self.assertEqual(len(matching), 1)
        return matching[0]

    def insert(self, table, row):
        self.connection.execute(sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
            sql.Identifier(self.schema, table),
            sql.SQL(", ").join(sql.Identifier(name) for name in row),
            sql.SQL(", ").join(sql.Placeholder() for _ in row)), tuple(row.values()))

    def update(self, table, transaction_id, values):
        self.connection.execute(sql.SQL("UPDATE {} SET {} WHERE planner_transaction_id = %s").format(
            sql.Identifier(self.schema, table),
            sql.SQL(", ").join(sql.SQL("{} = %s").format(sql.Identifier(name)) for name in values)),
            (*values.values(), transaction_id))

    def records(self, label="one"):
        """Independent full rows; opaque bytes explicitly are not signed plans."""
        payload = b'{"opaque":"payload"}'
        envelope = b'{"opaque":"original-envelope"}'
        context = b'{"opaque":"original-context"}'
        raw_digest = lambda value: "sha256:" + hashlib.sha256(value).hexdigest()
        encoded = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        parent = {
            "planner_transaction_id": "transaction-" + label, "plan_protocol": "revocation-v4",
            "retained_record_digest": None, "operation": "webauthn.credential.revoke",
            "operation_id": "operation-" + label, "request_digest": token("request-" + label),
            "capability_id": "capability-" + label, "operation_contract_digest": token("operation-contract"),
            "query_manifest_digest": token("query-manifest"), "selected_business_rows_json": "[]",
            "selected_business_rows_digest": raw_digest(b"[]"), "mutation_plan_json": "[]",
            "mutation_plan_digest": raw_digest(b"[]"), "work_units": 1,
            "authority_root_set_before_digest": token("before-roots"),
            "authorization_projection_digest": None, "authority_snapshot_digest": None,
            "planner_session_identity_digest": token("session"), "planner_measurement_digest": token("measurement"),
            "planner_attestation_receipt_digest": token("attestation"), "deadline_monotonic_ns": 200,
            "deadline_epoch_ns": 2000, "fence": 1, "status": "reserved",
            "exact_plan_base64url": None, "exact_plan_bytes_digest": None, "exact_plan_byte_count": None,
            "exact_response_base64url": None, "exact_response_bytes_digest": None,
            "exact_response_byte_count": None, "terminal_receipt_json": None,
            "terminal_receipt_digest": None, "reserved_at_epoch_ns": 1000,
            "planned_at_epoch_ns": None, "terminal_at_epoch_ns": None,
            "source_revision": authority_contract.SOURCE_REVISION,
        }
        planned = {
            **parent, "status": "planned", "retained_record_digest": token("record-" + label),
            "authorization_projection_digest": token("projection"), "authority_snapshot_digest": token("snapshot"),
            "exact_plan_base64url": encoded(payload), "exact_plan_bytes_digest": raw_digest(payload),
            "exact_plan_byte_count": len(payload), "planned_at_epoch_ns": 1100,
        }
        child = {
            "planner_transaction_id": parent["planner_transaction_id"], "plan_protocol": "revocation-v4",
            "exact_envelope_base64url": encoded(envelope), "exact_envelope_bytes_digest": raw_digest(envelope),
            "exact_envelope_byte_count": len(envelope), "evaluation_context_base64url": encoded(context),
            "evaluation_context_bytes_digest": raw_digest(context), "evaluation_context_byte_count": len(context),
            "planner_key_digest": token("planner-key"), "verifier_key_digest": token("verifier-key"),
            "retained_record_digest": planned["retained_record_digest"],
            "source_revision": authority_contract.SOURCE_REVISION,
        }
        return parent, planned, child

    def complete_pair(self, label="one"):
        parent, planned, child = self.records(label)
        self.connection.execute("SET CONSTRAINTS ALL DEFERRED")
        self.insert(self.PARENT, parent)
        self.insert(self.CHILD, child)
        self.update(self.PARENT, parent["planner_transaction_id"],
                    {name: planned[name] for name in (*self.PAYLOAD, "status")})
        self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
        return planned, child

    @staticmethod
    def changed(value):
        if type(value) is int:
            return value + 1
        return "changed" if value is None else value + "-changed"

    @staticmethod
    def terminal(parent, status):
        value = {**parent, "status": status, "exact_response_base64url": "e30",
                 "exact_response_bytes_digest": token("response"), "exact_response_byte_count": 2,
                 "terminal_at_epoch_ns": 1200}
        if status == "consumed":
            value.update(terminal_receipt_json="{}", terminal_receipt_digest=token("terminal"))
        return value

    def test_deferred_cycle_accepts_original_sidecar_before_parent_completion(self):
        constraints = self.connection.execute(
            "SELECT conname, condeferrable, condeferred, confupdtype, confdeltype "
            "FROM pg_catalog.pg_constraint WHERE conrelid IN (%s::regclass, %s::regclass) "
            "AND contype = 'f' ORDER BY conname",
            (self.namespace + "." + self.PARENT, self.namespace + "." + self.CHILD)).fetchall()
        self.assertEqual(constraints, [
            ("serverware_planner_retained_record_fk", True, True, "a", "a"),
            ("serverware_revocation_retained_parent_fk", True, True, "a", "a"),
        ])
        reserved, planned, child = self.records()
        self.insert(self.PARENT, reserved)
        self.insert(self.CHILD, child)
        self.assertEqual(self.snapshot(), ((reserved,), (child,)))
        self.update(self.PARENT, reserved["planner_transaction_id"],
                    {name: planned[name] for name in (*self.PAYLOAD, "status")})
        self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
        self.assertEqual(self.snapshot(), ((planned,), (child,)))
        self.assertNotEqual(planned["exact_plan_base64url"], child["exact_envelope_base64url"])
        # The reverse ordering is legal only when both references close before
        # the explicit boundary. No row is committed by this fixture.
        _, second, second_child = self.records("two")
        self.connection.execute("SET CONSTRAINTS ALL DEFERRED")
        self.insert(self.PARENT, second)
        self.insert(self.CHILD, second_child)
        self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
        self.assertEqual(self.snapshot(), ((planned, second), (child, second_child)))

    def test_incomplete_or_mismatched_pairs_roll_back_at_deferred_boundary(self):
        all_names = {"serverware_planner_retained_record_fk", "serverware_revocation_retained_parent_fk"}
        for case, names in (
                ("parent-only", {"serverware_planner_retained_record_fk"}),
                ("child-only", {"serverware_revocation_retained_parent_fk"}),
                ("reserved-parent", {"serverware_revocation_retained_parent_fk"}),
                ("wrong-digest", all_names), ("wrong-id", all_names),
                ("legacy-parent", {"serverware_revocation_retained_parent_fk"})):
            with self.subTest(case=case):
                reserved, planned, child = self.records(case)
                with self.assertRaises(psycopg.errors.ForeignKeyViolation) as caught:
                    with self.connection.transaction():
                        self.connection.execute("SET CONSTRAINTS ALL DEFERRED")
                        if case != "child-only":
                            parent = reserved if case in ("reserved-parent", "legacy-parent") else planned
                            if case == "legacy-parent":
                                parent = {**parent, "plan_protocol": "v3"}
                            self.insert(self.PARENT, parent)
                        if case != "parent-only":
                            if case == "wrong-digest":
                                child = {**child, "retained_record_digest": token("other-record")}
                            if case == "wrong-id":
                                child = {**child, "planner_transaction_id": "other-transaction"}
                            self.insert(self.CHILD, child)
                        self.assertEqual(len(self.rows(self.PARENT)), int(case != "child-only"))
                        self.assertEqual(len(self.rows(self.CHILD)), int(case != "parent-only"))
                        self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
                self.assertEqual(caught.exception.sqlstate, "23503")
                self.assertIn(caught.exception.diag.constraint_name, names)
                self.assertEqual(self.snapshot(), ((), ()))

    def test_parent_protocol_status_and_sidecar_shapes_are_closed(self):
        reserved, planned, child = self.records()
        legacy = {**reserved, "planner_transaction_id": "legacy", "capability_id": "legacy-capability"}
        del legacy["plan_protocol"]
        self.insert(self.PARENT, legacy)
        self.assertEqual(self.rows(self.PARENT)[0], {**legacy, "plan_protocol": "v3"})
        baseline = self.snapshot()
        bad_parents = (
            {**reserved, "plan_protocol": "future"},
            {**reserved, "plan_protocol": "v3", "retained_record_digest": token("unexpected")},
            {**reserved, "operation": "webauthn.counter.cas"},
            {**reserved, "status": "planned"},
            {**planned, "retained_record_digest": None},
            {**planned, "exact_plan_byte_count": None},
            {**planned, "status": "reserved"},
            {**planned, "status": "consumed"},
            {**reserved, "status": "failed"},
            {**self.terminal(reserved, "failed"), "exact_plan_base64url": "e30"},
        )
        for index, value in enumerate(bad_parents):
            with self.subTest(parent=index), self.assertRaises(psycopg.errors.CheckViolation) as caught:
                with self.connection.transaction():
                    self.insert(self.PARENT, value)
            self.assertEqual(caught.exception.sqlstate, "23514")
            self.assertEqual(self.snapshot(), baseline)
        with self.assertRaises(psycopg.errors.NotNullViolation) as caught:
            with self.connection.transaction():
                self.insert(self.PARENT, {**reserved, "plan_protocol": None})
        self.assertEqual((caught.exception.sqlstate, caught.exception.diag.column_name), ("23502", "plan_protocol"))
        for name, value in (
                ("plan_protocol", "v3"), ("source_revision", "old"),
                ("exact_envelope_byte_count", 1), ("evaluation_context_byte_count", 524289),
                ("exact_envelope_base64url", child["exact_envelope_base64url"] + "="),
                ("evaluation_context_base64url", "!" * len(child["evaluation_context_base64url"])),
                ("planner_key_digest", "not-a-digest"), ("retained_record_digest", "sha256:" + "A" * 64)):
            with self.subTest(child=name), self.assertRaises(psycopg.errors.CheckViolation) as caught:
                with self.connection.transaction():
                    self.insert(self.CHILD, {**child, name: value})
            self.assertEqual(caught.exception.sqlstate, "23514")
            self.assertEqual(self.snapshot(), baseline)

    def test_sidecar_update_delete_and_duplicate_insert_preserve_original(self):
        planned, child = self.complete_pair()
        baseline = self.snapshot()
        for name in child:
            with self.subTest(column=name), self.assertRaisesRegex(
                    psycopg.errors.RaiseException, "candidate-authority history is immutable") as caught:
                with self.connection.transaction():
                    self.update(self.CHILD, child["planner_transaction_id"], {name: self.changed(child[name])})
            self.assertEqual(caught.exception.sqlstate, "P0001")
            self.assertEqual(self.snapshot(), baseline)
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "history is immutable"):
            with self.connection.transaction():
                self.update(self.CHILD, child["planner_transaction_id"], child)
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "history is immutable") as caught:
            with self.connection.transaction():
                self.connection.execute(sql.SQL("DELETE FROM {} WHERE planner_transaction_id = %s").format(
                    sql.Identifier(self.schema, self.CHILD)), (child["planner_transaction_id"],))
        self.assertEqual(caught.exception.sqlstate, "P0001")
        with self.assertRaises(psycopg.errors.UniqueViolation) as caught:
            with self.connection.transaction():
                self.insert(self.CHILD, child)
        self.assertEqual(caught.exception.sqlstate, "23505")
        self.assertEqual(caught.exception.diag.constraint_name, self.CHILD + "_pkey")
        with self.assertRaises(psycopg.errors.ForeignKeyViolation) as caught:
            with self.connection.transaction():
                self.connection.execute(sql.SQL("DELETE FROM {} WHERE planner_transaction_id = %s").format(
                    sql.Identifier(self.schema, self.PARENT)), (planned["planner_transaction_id"],))
        self.assertEqual(caught.exception.diag.constraint_name, "serverware_revocation_retained_parent_fk")
        self.assertEqual(self.snapshot(), baseline)

    def test_planned_parent_reservation_and_payload_fields_are_immutable(self):
        planned, _ = self.complete_pair()
        baseline = self.snapshot()
        self.assertEqual(len(self.RESERVATION), 22)
        self.assertEqual(len(self.PAYLOAD), 7)
        for name in (*self.RESERVATION, *self.PAYLOAD):
            with self.subTest(column=name), self.assertRaisesRegex(
                    psycopg.errors.RaiseException, "planner reservation and retained evidence are immutable") as caught:
                with self.connection.transaction():
                    self.update(self.PARENT, planned["planner_transaction_id"], {name: self.changed(planned[name])})
            self.assertEqual(caught.exception.sqlstate, "P0001")
            self.assertEqual(self.snapshot(), baseline)
        # Equality is permitted by the real guard; timestamps and original
        # payload bytes are not silently replaced by retry metadata.
        self.update(self.PARENT, planned["planner_transaction_id"], planned)
        self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
        self.assertEqual(self.snapshot(), baseline)

    def test_reservation_and_terminal_transitions_preserve_pair_custody(self):
        reserved, planned, child = self.records("skip")
        self.insert(self.PARENT, reserved)
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "retained evidence are immutable") as caught:
            with self.connection.transaction():
                consumed = self.terminal(planned, "consumed")
                self.update(self.PARENT, reserved["planner_transaction_id"], consumed)
        self.assertEqual(caught.exception.sqlstate, "P0001")
        self.assertEqual(self.snapshot(), ((reserved,), ()))
        failed = self.terminal(reserved, "failed")
        self.update(self.PARENT, reserved["planner_transaction_id"], failed)
        self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
        self.assertEqual(self.snapshot(), ((failed,), ()))
        terminal_parents = [failed]
        for status in ("consumed", "failed"):
            actual, actual_child = self.complete_pair(status)
            terminal = self.terminal(actual, status)
            self.update(self.PARENT, actual["planner_transaction_id"], terminal)
            self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
            self.assertIn(terminal, self.rows(self.PARENT))
            self.assertIn(actual_child, self.rows(self.CHILD))
            terminal_parents.append(terminal)
        baseline = self.snapshot()
        for terminal in terminal_parents:
            for name in self.TERMINAL:
                with self.subTest(status=terminal["status"], column=name), self.assertRaisesRegex(
                        psycopg.errors.RaiseException, "retained evidence are immutable") as caught:
                    with self.connection.transaction():
                        self.update(self.PARENT, terminal["planner_transaction_id"], {name: self.changed(terminal[name])})
                self.assertEqual(caught.exception.sqlstate, "P0001")
                self.assertEqual(self.snapshot(), baseline)
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "retained evidence are immutable"):
            with self.connection.transaction():
                self.update(self.PARENT, failed["planner_transaction_id"], reserved)
        self.assertEqual(self.snapshot(), baseline)

    def test_assertion_custody_primary_challenge_and_identity_are_unique(self):
        original, _ = self.authorization_rows()
        self.insert(self.ASSERTION, original)
        self.assertEqual(self.rows(self.ASSERTION), (original,))
        baseline = self.custody_snapshot()
        identity = ("operation_id", "request_digest", "capability_id")
        variants = (
            (("assertion_evidence_digest",), {**self.authorization_rows("primary")[0],
                "assertion_evidence_digest": original["assertion_evidence_digest"]}),
            (("challenge_id",), {**self.authorization_rows("challenge")[0],
                "challenge_id": original["challenge_id"]}),
            (identity, {**self.authorization_rows("identity")[0],
                **{name: original[name] for name in identity}}),
        )
        for columns, changed in variants:
            expected_name = self.unique_constraint(self.ASSERTION, columns)
            if len(columns) == 1:
                self.assertEqual(expected_name, self.ASSERTION + (
                    "_pkey" if columns[0] == "assertion_evidence_digest" else "_challenge_id_key"))
            with self.subTest(columns=columns), self.assertRaises(psycopg.errors.UniqueViolation) as caught:
                with self.connection.transaction():
                    self.insert(self.ASSERTION, changed)
            self.assertEqual((caught.exception.sqlstate, caught.exception.diag.constraint_name),
                             ("23505", expected_name))
            self.assertEqual(self.custody_snapshot(), baseline)

    def test_authorization_custody_primary_transaction_and_identity_are_unique(self):
        _, original = self.authorization_rows()
        self.insert(self.PROJECTION, original)
        self.assertEqual(self.rows(self.PROJECTION), (original,))
        # Actual DDL has no custody-chain FK. These rows are not a verified
        # record, and an absent referenced assertion is not database admission.
        foreign_keys = self.connection.execute(
            "SELECT conname FROM pg_catalog.pg_constraint "
            "WHERE conrelid = %s::regclass AND contype = 'f'",
            (self.namespace + "." + self.PROJECTION,)).fetchall()
        self.assertEqual(foreign_keys, [])
        baseline = self.custody_snapshot()
        identity = ("operation_id", "request_digest", "capability_id")
        variants = (
            (("authorization_projection_digest",), {**self.authorization_rows("primary")[1],
                "authorization_projection_digest": original["authorization_projection_digest"]}),
            (("planner_transaction_id",), {**self.authorization_rows("transaction")[1],
                "planner_transaction_id": original["planner_transaction_id"]}),
            (identity, {**self.authorization_rows("identity")[1],
                **{name: original[name] for name in identity}}),
        )
        for columns, changed in variants:
            expected_name = self.unique_constraint(self.PROJECTION, columns)
            if columns == ("authorization_projection_digest",):
                self.assertEqual(expected_name, self.PROJECTION + "_pkey")
            with self.subTest(columns=columns), self.assertRaises(psycopg.errors.UniqueViolation) as caught:
                with self.connection.transaction():
                    self.insert(self.PROJECTION, changed)
            self.assertEqual((caught.exception.sqlstate, caught.exception.diag.constraint_name),
                             ("23505", expected_name))
            self.assertEqual(self.custody_snapshot(), baseline)

    def test_authorization_custody_update_delete_preserve_all_original_columns(self):
        evidence, projection = self.authorization_rows()
        for table, row in ((self.ASSERTION, evidence), (self.PROJECTION, projection)):
            self.insert(table, row)
        baseline = self.custody_snapshot()
        for table, key, row in ((self.ASSERTION, "assertion_evidence_digest", evidence),
                               (self.PROJECTION, "authorization_projection_digest", projection)):
            for name in row:
                with self.subTest(table=table, column=name), self.assertRaisesRegex(
                        psycopg.errors.RaiseException, "candidate-authority history is immutable") as caught:
                    with self.connection.transaction():
                        self.connection.execute(sql.SQL("UPDATE {} SET {} = %s WHERE {} = %s").format(
                            sql.Identifier(self.schema, table), sql.Identifier(name), sql.Identifier(key)),
                            (self.changed(row[name]), row[key]))
                self.assertEqual(caught.exception.sqlstate, "P0001")
                self.assertEqual(self.custody_snapshot(), baseline)
            with self.subTest(table=table, action="equal-update"), self.assertRaisesRegex(
                    psycopg.errors.RaiseException, "candidate-authority history is immutable") as caught:
                with self.connection.transaction():
                    self.connection.execute(sql.SQL("UPDATE {} SET {} = %s WHERE {} = %s").format(
                        sql.Identifier(self.schema, table), sql.Identifier(key), sql.Identifier(key)),
                        (row[key], row[key]))
            self.assertEqual(caught.exception.sqlstate, "P0001")
            with self.subTest(table=table, action="delete"), self.assertRaisesRegex(
                    psycopg.errors.RaiseException, "candidate-authority history is immutable") as caught:
                with self.connection.transaction():
                    self.connection.execute(sql.SQL("DELETE FROM {} WHERE {} = %s").format(
                        sql.Identifier(self.schema, table), sql.Identifier(key)), (row[key],))
            self.assertEqual(caught.exception.sqlstate, "P0001")
            self.assertEqual(self.custody_snapshot(), baseline)

    def test_four_custody_rows_roll_back_on_later_immutable_failure(self):
        def complete(label):
            reserved, planned, child = self.records(label)
            evidence, projection = self.authorization_rows(label)
            planned = {**planned, "authorization_projection_digest": projection["authorization_projection_digest"]}
            self.connection.execute("SET CONSTRAINTS ALL DEFERRED")
            self.insert(self.PARENT, reserved)
            self.insert(self.ASSERTION, evidence)
            self.insert(self.PROJECTION, projection)
            self.insert(self.CHILD, child)
            self.update(self.PARENT, reserved["planner_transaction_id"],
                        {name: planned[name] for name in (*self.PAYLOAD, "status")})
            self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
            return planned, child, evidence, projection

        prior = complete("prior")
        baseline = self.custody_snapshot()
        self.assertEqual(baseline, tuple((row,) for row in prior))
        with self.assertRaisesRegex(psycopg.errors.RaiseException,
                "candidate-authority history is immutable") as caught:
            with self.connection.transaction():
                current = complete("current")
                actual = self.custody_snapshot()
                self.assertEqual(tuple(map(len, actual)), (2, 2, 2, 2))
                for rows, row in zip(actual, current):
                    self.assertIn(row, rows)
                self.connection.execute(sql.SQL("UPDATE {} SET evidence_json = %s "
                    "WHERE assertion_evidence_digest = %s").format(
                        sql.Identifier(self.schema, self.ASSERTION)),
                    ('{"changed":true}', current[2]["assertion_evidence_digest"]))
        self.assertEqual(caught.exception.sqlstate, "P0001")
        self.assertEqual(self.custody_snapshot(), baseline)
        self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
        self.assertEqual(self.custody_snapshot(), baseline)
        # The outer transaction is still open and rollback-owned. This proves
        # neither top-level commit nor the production verifier/store call path.


class AuthorityRevocationRetainedBindingPostgresTests(unittest.TestCase):
    """Actual retained-byte SQL binding, not signature or execution authority.

    The positive starts with real independently signed/proved v4 fixture bytes,
    also replayed by the genuine Python verifier. SQL only binds their original
    transport, stored identities and commitments. It cannot authenticate a
    replacement signing key, prove current roots, or authorize an operation.
    """

    PARENT = "policy_authority_planner_transactions"
    CHILD = "policy_authority_revocation_retained_plans"

    @classmethod
    def setUpClass(cls):
        cls.fixture = revocation_oracle.PlanFixture(approval=False, include_audit=False)
        cls.envelope_bytes = canonical(cls.fixture.envelope)
        cls.context = retained_oracle.record_context(cls.fixture)
        cls.context_bytes = canonical(cls.context)
        cls.header = retained_oracle.record_header(cls.fixture, cls.envelope_bytes, cls.context_bytes)
        expectations = cls.fixture.arguments()
        expectations.pop("envelope")
        # Real signatures, mixed proofs and kernel replay. This does not turn
        # the independently supplied synthetic pins into production enrollment.
        actual = retained_record._verify_record_on_work(envelope_bytes=cls.envelope_bytes,
            evaluation_context_bytes=cls.context_bytes,
            work=query_work._ValidationWork(query_work.QueryReadValidationLimits()), **expectations)
        if (actual.payload_bytes != canonical(cls.fixture.payload) or actual.header != cls.header
                or actual.record_digest != digest("serverware.policyAuthorityRevocationRetainedPlan/v1",
                                                   canonical(cls.header))):
            raise AssertionError("genuine fixture replay differs from independent retained commitments")

    def setUp(self):
        self.connection = AuthorityRootTransitionPostgresTests.connection()
        self.addCleanup(self.connection.close)
        self.assertEqual(self.connection.execute("SELECT inet_server_addr()").fetchone(), (None,))
        self.schema = "serverware_revocation_binding_" + uuid.uuid4().hex
        self.namespace = '"' + self.schema + '"'
        self.connection.execute("BEGIN ISOLATION LEVEL SERIALIZABLE")
        self.addCleanup(self.rollback_owned_schema)
        self.connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.connection.execute(sql.SQL("SET LOCAL search_path TO {}, pg_catalog").format(sql.Identifier(self.schema)))
        self.connection.execute(production_writer_capability_table_sql())
        self.connection.execute(authority_v9_schema_source())
        self.connection.execute(planner_retention_guard_sql(self.namespace))
        for statement in production_digest_functions(self.namespace):
            self.connection.execute(statement)
        self.connection.execute(wire_json_function_sql(self.namespace))
        self.connection.execute(f"""
            CREATE FUNCTION {self.namespace}.retained_component(planner_id text)
            RETURNS TABLE(payload jsonb, measured_plan jsonb, evaluation_context jsonb,
                mixed_transition jsonb, primary_transition jsonb, record_digest text,
                snapshot_digest text, payload_bytes bytea, envelope_bytes bytea, context_bytes bytea)
            LANGUAGE plpgsql SET search_path = pg_catalog AS $retained_component$
            DECLARE
                planner {self.namespace}.policy_authority_planner_transactions%ROWTYPE;
                {revocation_retained_declarations_sql()}
            BEGIN
                SELECT * INTO STRICT planner FROM {self.namespace}.policy_authority_planner_transactions
                    WHERE planner_transaction_id = planner_id FOR UPDATE;
                {load_revocation_retained_sql(self.namespace)}
                RETURN QUERY SELECT rv_payload, rv_plan, rv_context, rv_transition, rv_primary,
                    rv_record_digest, rv_snapshot_digest, rv_payload_bytes, rv_envelope_bytes, rv_context_bytes;
            END;
            $retained_component$;
            CREATE FUNCTION {self.namespace}.legacy_component(planner_id text)
            RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog AS $legacy_component$
            DECLARE
                planner {self.namespace}.policy_authority_planner_transactions%ROWTYPE;
                capability record;
                {root_transition_declarations_sql()}
            BEGIN
                SELECT * INTO STRICT planner FROM {self.namespace}.policy_authority_planner_transactions
                    WHERE planner_transaction_id = planner_id FOR UPDATE;
                {load_root_transition_sql(self.namespace)}
            END;
            $legacy_component$;
        """)

    def rollback_owned_schema(self):
        self.connection.rollback()
        self.assertEqual(self.connection.execute("SELECT pg_catalog.to_regnamespace(%s)",
            (self.schema,)).fetchone(), (None,))

    def records(self):
        parent, child = persistence_oracle.expected_rows(self.fixture, self.fixture.now_epoch_ns)
        parent.update(exact_response_base64url=None, exact_response_bytes_digest=None,
            exact_response_byte_count=None, terminal_receipt_json=None, terminal_receipt_digest=None,
            terminal_at_epoch_ns=None)
        self.assertEqual((len(parent), len(child)), (36, 12))
        return parent, child

    def reanchor(self, parent, child, *, envelope=None, context=None, payload=None):
        # Independently refresh only storage byte/header anchors. Deliberately
        # do not repair a changed signature, mixed proof, Snapshot or claim.
        for row, prefix, raw in ((child, "exact_envelope", envelope),
                                  (child, "evaluation_context", context),
                                  (parent, "exact_plan", payload)):
            if raw is not None:
                row[prefix + "_base64url"] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
                row[prefix + "_bytes_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
                row[prefix + "_byte_count"] = len(raw)
        header = {**self.header, "plannerKeyDigest": child["planner_key_digest"],
            "verifierKeyDigest": child["verifier_key_digest"],
            "envelopeDigest": child["exact_envelope_bytes_digest"],
            "envelopeByteCount": child["exact_envelope_byte_count"],
            "contextDigest": child["evaluation_context_bytes_digest"],
            "contextByteCount": child["evaluation_context_byte_count"]}
        parent["retained_record_digest"] = child["retained_record_digest"] = digest(
            "serverware.policyAuthorityRevocationRetainedPlan/v1", canonical(header))

    @contextmanager
    def inserted(self, parent, child):
        # DDL rejection is not silently counted as binder coverage: insertion
        # happens before each assertRaises scope. Rollback keeps cases isolated.
        self.connection.execute("SAVEPOINT retained_binding_case")
        try:
            for table, row in ((self.PARENT, parent), (self.CHILD, child)):
                if row is not None:
                    self.connection.execute(sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                        sql.Identifier(self.schema, table),
                        sql.SQL(", ").join(sql.Identifier(name) for name in row),
                        sql.SQL(", ").join(sql.Placeholder() for _ in row)), tuple(row.values()))
            yield
        finally:
            self.connection.execute("ROLLBACK TO SAVEPOINT retained_binding_case")
            self.connection.execute("RELEASE SAVEPOINT retained_binding_case")

    def bind(self, parent, *, legacy=False):
        function = "legacy_component" if legacy else "retained_component"
        return self.connection.execute(sql.SQL("SELECT * FROM {}(%s)").format(
            sql.Identifier(self.schema, function)), (parent["planner_transaction_id"],)).fetchone()

    def denied(self, parent, child, *, legacy=False, sqlstate="P0001", message=None):
        with self.inserted(parent, child):
            with self.assertRaises(psycopg.Error) as caught:
                self.bind(parent, legacy=legacy)
            self.assertEqual(caught.exception.sqlstate, sqlstate)
            if message is not None:
                self.assertRegex(str(caught.exception), message)

    def payload_case(self, payload):
        parent, child = self.records()
        envelope = {**self.fixture.envelope, "payload": payload}
        self.reanchor(parent, child, envelope=canonical(envelope), payload=canonical(payload))
        return parent, child

    def test_genuine_original_bytes_bind_mixed_transition_and_snapshot_v4(self):
        parent, child = self.records()
        with self.inserted(parent, child):
            self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
            result = self.bind(parent)
            measured = self.fixture.payload["measuredPlan"]
            snapshot = digest("serverware.policyAuthoritySnapshot/v4", *(measured[name].encode("ascii")
                for name in ("operation", "operationId", "requestDigest", "queryManifestDigest",
                    "authorityRootSetBeforeDigest", "authorizationProjectionDigest",
                    "selectedBusinessRowsDigest", "mutationPlanDigest", "rootTransitionDigest")))
            self.assertEqual(result, (self.fixture.payload, measured, self.context,
                self.fixture.payload["rootTransition"], self.fixture.payload["rootTransition"]["primaryTransition"],
                digest("serverware.policyAuthorityRevocationRetainedPlan/v1", canonical(self.header)), snapshot,
                canonical(self.fixture.payload), self.envelope_bytes, self.context_bytes))
            self.assertEqual(snapshot, measured["authoritySnapshotDigest"])
            # The pure binder reads actual custody rows and never mutates them.
            self.assertEqual(self.connection.execute(sql.SQL("SELECT pg_catalog.to_jsonb(p) FROM {} p").format(
                sql.Identifier(self.schema, self.PARENT))).fetchone(), (parent,))
            self.assertEqual(self.connection.execute(sql.SQL("SELECT pg_catalog.to_jsonb(p) FROM {} p").format(
                sql.Identifier(self.schema, self.CHILD))).fetchone(), (child,))

    def test_raw_hashes_and_separate_payload_envelope_context_anchors_are_required(self):
        for target, field in (("parent", "exact_plan_bytes_digest"),
                ("child", "exact_envelope_bytes_digest"), ("child", "evaluation_context_bytes_digest")):
            parent, child = self.records()
            (parent if target == "parent" else child)[field] = token("wrong stored bytes")
            with self.subTest(target=target, field=field):
                self.denied(parent, child, message="bytes changed")
        # The parent DDL keeps payload bytes opaque and permits these inputs;
        # the stricter sidecar CHECKs would reject them before this binder.
        # Exercise the common transport body through the actual parent row.
        for variant in ("alphabet", "padding", "byte_count", "unused_bits"):
            parent, child = self.records()
            if variant == "alphabet":
                parent["exact_plan_base64url"] = "%" + parent["exact_plan_base64url"][1:]
            elif variant == "padding":
                parent["exact_plan_base64url"] += "="
            elif variant == "byte_count":
                parent["exact_plan_byte_count"] += 1
            else:
                raw = canonical(self.fixture.payload)
                if len(raw) % 3 == 0:
                    raw += b" "  # Reach a padding-bit case before JSON admission.
                self.reanchor(parent, child, payload=raw)
                alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                encoded = parent["exact_plan_base64url"]
                last = alphabet.index(encoded[-1])
                self.assertEqual(last % (16 if len(raw) % 3 == 1 else 4), 0)
                parent["exact_plan_base64url"] = encoded[:-1] + alphabet[last + 1]
            with self.subTest(transport=variant):
                self.denied(parent, child, message=("payload bytes changed" if variant == "unused_bits"
                    else "payload transport is invalid"))
        parent, child = self.records()
        self.reanchor(parent, child, payload=b"{}")
        self.denied(parent, child)
        parent, child = self.records()
        self.denied(parent, None, sqlstate="P0002", message="query returned no rows")
        # Independently changed original envelope payload cannot be replaced
        # by the parent's still-valid byte digest or vice versa.
        changed = copy.deepcopy(self.fixture.envelope)
        changed["payload"]["expectedResult"] = {"unrelated": True}
        parent, child = self.records()
        self.reanchor(parent, child, envelope=canonical(changed))
        self.denied(parent, child)

    def test_canonical_raw_aliases_and_duplicate_decoded_keys_are_rejected(self):
        for document in ("envelope", "context", "payload"):
            raw = {"envelope": self.envelope_bytes, "context": self.context_bytes,
                   "payload": canonical(self.fixture.payload)}[document]
            # All variants get fresh byte/hash/header anchors. Only the
            # original lexical spelling differs from admitted canonical wire.
            key = b'"schema":'
            self.assertIn(key, raw)
            aliases = (b" " + raw, raw + b"\n", raw.replace(key, b'"\\u0073chema":', 1),
                b'{"schema":"duplicate",' + raw[1:])
            for alias in aliases:
                parent, child = self.records()
                self.reanchor(parent, child, **{document: alias})
                with self.subTest(document=document, prefix=alias[:24]):
                    self.denied(parent, child)
        # A nested duplicate must be caught before JSONB erases it, even when
        # it has the same decoded value and is outside the top-level key set.
        key = b'"rootRevision":'
        raw = self.envelope_bytes
        self.assertIn(key, raw)
        alias = raw.replace(key, b'"rootRevision":0,"rootRevision":', 1)
        parent, child = self.records()
        self.reanchor(parent, child, envelope=alias)
        self.denied(parent, child)
        for boundary in ("node", "depth"):
            context = copy.deepcopy(self.context)
            excessive = [None] * 4096 if boundary == "node" else None
            if boundary == "depth":
                for _ in range(9):
                    excessive = [excessive]
            context["expectedApproverPolicyDigest"] = excessive
            raw = canonical(context)
            self.assertLessEqual(len(raw), 512 * 1024)
            parent, child = self.records()
            self.reanchor(parent, child, context=raw)
            with self.subTest(context_boundary=boundary):
                self.denied(parent, child, message="authority wire JSON " + boundary + " bound exceeded")

    def test_closed_v4_documents_and_integer_token_types_do_not_use_jsonb_aliases(self):
        for path, action in (((), "extra"), (("measuredPlan",), "extra"),
                (("rootTransition",), "extra"), (("rootTransition", "primaryTransition"), "extra")):
            payload = copy.deepcopy(self.fixture.payload)
            target = payload
            for field in path:
                target = target[field]
            target["foreign"] = None
            with self.subTest(path=path, action=action):
                self.denied(*self.payload_case(payload))
        for document, raw, key, value in (
                ("envelope", self.envelope_bytes, "fence", self.fixture.fence),
                ("context", self.context_bytes, "expectedFence", self.fixture.fence)):
            original = ('"' + key + '":' + str(value)).encode("ascii")
            self.assertIn(original, raw)
            for token_value in (str(value) + ".0", str(value) + "e0", "true", "null"):
                alias = raw.replace(original, ('"' + key + '":' + token_value).encode("ascii"), 1)
                parent, child = self.records()
                self.reanchor(parent, child, **{document: alias})
                message = None
                if document == "envelope":
                    # Keep the parent's exact payload coherent with the
                    # envelope so boolean/null reach the real counter guard,
                    # not merely the envelope-versus-parent equality check.
                    changed_payload = canonical(self.fixture.payload).replace(original,
                        ('"' + key + '":' + token_value).encode("ascii"), 1)
                    self.reanchor(parent, child, payload=changed_payload)
                    if token_value in ("true", "null"):
                        message = "counter type is invalid"
                with self.subTest(document=document, token=token_value):
                    self.denied(parent, child, message=message)
        parent, child = self.records()
        changed = {**self.fixture.envelope, "schema": "serverware.signedPolicyAuthorityMeasuredPlan/v3"}
        self.reanchor(parent, child, envelope=canonical(changed))
        self.denied(parent, child)

    def test_locked_parent_and_original_context_bind_identity_deadline_and_cutoff(self):
        for field, value in (("operation_id", token("foreign operation")),
                ("request_digest", token("foreign request")), ("capability_id", token("foreign capability")),
                ("fence", self.fixture.fence + 1), ("deadline_epoch_ns", self.fixture.deadline_epoch_ns + 1),
                ("planner_measurement_digest", token("foreign planner"))):
            parent, child = self.records()
            parent[field] = value
            with self.subTest(parent=field):
                self.denied(parent, child)
        for field, value in (("expectedCapabilityId", token("foreign capability")),
                ("expectedPlannerTransactionId", token("foreign transaction")),
                ("expectedFence", self.fixture.fence + 1),
                ("deadlineEpochNs", self.fixture.deadline_epoch_ns + 1),
                ("databaseCutoffUs", self.fixture.semantic.cutoff_us + 1)):
            context = {**self.context, field: value}
            parent, child = self.records()
            self.reanchor(parent, child, context=canonical(context))
            with self.subTest(context=field):
                self.denied(parent, child)

    def test_key_digests_and_record_header_are_original_integrity_bindings(self):
        for field in ("planner_key_digest", "verifier_key_digest", "retained_record_digest"):
            parent, child = self.records()
            child[field] = token("different retained " + field)
            if field == "retained_record_digest":
                parent[field] = child[field]
            with self.subTest(field=field):
                self.denied(parent, child)
        # A different valid header domain is not interchangeable, even with
        # coherent parent/sidecar relational digest values.
        parent, child = self.records()
        parent["retained_record_digest"] = child["retained_record_digest"] = digest(
            "serverware.policyAuthorityRevocationRetainedPlan/v0", canonical(self.header))
        self.denied(parent, child)

    def test_mixed_transition_and_nine_snapshot_frames_keep_their_v4_domains(self):
        payload = copy.deepcopy(self.fixture.payload)
        payload["rootTransition"]["proofBundleDigest"] = token("wrong proof bundle")
        self.denied(*self.payload_case(payload))
        payload = copy.deepcopy(self.fixture.payload)
        payload["rootTransition"]["primaryTransition"]["businessAfterRoots"][0]["rootRevision"] += 1
        self.denied(*self.payload_case(payload))
        fields = ("operation", "operationId", "requestDigest", "queryManifestDigest",
            "authorityRootSetBeforeDigest", "authorizationProjectionDigest",
            "selectedBusinessRowsDigest", "mutationPlanDigest", "rootTransitionDigest")
        for domain, count in (("serverware.policyAuthoritySnapshot/v3", 9),
                               ("serverware.policyAuthoritySnapshot/v4", 8)):
            payload = copy.deepcopy(self.fixture.payload)
            measured = payload["measuredPlan"]
            measured["authoritySnapshotDigest"] = digest(domain,
                *(measured[name].encode("ascii") for name in fields[:count]))
            parent, child = self.payload_case(payload)
            parent["authority_snapshot_digest"] = measured["authoritySnapshotDigest"]
            with self.subTest(domain=domain, count=count):
                self.denied(parent, child)
        # The legacy variadic helper's ninth-frame exception is still v3-only.
        with self.assertRaises(psycopg.Error) as caught:
            with self.connection.transaction():
                self.connection.execute(sql.SQL("SELECT {}(%s, VARIADIC %s::text[])").format(
                    sql.Identifier(self.schema, "serverware_policy_authority_domain_digest")),
                    ("serverware.policyAuthoritySnapshot/v4", ["x"] * 9))
        self.assertEqual(caught.exception.sqlstate, "P0001")
        self.assertRegex(str(caught.exception), "digest framing is outside its fixed bound")

    def test_integrity_binding_never_authenticates_signature_or_opens_legacy_v3(self):
        parent, child = self.records()
        self.denied(parent, child, legacy=True, message="requires legacy v3 protocol")
        envelope = {**self.fixture.envelope,
            "signatureBase64Url": base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")}
        raw = canonical(envelope)
        self.reanchor(parent, child, envelope=raw)
        with self.inserted(parent, child):
            result = self.bind(parent)
            self.assertEqual(result[8], raw)
        expectations = self.fixture.arguments()
        expectations.pop("envelope")
        with self.assertRaises(retained_record.RevocationRetentionError):
            retained_record._verify_record_on_work(envelope_bytes=raw,
                evaluation_context_bytes=self.context_bytes,
                work=query_work._ValidationWork(query_work.QueryReadValidationLimits()), **expectations)
        # No SQL proof/signature success token is passed into that verifier;
        # false cryptographic authority remains false after integrity binding.


class AuthorityRevocationCountedTransitionPostgresTests(unittest.TestCase):
    """Counted-only before/maintenance/after component, never a full executor.

    The original retained fixture really replays. Damaged component inputs are
    injected only after its real integrity binder, to isolate the new guards;
    they are not represented as valid signed plans. The signed primary vectors
    remain population ceilings, not a substitute for actual primary locking.
    """

    PARENT = AuthorityRevocationRetainedBindingPostgresTests.PARENT
    CHILD = AuthorityRevocationRetainedBindingPostgresTests.CHILD
    records = AuthorityRevocationRetainedBindingPostgresTests.records
    inserted = AuthorityRevocationRetainedBindingPostgresTests.inserted
    rollback_owned_schema = AuthorityRevocationRetainedBindingPostgresTests.rollback_owned_schema

    @classmethod
    def setUpClass(cls):
        # Reuse genuine fixture setup without inheriting its eight test IDs.
        AuthorityRevocationRetainedBindingPostgresTests.setUpClass.__func__(cls)

    def setUp(self):
        AuthorityRevocationRetainedBindingPostgresTests.setUp(self)
        for statement in counted_store_ddl(self.namespace):
            self.connection.execute(statement)
        self.connection.execute(canonical_json_function_sql(self.namespace))
        self.connection.execute(framed_digest_function_sql(self.namespace))
        for statement in (*counted_hash_functions_sql(self.namespace),
                *counted_projection_functions_sql(self.namespace), *counted_path_functions_sql(self.namespace),
                *counted_maintenance_functions_sql(self.namespace)):
            self.connection.execute(statement)
        self.before_store = self.expected_store()
        for table in counted_store_oracle.TABLES:
            columns = tuple(name for name, _ in counted_store_oracle.COLUMNS[table])
            rows = list(self.before_store[table].values())
            if rows:
                with self.connection.cursor() as cursor:
                    cursor.executemany(sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                        sql.Identifier(self.schema, table),
                        sql.SQL(", ").join(sql.Identifier(name) for name in columns),
                        sql.SQL(", ").join(sql.Placeholder() for _ in columns)),
                        [tuple(row[name] for name in columns) for row in rows])
        self.assertEqual(self.snapshot(), self.before_store)
        self.connection.execute(f"""
            CREATE FUNCTION {self.namespace}.counted_component(
                planner_id text, damaged jsonb, requested_phase text, drift_index text)
            RETURNS TABLE(index_ids text[], write_ids text[], expected_before jsonb,
                expected_after jsonb, actual_before jsonb, actual_after jsonb)
            LANGUAGE plpgsql SET search_path = pg_catalog AS $counted_component$
            DECLARE
                planner {self.namespace}.policy_authority_planner_transactions%ROWTYPE;
                component_mutation jsonb;
                component_after_claim jsonb;
                {revocation_retained_declarations_sql()}
                {revocation_counted_declarations_sql()}
            BEGIN
                SELECT * INTO STRICT planner FROM {self.namespace}.policy_authority_planner_transactions
                    WHERE planner_transaction_id = planner_id FOR UPDATE;
                {load_revocation_retained_sql(self.namespace)}
                -- Test-only corrupted component inputs AFTER genuine binding.
                -- This is deliberately not cryptographic or kernel admission.
                IF damaged ? 'before' THEN
                    rv_transition := pg_catalog.jsonb_set(rv_transition, '{{indexBeforeHeads}}', damaged->'before');
                    rv_payload := pg_catalog.jsonb_set(rv_payload,
                        '{{revocationProofBundle,inputs,countedBeforeHeads}}', damaged->'before');
                END IF;
                IF damaged ? 'after' THEN
                    rv_transition := pg_catalog.jsonb_set(rv_transition, '{{indexAfterHeads}}', damaged->'after');
                END IF;
                IF damaged ? 'queries' THEN
                    rv_payload := pg_catalog.jsonb_set(rv_payload,
                        '{{revocationProofBundle,inputs,queries}}', damaged->'queries');
                END IF;
                IF damaged ? 'mutations' THEN
                    rv_payload := pg_catalog.jsonb_set(rv_payload, '{{mutationPlan}}', damaged->'mutations');
                    rv_payload := pg_catalog.jsonb_set(rv_payload,
                        '{{revocationProofBundle,inputs,mutations}}', damaged->'mutations');
                END IF;
                rv_payload := pg_catalog.jsonb_set(rv_payload, '{{rootTransition}}', rv_transition);
                IF requested_phase = 'unprepared-before' THEN
                    {lock_and_assert_revocation_counted_before_sql(self.namespace)}
                END IF;
                {prepare_revocation_counted_transition_sql(self.namespace)}
                IF requested_phase = 'replace-after-prepare' THEN
                    rv_transition := '{{}}'::jsonb;
                    rv_payload := pg_catalog.jsonb_set(rv_payload, '{{rootTransition}}', rv_transition);
                    rv_payload := pg_catalog.jsonb_set(rv_payload,
                        '{{revocationProofBundle,inputs,countedBeforeHeads}}', '[]'::jsonb);
                END IF;
                IF requested_phase = 'prepare-twice' THEN
                    {prepare_revocation_counted_transition_sql(self.namespace)}
                END IF;
                IF requested_phase = 'after-without-before' THEN
                    {assert_revocation_counted_after_sql(self.namespace)}
                END IF;
                {lock_and_assert_revocation_counted_before_sql(self.namespace)}
                IF requested_phase = 'replace-after-before' THEN
                    rv_transition := pg_catalog.jsonb_set(rv_transition, '{{indexAfterHeads}}', '[]'::jsonb);
                    rv_payload := pg_catalog.jsonb_set(rv_payload, '{{rootTransition}}', rv_transition);
                    rv_payload := pg_catalog.jsonb_set(rv_payload,
                        '{{revocationProofBundle,inputs,queries}}', '[]'::jsonb);
                END IF;
                IF requested_phase = 'before-twice' THEN
                    {lock_and_assert_revocation_counted_before_sql(self.namespace)}
                END IF;
                FOR component_mutation IN SELECT value FROM
                    pg_catalog.jsonb_array_elements(rv_payload->'mutationPlan')
                LOOP
                    IF component_mutation->>'table' IN ('webauthn_credentials', 'webauthn_challenges',
                            'oidc_browser_sessions', 'approval_grants', 'control_plane_approvals',
                            'webauthn_trust_publications') THEN
                        PERFORM {self.namespace}.serverware_policy_authority_counted_apply_event(
                            component_mutation->>'table', component_mutation->>'operation',
                            NULLIF(component_mutation->'expectedRow', 'null'::jsonb),
                            NULLIF(component_mutation->'row', 'null'::jsonb));
                    END IF;
                END LOOP;
                IF drift_index IS NOT NULL THEN
                    UPDATE {self.namespace}.policy_authority_counted_index_heads
                        SET index_revision = index_revision + 1 WHERE index_id = drift_index;
                END IF;
                IF requested_phase = 'rebind-drift' THEN
                    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                        'indexId', head.index_id, 'indexRevision', head.index_revision,
                        'rootDigest', head.root_digest, 'leafCount', head.leaf_count)
                        ORDER BY head.index_id COLLATE "C") INTO component_after_claim
                    FROM {self.namespace}.policy_authority_counted_index_heads AS head
                    WHERE head.index_id = ANY(rvc_index_ids);
                    rv_transition := pg_catalog.jsonb_set(rv_transition, '{{indexAfterHeads}}', component_after_claim);
                    rv_payload := pg_catalog.jsonb_set(rv_payload, '{{rootTransition}}', rv_transition);
                END IF;
                {assert_revocation_counted_after_sql(self.namespace)}
                IF requested_phase = 'after-twice' THEN
                    {assert_revocation_counted_after_sql(self.namespace)}
                END IF;
                RETURN QUERY SELECT rvc_index_ids, rvc_write_ids, rvc_before_heads, rvc_after_heads,
                    rvc_actual_before_heads, rvc_actual_after_heads;
            END;
            $counted_component$;
        """)

    def models(self, rows, *, after=False):
        expiry = (self.fixture.semantic.read_write.expiry_after if after
                  else self.fixture.semantic.read_write.expiry_before)
        result = {}
        for identity in counted_store_oracle.INDEX_IDS:
            profile = counted_profile_oracle.expected_profile(identity)
            leaves, identifiers = [], {}
            for row in rows.get(profile.table, {}).values():
                leaf = counted_mutation_oracle.image_leaf(profile, row, expiry.get(row["id"]))
                if leaf is not None:
                    leaves.append(leaf)
                    identifiers[leaf.key] = row["id"]
            result[identity] = (counted_tree_oracle.IndependentIndex(leaves, profile), identifiers)
        return result

    def expected_store(self, *, after=False):
        """Full independent population and touched-record revision oracle."""
        rows = {table: {row["id"]: copy.deepcopy(row) for row in self.fixture.semantic.rows.get(table, [])}
                for table in counted_mutation_oracle.PROFILE_TABLES}
        models = self.models(rows)
        revisions = {identity: 29 for identity in counted_store_oracle.INDEX_IDS}
        leaf_revisions = {(identity, path): 29 for identity, (tree, _) in models.items() for path in tree.leaves}
        node_revisions = {(identity, path): 29 for identity, (tree, _) in models.items()
                          for path, (_, count) in tree.nodes.items() if path and count}
        if after:
            for mutation in self.fixture.payload["mutationPlan"]:
                table = mutation["table"]
                if table not in counted_mutation_oracle.PROFILE_TABLES:
                    continue
                old, new = mutation["expectedRow"], mutation["row"]
                changes = {}
                for identity in counted_mutation_oracle.PROFILE_TABLES[table]:
                    profile = counted_profile_oracle.expected_profile(identity)
                    changes[identity] = (
                        counted_mutation_oracle.image_leaf(profile, old,
                            self.fixture.semantic.read_write.expiry_before.get(mutation["key"]["id"])),
                        counted_mutation_oracle.image_leaf(profile, new,
                            self.fixture.semantic.read_write.expiry_after.get(mutation["key"]["id"])))
                rows[table].pop(mutation["key"]["id"], None)
                if new is not None:
                    rows[table][new["id"]] = copy.deepcopy(new)
                models = self.models(rows, after=True)
                for identity, (old_leaf, new_leaf) in changes.items():
                    if old_leaf is None and new_leaf is None:
                        continue
                    revisions[identity] += 1
                    tree = models[identity][0]
                    paths = {leaf.key for leaf in (old_leaf, new_leaf) if leaf is not None}
                    touched = {path[:depth] for path in paths for depth in range(1, 161)}
                    node_revisions = {address: revision for address, revision in node_revisions.items()
                                      if address[0] != identity or address[1] in tree.nodes
                                      and tree.nodes[address[1]][1] > 0}
                    for path in touched:
                        if path in tree.nodes and tree.nodes[path][1] > 0:
                            node_revisions[(identity, path)] = revisions[identity]
                    if old_leaf is not None:
                        leaf_revisions.pop((identity, old_leaf.key), None)
                    if new_leaf is not None:
                        leaf_revisions[(identity, new_leaf.key)] = revisions[identity]
        result = {table: {} for table in counted_store_oracle.TABLES}
        for identity, (tree, identifiers) in models.items():
            result[counted_store_oracle.HEADS][identity] = counted_store_oracle.head(identity,
                index_revision=revisions[identity], root_digest=tree.root.digest, leaf_count=tree.root.count)
            for path, leaf in tree.leaves.items():
                result[counted_store_oracle.LEAVES][(identity, path)] = {"index_id": identity,
                    "projection_digest": tree.profile.projection_digest, "index_key": path,
                    "primary_id": identifiers[path], "primary_key_digest": leaf.primary_key_digest,
                    "primary_row_digest": leaf.primary_row_digest, "index_revision": leaf_revisions[(identity, path)]}
            for path, (node_digest, count) in tree.nodes.items():
                if path and count:
                    result[counted_store_oracle.NODES][(identity, len(path), path)] = {"index_id": identity,
                        "projection_digest": tree.profile.projection_digest, "depth": len(path),
                        "path_prefix": path, "node_digest": node_digest, "subtree_count": count,
                        "index_revision": node_revisions[(identity, path)]}
        return result

    def snapshot(self):
        result = {}
        for table in counted_store_oracle.TABLES:
            fields = {counted_store_oracle.HEADS: ("index_id",),
                      counted_store_oracle.LEAVES: ("index_id", "index_key"),
                      counted_store_oracle.NODES: ("index_id", "depth", "path_prefix")}[table]
            rows = self.connection.execute(sql.SQL("SELECT pg_catalog.to_jsonb(t) FROM {} AS t").format(
                sql.Identifier(self.schema, table))).fetchall()
            result[table] = {(row[0][fields[0]] if len(fields) == 1 else tuple(row[0][name] for name in fields)): row[0]
                             for row in rows}
        return result

    def head_documents(self, store, identities):
        return [{"indexId": identity, "indexRevision": store[counted_store_oracle.HEADS][identity]["index_revision"],
                 "rootDigest": store[counted_store_oracle.HEADS][identity]["root_digest"],
                 "leafCount": store[counted_store_oracle.HEADS][identity]["leaf_count"]} for identity in identities]

    def call_component(self, parent, *, damaged=None, phase="normal", drift=None):
        return self.connection.execute(sql.SQL("SELECT * FROM {}(%s,%s,%s,%s)").format(
            sql.Identifier(self.schema, "counted_component")),
            (parent["planner_transaction_id"], Jsonb({} if damaged is None else damaged), phase, drift)).fetchone()

    def deny_component(self, parent, message, **changes):
        before = self.snapshot()
        with self.assertRaises(psycopg.Error) as caught:
            with self.connection.transaction():
                self.call_component(parent, **changes)
        self.assertEqual(caught.exception.sqlstate, "P0001")
        self.assertRegex(str(caught.exception), message)
        self.assertEqual(self.snapshot(), before)

    def inventories(self):
        read_ids = ("webauthn_control_approval_approved", "webauthn_grant_approver_active",
                    "webauthn_publication_status", "webauthn_registration_unused_global",
                    "webauthn_session_credential_status")
        write_ids = sorted({identity for mutation in self.fixture.payload["mutationPlan"]
                            for identity in counted_mutation_oracle.PROFILE_TABLES.get(mutation["table"], ())})
        return list(sorted(set(read_ids) | set(write_ids))), write_ids, list(read_ids)

    def test_exact_source_union_uses_real_maintenance_and_independent_full_store(self):
        parent, child = self.records()
        identities, write_ids, read_ids = self.inventories()
        queries = self.fixture.semantic.bundle["inputs"]["queries"]
        self.assertEqual(len(queries), 6)
        self.assertEqual({item["role"] for item in queries}, {"sessions_pending_webauthn", "sessions_active",
            "grants", "approvals", "global_registration_challenges", "pending_trust_publications"})
        self.assertEqual(len(read_ids), 5)
        self.assertEqual(len(self.before_store[counted_store_oracle.HEADS]), 11)
        expected_after = self.expected_store(after=True)
        before_heads = self.head_documents(self.before_store, identities)
        after_heads = self.head_documents(expected_after, identities)
        self.assertEqual(before_heads, self.fixture.semantic.transition["indexBeforeHeads"])
        self.assertEqual(after_heads, self.fixture.semantic.transition["indexAfterHeads"])
        with self.inserted(parent, child):
            result = self.call_component(parent)
            self.assertEqual(result, (identities, write_ids, before_heads, after_heads, before_heads, after_heads))
            self.assertEqual(self.snapshot(), expected_after)
            self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
        self.assertEqual(self.snapshot(), self.before_store)

    def test_membership_exit_nonmember_and_read_only_profiles_keep_exact_revisions(self):
        parent, child = self.records()
        expected = self.expected_store(after=True)
        before, after = self.before_store[counted_store_oracle.HEADS], expected[counted_store_oracle.HEADS]
        live = "webauthn_credential_live_trust"
        self.assertEqual(after[live]["leaf_count"], before[live]["leaf_count"] - 1)
        self.assertGreater(after[live]["index_revision"], before[live]["index_revision"])
        identities, write_ids, read_ids = self.inventories()
        readonly = set(read_ids) - set(write_ids)
        self.assertTrue(readonly)
        for identity in readonly:
            self.assertEqual(after[identity], before[identity])
        nonmembers = []
        for mutation in self.fixture.payload["mutationPlan"]:
            for identity in counted_mutation_oracle.PROFILE_TABLES.get(mutation["table"], ()):
                profile = counted_profile_oracle.expected_profile(identity)
                key = mutation["key"]["id"]
                old = counted_mutation_oracle.image_leaf(profile, mutation["expectedRow"],
                    self.fixture.semantic.read_write.expiry_before.get(key))
                new = counted_mutation_oracle.image_leaf(profile, mutation["row"],
                    self.fixture.semantic.read_write.expiry_after.get(key))
                if old is None and new is None:
                    nonmembers.append((identity, key))
        self.assertTrue(nonmembers)
        with self.inserted(parent, child):
            self.call_component(parent)
            self.assertEqual(self.snapshot(), expected)
            # Exact independent leaves/node revisions include unchanged older
            # records and every genuinely touched path, not just final roots.
            self.assertTrue(any(row["index_revision"] == 29
                                for row in expected[counted_store_oracle.NODES].values()))
            self.assertTrue(any(row["index_revision"] > 29
                                for row in expected[counted_store_oracle.NODES].values()))
        for changed in ("revision", "count", "overflow"):
            before_heads = copy.deepcopy(self.fixture.semantic.transition["indexBeforeHeads"])
            after_heads = copy.deepcopy(self.fixture.semantic.transition["indexAfterHeads"])
            old = next(item for item in before_heads if item["indexId"] == "webauthn_credential_id")
            new = next(item for item in after_heads if item["indexId"] == old["indexId"])
            if changed == "revision":
                new["indexRevision"] += 1
            elif changed == "count":
                new["leafCount"] = 0
                new["rootDigest"] = counted_tree_oracle.empty(
                    counted_profile_oracle.expected_profile(old["indexId"]), "")[0]
            else:
                # Both scalars are individually int64-valid; the genuine
                # member event's +1 is what must fail, before any live read.
                old["indexRevision"] = new["indexRevision"] = 2**63 - 1
            parent, child = self.records()
            with self.subTest(projected_delta=changed), self.inserted(parent, child):
                self.deny_component(parent, "revocation counted projected head delta changed",
                    damaged={"before": before_heads, "after": after_heads})

    def test_prepare_rejects_missing_extra_duplicate_reordered_and_typed_head_vectors(self):
        original = self.fixture.semantic.transition
        identities, _, _ = self.inventories()
        extra_id = next(identity for identity in counted_store_oracle.INDEX_IDS if identity not in identities)
        extra_head = self.head_documents(self.before_store, (extra_id,))[0]
        for side, field in (("before", "indexBeforeHeads"), ("after", "indexAfterHeads")):
            baseline = original[field]
            cases = (
                (baseline[:-1], "head or frontier inventory differs from exact union"),
                (sorted([*copy.deepcopy(baseline), extra_head], key=lambda item: item["indexId"]),
                 "head or frontier inventory differs from exact union"),
                ([baseline[0], baseline[0], *baseline[2:]], "compact head is not exact sorted source"),
                (list(reversed(baseline)), "compact head is not exact sorted source"),
            )
            for vector, message in cases:
                parent, child = self.records()
                with self.subTest(side=side, message=message), self.inserted(parent, child):
                    self.deny_component(parent, "revocation counted " + message, damaged={side: vector})
            for field_name, replacement in (("indexRevision", True), ("leafCount", None),
                                              ("indexRevision", 2**63)):
                vector = copy.deepcopy(baseline)
                vector[0][field_name] = replacement
                parent, child = self.records()
                message = "counter bound is invalid" if replacement == 2**63 else "counter type is invalid"
                with self.subTest(side=side, field=field_name, value=replacement), self.inserted(parent, child):
                    self.deny_component(parent, "revocation counted " + message, damaged={side: vector})

    def test_prepare_requires_all_six_source_roles_and_actual_mutation_profile_closure(self):
        queries = self.fixture.semantic.bundle["inputs"]["queries"]
        parent, child = self.records()
        with self.inserted(parent, child):
            # This SQL component binds the complete role set, not declaration
            # order. No claim is made that altered retained bytes replay.
            self.call_component(parent, damaged={"queries": list(reversed(queries))})
            self.assertEqual(self.snapshot(), self.expected_store(after=True))
        variants = [(queries[:-1], "role inventory is invalid"),
                    ([queries[0], queries[0], *queries[2:]], "role is duplicated")]
        for value, message in variants:
            parent, child = self.records()
            with self.subTest(message=message), self.inserted(parent, child):
                self.deny_component(parent, "revocation counted " + message, damaged={"queries": value})
        for field, value in (("maximumRows", 2), ("selectorItems", [["publication_status", "published"]])):
            altered = copy.deepcopy(queries)
            pending = next(item for item in altered if item["role"] == "pending_trust_publications")
            pending[field] = value
            parent, child = self.records()
            with self.subTest(field=field), self.inserted(parent, child):
                self.deny_component(parent, "revocation counted role selector or bound changed",
                    damaged={"queries": altered})
        mutations = self.fixture.payload["mutationPlan"]
        for change in ("template", "duplicate", "omit_writes"):
            altered = copy.deepcopy(mutations)
            if change == "template":
                altered[0]["templateId"] = "not-a-source-template"
                message = "mutation template is not source declared"
            elif change == "duplicate":
                altered.append(copy.deepcopy(altered[0]))
                message = "mutation address is duplicated"
            else:
                altered = []
                message = "head or frontier inventory differs from exact union"
            parent, child = self.records()
            with self.subTest(change=change), self.inserted(parent, child):
                self.deny_component(parent, "revocation counted " + message, damaged={"mutations": altered})

    def test_before_rejects_ddl_admitted_stale_or_missing_live_heads_without_repair(self):
        identity = "webauthn_credential_id"
        for change in ("index_revision", "root_digest", "leaf_count", "missing"):
            parent, child = self.records()
            with self.subTest(change=change), self.inserted(parent, child):
                if change == "missing":
                    for table in (counted_store_oracle.NODES, counted_store_oracle.LEAVES, counted_store_oracle.HEADS):
                        self.connection.execute(sql.SQL("DELETE FROM {} WHERE index_id = %s").format(
                            sql.Identifier(self.schema, table)), (identity,))
                    message = "before head is absent"
                else:
                    current = self.before_store[counted_store_oracle.HEADS][identity][change]
                    value = token("stale counted root") if change == "root_digest" else current + 1
                    # Real CHECK/FK admission occurs before the guard-denial
                    # scope; a storage constraint failure is not guard proof.
                    self.connection.execute(sql.SQL("UPDATE {} SET {} = %s WHERE index_id = %s").format(
                        sql.Identifier(self.schema, counted_store_oracle.HEADS), sql.Identifier(change)), (value, identity))
                    message = "before live head changed"
                self.deny_component(parent, "revocation counted " + message)
        self.assertEqual(self.snapshot(), self.before_store)

    def test_after_root_mismatch_rolls_back_every_actual_counted_maintenance_record(self):
        after = copy.deepcopy(self.fixture.semantic.transition["indexAfterHeads"])
        altered = next(item for item in after if item["indexId"] == "webauthn_credential_id")
        self.assertGreater(altered["leafCount"], 0)
        altered["rootDigest"] = token("incorrect after commitment")
        parent, child = self.records()
        with self.inserted(parent, child):
            self.deny_component(parent, "revocation counted after live head changed", damaged={"after": after})
            # The same untouched before population then admits the real
            # original transition; failure did not leave partial path writes.
            self.call_component(parent)
            self.assertEqual(self.snapshot(), self.expected_store(after=True))
        self.assertEqual(self.snapshot(), self.before_store)

    def test_read_only_head_drift_denies_but_unrelated_installed_profiles_are_not_invented_members(self):
        identities, write_ids, read_ids = self.inventories()
        readonly = next(identity for identity in read_ids if identity not in write_ids)
        unrelated = next(identity for identity in counted_store_oracle.INDEX_IDS if identity not in identities)
        parent, child = self.records()
        with self.inserted(parent, child):
            self.deny_component(parent, "revocation counted after live head changed", drift=readonly)
        parent, child = self.records()
        with self.inserted(parent, child):
            # This genuine installed profile remains outside the exact source
            # read/write union. Its presence and unrelated revision are legal.
            self.connection.execute(sql.SQL("UPDATE {} SET index_revision = index_revision + 1 WHERE index_id = %s").format(
                sql.Identifier(self.schema, counted_store_oracle.HEADS)), (unrelated,))
            result = self.call_component(parent)
            self.assertEqual(result[0], identities)
            expected = self.expected_store(after=True)
            expected[counted_store_oracle.HEADS][unrelated]["index_revision"] += 1
            self.assertEqual(self.snapshot(), expected)

    def test_private_prepare_before_after_phases_are_single_use_and_ordered(self):
        for phase, message in (("unprepared-before", "before"), ("prepare-twice", "prepare"),
                               ("after-without-before", "after"), ("before-twice", "before"),
                               ("after-twice", "after")):
            parent, child = self.records()
            with self.subTest(phase=phase), self.inserted(parent, child):
                self.deny_component(parent, "revocation counted " + message + " phase is invalid", phase=phase)
        identities, write_ids, read_ids = self.inventories()
        expected = self.expected_store(after=True)
        before_heads = self.head_documents(self.before_store, identities)
        after_heads = self.head_documents(expected, identities)
        for phase in ("replace-after-prepare", "replace-after-before"):
            parent, child = self.records()
            with self.subTest(captured=phase), self.inserted(parent, child):
                # Replacing upstream JSON after capture cannot select a new
                # expected vector; actual maintenance keeps its original plan.
                result = self.call_component(parent, phase=phase)
                self.assertEqual(result, (identities, write_ids, before_heads, after_heads, before_heads, after_heads))
                self.assertEqual(self.snapshot(), expected)
        readonly = next(identity for identity in read_ids if identity not in write_ids)
        parent, child = self.records()
        with self.inserted(parent, child):
            # A fabricated upstream after vector exactly matches drifted SQL
            # rows, but the originally captured vector must still reject it.
            self.deny_component(parent, "revocation counted after live head changed",
                phase="rebind-drift", drift=readonly)


class AuthorityRevocationCapabilityCustodyPostgresTests(unittest.TestCase):
    """Actual DDL/guards with opaque transport, not crypto or issuer approval."""

    PARENT = AuthorityRevocationRetentionPostgresTests.PARENT
    CHILD = AuthorityRevocationRetentionPostgresTests.CHILD
    ASSERTION = AuthorityRevocationRetentionPostgresTests.ASSERTION
    PROJECTION = AuthorityRevocationRetentionPostgresTests.PROJECTION
    CAPABILITY = "policy_authority_writer_capabilities"
    SIDECAR = "policy_authority_revocation_retained_capabilities"
    ENVELOPE = "policy_authority_execution_envelopes"
    IDENTITY = (
        "capability_id", "capability_protocol", "capability_record_digest", "capability_digest",
        "envelope_id", "operation", "operation_id", "handler_name", "request_digest",
        "operation_manifest_digest", "query_manifest_digest", "authority_root_set_digest",
        "authority_snapshot_digest", "approver_policy_digest", "webauthn_receipt_json",
        "webauthn_receipt_digest", "webauthn_trust_high_water_digest", "witness_reservation_digest",
        "witness_sequence", "witness_head_digest", "deadline_monotonic_ns", "fence",
        "issued_monotonic_ns", "issued_at_epoch_ns", "expires_at_epoch_ns",
        "issuer_session_identity_digest", "issuer_measurement_digest", "issuer_attestation_receipt_digest",
        "issuer_credential_issuance_digest", "expected_result_digest", "planner_transaction_id",
        "authorization_projection_digest", "selected_business_rows_digest", "mutation_plan_digest",
        "deadline_epoch_ns",
    )
    LIFECYCLE = (
        "status", "writer_token_digest", "reserved_at_epoch_ns", "reserved_transaction_id",
        "result_digest", "commit_receipt_digest", "committed_at_epoch_ns", "failure_digest", "failed_at_epoch_ns",
    )
    rollback_owned_schema = AuthorityRevocationRetentionPostgresTests.rollback_owned_schema
    insert = AuthorityRevocationRetentionPostgresTests.insert
    update = AuthorityRevocationRetentionPostgresTests.update
    changed = staticmethod(AuthorityRevocationRetentionPostgresTests.changed)

    def setUp(self):
        AuthorityRevocationRetentionPostgresTests.setUp(self)
        self.connection.execute(capability_retention_guard_sql(self.namespace))
        for statement in production_retained_immutable_sql(self.SIDECAR):
            self.connection.execute(statement)

    def rows(self, table):
        keys = {self.PARENT: "planner_transaction_id", self.CHILD: "planner_transaction_id",
                self.ENVELOPE: "envelope_id", self.CAPABILITY: "capability_id", self.SIDECAR: "capability_id"}
        return tuple(row[0] for row in self.connection.execute(sql.SQL(
            'SELECT pg_catalog.to_jsonb(t) FROM {} AS t ORDER BY {} COLLATE "C"').format(
                sql.Identifier(self.schema, table), sql.Identifier(keys[table]))).fetchall())

    def snapshot(self):
        return tuple(self.rows(table) for table in
                     (self.PARENT, self.CHILD, self.ENVELOPE, self.CAPABILITY, self.SIDECAR))

    def records(self, label="capability"):
        # Reuse the independently written opaque planner rows, not any runtime
        # record/descriptor producer. Nothing here represents signed evidence.
        _, planner, retained = AuthorityRevocationRetentionPostgresTests.records(self, label)
        transaction_id, capability_id = token("planner-" + label), token("capability-" + label)
        planner.update(planner_transaction_id=transaction_id, capability_id=capability_id)
        retained["planner_transaction_id"] = transaction_id
        envelope_id = token("execution-" + label)
        raw_digest = lambda value: "sha256:" + hashlib.sha256(value).hexdigest()
        encoded = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        wrapper = b'{"opaque":"execution"}'
        capability_raw, witness_raw = b'{"opaque":"capability"}', b'{"opaque":"reserve"}'
        execution = {
            "envelope_id": envelope_id, "parent_envelope_id": None, "purpose": "execute-v9",
            "operation": planner["operation"], "operation_id": planner["operation_id"],
            "request_digest": planner["request_digest"], "capability_id": capability_id,
            "planner_transaction_id": transaction_id,
            "authorization_projection_digest": planner["authorization_projection_digest"],
            "operation_contract_digest": planner["operation_contract_digest"],
            "exact_request_base64url": encoded(wrapper), "exact_request_bytes_digest": raw_digest(wrapper),
            "exact_request_byte_count": len(wrapper), "deadline_monotonic_ns": 200,
            "deadline_epoch_ns": 2000, "fence": 1, "status": "reserved",
            "exact_response_base64url": None, "exact_response_bytes_digest": None,
            "exact_response_byte_count": None, "result_digest": None, "terminal_receipt_json": None,
            "terminal_receipt_digest": None, "failure_code": None, "failure_digest": None,
            "reserved_at_epoch_ns": 1000, "terminal_at_epoch_ns": None,
            "source_revision": authority_contract.SOURCE_REVISION,
        }
        capability = {
            "capability_id": capability_id, "capability_protocol": "revocation-v4",
            "capability_record_digest": token("capability-record-" + label),
            "capability_digest": token("capability-payload-" + label), "envelope_id": envelope_id,
            "operation": planner["operation"], "operation_id": planner["operation_id"],
            "handler_name": "revoke_webauthn_credential", "request_digest": planner["request_digest"],
            "operation_manifest_digest": token("manifest"), "query_manifest_digest": planner["query_manifest_digest"],
            "authority_root_set_digest": planner["authority_root_set_before_digest"],
            "authority_snapshot_digest": planner["authority_snapshot_digest"], "approver_policy_digest": None,
            "webauthn_receipt_json": "{}", "webauthn_receipt_digest": token("webauthn"),
            "webauthn_trust_high_water_digest": token("trust"),
            "witness_reservation_digest": token("witness-" + label), "witness_sequence": 1,
            "witness_head_digest": token("head"), "deadline_monotonic_ns": 200, "fence": 1,
            "issued_monotonic_ns": 100, "issued_at_epoch_ns": 1000, "expires_at_epoch_ns": 2000,
            "issuer_session_identity_digest": token("issuer"), "issuer_measurement_digest": token("measurement"),
            "issuer_attestation_receipt_digest": token("attestation"), "issuer_credential_issuance_digest": token("issuance"),
            "status": "issued", "writer_token_digest": None, "reserved_at_epoch_ns": None,
            "reserved_transaction_id": None, "result_digest": None, "commit_receipt_digest": None,
            "committed_at_epoch_ns": None, "failure_digest": None, "failed_at_epoch_ns": None,
            "expected_result_digest": token("result"), "planner_transaction_id": transaction_id,
            "authorization_projection_digest": planner["authorization_projection_digest"],
            "selected_business_rows_digest": planner["selected_business_rows_digest"],
            "mutation_plan_digest": planner["mutation_plan_digest"], "deadline_epoch_ns": 2000,
        }
        sidecar = {
            "capability_id": capability_id, "capability_protocol": "revocation-v4",
            "capability_record_digest": capability["capability_record_digest"],
            "planner_transaction_id": transaction_id, "plan_protocol": "revocation-v4",
            "retained_record_digest": retained["retained_record_digest"], "execution_envelope_id": envelope_id,
            "capability_digest": capability["capability_digest"], "root_transition_digest": token("transition"),
            "authority_snapshot_digest": planner["authority_snapshot_digest"],
            "exact_request_bytes_digest": raw_digest(wrapper), "exact_capability_base64url": encoded(capability_raw),
            "exact_capability_bytes_digest": raw_digest(capability_raw), "exact_capability_byte_count": len(capability_raw),
            "signer_key_digest": token("capability-key"), "witness_key_digest": token("witness-key"),
            "exact_witness_request_base64url": encoded(witness_raw),
            "exact_witness_request_bytes_digest": raw_digest(witness_raw), "exact_witness_request_byte_count": len(witness_raw),
            "source_revision": authority_contract.SOURCE_REVISION,
        }
        self.assertEqual(tuple(map(len, (planner, retained, execution, capability, sidecar))), (36, 12, 28, 44, 20))
        self.assertEqual(set(capability), set(self.IDENTITY + self.LIFECYCLE))
        return planner, retained, execution, capability, sidecar

    def insert_records(self, records):
        self.connection.execute("SET CONSTRAINTS ALL DEFERRED")
        for table, row in zip((self.PARENT, self.CHILD, self.ENVELOPE, self.CAPABILITY, self.SIDECAR), records):
            self.insert(table, row)
        self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")

    def changed_lifecycle_value(self, row, field):
        # Input casts happen before BEFORE UPDATE triggers. Supply a valid
        # BIGINT even when the old timestamp/transaction column is NULL, so
        # the denial establishes the real guard rather than a codec failure.
        if field in {"reserved_at_epoch_ns", "reserved_transaction_id", "committed_at_epoch_ns", "failed_at_epoch_ns"}:
            return 1 if row[field] is None else row[field] + 1
        return self.changed(row[field])

    def test_capability_custody_deferred_parent_plan_and_envelope_bindings(self):
        constraints = self.connection.execute(
            "SELECT conname, condeferrable, condeferred, confupdtype, confdeltype "
            "FROM pg_catalog.pg_constraint WHERE conrelid IN (%s::regclass, %s::regclass) "
            "AND contype = 'f' ORDER BY conname",
            (self.namespace + "." + self.CAPABILITY, self.namespace + "." + self.SIDECAR)).fetchall()
        self.assertEqual(constraints, [(name, True, True, "a", "a") for name in (
            "serverware_revocation_capability_envelope_fk", "serverware_revocation_capability_parent_fk",
            "serverware_revocation_capability_plan_fk", "serverware_writer_capability_retained_fk")])
        for case in ("missing-parent", "missing-sidecar", "missing-envelope", "wrong-plan",
                     "wrong-capability", "wrong-record", "wrong-transaction", "wrong-execution"):
            rows = self.records(case)
            with self.subTest(case=case), self.assertRaises(psycopg.errors.ForeignKeyViolation) as caught:
                with self.connection.transaction():
                    self.connection.execute("SET CONSTRAINTS ALL DEFERRED")
                    for table, row in zip((self.PARENT, self.CHILD, self.ENVELOPE, self.CAPABILITY, self.SIDECAR), rows):
                        if (case, table) in (("missing-parent", self.CAPABILITY),
                                             ("missing-sidecar", self.SIDECAR), ("missing-envelope", self.ENVELOPE)):
                            continue
                        if table == self.SIDECAR:
                            fields = {"wrong-plan": "retained_record_digest", "wrong-capability": "capability_id",
                                "wrong-record": "capability_record_digest", "wrong-transaction": "planner_transaction_id",
                                "wrong-execution": "execution_envelope_id"}
                            if case in fields:
                                row = {**row, fields[case]: token("wrong")}
                        self.insert(table, row)
                    self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
            self.assertEqual(caught.exception.sqlstate, "23503")
            self.assertIn(caught.exception.diag.constraint_name, {row[0] for row in constraints})
            self.assertEqual(self.snapshot(), ((), (), (), (), ()))
        records = self.records()
        self.connection.execute("SET CONSTRAINTS ALL DEFERRED")
        # Both halves may precede their parents, but all deferred references
        # must close. This savepoint/constraint proof is not a top-level commit.
        for index in (4, 3, 2, 1, 0):
            self.insert((self.PARENT, self.CHILD, self.ENVELOPE, self.CAPABILITY, self.SIDECAR)[index], records[index])
        self.connection.execute("SET CONSTRAINTS ALL IMMEDIATE")
        self.assertEqual(self.snapshot(), tuple((row,) for row in records))

    def test_capability_protocol_and_original_transport_shapes_are_closed(self):
        planner, retained, execution, capability, sidecar = self.records()
        legacy = {**capability, "capability_record_digest": None}
        del legacy["capability_protocol"]
        self.insert(self.CAPABILITY, legacy)
        self.assertEqual(self.rows(self.CAPABILITY), ({**legacy, "capability_protocol": "v3"},))
        baseline = self.snapshot()
        for field, value in (("capability_protocol", "future"), ("capability_protocol", "v3"),
                             ("capability_record_digest", None), ("capability_record_digest", "not-a-digest"),
                             ("operation", "webauthn.counter.cas")):
            candidate = {**capability, field: value, "capability_id": token("bad"),
                "capability_digest": token("bad-digest"), "envelope_id": token("bad-envelope"),
                "operation_id": "bad-operation", "request_digest": token("bad-request"),
                "witness_reservation_digest": token("bad-witness"), "planner_transaction_id": token("bad-planner")}
            with self.subTest(parent=field, value=value), self.assertRaises(psycopg.errors.CheckViolation):
                with self.connection.transaction():
                    self.insert(self.CAPABILITY, candidate)
            self.assertEqual(self.snapshot(), baseline)
        for field, value in (("capability_protocol", "v3"), ("plan_protocol", "v3"),
                ("source_revision", "old"), ("capability_record_digest", "sha256:" + "A" * 64),
                ("exact_capability_byte_count", 4194305), ("exact_witness_request_byte_count", 65537),
                ("exact_capability_byte_count", 1), ("exact_witness_request_byte_count", 1),
                ("exact_capability_base64url", sidecar["exact_capability_base64url"] + "="),
                ("exact_witness_request_base64url", "!" * len(sidecar["exact_witness_request_base64url"])),
                ("signer_key_digest", "wrong"), ("witness_key_digest", "wrong")):
            with self.subTest(sidecar=field, value=value), self.assertRaises(psycopg.errors.CheckViolation):
                with self.connection.transaction():
                    self.insert(self.SIDECAR, {**sidecar, field: value})
            self.assertEqual(self.snapshot(), baseline)
        for stem in ("exact_capability", "exact_witness_request"):
            for count, transport in ((2, "e31"), (4, "e30KeB")):
                with self.subTest(padding=stem, count=count), self.assertRaises(psycopg.errors.CheckViolation):
                    with self.connection.transaction():
                        self.insert(self.SIDECAR, {**sidecar, stem + "_byte_count": count,
                            stem + "_base64url": transport})
                self.assertEqual(self.snapshot(), baseline)

    def test_capability_sidecar_and_initial_parent_identity_are_immutable(self):
        records = self.records()
        self.insert_records(records)
        capability, sidecar = records[3:]
        baseline = self.snapshot()
        for table, row, columns in ((self.SIDECAR, sidecar, tuple(sidecar)),
                                    (self.CAPABILITY, capability, self.IDENTITY)):
            for field in columns:
                with self.subTest(table=table, field=field), self.assertRaisesRegex(
                        psycopg.errors.RaiseException, "immutable"):
                    with self.connection.transaction():
                        self.update(table, row["planner_transaction_id"], {field: self.changed(row[field])})
                self.assertEqual(self.snapshot(), baseline)
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "immutable"):
            with self.connection.transaction():
                self.update(self.SIDECAR, sidecar["planner_transaction_id"], sidecar)
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "immutable"):
            with self.connection.transaction():
                self.connection.execute(sql.SQL("DELETE FROM {}").format(sql.Identifier(self.schema, self.SIDECAR)))
        self.update(self.CAPABILITY, capability["planner_transaction_id"], capability)
        self.assertEqual(self.snapshot(), baseline)
        legacy = {**self.records("legacy")[3], "capability_protocol": "v3", "capability_record_digest": None}
        self.insert(self.CAPABILITY, legacy)
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "immutable"):
            with self.connection.transaction():
                self.update(self.CAPABILITY, legacy["planner_transaction_id"], {
                    "capability_protocol": "revocation-v4", "capability_record_digest": token("adoption")})
        # Legacy identity and lifecycle behavior are not silently rewritten.
        self.update(self.CAPABILITY, legacy["planner_transaction_id"], {"handler_name": "legacy-handler"})

    def test_capability_lifecycle_reconciliation_and_later_failures_preserve_custody(self):
        records = self.records()
        self.insert_records(records)
        capability = records[3]
        transaction_id = capability["planner_transaction_id"]
        reserved = {"status": "reserved", "writer_token_digest": token("writer"),
                    "reserved_at_epoch_ns": 1200, "reserved_transaction_id": 42}
        self.update(self.CAPABILITY, transaction_id, reserved)
        baseline = self.snapshot()
        for field in ("writer_token_digest", "reserved_at_epoch_ns", "reserved_transaction_id"):
            with self.subTest(reservation=field), self.assertRaisesRegex(psycopg.errors.RaiseException, "immutable"):
                with self.connection.transaction():
                    self.update(self.CAPABILITY, transaction_id, {field: self.changed(reserved[field])})
            self.assertEqual(self.snapshot(), baseline)
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "immutable"):
            with self.connection.transaction():
                self.update(self.CAPABILITY, transaction_id, {name: capability[name] for name in self.LIFECYCLE})
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "immutable"):
            with self.connection.transaction():
                failed = {name: capability[name] for name in self.LIFECYCLE}
                failed.update(status="failed", failure_digest=token("failure"), failed_at_epoch_ns=1300)
                self.update(self.CAPABILITY, transaction_id, failed)
        self.assertEqual(self.snapshot(), baseline)
        committed = {**reserved, "status": "committed", "result_digest": capability["expected_result_digest"],
                     "commit_receipt_digest": token("commit"), "committed_at_epoch_ns": 1300}
        self.update(self.CAPABILITY, transaction_id, committed)
        for status in ("committed", "reconciled"):
            self.update(self.CAPABILITY, transaction_id, {"status": status})
            baseline = self.snapshot()
            for field in self.LIFECYCLE:
                if field == "status":
                    replacement = "reserved"
                else:
                    replacement = self.changed_lifecycle_value(self.rows(self.CAPABILITY)[0], field)
                with self.subTest(terminal=status, field=field), self.assertRaisesRegex(psycopg.errors.RaiseException, "immutable"):
                    with self.connection.transaction():
                        self.update(self.CAPABILITY, transaction_id, {field: replacement})
                self.assertEqual(self.snapshot(), baseline)
        for status in ("expired", "failed"):
            terminal_records = self.records(status)
            self.insert_records(terminal_records)
            terminal_id = terminal_records[3]["planner_transaction_id"]
            values = {"status": status}
            if status == "failed":
                values.update(failure_digest=token("failure"), failed_at_epoch_ns=1300)
            self.update(self.CAPABILITY, terminal_id, values)
            baseline = self.snapshot()
            terminal_row = next(row for row in self.rows(self.CAPABILITY) if row["planner_transaction_id"] == terminal_id)
            for field in self.LIFECYCLE:
                replacement = "issued" if field == "status" else self.changed_lifecycle_value(terminal_row, field)
                with self.subTest(terminal=status, field=field), self.assertRaisesRegex(psycopg.errors.RaiseException, "immutable"):
                    with self.connection.transaction():
                        self.update(self.CAPABILITY, terminal_id, {field: replacement})
                self.assertEqual(self.snapshot(), baseline)
        expired_records = self.records("reserved-expiry")
        self.insert_records(expired_records)
        expired_id = expired_records[3]["planner_transaction_id"]
        expiry_reservation = {**reserved, "writer_token_digest": token("expiry-writer")}
        self.update(self.CAPABILITY, expired_id, expiry_reservation)
        self.update(self.CAPABILITY, expired_id, {"status": "expired"})
        expired_row = next(row for row in self.rows(self.CAPABILITY) if row["planner_transaction_id"] == expired_id)
        self.assertEqual(expired_row, {**expired_records[3], **expiry_reservation, "status": "expired"})
        direct_records = self.records("direct-commit")
        self.insert_records(direct_records)
        direct_id = direct_records[3]["planner_transaction_id"]
        direct_commit = {**committed, "writer_token_digest": token("direct-writer"),
                         "commit_receipt_digest": token("direct-commit")}
        self.update(self.CAPABILITY, direct_id, direct_commit)
        direct_row = next(row for row in self.rows(self.CAPABILITY) if row["planner_transaction_id"] == direct_id)
        self.assertEqual(direct_row, {**direct_records[3], **direct_commit})
        baseline = self.snapshot()
        with self.assertRaisesRegex(psycopg.errors.RaiseException, "immutable"):
            with self.connection.transaction():
                later = self.records("later")
                self.insert_records(later)
                self.update(self.CAPABILITY, later[3]["planner_transaction_id"], {"operation_id": "retargeted"})
        self.assertEqual(self.snapshot(), baseline)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    run_native_fixture("scripts/test_authority_root_transition_postgres.py",
        argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
