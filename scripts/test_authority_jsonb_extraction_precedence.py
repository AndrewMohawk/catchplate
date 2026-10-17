#!/usr/bin/env python3
"""Source controls and rollback-only PostgreSQL JSONB precedence regression.

Only stdlib is imported. --emit-postgres-sql emits the complete actual native
hold guard and the two actual successor vector-stripping expressions for an
externally owned disposable PostgreSQL16 Unix-socket fixture. It starts no
engine, opens no connection, and imports no production module. Synthetic
tables/records stand for previously admitted inputs, not authority or a full
executor. The successor cases cover only the exact stripping expressions.
"""
from __future__ import annotations

import argparse
import ast
import copy
import json
import sys
import unittest

from test_authority_executor_optional_evidence import _one, _read, _template


SCHEMA = "catchplate_jsonb_precedence_component"
NAMESPACE = '"' + SCHEMA + '"'
DENIAL = "native publication current-root hold is unresolved"


def _literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def _json(value):
    return _literal(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))) + "::jsonb"


def _hold():
    tree = _read("catchplate/authority_native_activation_hold.py")
    constants = {node.targets[0].id: node.value for node in tree.body
        if type(node) is ast.Assign and len(node.targets) == 1 and type(node.targets[0]) is ast.Name}
    table, scope, exempt = (ast.literal_eval(constants[name]) for name in ("TABLE", "SCOPE", "EXEMPT"))
    fields = constants["FIELDS"]
    if (type(fields) is not ast.Call or type(fields.func) is not ast.Name
            or fields.func.id != "frozenset" or len(fields.args) != 1 or fields.keywords):
        raise ValueError("hold source field roster changed")
    fields = tuple(sorted(ast.literal_eval(fields.args[0])))
    function = _one([node for node in tree.body if type(node) is ast.FunctionDef and node.name == "sql"])
    template = _one([node.value for node in function.body if type(node) is ast.Return])
    guard = _template(template, dict(namespace=NAMESPACE, TABLE=table, SCOPE=scope,
        exempt=",".join(_literal(name) for name in exempt), operation_sql="capability.operation",
        mutations_sql="planner.mutation_plan_json::pg_catalog.jsonb"))
    fixed = "((m->'row') - 'phase' - 'publication_sha256' - 'finalization_digest')"
    old = "(m->'row' - 'phase' - 'publication_sha256' - 'finalization_digest')"
    if guard.count(fixed) != 1 or old in guard:
        raise ValueError("hold extraction-before-deletion seam is not exact")
    return guard, guard.replace(fixed, old), table, scope, fields


def _vectors():
    tree = _read("catchplate/authority_store/successor_execution_sql.py")
    function = _one([node for node in tree.body if type(node) is ast.FunctionDef and node.name == "_packet"])
    template = _one([node.value for node in function.body if type(node) is ast.Return])
    body = _template(template)
    expressions = []
    for field in ("beforeVector", "afterVector"):
        fixed = "((sxe_packet->'" + field + "') - 'primaryRoots' - 'countedRoots')"
        old = "(sxe_packet->'" + field + "' - 'primaryRoots' - 'countedRoots')"
        if body.count(fixed + " IS DISTINCT FROM ") != 1 or old in body:
            raise ValueError("successor vector stripping source seam changed")
        expressions.append((field, fixed, old))
    return tuple(expressions)


def postgres_sql():
    guard, old_guard, table, scope, fields = _hold()
    # These minimal tables exercise the real guard. They are not a substitute
    # for production DDL, signatures, source/catalog, roots or custody admission.
    values = {name: "synthetic-" + name for name in fields}
    values.update(scope=scope, phase="held", issued_at_epoch_ns=1, expires_at_epoch_ns=2,
        publication_sha256=None, finalization_digest=None)
    columns = ",".join(name + (" bigint" if name.endswith("_epoch_ns") else " text") for name in fields)
    insert = (f"INSERT INTO {NAMESPACE}.{table} VALUES ("
        + ",".join("NULL" if values[name] is None else _literal(values[name]) for name in fields) + ");")
    published = {**values, "phase": "published", "publication_sha256": "synthetic-publication",
        "finalization_digest": "synthetic-finalization"}
    terminal = {name: published[name] for name in
        ("activation_id", "prepared_sha256", "publication_sha256", "finalization_digest")}
    finalization = [dict(table=table, operation="UPDATE", key={"scope": scope},
        expectedRow=values, row=published), dict(table="policy_native_activation_finalizations",
        operation="INSERT", key={"activation_id": values["activation_id"]}, expectedRow=None, row=terminal)]
    ordinary = [dict(table="webauthn_challenges", operation="INSERT", key={"id": "synthetic-challenge"},
        expectedRow=None, row={"id": "synthetic-challenge"})]
    audit = [dict(table="metadata_audit_outbox", operation="INSERT", key={"id": "synthetic-audit"},
        expectedRow=None, row={"id": "synthetic-audit"})]
    preparation = {name: values[name] for name in ("activation_id", "prepared_sha256")}
    inclusion = [dict(table="policy_native_activation_preparations", operation="UPDATE",
        key={"activation_id": values["activation_id"]}, expectedRow=preparation,
        row={**preparation, "receipt": "synthetic-inclusion"})]

    def call(operation, mutations, old=False):
        return (f"PERFORM {NAMESPACE}.exercise_hold({_literal(operation)}, {_json(mutations)}, "
            + ("TRUE" if old else "FALSE") + ");")

    negatives = [("unrelated-while-held", "webauthn.challenge.create", ordinary),
        ("missing-finalization", "native-policy-activation.finalize", finalization[:1])]
    for field in ("activation_id", "prepared_sha256"):
        changed = copy.deepcopy(finalization)
        changed[0]["row"][field] = "changed-" + field
        negatives.append(("changed-" + field, "native-policy-activation.finalize", changed))
    changed = copy.deepcopy(finalization)
    changed[1]["row"]["publication_sha256"] = "different-publication"
    negatives.append(("terminal-publication-join", "native-policy-activation.finalize", changed))
    refusals = []
    for label, operation, mutations in negatives:
        refusals.append(f"""
    caught := FALSE;
    BEGIN
        {call(operation, mutations)}
    EXCEPTION WHEN SQLSTATE 'P0001' THEN
        IF SQLERRM <> {_literal(DENIAL)} THEN RAISE; END IF;
        caught := TRUE;
    END;
    IF NOT caught THEN RAISE EXCEPTION {_literal('hold refusal missing: ' + label)}; END IF;
""")
    vector_checks = []
    header = {"schema": "synthetic-vector", "sourceRevision": "synthetic-source", "databaseId": "fixture"}
    for field, expression, old_expression in _vectors():
        packet = {field: {**header, "primaryRoots": [{"raw": "primary"}], "countedRoots": [{"raw": "counted"}]}}
        vector_checks.append(f"""
    sxe_packet := {_json(packet)};
    IF {expression} IS DISTINCT FROM {_json(header)}
    THEN RAISE EXCEPTION 'actual vector stripping changed its header'; END IF;
    sxe_packet := pg_catalog.jsonb_set(sxe_packet, ARRAY[{_literal(field)}, 'databaseId'], '"changed"'::jsonb);
    IF {expression} IS NOT DISTINCT FROM {_json(header)}
    THEN RAISE EXCEPTION 'vector header mismatch was accepted'; END IF;
    caught := FALSE;
    BEGIN
        PERFORM {old_expression};
    EXCEPTION WHEN SQLSTATE '42725' THEN caught := TRUE;
    END;
    IF NOT caught THEN RAISE EXCEPTION 'original vector ambiguity control did not fail42725'; END IF;
""")
    return f"""\\set ON_ERROR_STOP on
BEGIN;
SET LOCAL statement_timeout = '20s';
SET LOCAL lock_timeout = '2s';
CREATE SCHEMA {NAMESPACE};
CREATE TABLE {NAMESPACE}.{table} ({columns});
CREATE TABLE {NAMESPACE}.policy_native_canary_heads (canary_id text);
CREATE FUNCTION {NAMESPACE}.exercise_hold(supplied_operation text, supplied_mutations jsonb, use_old boolean)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog AS $hold_component$
DECLARE capability record; planner record;
BEGIN
    SELECT supplied_operation AS operation INTO capability;
    SELECT supplied_mutations::text AS mutation_plan_json INTO planner;
    IF use_old THEN
        {old_guard}
    ELSE
        {guard}
    END IF;
END;
$hold_component$;
DO $hold_checks$
DECLARE caught boolean; sxe_packet jsonb;
BEGIN
    IF pg_catalog.current_setting('server_version_num')::integer NOT BETWEEN 160000 AND 169999
        OR pg_catalog.getdatabaseencoding() <> 'UTF8' OR pg_catalog.inet_server_addr() IS NOT NULL
    THEN RAISE EXCEPTION 'component requires PostgreSQL16 UTF8 over a Unix socket'; END IF;
    {call('webauthn.challenge.create', ordinary)}
    caught := FALSE;
    BEGIN
        {call('webauthn.challenge.create', ordinary, old=True)}
    EXCEPTION WHEN SQLSTATE '42725' THEN caught := TRUE;
    END;
    IF NOT caught THEN RAISE EXCEPTION 'original hold ambiguity control did not fail42725'; END IF;
    {insert}
    {call('webauthn.challenge.create', audit)}
    {call('native-policy-activation.record-inclusion', inclusion)}
    {call('native-policy-activation.finalize', finalization)}
    {''.join(refusals)}
    IF (SELECT pg_catalog.count(*) FROM {NAMESPACE}.{table} WHERE phase = 'held'
            AND expires_at_epoch_ns = 2) <> 1
    THEN RAISE EXCEPTION 'guard fixture unexpectedly changed or expired the hold'; END IF;
    {''.join(vector_checks)}
END;
$hold_checks$;
ROLLBACK;
SELECT 'jsonb precedence component: hold/old42725/five refusals/two vectors OK' AS result;
"""


class JsonbExtractionSourceControls(unittest.TestCase):
    def test_complete_actual_hold_keeps_guards_and_only_groups_extraction(self):
        guard, old, _table, _scope, fields = _hold()
        self.assertEqual(guard.replace("((m->'row') -", "(m->'row' -"), old)
        self.assertEqual(len(fields), 12)
        self.assertIn("IN EXCLUSIVE MODE", guard)
        self.assertIn("h.phase = 'held'", guard)
        self.assertIn("m->'expectedRow' = to_jsonb(h)", guard)
        self.assertIn("native-policy-activation.record-inclusion", guard)
        self.assertIn("f->'row'->>'finalization_digest' = m->'row'->>'finalization_digest'", guard)

    def test_both_actual_successor_vector_expressions_have_same_narrow_fix(self):
        values = _vectors()
        self.assertEqual(tuple(item[0] for item in values), ("beforeVector", "afterVector"))
        for field, fixed, old in values:
            self.assertEqual(fixed.replace("((sxe_packet->'" + field + "')", "(sxe_packet->'" + field + "'"), old)

    def test_emitted_native_controls_are_rollback_only_and_keep_exact_fragments(self):
        program = postgres_sql()
        self.assertIn(_hold()[0], program)
        self.assertIn(_hold()[1], program)
        self.assertEqual(program.count("WHEN SQLSTATE '42725'"), 3)
        self.assertEqual(program.count("WHEN SQLSTATE 'P0001'"), 5)
        self.assertIn("ROLLBACK;", program)
        self.assertNotIn("COMMIT;", program)
        self.assertNotIn("catchplate.authority_transition_registry", sys.modules)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-postgres-sql", action="store_true")
    arguments = parser.parse_args()
    if arguments.emit_postgres_sql:
        sys.stdout.write(postgres_sql())
    else:
        unittest.main(argv=[sys.argv[0]])
