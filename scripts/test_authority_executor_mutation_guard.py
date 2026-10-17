#!/usr/bin/env python3
"""Actual write-set guard regression, not full executor/pilot admission.

Stdlib/source extraction only. --emit-postgres-sql emits a rollback-only
component for an externally owned isolated PostgreSQL16.14 Unix socket.
The full guard, two table declarations and wire/digest helpers are actual
source. Synthetic capability/planner records represent already-admitted
inputs. Three table CHECKs are deliberately removed only inside this rolled
back fixture to prove the guard independently rejects corrupted catalog pins.
No connection, container, production import or business mutation occurs here.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import unittest

import test_authority_executor_optional_evidence as source


SCHEMA = "catchplate_mutation_guard_component"
NAMESPACE = '"' + SCHEMA + '"'
LABEL = "executor_state"
TABLE = "policy_authority_operation_mutation_templates"
DEPENDENCY = "policy_authority_query_dependency_manifests"
DENIAL = "authority v9 mutation is outside the write set"
OLD_GUARD_SHA256 = "37b161353385d6c515290632bb0377992a78d4251347eb7b693e89a1f95a9d81"


def _literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _source_revision():
    tree = source._read("catchplate/authority_contract.py")
    return source._one([ast.literal_eval(node.value) for node in tree.body
        if type(node) is ast.Assign and len(node.targets) == 1
        and type(node.targets[0]) is ast.Name and node.targets[0].id == "SOURCE_REVISION"])


def _closed_record():
    tree = source._read("catchplate/authority_store/mutation_sql.py")
    roster = source._one([ast.literal_eval(node.value) for node in tree.body
        if type(node) is ast.Assign and len(node.targets) == 1
        and type(node.targets[0]) is ast.Name and node.targets[0].id == "_RECORD_FIELDS"])
    function = source._one([node for node in tree.body
        if type(node) is ast.FunctionDef and node.name == "closed_record_sql"])
    template = source._one([node for node in ast.walk(function) if type(node) is ast.JoinedStr])
    return source._template(template, dict(record="mutation",
        fields=", ".join(_literal(field) for field in roster["mutation"]))).strip()


def _guard_parts():
    tree = source._read("catchplate/authority_store/executor_v9.py")
    function = source._one([node for node in tree.body if type(node) is ast.FunctionDef
        and node.name == "install_authority_v9_executor"])
    template = source._one([source._template(node) for node in ast.walk(function)
        if type(node) is ast.JoinedStr and any(type(part) is ast.Constant
            and type(part.value) is str and "AS $catchplate_execute_v9$" in part.value
            for part in node.values)])
    if len(re.findall(r"AS \$catchplate_execute_v9\$\s+<<" + LABEL + r">>\s+DECLARE", template)) != 1:
        raise ValueError("actual executor outer block label changed")
    start = template.index("IF NOT {closed_record_sql(", template.index("FOR mutation IN"))
    end = template.index("END IF;", start) + len("END IF;")
    fixed = template[start:end]
    qualifier = LABEL + ".mutation"
    if fixed.count(qualifier) != 3 or template.count(qualifier) != 3:
        raise ValueError("actual executor qualification is not exactly three references")
    old = fixed.replace(qualifier, "mutation")
    if source._normalized_sha(old) != OLD_GUARD_SHA256:
        raise ValueError("write-set predicate changed beyond three variable qualifications")
    substitutions = {"{closed_record_sql('mutation')}": _closed_record(),
        "{namespace}": NAMESPACE, "{source_revision}": _source_revision()}
    for name, replacement in substitutions.items():
        fixed, old = fixed.replace(name, replacement), old.replace(name, replacement)
    if "{" in fixed or "{" in old:
        raise ValueError("actual guard gained an unknown source interpolation")
    return fixed, old


def _table(relative, table):
    tree = source._read(relative)
    expression = r"CREATE TABLE IF NOT EXISTS\s+" + table + r" \(.*?\n\s+\);"
    declaration = source._one([match for node in ast.walk(tree)
        if type(node) is ast.Constant and type(node.value) is str
        for match in re.findall(expression, node.value, re.S)])
    if "__MAX_" in declaration or "{" in declaration:
        raise ValueError("component table acquired an unresolved source substitution")
    return declaration.replace(table + " (", NAMESPACE + "." + table + " (", 1)


def postgres_sql():
    fixed, old = _guard_parts()
    wire, digest = source._actual_helpers()
    wire, digest = wire.replace(source.NAMESPACE, NAMESPACE), digest.replace(source.NAMESPACE, NAMESPACE)
    template_ddl = _table("catchplate/authority_store/v9_schema_source.py", TABLE)
    dependency_ddl = _table("catchplate/authority_store/metadata_schema_source.py", DEPENDENCY)
    revision = _source_revision()
    operation, table, template_id = "webauthn.challenge.create", "webauthn_challenges", "synthetic-template"
    manifest = "sha256:" + "a" * 64
    key = {"id": "synthetic-challenge"}
    framed = (b"catchplate.policyAuthorityBusinessKey/v1\0"
        + len(table.encode()).to_bytes(8, "big") + table.encode()
        + len(_canonical(key).encode()).to_bytes(8, "big") + _canonical(key).encode())
    mutation = dict(expectedRow=None, key=key, keyDigest="sha256:" + hashlib.sha256(framed).hexdigest(),
        operation="INSERT", row=key, table=table, templateId=template_id)
    selected = [dict(table=table, key=key)]

    def call(name="exercise_fixed", value=None, rows=None):
        return (f"PERFORM {NAMESPACE}.{name}(" + _literal(_canonical(mutation if value is None else value))
            + "::jsonb," + _literal(_canonical(selected if rows is None else rows)) + "::jsonb);")

    def function(name, guard):
        return f"""
CREATE FUNCTION {NAMESPACE}.{name}(supplied_mutation jsonb, supplied_selected jsonb)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, {NAMESPACE}, pg_temp AS $component$
<<{LABEL}>>
DECLARE mutation jsonb := supplied_mutation; capability record; planner record;
BEGIN
    SELECT {_literal(operation)}::text AS operation,
        {_literal(manifest)}::text AS operation_manifest_digest INTO capability;
    SELECT supplied_selected::text AS selected_business_rows_json INTO planner;
    {guard}
END;
$component$;
"""

    def refusal(label, setup="", statement=None, cleanup=""):
        return f"""
    {setup}
    caught := FALSE;
    BEGIN
        {call() if statement is None else statement}
    EXCEPTION WHEN SQLSTATE 'P0001' THEN
        IF SQLERRM <> {_literal(DENIAL)} THEN RAISE; END IF;
        caught := TRUE;
    END;
    IF NOT caught THEN RAISE EXCEPTION 'component refusal missing: {label}'; END IF;
    {cleanup}
"""

    negatives = []
    for label, field, original, bad in (
        ("template", "template_id", template_id, "different-template"),
        ("table", "table_name", table, "different-table"),
        ("operation", "operation", operation, "different-operation"),
        ("predicate", "predicate_kind", "exact-primary-key-and-full-row-cas-v1", "different-predicate"),
        ("cardinality", "cardinality", 1, 2),
        ("source-pin", "source_revision", revision, "different-source"),
        ("manifest-pin", "operation_manifest_digest", manifest, "different-manifest"),
        ("canonical-template", "template_json", "{}", "{ }"),
    ):
        negatives.append(refusal(label,
            f"UPDATE {NAMESPACE}.{TABLE} SET {field}={_literal(bad)};",
            cleanup=f"UPDATE {NAMESPACE}.{TABLE} SET {field}={_literal(original)};"))
    negatives.append(refusal("mutation-operation", statement=call(value={**mutation, "operation": "UPDATE"})))
    negatives.append(refusal("write-set", f"UPDATE {NAMESPACE}.{DEPENDENCY} SET write_access=0;",
        cleanup=f"UPDATE {NAMESPACE}.{DEPENDENCY} SET write_access=1;"))
    negatives.append(refusal("selected-key", statement=call(rows=[])))
    negatives.append(refusal("key-digest", statement=call(value={**mutation, "keyDigest": "sha256:" + "0" * 64})))
    return f"""\\set ON_ERROR_STOP on
BEGIN;
SET LOCAL statement_timeout = '15s';
SET LOCAL lock_timeout = '1s';
SET LOCAL plpgsql.variable_conflict = 'error';
CREATE SCHEMA {NAMESPACE};
{wire}
{digest};
{template_ddl}
{dependency_ddl}
INSERT INTO {NAMESPACE}.{TABLE} VALUES (
    {_literal(operation)}, {_literal(template_id)}, {_literal(table)}, 'INSERT', 'absent', 'present',
    'exact-primary-key-and-full-row-cas-v1', 1, '{{}}', {_literal(manifest)}, {_literal(revision)});
INSERT INTO {NAMESPACE}.{DEPENDENCY} VALUES (
    {_literal(operation)}, 1, 'synthetic-predicate', {_literal(table)}, 'synthetic-handler', '["id"]',
    1, 'incremental-authenticated-relation-root-v3', 'relation-root-and-explicit-key-set',
    'closed-operation-argument-path-v1', '[]', 'radix16-canonical-multiproof-v2', 1, 1,
    'synthetic-entry', 'synthetic-manifest', {_literal(revision)});
{function('exercise_old', old)}
{function('exercise_fixed', fixed)}
DO $checks$
DECLARE caught boolean; constraint_row record; removed integer := 0;
BEGIN
    IF pg_catalog.current_setting('server_version_num')::integer <> 160014
        OR pg_catalog.getdatabaseencoding() <> 'UTF8' OR pg_catalog.inet_server_addr() IS NOT NULL
    THEN RAISE EXCEPTION 'component requires PostgreSQL16.14 UTF8 over a Unix socket'; END IF;
    caught := FALSE;
    BEGIN
        {call('exercise_old')}
    EXCEPTION WHEN SQLSTATE '42702' THEN caught := TRUE;
    END;
    IF NOT caught THEN RAISE EXCEPTION 'original guard did not fail42702'; END IF;
    {call()}
    -- Fixture-only corrupted-catalog injection; the actual source CHECKs above
    -- initially admitted the valid row. Production DDL is not altered.
    FOR constraint_row IN
        SELECT c.conname FROM pg_catalog.pg_constraint AS c
        JOIN pg_catalog.pg_attribute AS a ON a.attrelid=c.conrelid
            AND c.conkey=ARRAY[a.attnum]::smallint[]
        WHERE c.conrelid='{SCHEMA}.{TABLE}'::regclass AND c.contype='c'
            AND a.attname IN ('predicate_kind','cardinality','source_revision')
    LOOP
        EXECUTE pg_catalog.format('ALTER TABLE %I.%I DROP CONSTRAINT %I',
            '{SCHEMA}', '{TABLE}', constraint_row.conname);
        removed := removed + 1;
    END LOOP;
    IF removed <> 3 THEN RAISE EXCEPTION 'component source constraint roster changed'; END IF;
    {''.join(negatives)}
    {call()}
END;
$checks$;
ROLLBACK;
SELECT 'mutation guard component: old42702/fixed valid/twelve refusals OK' AS result;
"""


class MutationGuardSourceControls(unittest.TestCase):
    def test_actual_guard_changes_only_three_variable_qualifications(self):
        fixed, old = _guard_parts()
        self.assertEqual(fixed.replace(LABEL + ".mutation", "mutation"), old)
        self.assertEqual(fixed.count(LABEL + ".mutation"), 3)
        self.assertIn("template.mutation =", fixed)
        self.assertIn("template.cardinality = 1", fixed)
        self.assertIn("template.source_revision =", fixed)

    def test_actual_relation_column_is_the_conflict_and_shared_helpers_are_real(self):
        declaration = _table("catchplate/authority_store/v9_schema_source.py", TABLE)
        self.assertIn("mutation TEXT NOT NULL", declaration)
        self.assertIn("CHECK (cardinality = 1)", declaration)
        self.assertIn("jsonb_object_keys(mutation)", _closed_record())
        self.assertNotIn("catchplate.authority_transition_registry", sys.modules)

    def test_native_program_retains_full_old_and_fixed_guard_and_rolls_back(self):
        program = postgres_sql()
        fixed, old = _guard_parts()
        self.assertIn(fixed, program)
        self.assertIn(old, program)
        self.assertEqual(program.count("WHEN SQLSTATE '42702'"), 1)
        self.assertEqual(program.count("WHEN SQLSTATE 'P0001'"), 12)
        _wire, digest = source._actual_helpers()
        self.assertIn(digest.replace(source.NAMESPACE, NAMESPACE) + ";\nCREATE TABLE", program)
        self.assertIn("ROLLBACK;", program)
        self.assertNotIn("COMMIT;", program)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-postgres-sql", action="store_true")
    arguments = parser.parse_args()
    if arguments.emit_postgres_sql:
        sys.stdout.write(postgres_sql())
    else:
        unittest.main(argv=[sys.argv[0]])
