#!/usr/bin/env python3
"""Source/rendering controls, NOT PostgreSQL execution or count authority.

These call the real renderer and inspect its source-owned inventory, explicit
guards and ordering. They cannot establish PL/pgSQL syntax, SQL branch behavior,
transaction locking, initialization, root authenticity/currentness or delivery.
The separate native PostgreSQL fixture must execute the actual rendered guard.
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

from serverware import authority_contract
from serverware.authority_primary_contract import PRIMARY_KEY_COLUMNS
from serverware.authority_store.audit_capacity_sql import (
    AUDIT_CAPACITY_FUNCTION_NAME,
    AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES,
    MAX_COUNTER_BYTES,
    assert_audit_capacity_sql,
    audit_capacity_function_sql,
)


AGGREGATE = "policy_authority_bounded_aggregate_states"
OUTBOX = "metadata_audit_outbox"
KIND = "metadata-audit-outbox-global-capacity-v1"
ROW_FIELDS = {
    "aggregate_id", "aggregate_kind", "partition_digest", "revision",
    "live_count", "active_count", "capacity_limit", "reserved_units_json",
    "committed_units_json", "next_sequence", "minimum_expiry_epoch_ns",
    "expiry_index_root_digest", "work_page_id", "state_json", "state_digest",
    "updated_at_epoch_ns", "source_revision",
}


def render(namespace='"fixture"', **overrides):
    arguments = {
        "operation_sql": "capability.operation",
        "selected_rows_sql": "planner.selected_business_rows_json::pg_catalog.jsonb",
        "mutations_sql": "planner.mutation_plan_json::pg_catalog.jsonb",
        "work_units_sql": "planner.work_units",
    }
    arguments.update(overrides)
    return assert_audit_capacity_sql(namespace, **arguments)


def contract_literal(sql):
    prefix = "ac_contract constant pg_catalog.jsonb := '"
    start = sql.index(prefix) + len(prefix)
    end = sql.index("'::pg_catalog.jsonb;", start)
    return json.loads(sql[start:end].replace("''", "'"))


class GlobalAuditCapacitySqlSourceTests(unittest.TestCase):
    def setUp(self):
        self.sql = render()

    def test_source_contract_is_complete_and_contains_no_database_labels(self):
        inventory = contract_literal(self.sql)
        self.assertEqual(set(inventory), set(authority_contract.OPERATIONS))
        for operation, entry in inventory.items():
            with self.subTest(operation=operation):
                spec = authority_contract.operation_spec(operation)
                tables = set(spec["businessReads"]) | set(spec["businessWrites"]) | set(spec["authorizationReads"])
                self.assertEqual(entry, {
                    "participates": OUTBOX in spec["businessWrites"],
                    "counterPermission": (
                        AGGREGATE in spec["businessWrites"]
                        and "aggregate-high-water" in spec["proofPrimitives"]
                        and any(item["table"] == AGGREGATE and item["mutation"] == "UPDATE"
                            for item in spec["mutationTemplates"])
                    ),
                    "maximumQueryRows": spec["maximumQueryRows"],
                    "maximumMutations": spec["maximumMutations"],
                    "maximumBusinessQueryRows": spec["maximumBusinessQueryRows"],
                    "maximumBusinessMutations": spec["maximumBusinessMutations"],
                    "maximumBusinessWorkUnits": spec["maximumBusinessWorkUnits"],
                    "keys": {table: sorted(PRIMARY_KEY_COLUMNS[table]) for table in tables},
                    "templates": {item["templateId"]: {
                        "table": item["table"], "mutation": item["mutation"],
                        "predicate": item["predicate"], "cardinality": item["cardinality"],
                    } for item in spec["mutationTemplates"]},
                })
        self.assertNotRegex(self.sql, r'FROM "fixture"\.(?!serverware_policy_authority_wire_walk\s*\()[a-z_]')
        self.assertNotIn("policy_authority_operation_mutation_templates", self.sql)

    def test_rendering_is_deterministic_and_namespace_is_closed(self):
        self.assertEqual(self.sql, render())
        alternate = render('"other_fixture"')
        self.assertEqual(alternate, self.sql.replace('"fixture".', '"other_fixture".'))
        for invalid in (None, "fixture", '"UPPER"', '"one"."two"', '"has-space "'):
            with self.subTest(namespace=invalid):
                with self.assertRaisesRegex(ValueError, "exact quoted identifier"):
                    render(invalid)
                with self.assertRaisesRegex(ValueError, "exact quoted identifier"):
                    audit_capacity_function_sql(invalid)

    def test_only_source_variables_are_accepted_as_input_expressions(self):
        self.assertIn("ac_operation text := operation_name;", render(operation_sql="operation_name"))
        self.assertIn("ac_selected pg_catalog.jsonb := selected_rows;", render(selected_rows_sql="selected_rows"))
        for name in ("operation_sql", "selected_rows_sql", "mutations_sql", "work_units_sql"):
            for invalid in (None, "", "%s", "input + other", "'literal'", "call()", "a.b.c", "input;", " input"):
                with self.subTest(name=name, value=invalid):
                    with self.assertRaisesRegex(ValueError, "exact SQL variable"):
                        render(**{name: invalid})
        with self.assertRaisesRegex(ValueError, "exact SQL variable"):
            render(operation_sql="operation_name::pg_catalog.jsonb")

    def test_installed_function_reuses_the_same_guard_without_parameter_interpolation(self):
        body = assert_audit_capacity_sql('"fixture"', operation_sql="supplied_operation",
            selected_rows_sql="supplied_selected_rows", mutations_sql="supplied_mutations",
            work_units_sql="supplied_work_units")
        installed = audit_capacity_function_sql('"fixture"')
        self.assertEqual(installed.count(body), 1)
        self.assertEqual(AUDIT_CAPACITY_FUNCTION_NAME, "serverware_policy_authority_assert_audit_capacity")
        self.assertIn(f'CREATE OR REPLACE FUNCTION "fixture".{AUDIT_CAPACITY_FUNCTION_NAME}(', installed)
        self.assertRegex(installed, r"supplied_operation text,\s+supplied_selected_rows pg_catalog\.jsonb,\s+supplied_mutations pg_catalog\.jsonb,\s+supplied_work_units bigint")
        self.assertIn("RETURNS void", installed)
        self.assertIn("SECURITY INVOKER", installed)
        self.assertNotIn("SECURITY DEFINER", installed)
        header = installed.split("AS $serverware_audit_capacity$", 1)[0]
        self.assertNotRegex(header, r"\bSTRICT\b")  # SQL NULL inputs must reach rejecting guards.
        self.assertNotIn("DO $", installed)
        self.assertNotIn("%s", installed)

    def test_planner_invoker_dependencies_are_an_exact_read_only_signature_set(self):
        self.assertEqual(AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES, (
            ("serverware_policy_authority_assert_audit_capacity", ("text", "jsonb", "jsonb", "bigint")),
            ("serverware_policy_authority_domain_digest", ("text", "text[]")),
            ("serverware_policy_authority_wire_json", ("jsonb",)),
            ("serverware_policy_authority_wire_string", ("text", "boolean", "bigint")),
            ("serverware_policy_authority_wire_walk", ("jsonb", "integer", "bigint", "bigint", "boolean")),
        ))
        db_source = (ROOT / "serverware/db.py").read_text(encoding="utf-8")
        db_tree = ast.parse(db_source)
        seal = next(node for node in db_tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_seal_postgres_schema_acl")
        seal_source = ast.get_source_segment(db_source, seal)
        for guard in ("!= AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES",
                      "AND NOT grant_entry.is_grantable", "or not exact_planner_functions"):
            self.assertIn(guard, seal_source)
        unexpected = next(node for node in ast.walk(seal) if isinstance(node, ast.Assign)
                          and any(isinstance(target, ast.Name) and target.id == "unexpected_function"
                                  for target in node.targets))
        unexpected_source = ast.get_source_segment(db_source, unexpected)
        # PUBLIC's grantee 0 has no pg_roles row. Its NULL role-name must
        # resolve to denied, not disappear through NOT(NULL) in the WHERE.
        self.assertIn('"LEFT JOIN pg_catalog.pg_roles AS grantee "', unexpected_source)
        self.assertIn('"AND NOT COALESCE(("', unexpected_source)
        self.assertIn('"), FALSE) LIMIT 1"', unexpected_source)
        schema_source = (ROOT / "serverware/authority_store/schema.py").read_text(encoding="utf-8")
        self.assertIn('"authorityPlannerWriterFunctionSignatures"', schema_source)
        self.assertEqual(schema_source.count("authority_planner_writer_function_signatures=("), 2)
        self.assertEqual(db_source.count("authority_planner_writer_function_signatures=("), 1)

    def test_executor_wiring_preserves_historical_inputs_and_narrow_ddl_budgets(self):
        # Source wiring only: neither importing the registry nor substituting
        # a database connection proves a successful planner transaction.
        source = (ROOT / "serverware/authority_store/executor_v9.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        self.assertNotIn("authority_v9_schema_source", functions)
        aliases = [alias for node in tree.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware.authority_store.v9_schema_source"
                   for alias in node.names]
        self.assertEqual([(alias.name, alias.asname) for alias in aliases],
                         [("authority_v9_schema_source", None)])
        ddl_path = ROOT / "serverware/authority_store/v9_schema_source.py"
        self.assertLessEqual(ddl_path.stat().st_size, 2 * 1024 * 1024)
        ddl_source = ddl_path.read_text(encoding="utf-8")
        ddl_tree = ast.parse(ddl_source)
        ddl_functions = [node for node in ddl_tree.body if isinstance(node, ast.FunctionDef)
                         and node.name == "authority_v9_schema_source"]
        self.assertEqual(len(ddl_functions), 1)
        ddl = ast.get_source_segment(ddl_source, ddl_functions[0])
        self.assertEqual(ddl.count(authority_contract.SOURCE_REVISION), 17)
        self.assertNotIn("2026-07-30.24", ddl)
        self.assertIn("length(selected_business_rows_json)\n                    BETWEEN 2 AND __MAX_PLAN_SELECTED_BYTES__", ddl)
        self.assertIn("CHECK (work_units BETWEEN 1 AND __MAX_PLAN_WORK_UNITS__)", ddl)
        self.assertIn('str(authority_contract.MAX_PLAN_SELECTED_BYTES)', ddl)
        self.assertIn('str(authority_contract.MAX_PLAN_WORK_UNITS)', ddl)
        self.assertIn("CHECK (exact_request_byte_count BETWEEN 2 AND 4194304)", ddl)
        installed = ast.get_source_segment(source, functions["install_authority_v9_executor"])
        loaded = installed.index("{load_root_transition_sql(namespace)}")
        guarded = installed.index("PERFORM {namespace}.{AUDIT_CAPACITY_FUNCTION_NAME}(")
        replay = installed.index("IF capability.status = 'committed' THEN")
        self.assertLess(loaded, guarded)
        self.assertLess(guarded, replay)
        self.assertIn("planner.selected_business_rows_json::pg_catalog.jsonb", installed[guarded:replay])
        self.assertIn("planner.mutation_plan_json::pg_catalog.jsonb", installed[guarded:replay])
        self.assertIn("planner.work_units", installed[guarded:replay])
        for name, dml in (("reserve_authority_planner_transaction", "INSERT INTO serverware_metadata."),
                          ("complete_authority_planner_transaction", "UPDATE serverware_metadata.")):
            method = ast.get_source_segment(source, functions[name])
            self.assertEqual(method.count("authority_audit_capacity.validate_capacity_transition("), 1)
            self.assertEqual(method.count("authority_audit_capacity.validate_transition_work_units("), 1)
            self.assertEqual(method.count("{AUDIT_CAPACITY_FUNCTION_NAME}(%s,%s::jsonb,%s::jsonb,%s)"), 1)
            self.assertLess(method.index("authority_audit_capacity.validate_capacity_transition("),
                            method.index("{AUDIT_CAPACITY_FUNCTION_NAME}(%s"))
            self.assertLess(method.index("{AUDIT_CAPACITY_FUNCTION_NAME}(%s"), method.index(dml))

    def test_selected_source_keys_presence_and_uniqueness_are_explicit(self):
        for guard in (
            "ac_spec->'keys' ? (ac_selection->>'table')",
            "jsonb_object_keys(ac_selection->'key')",
            "IS DISTINCT FROM ac_spec->'keys'->(ac_selection->>'table')",
            "CASE ac_selection->'present'",
            "WHEN 'false'::pg_catalog.jsonb THEN",
            "ac_selection->'row' IS NOT DISTINCT FROM 'null'::pg_catalog.jsonb",
            "ac_selection->'row'->ac_key_field IS DISTINCT FROM",
            "GROUP BY item.value->>'table', item.value->'key' HAVING pg_catalog.count(*) <> 1",
            "pg_catalog.octet_length(ac_selection->'key'->>'id') NOT BETWEEN 1 AND 256",
        ):
            self.assertIn(guard, self.sql)
        self.assertIn("selected primary key is not source-exact", self.sql)
        self.assertIn("item.value::text ~ '^-?(0|[1-9][0-9]*)$'", self.sql)
        self.assertLess(self.sql.index("selected presence is not exact"), self.sql.index("FOR ac_mutation IN"))

    def test_entire_inventory_uses_the_shared_bounded_integer_wire_walk(self):
        self.assertIn("serverware_policy_authority_wire_walk(", self.sql)
        self.assertRegex(self.sql, r"jsonb_build_array\(ac_selected, ac_mutations\),\s+128, 1000000, 67108864, FALSE")
        self.assertIn("ac_inventory_bytes NOT BETWEEN 1 AND 67108864", self.sql)
        self.assertLess(self.sql.index("operation bound is exceeded"), self.sql.index("serverware_policy_authority_wire_walk("))
        self.assertLess(self.sql.index("serverware_policy_authority_wire_walk("), self.sql.index("FOR ac_selection IN"))

    def test_full_before_cas_source_templates_and_no_key_moves_precede_arithmetic(self):
        for guard in (
            "ac_template := ac_spec->'templates'->(ac_mutation->>'templateId')",
            "ac_template->'table' IS DISTINCT FROM ac_mutation->'table'",
            "ac_template->'mutation' IS DISTINCT FROM ac_mutation->'operation'",
            "ac_template->>'predicate' IS DISTINCT FROM 'exact-primary-key-and-full-row-cas-v1'",
            "ac_template->'cardinality' IS DISTINCT FROM '1'::pg_catalog.jsonb",
            "ac_mutation->'expectedRow' IS DISTINCT FROM ac_selection->'row'",
            "ac_selection->'present' IS DISTINCT FROM 'false'::pg_catalog.jsonb",
            "ac_selection->'present' IS DISTINCT FROM 'true'::pg_catalog.jsonb",
            "ac_after->ac_key_field IS DISTINCT FROM ac_key->ac_key_field",
        ):
            self.assertIn(guard, self.sql)
        self.assertLess(self.sql.index("mutation moves its key"), self.sql.index("ac_delta := ac_delta +"))

    def test_membership_and_sequence_are_derived_only_from_the_actual_images(self):
        self.assertIn("ac_old_member := CASE WHEN ac_before->>'status' IN ('pending', 'claimed') THEN 1 ELSE 0 END", self.sql)
        self.assertIn("ac_new_member := CASE WHEN ac_after->>'status' IN ('pending', 'claimed') THEN 1 ELSE 0 END", self.sql)
        self.assertIn("ac_delta := ac_delta + ac_new_member - ac_old_member", self.sql)
        self.assertRegex(self.sql, r"IF ac_mutation->>'operation' = 'INSERT' THEN\s+ac_insert_count := ac_insert_count \+ 1")
        self.assertIn("ac_after->'status' IS DISTINCT FROM '\"pending\"'::pg_catalog.jsonb", self.sql)
        self.assertIn("ac_before->>'status' = 'audited'", self.sql)
        self.assertIn("ac_after->'status' IS DISTINCT FROM '\"audited\"'::pg_catalog.jsonb", self.sql)
        self.assertNotIn("supplied_delta", self.sql)
        self.assertNotIn("live_delta", self.sql)

    def test_empty_replay_still_requires_source_permission_and_exact_global_before(self):
        self.assertLess(self.sql.index("operation lacks the source counter contract"), self.sql.index("FOR ac_selection IN"))
        self.assertLess(self.sql.index("participating operation lacks global selection"), self.sql.index("FOR ac_mutation IN"))
        self.assertIn("nonparticipant selected the reserved global row", self.sql)
        self.assertIn("ac_selection->'contractSelector' IS DISTINCT FROM 'null'::pg_catalog.jsonb", self.sql)
        self.assertIn("(ac_outbox_count = 0 AND ac_counter_count <> 0)", self.sql)
        self.assertIn("(ac_outbox_count > 0 AND ac_counter_count <> 1)", self.sql)
        self.assertIn("ELSE pg_catalog.jsonb_build_array(ac_before) END", self.sql)
        self.assertLess(self.sql.index("global profile is invalid"), self.sql.index("IF ac_outbox_count > 0 THEN"))

    def test_business_budgets_exclude_only_the_exact_framework_global_records(self):
        self.assertIn("- CASE WHEN ac_global_selection IS NULL THEN 0 ELSE 1 END", self.sql)
        self.assertIn("pg_catalog.jsonb_array_length(ac_mutations) - ac_counter_count", self.sql)
        self.assertIn("(ac_spec->>'maximumBusinessQueryRows')::bigint", self.sql)
        self.assertIn("(ac_spec->>'maximumBusinessMutations')::bigint", self.sql)
        self.assertLess(self.sql.index("global selection is crossed or absent"), self.sql.index("business selected row bound is exceeded"))
        self.assertLess(self.sql.index("global mutation is crossed or bootstrapped"), self.sql.index("business mutation bound is exceeded"))
        self.assertIn("ac_work_units IS NULL", self.sql)
        self.assertIn("ac_work_units NOT BETWEEN 1 + ac_framework_work", self.sql)
        self.assertIn("(ac_spec->>'maximumBusinessWorkUnits')::bigint + ac_framework_work", self.sql)
        self.assertIn("CASE WHEN ac_outbox_count > 0 THEN 1 ELSE 0 END", self.sql)
        self.assertRegex(self.sql, r"ac_selected, 128, 1000000,\s+4202496, FALSE")
        self.assertRegex(self.sql, r"ac_global_selection, 128, 1000000,\s+8192, FALSE")
        self.assertRegex(self.sql, r"ac_business_selected, 128, 1000000,\s+4194304, FALSE")
        self.assertIn("WHERE NOT (item.value->>'table' = 'policy_authority_bounded_aggregate_states'", self.sql)
        self.assertIn("item.value->'key' = pg_catalog.jsonb_build_object('aggregate_id', ac_id)", self.sql)
        self.assertLess(self.sql.index("nonparticipant selected the reserved global row"),
                        self.sql.index("INTO ac_business_selected"))

    def test_global_counter_aliases_and_bootstrap_are_rejected(self):
        for field in ("aggregate_id", "aggregate_kind", "partition_digest"):
            self.assertIn(f"ac_before->>'{field}'", self.sql)
            self.assertIn(f"ac_after->>'{field}'", self.sql)
        self.assertIn("ac_key->>'aggregate_id' = ac_id", self.sql)
        self.assertIn("ac_mutation->>'operation' IS DISTINCT FROM 'UPDATE'", self.sql)
        self.assertIn("global mutation is crossed or bootstrapped", self.sql)
        self.assertIn(f"'{KIND}:' || ac_partition", self.sql)
        self.assertIn("'serverware.metadataAuditOutboxCapacityPartition/v1', 'global'", self.sql)
        self.assertNotIn("'metadata-audit-outbox-capacity:'", self.sql)

    def test_compact_profile_state_and_framing_are_source_closed(self):
        match = re.search(r"jsonb_object_keys\(ac_row\).*?ARRAY\[([^]]+)\]::text\[\]", self.sql, re.S)
        self.assertIsNotNone(match)
        self.assertEqual(set(re.findall(r"'([^']+)'", match.group(1))), ROW_FIELDS)
        for fragment in (
            "ac_row->'live_count' IS DISTINCT FROM ac_row->'active_count'",
            "ac_row->'capacity_limit' IS DISTINCT FROM '100000'::pg_catalog.jsonb",
            "ac_row->'reserved_units_json' IS DISTINCT FROM pg_catalog.to_jsonb('{}'::text)",
            "ac_row->'committed_units_json' IS DISTINCT FROM pg_catalog.to_jsonb('{}'::text)",
            "ac_row->'minimum_expiry_epoch_ns' IS DISTINCT FROM 'null'::pg_catalog.jsonb",
            "ac_row->'work_page_id' IS DISTINCT FROM 'null'::pg_catalog.jsonb",
            "'serverware.policyAuthorityAggregateExpiryIndex/v1', '[]'",
            "serverware_policy_authority_wire_json(ac_state)",
            "'serverware.policyAuthorityAggregateState/v1', ac_state_text",
            "ac_row->'state_json' IS DISTINCT FROM pg_catalog.to_jsonb(ac_state_text)",
            authority_contract.SOURCE_REVISION,
        ):
            self.assertIn(fragment, self.sql)
        self.assertEqual(MAX_COUNTER_BYTES, 4096)
        self.assertIn("serverware_policy_authority_wire_json(ac_row)) > 4096", self.sql)
        self.assertNotIn("serverware_policy_authority_canonical_json", self.sql)

    def test_exact_numbers_and_derived_bounds_precede_bigint_arithmetic(self):
        self.assertIn("pg_catalog.jsonb_typeof(ac_row->ac_field) IS DISTINCT FROM 'number'", self.sql)
        self.assertIn("'^(0|[1-9][0-9]{0,18})$'", self.sql)
        self.assertIn("(ac_row->>ac_field)::numeric > 9223372036854775807", self.sql)
        self.assertIn("ac_next_count NOT BETWEEN 0 AND 100000", self.sql)
        self.assertIn("ac_next_sequence > 9223372036854775807", self.sql)
        self.assertIn("(ac_after->>'updated_at_epoch_ns')::bigint <", self.sql)
        self.assertLess(self.sql.index("counter is not an exact integer"), self.sql.index("(ac_row->>ac_field)::numeric"))
        self.assertLess(self.sql.index("derived transition is outside its bound"), self.sql.index("'revision', (ac_before->>'revision')::bigint + 1"))
        self.assertIn("ac_after IS DISTINCT FROM ac_expected", self.sql)

    def test_guard_is_read_only_and_has_no_hidden_authority_or_io_import(self):
        self.assertNotRegex(self.sql, r"(?mi)^\s*(INSERT|UPDATE|DELETE|TRUNCATE|CREATE|ALTER|DROP|EXECUTE|COMMIT|ROLLBACK|PERFORM)\b")
        self.assertNotRegex(self.sql, r"\b(clock_timestamp|transaction_timestamp|now|pg_advisory_xact_lock)\s*\(")
        path = ROOT / "serverware/authority_store/audit_capacity_sql.py"
        self.assertLess(path.stat().st_size, 64 * 1024)
        source = path.read_text(encoding="utf-8")
        imports = {node.module for node in ast.walk(ast.parse(source)) if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imports, {
            "__future__", "serverware", "serverware.audit_outbox_contract",
            "serverware.authority_primary_contract", "serverware.authority_store.mutation_sql",
            "serverware.authority_store.wire_json_sql",
        })
        self.assertNotIn("authority_audit_capacity", source)


if __name__ == "__main__":
    unittest.main()
