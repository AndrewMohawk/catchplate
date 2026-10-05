#!/usr/bin/env python3
"""Source-fragment controls only: no SQL execution or authority admission."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_contract as authority
from serverware import authority_current_root_vector as vector
from serverware.authority_store import challenge_maintenance_effects_sql as effects
from serverware.authority_store import current_root_execution_sql as execution
from serverware.authority_store import mutation_sql


NAMESPACE = '"fixture"'


class ChallengeExecutionSQLSourceTests(unittest.TestCase):
    def test_aggregate_keeps_exact_shared_fragments_and_original_effect_order(self):
        header, heads, operations = execution._source()
        parts = (execution._setup_sql(NAMESPACE, header, heads, operations),
            execution._aggregate_inputs_sql(NAMESPACE),
            execution._vectors_marker_sql(NAMESPACE), execution._locked_before_sql(NAMESPACE),
            execution._aggregate_effects_sql(NAMESPACE), execution._finish_sql(NAMESPACE))
        rendered = execution.current_root_execution_apply_body_sql(NAMESPACE)
        self.assertEqual(rendered, "".join(parts))
        self.assertIn("jsonb_typeof(crx_selected_rows)", parts[1])
        self.assertIn("jsonb_typeof(crx_mutations)", parts[1])
        self.assertIn("crx_work_units >", parts[1])
        self.assertIn("source limits", parts[1])
        positions = [rendered.index(value) for value in (
            "successor same-call operation inputs differ",
            "successor marker sequence or fence is invalid",
            "successor actual locked before vector changed",
            "successor selected row changed under its lock",
            "Keep genuine semantic replay order",
            "WITH ORDINALITY AS item(value, ordinal) ORDER BY item.ordinal",
            "successor actual maintained after vector differs",
            "successor immutable marker insertion was not exact")]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(rendered.count(mutation_sql.apply_mutation_sql(NAMESPACE)), 1)

    def test_begin_is_literal_maintain_and_reuses_exact_shared_admission_fragments(self):
        header, heads, operations = execution._source()
        selected = {effects.OPERATION: operations[effects.OPERATION]}
        rendered = execution.maintenance_execution_begin_sql(NAMESPACE)
        self.assertTrue(rendered.startswith(execution._maintenance_only_sql()))
        self.assertLess(rendered.index("maintenance execution operation is not source fixed"),
            rendered.index("crx_source :="))
        self.assertIn(execution._setup_sql(NAMESPACE, header, heads, selected), rendered)
        for part in (execution._operation_inputs_sql(NAMESPACE),
                execution._vectors_marker_sql(NAMESPACE), execution._locked_before_sql(NAMESPACE)):
            self.assertEqual(rendered.count(part), 1)
        self.assertNotIn('"webauthn.challenge.create":', rendered)
        for template in authority.operation_spec(effects.OPERATION)["mutationTemplates"]:
            self.assertIn(template["templateId"], rendered)
        for forbidden in ("crx_selected_rows", "crx_mutations", "crx_work_units",
                "FOR mutation IN", "INSERT INTO"):
            self.assertNotIn(forbidden, rendered)

    def test_begin_locks_complete_original_vectors_and_every_marker_identity(self):
        rendered = execution.maintenance_execution_begin_sql(NAMESPACE)
        self.assertIn("IN SHARE ROW EXCLUSIVE MODE", rendered)
        self.assertEqual(rendered.count(execution._observe_sql(NAMESPACE)), 1)
        for table in vector.PRIMARY_TABLES:
            self.assertIn("'" + table + "'", rendered)
        for identity in vector.INDEX_IDS:
            self.assertIn("'" + identity + "'", rendered)
        for required in ("ORDER BY table_name COLLATE \"C\" LIMIT",
                "ORDER BY index_id COLLATE \"C\" LIMIT", "FOR UPDATE",
                "crx_actual_json IS DISTINCT FROM crx_before_vector_json",
                "marker.pending_decision_digest", "marker.pending_request_digest",
                "marker.enrollment_digest", "marker.fence", "marker.operation_id",
                "marker.capability_digest"):
            self.assertIn(required, rendered)
        self.assertLess(rendered.index("successor actual locked before vector changed"),
            rendered.index("successor marker identity is already used"))

    def test_finish_requires_complete_after_vector_before_exactly_one_marker_insert(self):
        rendered = execution.maintenance_execution_finish_sql(NAMESPACE)
        self.assertEqual(rendered,
            execution._maintenance_only_sql() + execution._finish_sql(NAMESPACE))
        self.assertEqual(rendered.count(execution._observe_sql(NAMESPACE)), 1)
        self.assertEqual(rendered.count("INSERT INTO"), 1)
        self.assertEqual(rendered.count("GET DIAGNOSTICS matched_count = ROW_COUNT;"), 1)
        for column in authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS:
            self.assertIn(column, rendered)
        self.assertLess(rendered.index("crx_actual_json IS DISTINCT FROM crx_after_vector_json"),
            rendered.index("INSERT INTO"))
        self.assertLess(rendered.index("INSERT INTO"), rendered.index("GET DIAGNOSTICS"))
        self.assertIn("matched_count <> 1 OR crx_inserted IS DISTINCT FROM crx_marker", rendered)
        self.assertEqual(rendered.count(execution._live_sql()), 2)
        for forbidden in ("crx_selected_rows", "crx_mutations", "crx_work_units",
                "ON CONFLICT", "EXCEPTION WHEN", "COMMIT;", "ROLLBACK;",
                "set_config(", "crx_deadline_epoch_ns :="):
            self.assertNotIn(forbidden, rendered)

    def test_actual_maintenance_source_guard_refuses_changed_write_template_or_profile(self):
        original = authority.operation_spec
        for field, value in (("businessWrites", ("webauthn_challenges", "audit_log")),
                ("maximumMutations", 257), ("mutationTemplates", ())):
            changed = deepcopy(original(effects.OPERATION))
            changed[field] = value
            def selected(operation, changed=changed):
                return changed if operation == effects.OPERATION else original(operation)
            with self.subTest(field=field), patch.object(authority, "operation_spec", selected):
                with self.assertRaisesRegex(ValueError, "effect source inventory changed"):
                    execution.maintenance_execution_begin_sql(NAMESPACE)
        ids = effects.projection.index_ids_for_table(effects.TABLE)
        with patch.object(effects.projection, "index_ids_for_table", return_value=ids[:-1]):
            with self.assertRaisesRegex(ValueError, "effect source inventory changed"):
                execution.maintenance_execution_begin_sql(NAMESPACE)

    def test_namespace_and_transaction_deadline_remain_closed_without_installer(self):
        for render in (execution.current_root_execution_apply_body_sql,
                execution.maintenance_execution_begin_sql, execution.maintenance_execution_finish_sql):
            for namespace in (None, "public", '"a"."b"', '"a";SELECT 1'):
                with self.subTest(render=render.__name__, namespace=namespace), self.assertRaises(ValueError):
                    render(namespace)
        rendered = execution.maintenance_execution_begin_sql(NAMESPACE)
        for required in ("server_version_num", "'serializable'", "transaction_read_only",
                "transaction_deferrable", "lock_timeout", "statement_timeout",
                "idle_in_transaction_session_timeout", ">= crx_deadline_epoch_ns"):
            self.assertIn(required, rendered)
        for forbidden in ("CREATE ", "GRANT ", "REVOKE ", "SET ROLE", "set_config(",
                "COMMIT;", "ROLLBACK;", "EXCEPTION WHEN", "crx_deadline_epoch_ns :="):
            self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()
