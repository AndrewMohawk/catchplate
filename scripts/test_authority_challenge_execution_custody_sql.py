#!/usr/bin/env python3
"""Unrun source controls for tentative custody; not PG/authority assurance."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware.authority_store import challenge_execution_custody_sql as custody


NAMESPACE = '"fixture"'


class ChallengeExecutionCustodySQLSourceTests(unittest.TestCase):
    def test_exact_two_table_inventory_and_bounded_text_columns(self):
        sql = custody.installation_sql(NAMESPACE)
        self.assertEqual(custody.STEP_COLUMNS, ("pending_decision_digest", "step_ordinal",
            "descriptor_json", "body_json", "issuer_identity_digest"))
        self.assertEqual(custody.CUSTODY_COLUMNS, ("pending_decision_digest", "packet_digest",
            "packet_json", "issuer_identity_digest"))
        self.assertEqual(sql.count("CREATE TABLE"), 2)
        for table in (custody.STEP_TABLE, custody.CUSTODY_TABLE):
            self.assertIn(NAMESPACE + "." + table, sql)
        self.assertIn("PRIMARY KEY (pending_decision_digest, step_ordinal)", sql)
        self.assertIn("pending_decision_digest TEXT NOT NULL PRIMARY KEY", sql)
        self.assertIn("step_ordinal BETWEEN 0 AND 1547", sql)
        for column, maximum in (("descriptor_json", 512), ("body_json", 4194304),
                ("packet_json", 8388608)):
            self.assertIn(f"octet_length({column}) BETWEEN 2 AND {maximum}", sql)
            self.assertIn(f"length({column}) = pg_catalog.octet_length({column})", sql)
        self.assertEqual(sql.count("~ '^sha256:[0-9a-f]{64}$'"), 5)
        for forbidden in ("FUNCTION", "TRIGGER", "GRANT ", "REVOKE ", "DEFAULT", "IF NOT EXISTS"):
            self.assertNotIn(forbidden, sql)

    def test_original_bounds_precede_parse_and_real_ascii_wire_precedes_shape_use(self):
        sql = custody.step_body_sql(NAMESPACE)
        framing = sql.index("maintenance custody original framing differs")
        parse = sql.index("cxs_descriptor_json::pg_catalog.jsonb")
        wire = sql.index("serverware_policy_authority_wire_walk(")
        typed = sql.index("maintenance custody descriptor is not source closed")
        self.assertLess(framing, parse)
        self.assertLess(parse, wire)
        self.assertLess(wire, typed)
        self.assertEqual(sql.count("serverware_policy_authority_wire_walk("), 4)
        for original in ("cxs_descriptor_json", "cxs_body_json"):
            self.assertIn("cxs_rendered.rendered COLLATE \"C\" IS DISTINCT FROM "
                + original + ' COLLATE "C"', sql)
        for required in ("cxs_measured.visited_nodes, cxs_measured.emitted_bytes, TRUE",
                "cxs_rendered.visited_nodes IS DISTINCT FROM cxs_measured.visited_nodes",
                "cxs_rendered.emitted_bytes IS DISTINCT FROM cxs_measured.emitted_bytes",
                "sha256(pg_catalog.convert_to(cxs_body_json, 'UTF8'))",
                "octet_length(cxs_body_json)::bigint"):
            self.assertIn(required, sql)
        self.assertNotIn("::jsonb::text", sql)

    def test_closed_descriptor_exact_types_and_phase_coordinates(self):
        sql = custody.step_body_sql(NAMESPACE)
        for field in custody._DESCRIPTOR_FIELDS:
            self.assertIn("'" + field + "'", sql)
        for expression, maximum in (("cxs_descriptor->'phaseOrdinal'", 6),
                ("cxs_descriptor->'rowOrdinal'", 255),
                ("cxs_descriptor->'byteCount'", custody.MAX_BODY_BYTES)):
            integer = custody._integer(expression, maximum)
            self.assertIn(integer, sql)
            self.assertLess(integer.index("integer type differs"), integer.index("::numeric"))
        self.assertIn("cxs_phase NOT IN (0, 1, 2, 4, 5, 6)", sql)
        self.assertIn("NOT IN ('phase-before', 'row', 'phase-after')", sql)
        self.assertIn("cxs_body->'phaseOrdinal' IS DISTINCT FROM cxs_descriptor->'phaseOrdinal'", sql)
        self.assertIn("cxs_body->'rowOrdinal' IS DISTINCT FROM cxs_descriptor->'rowOrdinal'", sql)
        self.assertIn("OR cxs_ordinal <> 0", sql)
        self.assertIn(custody._integer("cxs_body->'rowCount'", 256), sql)

    def test_actual_row_and_all_nine_phase_profiles_are_source_bound(self):
        sql = custody.step_body_sql(NAMESPACE)
        ids, templates = custody.effects._source()
        self.assertEqual(len(ids), 9)
        for schema in (custody.source_pass.ROW_EFFECT_SCHEMA, custody.source_pass.PHASE_EFFECT_SCHEMA):
            self.assertIn(schema, sql)
        for template in templates.values():
            self.assertIn(template, sql)
        self.assertIn("cxs_phase IN (0, 4)", sql)
        for name in ("primaryBefore", "primaryAfter", "primaryRoot"):
            self.assertIn("cxs_root := cxs_body->'" + name + "'", sql)
        self.assertIn("jsonb_array_length(cxs_body->'indexHeads') <> 9", sql)
        self.assertLess(sql.index("maintenance custody phase body is not source closed"),
            sql.index("jsonb_array_length(cxs_body->'indexHeads')"))
        for identity in ids:
            self.assertIn(identity, sql)
            self.assertIn(custody.effects.projection.profile_for(identity).projection_digest, sql)
        self.assertIn(custody.effects.projection.projection_manifest_digest(), sql)
        self.assertIn('IS DISTINCT FROM cxs_ids[cxs_position] COLLATE "C"', sql)
        self.assertIn("WITH ORDINALITY AS item(value, ordinal) ORDER BY item.ordinal", sql)
        self.assertIn("(cxs_head->>'rootCount')::bigint > (cxs_root->>'leafCount')::bigint", sql)

    def test_unsealed_insert_and_literal_full_row_readback_without_business_effects(self):
        sql = custody.step_body_sql(NAMESPACE)
        sealed = custody._unsealed(NAMESPACE)
        self.assertEqual(sql.count(sealed), 2)
        insert = sql.index("INSERT INTO")
        readback = sql.index("SELECT stored.* INTO STRICT cxs_stored")
        self.assertLess(sql.index(sealed), insert)
        self.assertLess(insert, readback)
        self.assertLess(readback, sql.rindex(sealed))
        self.assertEqual(sql.count("INSERT INTO"), 1)
        self.assertIn("ON CONFLICT (pending_decision_digest, step_ordinal) DO NOTHING", sql)
        self.assertIn("stored.step_ordinal = cxs_step_ordinal FOR UPDATE", sql)
        for column in custody.STEP_COLUMNS:
            self.assertIn("cxs_stored." + column, sql)
        for forbidden in ("UPDATE ", "DELETE FROM", "ON CONFLICT DO UPDATE", "CREATE ",
                "GRANT ", "REVOKE ", "COMMIT;", "ROLLBACK;", "EXCEPTION WHEN", "set_config(",
                "cxs_deadline_epoch_ns :=", "crx_selected_rows", "crx_mutations", "crx_work_units"):
            self.assertNotIn(forbidden, sql)
        self.assertEqual(sql.count(custody._live()), 3)

    def test_namespace_and_actual_stream_source_changes_are_refused(self):
        for render in (custody.installation_sql, custody.step_body_sql):
            for namespace in (None, "public", '"a"."b"', '"a";SELECT 1'):
                with self.subTest(render=render.__name__, namespace=namespace), self.assertRaises(ValueError):
                    render(namespace)
        for name, value in (("MAX_STEPS", 1549), ("MAX_BODY_BYTES", 4194305),
                ("PHASES", (0, 1, 2, 3, 4, 5, 6))):
            with self.subTest(name=name), patch.object(custody.stream, name, value):
                with self.assertRaisesRegex(ValueError, "stream source changed"):
                    custody.step_body_sql(NAMESPACE)
        ids = custody.effects.projection.index_ids_for_table(custody.effects.TABLE)
        with patch.object(custody.effects.projection, "index_ids_for_table", return_value=ids[:-1]):
            with self.assertRaisesRegex(ValueError, "effect source inventory changed"):
                custody.step_body_sql(NAMESPACE)


if __name__ == "__main__":
    unittest.main()
