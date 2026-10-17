#!/usr/bin/env python3
"""Source-fragment controls only; no SQL execution or authority acceptance."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_contract as authority
from catchplate import authority_index_projection as projection
from catchplate.authority_store import challenge_maintenance_effects_sql as effects
from catchplate.authority_store import mutation_sql


class ChallengeMaintenanceEffectsSourceTests(unittest.TestCase):
    def test_namespace_and_phase_edge_are_closed_source_parameters(self):
        class Alias(str):
            pass
        for namespace in (None, 'public', '"a"."b"', '"a";SELECT 1', Alias('"fixture"')):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                effects.row_body_sql(namespace)
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                effects.phase_roots_body_sql(namespace, stage="before")
        for stage in (None, True, "both", "before;", Alias("before")):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                effects.phase_roots_body_sql('"fixture"', stage=stage)

    def test_row_uses_genuine_locked_full_old_cas_after_exact_phase_guard(self):
        sql = effects.row_body_sql('"fixture"')
        shared = mutation_sql.apply_mutation_sql('"fixture"')
        self.assertEqual(sql.count(shared), 1)
        self.assertIn(mutation_sql.locked_primary_key_row_sql('"fixture"', "mutation"), sql)
        self.assertLess(sql.index("mutation identity differs"), sql.index(shared))
        self.assertLess(sql.index("prune is not its exact DELETE"), sql.index(shared))
        self.assertIn("cme_phase_ordinal NOT IN (0, 1, 2, 4, 5, 6)", sql)
        self.assertIn("cme_row_ordinal NOT BETWEEN 0 AND 255", sql)
        self.assertIn("current_row IS DISTINCT FROM mutation->'expectedRow'", sql)
        self.assertIn("matched_count <> 1", sql)
        self.assertIn("post_row IS DISTINCT FROM mutation->'row'", sql)

    def test_exact_source_templates_key_and_only_used_at_or_unreferenced_delete(self):
        sql = effects.row_body_sql('"fixture"')
        for template in authority.operation_spec(effects.OPERATION)["mutationTemplates"]:
            self.assertIn(template["templateId"], sql)
        self.assertIn("catchplate.policyAuthorityBusinessKey/v1", sql)
        self.assertIn("mutation->'expectedRow'->'id' IS DISTINCT FROM mutation->'key'->'id'", sql)
        self.assertIn("cme_phase_ordinal IN (0, 4)", sql)
        self.assertIn("mutation->'expectedRow'->'used_at' IS DISTINCT FROM 'null'", sql)
        self.assertIn("(mutation->'row' - 'used_at') IS DISTINCT FROM (mutation->'expectedRow' - 'used_at')", sql)
        self.assertIn("'retention_reference_mask' IS DISTINCT FROM '0'", sql)

    def test_original_canonical_bytes_and_primary_descriptors_bracket_real_effect(self):
        sql = effects.row_body_sql('"fixture"')
        self.assertLess(sql.index("NOT BETWEEN 2 AND 4194304"), sql.index("cme_mutation_json::"))
        self.assertEqual(sql.count("catchplate_policy_authority_wire_walk("), 2)
        self.assertIn("cme_canonical COLLATE \"C\" IS DISTINCT FROM cme_mutation_json", sql)
        before = sql.index("cme_actual_primary IS DISTINCT FROM cme_primary_before")
        effect = sql.index(mutation_sql.apply_mutation_sql('"fixture"'))
        after = sql.index("cme_actual_primary IS DISTINCT FROM cme_primary_after")
        self.assertLess(before, effect)
        self.assertLess(effect, after)
        self.assertEqual(sql.count("LIMIT 2 FOR UPDATE"), 2)

    def test_all_nine_actual_source_heads_and_empty_phase_edges_remain_required(self):
        ids = projection.index_ids_for_table(effects.TABLE)
        self.assertEqual(len(ids), 9)
        for stage in ("before", "after"):
            sql = effects.phase_roots_body_sql('"fixture"', stage=stage)
            for identity in ids:
                self.assertIn(identity, sql)
                self.assertIn(projection.profile_for(identity).projection_digest, sql)
            self.assertIn(projection.projection_manifest_digest(), sql)
            self.assertIn('ORDER BY index_id COLLATE "C" LIMIT 10 FOR UPDATE', sql)
            self.assertIn("cme_position <> 9", sql)
            self.assertIn("'rootCount', cme_head.leaf_count", sql)
            self.assertIn("cme_actual_phase IS DISTINCT FROM cme_phase_" + stage, sql)
            self.assertNotIn("cme_row_ordinal", sql)

    def test_no_callable_installer_deadline_renewal_or_transaction_escape(self):
        sql = "\n".join((effects.declarations_sql(), effects.row_body_sql('"fixture"'),
            effects.phase_roots_body_sql('"fixture"', stage="before"),
            effects.phase_roots_body_sql('"fixture"', stage="after")))
        for forbidden in ("CREATE ", "GRANT ", "REVOKE ", "SET ROLE", "set_config(",
                "COMMIT;", "ROLLBACK;", "EXCEPTION WHEN", "cme_deadline_epoch_ns :="):
            self.assertNotIn(forbidden, sql)
        self.assertGreaterEqual(sql.count(">= cme_deadline_epoch_ns"), 7)


if __name__ == "__main__":
    unittest.main()
