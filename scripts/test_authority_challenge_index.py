#!/usr/bin/env python3
"""Pure fresh-source challenge ordering/projection controls, not DB admission.

No database, installation, measured plan, proof acceptance or runtime authority
is simulated. Literal key tails and the existing independent old-descriptor
oracle check the exact codec boundary used by later integrated proof fixtures.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_challenge_id as ids
from catchplate import authority_index_projection as projection
from catchplate import authority_index_trace as trace
from catchplate import authority_index_heads as heads
import test_authority_index_join as old_oracle


UUID0 = "00000000-0000-0000-0000-000000000000"
UUID1 = "00000000-0000-0000-0000-000000000001"
UUID_MAX = "ffffffff-ffff-ffff-ffff-ffffffffffff"
SHA0 = "sha256:" + "0" * 64
SHA1 = "sha256:" + "0" * 63 + "1"
PK = "sha256:" + "a" * 64
ROW = "sha256:" + "b" * 64
EPOCH = "1970-01-01T00:00:00+00:00"


def row(identifier=UUID0):
    return dict(id=identifier, challenge="challenge", challenge_type="authentication",
        user_id="user", scope_key=None, expires_at=EPOCH, created_at=EPOCH,
        used_at=None, retention_reference_mask=0)


def project(name, value):
    return projection.project_row(name, value, primary_key_digest=PK, primary_row_digest=ROW)


class ChallengeIndexTests(unittest.TestCase):
    def test_generated_id_tail_has_literal_layout_and_exact_text_order(self):
        expected = {
            UUID0: "00" + "0" * 64 + "0" * 14,
            UUID1: "00" + "0" * 31 + "1" + "0" * 32 + "0" * 14,
            UUID_MAX: "00" + "f" * 32 + "0" * 32 + "0" * 14,
            SHA0: "01" + "0" * 64 + "0" * 14,
            SHA1: "01" + "0" * 63 + "1" + "0" * 14,
        }
        for identifier, literal in expected.items():
            self.assertEqual(ids.order_suffix(identifier), literal)
            self.assertEqual(len(literal), 80)
        self.assertEqual(sorted(expected), sorted(expected, key=ids.order_suffix))

    def test_custom_and_noncanonical_ids_are_not_historically_adopted(self):
        class TextSubclass(str):
            pass
        for value in ("custom-id", UUID_MAX.upper(), UUID0.replace("-", ""),
                      SHA0 + "\n", "SHA256:" + "0" * 64, "sha256:" + "F" * 64,
                      None, 0, False, TextSubclass(UUID0)):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "fresh challenge source"):
                    ids.require_generated(value)

    def test_new_keys_keep_actual_commitments_and_source_timestamp_order(self):
        name = "webauthn_challenge_unused_global"
        ordered = []
        for timestamp, encoded in (("1969-12-31T23:59:59.999999+00:00", "7fffffffffffffff"),
                                   (EPOCH, "8000000000000000"),
                                   ("1970-01-01T00:00:00.000001+00:00", "8000000000000001")):
            for identifier in (UUID0, UUID1, UUID_MAX, SHA0, SHA1):
                value = row(identifier)
                value["expires_at"] = timestamp
                leaf = project(name, value)
                self.assertEqual(leaf.key[64:80], encoded)
                self.assertEqual(leaf.key[80:], ids.order_suffix(identifier))
                self.assertEqual((leaf.primary_key_digest, leaf.primary_row_digest), (PK, ROW))
                ordered.append(leaf.key)
        self.assertEqual(ordered, sorted(ordered))
        self.assertEqual(len(set(ordered)), len(ordered))

    def test_cutoff_inclusivity_and_i64_extremes_are_closed(self):
        name = "webauthn_challenge_unused_global"
        leaf = project(name, row())
        def contains(interval):
            return interval.lower <= leaf.key and (interval.upper is None or leaf.key < interval.upper)
        for direction, expected in (("at-or-before", True), ("strictly-after", False), ("all", True)):
            self.assertEqual(contains(projection.query_interval(name,
                dict(cutoff_us=0, direction=direction))), expected)
        empty = projection.query_interval(name, dict(cutoff_us=2**63 - 1, direction="strictly-after"))
        self.assertEqual(empty.lower, empty.upper)
        self.assertFalse(contains(projection.query_interval(name,
            dict(cutoff_us=-(2**63), direction="at-or-before"))))
        for selector in (dict(cutoff_us=False, direction="all"), dict(cutoff_us=0, direction="other"),
                         dict(cutoff_us=0, direction="all", lower="0" * 160)):
            with self.assertRaises(projection.IndexProjectionError):
                projection.query_interval(name, selector)

    def test_scope_null_is_not_empty_and_terminal_membership_uses_actual_mask(self):
        scope = "webauthn_challenge_scope_unused"
        selector = dict(challenge_type="authentication", user_id="user", scope_key=None)
        null_interval = projection.query_interval(scope, selector)
        empty_interval = projection.query_interval(scope, dict(selector, scope_key=""))
        self.assertNotEqual(null_interval, empty_interval)
        self.assertTrue(null_interval.lower <= project(scope, row()).key < null_interval.upper)
        terminal = "webauthn_challenge_terminal_unreferenced_global"
        self.assertIsNone(project(terminal, row()))
        used = dict(row(), used_at=EPOCH)
        self.assertIsNotNone(project(terminal, used))
        for mask in range(1, 8):
            self.assertIsNone(project(terminal, dict(used, retention_reference_mask=mask)))
        for invalid in (-1, 8, False, 0.0):
            with self.assertRaises(projection.IndexProjectionError):
                project(terminal, dict(used, retention_reference_mask=invalid))

    def test_older_profile_documents_are_unchanged(self):
        for name in ("webauthn_registration_unused_global", "webauthn_registration_unused_user"):
            self.assertEqual(projection._definition(name).document(), old_oracle.descriptor(name))
        self.assertEqual(len(projection.INDEX_IDS), 24)
        self.assertEqual(len(projection.index_ids_for_table("webauthn_challenges")), 9)

    def test_sql_identity_guards_select_exact_layout_and_independent_commitments(self):
        # Render the actual shared source guards; SQL execution is a separate
        # PostgreSQL fixture, not simulated by this pure regression.
        import re
        from catchplate.authority_store import counted_path_sql as path
        from catchplate.authority_store import counted_store_sql as store

        compact = lambda value: " ".join(value.split())
        guard = compact(store._key_identity_check(
            "index_id", "index_key", "primary_id", "primary_key_digest"))
        rosters = re.findall(r'WHEN index_id COLLATE "C" IN \(([^)]+)\) THEN', guard)
        self.assertEqual(len(rosters), 2)
        challenge, legacy = [re.findall(r"'([^']*)'", roster) for roster in rosters]
        expected_challenge = {
            name for name in projection.INDEX_IDS
            if projection._definition(name).document()["keySuffix"]
                == "UUID36-class0-padded16-or-sha256-class1/zero7/exact-text-order"
        }
        self.assertEqual(len(expected_challenge), 7)
        self.assertEqual(set(challenge), expected_challenge)
        self.assertEqual(set(legacy), set(projection.INDEX_IDS) - expected_challenge)
        self.assertCountEqual(challenge + legacy, projection.INDEX_IDS)
        self.assertNotIn("unknown_profile", challenge + legacy)
        self.assertEqual(guard.count("ELSE FALSE"), 2)
        self.assertTrue(guard.endswith("ELSE FALSE END)"))
        for length, pattern, suffix in (
            (36, ids.UUID_PATTERN, "'00' || pg_catalog.replace(primary_id, '-', '') || pg_catalog.repeat('0', 46)"),
            (71, ids.SHA_PATTERN, "'01' || pg_catalog.substr(primary_id, 8) || pg_catalog.repeat('0', 14)"),
        ):
            self.assertIn(f'pg_catalog.octet_length(primary_id) = {length} AND primary_id COLLATE "C" ~ \'^{pattern}$\'', guard)
            self.assertIn(f'pg_catalog.substr(index_key, 81) COLLATE "C" = ({suffix}) COLLATE "C"', guard)
        self.assertIn('pg_catalog.substr(index_key, 97) COLLATE "C" = pg_catalog.substr(primary_key_digest, 8) COLLATE "C"', guard)
        leaves = compact(store.counted_store_ddl('"fixture"')[1])
        self.assertIn(f"CONSTRAINT counted_leaves_suffix CHECK ( {guard} IS TRUE )", leaves)

        rendered_path = compact(path.counted_path_functions_sql('"fixture"')[0])
        self.assertIn('identity_digest := "fixture".catchplate_policy_authority_domain_digest( '
            "'catchplate.policyAuthorityBusinessKey/v1',source_table, "
            '\"fixture\".catchplate_policy_authority_wire_json(pg_catalog.jsonb_build_object(\'id\',event_id)));', rendered_path)
        for side in ("old", "new"):
            self.assertIn(f"{side}_primary_key_digest := projected.primary_key_digest;", rendered_path)
            side_guard = compact(store._key_identity_check(
                "index_identity", f"{side}_key", "event_id", "identity_digest"))
            self.assertIn(f'{side}_member AND ({side}_primary_key_digest COLLATE "C" '
                f'IS DISTINCT FROM identity_digest COLLATE "C" OR {side_guard} IS NOT TRUE)', rendered_path)

    def test_count_trace_shape_cannot_authorize_other_profiles_or_tables(self):
        key = dict(profile=trace.COUNT_READ_PROFILE,
            indexId="webauthn_challenge_unused_global", projectionDigest=PK,
            indexRevision=1, rootDigest=ROW, rootCount=50000,
            lower="0" * 160, upper=None, prefixes=[dict(depth=1, pathPrefix="0")], limit=2)
        trace.validate_count_read_trace("webauthn.challenge.create", "policy_authority_counted_index_nodes", key)
        for field, value in (("indexId", "webauthn_credential_id"), ("rootCount", True),
                             ("limit", 1), ("prefixes", [dict(depth=2, pathPrefix="0")])):
            changed = copy.deepcopy(key)
            changed[field] = value
            with self.assertRaises(trace.IndexTraceError):
                trace.validate_count_read_trace("webauthn.challenge.create", "policy_authority_counted_index_nodes", changed)
        with self.assertRaises(trace.IndexTraceError):
            trace.validate_count_read_trace("webauthn.challenge.create", "webauthn_challenges", key)
        with self.assertRaises(trace.IndexTraceError):
            trace.validate_count_read_trace("webauthn.challenge.claim", "policy_authority_counted_index_nodes", key)

    def test_deferred_retention_guard_uses_source_owner_without_table_grants(self):
        from catchplate.authority_store import challenge_retention_sql as retention_sql

        statements = retention_sql.challenge_retention_installation_sql('"fixture"')
        guard = statements[1]
        self.assertIn("RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER", guard)
        self.assertNotIn("SECURITY INVOKER", guard)
        self.assertIn('SET search_path = pg_catalog, "fixture", pg_temp', guard)
        self.assertIn('TG_TABLE_SCHEMA COLLATE "C" <> \'fixture\' COLLATE "C"', guard)
        self.assertIn("OR TG_WHEN <> 'AFTER' OR TG_LEVEL <> 'ROW' OR TG_NARGS <> 0", guard)
        self.assertEqual(retention_sql.SOURCE_TABLES, (
            "jit_webauthn_assertion_receipts", "policy_activation_webauthn_assertions",
            "webauthn_challenges", "webauthn_recovery_ceremonies"))
        for ordinal, table in enumerate(retention_sql.SOURCE_TABLES):
            self.assertIn(f'FROM "fixture".{table} AS source_row', guard)
            self.assertIn(f'CREATE CONSTRAINT TRIGGER catchplate_retention_{ordinal} '
                f'AFTER INSERT OR UPDATE OR DELETE ON "fixture".{table} '
                'DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION '
                '"fixture".catchplate_policy_authority_challenge_retention_guard()', statements)
        for field in retention_sql.INLINE_FIELDS:
            self.assertIn(f"actual->'{field}' IS DISTINCT FROM expected->'{field}'", guard)
        self.assertIn("RAISE EXCEPTION 'challenge retention original join differs'", guard)
        self.assertIn("RAISE EXCEPTION 'challenge retention source survives its challenge'", guard)
        self.assertNotIn("GRANT ", "\n".join(statements))

    def test_private_head_inventories_are_exact_not_caller_subsets(self):
        self.assertEqual(len(heads.required_index_ids("webauthn.challenge.create")), 5)
        challenge = heads.required_index_ids("webauthn.challenge.create", include_write_heads=True)
        self.assertEqual(challenge, projection.index_ids_for_table("webauthn_challenges"))
        jit = heads.required_index_ids("jit.assertion.issue", include_write_heads=True)
        self.assertEqual(set(jit), set(challenge) | set(projection.index_ids_for_table("webauthn_credentials")))
        self.assertEqual(len(jit), 12)
        with self.assertRaises(heads.IndexHeadReadError):
            heads.required_index_ids("jit.assertion.issue")
        with self.assertRaises(heads.IndexHeadReadError):
            heads.validate_head_trace_key("webauthn.challenge.create",
                dict(profile=heads.READ_PROFILE, indexIds=list(challenge[:-1]), rowLimit=len(challenge)))
        for operation in heads.RECOVERY_OPERATIONS:
            expected = set(jit) if operation == "webauthn.recovery.finalize" else set(challenge)
            if operation in heads.RECOVERY_HISTORY_OPERATIONS:
                expected.add(heads.RECOVERY_HISTORY_ID)
            self.assertEqual(set(heads.required_index_ids(operation, include_write_heads=True)), expected)
            if operation in heads.RECOVERY_HISTORY_OPERATIONS:
                self.assertEqual(heads.required_index_ids(operation), (heads.RECOVERY_HISTORY_ID,))
            else:
                with self.assertRaises(heads.IndexHeadReadError):
                    heads.required_index_ids(operation)


if __name__ == "__main__":
    unittest.main()
