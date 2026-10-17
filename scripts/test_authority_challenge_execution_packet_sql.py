#!/usr/bin/env python3
"""Renderer/source controls only; no PostgreSQL, signature or proof admission.

These controls inspect actual emitted fixed SQL and shared codec composition.
They do not execute the statements or replace protected issuer/seal/root tests.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate.authority_store import challenge_execution_packet_sql as source


NAMESPACE = '"fixture"'


class ChallengeExecutionPacketSQLControls(unittest.TestCase):
    def test_original_packet_bounds_and_canonical_digest_precede_outputs(self):
        sql = source.packet_body_sql(NAMESPACE)
        declarations = source.declarations_sql()
        for name in ("packet_json", "packet_digest", "pending_decision_digest", "deadline_epoch_ns",
                "packet", "stream", "stream_json", "before_vector_json", "after_vector_json",
                "result_json", "marker", "issued", "expires"):
            self.assertRegex(declarations, r"\bcxe_" + name + r"\s+(?:text|bigint|jsonb);")
        self.assertIn(source._closed("cxe_packet", source.packet.FIELDS), sql)
        self.assertIn(source.codecs._wire(NAMESPACE, "cxe_packet", "cxe_canonical",
            source.packet.MAX_BYTES, source.packet.MAX_NODES, source.packet.MAX_DEPTH), sql)
        self.assertIn(source.codecs._digest(NAMESPACE, source.packet.IDENTITY_DOMAIN, "cxe_packet_json"), sql)
        self.assertLess(sql.index("octet_length(cxe_packet_json) NOT BETWEEN 2 AND 8388608"),
            sql.index("cxe_packet := cxe_packet_json::jsonb"))
        self.assertLess(sql.index("maintenance packet identity differs"), sql.index("cxe_issued :="))
        self.assertIn("cxe_packet->>'pendingDecisionDigest' IS DISTINCT FROM cxe_pending_decision_digest", sql)
        self.assertIn('cxe_canonical COLLATE "C" IS DISTINCT FROM cxe_packet_json COLLATE "C"', sql)

    def test_every_original_uses_actual_frame_codec_and_maintenance_aggregate_ceiling(self):
        sql = source.packet_body_sql(NAMESPACE)
        # Stream header + two complete vectors + six controls + raw3.
        self.assertEqual(sql.count(source.codecs._frame()), 12)
        self.assertEqual(sql.count("IF sxe_total > 8388608"), 12)
        for name, maximum in source.packet.CONTROL_MAXIMA:
            self.assertIn("sxe_frame := cxe_packet->'originals'->'" + name + "'; sxe_maximum := " + str(maximum), sql)
        for ordinal, maximum in enumerate(source.grants.FRAME_MAXIMA):
            self.assertIn(f"sxe_frame := cxe_packet->'originals'->'plan'->{ordinal}; sxe_maximum := {maximum}", sql)
            self.assertIn(f"jsonb_build_object('position', {ordinal},", sql)
        self.assertLess(sql.index("maintenance raw3 is not an array"),
            sql.index("jsonb_array_length(cxe_packet->'originals'->'plan')"))
        self.assertIn("pg_catalog.translate(pg_catalog.encode(sxe_raw, 'base64')", sql)
        self.assertIn("pg_catalog.sha256(sxe_raw)", sql)
        self.assertIn("maintenance original JSON spelling differs", sql)
        self.assertIn("maintenance original is not canonical ASCII", sql)

    def test_six_phase_schedule_is_bounded_contiguous_and_has_both_empty_edges(self):
        sql = source._stream_sql(NAMESPACE)
        self.assertIn(source._closed("cxe_stream", source.HEADER_FIELDS), sql)
        self.assertIn(source._closed("cxe_descriptor", source.stream._DESCRIPTOR_FIELDS), sql)
        self.assertIn("ARRAY[0, 1, 2, 4, 5, 6]::integer[]", sql)
        self.assertIn("NOT BETWEEN 12 AND 1548", sql)
        self.assertLess(sql.index("maintenance stream header shape differs"),
            sql.index("jsonb_array_length(cxe_stream->'steps')"))
        self.assertIn("WITH ORDINALITY AS item(value, ordinal) ORDER BY item.ordinal", sql)
        for clause in ("cxe_phase_position > 6", "cxe_in_phase OR", "NOT cxe_in_phase OR cxe_rows >= 256",
                "(cxe_descriptor->>'rowOrdinal')::integer <> cxe_rows",
                "cxe_rows := cxe_rows + 1", "cxe_phase_position := cxe_phase_position + 1",
                "cxe_phase_position <> 7 OR cxe_in_phase"):
            self.assertIn(clause, sql)
        # No minimum row count: every phase may contain only its before/after.
        self.assertNotIn("cxe_rows <= 0", sql)
        self.assertIn("cxe_body_total := cxe_body_total + (cxe_descriptor->>'byteCount')::bigint", sql)
        self.assertIn("cxe_body_total IS DISTINCT FROM (cxe_stream->>'totalBodyBytes')::bigint", sql)
        self.assertIn(source.codecs._digest(NAMESPACE, source.stream.SEED_DOMAIN, "cxe_canonical"), sql)
        self.assertIn(source.codecs._digest(NAMESPACE, source.stream.STEP_DOMAIN, "cxe_chain, cxe_canonical"), sql)
        self.assertIn("cxe_chain IS DISTINCT FROM cxe_stream->>'chainDigest'", sql)

    def test_original_domains_vectors_result_and_complete_marker_are_joined(self):
        sql = source.packet_body_sql(NAMESPACE)
        for domain in (source.plan.IDENTITY_DOMAIN, source.plan.REQUEST_DOMAIN, source.plan.MANIFEST_DOMAIN,
                source.stream.IDENTITY_DOMAIN, source.vector.IDENTITY_DOMAIN, source.stream.RESULT_DOMAIN,
                source.admission.computation.ORIGINAL_RECORD_DOMAIN,
                source.authorization.ENROLLMENT_IDENTITY_DOMAIN, source.grants.ENROLLMENT_IDENTITY_DOMAIN,
                source.grants.GRANT_IDENTITY_DOMAIN, source.authorization.REQUEST_IDENTITY_DOMAIN,
                source.authorization.RECEIPT_IDENTITY_DOMAIN, source.admission.pending.computation.SNAPSHOT_DOMAIN):
            self.assertIn("'" + domain + "'", sql)
        self.assertIn(source._closed("cxe_marker", source.authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS), sql)
        for name in source.authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS:
            self.assertIn("(cxe_marker->'" + name + "') IS DISTINCT FROM (", sql)
        for expression in ("cxe_grant->'originalFrames'", "cxe_snapshot->'originalFrames'",
                "cxe_reserve->'beforeVector'", "cxe_reserve->'afterVector'",
                "cxe_parent->'manifestDigest'", "cxe_parent->>'requestBytesDigest'",
                "cxe_snapshot->>'retainedRecordDigest'", "cxe_grant->'requestAuthorizationDigest'"):
            self.assertIn("(" + expression + ") IS DISTINCT FROM (", sql)
        self.assertIn("cxe_plan_json, cxe_request_json, cxe_manifest_json", sql)
        self.assertIn("'catchplate.policyAuthorityOperation/v2'", sql)

    def test_original_intervals_are_equal_and_processing_deadline_only_narrows(self):
        sql = source.packet_body_sql(NAMESPACE)
        for document in ("cxe_grant", "cxe_parent", "cxe_reserve", "cxe_receipt"):
            for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
                self.assertIn(f"({document}->'{field}') IS DISTINCT FROM (cxe_packet->'{field}')", sql)
        for original, current in (("originalIssuedAtEpochNs", "issuedAtEpochNs"),
                ("originalExpiresAtEpochNs", "expiresAtEpochNs")):
            self.assertIn(f"(cxe_snapshot->'{original}') IS DISTINCT FROM (cxe_packet->'{current}')", sql)
        assignments = re.findall(r"cxe_deadline_epoch_ns\s*:=\s*([^;]+);", sql)
        self.assertEqual(assignments, ["LEAST(cxe_deadline_epoch_ns, cxe_expires)"])
        self.assertEqual(len(re.findall(r"cxe_issued\s*:=", sql)), 1)
        self.assertEqual(len(re.findall(r"cxe_expires\s*:=", sql)), 1)
        self.assertGreaterEqual(sql.count(source._live_sql()), 4)
        for field in ("maxControlAgeNs", "maxClockSkewNs", "maximumGrantAgeNs", "maximumClockSkewNs"):
            self.assertIn("->>'" + field + "'", sql)
        self.assertIn("maintenance packet original interval or sequence differs", sql)

    def test_shared_codec_scratch_is_local_and_no_aggregate_or_authority_is_added(self):
        sql = source.packet_body_sql(NAMESPACE)
        self.assertTrue(sql.lstrip().startswith("DECLARE"))
        used = set(re.findall(r"\bsxe_[a-z_]+\b", sql))
        declared = set(re.findall(r"\b(sxe_[a-z_]+)\s+(?:record|jsonb|bigint|bytea)\b", sql))
        self.assertEqual(used, declared)
        for forbidden in ("selectedRows", "mutations", "workUnits", "crx_", "sxe_packet", "CREATE ",
                "GRANT ", "REVOKE ", "INSERT INTO", "UPDATE ", "DELETE FROM", "FOR UPDATE",
                "SET ROLE", "set_config(", "COMMIT;", "ROLLBACK;", "EXCEPTION WHEN",
                "policy_authority_authenticated_table_roots", "policy_authority_counted_index_heads",
                "policy_authority_challenge_execution_custody"):
            self.assertNotIn(forbidden, sql)
        self.assertNotIn("sxe_", source.declarations_sql())
        # Rendering order must not depend on randomized frozenset iteration.
        sequence = [sql.index("jsonb_typeof(cxe_stream->'" + name + "')")
            for name in sorted(source.HEADER_FIELDS) if name.endswith("Digest")]
        self.assertEqual(sequence, sorted(sequence))

    def test_changed_source_rosters_and_unquoted_names_refuse(self):
        for namespace in (None, "public", '"a"."b"', '"a"; SELECT 1', '"' + 'a' * 64 + '"'):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                source.packet_body_sql(namespace)
        for owner, field, changed in ((source.packet, "MAX_BYTES", source.packet.MAX_BYTES + 1),
                (source.stream, "PHASES", (0, 1, 2, 3, 4, 5)),
                (source.stream, "MAX_STEPS", 1549),
                (source.packet, "CONTROL_MAXIMA", source.packet.CONTROL_MAXIMA[:-1]),
                (source.authority, "CURRENT_ROOT_COMMIT_MARKER_COLUMNS", ())):
            with self.subTest(field=field), mock.patch.object(owner, field, changed), self.assertRaises(ValueError):
                source.packet_body_sql(NAMESPACE)


if __name__ == "__main__":
    unittest.main()
