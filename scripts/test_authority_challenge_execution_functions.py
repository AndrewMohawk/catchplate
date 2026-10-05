#!/usr/bin/env python3
"""UNRUN renderer controls; no PostgreSQL compilation or execution claim."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware.authority_store import challenge_execution_sql as sql


def pins(label):
    return ("sha256:" + "1" * 64, "sha256:" + "2" * 64, "sha256:" + "3" * 64,
        "CN=" + label, "01" if label == "issuer" else "02", "CN=synthetic-ca")


def rendered():
    return sql.functions_sql('"serverware_metadata"', owner_role="source_owner",
        issuer_pins=pins("issuer"), executor_pins=pins("executor"))


class MaintenanceFunctionControls(unittest.TestCase):
    def test_exact_functions_separate_principals_and_security_metadata(self):
        source = rendered()
        self.assertEqual(source.count("CREATE OR REPLACE FUNCTION"), 3)
        self.assertEqual(source.count("SECURITY DEFINER VOLATILE"), 3)
        for name in sql.contract.FUNCTION_SIGNATURES:
            self.assertIn(name, source)
        self.assertIn(sql.contract.ISSUER_ROLE, source)
        self.assertIn(sql.contract.EXECUTOR_ROLE, source)
        self.assertNotIn("GRANT ", source)
        self.assertNotIn("set_config(", source)

    def test_retention_cannot_seal_or_execute_business_effects(self):
        source = rendered().split("CREATE OR REPLACE FUNCTION")[1]
        self.assertIn(sql.custody.STEP_TABLE, source)
        self.assertIn("already sealed", source)
        self.assertNotIn("INSERT INTO \"serverware_metadata\"." + sql.custody.CUSTODY_TABLE, source)
        self.assertNotIn("UPDATE \"serverware_metadata\".webauthn_challenges", source)

    def test_seal_checks_complete_raw_steps_before_header_insert(self):
        source = rendered().split("CREATE OR REPLACE FUNCTION")[2]
        self.assertLess(source.index("stored raw stream is incomplete"), source.index(
            "INSERT INTO \"serverware_metadata\"." + sql.custody.CUSTODY_TABLE))
        self.assertIn("LIMIT 1549 FOR UPDATE", source)
        self.assertIn("cxg_step.step_ordinal IS DISTINCT FROM cxg_seen", source)
        self.assertIn("issuer_identity_digest IS DISTINCT FROM cxg_issuer_identity", source)
        self.assertIn("cxs_descriptor IS DISTINCT FROM cxe_stream->'steps'->cxg_seen", source)

    def test_identifier_executor_keeps_real_root_and_marker_transaction_chain(self):
        source = rendered().split("CREATE OR REPLACE FUNCTION")[3]
        signature = source[:source.index("RETURNS")]
        self.assertIn("supplied_pending_decision_digest text, supplied_packet_digest text", signature)
        self.assertNotIn("packet_json text", signature)
        self.assertLess(source.index("actual locked before vector changed"), source.index("maintenance row sequence"))
        self.assertIn("challenge maintenance primary before differs", source)
        self.assertIn("challenge maintenance primary after differs", source)
        self.assertIn("challenge maintenance phase before differs", source)
        self.assertIn("challenge maintenance phase after differs", source)
        marker_insert = 'INSERT INTO "serverware_metadata".' + sql.authority.CURRENT_ROOT_COMMIT_MARKER_TABLE
        self.assertLess(source.index("stored raw stream is incomplete"), source.index(marker_insert))
        self.assertNotIn("COMMIT;", source)
        self.assertNotIn("EXCEPTION WHEN", source)

    def test_validation_prefix_is_shared_without_a_replay_insert(self):
        namespace = '"serverware_metadata"'
        validation = sql.custody.validation_body_sql(namespace)
        self.assertIn(validation, sql.custody.step_body_sql(namespace))
        self.assertIn(validation, sql._steps(namespace, apply=False))
        self.assertIn(validation, sql._steps(namespace, apply=True))
        self.assertNotIn("INSERT INTO", validation)
        self.assertNotIn("INSERT INTO", sql._steps(namespace, apply=False))
        with self.assertRaises(ValueError):
            sql._steps(namespace, apply=1)

    def test_identity_or_namespace_substitution_refuses_before_rendering(self):
        for arguments in (
            dict(owner_role=sql.contract.ISSUER_ROLE, issuer_pins=pins("issuer"), executor_pins=pins("executor")),
            dict(owner_role="source_owner", issuer_pins=pins("issuer"), executor_pins=pins("issuer")),
            dict(owner_role="bad;role", issuer_pins=pins("issuer"), executor_pins=pins("executor")),
        ):
            with self.assertRaises(ValueError):
                sql.functions_sql('"serverware_metadata"', **arguments)


if __name__ == "__main__":
    unittest.main()
