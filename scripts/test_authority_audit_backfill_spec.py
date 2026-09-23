#!/usr/bin/env python3
"""Pure declaration/source checks, not a populated audit initializer.

The real declaration and pure capacity constants are imported. Nothing creates
a database, registry capability, signed receipt, authenticated baseline or live
counter. Independent root currentness and installation remain unimplemented.
"""
from __future__ import annotations

import ast
import hashlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.authority import phase2_store_spec as spec
from serverware import authority_audit_capacity as capacity
from serverware import authority_contract


KIND = "metadata-audit-outbox-global-capacity-v1"


def framed(domain: str, frame: bytes) -> str:
    # Independent byte spelling of the transition-core domain framing.
    digest = hashlib.sha256(domain.encode("ascii") + b"\0")
    digest.update(len(frame).to_bytes(8, "big"))
    digest.update(frame)
    return "sha256:" + digest.hexdigest()


PARTITION = framed("serverware.metadataAuditOutboxCapacityPartition/v1", b"global")
EMPTY_EXPIRY = framed("serverware.policyAuthorityAggregateExpiryIndex/v1", b"[]")


class AuthorityAuditBackfillSpecTests(unittest.TestCase):
    def test_global_declaration_is_exact_source_owned_compact_profile(self):
        self.assertEqual(dict(spec.AGGREGATE_BACKFILLS[KIND]), {
            "sourceTables": ("metadata_audit_outbox",),
            "liveStates": ("pending", "claimed"),
            "groupKey": (), "expiryColumn": None,
            "capacitySource": "serverware.audit_outbox_contract.MAX_PENDING",
            "capacityLimit": 100_000,
            "aggregateId": KIND + ":" + PARTITION,
            "partitionDigest": PARTITION,
            "stateSchema": "serverware.policyAuthorityAggregateState/v1",
            "activeCountRule": "equal-live-count",
            "reservedUnits": {}, "committedUnits": {},
            "minimumExpiryEpochNs": None,
            "expiryIndexRootDigest": EMPTY_EXPIRY,
            "workPageId": None, "maximumRowBytes": 4096,
            "initializerImplemented": False, "onlineActivationPermitted": False,
        })
        self.assertEqual((capacity.AGGREGATE_KIND, capacity.AGGREGATE_ID,
                          capacity.PARTITION_DIGEST, capacity.EMPTY_EXPIRY_DIGEST),
                         (KIND, KIND + ":" + PARTITION, PARTITION, EMPTY_EXPIRY))
        self.assertIs(type(spec.AGGREGATE_BACKFILLS[KIND]["capacityLimit"]), int)

    def test_neither_legacy_identity_nor_configuration_supplies_global_capacity(self):
        for obsolete in ("metadata-audit-outbox", "metadata-audit-outbox-capacity"):
            self.assertNotIn(obsolete, spec.AGGREGATE_BACKFILLS)
        declaration = spec.AGGREGATE_BACKFILLS[KIND]
        self.assertEqual(declaration["capacityLimit"], capacity.MAX_PENDING)
        self.assertNotEqual(declaration["capacitySource"], "configuration")
        self.assertNotIn("audited", declaration["liveStates"])
        self.assertEqual(len(declaration["liveStates"]), 2)

    def test_declaration_and_empty_maps_are_immutable_with_activation_disabled(self):
        declaration = spec.AGGREGATE_BACKFILLS[KIND]
        for mapping, key, value in (
            (spec.AGGREGATE_BACKFILLS, KIND, {}),
            (declaration, "capacityLimit", 100_001),
            (declaration, "initializerImplemented", True),
            (declaration, "onlineActivationPermitted", True),
            (declaration["reservedUnits"], "caller", 1),
            (declaration["committedUnits"], "old-operation", 1),
        ):
            with self.subTest(key=key):
                with self.assertRaises(TypeError):
                    mapping[key] = value
        self.assertIs(declaration["initializerImplemented"], False)
        self.assertIs(declaration["onlineActivationPermitted"], False)
        self.assertTrue({"liveCount", "activeCount", "revision", "nextSequence", "stateDigest"}
                        .isdisjoint(declaration))

    def test_unrelated_backfill_declarations_are_preserved(self):
        expected = {
            "approval-request-capacity": {
                "sourceTables": ("approval_requests",), "liveStates": ("pending",),
                "groupKey": (), "expiryColumn": "expires_at", "capacitySource": "configuration"},
            "approval-review-receipt-capacity": {
                "sourceTables": ("approval_review_receipts",), "liveStates": ("unused-unexpired",),
                "groupKey": (), "expiryColumn": "expires_at", "capacitySource": "configuration"},
            "control-approval-head": {
                "sourceTables": ("control_plane_approvals",), "liveStates": ("pending", "approved"),
                "groupKey": ("action", "resource_id", "payload_digest"),
                "expiryColumn": "expires_at", "capacitySource": "configuration"},
            "credential-nonce-capacity": {
                "sourceTables": ("credential_lease_nonces", "credential_lease_replay_state"),
                "liveStates": ("unexpired",), "groupKey": ("scope",),
                "expiryColumn": "expires_at_epoch_ms", "capacitySource": "configuration"},
            "durable-budget-high-water": {
                "sourceTables": ("durable_budget_definitions", "durable_budget_events"),
                "liveStates": ("reserved", "dispatched", "committed"), "groupKey": ("budget_key",),
                "expiryColumn": "expires_at_epoch_ms", "capacitySource": "durable_budget_definitions.max_units"},
            "traversal-chain-high-water": {
                "sourceTables": ("traversal_budget_chains", "traversal_budget_cursors", "traversal_budget_page_reservations"),
                "liveStates": ("available", "reserved", "dispatched"), "groupKey": ("chain_key",),
                "expiryColumn": "reservation_expires_at_epoch_ms", "capacitySource": "traversal_budget_chains"},
        }
        self.assertEqual({key: dict(value) for key, value in spec.AGGREGATE_BACKFILLS.items()
                          if key != KIND}, expected)

    def test_outer_source_and_receipt_bindings_remain_declarations_not_receipts(self):
        outer = spec.PHASE2_STORE_SPEC
        self.assertIs(outer["aggregateBackfills"], spec.AGGREGATE_BACKFILLS)
        self.assertEqual(outer["schema"], "serverware.policyAuthorityPhase2StoreSpec/v1")
        self.assertEqual(outer["sourceRevision"], authority_contract.SOURCE_REVISION)
        self.assertEqual(outer["receiptSchema"], "serverware.policyAuthorityPhase2BackfillReceipt/v1")
        self.assertEqual(outer["backfillMode"], "offline-serializable-signed-exact")
        self.assertIs(outer["runtimeFullTableScansPermitted"], False)
        self.assertEqual(outer["requiredReceiptBindings"], (
            "sourceSchemaDigest", "sourceRootSetDigest", "sourceRowCountsDigest",
            "aggregateRowsDigest", "exactPageRowsDigest", "operationManifestDigest",
            "migrationMeasurementDigest", "migrationAttestationReceiptDigest", "completedAtEpochNs",
        ))
        self.assertIn("signed backfill receipt is installed", outer["activationRule"])
        self.assertIn("authenticated roots", outer["activationRule"])
        self.assertIn("admission remains disabled", outer["existingV9UpgradeRule"])

    def test_source_uses_real_capacity_constants_without_initializer_or_config_io(self):
        # Supplemental source closure only, not native SQL or installation proof.
        path = ROOT / "scripts/authority/phase2_store_spec.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        self.assertFalse(any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                             for node in tree.body))
        imports = {node.module for node in tree.body if isinstance(node, ast.ImportFrom)}
        self.assertEqual(imports, {"__future__", "types", "typing", "serverware"})
        self.assertFalse(any(isinstance(node, ast.Import) for node in tree.body))
        aliases = [alias for node in tree.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware" for alias in node.names
                   if alias.name == "authority_audit_capacity"]
        self.assertEqual([(alias.name, alias.asname) for alias in aliases],
                         [("authority_audit_capacity", "audit_capacity")])
        assignment = next(node for node in tree.body if isinstance(node, ast.AnnAssign)
                          and isinstance(node.target, ast.Name) and node.target.id == "AGGREGATE_BACKFILLS")
        declarations = assignment.value.args[0]
        entries = [(key, value) for key, value in zip(declarations.keys, declarations.values)
                   if isinstance(key, ast.Attribute) and ast.unparse(key) == "audit_capacity.AGGREGATE_KIND"]
        self.assertEqual(len(entries), 1)
        entry = entries[0][1].args[0]
        values = {ast.literal_eval(key): ast.unparse(value) for key, value in zip(entry.keys, entry.values)}
        for field, constant in {
            "aggregateId": "AGGREGATE_ID", "partitionDigest": "PARTITION_DIGEST",
            "capacityLimit": "MAX_PENDING", "stateSchema": "STATE_SCHEMA",
            "expiryIndexRootDigest": "EMPTY_EXPIRY_DIGEST", "maximumRowBytes": "MAX_COUNTER_BYTES",
        }.items():
            self.assertEqual(values[field], "audit_capacity." + constant)


if __name__ == "__main__":
    unittest.main()
