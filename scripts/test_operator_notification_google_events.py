#!/usr/bin/env python3
"""Pure Google audit projections over disposable SQLite, not lifecycle proof."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_operator_notification_events as base

events = base.events
ACTOR = "operator-google-audit-test"
REF = "00000000-0000-4000-8000-000000000001"
OTHER = "00000000-0000-4000-8000-000000000002"
OP = "00000000-0000-4000-8000-000000000003"
KINDS = (
    "operator_catalog.oauth.consent_started", "operator_catalog.oauth.account_connected",
    "operator_catalog.oauth.consent_failed", "credential.oauth_refreshed", "credential.oauth_refresh_failed",
    "operator_catalog.oauth.reauthorization_started", "operator_catalog.oauth.reauthorized",
    "operator_catalog.oauth.reauthorization_failed", "operator_catalog.oauth.disconnect_requested",
    "operator_catalog.oauth.disconnect_provider_accepted", "operator_catalog.oauth.disconnect_retry_retained",
    "operator_catalog.oauth.cleanup_quarantined", "operator_catalog.oauth.cleanup_fenced",
    "operator_catalog.oauth.refresh_rejected",
)
SAFE = {"actor_type", "actor_id", "provider", "intent_id", "credential_id", "operation_id", "work_id",
    "revision", "catalog_revision", "policy_hash", "policy_sequence", "credential_version",
    "previous_credential_version", "credential_generation", "previous_credential_generation",
    "original_oauth_intent_id", "affected_rule_count", "application_count", "credential_count",
    "revoked_rule_count", "attempts"}


def vector(kind):
    """Independent literal producer-shaped vectors; actual writers are tested separately."""
    common = {"revision": 3, "policy_hash": base.DIGEST}
    payloads = (
        {**common, "intent_id": OP, "provider": "google", "status": "awaiting_consent", "credential_id": None, "reason": None},
        {**common, "intent_id": OP, "provider": "google", "status": "connected", "credential_id": REF, "reason": None},
        {"intent_id": OP, "provider": "google", "reason": "consent_denied"},
        {"credential_id": REF, "provider": "google", "previous_credential_version": 1, "credential_version": 2,
            "expires_at_epoch_ms": base.NOW_MS + 60000, "refresh_token_rotated": True, "scopes": [base.CANARY]},
        {"credential_id": REF, "provider": "google", "credential_version": 2, "reason": "OAuthError"},
        {**common, "operation_id": OP, "credential_id": REF, "credential_generation": 1, "affected_rule_ids": [OTHER]},
        {**common, "schema": "serverware.operatorGoogleReauthorizationReceipt/v1", "operation_id": OP,
            "credential_id": REF, "previous_credential_generation": 1, "credential_generation": 2,
            "original_oauth_intent_id": OTHER, "affected_rule_ids": [OTHER], "application_ids": [REF]},
        {"operation_id": OP, "credential_id": REF, "status": "denied", "reason": "consent_denied", "provider_revocation": "not_requested"},
        {**common, "schema": "serverware.operatorGoogleDisconnectReceipt/v1", "operation_id": OP,
            "credential_id": REF, "actor_id": ACTOR, "project_wide_acknowledged": True, "policy_sequence": 2,
            "credential_ids": [REF], "affected_rule_ids": [OTHER], "affected_application_ids": [REF]},
        {"operation_id": OP, "credential_id": REF, "provider": "google", "provider_outcome": "accepted",
            "propagation": "not_proven", "reconnect": "blocked"},
        {"operation_id": OP, "credential_id": REF, "attempts": 1, "next_attempt_at": base.EXPIRES, "provider_outcome": "not_proven"},
        {**common, "work_id": OP, "credential_ids": [REF], "revoked_rule_ids": [OTHER], "reason": "explicit_disconnect"},
        {"schema": "serverware.operatorGoogleCleanupFence/v1", "work_id": OP, "source": "operator_google_disconnect_v1",
            "catalog_revision": 3, "policy_hash": base.DIGEST, "credential_ids": [REF]},
        {"schema": "serverware.operatorGoogleRefreshRejected/v1", "work_id": OP, "credential_id": REF,
            "credential_generation": 2, "source": "operator_google_refresh_v1", "outcome": "definite_refresh_rejected",
            "issued_material": False, "provider_revocation": "not_requested", "http_status": 400, "error_code": "invalid_grant"},
    )
    payload = deepcopy(payloads[KINDS.index(kind)])
    actor_type = "system" if kind in (KINDS[3], KINDS[4], KINDS[13]) else "admin"
    actor = "oauth-refresh" if kind in (KINDS[3], KINDS[4]) else ACTOR
    identifier = ("operator-google-reauthorized:" + OP if kind == KINDS[6] else
        "operator-google-refresh-rejected:" + OP if kind == KINDS[13] else str(uuid.uuid4()))
    return payload, {"actor_type": actor_type, "actor": actor, "identifier": identifier}


class GoogleEventTests(unittest.TestCase):
    setUp = base.EventTests.setUp
    tearDown = base.EventTests.tearDown
    reader = base.EventTests.reader
    append = base.EventTests.append
    read = base.EventTests.read

    def add(self, kind, *, changes=None, **metadata):
        payload, fields = vector(kind)
        payload.update(changes or {})
        fields.update(metadata)
        identifier = self.append(kind, payload, **fields)
        return identifier

    def one(self, identifier):
        return next(item for item in self.read()[0] if item.event_id == identifier)

    def test_current_audit_roster_and_unchanged_action_sources(self):
        self.assertEqual(len(events.AUDIT_EVENT_TYPES), 67)
        self.assertTrue(set(KINDS) <= set(events.AUDIT_EVENT_TYPES))
        self.assertFalse(set(KINDS) & set(events.ACTION_EVENT_TYPES))
        self.assertEqual(set(events.ACTION_EVENT_TYPES), {"approval.requested", "control_plane.approval.requested",
            "native_pilot.prepare_available", "native_pilot.confirmation_available", "native_pilot.security_key_available"})
        for suffix in ("intent_created", "exchange_claimed", "reauthorization_schema_admitted"):
            self.assertNotIn("operator_catalog.oauth." + suffix, events.AUDIT_EVENT_TYPES)

    def test_all_fourteen_closed_projections_and_final_source_recheck(self):
        for kind in KINDS:
            self.add(kind)
        batch, cursor = self.read()
        self.assertEqual(cursor.rowid, 14)
        self.assertEqual(tuple(item.event_type for item in batch), KINDS)
        with self.reader(forbid_secrets=True) as conn:
            for item in batch:
                self.assertIsNone(item.action_payload)
                value = item.audit_payload
                self.assertEqual(set(value), {"schema", "channel", "source", "summary", "review_path", "details", "projection"})
                self.assertEqual((value["channel"], value["review_path"], value["projection"]), ("audit_log", "/#audit", "approved_fields"))
                self.assertEqual(value["details"]["provider"], "google")
                self.assertLessEqual(set(value["details"]), SAFE)
                self.assertTrue(events.payload_matches_source(conn, value, now_epoch_ms=base.NOW_MS))
                self.assertFalse(events.action_is_current(conn, value, now_epoch_ms=base.NOW_MS))
        self.assertEqual(batch[6].audit_payload["details"]["affected_rule_count"], 1)
        self.assertEqual(batch[11].audit_payload["details"]["revoked_rule_count"], 1)

    def test_private_producer_receipts_and_unknown_fields_never_export(self):
        private = {key: base.CANARY for key in ("email", "provider_account", "provider_subject", "oauth_client_id",
            "client_secret", "access_token", "refresh_token", "state", "code", "authorization_url", "name", "error")}
        private["scopes"] = [base.CANARY]
        private["nested"] = {"secret": base.CANARY}
        for kind in KINDS:
            self.add(kind, changes=private)
        batch, _ = self.read()
        self.assertEqual(len(batch), 14)
        self.assertNotIn(base.CANARY, json.dumps([item.audit_payload for item in batch]))
        for item in batch:
            self.assertTrue(set(item.audit_payload["details"]).isdisjoint(private))

    def test_actor_refusal_in_initial_projection_and_after_queue(self):
        for kind in KINDS:
            identifier = self.add(kind)
            accepted = self.one(identifier).audit_payload
            self.writer.execute("UPDATE audit_events SET actor_type='proxy' WHERE id=?", (identifier,))
            self.writer.commit()
            self.assertFalse(any(item.event_id == identifier for item in self.read()[0]))
            with self.reader() as conn:
                self.assertFalse(events.payload_matches_source(conn, accepted, now_epoch_ms=base.NOW_MS))
        for kind in (KINDS[3], KINDS[4]):
            identifier = self.add(kind, actor="not-oauth-refresh")
            self.assertFalse(any(item.event_id == identifier for item in self.read()[0]))

    def test_generic_refresh_requires_explicit_google_provider(self):
        for kind in (KINDS[3], KINDS[4]):
            for provider in (None, "x", "Google", ["google"], True):
                identifier = self.add(kind, changes={"provider": provider})
                self.assertFalse(any(item.event_id == identifier for item in self.read()[0]))
        self.assertEqual(self.read()[0], ())

    def test_deterministic_id_type_and_body_binding(self):
        for kind, prefix, key in ((KINDS[6], "operator-google-reauthorized:", "operation_id"),
                                 (KINDS[13], "operator-google-refresh-rejected:", "work_id")):
            invalid_hash = "sha256:" + ("b" if key == "operation_id" else "c") * 64
            for identifier in (str(uuid.uuid4()), invalid_hash, prefix + OTHER,
                               prefix + "00000000-0000-4000-8000-00000000000A",
                               prefix + "{" + OP + "}", prefix + OP + ":extra", "wrong:" + prefix + OP):
                self.add(kind, identifier=identifier)
            self.assertEqual(self.read()[0], ())
            identifier = self.add(kind)
            accepted = self.one(identifier).audit_payload
            payload, _ = vector(kind)
            payload[key] = OTHER
            self.writer.execute("UPDATE audit_events SET event_json=? WHERE id=?", (json.dumps(payload), identifier))
            self.writer.commit()
            with self.reader() as conn:
                self.assertFalse(events.payload_matches_source(conn, accepted, now_epoch_ms=base.NOW_MS))
        self.add(KINDS[0], identifier=base.DIGEST)
        self.assertEqual(self.read()[0], ())

    def test_lifecycle_status_and_exact_boolean_guards(self):
        cases = ((0, "status", "connected"), (1, "credential_id", None), (2, "reason", "raw-provider-error"),
            (3, "refresh_token_rotated", 1), (3, "credential_version", True), (4, "reason", "raw-provider-error"),
            (5, "credential_generation", False), (6, "schema", "wrong"), (6, "previous_credential_generation", 2),
            (7, "provider_revocation", "accepted"), (7, "status", "adopted"), (8, "actor_id", "another-admin"),
            (8, "project_wide_acknowledged", 1), (9, "propagation", "proven"), (9, "provider", "x"),
            (10, "attempts", True), (11, "reason", "raw-provider-error"), (12, "source", "generic_refresh"),
            (13, "issued_material", 0), (13, "http_status", True), (13, "http_status", 401))
        for index, key, value in cases:
            payload, fields = vector(KINDS[index])
            # Deterministic producer IDs still must be unique in this test DB.
            if index in (6, 13):
                identifier = str(uuid.uuid4())
                payload["operation_id" if index == 6 else "work_id"] = identifier
                fields["identifier"] = ("operator-google-reauthorized:" if index == 6 else "operator-google-refresh-rejected:") + identifier
            payload[key] = value
            self.append(KINDS[index], payload, **fields)
        self.assertEqual(self.read()[0], ())

    def test_uuid_lists_are_closed_unique_sorted_and_counted(self):
        for value in (None, {}, [True], [REF, REF], [OTHER, REF], ["private-account-name"]):
            self.add(KINDS[11], changes={"credential_ids": value})
        self.assertEqual(self.read()[0], ())
        identifier = self.add(KINDS[11], changes={"credential_ids": [], "revoked_rule_ids": []})
        self.assertEqual(self.one(identifier).audit_payload["details"]["credential_count"], 0)

    def test_invalid_calendar_skips_without_blocking_later_event(self):
        self.add(KINDS[10], changes={"next_attempt_at": "2026-99-01T00:00:00Z"})
        identifier = self.add(KINDS[1])
        batch, cursor = self.read()
        self.assertEqual(cursor.rowid, 2)
        self.assertEqual([item.event_id for item in batch], [identifier])

    def test_final_recheck_binds_projected_references_without_current_owner(self):
        identifier = self.add(KINDS[1])
        accepted = self.one(identifier).audit_payload
        with self.reader(forbid_secrets=True) as conn:
            self.assertTrue(events.payload_matches_source(conn, accepted, now_epoch_ms=base.NOW_MS + 86400000))
        payload, _ = vector(KINDS[1])
        payload["credential_id"] = OTHER
        self.writer.execute("UPDATE audit_events SET event_json=? WHERE id=?", (json.dumps(payload), identifier))
        self.writer.commit()
        with self.reader() as conn:
            self.assertFalse(events.payload_matches_source(conn, accepted, now_epoch_ms=base.NOW_MS))

    def test_malformed_google_has_no_metadata_fallback_but_old_events_keep_it(self):
        for kind in KINDS:
            _, fields = vector(kind)
            self.append(kind, raw="[]", **fields)
        identifier = self.append("operator_catalog.application.created", raw="[]")
        batch, cursor = self.read()
        self.assertEqual(cursor.rowid, 15)
        self.assertEqual([item.event_id for item in batch], [identifier])
        self.assertEqual(batch[0].audit_payload["projection"], "metadata_only")


if __name__ == "__main__":
    unittest.main(verbosity=2)
