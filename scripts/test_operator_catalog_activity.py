#!/usr/bin/env python3
"""Real SQLite projection controls; no app, provider, or audit-chain proof.

Run once with a private TMPDIR under the bounded network-none Python harness.
Fixtures are synthetic durable rows, not evidence of client delivery.
"""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import operator_catalog_activity as activity

NOW = 1_800_000_000_000
CREDENTIAL = str(uuid.UUID(int=1))
OTHER_CREDENTIAL = str(uuid.UUID(int=2))
APPLICATION = str(uuid.UUID(int=3))
OTHER_APPLICATION = str(uuid.UUID(int=4))
RULE = str(uuid.UUID(int=5))
OTHER_RULE = str(uuid.UUID(int=6))
START = "data_plane.credential.release_started"
RELEASE = "data_plane.response.released"
BLOCK = "data_plane.response.blocked"
REFRESH = "credential.oauth_refreshed"
FAILURE = "credential.oauth_refresh_failed"
SECRET = "synthetic-private-token-or-provider-error-never-project"


def digest(value):
    return "sha256:" + format(value, "064x")


def timestamp(epoch_ms):
    return datetime.fromtimestamp(epoch_ms / 1000, timezone.utc).isoformat()


def catalog():
    return {
        "credentials": [
            {"id": CREDENTIAL, "auth_type": "google_oauth", "status": "active"},
            {"id": OTHER_CREDENTIAL, "auth_type": "bearer", "status": "revoked"},
        ],
        "applications": [
            {"id": APPLICATION, "principal_id": "agent:one"},
            {"id": OTHER_APPLICATION, "principal_id": "agent:two"},
        ],
        "access_rules": [
            {"id": RULE, "route_id": "route:one", "credential_id": CREDENTIAL,
             "application_id": APPLICATION},
            {"id": OTHER_RULE, "route_id": "route:two", "credential_id": OTHER_CREDENTIAL,
             "application_id": OTHER_APPLICATION},
        ],
    }


def refresh(version=2, **changes):
    return {"credential_id": CREDENTIAL, "provider": "google",
            "previous_credential_version": version - 1, "credential_version": version,
            **changes}


def response(*, attempt=1, credential=CREDENTIAL, principal="agent:one", route="route:one"):
    common = {"component": "serverware-decision-gate-rs", "attempt_id": digest(attempt),
              "flow_id": digest(attempt), "credential_ref": credential, "credential_version": 2,
              "principal_id": principal, "route_id": route, "policy_hash": digest(10),
              "request_digest": digest(11), "operation_digest": digest(12), "method": "GET"}
    return ({**common, "outcome": "release_started"},
            {**common, "outcome": "released", "upstream_status": 200,
             "response_body_sha256": digest(13), "response_body_bytes": 12})


class SQLiteFixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="operator-activity-",
            dir=os.environ.get("TMPDIR", "/srv/catchplate-fast/tmp"))
        self.path = Path(self.temp.name) / "audit.sqlite3"
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("CREATE TABLE audit_events (id TEXT PRIMARY KEY, event_type TEXT, "
                          "actor_type TEXT, actor_id TEXT, event_json TEXT, created_at TEXT)")
        self.conn.commit()
        self.catalog = catalog()
        self.serial = 100
        self.last_statements = []

    def close(self):
        self.conn.close()
        self.temp.cleanup()

    def clear(self):
        self.conn.execute("DELETE FROM audit_events")
        self.conn.commit()

    def add(self, kind, event=None, *, when=NOW - 1000, actor_type=None,
            actor_id=None, raw=None, sql_text=False, **columns):
        self.serial += 1
        row = {"id": digest(self.serial), "event_type": kind,
               "actor_type": actor_type or ("system" if kind in {REFRESH, FAILURE} else "data-plane"),
               "actor_id": actor_id or ("oauth-refresh" if kind in {REFRESH, FAILURE} else "gate:one"),
               "event_json": json.dumps(event or {}, separators=(",", ":")) if raw is None else raw,
               "created_at": timestamp(when), **columns}
        values = [row[key] for key in ("id", "event_type", "actor_type", "actor_id", "event_json", "created_at")]
        slots = "?,?,?,?,CAST(? AS TEXT),?" if sql_text else "?,?,?,?,?,?"
        self.conn.execute("INSERT INTO audit_events VALUES (" + slots + ")", values)
        self.conn.commit()
        return row["id"]

    def pair(self, *, attempt=1, start_when=NOW - 2000, release_when=NOW - 1000,
             start_changes=None, release_changes=None, start_actor="gate:one", release_actor="gate:one",
             **scope):
        start, released = response(attempt=attempt, **scope)
        start.update(start_changes or {})
        released.update(release_changes or {})
        first = self.add(START, start, when=start_when, actor_id=start_actor)
        last = self.add(RELEASE, released, when=release_when, actor_id=release_actor)
        return first, last

    def rows(self):
        # CAST permits inspecting intentionally invalid UTF-8 test rows safely.
        return self.conn.execute("SELECT rowid,CAST(id AS BLOB),CAST(event_type AS BLOB),"
            "CAST(actor_type AS BLOB),CAST(actor_id AS BLOB),CAST(event_json AS BLOB),"
            "CAST(created_at AS BLOB) FROM audit_events ORDER BY rowid").fetchall()

    def project(self, *, value=None, now=NOW, transaction=True):
        before, logical = self.rows(), deepcopy(self.catalog if value is None else value)
        supplied = deepcopy(logical)
        denied, statements = [], []
        with closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)) as reader:
            try:
                reader.execute("PRAGMA query_only=ON")
                if transaction:
                    reader.execute("BEGIN")
                changes = reader.total_changes

                def authorize(action, first, second, database, source):
                    if action not in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
                                      sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}:
                        denied.append(action)
                        return sqlite3.SQLITE_DENY
                    return sqlite3.SQLITE_OK

                reader.set_authorizer(authorize)
                reader.set_trace_callback(statements.append)
                result = activity.project(reader, supplied, observed_at_epoch_ms=now)
                assert reader.total_changes == changes
                assert reader.in_transaction == transaction
                assert not denied, "projection attempted a non-read SQLite action"
            finally:
                reader.set_authorizer(None)
                reader.set_trace_callback(None)
                reader.rollback()
        assert self.rows() == before, "projection changed durable rows"
        assert supplied == logical, "projection changed catalog input"
        self.last_statements = statements
        return result


class OperatorCatalogActivityTests(unittest.TestCase):
    def setUp(self):
        self.f = SQLiteFixture()
        self.addCleanup(self.f.close)

    def account(self, result, identifier=CREDENTIAL):
        self.assertEqual(result["status"], "available")
        return next(row for row in result["accounts"] if row["credential_id"] == identifier)

    def assert_unobserved(self, result):
        self.assertTrue(all(row["last_successful_response"] is None for row in result["accounts"]))

    def test_empty_window_is_available_not_health_or_chain_proof(self):
        result = self.f.project()
        self.assertEqual(result["schema"], "serverware.operatorAccountActivity/v1")
        self.assertEqual(result["chain_verification"], "not_checked")
        self.assertEqual(result["observed_at_epoch_ms"], NOW)
        self.assertEqual(len(result["accounts"]), 2)
        self.assertEqual(result["window"]["rows_scanned"], 0)
        self.assertEqual(result["window"]["bytes_read"], 0)
        self.assertFalse(result["window"]["incomplete"])
        self.assertEqual(self.account(result)["last_refresh_outcome"], "unobserved")
        self.assert_unobserved(result)

    def test_install_three_aliases_require_exact_methods_and_never_infer_package_completion(self):
        record = {"id": RULE, "route_id": "operator." + RULE, "name": "Install explicit closure",
            "application_id": APPLICATION, "credential_id": CREDENTIAL, "status": "active",
            "operation_bundle": "npm_install_v1", "packages": ["fixture-package"],
            "upstream_url": "https://registry.npmjs.org/", "methods": ["GET", "POST"],
            "request_fields": [], "response_fields": [], "query_keys": [],
            "allowed_headers": ["accept", "content-type", "npm-auth-type", "npm-command", "npm-in-ci", "npm-scope",
                "pacote-integrity", "pacote-pkg-id", "pacote-req-type", "pacote-version", "user-agent"],
            "response_mode": "npm_install_v1", "credential_input": "replace_exact",
            "placeholder": "Bearer serverware-npm-placeholder-v1"}
        self.f.catalog["access_rules"][0] = record
        self.f.catalog["credentials"][0]["auth_type"] = "bearer"
        for suffix, method in (("", "GET"), (".tarball", "GET"), (".audit", "POST")):
            for admitted in (True, False):
                with self.subTest(suffix=suffix, admitted=admitted):
                    self.f.clear()
                    actual = method if admitted else "PUT"
                    _, terminal = self.f.pair(route=record["route_id"] + suffix,
                        start_changes={"method": actual}, release_changes={"method": actual})
                    result = self.f.project()
                    if admitted:
                        evidence = self.account(result)["last_successful_response"]
                        self.assertEqual(evidence["event_id"], terminal)
                        self.assertEqual(evidence["rule_id"], RULE)
                        self.assertFalse(result["window"]["incomplete"])
                        self.assertNotIn("installed", evidence)
                    else:
                        self.assert_unobserved(result)
                        self.assertEqual(result["window"]["unmatched_responses"], 1)
        self.f.clear()
        self.f.pair(route=record["route_id"] + ".other")
        self.assert_unobserved(self.f.project())

    def test_refresh_success_failure_use_recorded_time_then_rowid(self):
        failed = self.f.add(FAILURE, refresh(3), when=NOW - 1000)
        success = self.f.add(REFRESH, refresh(3), when=NOW - 2000)
        row = self.account(self.f.project())
        self.assertEqual(row["last_refresh_success"], {"event_id": success,
            "recorded_at_epoch_ms": NOW - 2000, "credential_version": 3})
        self.assertEqual(row["last_refresh_failure"]["event_id"], failed)
        self.assertEqual(row["last_refresh_outcome"], "failure")
        equal_later = self.f.add(REFRESH, refresh(4), when=NOW - 1000)
        row = self.account(self.f.project())
        self.assertEqual(row["last_refresh_outcome"], "success")
        self.assertEqual(row["last_refresh_success"]["event_id"], equal_later)

    def test_refresh_rejects_wrong_identity_provider_actor_and_generation(self):
        cases = [{"credential_id": OTHER_CREDENTIAL}, {"credential_id": str(uuid.UUID(int=99))},
                 {"provider": "other"}, {"credential_version": True}, {"credential_version": 0},
                 {"credential_version": "2"}, {"previous_credential_version": 2},
                 {"previous_credential_version": 3}, {"previous_credential_version": None}]
        for change in cases:
            with self.subTest(change=change):
                self.f.clear()
                self.f.add(REFRESH, refresh(**change))
                result = self.f.project()
                self.assertTrue(all(row["last_refresh_success"] is None for row in result["accounts"]))
        for field, value in (("actor_type", "data-plane"), ("actor_id", "other-refresh")):
            self.f.clear()
            self.f.add(REFRESH, refresh(), **{field: value})
            self.assertIsNone(self.account(self.f.project())["last_refresh_success"])

    def x_refresh_fixture(self):
        intent, work = str(uuid.UUID(int=71)), str(uuid.UUID(int=72))
        self.f.catalog["credentials"][0].update(auth_type="x_oauth", operator_x_account={
            "schema": "serverware.operatorXAccountBinding/v1", "intent_id": intent})
        return {"operation_id": intent, "provider": "x", "credential_id": CREDENTIAL,
            "work_id": work, "previous_credential_generation": 1,
            "credential_generation": 2, "revision": 9}

    def test_x_refresh_success_joins_real_producer_shape_to_retained_intent(self):
        event = self.x_refresh_fixture()
        identifier = str(uuid.UUID(int=73))
        self.f.add("operator_catalog.x_oauth.account_refreshed", event,
            id=identifier, actor_type="admin", actor_id="synthetic-consent-admin")
        result = self.f.project()
        self.assertEqual(self.account(result)["last_refresh_success"], {"event_id": identifier,
            "recorded_at_epoch_ms": NOW - 1000, "credential_version": 2})
        self.assertEqual(self.account(result)["last_refresh_outcome"], "success")
        self.assertIsNone(self.account(result)["last_refresh_failure"])
        self.assertNotIn(event["work_id"], json.dumps(result))
        self.assertNotIn(event["operation_id"], json.dumps(result))

    def test_x_refresh_rejects_crossed_intent_actor_generation_and_private_extras(self):
        event = self.x_refresh_fixture()
        cases = [{"operation_id": str(uuid.UUID(int=74))}, {"credential_id": OTHER_CREDENTIAL},
            {"provider": "google"}, {"work_id": "not-a-uuid"}, {"credential_generation": True},
            {"credential_generation": 3}, {"previous_credential_generation": 2},
            {"revision": True}, {"access_token": SECRET}, {"reason": SECRET}]
        for change in cases:
            with self.subTest(change=change):
                self.f.clear()
                self.f.add("operator_catalog.x_oauth.account_refreshed", {**event, **change},
                    id=str(uuid.UUID(int=73)), actor_type="admin", actor_id="synthetic-consent-admin")
                result = self.f.project()
                self.assertIsNone(self.account(result)["last_refresh_success"])
                self.assertEqual(result["window"]["invalid_events"], 1)
                self.assertNotIn(SECRET, json.dumps(result))
        for changes in ({"actor_type": "system"}, {"id": digest(73)}):
            self.f.clear()
            self.f.add("operator_catalog.x_oauth.account_refreshed", event,
                **{"id": str(uuid.UUID(int=73)), "actor_type": "admin",
                    "actor_id": "synthetic-consent-admin", **changes})
            self.assertIsNone(self.account(self.f.project())["last_refresh_success"])

    def test_x_uncertain_operation_and_google_refresh_never_invent_failure(self):
        event = self.x_refresh_fixture()
        self.f.add("operator_catalog.x_oauth.operation_uncertain", {"operation_id": event["operation_id"],
            "provider": "x", "credential_id": CREDENTIAL, "work_id": event["work_id"],
            "reason": "refresh_failed"}, actor_type="admin", actor_id="synthetic-consent-admin")
        self.f.add(FAILURE, refresh(provider="x"))
        self.f.add(REFRESH, refresh())
        account = self.account(self.f.project())
        self.assertIsNone(account["last_refresh_success"])
        self.assertIsNone(account["last_refresh_failure"])
        self.assertEqual(account["last_refresh_outcome"], "unobserved")

    def test_joined_response_supports_oauth_and_retained_static_credentials(self):
        for credential, principal, route, app, rule in (
            (CREDENTIAL, "agent:one", "route:one", APPLICATION, RULE),
            (OTHER_CREDENTIAL, "agent:two", "route:two", OTHER_APPLICATION, OTHER_RULE),
        ):
            with self.subTest(credential=credential):
                self.f.clear()
                _, terminal = self.f.pair(credential=credential, principal=principal, route=route)
                result = self.f.project()
                self.assertEqual(self.account(result, credential)["last_successful_response"],
                    {"event_id": terminal, "recorded_at_epoch_ms": NOW - 1000,
                     "credential_version": 2, "application_id": app, "rule_id": rule})
                self.assertFalse(result["window"]["incomplete"])

    def test_crossed_join_fields_never_select_a_response(self):
        changes = {"credential_ref": OTHER_CREDENTIAL, "credential_version": 3,
                   "principal_id": "agent:two", "route_id": "route:two", "policy_hash": digest(31),
                   "request_digest": digest(32), "operation_digest": digest(33), "method": "POST",
                   "attempt_id": digest(34), "flow_id": digest(35), "component": "other"}
        for field, value in changes.items():
            with self.subTest(field=field):
                self.f.clear()
                self.f.pair(release_changes={field: value})
                result = self.f.project()
                self.assert_unobserved(result)
                self.assertEqual(result["window"]["unmatched_responses"], 1)
        self.f.clear()
        self.f.pair(release_actor="gate:another-instance")
        self.assert_unobserved(self.f.project())

    def test_missing_required_response_identity_and_evidence_are_unmatched(self):
        fields = ("credential_ref", "credential_version", "principal_id", "route_id", "policy_hash",
                  "request_digest", "operation_digest", "attempt_id", "flow_id", "method",
                  "response_body_sha256", "response_body_bytes", "upstream_status")
        for field in fields:
            with self.subTest(field=field):
                self.f.clear()
                self.f.pair(release_changes={field: None})
                result = self.f.project()
                self.assert_unobserved(result)
                self.assertTrue(result["window"]["incomplete"])

    def test_catalog_identity_must_bind_credential_application_and_rule(self):
        self.f.pair()
        for collection, key, value in (("access_rules", "credential_id", OTHER_CREDENTIAL),
                ("access_rules", "application_id", OTHER_APPLICATION),
                ("access_rules", "route_id", "route:not-this-one"),
                ("applications", "principal_id", "agent:not-this-one")):
            with self.subTest(key=key):
                changed = deepcopy(self.f.catalog)
                changed[collection][0][key] = value
                result = self.f.project(value=changed)
                self.assertEqual(result["status"], "available")
                self.assert_unobserved(result)

    def test_missing_duplicate_and_blocked_attempt_members_disqualify(self):
        for extra in (None, START, RELEASE, BLOCK):
            with self.subTest(extra=extra):
                self.f.clear()
                start, released = response()
                if extra is not None:
                    self.f.add(START, start)
                self.f.add(RELEASE, released)
                if extra is not None:
                    self.f.add(extra, start if extra == START else released)
                result = self.f.project()
                self.assert_unobserved(result)
                self.assertEqual(result["window"]["unmatched_responses"], 2 if extra == RELEASE else 1)

    def test_release_before_durable_start_is_not_a_pair(self):
        start, released = response()
        self.f.add(RELEASE, released, when=NOW - 1000)
        self.f.add(START, start, when=NOW - 2000)
        result = self.f.project()
        self.assert_unobserved(result)
        self.assertEqual(result["window"]["unmatched_responses"], 1)

    def test_clock_regression_does_not_replace_terminal_time_order(self):
        _, earlier = self.f.pair(attempt=1, start_when=NOW - 500, release_when=NOW - 2000)
        _, later = self.f.pair(attempt=2, start_when=NOW - 4000, release_when=NOW - 1000)
        result = self.f.project()
        self.assertNotEqual(earlier, later)
        self.assertEqual(self.account(result)["last_successful_response"]["event_id"], later)
        self.assertFalse(result["window"]["incomplete"])
        self.f.clear()
        _, regressed = self.f.pair(start_when=NOW - 500, release_when=NOW - 2000)
        self.assertEqual(self.account(self.f.project())["last_successful_response"]["event_id"], regressed)

    def test_unsuccessful_or_malformed_terminal_evidence_is_not_success(self):
        for change in ({"upstream_status": 199}, {"upstream_status": 300}, {"upstream_status": 401},
                {"upstream_status": 500}, {"upstream_status": True}, {"upstream_status": "200"},
                {"outcome": "blocked"}, {"response_body_bytes": -1}, {"response_body_bytes": True},
                {"response_body_sha256": "not-a-digest"}, {"credential_version": True}):
            with self.subTest(change=change):
                self.f.clear()
                self.f.pair(release_changes=change)
                self.assert_unobserved(self.f.project())

    def test_global_tail_limit_excludes_old_evidence_and_reports_precision(self):
        self.f.add(REFRESH, refresh())
        for _ in range(256):
            self.f.add("unrelated.event", {})
        result = self.f.project()
        self.assertEqual(result["window"]["rows_scanned"], 256)
        self.assertTrue(result["window"]["has_older_rows"])
        self.assertTrue(result["window"]["incomplete"])
        self.assertEqual(result["window"]["bytes_read"], 0)
        self.assertIsNone(self.account(result)["last_refresh_success"])

    def test_per_event_and_total_byte_limits_are_inclusive(self):
        raw = json.dumps(refresh(), separators=(",", ":"))
        exact = raw + " " * (16384 - len(raw.encode()))
        self.f.add(REFRESH, raw=exact)
        result = self.f.project()
        self.assertIsNotNone(self.account(result)["last_refresh_success"])
        self.assertEqual(result["window"]["bytes_read"], 16384)
        self.f.clear()
        self.f.add(REFRESH, raw=exact + " ")
        result = self.f.project()
        self.assertEqual(result["window"]["oversized_events"], 1)
        self.assertEqual(result["window"]["bytes_read"], 0)
        self.assertTrue(result["window"]["incomplete"])
        self.f.clear()
        for _ in range(129):
            self.f.add(REFRESH, raw=exact)
        result = self.f.project()
        self.assertEqual(result["window"]["bytes_read"], 2097152)
        self.assertTrue(result["window"]["byte_budget_exhausted"])
        self.assertEqual(result["window"]["rows_scanned"], 129)
        self.assertTrue(result["window"]["incomplete"])

    def test_malformed_json_unicode_and_structure_never_project(self):
        invalid = ["{", "[]", '{"credential_id":1,"credential_id":2}', '{"value":NaN}',
                   '{"value":1e9999}', '{"value":"\\ud800"}',
                   '{"value":' + "[" * 34 + "0" + "]" * 34 + "}",
                   '{"value":[' + ",".join("0" for _ in range(4096)) + "]}"]
        for raw in invalid:
            with self.subTest(raw=raw[:30]):
                self.f.clear()
                self.f.add(REFRESH, raw=raw)
                result = self.f.project()
                self.assertEqual(result["window"]["invalid_events"], 1)
                self.assertIsNone(self.account(result)["last_refresh_success"])
        self.f.clear()
        self.f.add(REFRESH, raw=b'{"value":"\xff"}', sql_text=True)
        self.assertEqual(self.f.project()["window"]["invalid_events"], 1)
        self.f.clear()
        self.f.add(REFRESH, raw=b"{}")
        self.assertEqual(self.f.project()["window"]["bytes_read"], 0)

    def test_oversized_sql_metadata_is_rejected_before_payload_fetch(self):
        for field, limit in (("id", 80), ("event_type", 96), ("actor_type", 32),
                             ("actor_id", 256), ("created_at", 64)):
            with self.subTest(field=field):
                self.f.clear()
                self.f.add(REFRESH, refresh(), **{field: "x" * (limit + 1)})
                result = self.f.project()
                self.assertEqual(result["window"]["invalid_events"], 1)
                self.assertEqual(result["window"]["bytes_read"], 0)
                self.assertTrue(result["window"]["incomplete"])

    def test_invalid_future_and_naive_timestamps_are_not_observations(self):
        for value in ("not-a-date", "2026-10-09T12:00:00", timestamp(NOW + 1),
                      "1969-12-31T23:59:59+00:00", "", 123):
            with self.subTest(value=value):
                self.f.clear()
                self.f.add(REFRESH, refresh(), created_at=value)
                result = self.f.project()
                self.assertEqual(result["window"]["invalid_events"], 1)
                self.assertIsNone(self.account(result)["last_refresh_success"])

    def test_persistence_and_projection_have_zero_logical_writes(self):
        self.f.add(REFRESH, refresh())
        self.f.pair()
        before = self.f.path.read_bytes()
        first = self.f.project()
        self.f.conn.close()
        self.f.conn = sqlite3.connect(self.f.path)
        second = self.f.project()
        self.assertEqual(first, second)
        self.assertEqual(self.f.path.read_bytes(), before)
        self.assertTrue(self.f.last_statements)
        self.assertTrue(all(statement.lstrip().upper().startswith("SELECT ")
                            for statement in self.f.last_statements))
        self.assertNotIn("serverware.app", sys.modules)
        self.assertNotIn("serverware.db", sys.modules)
        self.assertNotIn("serverware.config", sys.modules)

    def test_missing_snapshot_invalid_catalog_or_store_is_unavailable(self):
        candidates = [self.f.project(transaction=False), self.f.project(now=True)]
        for collection in ("credentials", "applications", "access_rules"):
            changed = deepcopy(self.f.catalog)
            changed[collection].append(deepcopy(changed[collection][0]))
            candidates.append(self.f.project(value=changed))
        self.f.conn.execute("DROP TABLE audit_events")
        self.f.conn.commit()
        with sqlite3.connect(self.f.path) as reader:
            reader.execute("BEGIN")
            candidates.append(activity.project(reader, self.f.catalog, observed_at_epoch_ms=NOW))
        for result in candidates:
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["accounts"], [])
            self.assertTrue(result["window"]["incomplete"])

    def test_public_allowlist_omits_raw_payloads_secrets_and_internal_joins(self):
        self.f.catalog["credentials"][0]["secret"] = SECRET
        self.f.add(REFRESH, refresh(secret=SECRET, provider_account=SECRET))
        self.f.add(FAILURE, refresh(reason=SECRET))
        self.f.pair(start_changes={"secret": SECRET}, release_changes={"url": SECRET,
            "headers": {"Authorization": SECRET}, "response_validation": {"private": SECRET}})
        result = self.f.project()
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(set(result), {"schema", "status", "observed_at_epoch_ms",
                                     "chain_verification", "window", "accounts"})
        self.assertEqual(set(result["window"]), {"row_limit", "event_byte_limit", "byte_limit",
            "rows_scanned", "bytes_read", "has_older_rows", "byte_budget_exhausted",
            "oversized_events", "invalid_events", "unmatched_responses", "incomplete"})
        self.assertEqual((result["window"]["row_limit"], result["window"]["event_byte_limit"],
                          result["window"]["byte_limit"]), (256, 16384, 2097152))
        for row in result["accounts"]:
            self.assertEqual(set(row), {"credential_id", "last_successful_response",
                "last_refresh_success", "last_refresh_failure", "last_refresh_outcome"})
            for key in ("last_refresh_success", "last_refresh_failure", "last_successful_response"):
                if row[key] is not None:
                    expected = {"event_id", "recorded_at_epoch_ms", "credential_version"}
                    if key == "last_successful_response":
                        expected |= {"application_id", "rule_id"}
                    self.assertEqual(set(row[key]), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
