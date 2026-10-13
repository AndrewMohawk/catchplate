#!/usr/bin/env python3
"""Offline approval metadata/history: real db functions and disposable SQLite.

No production database, authority, native opener or HTTP server is exercised.
The UI's pure history formatter is extracted verbatim to avoid app startup.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_DATA = tempfile.TemporaryDirectory(prefix="approval-history-metadata-")
os.environ["SERVERWARE_PROCESS_MODE"] = "serverware-control-plane"
os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
os.environ["SERVERWARE_DATA_DIR"] = _DATA.name


def _no_external_io(event, _arguments):
    if event.startswith("socket.") or event in {
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
    }:
        raise AssertionError("history component attempted external I/O")


sys.addaudithook(_no_external_io)
from serverware import db


PUBLIC = ("id", "status", "requested_at", "expires_at", "approved_until",
          "decision_note", "approved_by", "approval_authn", "request_digest",
          "operation_digest")
FILTERS = ("principal_id", "route_id", "credential_id", "policy_hash")
PRIVATE = ("url", "canonical_request", "redacted_display", "approver_policy_json")
AUTHN = {"method": "webauthn", "authenticator_class": "hardware",
         "user_verified": True, "ignored_internal_field": "not rendered"}

# Independent expected roster, not derived from the implementation constant.
# Unlike similar-history rows, single-request public metadata includes the URL
# and complete retained policy, but never selects the private review documents.
METADATA_PUBLIC = (
    "id", "route_id", "method", "url", "status", "requested_at", "expires_at",
    "approved_until", "decision_note", "principal_id", "credential_id",
    "credential_version", "policy_hash", "request_digest", "operation_digest",
    "grant_ttl_seconds", "grant_max_uses", "approver_policy_digest",
    "verified_assertion_receipt_digest", "approved_by",
)
METADATA_PRIVATE = ("canonical_request", "redacted_display", "approval_authn")
STORED_POLICY = {
    "allowAnyApproverId": False, "allowedApproverIds": ["oidc:reviewer-a", "oidc:reviewer-b"],
    "requiredRoles": ["approver", "finance"], "requireWebAuthn": True, "threshold": 2,
    "credentialPolicy": {"userVerification": "required", "authenticatorClasses": ["hardware"],
                         "requireAttestation": True},
}


def actual_history_formatter():
    source = ROOT / "serverware/app.py"
    tree = ast.parse(source.read_text())
    selected = [node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == "_approval_history_item"]
    if len(selected) != 1 or selected[0].decorator_list:
        raise AssertionError("actual history formatter is not a single pure function")
    namespace = {"Any": object}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"), namespace)
    return namespace["_approval_history_item"]


class ApprovalHistoryMetadataTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.addCleanup(self.connection.close)
        self.connection.execute("CREATE TABLE approval_requests (" + ",".join(
            name + " TEXT" for name in PUBLIC + FILTERS + PRIVATE) + ")")
        self.approval = {"id": "current", **{name: name + "-selected" for name in FILTERS}}
        self.read_columns = set()
        self.denied_columns = []
        self.queries = []

        @contextmanager
        def local_connection():
            with self.connection:
                yield self.connection

        self.connect = patch.object(db, "connect", side_effect=local_connection).start()
        self.addCleanup(patch.stopall)
        self.decrypt = patch.object(db, "_decrypt_approval_json", side_effect=AssertionError(
            "history attempted document decryption")).start()
        self.convert = patch.object(db, "row_to_approval", side_effect=AssertionError(
            "history used the private document reader")).start()

    def insert(self, identifier, day, **changes):
        row = {"id": identifier, "status": "approved", "requested_at": f"2026-10-{day:02d}T00:00:00Z",
               "expires_at": "2026-10-31T00:00:00Z", "approved_until": "2026-10-31T00:01:00Z",
               "decision_note": "synthetic decision", "approved_by": "synthetic-reviewer",
               "approval_authn": json.dumps(AUTHN), "request_digest": "sha256:" + "1" * 64,
               "operation_digest": "sha256:" + "2" * 64,
               **{name: self.approval[name] for name in FILTERS},
               **{name: "v2:INVALID-PRIVATE-CANARY:" + name for name in PRIVATE}, **changes}
        self.connection.execute("INSERT INTO approval_requests (" + ",".join(row) +
            ") VALUES (" + ",".join("?" for _ in row) + ")", tuple(row.values()))

    def query(self, approval=None, limit=5):
        def authorize(action, table, column, _database, _trigger):
            if action == sqlite3.SQLITE_READ and table == "approval_requests":
                self.read_columns.add(column)
                if column not in PUBLIC + FILTERS:
                    self.denied_columns.append(column)
                    return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        self.connection.set_authorizer(authorize)
        self.connection.set_trace_callback(self.queries.append)
        before = self.connection.total_changes
        try:
            result = db.list_similar_approvals(self.approval if approval is None else approval, limit=limit)
        finally:
            self.connection.set_authorizer(None)
            self.connection.set_trace_callback(None)
        self.assertEqual(self.connection.total_changes, before)
        self.decrypt.assert_not_called()
        self.convert.assert_not_called()
        self.assertEqual(self.denied_columns, [])
        return result

    def test_invalid_ciphertext_never_selected_or_decrypted_and_caller_shape(self):
        self.insert("history", 10)
        rows = self.query()
        self.assertEqual(len(rows), 1)
        self.assertEqual(set(rows[0]), set(PUBLIC))
        self.assertEqual(rows[0]["approval_authn"], AUTHN)
        self.assertTrue(set(PUBLIC) <= self.read_columns)
        self.assertFalse(set(PRIVATE) & self.read_columns)
        formatted = actual_history_formatter()(rows[0])
        self.assertEqual(formatted, {**{name: rows[0][name] for name in PUBLIC if name != "approval_authn"},
            "authn": {name: AUTHN[name] for name in ("method", "authenticator_class", "user_verified")}})
        self.assertNotIn("INVALID-PRIVATE-CANARY", json.dumps(formatted))

    def test_filters_current_exclusion_order_and_limit_unchanged(self):
        self.insert("current", 31)
        self.insert("older", 8)
        self.insert("middle", 9, status="denied")
        self.insert("newest", 10, status="expired")
        for name in FILTERS:
            self.insert("different-" + name, 30, **{name: "different"})
        self.assertEqual([row["id"] for row in self.query()], ["newest", "middle", "older"])
        self.assertEqual([row["id"] for row in self.query(limit=2)], ["newest", "middle"])
        self.assertEqual(self.query(limit=0), [])

    def test_absent_optional_filters_keep_original_selection_semantics(self):
        self.insert("selected", 10)
        self.insert("other-principal", 11, principal_id="other")
        self.insert("other-route", 12, route_id="other")
        relaxed = {**self.approval, "principal_id": None}
        self.assertEqual([row["id"] for row in self.query(relaxed)], ["other-principal", "selected"])
        self.assertEqual([row["id"] for row in self.query({"id": "current"})],
                         ["other-route", "other-principal", "selected"])

    def test_null_authentication_and_parameterized_scope(self):
        special = "scope' OR 1=1 --"
        self.insert("special", 10, principal_id=special, approval_authn=None, operation_digest=None)
        self.insert("unrelated", 11)
        rows = self.query({**self.approval, "principal_id": special})
        self.assertEqual([row["id"] for row in rows], ["special"])
        self.assertIsNone(rows[0]["approval_authn"])
        self.assertIsNone(rows[0]["operation_digest"])
        self.assertEqual(actual_history_formatter()(rows[0])["authn"], {
            "method": None, "authenticator_class": None, "user_verified": None})


class ApprovalRequestMetadataTests(unittest.TestCase):
    """Actual SQLite projection, not private opening or authority admission."""
    def setUp(self):
        self.connection = sqlite3.connect(":memory:", cached_statements=0)
        self.connection.row_factory = sqlite3.Row
        self.addCleanup(self.connection.close)
        columns = METADATA_PUBLIC + ("approver_policy_json",) + METADATA_PRIVATE
        integers = {"credential_version", "grant_ttl_seconds", "grant_max_uses"}
        self.connection.execute("CREATE TABLE approval_requests (" + ",".join(
            name + (" INTEGER" if name in integers else " TEXT") +
            (" PRIMARY KEY" if name == "id" else "") for name in columns) + ")")

        @contextmanager
        def local_connection():
            yield self.connection

        for name, replacement in (
            ("connect", {"side_effect": local_connection}),
            ("_decrypt_approval_json", {"side_effect": AssertionError("metadata attempted private decryption")}),
            ("row_to_approval", {"side_effect": AssertionError("metadata used private document projection")}),
        ):
            patcher = patch.object(db, name, **replacement)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def insert(self, identifier="selected", **updates):
        row = {
            "id": identifier, "route_id": "route.synthetic", "method": "POST",
            "url": "https://public.example.test/reviewed-operation", "status": "pending",
            "requested_at": "2026-10-13T00:00:00Z", "expires_at": "2026-10-13T00:05:00Z",
            "approved_until": None, "decision_note": None, "principal_id": "agent:synthetic",
            "credential_id": "synthetic-credential", "credential_version": 7,
            "policy_hash": "sha256:" + "1" * 64, "request_digest": "sha256:" + "2" * 64,
            "operation_digest": "sha256:" + "3" * 64, "grant_ttl_seconds": 30,
            "grant_max_uses": 1, "approver_policy_digest": "sha256:" + "4" * 64,
            "verified_assertion_receipt_digest": None, "approved_by": None,
            "approver_policy_json": json.dumps(STORED_POLICY),
            **{name: "v2:INVALID-PRIVATE-CANARY:" + name for name in METADATA_PRIVATE}, **updates,
        }
        self.connection.execute("INSERT INTO approval_requests (" + ",".join(row) +
            ") VALUES (" + ",".join("?" for _ in row) + ")", tuple(row.values()))
        return {**{name: row[name] for name in METADATA_PUBLIC},
                "approver_policy": json.loads(row["approver_policy_json"]) if row["approver_policy_json"] else None}

    def query(self, identifier):
        selected = set()
        refused = []
        queries = []

        def authorize(action, table, column, _database, _trigger):
            if action == sqlite3.SQLITE_READ:
                if table != "approval_requests" or column not in METADATA_PUBLIC + ("approver_policy_json",):
                    refused.append((table, column))
                    return sqlite3.SQLITE_DENY
                selected.add(column)
            elif action != sqlite3.SQLITE_SELECT:
                refused.append((action, table))
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        before = self.connection.total_changes
        self.connection.set_authorizer(authorize)
        self.connection.set_trace_callback(queries.append)
        try:
            result = db.get_approval_request_metadata(identifier)
        finally:
            self.connection.set_authorizer(None)
            self.connection.set_trace_callback(None)
        self.assertEqual(self.connection.total_changes, before)
        self.assertEqual(refused, [])
        self.assertEqual(selected, set(METADATA_PUBLIC) | {"approver_policy_json"})
        self.assertEqual(len(queries), 1)
        self._decrypt_approval_json.assert_not_called()
        self.row_to_approval.assert_not_called()
        self.assertNotIn("INVALID-PRIVATE-CANARY", json.dumps(result))
        return result

    def test_exact_public_fields_and_stored_policy_survive_invalid_private_ciphertext(self):
        expected = self.insert()
        result = self.query("selected")
        self.assertEqual(result, expected)
        self.assertEqual(set(result), set(METADATA_PUBLIC) | {"approver_policy"})
        self.assertEqual(result["approver_policy"], STORED_POLICY)
        self.assertEqual(result["approver_policy"]["threshold"], 2)

    def test_exact_id_absence_and_parameter_binding(self):
        self.insert("unrelated")
        special = "approval' OR 1=1 --"
        expected = self.insert(special)
        self.assertIsNone(self.query("missing"))
        self.assertIsNone(self.query("unrelated' OR 1=1 --"))
        self.assertEqual(self.query(special), expected)

    def test_status_and_metadata_do_not_depend_on_private_document_availability(self):
        for index, (status, private) in enumerate((
            ("pending", None), ("approved", "{"), ("denied", b"\x00\xffciphertext"),
            ("expired", "v2:INVALID-PRIVATE-CANARY:no-key"),
        )):
            with self.subTest(status=status, private_type=type(private).__name__):
                identifier = "state-" + str(index)
                expected = self.insert(identifier, status=status,
                    **{name: private for name in METADATA_PRIVATE})
                self.assertEqual(self.query(identifier), expected)

    def test_absent_stored_policy_is_not_reconstructed_from_private_documents(self):
        expected = self.insert(approver_policy_json=None,
            canonical_request=json.dumps({"approver_policy": STORED_POLICY}),
            redacted_display=json.dumps({"approver_policy": STORED_POLICY}))
        self.assertIsNone(expected["approver_policy"])
        self.assertEqual(self.query("selected"), expected)


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        _DATA.cleanup()
