#!/usr/bin/env python3
"""Offline history projection: real db function and disposable SQLite only.

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


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        _DATA.cleanup()
