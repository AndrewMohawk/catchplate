#!/usr/bin/env python3
"""Offline native-reference refusal in actual legacy approval readers.

Only disposable in-memory SQLite and synthetic strings are used. No app/server,
authority transaction, native private opening, network or provider is exercised.
The review route body is extracted verbatim without importing the application.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_DATA = tempfile.TemporaryDirectory(prefix="native-jit-legacy-reader-")
os.environ["CATCHPLATE_PROCESS_MODE"] = "catchplate-control-plane"
os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"
os.environ["CATCHPLATE_DATA_DIR"] = _DATA.name


def _no_external_io(event, _arguments):
    if event.startswith("socket.") or event in {
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
    }:
        raise AssertionError("legacy reader test attempted external I/O")


sys.addaudithook(_no_external_io)
from catchplate import db


REFUSAL = "approval review payload is unavailable"
CANARY = "synthetic-private-reference-NEVER-DISPLAY"
# Namespace tests, not proof that any descriptor passes a native parser.
REFERENCES = (
    "native-jit:", "native-jit:v1:", "native-jit:v1:{}",
    'native-jit:v1:{"fixture":"' + CANARY + '"}',
    "native-jit:v0:" + CANARY, "native-jit:v2:" + CANARY,
    "native-jit:unknown:" + CANARY, "native-jit:\n" + CANARY,
)
PUBLIC = (
    "id", "route_id", "method", "url", "status", "requested_at", "expires_at",
    "approved_until", "decision_note", "principal_id", "credential_id",
    "credential_version", "policy_hash", "request_digest", "operation_digest",
    "grant_ttl_seconds", "grant_max_uses", "approver_policy_digest",
    "verified_assertion_receipt_digest", "approved_by",
)
PRIVATE = ("canonical_request", "redacted_display")
POLICY = {"threshold": 1, "allowedApproverIds": ["oidc:synthetic-reviewer"]}


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def row(**updates):
    return {
        "id": "synthetic-approval", "route_id": "route.synthetic", "method": "GET",
        "url": "sha256:" + "a" * 64, "status": "pending",
        "requested_at": "2026-10-13T00:00:00Z", "expires_at": "2026-10-13T00:05:00Z",
        "approved_until": None, "decision_note": None, "principal_id": "agent:synthetic",
        "credential_id": "credential.synthetic", "credential_version": 1,
        "policy_hash": "sha256:" + "b" * 64, "request_digest": "sha256:" + "c" * 64,
        "operation_digest": "sha256:" + "d" * 64, "grant_ttl_seconds": 30,
        "grant_max_uses": 1, "approver_policy_digest": "sha256:" + "e" * 64,
        "verified_assertion_receipt_digest": None, "approved_by": None,
        "approver_policy_json": json.dumps(POLICY), "approval_authn": None,
        "canonical_request": REFERENCES[3], "redacted_display": REFERENCES[3],
        **updates,
    }


class NamespaceGuardTests(unittest.TestCase):
    def test_reserved_family_refuses_before_legacy_decryption(self):
        with patch.object(db, "decrypt_secret", side_effect=AssertionError("unexpected decrypt")) as decrypt:
            for stored in REFERENCES:
                with self.subTest(prefix=stored.split(":", 2)[:2]):
                    with self.assertRaises(ValueError) as raised:
                        db._decrypt_approval_json(stored)
                    self.assertEqual(str(raised.exception), REFUSAL)
                    self.assertIsNone(raised.exception.__cause__)
                    self.assertNotIn(CANARY, str(raised.exception))
            decrypt.assert_not_called()

    def test_reference_is_never_hashed_as_a_plaintext_review_document(self):
        with patch.object(db, "decrypt_secret", side_effect=AssertionError("unexpected decrypt")) as decrypt, \
                patch.object(db, "_approval_json_digest", side_effect=AssertionError("reference was hashed")) as hashed:
            for stored in REFERENCES:
                with self.subTest(prefix=stored.split(":", 2)[:2]), self.assertRaises(ValueError) as raised:
                    db._stored_approval_json_digest(stored)
                self.assertEqual(str(raised.exception), REFUSAL)
            decrypt.assert_not_called()
            hashed.assert_not_called()

    def test_legacy_plaintext_and_nonreserved_prefix_semantics_unchanged(self):
        for text in ('{"method":"GET"}', "", "legacy non-JSON text", "native-jit-other:legacy",
                     '{"note":"native-jit:v1:embedded text is not a stored reference"}'):
            with self.subTest(kind=text[:20]):
                self.assertEqual(db._decrypt_approval_json(text), text)
                self.assertEqual(db._stored_approval_json_digest(text), digest(text))

    def test_legacy_v1_decryption_and_digest_unchanged(self):
        text = '{"method":"GET","legacy":1}'
        with patch.object(db, "decrypt_secret", return_value=text) as decrypt:
            self.assertEqual(db._decrypt_approval_json("v1:synthetic-ciphertext"), text)
            self.assertEqual(db._stored_approval_json_digest("v1:synthetic-ciphertext"), digest(text))
            self.assertEqual(decrypt.call_count, 2)
            self.assertTrue(all(call.args == ("v1:synthetic-ciphertext",) for call in decrypt.call_args_list))

    def test_legacy_v2_ciphertext_and_digest_fast_path_unchanged(self):
        text = '{"method":"GET","legacy":2}'
        stored = "v2:" + digest(text) + ":v1:synthetic-ciphertext"
        with patch.object(db, "encrypt_secret", return_value="v1:synthetic-ciphertext"):
            self.assertEqual(db._encrypt_approval_json(text), stored)
        with patch.object(db, "decrypt_secret", return_value=text) as decrypt:
            self.assertEqual(db._stored_approval_json_digest(stored), digest(text))
            decrypt.assert_not_called()
            self.assertEqual(db._decrypt_approval_json(stored), text)
            decrypt.assert_called_once_with("v1:synthetic-ciphertext")
            with self.assertRaisesRegex(ValueError, "^approval review payload digest mismatch$"):
                db._decrypt_approval_json("v2:" + "0" * 64 + ":v1:synthetic-ciphertext")
        with self.assertRaisesRegex(ValueError, "^approval review payload digest is invalid$"):
            db._stored_approval_json_digest("v2:invalid:v1:synthetic-ciphertext")

    def test_either_private_column_refuses_instead_of_becoming_an_empty_review(self):
        for column in PRIVATE:
            value = row(canonical_request='{"method":"GET"}', redacted_display='{"method":"GET"}')
            value[column] = REFERENCES[3]
            with self.subTest(column=column), patch.object(db, "decrypt_secret") as decrypt:
                with self.assertRaises(ValueError) as raised:
                    db.row_to_approval(value)
                self.assertEqual(str(raised.exception), REFUSAL)
                decrypt.assert_not_called()

    def test_legacy_url_recovery_refuses_with_a_fixed_error(self):
        with self.assertRaises(db.MetadataStoreError) as raised:
            db._legacy_jit_pending_approval_key_from_row(row())
        self.assertEqual(str(raised.exception), "pending approval legacy URL recovery value is invalid")
        self.assertEqual(str(raised.exception.__cause__), REFUSAL)
        self.assertNotIn(CANARY, str(raised.exception))


class StoredReaderTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:", cached_statements=0)
        self.connection.row_factory = sqlite3.Row
        self.addCleanup(self.connection.close)
        columns = PUBLIC + ("approver_policy_json", "approval_authn") + PRIVATE
        integers = {"credential_version", "grant_ttl_seconds", "grant_max_uses"}
        self.connection.execute("CREATE TABLE approval_requests (" + ",".join(
            name + (" INTEGER" if name in integers else " TEXT") for name in columns) + ")")
        value = row()
        self.connection.execute("INSERT INTO approval_requests (" + ",".join(value) +
            ") VALUES (" + ",".join("?" for _ in value) + ")", tuple(value.values()))

        @contextmanager
        def local_connection():
            yield self.connection

        patcher = patch.object(db, "connect", side_effect=local_connection)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_private_get_refuses_without_mutation_or_secret_decryption(self):
        before = self.connection.total_changes
        with patch.object(db, "decrypt_secret") as decrypt:
            with self.assertRaises(ValueError) as raised:
                db.get_approval_request("synthetic-approval")
            self.assertEqual(str(raised.exception), REFUSAL)
            decrypt.assert_not_called()
        self.assertEqual(self.connection.total_changes, before)

    def test_metadata_list_and_history_remain_readable_without_private_opening(self):
        before = self.connection.total_changes
        expected = {**{key: row()[key] for key in PUBLIC}, "approver_policy": POLICY}
        with patch.object(db, "_decrypt_approval_json", side_effect=AssertionError("metadata opened review")) as decrypt, \
                patch.object(db, "row_to_approval", side_effect=AssertionError("metadata used private reader")) as private:
            self.assertEqual(db.get_approval_request_metadata("synthetic-approval"), expected)
            self.assertEqual(db.list_approvals(status="pending"), [expected])
            history = db.list_similar_approvals({**expected, "id": "other"})
            self.assertEqual([item["id"] for item in history], ["synthetic-approval"])
            for public_value in (expected, history):
                self.assertNotIn("native-jit:", json.dumps(public_value))
                self.assertNotIn(CANARY, json.dumps(public_value))
            decrypt.assert_not_called()
            private.assert_not_called()
        self.assertEqual(self.connection.total_changes, before)

    def test_actual_review_route_cannot_construct_document_or_issue_receipt(self):
        source = ROOT / "catchplate/app.py"
        tree = ast.parse(source.read_text())
        selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "approval_review"]
        self.assertEqual(len(selected), 1)
        function = deepcopy(selected[0])
        function.decorator_list = []  # No server registration; function body is unchanged.
        document = Mock(side_effect=AssertionError("native reference reached document rendering"))
        reviewer = Mock()
        namespace = {"db": db, "Any": object, "AdminIdentity": object,
                     "Depends": lambda _dependency: None, "require_role": lambda *_roles: None,
                     "_approval_is_expired": lambda _approval: False,
                     "_assert_approval_reviewer_allowed": reviewer,
                     "_approval_review_document": document, "hashlib": hashlib,
                     "_canonical_json": json.dumps}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
        identity = SimpleNamespace(user_id="oidc:synthetic-reviewer", has_any_role=lambda _roles: True)
        before = self.connection.total_changes
        with patch.object(db, "issue_approval_review_receipt", side_effect=AssertionError("unexpected receipt write")) as receipt:
            with self.assertRaises(ValueError) as raised:
                namespace["approval_review"]("synthetic-approval", identity)
            self.assertEqual(str(raised.exception), REFUSAL)
            reviewer.assert_called_once()
            document.assert_not_called()
            receipt.assert_not_called()
        self.assertEqual(self.connection.total_changes, before)


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        _DATA.cleanup()
