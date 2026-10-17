#!/usr/bin/env python3
"""Actual decision route functions through FastAPI/ASGI, not live authority.

The real native pending-row projection is stored in disposable SQLite and read
by the source-selected production metadata query. Identity, receipts, challenges
and dispatch are explicit doubles. No production database, PostgreSQL, network,
private opening or measured-authority admission is exercised.
"""
from __future__ import annotations

from copy import deepcopy
from contextlib import nullcontext
from datetime import datetime, timezone
import ast
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from typing import Any
from unittest.mock import Mock


def no_external_effects(event, arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen",
            "os.system", "os.exec", "os.posix_spawn"}:
        raise AssertionError("decision fence controls forbid external effects")
    if event == "sqlite3.connect" and arguments[0] != ":memory:":
        raise AssertionError("decision fence controls only permit disposable in-memory SQLite")


sys.addaudithook(no_external_effects)
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, HTTPException

import test_jit_denial_api as route_units
from catchplate import authority_transition_core as core
from catchplate import authority_transition_native_jit_pending as pending
from catchplate import authority_transition_quota as quota
from catchplate.db_common import loads

ID, REVIEW = route_units.ID, route_units.REVIEW
ERROR = "Native decisions require protected continuation authority"
NATIVE = ("native-jit:" + "a" * 64, "native-jit:malformed", "native-jit", "native-jit-other",
    "NATIVE-JIT:malformed", " \t\r\nNaTiVe-JiT:malformed", "\u2003native-jit:malformed")
PATHS = ("approve", "webauthn/options", "deny", "deny/webauthn/options")
DB_TREE = ast.parse((ROOT / "catchplate/db.py").read_text())


def native_row():
    """Actual storage projection and native references, with public synthetic inputs."""
    policy = {"schema": "catchplate.jitApproverPolicy/v1", "allowAnyApproverId": False,
        "allowedApproverIds": [route_units.ACTOR], "requiredRoles": ["approver", "finance"],
        "requireWebAuthn": True, "threshold": 2,
        "credentialPolicy": deepcopy(route_units.ARGUMENTS["approver_credential_policy"])}
    normalized = {"route_id": "route.synthetic", "method": "POST",
        "url_commitment": "sha256:" + "c" * 64, "principal_id": "agent:synthetic",
        "credential_id": "synthetic-credential", "credential_version": 7,
        "policy_hash": route_units.POLICY, "request_digest": route_units.DIGEST,
        "operation_digest": None, "pending_ttl_seconds": 300,
        "grant_ttl_seconds": 30, "grant_max_uses": 1, "approver_policy": policy,
        "approver_policy_digest": core.framed_digest(
            "catchplate.jitApproverPolicy/v1", core.canonical_bytes(policy))}
    now = datetime(2099, 1, 1, tzinfo=timezone.utc)
    values = [{"ciphertext_base64url": pending.reference(approval_id=ID,
        parent_digest=route_units.DIGEST, pair_digest="sha256:" + "d" * 64, value_kind=kind),
        "expires_at_epoch_ns": core._epoch_nanoseconds(now) + 300_000_000_000}
        for kind in pending.KINDS]
    return dict(quota.jit_pending_projection(normalized, approval_id=ID,
        canonical_value=values[0], display_value=values[1], database_now=now).row)


class MetadataStore:
    """Production query/projection functions against a fresh, single-row SQLite DB."""
    def __init__(self, row):
        self.connection = sqlite3.connect(":memory:", cached_statements=0, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        integers = {"credential_version", "grant_ttl_seconds", "grant_max_uses"}
        self.connection.execute("CREATE TABLE approval_requests (" + ",".join(
            name + (" INTEGER" if name in integers else " TEXT") +
            (" PRIMARY KEY" if name == "id" else "") for name in row) + ")")
        self.connection.execute("INSERT INTO approval_requests (" + ",".join(row) +
            ") VALUES (" + ",".join("?" for _ in row) + ")", tuple(row.values()))
        self.private = {"canonical_request", "redacted_display"}
        self.decrypt = Mock(side_effect=AssertionError("private decryption is forbidden"))
        self.private_projection = Mock(side_effect=AssertionError("private projection is forbidden"))
        self.ns = {"Any": Any, "Mapping": dict, "sqlite3": sqlite3, "loads": loads,
            "connect": lambda: nullcontext(self.connection), "_decrypt_approval_json": self.decrypt,
            "row_to_approval": self.private_projection}
        for name in ("_APPROVAL_PUBLIC_FIELDS", "_APPROVAL_REFERENCE_WHITESPACE"):
            matches = [node for node in DB_TREE.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
            if len(matches) != 1:
                raise AssertionError("metadata source constant roster changed")
            self.ns[name] = ast.literal_eval(matches[0].value)
        route_units.select(DB_TREE, {"approval_public_summary", "row_to_approval_public",
            "get_approval_request_metadata"}, self.ns, "catchplate/db.py")

    def close(self):
        self.connection.close()

    def metadata(self, identifier=ID, *, for_decision=False):
        columns, projected, denied = set(), [], []
        allowed = set(self.ns["_APPROVAL_PUBLIC_FIELDS"]) | {"approver_policy_json"}
        if for_decision:
            allowed |= self.private

        def authorize(action, table, column, _database, _trigger):
            if action == sqlite3.SQLITE_READ and table == "approval_requests" and column in allowed:
                columns.add(column)
            elif action == sqlite3.SQLITE_SELECT:
                pass
            elif action == sqlite3.SQLITE_FUNCTION and column in {"lower", "substr", "ltrim"}:
                pass
            else:
                denied.append((action, table, column))
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        def factory(cursor, values):
            result = sqlite3.Row(cursor, values)
            projected.append(set(result.keys()))
            return result

        before = self.connection.total_changes
        self.connection.row_factory = factory
        self.connection.set_authorizer(authorize)
        try:
            result = self.ns["get_approval_request_metadata"](identifier, for_decision=for_decision)
        finally:
            self.connection.set_authorizer(None)
            self.connection.row_factory = sqlite3.Row
        if denied or self.connection.total_changes != before:
            raise AssertionError("metadata read accessed forbidden columns or mutated SQLite")
        if any(self.private & fields for fields in projected):
            raise AssertionError("query returned raw private values")
        if not for_decision and self.private & columns:
            raise AssertionError("ordinary metadata inspected private columns")
        self.decrypt.assert_not_called()
        self.private_projection.assert_not_called()
        return result


def attach_store(fixture, store):
    fixture.approval = store.metadata(for_decision=True)
    fixture.db.get_approval_request_metadata.side_effect = store.metadata


class Fixture(route_units.Fixture):
    def __init__(self):
        self.http, self.auth_error, self.auth_calls = FastAPI(), None, 0
        super().__init__(metadata_routes=True)
        self.approval["url"] = "https://synthetic.invalid/resource"

    def require_role(self, *roles):
        self.roles.append(roles)

        def authenticate():
            self.auth_calls += 1
            if self.auth_error is not None:
                raise self.auth_error
            return self.identity

        return authenticate

    def post(self, path):
        def decorate(function):
            self.routes[path] = function
            # The selected production function keeps its actual Depends and
            # request models; only this identity annotation is a test double.
            function.__globals__["AdminIdentity"] = Any
            return self.http.post(path)(function)

        return decorate

    def downstream(self):
        return (self.policy, self.descriptors, self.publish,
            self.db.get_active_approval_review_receipt, self.db.get_approval_request,
            self.db.issue_approval_review_receipt, self.db.issue_policy_authority_webauthn_challenge,
            self.db.approve_request, self.db.deny_request, self.db.record_audit_event,
            self.db.approval_public_summary)


def payload(path):
    value = {"reviewReceiptId": REVIEW}
    if path.startswith("deny"):
        value["reason"] = "Not approved"
    else:
        value["note"] = "Not approved"
    if path == "webauthn/options":
        value["ttlSeconds"] = 17
    if not path.endswith("options"):
        value.update(assertion=deepcopy(route_units.ASSERTION), authorityChallengeId="authority-challenge")
    return value


async def request(fixture, path):
    body = json.dumps(payload(path), separators=(",", ":")).encode("ascii")
    target = "/api/approvals/" + ID + "/" + path
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1", "method": "POST", "scheme": "https", "path": target,
        "raw_path": target.encode("ascii"), "query_string": b"", "root_path": "",
        "headers": [(b"host", b"console.example.test"), (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii"))],
        "client": ("127.0.0.1", 12345), "server": ("console.example.test", 443)}
    messages, delivered = [], False

    async def receive():
        nonlocal delivered
        if delivered:
            raise AssertionError("unexpected second request body read")
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)

    await fixture.http(scope, receive, send)
    starts = [message for message in messages if message["type"] == "http.response.start"]
    if len(starts) != 1:
        raise AssertionError("response framing changed")
    raw = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    if len(raw) > 16384:
        raise AssertionError("response bound exceeded")
    return starts[0]["status"], json.loads(raw)


class NativeDecisionHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_four_routes_refuse_native_family_before_downstream_calls(self):
        for field in ("url", "canonical_request", "redacted_display"):
            for marker in NATIVE:
                row = native_row()
                row.update(canonical_request="v2:synthetic-ciphertext", redacted_display="v2:synthetic-ciphertext")
                row[field] = marker
                store = MetadataStore(row)
                try:
                    for path in PATHS:
                        with self.subTest(path=path, field=field, marker=marker):
                            fixture = Fixture()
                            attach_store(fixture, store)
                            before = deepcopy((fixture.approval, fixture.receipt))
                            self.assertEqual(await request(fixture, path), (409, {"detail": ERROR}))
                            self.assertEqual(fixture.auth_calls, 1)
                            fixture.db.get_approval_request_metadata.assert_called_once_with(ID, for_decision=True)
                            for callback in fixture.downstream():
                                callback.assert_not_called()
                            self.assertEqual((fixture.approval, fixture.receipt), before)
                finally:
                    store.close()

    async def test_genuine_pending_projection_sha_url_refuses_all_four_routes(self):
        row = native_row()
        self.assertEqual(row["url"], "sha256:" + "c" * 64)
        for field in ("canonical_request", "redacted_display"):
            self.assertTrue(row[field].startswith("native-jit:v1:"))
        store = MetadataStore(row)
        self.addCleanup(store.close)
        ordinary = store.metadata()
        self.assertNotIn("_legacy_decision_blocked", ordinary)
        self.assertNotIn("native-jit", json.dumps(ordinary))
        for path in PATHS:
            fixture = Fixture()
            attach_store(fixture, store)
            with self.subTest(path=path):
                self.assertIs(fixture.approval["_legacy_decision_blocked"], True)
                self.assertEqual(await request(fixture, path), (409, {"detail": ERROR}))
                for callback in fixture.downstream():
                    callback.assert_not_called()

    async def test_native_terminal_or_expired_rows_cannot_enter_replay_paths(self):
        for path in PATHS:
            for change in ({"status": "approved"}, {"status": "denied"},
                    {"expires_at": "2000-01-01T00:00:00+00:00"}):
                fixture = Fixture()
                fixture.approval.update(_legacy_decision_blocked=True, **change)
                with self.subTest(path=path, change=change):
                    self.assertEqual(await request(fixture, path), (409, {"detail": ERROR}))
                    for callback in fixture.downstream():
                        callback.assert_not_called()

    async def test_authentication_and_role_refusals_precede_metadata(self):
        for path in PATHS:
            for code in (401, 403):
                fixture = Fixture()
                fixture.auth_error = HTTPException(code, "authentication unavailable")
                with self.subTest(path=path, code=code):
                    self.assertEqual(await request(fixture, path), (code, {"detail": "authentication unavailable"}))
                    fixture.db.get_approval_request_metadata.assert_not_called()
                    for callback in fixture.downstream():
                        callback.assert_not_called()

    async def test_valid_legacy_routes_retain_their_original_dispatch(self):
        for path in PATHS:
            fixture = Fixture()
            with self.subTest(path=path):
                code, result = await request(fixture, path)
                self.assertEqual(code, 200)
                fixture.db.get_approval_request_metadata.assert_called_once_with(ID, for_decision=True)
                fixture.policy.assert_called_once_with(fixture.approval, require_current_policy=True)
                fixture.db.get_active_approval_review_receipt.assert_called_once_with(
                    REVIEW, approval_request_id=ID, reviewer_id=route_units.ACTOR)
                fixture.db.get_approval_request.assert_not_called()
                fixture.db.issue_approval_review_receipt.assert_not_called()
                if path.endswith("options"):
                    self.assertEqual(result["catchplate"]["operation"], "jit.deny" if path.startswith("deny") else "jit.decide")
                    fixture.db.issue_policy_authority_webauthn_challenge.assert_called_once()
                    fixture.db.approve_request.assert_not_called()
                    fixture.db.deny_request.assert_not_called()
                else:
                    (fixture.db.deny_request if path == "deny" else fixture.db.approve_request).assert_called_once()
                    (fixture.db.approve_request if path == "deny" else fixture.db.deny_request).assert_not_called()
                    fixture.db.issue_policy_authority_webauthn_challenge.assert_not_called()

    async def test_legacy_missing_terminal_receipt_and_policy_refusals_preserved(self):
        controls = ((404, lambda f: setattr(f.db.get_approval_request_metadata, "return_value", None)),
            (409, lambda f: f.approval.update(status="denied")),
            (412, lambda f: setattr(f.db.get_active_approval_review_receipt, "return_value", None)),
            (409, lambda f: setattr(f.policy, "side_effect", HTTPException(409, "policy changed"))),
            (403, lambda f: f.jit["approvers"].update(users=["oidc:other-reviewer"])))
        for path in PATHS:
            for code, change in controls:
                fixture = Fixture()
                change(fixture)
                with self.subTest(path=path, code=code):
                    status, _ = await request(fixture, path)
                    self.assertEqual(status, code)
                    fixture.db.approve_request.assert_not_called()
                    fixture.db.deny_request.assert_not_called()
                    fixture.db.issue_policy_authority_webauthn_challenge.assert_not_called()
                    fixture.db.get_approval_request.assert_not_called()
                    fixture.publish.assert_not_called()

    async def test_ordinary_url_containing_native_text_is_not_a_native_reference(self):
        row = native_row()
        row.update(url="https://synthetic.invalid/native-jit:ordinary-path",
            canonical_request="v2:synthetic-ciphertext", redacted_display="v2:synthetic-ciphertext")
        store = MetadataStore(row)
        self.addCleanup(store.close)
        for path in PATHS:
            fixture = Fixture()
            attach_store(fixture, store)
            with self.subTest(path=path):
                self.assertIs(fixture.approval["_legacy_decision_blocked"], False)
                status, _ = await request(fixture, path)
                self.assertEqual(status, 200)

    async def test_absent_or_non_boolean_fence_result_refuses_before_downstream(self):
        for path in PATHS:
            for value in (None, 0, 1, "false", [], {}):
                fixture = Fixture()
                fixture.approval["_legacy_decision_blocked"] = value
                with self.subTest(path=path, value=value):
                    self.assertEqual(await request(fixture, path), (409, {"detail": ERROR}))
                    for callback in fixture.downstream():
                        callback.assert_not_called()
            fixture = Fixture()
            del fixture.approval["_legacy_decision_blocked"]
            self.assertEqual(await request(fixture, path), (409, {"detail": ERROR}))


class MetadataProjectionTests(unittest.TestCase):
    def test_null_references_fail_closed_without_returning_private_values(self):
        for field in ("url", "canonical_request", "redacted_display"):
            row = native_row()
            row.update(canonical_request="v2:synthetic-ciphertext", redacted_display="v2:synthetic-ciphertext")
            row[field] = None
            store = MetadataStore(row)
            try:
                with self.subTest(field=field):
                    self.assertIs(store.metadata(for_decision=True)["_legacy_decision_blocked"], True)
                    self.assertNotIn("_legacy_decision_blocked", store.metadata())
            finally:
                store.close()

    def test_derived_sql_case_driver_types_fail_closed_and_whitespace_matches_python(self):
        store = MetadataStore(native_row())
        self.addCleanup(store.close)
        whitespace = store.ns["_APPROVAL_REFERENCE_WHITESPACE"]
        self.assertNotIn("\x00", whitespace)
        self.assertEqual(set(whitespace), {chr(value) for value in range(0x3100) if chr(value).isspace()})
        row = store.metadata()
        for value in (False, True, None, "0", "1", 0.0, [], {}, 1, 2, -1, 0):
            # This narrow driver-double control tests only the result-type guard;
            # the other controls execute the actual CASE through SQLite.
            connection = Mock()
            connection.execute.return_value.fetchone.return_value = {**row, "legacy_decision_blocked": value}
            store.ns["connect"] = lambda: nullcontext(connection)
            with self.subTest(value=value):
                result = store.ns["get_approval_request_metadata"](ID, for_decision=True)
                self.assertIs(result["_legacy_decision_blocked"], not (type(value) is int and value == 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
