#!/usr/bin/env python3
"""Offline publication boundary using the actual runtime function.

Approval records and HTTP acknowledgements are synthetic. These tests exercise
no approval writer, threshold calculation, gate server, or native authority.
Publication admission, request construction, and acknowledgement validation are
the real functions with transport and metrics replaced. Two source-selected
route-body tests use synthetic authority/authentication dependencies; they are
not HTTP authentication or threshold-writer acceptance.
"""
from __future__ import annotations

import ast
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TOKEN = "synthetic-grant-publication-service-token"
_external_effects = []


def no_external_io(event, _arguments):
    if event.startswith("sqlite3.") or event in {
            "socket.connect", "socket.bind", "socket.getaddrinfo",
            "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        _external_effects.append(event)
        raise AssertionError("publication component attempted external I/O")


def actual_approve_body(namespace):
    """Compile the unchanged route body, not its FastAPI dependency wiring."""
    source = ROOT / "serverware/app.py"
    nodes = [node for node in ast.parse(source.read_text()).body
             if isinstance(node, ast.FunctionDef) and node.name == "approve"]
    if len(nodes) != 1:
        raise AssertionError("expected one actual approval route")
    node = nodes[0]
    if [argument.arg for argument in node.args.args] != [
            "approval_id", "ttl_seconds", "payload", "identity"]:
        raise AssertionError("approval route argument contract changed")
    node.decorator_list = []
    node.args.defaults = []
    for argument in node.args.args:
        argument.annotation = None
    node.returns = None
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), namespace)
    return namespace["approve"]


def approval():
    return {
        "id": "synthetic-approval",
        "status": "approved",
        "principal_id": "agent:synthetic",
        "route_id": "route:synthetic",
        "credential_id": "credential:synthetic",
        "credential_version": 7,
        "policy_hash": "sha256:" + "1" * 64,
        "request_digest": "sha256:" + "2" * 64,
        "operation_digest": "sha256:" + "3" * 64,
        "grant_max_uses": 2,
        "grant_ttl_seconds": 17,
    }


def acknowledgement():
    return {
        "ok": True,
        "grant_id": "approval:synthetic-approval",
        "approval_id": "synthetic-approval",
        "policy_hash": "sha256:" + "1" * 64,
    }


class RuntimeGrantPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.addaudithook(no_external_io)
        cls.stack = ExitStack()
        cls.addClassCleanup(cls.stack.close)
        directory = cls.stack.enter_context(tempfile.TemporaryDirectory(
            prefix="runtime-grant-publication-"))
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("SERVERWARE_")}
        environment.update(SERVERWARE_PROCESS_MODE="serverware-control-plane",
            SERVERWARE_RELEASE_CHANNEL="dev", SERVERWARE_DATA_DIR=directory)
        cls.stack.enter_context(patch.dict(os.environ, environment, clear=True))
        from serverware import runtime
        cls.runtime = runtime

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(self.runtime, "DECISION_GATE_BASE",
            "https://synthetic-gate.invalid"))
        self.stack.enter_context(patch.object(self.runtime, "DATA_PLANE_AUDIT_TOKEN", TOKEN))
        self.stack.enter_context(patch.object(self.runtime, "DECISION_GATE_TIMEOUT_SECONDS", 2.5))
        self.transport = self.stack.enter_context(patch.object(self.runtime,
            "request_bytes", return_value=SimpleNamespace(
                body=json.dumps(acknowledgement()).encode("ascii"))))
        self.metric = self.stack.enter_context(patch.object(self.runtime, "_inc"))
        # Guards remain independently observable even if a future caller catches
        # their AssertionError. None of these effects belongs to publication.
        self.forbidden = []
        for owner, name in ((self.runtime.db, "connect"),
                (self.runtime.db, "record_audit_event"),
                (self.runtime, "start_runtime_workers")):
            self.forbidden.append(self.stack.enter_context(patch.object(owner,
                name, side_effect=AssertionError("unexpected publication effect"))))
        self.addCleanup(self.assert_no_forbidden_effects)

    def assert_no_forbidden_effects(self):
        for effect in self.forbidden:
            effect.assert_not_called()
        self.assertEqual(_external_effects, [])

    def route_case(self, updated):
        from fastapi import HTTPException
        retained = {**approval(), "status": "pending"}
        receipt = {"id": "synthetic-review-receipt"}
        writer_arguments = {"item_id": retained["id"], "actor_id": "synthetic-reviewer"}
        store = SimpleNamespace(
            get_approval_request_metadata=Mock(return_value=retained),
            get_active_approval_review_receipt=Mock(return_value=receipt),
            approve_request=Mock(return_value=updated),
            record_audit_event=Mock(),
            approval_public_summary=Mock(wraps=self.runtime.db.approval_public_summary),
            MetadataStoreError=self.runtime.db.MetadataStoreError,
            RBACBindingStoreError=self.runtime.db.RBACBindingStoreError)
        publisher = Mock(wraps=self.runtime.publish_decision_gate_grant)
        namespace = {"db": store, "runtime": SimpleNamespace(publish_decision_gate_grant=publisher),
            "HTTPException": HTTPException, "_approval_is_expired": Mock(return_value=False),
            "_approval_jit_policy": Mock(return_value={"required": True}),
            "_assert_approver_allowed": Mock(),
            "_jit_approve_authority_arguments": Mock(return_value=writer_arguments)}
        function = actual_approve_body(namespace)
        payload = SimpleNamespace(review_receipt_id=receipt["id"],
            assertion={"id": "synthetic-assertion-credential"},
            authority_challenge_id="synthetic-authority-challenge", note=None)
        before = copy.deepcopy(updated)
        result = function(retained["id"], 30, payload,
            SimpleNamespace(user_id="synthetic-reviewer"))
        self.assertEqual(updated, before)
        store.get_approval_request_metadata.assert_called_once_with(retained["id"])
        store.get_active_approval_review_receipt.assert_called_once_with(receipt["id"],
            approval_request_id=retained["id"], reviewer_id="synthetic-reviewer")
        store.approve_request.assert_called_once_with(**writer_arguments,
            authn={"assertion": payload.assertion, "credential_id": payload.assertion["id"]},
            challenge_id=payload.authority_challenge_id)
        store.approval_public_summary.assert_called_once_with(updated)
        return result, store, publisher

    def test_nonapproved_and_missing_status_never_construct_or_send_grants(self):
        statuses = ("pending", "denied", "expired", "revoked", "cancelled",
                    "APPROVED", "approved ", "", None, True, 1, [], {})
        with patch.object(self.runtime.urllib.request, "Request",
                side_effect=AssertionError("nonapproved grant was constructed")) as request:
            for status in statuses:
                with self.subTest(status_type=type(status).__name__):
                    value = {**approval(), "status": status}
                    before = copy.deepcopy(value)
                    result = self.runtime.publish_decision_gate_grant(value)
                    self.assertEqual(result, {"enabled": True, "ok": False,
                        "error": "approval is not approved"})
                    self.assertEqual(value, before)
            value = approval()
            value.pop("status")
            self.assertEqual(self.runtime.publish_decision_gate_grant(value),
                {"enabled": True, "ok": False, "error": "approval is not approved"})
            request.assert_not_called()
        self.transport.assert_not_called()
        self.metric.assert_not_called()

    def test_pending_vote_refuses_before_grant_fields_or_integer_conversion(self):
        for value in ({"status": "pending"},
                {**approval(), "status": "pending", "credential_version": "not-an-integer",
                 "grant_max_uses": {}, "grant_ttl_seconds": []}):
            self.assertEqual(self.runtime.publish_decision_gate_grant(value),
                {"enabled": True, "ok": False, "error": "approval is not approved"})
        self.transport.assert_not_called()
        self.metric.assert_not_called()

    def test_only_approved_transition_sends_exact_unchanged_grant_once(self):
        value = {**approval(), "status": "pending"}
        self.assertFalse(self.runtime.publish_decision_gate_grant(value)["ok"])
        self.transport.assert_not_called()
        # This models only the returned state transition; it is not a vote or
        # a simulated threshold-authority acceptance.
        value["status"] = "approved"
        before = copy.deepcopy(value)
        result = self.runtime.publish_decision_gate_grant(value)
        self.assertEqual(value, before)
        self.transport.assert_called_once()
        request = self.transport.call_args.args[0]
        self.assertEqual(request.full_url, "https://synthetic-gate.invalid/v1/grants")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(dict((name.lower(), value) for name, value in request.header_items()),
            {"content-type": "application/json", "x-serverware-data-plane-token": TOKEN})
        expected = {"grantId": "approval:synthetic-approval", "approvalId": "synthetic-approval",
            "principalId": "agent:synthetic", "routeId": "route:synthetic",
            "credentialRef": "credential:synthetic", "credentialVersion": 7,
            "policyHash": "sha256:" + "1" * 64, "requestDigest": "sha256:" + "2" * 64,
            "operationDigest": "sha256:" + "3" * 64, "maxUses": 2, "ttlSeconds": 17}
        self.assertEqual(request.data, json.dumps(expected, separators=(",", ":"),
            sort_keys=True).encode("utf-8"))
        self.assertEqual(self.transport.call_args.kwargs, {"timeout": 2.5, "max_bytes": 256 * 1024})
        self.assertEqual(result, {"enabled": True, "ok": True, "error": None,
            "response": acknowledgement(), "payload": expected})
        self.assertNotIn(TOKEN, json.dumps(result))
        self.metric.assert_called_once_with("decision_gate_grant_publish_success")

    def test_approved_acknowledgement_still_requires_all_three_bindings(self):
        for field in ("grant_id", "approval_id", "policy_hash"):
            with self.subTest(field=field):
                response = {**acknowledgement(), field: "different"}
                self.transport.return_value = SimpleNamespace(body=json.dumps(response).encode("ascii"))
                result = self.runtime.publish_decision_gate_grant(approval())
                self.assertIs(result["ok"], False)
                self.assertEqual(result["error"],
                    "decision gate grant acknowledgement binding mismatch: " + field)
        self.assertEqual(self.transport.call_count, 3)
        self.assertEqual(self.metric.call_count, 3)
        for call in self.metric.call_args_list:
            self.assertEqual(call.args, ("decision_gate_grant_publish_failure",))

    def test_disabled_gate_preserves_existing_result_without_publication(self):
        with patch.object(self.runtime, "DECISION_GATE_BASE", ""):
            for status in ("pending", "approved"):
                self.assertEqual(self.runtime.publish_decision_gate_grant(
                    {**approval(), "status": status}), {"enabled": False, "ok": False,
                        "error": "decision gate base is not configured"})
        self.transport.assert_not_called()
        self.metric.assert_not_called()

    def test_approved_missing_fields_still_refuses_before_transport(self):
        value = approval()
        value.pop("credential_id")
        self.assertEqual(self.runtime.publish_decision_gate_grant(value),
            {"enabled": True, "ok": False, "error": "approval is missing grant fields",
             "missing": ["credential_id"]})
        self.transport.assert_not_called()
        self.metric.assert_called_once_with("decision_gate_grant_publish_failure")

    def test_approved_transport_failure_never_claims_delivery_or_retries(self):
        self.transport.side_effect = TimeoutError("synthetic timeout")
        result = self.runtime.publish_decision_gate_grant(approval())
        self.assertIs(result["enabled"], True)
        self.assertIs(result["ok"], False)
        self.assertEqual(result["error"], "synthetic timeout")
        self.assertNotIn("response", result)
        self.transport.assert_called_once()
        self.metric.assert_called_once_with("decision_gate_grant_publish_failure")

    def test_actual_route_pending_vote_neither_publishes_nor_audits_delivery(self):
        value = {**approval(), "status": "pending",
            "canonical_request": {"private": "synthetic-private-review-canary"}}
        result, store, publisher = self.route_case(value)
        publisher.assert_not_called()
        store.record_audit_event.assert_not_called()
        self.transport.assert_not_called()
        self.metric.assert_not_called()
        self.assertEqual(result, {**self.runtime.db.approval_public_summary(value),
            "data_plane_grant_publish": {"enabled": False, "ok": False, "error": None}})
        self.assertNotIn("synthetic-private-review-canary", json.dumps(result))

    def test_actual_route_approved_publishes_once_and_projects_safe_delivery(self):
        value = {**approval(), "canonical_request": {"private": "synthetic-private-review-canary"}}
        result, store, publisher = self.route_case(value)
        publisher.assert_called_once_with(value)
        self.transport.assert_called_once()
        self.assertEqual(result, {**self.runtime.db.approval_public_summary(value),
            "data_plane_grant_publish": {"enabled": True, "ok": True, "error": None}})
        store.record_audit_event.assert_called_once_with("data_plane.grant.publish",
            {"approval_request_id": value["id"], "route_id": value["route_id"],
             "principal_id": value["principal_id"], "credential_id": value["credential_id"],
             "credential_version": value["credential_version"], "policy_hash": value["policy_hash"],
             "request_digest": value["request_digest"], "operation_digest": value["operation_digest"],
             "ok": True, "error": None}, actor_id="synthetic-reviewer")
        documents = json.dumps({"public": result, "audit": store.record_audit_event.call_args.args})
        for private in ("synthetic-private-review-canary", TOKEN, '"payload"', '"response"'):
            self.assertNotIn(private, documents)


if __name__ == "__main__":
    unittest.main(verbosity=2)
