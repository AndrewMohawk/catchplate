#!/usr/bin/env python3
"""Source-selected model/route units, not ASGI or measured-authority acceptance.

The actual denial models, route functions, policy argument producer and WebAuthn
options producer run with explicit DB, authority and role-dependency doubles.
No application import/startup, PostgreSQL, authenticator, private review opening
or one-use authority capability is established by this suite.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
from typing import Any
import unittest
from unittest.mock import Mock


def no_external_effects(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen", "os.system"} or event.startswith("sqlite3."):
        raise AssertionError("denial API units forbid external effects")


sys.addaudithook(no_external_effects)
from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

ROOT = Path(__file__).resolve().parents[1]
APP_TREE = ast.parse((ROOT / "serverware/app.py").read_text())
WEBAUTHN_TREE = ast.parse((ROOT / "serverware/webauthn.py").read_text())
ID = "11111111-2222-4333-8444-555555555555"
REVIEW = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
ACTOR = "oidc:synthetic-reviewer"
POLICY = "sha256:" + "a" * 64
DIGEST = "sha256:" + "b" * 64
CANARY = "private-authority-error-canary"
ASSERTION = {"id": "synthetic-authenticator", "response": {"clientDataJSON": "opaque-original"}}
ARGUMENTS = {
    "item_id": ID, "note": "Not approved", "actor_id": ACTOR,
    "review_receipt_id": REVIEW, "review_digest": DIGEST, "require_review_receipt": True,
    "required_approver_roles": {"approver", "finance"}, "authority_policy_hash": POLICY,
    "authority_route_id": "route.synthetic", "allowed_approver_ids": {ACTOR},
    "require_approver_webauthn": True, "approval_threshold": 2,
    "approver_credential_policy": {"userVerification": "required", "authenticatorClasses": ["hardware"]},
}


def select(tree, names, namespace, filename):
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    if len(nodes) != len(names) or {node.name for node in nodes} != set(names):
        raise AssertionError("production source-selection roster changed")
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *nodes], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), filename, "exec"), namespace)


class MetadataError(RuntimeError):
    pass


class RbacError(RuntimeError):
    pass


class WebAuthnError(RuntimeError):
    pass


class Fixture:
    """These successful authority/DB seams are doubles, never admission."""
    def __init__(self):
        self.approval = {
            "id": ID, "status": "pending", "expires_at": "2999-01-01T00:00:00+00:00",
            "policy_hash": POLICY, "route_id": "route.synthetic",
            "approver_policy": {"allowAnyApproverId": False, "allowedApproverIds": [ACTOR],
                "requiredRoles": ["approver", "finance"], "requireWebAuthn": True, "threshold": 2,
                "credentialPolicy": deepcopy(ARGUMENTS["approver_credential_policy"])},
        }
        self.receipt = {"id": REVIEW, "review_digest": DIGEST}
        self.jit = {"approvers": {"users": [ACTOR], "authn": {"userVerification": "required"}}}
        self.identity = SimpleNamespace(user_id=ACTOR)
        self.updated = {"id": ID, "status": "denied", "private": CANARY}
        self.db = SimpleNamespace(
            MetadataStoreError=MetadataError, RBACBindingStoreError=RbacError,
            get_approval_request=Mock(return_value=self.approval),
            get_active_approval_review_receipt=Mock(return_value=self.receipt),
            deny_request=Mock(return_value=self.updated),
            approval_public_summary=Mock(return_value={"id": ID, "status": "denied"}),
            issue_policy_authority_webauthn_challenge=Mock(return_value={"id": "authority-challenge", "challenge": "opaque-challenge"}),
        )
        self.routes = {}
        self.roles = []
        self.descriptors = Mock(return_value=[{"type": "public-key", "id": "synthetic-authenticator"}])
        self.policy = Mock(return_value=self.jit)
        module = ModuleType("_jit_denial_api_selected")
        sys.modules[module.__name__] = module
        self.ns = module.__dict__
        self.ns.update({"Any": Any, "BaseModel": BaseModel, "ConfigDict": ConfigDict,
            "Field": Field, "field_validator": field_validator, "HTTPException": HTTPException,
            "Depends": Depends, "datetime": datetime, "timezone": timezone,
            "db": self.db, "WebAuthnError": WebAuthnError, "WEBAUTHN_RP_ID": "console.example.test",
            "_credential_descriptors_for_policy": self.descriptors,
            "_approval_jit_policy": self.policy, "require_role": self.require_role,
            "app": SimpleNamespace(post=self.post)})
        select(WEBAUTHN_TREE, {"_authority_jit_decision_options", "authority_approval_options", "authority_denial_options"}, self.ns, "serverware/webauthn.py")
        select(APP_TREE, {"_approval_decision_note", "ApprovalApprove", "ApprovalWebAuthnOptionsRequest",
            "ApprovalDenyOptionsRequest", "ApprovalDeny", "_approval_authn_policy", "_approval_is_expired",
            "_jit_decision_authority_arguments", "_jit_approve_authority_arguments", "_jit_deny_authority_arguments",
            "_assert_approver_allowed", "_denial_review_context", "deny", "denial_webauthn_options"}, self.ns, "serverware/app.py")

    def require_role(self, *roles):
        self.roles.append(roles)
        return lambda: self.identity

    def post(self, path):
        def decorate(function):
            self.routes[path] = function
            return function
        return decorate

    def payload(self, **updates):
        return self.ns["ApprovalDeny"].model_validate({"reason": "Not approved", "reviewReceiptId": REVIEW,
            "assertion": deepcopy(ASSERTION), "authorityChallengeId": "authority-challenge", **updates})

    def options(self, **updates):
        return self.ns["ApprovalDenyOptionsRequest"].model_validate({"reason": "Not approved", "reviewReceiptId": REVIEW, **updates})

    def deny(self, **updates):
        return self.ns["deny"](ID, self.payload(**updates), self.identity)

    def challenge(self, **updates):
        return self.ns["denial_webauthn_options"](ID, self.options(**updates), self.identity)


class DenialApiTests(unittest.TestCase):
    def assert_http(self, status, callback):
        with self.assertRaises(HTTPException) as caught:
            callback()
        self.assertEqual(caught.exception.status_code, status)
        self.assertNotIn(CANARY, str(caught.exception.detail))
        return caught.exception

    def test_note_utf8_contract_shared_without_normalization(self):
        fixture = Fixture()
        for name, field in (("ApprovalApprove", "note"), ("ApprovalWebAuthnOptionsRequest", "note"),
                            ("ApprovalDenyOptionsRequest", "reason"), ("ApprovalDeny", "reason")):
            model = fixture.ns[name]
            base = {"reviewReceiptId": REVIEW}
            if name == "ApprovalDeny":
                base.update(assertion=deepcopy(ASSERTION), authorityChallengeId="authority-challenge")
            for value in (None, "", "a" * 500, "é" * 250, "😀" * 125, "in ternal"):
                with self.subTest(model=name, accepted_bytes=None if value is None else len(value.encode())):
                    parsed = model.model_validate({**base, field: value})
                    self.assertEqual(getattr(parsed, field), value)
            for value in ("a" * 501, "é" * 251, "😀" * 126, " leading", "trailing ", "a\nb", "a\tb", "a\x00b", "a\x7fb", "\ud800", 3, True, b"bytes"):
                with self.subTest(model=name, refused_type=type(value).__name__):
                    with self.assertRaises(ValidationError):
                        model.model_validate({**base, field: value})

    def test_denial_models_closed_and_proof_fields_required(self):
        fixture = Fixture()
        values = fixture.payload().model_dump(by_alias=True)
        self.assertEqual(set(values), {"reason", "reviewReceiptId", "assertion", "authorityChallengeId"})
        for field in ("reviewReceiptId", "assertion", "authorityChallengeId"):
            missing = dict(values)
            del missing[field]
            with self.subTest(missing=field), self.assertRaises(ValidationError):
                fixture.ns["ApprovalDeny"].model_validate(missing)
        for updates in ({"ttlSeconds": 10}, {"reviewReceiptId": "not-a-uuid"},
                        {"assertion": []}, {"authorityChallengeId": ""}, {"authorityChallengeId": "a" * 513}):
            with self.subTest(updates=tuple(updates)), self.assertRaises(ValidationError):
                fixture.payload(**updates)
        for field in ("ttlSeconds", "assertion", "authorityChallengeId", "operation"):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                fixture.options(**{field: "unexpected"})

    def test_routes_keep_approver_dependency_and_fixed_operation(self):
        fixture = Fixture()
        self.assertEqual(set(fixture.routes), {"/api/approvals/{approval_id}/deny", "/api/approvals/{approval_id}/deny/webauthn/options"})
        self.assertEqual(fixture.roles, [("approver",), ("approver",)])
        result = fixture.challenge()
        self.assertEqual(result, {"publicKey": {"challenge": "opaque-challenge", "rpId": "console.example.test",
            "allowCredentials": [{"type": "public-key", "id": "synthetic-authenticator"}], "timeout": 120000,
            "userVerification": "required"}, "serverware": {"authorityChallengeId": "authority-challenge", "operation": "jit.deny"}})
        fixture.db.issue_policy_authority_webauthn_challenge.assert_called_once_with(
            operation="jit.deny", input_value=ARGUMENTS, user_id=ACTOR, credential_id="synthetic-authenticator")
        fixture.db.deny_request.assert_not_called()

    def test_deny_forwards_originals_and_only_returns_public_summary(self):
        fixture = Fixture()
        result = fixture.deny()
        self.assertEqual(result, {"id": ID, "status": "denied"})
        fixture.db.deny_request.assert_called_once_with(**ARGUMENTS,
            authn={"assertion": ASSERTION, "credential_id": ASSERTION["id"]}, challenge_id="authority-challenge")
        fixture.db.approval_public_summary.assert_called_once_with(fixture.updated)
        fixture.db.get_active_approval_review_receipt.assert_called_once_with(REVIEW, approval_request_id=ID, reviewer_id=ACTOR)
        fixture.policy.assert_called_once_with(fixture.approval, require_current_policy=True)
        fixture.db.issue_policy_authority_webauthn_challenge.assert_not_called()

    def test_options_and_execute_bind_same_original_reason_review_policy(self):
        fixture = Fixture()
        note = "é" * 250
        fixture.challenge(reason=note)
        fixture.deny(reason=note)
        expected = fixture.db.issue_policy_authority_webauthn_challenge.call_args.kwargs["input_value"]
        actual = dict(fixture.db.deny_request.call_args.kwargs)
        self.assertEqual(actual.pop("authn"), {"assertion": ASSERTION, "credential_id": ASSERTION["id"]})
        self.assertEqual(actual.pop("challenge_id"), "authority-challenge")
        self.assertEqual(actual, expected)
        self.assertNotIn("ttl_seconds", actual)
        self.assertEqual(actual["note"], note)

    def test_context_refuses_missing_terminal_expired_stale_or_wrong_actor(self):
        changes = [
            (404, lambda f: setattr(f.db.get_approval_request, "return_value", None)),
            (409, lambda f: f.approval.update(status="denied")),
            (409, lambda f: f.approval.update(expires_at="2000-01-01T00:00:00+00:00")),
            (409, lambda f: setattr(f.policy, "side_effect", HTTPException(409, "policy changed"))),
            (403, lambda f: f.jit["approvers"].update(users=["oidc:other-reviewer"])),
            (412, lambda f: setattr(f.db.get_active_approval_review_receipt, "return_value", None)),
        ]
        for status, change in changes:
            for action in ("challenge", "deny"):
                with self.subTest(status=status, action=action):
                    fixture = Fixture()
                    change(fixture)
                    self.assert_http(status, getattr(fixture, action))
                    fixture.db.deny_request.assert_not_called()
                    fixture.db.issue_policy_authority_webauthn_challenge.assert_not_called()

    def test_receipt_and_authority_errors_are_fixed_and_not_retried(self):
        for method in ("get_approval_request", "get_active_approval_review_receipt"):
            for action in ("challenge", "deny"):
                fixture = Fixture()
                getattr(fixture.db, method).side_effect = MetadataError(CANARY)
                self.assert_http(503, getattr(fixture, action))
                self.assertEqual(getattr(fixture.db, method).call_count, 1)
                fixture.db.deny_request.assert_not_called()
        for error in (MetadataError, RbacError):
            fixture = Fixture()
            fixture.db.deny_request.side_effect = error(CANARY)
            self.assert_http(409, fixture.deny)
            fixture.db.deny_request.assert_called_once()
            fixture.db.approval_public_summary.assert_not_called()
            fixture.db.issue_policy_authority_webauthn_challenge.assert_not_called()
        fixture = Fixture()
        fixture.db.deny_request.return_value = None
        self.assert_http(409, fixture.deny)
        fixture.db.deny_request.assert_called_once()

    def test_assertion_identity_is_not_flattened_or_replaced(self):
        for assertion in ({}, {"id": ""}, {"id": 7}, {"rawId": None}):
            fixture = Fixture()
            self.assert_http(400, lambda: fixture.deny(assertion=assertion))
            fixture.db.deny_request.assert_not_called()
        fixture = Fixture()
        original = {"rawId": "original-raw-id", "response": {"opaque": "unchanged"}}
        fixture.deny(assertion=original)
        self.assertEqual(fixture.db.deny_request.call_args.kwargs["authn"], {"assertion": original, "credential_id": "original-raw-id"})

    def test_missing_stored_policy_never_issues_challenge_or_decision(self):
        for policy in (None, {}, {"credentialPolicy": {}, "threshold": "2"}):
            for action in ("challenge", "deny"):
                fixture = Fixture()
                fixture.approval["approver_policy"] = policy
                self.assert_http(409, getattr(fixture, action))
                fixture.db.issue_policy_authority_webauthn_challenge.assert_not_called()
                fixture.db.deny_request.assert_not_called()

    def test_approval_options_output_and_arguments_remain_decide_only(self):
        fixture = Fixture()
        arguments = fixture.ns["_jit_approve_authority_arguments"](approval=fixture.approval,
            actor_id=ACTOR, ttl_seconds=17, review_receipt=fixture.receipt, note="Not approved")
        self.assertEqual(arguments, {**ARGUMENTS, "ttl_seconds": 17})
        result = fixture.ns["authority_approval_options"](user_id=ACTOR, authn_policy={"userVerification": "required"}, target_arguments=arguments)
        self.assertEqual(result["serverware"], {"authorityChallengeId": "authority-challenge", "operation": "jit.decide"})
        fixture.db.issue_policy_authority_webauthn_challenge.assert_called_once_with(
            operation="jit.decide", input_value=arguments, user_id=ACTOR, credential_id="synthetic-authenticator")
        fixture.approval["approver_policy"]["allowAnyApproverId"] = True
        self.assertIsNone(fixture.ns["_jit_deny_authority_arguments"](approval=fixture.approval,
            actor_id=ACTOR, review_receipt=fixture.receipt, note=None)["allowed_approver_ids"])

    def test_options_producer_closed_and_refuses_no_eligible_credential(self):
        for descriptors in ([], [{"id": ""}], [{"id": 3}]):
            fixture = Fixture()
            fixture.descriptors.return_value = descriptors
            self.assert_http(403, fixture.challenge)
            fixture.db.issue_policy_authority_webauthn_challenge.assert_not_called()
        for error in (MetadataError, RbacError):
            fixture = Fixture()
            fixture.db.issue_policy_authority_webauthn_challenge.side_effect = error(CANARY)
            self.assert_http(503, fixture.challenge)
            fixture.db.issue_policy_authority_webauthn_challenge.assert_called_once()
        fixture = Fixture()
        with self.assertRaises(WebAuthnError):
            fixture.ns["_authority_jit_decision_options"](operation="jit.consume", user_id=ACTOR,
                authn_policy={}, target_arguments=ARGUMENTS)
        fixture.descriptors.assert_not_called()
        fixture.db.issue_policy_authority_webauthn_challenge.assert_not_called()

    def test_facade_roster_and_legacy_authority_guards_remain_closed(self):
        tree = ast.parse((ROOT / "serverware/db.py").read_text())
        matches = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "deny_request"]
        self.assertEqual(len(matches), 1)
        function = matches[0]
        self.assertEqual({arg.arg for arg in function.args.args + function.args.kwonlyargs},
            set(ARGUMENTS) | {"authn", "challenge_id"})
        self.assertEqual([statement.value.func.id for statement in function.body[:2]],
            ["_require_postgres_jit_authority", "_require_external_measured_authority_writer_dispatch"])
        defaults = dict(zip((arg.arg for arg in function.args.kwonlyargs), function.args.kw_defaults))
        self.assertIsNone(ast.literal_eval(defaults["review_receipt_id"]))
        self.assertIsNone(ast.literal_eval(defaults["review_digest"]))
        self.assertIs(ast.literal_eval(defaults["require_review_receipt"]), False)


if __name__ == "__main__":
    unittest.main()
