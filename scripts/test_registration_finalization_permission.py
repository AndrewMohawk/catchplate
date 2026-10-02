#!/usr/bin/env python3
"""Completion-possession component controls, not an admitted owner or hardware run.

Synthetic P-256 keys sign real WebAuthn assertion bytes. No verifier success,
database connection, current-root observation or live EnrollmentOwner is
fabricated. The owner lifecycle/expiry checks are explicitly source-contract
controls because this suite has no genuinely admitted cold-owner fixture.
"""
from __future__ import annotations

import ast
import base64
import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from serverware import control_plane_registration_finalization_permission as permission
from serverware import webauthn


RP_ID, ORIGIN = "completion.unit.invalid", "https://completion.unit.invalid"
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(b"component challenge, not authority").digest()).rstrip(b"=").decode()
PIN = "sha256:" + "1" * 64
ERRORS = (permission.FinalizationPermissionError, webauthn.WebAuthnError)


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class AssertionFixture:
    def __init__(self, baseline=7):
        self.key = ec.derive_private_key(7, ec.SECP256R1())
        numbers = self.key.public_key().public_numbers()
        self.credential = dict(id="component-record", user_id="component-user",
            credential_id=b64(b"component credential"), sign_count=baseline,
            public_key_cose=b64(cbor2.dumps({1: 2, 3: -7, -1: 1,
                -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})),
            revoked_at=None, authenticator_class="unknown", attestation_trusted=False,
            last_used_at=None, updated_at="unchanged-component-original")
        self.policy = {"userVerification": "required"}

    def signed(self, *, challenge=CHALLENGE, count=8, origin=ORIGIN,
            rp_id=RP_ID, flags=5):
        client = wire(dict(type="webauthn.get", challenge=challenge,
            origin=origin, crossOrigin=False))
        authenticator = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + count.to_bytes(4, "big")
        signature = self.key.sign(authenticator + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return dict(type="public-key", id=self.credential["credential_id"],
            rawId=self.credential["credential_id"], response=dict(clientDataJSON=b64(client),
                authenticatorData=b64(authenticator), signature=b64(signature), userHandle=None))


def tree(module):
    return ast.parse(Path(module.__file__).read_text())


def function(module, name):
    return next(node for node in tree(module).body if isinstance(node, ast.FunctionDef) and node.name == name)


def normalized(expression):
    return ast.dump(ast.parse(expression, mode="eval").body, include_attributes=False)


def contains(node, expression):
    wanted = normalized(expression)
    return any(ast.dump(child, include_attributes=False) == wanted for child in ast.walk(node))


def calls(node, expression):
    wanted = normalized(expression)
    return [child for child in ast.walk(node) if isinstance(child, ast.Call)
        and ast.dump(child.func, include_attributes=False) == wanted]


class FinalizationPermissionControls(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(webauthn, "WEBAUTHN_RP_ID", RP_ID))
        self.enterContext(patch.object(webauthn, "WEBAUTHN_ORIGIN", ORIGIN))

    def verify(self, fixture, assertion=None, challenge=CHALLENGE):
        return permission._verify(fixture.credential, fixture.policy,
            fixture.signed() if assertion is None else assertion, challenge)

    def test_real_signature_is_possession_only_and_preserves_metadata_inputs(self):
        fixture = AssertionFixture()
        original = copy.deepcopy(fixture.credential)
        original_bytes = wire(original)
        # These tripwires forbid the old challenge claim/counter writer. No
        # live database or invented successful metadata vector is supplied.
        with patch.object(webauthn.db, "create_webauthn_challenge", side_effect=AssertionError("metadata write")), \
                patch.object(webauthn.db, "claim_webauthn_challenge", side_effect=AssertionError("metadata write")), \
                patch.object(webauthn.db, "compare_and_swap_webauthn_sign_count", side_effect=AssertionError("metadata write")):
            result = self.verify(fixture)
        self.assertEqual(result, dict(user_id="component-user",
            credential_id=original["credential_id"], credential_record_id="component-record",
            observed_sign_count=8, stored_sign_count=7,
            persisted_counter_advanced=False, session_activated=False))
        self.assertEqual(fixture.credential, original)
        self.assertEqual(wire(fixture.credential), original_bytes)

    def test_real_signed_foreign_challenge_and_conflicting_credential_are_denied(self):
        fixture = AssertionFixture()
        with self.assertRaises(permission.FinalizationPermissionError):
            self.verify(fixture, fixture.signed(challenge=b64(b"another grant challenge")))
        for name in ("id", "rawId"):
            assertion = fixture.signed()
            assertion[name] = b64(b"foreign credential")
            with self.subTest(selector=name), self.assertRaises(permission.FinalizationPermissionError):
                self.verify(fixture, assertion)

    def test_signature_origin_rp_user_presence_and_verification_remain_real(self):
        fixture = AssertionFixture()
        for changes in ({"origin": "https://foreign.invalid"}, {"rp_id": "foreign.invalid"},
                {"flags": 1}, {"flags": 4}):
            with self.subTest(changes=changes), self.assertRaises(ERRORS):
                self.verify(fixture, fixture.signed(**changes))
        altered = fixture.signed()
        altered["response"]["signature"] = b64(b"not an ES256 signature")
        with self.assertRaises(webauthn.WebAuthnError):
            self.verify(fixture, altered)

    def test_counter_requires_both_zero_or_strict_increase_without_persistence(self):
        for baseline, observed, accepted in ((0, 0, True), (0, 1, True), (7, 8, True),
                (7, 7, False), (7, 6, False), (7, 0, False)):
            fixture = AssertionFixture(baseline)
            with self.subTest(baseline=baseline, observed=observed):
                if accepted:
                    result = self.verify(fixture, fixture.signed(count=observed))
                    self.assertEqual(result["observed_sign_count"], observed)
                    self.assertFalse(result["persisted_counter_advanced"])
                else:
                    with self.assertRaises(ERRORS):
                        self.verify(fixture, fixture.signed(count=observed))
                self.assertEqual(fixture.credential["sign_count"], baseline)

    def test_current_hardware_policy_is_not_inferred_from_a_valid_signature(self):
        fixture = AssertionFixture()
        self.verify(fixture)
        trust = webauthn._allowed_authenticator(fixture.credential, fixture.policy)
        self.assertFalse(trust["currently_trusted"])
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn._allowed_authenticator(fixture.credential,
                {**fixture.policy, "requireHardwareAttestation": True})
        scope = function(permission, "_scope")
        self.assertEqual(len(calls(scope, "webauthn._allowed_authenticator")), 1)

    def test_invalid_owner_never_reaches_a_credential_read_or_a_signature(self):
        fixture = AssertionFixture()
        with patch.object(webauthn.db, "get_webauthn_credential", side_effect=AssertionError("unadmitted read")), \
                patch.object(webauthn, "_verify_assertion_signature", side_effect=AssertionError("unadmitted verification")):
            for owner in (None, object()):
                with self.subTest(owner=type(owner).__name__), self.assertRaises(permission.startup.EnrollmentStartupError):
                    permission.issue(owner, {}, fixture.policy)
                with self.subTest(owner=type(owner).__name__), self.assertRaises(permission.startup.EnrollmentStartupError):
                    permission.consume(owner, {}, fixture.policy, fixture.signed())

    def test_source_one_owner_nonce_burns_before_scope_and_signature_without_retry(self):
        issue, consume = function(permission, "issue"), function(permission, "consume")
        for method in (issue, consume):
            with self.subTest(method=method.name):
                locked = next(node for node in method.body if isinstance(node, ast.With))
                self.assertTrue(contains(locked.items[0].context_expr, "startup._LOCK"))
                pid = calls(method, "startup._require_pid")
                self.assertEqual(len(pid), 1)
                self.assertLess(pid[0].lineno, locked.lineno)
        self.assertTrue(contains(issue, "owner._finalization_permission is not None"))
        self.assertTrue(contains(consume, "type(challenge) is not _Challenge"))
        target = ast.dump(ast.parse("owner._finalization_permission = None").body[0].targets[0],
            include_attributes=False)
        burn = next(node for node in ast.walk(consume) if isinstance(node, ast.Assign)
            and any(ast.dump(item, include_attributes=False) == target for item in node.targets)
            and contains(node.value, "_SPENT"))
        self.assertLess(burn.lineno, min(node.lineno for node in calls(consume, "_scope")))
        self.assertLess(burn.lineno, calls(consume, "_verify")[0].lineno)
        self.assertFalse(any(isinstance(node, (ast.Try, ast.While, ast.For)) for node in ast.walk(consume)))
        self.assertEqual(len(calls(consume, "_scope")), 2)
        self.assertEqual(len(calls(consume, "_current")), 3)
        self.assertIn("_finalization_permission", permission.startup._EnrollmentOwner.__slots__)
        close = function(permission.startup, "close")
        self.assertTrue(any(isinstance(node, ast.Assign)
            and any(ast.dump(item, include_attributes=False) == target for item in node.targets)
            and isinstance(node.value, ast.Constant) and node.value.value is None for node in ast.walk(close)))

    def test_source_foreign_grant_row_policy_and_original_expiry_cannot_be_rebased(self):
        scope, current, issue = (function(permission, name) for name in ("_scope", "_current", "issue"))
        self.assertEqual(len(calls(scope, "subjects._open_on_work")), 1)
        self.assertEqual(len(calls(scope, "subjects._inspect_material_on_owner")), 1)
        self.assertTrue(contains(scope, "selected_owner is not owner"))
        self.assertTrue(contains(scope, "_original(actual) != _original(binding)"))
        self.assertTrue(contains(scope, 'row.get("credential_id") != actual["credentialId"]'))
        self.assertTrue(contains(scope, 'row.get("user_id") != actual["userId"]'))
        for expression in ("owner._binding is not challenge.custody_binding",
                "owner._material is not challenge.material", "before < challenge.opened_ns",
                "after < before", "after >= challenge.deadline_ns", "epoch >= challenge.expires_epoch_ns"):
            with self.subTest(expression=expression):
                self.assertTrue(contains(current, expression))
        self.assertTrue(contains(issue, "min(MAX_LIFETIME_NS, owner._binding.maximum_deadline_ns, owner._binding.attestation_interval[1] - epoch)"))
        self.assertTrue(contains(issue, "min(before + lifetime, retained.deadline_ns, retained.window[4])"))
        self.assertTrue(contains(issue, "min(epoch + lifetime, retained.window[3], retained.window[0] + deadline - retained.window[2])"))
        self.assertEqual(len(calls(current, "challenge.retained.current")), 1)
        held = permission._Challenge(CHALLENGE, (b"grant", b"row", b"policy", b"trust"),
            object(), object(), 10, 20, 30, object())
        with self.assertRaises(FrozenInstanceError):
            held.deadline_ns = 999
        grant = dict(localDigest=PIN, userId="component-user", challengeId="component-registration",
            sessionId=None, mode="development-bootstrap", requestDigest=PIN, operationId=PIN,
            credentialId=AssertionFixture().credential["credential_id"])
        first = permission._original(permission.contract.request_binding(grant, recovery=False))
        other = {**grant, "localDigest": "sha256:" + "2" * 64}
        self.assertNotEqual(first, permission._original(permission.contract.request_binding(other, recovery=False)))

    def test_source_reads_only_target_row_and_preserves_complete_pending_vector(self):
        # The actual root vector includes credential, challenge and approval
        # tables. Prove this module has no DB call other than target SELECT;
        # do not claim an unperformed live root-vector measurement.
        body = tree(permission)
        database_calls = [ast.unparse(node.func) for node in ast.walk(body)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "db"]
        self.assertEqual(database_calls, ["webauthn.db.get_webauthn_credential"])
        from serverware import authority_current_root_vector as vector
        self.assertTrue({"webauthn_credentials", "webauthn_challenges", "control_plane_approvals"}
            <= set(vector.PRIMARY_TABLES))
        consume = function(permission, "consume")
        self.assertTrue(contains(consume, "_scope(owner, binding, authn_policy)[0] != challenge.scope"))
        raw = permission._original({"row": {"count": 7}, "policy": ["required"]})
        self.assertEqual(raw, b'{"policy":["required"],"row":{"count":7}}')
        with self.assertRaises(permission.FinalizationPermissionError):
            permission._original({"oversized": "x" * 65537})

    def test_required_two_person_policy_refuses_before_pending_metadata_writes(self):
        from fastapi import HTTPException
        from serverware import control_plane_registration_finalization_completion_routes as routes
        binding = {"action": permission.contract.COMPLETE_ACTION}
        observed = []

        def required(action):
            observed.append(action)
            return True

        # This is the pure source-policy refusal predicate, not authenticated
        # route dispatch or a successful application/approval fixture.
        with self.assertRaises(HTTPException) as denied:
            routes._approval_policy(SimpleNamespace(_control_plane_two_person_required=required), binding)
        self.assertEqual(denied.exception.status_code, 503)
        self.assertEqual(observed, [binding["action"]])
        self.assertIsNone(routes._approval_policy(SimpleNamespace(
            _control_plane_two_person_required=lambda action: False), binding))
        for name, downstream in (("_operator", "possession.issue"), ("_permission", "possession.consume")):
            body = function(routes, name)
            guards = calls(body, "_approval_policy")
            self.assertTrue(guards)
            self.assertLess(min(node.lineno for node in guards), calls(body, downstream)[0].lineno)
        from serverware import control_plane_registration_finalization_completion_pending as pending
        body = function(pending, "_handle")
        guard = min(node.lineno for node in calls(body, "routes._approval_policy"))
        self.assertLess(guard, calls(body, "_options")[0].lineno)
        self.assertLess(guard, calls(body, "_assertion")[0].lineno)


if __name__ == "__main__":
    unittest.main()
