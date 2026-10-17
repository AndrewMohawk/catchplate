#!/usr/bin/env python3
"""Pure domain/projection regressions, not connected receipt or grant acceptance."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
from types import MappingProxyType
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from catchplate import authority_approver_policy as policy_binding


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def domain_digest(domain, value):
    frame = canonical(value)
    return "sha256:" + hashlib.sha256(
        domain.encode("ascii") + b"\0" + len(frame).to_bytes(8, "big") + frame).hexdigest()


def fixture():
    return {"schema": "catchplate.jitApproverPolicy/v1",
        "requiredRoles": ["admin", "approver"], "roleMatch": "any",
        "allowedApproverIds": ["oidc:alpha", "oidc:beta"],
        "allowAnyApproverId": False, "requireWebAuthn": True, "threshold": 2,
        "credentialPolicy": {
            "allowedCredentialRecordIds": ["credential-alpha", "credential-beta"],
            "allowedAuthenticatorClasses": ["hardware", "yubikey"],
            "allowedAaguids": ["aaguid-alpha"], "requireAttestationTrusted": True,
            "requiredTrustBundleDigest": "sha256:" + "1" * 64,
            "minimumTrustBundleSequence": 7, "rpId": "synthetic.invalid",
            "origins": ["https://synthetic.invalid"], "requireUserPresence": True,
            "requireUserVerification": True, "counterPolicy": "strict",
            "maxAssertionAgeSeconds": 30}}


def arguments(policy):
    return {"required_roles": policy["requiredRoles"],
        "allowed_approver_ids": None if policy["allowAnyApproverId"] else policy["allowedApproverIds"],
        "require_webauthn": policy["requireWebAuthn"], "threshold": policy["threshold"],
        "credential_policy": policy["credentialPolicy"]}


def expected_material(policy):
    return {"schema": "catchplate.authorityApproverPolicyBinding/v1",
        "requiredApproverRoles": policy["requiredRoles"],
        "allowedApproverIds": policy["allowedApproverIds"],
        "allowAnyApproverId": policy["allowAnyApproverId"],
        "requireWebAuthn": policy["requireWebAuthn"], "threshold": policy["threshold"],
        "credentialPolicy": policy["credentialPolicy"]}


class ApproverPolicyProjectionTests(unittest.TestCase):
    def refused(self, value):
        with self.assertRaises(policy_binding.ApproverPolicyError) as caught:
            policy_binding.from_jit_policy(value)
        self.assertEqual(str(caught.exception), "approver policy projection is invalid")
        self.assertNotIn("SECRET-CANARY", repr(caught.exception))

    def test_real_producer_formula_and_distinct_genuine_domains(self):
        policy = fixture()
        original = copy.deepcopy(policy)
        expected = expected_material(policy)
        self.assertEqual(policy_binding.material(arguments(policy)), expected)
        authority_digest = domain_digest("catchplate.authorityApproverPolicyBinding/v1", expected)
        jit_digest = domain_digest("catchplate.jitApproverPolicy/v1", policy)
        self.assertEqual(policy_binding.digest(arguments(policy)), authority_digest)
        self.assertEqual(policy_binding.from_jit_policy(policy), authority_digest)
        self.assertNotEqual(authority_digest, jit_digest)
        self.assertNotEqual(authority_digest, domain_digest("catchplate.jitApproverPolicy/v1", expected))
        self.assertNotEqual(authority_digest,
            domain_digest("catchplate.authorityApproverPolicyBinding/v1", policy))
        self.assertEqual(policy, original)

    def test_all_aliases_keep_exact_precedence(self):
        policy = fixture()
        preferred = {"required_approver_roles": ["admin", "approver"],
            "required_roles": ["auditor"], "allowed_approver_ids": policy["allowedApproverIds"],
            "require_webauthn": True, "require_approver_webauthn": False,
            "threshold": 2, "approval_threshold": 1,
            "credential_policy": policy["credentialPolicy"],
            "approver_credential_policy": {"different": "not selected"}}
        fallback = {"required_roles": policy["requiredRoles"],
            "allowed_approver_ids": policy["allowedApproverIds"],
            "require_approver_webauthn": True, "approval_threshold": 2,
            "approver_credential_policy": policy["credentialPolicy"]}
        expected = policy_binding.from_jit_policy(policy)
        self.assertEqual(policy_binding.digest(preferred), expected)
        self.assertEqual(policy_binding.digest(fallback), expected)
        self.assertIsNone(policy_binding.material({**preferred, "required_approver_roles": None}))
        self.assertIsNone(policy_binding.digest({**preferred, "threshold": True}))

    def test_tagged_sets_and_tuples_preserve_producer_wire_semantics(self):
        values = arguments(fixture())
        expected = expected_material(fixture())
        for marker in ("set", "tuple"):
            supplied = copy.deepcopy(values)
            supplied["required_roles"] = {"$authorityType": marker, "items": ["approver", "admin"]}
            supplied["allowed_approver_ids"] = {"$authorityType": marker,
                "items": ["oidc:beta", "oidc:alpha"]}
            supplied["credential_policy"]["allowedAuthenticatorClasses"] = {
                "$authorityType": marker, "items": ["yubikey", "hardware"]}
            self.assertEqual(policy_binding.material(supplied), expected)
            self.assertEqual(policy_binding.digest(supplied), policy_binding.digest(values))
        self.assertIsNone(policy_binding.material({**values, "required_roles": {"admin", "approver"}}))

    def test_none_and_empty_exact_sets_are_not_conflated(self):
        policy = fixture()
        policy.update(allowedApproverIds=[], allowAnyApproverId=True)
        expected = expected_material(policy)
        self.assertEqual(policy_binding.material(arguments(policy)), expected)
        self.assertEqual(policy_binding.from_jit_policy(policy),
            domain_digest("catchplate.authorityApproverPolicyBinding/v1", expected))
        exact_empty = policy_binding.material({**arguments(policy), "allowed_approver_ids": []})
        self.assertIs(exact_empty["allowAnyApproverId"], False)
        self.assertNotEqual(policy_binding.digest({**arguments(policy), "allowed_approver_ids": []}),
            policy_binding.from_jit_policy(policy))
        self.refused({**policy, "allowAnyApproverId": False})
        self.refused({**fixture(), "allowAnyApproverId": True})

    def test_every_valid_semantic_change_changes_authority_commitment(self):
        policy = fixture()
        baseline = policy_binding.from_jit_policy(policy)
        variants = []
        for name, value in (("requiredRoles", ["approver"]), ("threshold", 1),
                ("allowedApproverIds", ["oidc:alpha", "oidc:gamma"])):
            variants.append({**copy.deepcopy(policy), name: value})
        for name, value in (("allowedCredentialRecordIds", []),
                ("allowedAuthenticatorClasses", ["yubikey"]), ("allowedAaguids", []),
                ("requireAttestationTrusted", False), ("requiredTrustBundleDigest", None),
                ("minimumTrustBundleSequence", 8), ("rpId", "other.synthetic.invalid"),
                ("origins", ["https://other.synthetic.invalid"]),
                ("counterPolicy", "strict-or-zero"), ("maxAssertionAgeSeconds", 29)):
            changed = copy.deepcopy(policy)
            changed["credentialPolicy"][name] = value
            variants.append(changed)
        digests = [policy_binding.from_jit_policy(value) for value in variants]
        self.assertNotIn(baseline, digests)
        self.assertEqual(len(digests), len(set(digests)))

    def test_existing_closed_normalizer_semantics_not_new_class_allowlist(self):
        for classes in ([], ["future-authenticator"], ["hardware", "yubikey"]):
            policy = fixture()
            policy["requiredRoles"] = []
            policy["credentialPolicy"]["allowedAuthenticatorClasses"] = classes
            policy["credentialPolicy"]["counterPolicy"] = "strict-or-zero"
            self.assertEqual(policy_binding.from_jit_policy(policy), policy_binding.digest(arguments(policy)))

    def test_missing_producer_fields_keep_optional_result(self):
        values = arguments(fixture())
        for name in values:
            missing = {key: value for key, value in values.items() if key != name}
            self.assertIsNone(policy_binding.material(missing))
            self.assertIsNone(policy_binding.digest(missing))

    def test_noncanonical_top_level_policy_is_not_normalized(self):
        policy = fixture()
        for name, value in (("schema", "catchplate.authorityApproverPolicyBinding/v1"),
                ("roleMatch", "all"), ("roleMatch", None), ("requireWebAuthn", False),
                ("requireWebAuthn", 1), ("allowAnyApproverId", 0), ("threshold", True),
                ("threshold", 1.0), ("threshold", 0), ("threshold", 17),
                ("threshold", 3), ("requiredRoles", ["approver", "admin"]),
                ("requiredRoles", ["approver", "approver"]),
                ("requiredRoles", ["SECRET-CANARY"]), ("allowedApproverIds", None),
                ("allowedApproverIds", ["oidc:alpha", "oidc:alpha"])):
            with self.subTest(field=name, value_type=type(value).__name__):
                self.refused({**copy.deepcopy(policy), name: value})
        self.refused({**policy, "unexpected": "SECRET-CANARY"})
        self.refused({key: value for key, value in policy.items() if key != "roleMatch"})
        self.refused(MappingProxyType(policy))

    def test_noncanonical_credential_policy_is_not_normalized(self):
        for name, value in (("allowedCredentialRecordIds", ["x", "x"]),
                ("allowedAuthenticatorClasses", ["yubikey", "hardware"]),
                ("allowedAaguids", [" SECRET-CANARY"]), ("requireAttestationTrusted", 1),
                ("requiredTrustBundleDigest", "sha256:" + "A" * 64),
                ("minimumTrustBundleSequence", True), ("minimumTrustBundleSequence", 0),
                ("requireUserPresence", False), ("requireUserVerification", 1),
                ("counterPolicy", "ignore"), ("maxAssertionAgeSeconds", True),
                ("maxAssertionAgeSeconds", 0), ("maxAssertionAgeSeconds", 31),
                ("rpId", ""), ("origins", []), ("origins", ["https://a", "https://b"])):
            policy = fixture()
            policy["credentialPolicy"][name] = value
            self.refused(policy)
        policy = fixture()
        policy["credentialPolicy"]["unexpected"] = "SECRET-CANARY"
        self.refused(policy)
        del policy["credentialPolicy"]["unexpected"]
        del policy["credentialPolicy"]["origins"]
        self.refused(policy)

    def test_original_string_and_total_policy_bounds(self):
        policy = fixture()
        policy["allowedApproverIds"] = ["a" * 513, "b"]
        self.refused(policy)
        policy = fixture()
        policy["allowedApproverIds"] = [f"approver-{index:04d}-" + "x" * 490 for index in range(140)]
        self.assertGreater(len(canonical(policy)), 65536)
        self.refused(policy)
        policy = fixture()
        policy["credentialPolicy"]["origins"] = ["https://synthetic.invalid/\ud800"]
        self.refused(policy)


if __name__ == "__main__":
    unittest.main(verbosity=2)
