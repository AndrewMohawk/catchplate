#!/usr/bin/env python3
"""Semantic client-shape tests; recording transport never returns acceptance."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_contract
from catchplate import authority_transition_core as core
from catchplate import webauthn_revocation_admission as admission
from catchplate.authority_transition_webauthn import prepare_revocation_input


class RecordedOnly(RuntimeError):
    pass


class RevocationAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.arguments = {
            "record_id": "own-record", "actor_id": "oidc:operator",
            "reason": "rotate key", "source": "explicit", "audit_event": None,
            "approval_grant_ids": [], "control_plane_approval_ids": [],
            "oidc_session_ids": [], "registration_challenge_ids": [],
        }
        self.authorization = {
            "challengeId": "authority-challenge", "credentialRecordId": "signer-record",
            "assertion": {"credentialId": "signer-id", "clientDataJSON": "YQ",
                          "authenticatorData": "Yg", "signature": "Yw"},
        }
        self.calls: list[tuple[str, dict]] = []

    def record(self, operation: str, value: dict) -> dict:
        self.calls.append((operation, copy.deepcopy(value)))
        raise RecordedOnly("local transport recorder: no authority acceptance")

    def test_challenge_and_execute_bind_identical_semantic_input(self) -> None:
        with patch.object(admission, "_dispatch", self.record):
            with self.assertRaises(RecordedOnly):
                admission.issue_self_revocation_challenge(
                    arguments=self.arguments, user_id="oidc:operator", credential_id="signer-id",
                )
            with self.assertRaises(RecordedOnly):
                admission.revoke_own_credential(
                    arguments=self.arguments, webauthn_authorization=self.authorization,
                )
        challenge_operation, challenge = self.calls[0]
        operation, execute = self.calls[1]
        self.assertEqual(challenge_operation, "webauthn.challenge.create")
        self.assertEqual(operation, "webauthn.credential.revoke")
        self.assertEqual(set(challenge), {"operation", "input", "userId", "credentialId"})
        self.assertEqual(set(execute), {"input", "webauthnAuthorization"})
        self.assertEqual(challenge["operation"], operation)
        self.assertEqual(challenge["input"], execute["input"])
        self.assertEqual(
            authority_contract.synthesize_business_intent(operation, challenge["input"]),
            authority_contract.synthesize_business_intent(operation, execute["input"]),
        )
        self.assertEqual(execute["webauthnAuthorization"], self.authorization)

    def test_other_challenge_actor_is_rejected_before_dispatch(self) -> None:
        with patch.object(admission, "_dispatch", self.record), self.assertRaises(core.TransitionKernelError):
            admission.issue_self_revocation_challenge(
                arguments=self.arguments, user_id="oidc:other", credential_id="signer-id",
            )
        self.assertEqual(self.calls, [])

    def test_internal_authority_and_inexact_raw_assertions_are_rejected(self) -> None:
        for field in ("businessIntent", "_connection", "transactionResult", "queryMultiproofs", "verified_webauthn_evidence"):
            with self.subTest(field=field), self.assertRaises(core.TransitionKernelError):
                prepare_revocation_input({**self.arguments, field: {}})
        references = (
            {**self.authorization, "verifiedAssertionReceiptDigest": "sha256:" + "0" * 64},
            {**self.authorization, "credentialId": "both-address-kinds"},
            {**self.authorization, "assertion": {**self.authorization["assertion"], "counter": 4}},
            {name: value for name, value in self.authorization.items() if name != "assertion"},
        )
        with patch.object(admission, "_dispatch", self.record):
            for reference in references:
                with self.subTest(reference=reference), self.assertRaises(core.TransitionKernelError):
                    admission.revoke_own_credential(arguments=self.arguments, webauthn_authorization=reference)
        self.assertEqual(self.calls, [])

    def test_nonexplicit_modes_are_not_authorized_by_raw_assertion(self) -> None:
        for source in ("trust-root-withdrawal", "offline-last-key-decommission", "admin", ""):
            with self.subTest(source=source), self.assertRaises(core.TransitionKernelError):
                prepare_revocation_input({**self.arguments, "source": source})

    def test_hint_sets_and_aggregate_mutation_budget_are_closed(self) -> None:
        for ids in (["a", "a"], ["b", "a"], [str(index) for index in range(33)], "not-a-list"):
            with self.subTest(ids=ids), self.assertRaises(core.TransitionKernelError):
                prepare_revocation_input({**self.arguments, "approval_grant_ids": ids})
        hints = [f"id-{index:02}" for index in range(32)]
        all_full = {**self.arguments, **{field: hints for field in (
            "approval_grant_ids", "control_plane_approval_ids", "oidc_session_ids", "registration_challenge_ids",
        )}}
        with self.assertRaisesRegex(core.TransitionKernelError, "aggregate mutation"):
            prepare_revocation_input(all_full)
        # 3 reserved target/assertion writes + 32 sessions + 32 grants +
        # 2*32 approval/audit writes + 4 registrations + 1 credential audit.
        exactly_136 = {
            **all_full, "registration_challenge_ids": hints[:4],
            "audit_event": {"reason": "at total mutation bound"},
        }
        self.assertEqual(prepare_revocation_input(exactly_136), exactly_136)
        with self.assertRaisesRegex(core.TransitionKernelError, "aggregate mutation"):
            prepare_revocation_input({**exactly_136, "registration_challenge_ids": hints[:5]})


if __name__ == "__main__":
    unittest.main()
