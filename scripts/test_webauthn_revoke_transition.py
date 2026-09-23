#!/usr/bin/env python3
"""Pure candidate-kernel fixtures, not database/completeness/hardware proof.

The evidence here is an explicit projection of a previously verified receipt.
Real pinned-signature controls live in test_webauthn_revoke_authorization.py.
No registry substitution or fake startup is used: this kernel stays inactive.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_transition_core as core
from serverware import authority_transition_policy as policy
from serverware import authority_transition_webauthn as candidate


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def selected(table: str, item_id: str, row: dict | None) -> dict:
    """The real selected-row shape, without claiming an authenticated DB read."""
    key = {"id": item_id}
    return {
        "table": table,
        "key": key,
        "keyDigest": core.framed_digest(
            "serverware.policyAuthorityBusinessKey/v1",
            table.encode("utf-8"), core.canonical_bytes(key),
        ),
        "present": row is not None,
        "row": None if row is None else copy.deepcopy(row),
        "contractSelector": None,
    }


class RevokeTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kernel = candidate.WebAuthnCredentialRevokeKernel()
        self.now = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        self.request_digest = digest(b"pure candidate revoke fixture")
        self.operation_id = core.framed_digest(
            "serverware.policyAuthorityOperation/v2",
            candidate.OPERATION.encode("ascii"), self.request_digest.encode("ascii"),
        )
        self.values = {
            "record_id": "credential-target", "actor_id": "user-owner",
            "reason": "self-service fixture", "source": "explicit",
            "audit_event": {"credential_record_id": "credential-target"},
            "approval_grant_ids": ["grant-one"],
            "control_plane_approval_ids": ["approval-one"],
            "oidc_session_ids": ["session-active", "session-pending"],
            "registration_challenge_ids": ["registration-other-user"],
        }

    def arguments(self, values: dict | None = None) -> dict:
        values = copy.deepcopy(self.values if values is None else values)
        return {**values, "businessIntent": authority_contract.synthesize_business_intent(candidate.OPERATION, values)}

    def credential(self, item_id: str) -> dict:
        return {
            "id": item_id, "credential_id": "public-" + item_id,
            "user_id": "user-owner", "sign_count": 2, "revoked_at": None,
            "revoked_by": None, "revocation_reason": None,
            "revocation_source": None, "last_used_at": None,
            "updated_at": (self.now - timedelta(days=1)).isoformat(),
            "transports": '["usb"]', "attestation_trusted": 1,
            "attestation_trust_path": '["fixture-root"]',
        }

    def context(self, *, separate_signer: bool = False) -> core.KernelContext:
        signer_id = "credential-signer" if separate_signer else self.values["record_id"]
        signer = self.credential(signer_id)
        raw_challenge = b"pure local candidate challenge"
        challenge = {
            "id": "assertion-challenge",
            "challenge": base64.urlsafe_b64encode(raw_challenge).decode("ascii").rstrip("="),
            "challenge_type": "policy_authority", "user_id": "user-owner",
            "scope_key": self.operation_id, "approval_request_id": None,
            "payload_json": core.canonical_bytes({
                "operationId": self.operation_id,
                "credentialId": signer["credential_id"],
                "rpId": "unit.example", "origin": "https://unit.example",
            }).decode("ascii"),
            "expires_at": (self.now + timedelta(minutes=1)).isoformat(),
            "used_at": None, "created_at": self.now.isoformat(),
        }
        challenge_public = {
            **json.loads(challenge["payload_json"]),
            "challengeId": challenge["id"], "challenge": challenge["challenge"],
            "challengeRowDigest": core.framed_digest(
                "serverware.policyAuthorityWebAuthnChallengeRow/v1", core.canonical_bytes(challenge),
            ),
        }
        # Deliberately a trusted projection, NOT an independently signed receipt.
        evidence = {
            "operation": candidate.OPERATION, "operationId": self.operation_id,
            "requestDigest": self.request_digest, "credentialRecordId": signer_id,
            "credentialId": signer["credential_id"], "challengeId": challenge["id"],
            "challengeDigest": digest(core.canonical_bytes(challenge_public)),
            "clientChallengeDigest": digest(raw_challenge),
            "rpId": "unit.example", "origin": "https://unit.example",
            "priorCounter": 2, "counter": 3,
        }
        target = self.credential(self.values["record_id"])
        rows = [selected("webauthn_credentials", target["id"], target)]
        if separate_signer:
            rows.append(selected("webauthn_credentials", signer_id, signer))
        rows.append(selected("webauthn_challenges", challenge["id"], challenge))
        for item_id, status in (("session-active", "active"), ("session-pending", "pending_webauthn")):
            rows.append(selected("oidc_browser_sessions", item_id, {
                "id": item_id, "bound_webauthn_credential_id": target["id"],
                "status": status, "revoked_at": None, "updated_at": self.now.isoformat(),
                "revocation_reason": None,
            }))
        rows.append(selected("approval_grants", "grant-one", {
            "id": "grant-one", "approver_webauthn_credential_id": target["id"],
            "state": "active", "uses_remaining": 5, "reserved_attempt_id": "reservation",
            "reserved_at_epoch_ms": 1, "reservation_expires_at_epoch_ms": 2,
        }))
        rows.append(selected("control_plane_approvals", "approval-one", {
            "id": "approval-one", "approver_webauthn_credential_id": target["id"],
            "status": "approved", "action": "fixture.action", "resource_id": "fixture-resource",
            "payload_digest": digest(b"fixture approval payload"),
            "requester_id": "user-requester", "approved_by": "user-owner",
        }))
        rows.append(selected("webauthn_challenges", "registration-other-user", {
            "id": "registration-other-user", "challenge_type": "registration",
            "user_id": "different-user", "used_at": None,
            "expires_at": (self.now + timedelta(minutes=2)).isoformat(),
        }))
        for subject in ("approval-one", None):
            item_id = candidate.audit_id(candidate.OPERATION, self.request_digest, subject)
            rows.append(selected("metadata_audit_outbox", item_id, None))
        return core.KernelContext(
            operation=candidate.OPERATION, arguments=self.arguments(), selected_rows=tuple(rows),
            database_now=self.now, request_digest=self.request_digest,
            verified_webauthn_evidence=evidence,
        )

    def mutation_rows(self, transition: core.KernelTransition) -> dict:
        return {(item["table"], item["key"]["id"]): item for item in transition.mutations}

    def test_all_cascades_and_merged_self_assertion_are_one_pure_plan(self) -> None:
        context = self.context()
        before = copy.deepcopy(context.selected_rows)
        transition = self.kernel.transition(context)
        mutations = self.mutation_rows(transition)
        self.assertEqual(len(transition.mutations), 9)
        target = mutations[("webauthn_credentials", "credential-target")]
        self.assertEqual(target["expectedRow"]["sign_count"], 2)
        self.assertEqual(target["row"]["sign_count"], 3)
        self.assertEqual(target["row"]["revoked_at"], self.now.isoformat())
        self.assertEqual(target["row"]["revocation_source"], "explicit")
        self.assertEqual(mutations[("webauthn_challenges", "assertion-challenge")]["row"]["used_at"], self.now.isoformat())
        for session_id in self.values["oidc_session_ids"]:
            row = mutations[("oidc_browser_sessions", session_id)]["row"]
            self.assertEqual(row["status"], "revoked")
            self.assertEqual(row["revocation_reason"], "bound_webauthn_credential_revoked")
        grant = mutations[("approval_grants", "grant-one")]["row"]
        self.assertEqual((grant["state"], grant["uses_remaining"]), ("revoked", 0))
        for field in ("reserved_attempt_id", "reserved_at_epoch_ms", "reservation_expires_at_epoch_ms"):
            self.assertIsNone(grant[field])
        self.assertEqual(mutations[("control_plane_approvals", "approval-one")]["row"]["status"], "invalidated")
        registration = mutations[("webauthn_challenges", "registration-other-user")]["row"]
        self.assertEqual(registration["user_id"], "different-user")
        self.assertEqual(registration["used_at"], self.now.isoformat())
        result = transition.result
        self.assertEqual([result[name] for name in (
            "revoked_grant_count", "revoked_control_plane_approval_count",
            "revoked_oidc_browser_session_count", "invalidated_registration_challenge_count",
        )], [1, 1, 2, 1])
        self.assertEqual(result["credential"]["transports"], ["usb"])
        self.assertEqual(result["credential"]["attestation_trust_path"], ["fixture-root"])
        self.assertIs(result["credential"]["attestation_trusted"], True)
        self.assertEqual(result["credential"]["sign_count"], 3)
        self.assertEqual(context.selected_rows, before)
        self.assertEqual(self.kernel.transition(context), transition)

    def test_separate_same_user_signer_updates_its_counter_not_revocation(self) -> None:
        transition = self.kernel.transition(self.context(separate_signer=True))
        mutations = self.mutation_rows(transition)
        self.assertEqual(len(transition.mutations), 10)
        signer = mutations[("webauthn_credentials", "credential-signer")]["row"]
        self.assertEqual(signer["sign_count"], 3)
        self.assertIsNone(signer["revoked_at"])
        self.assertEqual(transition.result["credential"]["sign_count"], 2)

    def test_per_approval_and_optional_credential_audits_match_storage_digest(self) -> None:
        transition = self.kernel.transition(self.context())
        audits = [item["row"] for item in transition.mutations if item["table"] == "metadata_audit_outbox"]
        self.assertEqual(len(audits), 2)
        for audit in audits:
            event_bytes = audit["event_json"].encode("utf-8")
            expected = digest(b"serverware.metadataAuditOutboxEvent/v1\0" + len(event_bytes).to_bytes(8, "big") + event_bytes)
            self.assertEqual(audit["event_digest"], expected)
            self.assertEqual((audit["status"], audit["storage_format_version"], audit["attempts"]), ("pending", 2, 0))
        approval = next(row for row in audits if row["event_type"] == "control_plane.approval.invalidated")
        self.assertEqual((approval["actor_type"], approval["actor_id"]), ("system", None))
        self.assertEqual(json.loads(approval["event_json"])["approval_id"], "approval-one")
        credential = next(row for row in audits if row["event_type"] == "webauthn.credential_revoked")
        self.assertEqual((credential["actor_type"], credential["actor_id"]), ("admin", "user-owner"))
        context = self.context()
        values = {**self.values, "audit_event": None}
        no_optional = self.kernel.transition(replace(context, arguments=self.arguments(values)))
        self.assertEqual(sum(item["table"] == "metadata_audit_outbox" for item in no_optional.mutations), 1)

    def test_selection_uses_whole_predicates_and_global_registration_not_hints(self) -> None:
        context = self.context()
        queries = self.kernel.queries_with_evidence(
            arguments=context.arguments, database_now=self.now,
            request_digest=self.request_digest, evidence=context.verified_webauthn_evidence,
        )
        predicate_values = lambda query: {(item.column, item.operator): item.value for item in query.predicates}
        registrations = next(query for query in queries if "global_registration_challenges" in query.query_id)
        self.assertEqual(predicate_values(registrations), {
            ("challenge_type", "eq"): "registration", ("used_at", "is-null"): None,
            ("expires_at", "gt"): self.now.isoformat(),
        })
        sessions = [query for query in queries if query.table == "oidc_browser_sessions"]
        self.assertEqual({predicate_values(query)[("status", "eq")] for query in sessions}, {"active", "pending_webauthn"})
        for query in queries:
            if query.absent_key is None:
                self.assertTrue(query.exact_page)
                self.assertEqual(query.proof_primitive, "ordered-exact-page")
                self.assertIsNone(query.page_size)
                self.assertIsNone(query.continuation_token_digest)
                self.assertNotIn("id", {item.column for item in query.predicates})
        capacity = [query for query in queries if "audit_capacity_" in query.query_id]
        self.assertEqual({predicate_values(query)[("status", "eq")] for query in capacity}, {"pending", "claimed"})
        self.assertEqual(sum(query.maximum_rows for query in queries), 192)
        self.assertLess(sum(query.maximum_rows for query in capacity), candidate.AUDIT_CAPACITY)

    def test_every_invalidated_approval_has_its_own_absent_key_audit(self) -> None:
        context = self.context()
        second = {
            **context.exact("control_plane_approvals", {"id": "approval-one"})["row"],
            "id": "approval-two", "resource_id": "second-resource",
        }
        second_audit = candidate.audit_id(candidate.OPERATION, self.request_digest, "approval-two")
        values = {**self.values, "control_plane_approval_ids": ["approval-one", "approval-two"]}
        context = replace(context, arguments=self.arguments(values), selected_rows=context.selected_rows + (
            selected("control_plane_approvals", second["id"], second),
            selected("metadata_audit_outbox", second_audit, None),
        ))
        transition = self.kernel.transition(context)
        audits = [item for item in transition.mutations if item["table"] == "metadata_audit_outbox"]
        self.assertEqual(len(audits), 3)
        approval_audits = [item for item in audits if item["row"]["event_type"] == "control_plane.approval.invalidated"]
        self.assertEqual({json.loads(item["row"]["event_json"])["approval_id"] for item in approval_audits}, {"approval-one", "approval-two"})
        self.assertEqual(len({item["keyDigest"] for item in approval_audits}), 2)
        self.assertTrue(all(item["operation"] == "INSERT" and item["expectedRow"] is None for item in approval_audits))
        self.assertEqual(transition.result["revoked_control_plane_approval_count"], 2)

    def test_omitted_extra_and_duplicate_dependency_hints_deny(self) -> None:
        for name in ("approval_grant_ids", "control_plane_approval_ids", "oidc_session_ids", "registration_challenge_ids"):
            for mode in ("omitted", "extra", "duplicate"):
                with self.subTest(field=name, mode=mode):
                    values = copy.deepcopy(self.values)
                    if mode == "omitted":
                        values[name] = []
                    elif mode == "extra":
                        values[name] = sorted(values[name] + ["unknown-dependent"])
                    else:
                        values[name] += values[name][:1]
                    with self.assertRaises(core.TransitionKernelError):
                        self.kernel.transition(replace(self.context(), arguments=self.arguments(values)))

    def test_nonexplicit_sources_and_aggregate_overflow_deny_before_selection(self) -> None:
        for source in ("trust-withdrawal", "administrative", "offline-last-key-decommission", ""):
            with self.subTest(source=source), self.assertRaises(core.TransitionKernelError):
                candidate.prepare_revocation_input({**self.values, "source": source})
        values = copy.deepcopy(self.values)
        for field in ("approval_grant_ids", "control_plane_approval_ids", "oidc_session_ids", "registration_challenge_ids"):
            values[field] = [f"fixture-{number:02d}" for number in range(32)]
        with self.assertRaisesRegex(core.TransitionKernelError, "aggregate mutation bound"):
            candidate.prepare_revocation_input(values)

    def test_other_owner_target_signer_or_challenge_deny(self) -> None:
        for table, item_id in (("webauthn_credentials", "credential-target"), ("webauthn_credentials", "credential-signer"), ("webauthn_challenges", "assertion-challenge")):
            with self.subTest(table=table, item_id=item_id):
                context = self.context(separate_signer=True)
                context.exact(table, {"id": item_id})["row"]["user_id"] = "different-user"
                before = copy.deepcopy(context.selected_rows)
                with self.assertRaises(core.TransitionKernelError):
                    self.kernel.transition(context)
                self.assertEqual(context.selected_rows, before)

    def test_missing_stale_wrong_binding_and_used_assertion_deny(self) -> None:
        context = self.context()
        with self.assertRaises(core.TransitionKernelError):
            self.kernel.transition(replace(context, verified_webauthn_evidence=None))
        for field, value in (("requestDigest", digest(b"other")), ("operationId", digest(b"other")), ("counter", 2), ("priorCounter", 1), ("challengeDigest", digest(b"other")), ("clientChallengeDigest", digest(b"other"))):
            with self.subTest(field=field), self.assertRaises(core.TransitionKernelError):
                self.kernel.transition(replace(context, verified_webauthn_evidence={**context.verified_webauthn_evidence, field: value}))
        for field, value in (("used_at", self.now.isoformat()), ("expires_at", self.now.isoformat()), ("scope_key", digest(b"other"))):
            with self.subTest(challenge_field=field):
                changed = self.context()
                changed.exact("webauthn_challenges", {"id": "assertion-challenge"})["row"][field] = value
                with self.assertRaises(core.TransitionKernelError):
                    self.kernel.transition(changed)

    def test_existing_audit_identity_and_row_budget_deny_without_input_writes(self) -> None:
        context = self.context()
        audit_id = candidate.audit_id(candidate.OPERATION, self.request_digest, "approval-one")
        audit = context.exact("metadata_audit_outbox", {"id": audit_id})
        audit.update(present=True, row={"id": audit_id, "status": "audited"})
        before = copy.deepcopy(context.selected_rows)
        with self.assertRaisesRegex(core.TransitionKernelError, "audit identity"):
            self.kernel.transition(context)
        self.assertEqual(context.selected_rows, before)
        context = self.context()
        excess = tuple(selected("metadata_audit_outbox", f"unrelated-{number}", {"id": f"unrelated-{number}", "status": "audited"}) for number in range(193))
        with self.assertRaisesRegex(core.TransitionKernelError, "aggregate plan"):
            self.kernel.transition(replace(context, selected_rows=context.selected_rows + excess))

    def test_candidate_is_not_registered_or_presented_as_startup_closure(self) -> None:
        registry_source = (ROOT / "serverware/authority_transition_registry.py").read_text()
        policy_source = (ROOT / "serverware/authority_transition_policy.py").read_text()
        self.assertNotIn("authority_transition_webauthn", registry_source)
        self.assertNotIn("WebAuthnCredentialRevokeKernel", registry_source)
        self.assertNotIn("WebAuthnCredentialRevokeKernel", policy_source)
        # Registry diagnostics remain the real gate; do not fabricate a registry
        # to import the planner or claim the four missing kernels are present.
        self.assertIn("missing transition kernels", registry_source)
        self.assertTrue({
            "webauthn.trust.stage", "webauthn.trust.complete",
            "webauthn.registration.finalize", candidate.OPERATION,
        }.isdisjoint(policy.KERNELS))

    def test_exact_empty_page_constructor_has_no_limit_plus_one_page_size(self) -> None:
        query = policy._exact_empty_page_query(
            operation=candidate.OPERATION, name="fixture_empty_page",
            table="approval_grants", predicates={"state": "active"}, order_by=("id",),
        )
        self.assertEqual(query.maximum_rows, 1)
        self.assertEqual(query.proof_primitive, "ordered-exact-page")
        self.assertTrue(query.exact_page)
        self.assertIsNone(query.page_size)
        self.assertIsNone(query.continuation_token_digest)


if __name__ == "__main__":
    unittest.main()
