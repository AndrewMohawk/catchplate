#!/usr/bin/env python3
"""Pure candidate-kernel fixtures, not database/completeness/hardware proof.

The evidence here is an explicit projection of a previously verified receipt.
Real pinned-signature controls live in test_webauthn_revoke_authorization.py.
No registry substitution or fake startup is used: this kernel stays inactive.
The shared capacity composition is exercised with independently hashed synthetic
counter rows, not authenticated initialization, maintained population or current
root authority. No blocked planner import is needed to call its real helpers.
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

from catchplate import authority_contract
from catchplate import authority_audit_capacity as capacity
from catchplate import authority_complete_query as complete
from catchplate import authority_transition_core as core
from catchplate import authority_transition_policy as policy
from catchplate import authority_transition_webauthn as candidate
import authority_revocation_trust_fixture as trust_oracle


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("ascii")


def framed(domain: str, *frames: bytes) -> str:
    value = hashlib.sha256(domain.encode("ascii") + b"\0")
    for frame in frames:
        value.update(len(frame).to_bytes(8, "big"))
        value.update(frame)
    return "sha256:" + value.hexdigest()


# Literal verifier-reader projection, independent of the production helper.
# Retention columns remain in the authenticated primary row and full-row CAS.
CHALLENGE_BINDING_FIELDS = (
    "id", "challenge", "challenge_type", "user_id", "scope_key",
    "approval_request_id", "payload_json", "expires_at", "used_at", "created_at",
)
CHALLENGE_RETENTION_FIELDS = (
    "retention_recovery_id", "retention_recovery_row_digest",
    "retention_jit_receipt_digest", "retention_jit_row_digest",
    "retention_activation_receipt_digest", "retention_activation_row_digest",
    "retention_reference_mask",
)


def challenge_binding(row: dict) -> dict:
    return {name: row[name] for name in CHALLENGE_BINDING_FIELDS}


def challenge_with_retention(row: dict) -> dict:
    if set(row) != set(CHALLENGE_BINDING_FIELDS):
        raise ValueError("fixture challenge must supply all ten reader fields")
    return {**row, **{name: None for name in CHALLENGE_RETENTION_FIELDS[:-1]},
            "retention_reference_mask": 0}


COUNTER_TABLE = "policy_authority_bounded_aggregate_states"
COUNTER_KIND = "metadata-audit-outbox-global-capacity-v1"
COUNTER_PARTITION = framed("catchplate.metadataAuditOutboxCapacityPartition/v1", b"global")
COUNTER_ID = COUNTER_KIND + ":" + COUNTER_PARTITION


def counter_row(**changes) -> dict:
    """Independent compact state/hash oracle; a constructed row has no authority."""
    row = {
        "aggregate_id": COUNTER_ID, "aggregate_kind": COUNTER_KIND,
        "partition_digest": COUNTER_PARTITION, "revision": 7,
        "live_count": 0, "active_count": 0, "capacity_limit": 100_000,
        "reserved_units_json": "{}", "committed_units_json": "{}", "next_sequence": 19,
        "minimum_expiry_epoch_ns": None,
        "expiry_index_root_digest": framed("catchplate.policyAuthorityAggregateExpiryIndex/v1", b"[]"),
        "work_page_id": None, "updated_at_epoch_ns": 1_000_000_000,
        "source_revision": authority_contract.SOURCE_REVISION, **changes,
    }
    state = {
        "schema": "catchplate.policyAuthorityAggregateState/v1",
        "aggregateId": row["aggregate_id"], "aggregateKind": row["aggregate_kind"],
        "partitionDigest": row["partition_digest"], "revision": row["revision"],
        "liveCount": row["live_count"], "activeCount": row["active_count"],
        "capacityLimit": row["capacity_limit"],
        "reservedUnits": json.loads(row["reserved_units_json"]),
        "committedUnits": json.loads(row["committed_units_json"]),
        "nextSequence": row["next_sequence"], "minimumExpiryEpochNs": row["minimum_expiry_epoch_ns"],
        "expiryIndexRootDigest": row["expiry_index_root_digest"], "workPageId": row["work_page_id"],
    }
    row["state_json"] = canonical(state).decode("ascii")
    row["state_digest"] = framed("catchplate.policyAuthorityAggregateState/v1", canonical(state))
    return row


def counter_selected(row: dict | None) -> dict:
    key = {"aggregate_id": COUNTER_ID}
    return {
        "table": COUNTER_TABLE, "key": key,
        "keyDigest": framed("catchplate.policyAuthorityBusinessKey/v1", COUNTER_TABLE.encode("ascii"), canonical(key)),
        "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None,
    }


def selected(table: str, item_id: str, row: dict | None) -> dict:
    """The real selected-row shape, without claiming an authenticated DB read."""
    key = {"id": item_id}
    return {
        "table": table,
        "key": key,
        "keyDigest": core.framed_digest(
            "catchplate.policyAuthorityBusinessKey/v1",
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
            "catchplate.policyAuthorityOperation/v2",
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
            **trust_oracle.credential_fields(),
        }

    def context(self, *, separate_signer: bool = False) -> core.KernelContext:
        signer_id = "credential-signer" if separate_signer else self.values["record_id"]
        signer = self.credential(signer_id)
        raw_challenge = b"pure local candidate challenge"
        challenge = challenge_with_retention({
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
        })
        challenge_public = {
            **json.loads(challenge["payload_json"]),
            "challengeId": challenge["id"], "challenge": challenge["challenge"],
            "challengeRowDigest": framed(
                "catchplate.policyAuthorityWebAuthnChallengeRow/v1", canonical(challenge_binding(challenge)),
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
        high_water = trust_oracle.trust_rows()["webauthn_trust_publication_high_water"][0]
        evidence.update(trustHighWaterDigest=framed("catchplate.webauthnTrustHighWater/v1",
                canonical(trust_oracle.trust_high_water_document(high_water))),
            metadataPublicationSequence=high_water["publication_sequence"],
            credentialPolicyDigest=framed("catchplate.policyAuthorityCredentialPolicy/v1",
                canonical(trust_oracle.credential_policy_document(signer, high_water))))
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
        rows.append(selected("webauthn_challenges", "registration-other-user", challenge_with_retention({
            "id": "registration-other-user", "challenge_type": "registration",
            "user_id": "different-user", "used_at": None,
            "challenge": "cmVnaXN0cmF0aW9u", "scope_key": None,
            "approval_request_id": None, "payload_json": "{}",
            "expires_at": (self.now + timedelta(minutes=2)).isoformat(),
            "created_at": self.now.isoformat(),
        })))
        for subject in ("approval-one", None):
            item_id = candidate.audit_id(candidate.OPERATION, self.request_digest, subject)
            rows.append(selected("metadata_audit_outbox", item_id, None))
        rows.extend(trust_oracle.selected_rows())
        return core.KernelContext(
            operation=candidate.OPERATION, arguments=self.arguments(), selected_rows=tuple(rows),
            database_now=self.now, request_digest=self.request_digest,
            verified_webauthn_evidence=evidence,
        )

    def mutation_rows(self, transition: core.KernelTransition) -> dict:
        return {(item["table"], item["key"]["id"]): item for item in transition.mutations}

    def with_capacity(self, context: core.KernelContext, **changes) -> core.KernelContext:
        return replace(context, selected_rows=(*context.selected_rows, counter_selected(counter_row(**changes))))

    def composed(self, context: core.KernelContext):
        # Actual common-planner helper order, not a replacement planner/registry.
        queries = capacity.add_capacity_query(candidate.OPERATION, self.kernel.queries_with_evidence(
            arguments=context.arguments, database_now=context.database_now,
            request_digest=context.request_digest, evidence=context.verified_webauthn_evidence,
        ))
        business = self.kernel.transition(context)
        mutations = capacity.finalize_capacity(context, business.mutations)
        work = capacity.transition_work_units(candidate.OPERATION,
            sum(query.work_units for query in queries), business.work_units, mutations)
        capacity.validate_capacity_transition(operation=candidate.OPERATION,
            selected_rows=context.selected_rows, mutations=mutations)
        capacity.validate_transition_work_units(candidate.OPERATION, work, mutations)
        return queries, business, mutations, work

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

    def test_reader_challenge_binding_preserves_full_retention_cas(self) -> None:
        context = self.context()
        for item in context.selected_rows:
            if item["table"] == "webauthn_challenges":
                self.assertEqual(set(item["row"]),
                    set(CHALLENGE_BINDING_FIELDS) | set(CHALLENGE_RETENTION_FIELDS))
                self.assertEqual(len(item["row"]), 17)
        challenge = context.exact("webauthn_challenges", {"id": "assertion-challenge"})["row"]
        challenge.update(retention_recovery_id="fixture-recovery",
            retention_recovery_row_digest=digest(b"fixture retained recovery row"),
            retention_reference_mask=1)
        original = copy.deepcopy(challenge)
        binding = challenge_binding(challenge)
        self.assertEqual(len(binding), 10)
        self.assertNotEqual(framed("catchplate.policyAuthorityWebAuthnChallengeRow/v1", canonical(binding)),
                            framed("catchplate.policyAuthorityWebAuthnChallengeRow/v1", canonical(challenge)))
        transition = self.kernel.transition(context)
        changed = self.mutation_rows(transition)[("webauthn_challenges", "assertion-challenge")]
        self.assertEqual(changed["expectedRow"], original)
        self.assertEqual(changed["row"], {**original, "used_at": self.now.isoformat()})
        self.assertEqual(challenge, original)
        # A receipt over the old full-row hash is not the real reader's receipt.
        wrong_public = {**json.loads(challenge["payload_json"]),
            "challengeId": challenge["id"], "challenge": challenge["challenge"],
            "challengeRowDigest": framed("catchplate.policyAuthorityWebAuthnChallengeRow/v1",
                                          canonical(challenge))}
        wrong = {**context.verified_webauthn_evidence,
                 "challengeDigest": digest(canonical(wrong_public))}
        with self.assertRaises(core.TransitionKernelError):
            self.kernel.transition(replace(context, verified_webauthn_evidence=wrong))
        for mode in ("missing-retention", "extra-field"):
            malformed = self.context()
            row = malformed.exact("webauthn_challenges", {"id": "assertion-challenge"})["row"]
            if mode == "missing-retention":
                del row["retention_recovery_id"]
            else:
                row["unexpected"] = None
            with self.subTest(mode=mode), self.assertRaises(core.TransitionKernelError):
                self.kernel.transition(malformed)

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
            expected = digest(b"catchplate.metadataAuditOutboxEvent/v1\0" + len(event_bytes).to_bytes(8, "big") + event_bytes)
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
        complete_queries = tuple(query for query in queries if type(query) is complete.CompleteIndexQuery)
        self.assertEqual(tuple(query.role for query in complete_queries), (
            "sessions_pending_webauthn", "sessions_active", "grants", "approvals",
            "global_registration_challenges", "pending_trust_publications",
        ))
        elapsed = self.now - datetime(1970, 1, 1, tzinfo=timezone.utc)
        cutoff_us = (elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds
        expected = {
            "sessions_pending_webauthn": ("webauthn_session_credential_status",
                {"credential_record_id": "credential-target", "status": "pending_webauthn"}, 2),
            "sessions_active": ("webauthn_session_credential_status",
                {"credential_record_id": "credential-target", "status": "active"}, 2),
            "grants": ("webauthn_grant_approver_active", {"credential_record_id": "credential-target"}, 1),
            "approvals": ("webauthn_control_approval_approved", {"credential_record_id": "credential-target"}, 1),
            "global_registration_challenges": ("webauthn_registration_unused_global",
                {"expires_after_us": cutoff_us}, 1),
            "pending_trust_publications": ("webauthn_publication_status", {"status": "pending"}, 1),
        }
        for query in complete_queries:
            self.assertEqual((query.index_id, query.selector(), query.maximum_rows), expected[query.role])
            self.assertEqual(query.proof_primitive, complete.PROOF_PRIMITIVE)
            self.assertNotIsInstance(query, core.BoundedQuery)
            for name in ("predicates", "order_by", "absent_key", "exact_page", "page_size",
                         "continuation_token_digest", "secondary_index_name"):
                self.assertFalse(hasattr(query, name))
        self.assertEqual(complete.validate_bindings(candidate.OPERATION, complete_queries,
            arguments=context.arguments, cutoff_us=cutoff_us), complete_queries)
        exact_queries = [query for query in queries if type(query) is core.BoundedQuery]
        self.assertEqual(len(exact_queries), 6)
        for query in exact_queries:
            self.assertEqual(query.proof_primitive, "primary-key-row")
            self.assertFalse(query.exact_page)
            self.assertEqual(query.maximum_rows, 1)
            if query.absent_key is not None:
                self.assertEqual(query.predicates,
                    tuple(core.QueryPredicate(column, "eq", value) for column, value in query.absent_key.items()))
                self.assertEqual(query.order_by, tuple(core.QueryOrder(column) for column in query.absent_key))
            else:
                self.assertEqual(query.table, "webauthn_trust_publications")
                self.assertEqual(query.order_by, (core.QueryOrder("id"),))
                self.assertEqual(tuple(item.column for item in query.predicates),
                    ("scope", "status", "bundle_digest", "payload_digest", "rollback_epoch", "sequence"))
                self.assertTrue(all(type(item.value) is core.SelectedRowFieldReference for item in query.predicates[2:]))
            self.assertEqual(query.contract_value()["schema"], "catchplate.policyAuthorityQueryProgram/v1")
        audit_queries = [query for query in queries if query.table == "metadata_audit_outbox"]
        self.assertEqual(len(audit_queries), 2)
        self.assertTrue(all(query.absent_key is not None and query.maximum_rows == 1 for query in audit_queries))
        self.assertFalse(any("audit_capacity_" in query.query_id or query.table == COUNTER_TABLE for query in queries))
        # Both session partitions reserve two rows. The complete pending-trust
        # query plus exact high-water/publication reads add three trust rows.
        self.assertEqual(sum(query.maximum_rows for query in complete_queries), 8)
        self.assertEqual(sum(query.maximum_rows for query in exact_queries), 6)
        self.assertEqual(sum(query.maximum_rows for query in queries), 14)
        composed_queries = capacity.add_capacity_query(candidate.OPERATION, queries)
        self.assertEqual(composed_queries[:-1], queries)
        self.assertEqual(composed_queries[-1].absent_key, {"aggregate_id": COUNTER_ID})
        self.assertEqual(composed_queries[-1].maximum_rows, 1)
        self.assertEqual(sum(query.maximum_rows for query in composed_queries), 15)

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

    def test_shared_capacity_two_audits_fill_exact_limit_with_one_independent_counter_cas(self) -> None:
        context = self.with_capacity(self.context(), live_count=99_998, active_count=99_998)
        before = copy.deepcopy((context.arguments, context.selected_rows, context.verified_webauthn_evidence))
        queries, business, mutations, work = self.composed(context)
        self.assertEqual((len(business.mutations), len(mutations), len(queries), work), (9, 10, 13, 73))
        self.assertTrue(all(item["table"] != COUNTER_TABLE for item in business.mutations))
        counter = mutations[-1]
        self.assertEqual((counter["table"], counter["key"], counter["operation"]),
                         (COUNTER_TABLE, {"aggregate_id": COUNTER_ID}, "UPDATE"))
        self.assertEqual(counter["expectedRow"], counter_row(live_count=99_998, active_count=99_998))
        elapsed = self.now - datetime(1970, 1, 1, tzinfo=timezone.utc)
        now_ns = (elapsed.days * 86400 + elapsed.seconds) * 1_000_000_000
        self.assertEqual(counter["row"], counter_row(revision=8, live_count=100_000,
            active_count=100_000, next_sequence=21, updated_at_epoch_ns=now_ns))
        self.assertEqual(sum(item["table"] == "metadata_audit_outbox" for item in mutations), 2)
        self.assertEqual((context.arguments, context.selected_rows, context.verified_webauthn_evidence), before)

    def test_shared_capacity_overflow_denies_complete_batch_without_changing_inputs(self) -> None:
        for outstanding in (99_999, 100_000):
            with self.subTest(outstanding=outstanding):
                context = self.with_capacity(self.context(), live_count=outstanding, active_count=outstanding)
                before = copy.deepcopy(context.selected_rows)
                business = self.kernel.transition(context)
                self.assertEqual(sum(item["table"] == "metadata_audit_outbox" for item in business.mutations), 2)
                with self.assertRaisesRegex(capacity.AuditCapacityError, "transition exceeds"):
                    self.composed(context)
                self.assertEqual(context.selected_rows, before)

    def test_shared_capacity_optional_audit_absence_does_not_remove_per_approval_charge(self) -> None:
        context = self.context()
        omitted = candidate.audit_id(candidate.OPERATION, self.request_digest, None)
        context = replace(context, arguments=self.arguments({**self.values, "audit_event": None}),
            selected_rows=tuple(item for item in context.selected_rows
                if not (item["table"] == "metadata_audit_outbox" and item["key"] == {"id": omitted})))
        _, business, mutations, _ = self.composed(self.with_capacity(context, live_count=99_999, active_count=99_999))
        audits = [item for item in business.mutations if item["table"] == "metadata_audit_outbox"]
        self.assertEqual(len(audits), 1)
        self.assertEqual(audits[0]["row"]["event_type"], "control_plane.approval.invalidated")
        self.assertEqual((mutations[-1]["row"]["live_count"], mutations[-1]["row"]["next_sequence"]), (100_000, 20))
        occupied = self.with_capacity(context)
        audit = next(item for item in occupied.selected_rows if item["table"] == "metadata_audit_outbox")
        audit.update(present=True, row={"id": audit["key"]["id"], "status": "audited"})
        before = copy.deepcopy(occupied.selected_rows)
        with self.assertRaisesRegex(core.TransitionKernelError, "audit identity"):
            self.composed(occupied)
        self.assertEqual(occupied.selected_rows, before)

    def test_shared_capacity_no_audit_cascade_still_requires_baseline_without_counter_write(self) -> None:
        context = self.context()
        values = {**self.values, "audit_event": None, "control_plane_approval_ids": []}
        context = replace(context, arguments=self.arguments(values), selected_rows=tuple(
            item for item in context.selected_rows
            if item["table"] not in {"control_plane_approvals", "metadata_audit_outbox"}))
        complete = self.with_capacity(context, live_count=100_000, active_count=100_000)
        queries, business, mutations, work = self.composed(complete)
        self.assertEqual((len(business.mutations), len(mutations), work), (6, 6, 55))
        self.assertEqual(mutations, business.mutations)
        self.assertEqual(sum(query.table == COUNTER_TABLE for query in queries), 1)
        self.assertFalse(any(item["table"] in {COUNTER_TABLE, "metadata_audit_outbox"} for item in mutations))
        with self.assertRaises(capacity.AuditCapacityError):
            self.composed(context)

    def test_shared_capacity_missing_absent_duplicate_and_malformed_counter_deny(self) -> None:
        malformed = counter_row()
        malformed["state_digest"] = digest(b"altered compact state")
        variants = (
            (), (counter_selected(None),),
            (counter_selected(counter_row()), counter_selected(counter_row())),
            (counter_selected(counter_row(capacity_limit=99_999)),),
            (counter_selected(counter_row(active_count=1)),),
            (counter_selected(counter_row(reserved_units_json='{"operation":1}')),),
            (counter_selected(counter_row(source_revision="retired-source")),),
            (counter_selected(malformed),),
        )
        for index, extra in enumerate(variants):
            context = self.context()
            context = replace(context, selected_rows=(*context.selected_rows, *extra))
            before = copy.deepcopy(context.selected_rows)
            with self.subTest(index=index), self.assertRaises(capacity.AuditCapacityError):
                self.composed(context)
            self.assertEqual(context.selected_rows, before)

    def test_shared_capacity_old_cas_future_time_and_forged_delta_are_rejected(self) -> None:
        context = self.with_capacity(self.context())
        _, _, mutations, _ = self.composed(context)
        newer = self.with_capacity(self.context(), revision=8)
        with self.assertRaises(capacity.AuditCapacityError):
            capacity.validate_capacity_transition(operation=candidate.OPERATION,
                selected_rows=newer.selected_rows, mutations=mutations)
        elapsed = self.now - datetime(1970, 1, 1, tzinfo=timezone.utc)
        now_ns = (elapsed.days * 86400 + elapsed.seconds) * 1_000_000_000
        with self.assertRaisesRegex(capacity.AuditCapacityError, "update time"):
            self.composed(self.with_capacity(self.context(), updated_at_epoch_ns=now_ns + 1))
        forged = copy.deepcopy(mutations)
        forged[-1]["row"] = counter_row(revision=8, live_count=1, active_count=1,
            next_sequence=20, updated_at_epoch_ns=now_ns)
        with self.assertRaises(capacity.AuditCapacityError):
            capacity.validate_capacity_transition(operation=candidate.OPERATION,
                selected_rows=context.selected_rows, mutations=forged)

    def test_business_budget_reserves_counter_slot_and_does_not_spend_framework_credit(self) -> None:
        spec = authority_contract.operation_spec(candidate.OPERATION)
        self.assertEqual((spec["maximumBusinessQueryRows"], spec["maximumBusinessMutations"],
                          spec["maximumBusinessWorkUnits"]), (192, 136, 2048))
        self.assertEqual((spec["maximumQueryRows"], spec["maximumMutations"], spec["maximumWorkUnits"]),
                         (193, 137, 2050))
        values = copy.deepcopy(self.values)
        for field, count in (("oidc_session_ids", 32), ("approval_grant_ids", 32),
                             ("control_plane_approval_ids", 20), ("registration_challenge_ids", 28)):
            values[field] = [f"{field}-{index:02d}" for index in range(count)]
        self.assertEqual(candidate.prepare_revocation_input(values), values)
        evidence = self.context(separate_signer=True).verified_webauthn_evidence
        queries = self.kernel.queries_with_evidence(arguments=self.arguments(values), database_now=self.now,
            request_digest=self.request_digest, evidence=evidence)
        self.assertEqual(sum(query.maximum_rows for query in queries), 171)
        self.assertEqual(sum(query.maximum_rows for query in capacity.add_capacity_query(candidate.OPERATION, queries)), 172)
        values["registration_challenge_ids"].append("registration_challenge_ids-28")
        with self.assertRaisesRegex(core.TransitionKernelError, "aggregate mutation bound"):
            candidate.prepare_revocation_input(values)

    def test_exact_framework_row_is_outside_business_row_and_kernel_work_allowance(self) -> None:
        context = self.context()
        business = self.kernel.transition(context)
        with_counter = self.with_capacity(context)
        self.assertEqual(self.kernel.transition(with_counter), business)
        # Synthetic selected-envelope accounting only; these extra rows do not
        # claim to be produced by this candidate's real query predicates.
        padding = tuple(selected("metadata_audit_outbox", f"unused-{index}", {
            "id": f"unused-{index}", "status": "audited",
        }) for index in range(192 - len(context.selected_rows)))
        boundary = replace(with_counter, selected_rows=(*with_counter.selected_rows, *padding))
        bounded = self.kernel.transition(boundary)
        capacity.finalize_capacity(boundary, bounded.mutations)
        extra = selected("metadata_audit_outbox", "one-too-many", {"id": "one-too-many", "status": "audited"})
        with self.assertRaisesRegex(core.TransitionKernelError, "aggregate plan"):
            self.kernel.transition(replace(boundary, selected_rows=(*boundary.selected_rows, extra)))

    def test_candidate_is_not_registered_or_presented_as_startup_closure(self) -> None:
        registry_source = (ROOT / "catchplate/authority_transition_registry.py").read_text()
        policy_source = (ROOT / "catchplate/authority_transition_policy.py").read_text()
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
