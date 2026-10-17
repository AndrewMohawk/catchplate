"""Terminal JIT denial from original facade arguments and verified v9 evidence.

One eligible actor can deny regardless of the approval threshold. A denial
consumes its exact review and assertion, never creates a vote or grant, and
retains the admitted raw receipt through the independent writer framework.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timezone

from catchplate import authority_transition_core as core
from catchplate import authority_transition_jit_approval as approval_owner
from catchplate import authority_transition_quota as shared
from catchplate import authority_transition_webauthn as assertions

OPERATION = "jit.deny"
FIELDS = frozenset({"item_id", "note", "actor_id", "authn", "challenge_id",
    "review_receipt_id", "review_digest", "require_review_receipt", "required_approver_roles",
    "authority_policy_hash", "authority_route_id", "allowed_approver_ids",
    "require_approver_webauthn", "approval_threshold", "approver_credential_policy"})
AUTHN_SCHEMA = "catchplate.jitDenialAuthnReceipt/v3"
_require = approval_owner._require


def arguments(original):
    shared._exact_arguments(original, required=FIELDS)
    values = dict(original)
    for name in ("item_id", "actor_id", "challenge_id"):
        core.require_text(values[name], "JIT denial " + name, maximum_bytes=512)
    if values["note"] is not None:
        core.require_text(values["note"], "JIT denial note", maximum_bytes=500, allow_empty=True)
    _require(values["require_review_receipt"] is True, "JIT denial requires its original review")
    core.require_text(values["review_receipt_id"], "JIT denial review receipt", maximum_bytes=256)
    core.require_digest(values["review_digest"], "JIT denial review digest")
    for name in ("required_approver_roles", "allowed_approver_ids"):
        item = values[name]
        if item is not None:
            _require(isinstance(item, Mapping) and set(item) == {"$authorityType", "items"}
                and item["$authorityType"] == "set" and type(item["items"]) is list,
                "JIT denial policy set is not the original facade representation")
            _require(all(type(member) is str for member in item["items"])
                and item["items"] == sorted(set(item["items"])), "JIT denial policy set is not canonical")
    authn = values["authn"]
    _require(isinstance(authn, Mapping) and set(authn) == {"assertion", "credential_id"}
        and isinstance(authn["assertion"], Mapping), "JIT denial raw assertion input is not closed")
    core.require_text(authn["credential_id"], "JIT denial browser credential", maximum_bytes=4096)
    return values


_arguments = arguments


@dataclass(frozen=True, slots=True)
class JitDenyKernel:
    operation: str = OPERATION
    handler: str = "deny_request"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(OPERATION, "deny_request")

    def queries(self, **kwargs):
        raise core.TransitionKernelError("JIT denial requires independently verified raw assertion evidence")

    def queries_with_evidence(self, *, arguments: Mapping, database_now, request_digest, evidence):
        del database_now
        values = _arguments(arguments)
        core.require_digest(request_digest, "JIT denial authority request")
        item_id, actor = values["item_id"], values["actor_id"]
        queries = [shared._query(operation=OPERATION, name=name, table=table, key=key) for name, table, key in (
            ("approval", "approval_requests", {"id": item_id}),
            ("grant", "approval_grants", {"id": "approval:" + item_id}),
            ("policy_high_water", "policy_high_water", {"scope": "global"}),
            ("actor_hardware", "webauthn_credentials", {"id": evidence["credentialRecordId"]}),
            ("actor_challenge", "webauthn_challenges", {"id": evidence["challengeId"]}),
            ("review_receipt", "approval_review_receipts", {"id": values["review_receipt_id"]}))]
        queries += [shared._role_query(OPERATION, "denier_role", actor),
            *assertions._trust_queries(OPERATION, work=None), shared._audit_query(OPERATION, request_digest)]
        return tuple(queries)

    def transition(self, context):
        values = arguments(context.arguments)
        item_id, actor = values["item_id"], values["actor_id"]
        selected = context.exact("approval_requests", {"id": item_id})
        approval = shared._row(selected, "JIT denial approval")
        approval_owner._require_legacy_decision(approval)
        policy, policy_digest = approval_owner._policy(context, values, approval)
        _require(approval["status"] in {"pending", "denied"}, "JIT denial approval is terminal")
        replay = approval["status"] == "denied"
        _require(replay or approval_owner._time(approval["expires_at"]) > context.database_now,
            "JIT denial pending approval expired")
        _, grant = shared._selected_or_none(context, "approval_grants", {"id": "approval:" + item_id})
        _require(grant is None and approval.get("approved_until") is None,
            "JIT denial cannot coexist with a grant")
        _require(all(approval.get(name) is not None for name in ("principal_id", "route_id", "credential_id",
            "credential_version", "policy_hash", "request_digest")), "JIT denial scope is incomplete")
        core.require_digest(approval["request_digest"], "JIT denied request")
        evidence, _receipt, receipt_digest, assertion_mutations = approval_owner._assertion(
            context, values, policy, replay=replay)
        authn = {"schema": AUTHN_SCHEMA, "approverPolicyDigest": policy_digest,
            "verifiedAssertionReceiptDigest": receipt_digest, "authorityCapabilityId": evidence["capabilityId"],
            "authorityRequestDigest": context.request_digest, "reviewReceiptId": values["review_receipt_id"],
            "reviewDigest": values["review_digest"]}
        authn_json = core.canonical_bytes(authn).decode("ascii")
        review_selected = context.exact("approval_review_receipts", {"id": values["review_receipt_id"]})
        review = shared._row(review_selected, "JIT denial original review")
        _require(review["approval_request_id"] == item_id and review["reviewer_id"] == actor
            and review["review_digest"] == values["review_digest"], "JIT denial review binding changed")
        mutations = list(assertion_mutations)
        if replay:
            _require(approval["approved_by"] == actor and approval["decision_note"] == values["note"]
                and approval["approval_authn"] == authn_json
                and approval["approver_webauthn_credential_id"] == evidence["credentialRecordId"]
                and approval["verified_assertion_receipt_digest"] == receipt_digest
                and approval["approval_challenge_id"] == evidence["challengeId"],
                "JIT denial replay conflicts with its original decision")
            audit = shared._row(context.exact("metadata_audit_outbox",
                {"id": shared._audit_identity(OPERATION, context.request_digest)}), "JIT denial original audit")
            challenge = shared._row(context.exact("webauthn_challenges",
                {"id": evidence["challengeId"]}), "JIT denial original challenge")
            _require(review["used_at"] == challenge["used_at"] == audit["created_at"]
                and review["used_at"] is not None, "JIT denial replay use timestamps changed")
            result = approval
        else:
            _require(review["used_at"] is None
                and approval_owner._time(review["expires_at"]) > context.database_now,
                "JIT denial review is not live and unused")
            now_s = context.database_now.astimezone(timezone.utc).isoformat()
            result = {**approval, "status": "denied", "decision_note": values["note"], "approved_by": actor,
                "approval_authn": authn_json, "approver_webauthn_credential_id": evidence["credentialRecordId"],
                "verified_assertion_receipt_digest": receipt_digest, "approval_challenge_id": evidence["challengeId"]}
            mutations += [core.mutation(operation=OPERATION, selected=review_selected,
                row={**review, "used_at": now_s}), core.mutation(operation=OPERATION, selected=selected, row=result)]
        event = {"schema": "catchplate.jitApprovalDenied/v3", "approvalRequestId": item_id,
            "routeId": approval["route_id"], "principalId": approval["principal_id"],
            "credentialId": approval["credential_id"], "credentialVersion": approval["credential_version"],
            "policyHash": approval["policy_hash"], "requestDigest": approval["request_digest"],
            "operationDigest": approval.get("operation_digest"), "approverPolicyDigest": policy_digest,
            "verifiedAssertionReceiptDigest": receipt_digest,
            "verifiedEvidenceDigest": evidence["verifiedAssertionReceiptDigest"],
            "authorityCapabilityId": evidence["capabilityId"], "authorityRequestDigest": context.request_digest,
            "reviewReceiptId": values["review_receipt_id"], "reviewDigest": values["review_digest"], "note": values["note"]}
        audit_mutations, audit_digest, audit_replay = shared._audit_mutations(context,
            event_type="approval.denied", actor_type="admin", actor_id=actor, event=event)
        _require(replay == audit_replay, "JIT denial lost its audit replay")
        mutations.extend(audit_mutations)
        return core.KernelTransition(mutations=tuple(mutations), result={**shared._jit_public(result),
            "audit_event_digest": audit_digest, "idempotent_replay": replay}, work_units=64 + len(mutations))
