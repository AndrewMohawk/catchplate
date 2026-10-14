"""Current JIT approval: original facade arguments and verified v9 assertions.

The planner proposes business mutations, never an approved framework receipt.
The writer independently retains the authentic capability receipt and vetoes
incomplete or no-longer-current prior voter histories in the same transaction.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Mapping

from serverware import authority_contract as contract
from serverware import authority_approver_policy as policies
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as shared
from serverware import authority_transition_webauthn as assertions
from serverware import authority_webauthn_bindings as bindings

OPERATION = "jit.decide"
FIELDS = frozenset({"item_id", "ttl_seconds", "note", "actor_id", "authn", "challenge_id",
    "review_receipt_id", "review_digest", "require_review_receipt", "required_approver_roles",
    "authority_policy_hash", "authority_route_id", "allowed_approver_ids",
    "require_approver_webauthn", "approval_threshold", "approver_credential_policy"})
MAX_DECISIONS = 16
# Exact original SQL projections in AuthorityProcess._read_webauthn_authority.
CHALLENGE_FIELDS = bindings.CHALLENGE_FIELDS
CREDENTIAL_FIELDS = bindings.CREDENTIAL_FIELDS


def _require(condition, message):
    if not condition:
        raise core.TransitionKernelError(message)


def _require_legacy_decision(approval):
    # Opening authorization is not native decision/continuation authority.
    # Match the complete reserved family used by the legacy receipt guard,
    # without parsing, decrypting or normalizing any stored private document.
    for field in ("url", "canonical_request", "redacted_display"):
        value = approval.get(field)
        _require(type(value) is str and value.lstrip()[:10].lower() != "native-jit",
            "Native JIT decisions require their continuation authority")


def _time(value):
    _require(type(value) is str, "JIT timestamp is not an original SQL value")
    try:
        result = datetime.fromisoformat(value)
    except ValueError as exc:
        raise core.TransitionKernelError("JIT timestamp is invalid") from exc
    _require(result.tzinfo is not None and result.utcoffset() == timedelta(0),
        "JIT timestamp is not UTC")
    return result


def arguments(original):
    shared._exact_arguments(original, required=FIELDS)
    values = dict(original)
    for name in ("item_id", "actor_id", "challenge_id"):
        core.require_text(values[name], "JIT " + name, maximum_bytes=512)
    core.require_integer(values["ttl_seconds"], "JIT requested TTL", minimum=1, maximum=3600)
    if values["note"] is not None:
        core.require_text(values["note"], "JIT note", maximum_bytes=500, allow_empty=True)
    _require(type(values["require_review_receipt"]) is bool, "JIT review mode is invalid")
    if values["require_review_receipt"]:
        core.require_text(values["review_receipt_id"], "JIT review receipt", maximum_bytes=256)
        core.require_digest(values["review_digest"], "JIT review digest")
    else:
        _require(values["review_receipt_id"] is None and values["review_digest"] is None,
            "JIT review evidence exceeds its mode")
    for name in ("required_approver_roles", "allowed_approver_ids"):
        item = values[name]
        if item is not None:
            _require(isinstance(item, Mapping) and set(item) == {"$authorityType", "items"}
                and item["$authorityType"] == "set" and type(item["items"]) is list,
                "JIT policy set is not the original facade representation")
            _require(all(type(member) is str for member in item["items"])
                and item["items"] == sorted(set(item["items"])), "JIT policy set is not canonical")
    authn = values["authn"]
    _require(isinstance(authn, Mapping) and set(authn) == {"assertion", "credential_id"}
        and isinstance(authn["assertion"], Mapping), "JIT raw assertion input is not closed")
    core.require_text(authn["credential_id"], "JIT browser credential", maximum_bytes=4096)
    return values


_arguments = arguments


def raw_receipt_from_originals(evidence, challenge, credential):
    """Recompute the producer's original receipt, not the signed-evidence hash.

    This projection is not assertion verification. The caller must already hold
    independently verified evidence and authenticated original selected rows;
    the writer compares the digest against its actual capability original.
    """
    challenge_original = {name: challenge[name] for name in CHALLENGE_FIELDS}
    credential_original = {name: credential[name] for name in CREDENTIAL_FIELDS}
    fields = ("operationId", "challengeDigest", "challengeId", "credentialRecordId",
        "credentialId", "credentialPolicyDigest", "trustHighWaterDigest", "clientDataJSONDigest",
        "authenticatorDataDigest", "signatureDigest", "flags", "priorCounter", "counter",
        "userPresent", "userVerified", "verifiedAtEpochNs")
    receipt = {"schema": "serverware.policyAuthorityWebAuthnReceipt/v1",
        **{name: evidence[name] for name in fields},
        "challengeRowDigest": bindings.challenge_row_digest(challenge_original),
        "credentialBindingDigest": bindings.credential_binding_digest(credential_original)}
    return receipt, core.framed_digest(receipt["schema"], core.canonical_bytes(receipt))


def _policy(context, values, approval):
    policy, digest = shared._stored_jit_policy(approval)
    try:
        authority_digest = policies.from_jit_policy(policy)
    except ValueError as exc:
        raise core.TransitionKernelError("JIT stored policy is not canonical") from exc
    _require(policies.digest(values) == authority_digest, "JIT caller policy differs from stored policy")
    _require(values["authority_policy_hash"] == approval["policy_hash"]
        and values["authority_route_id"] == approval["route_id"], "JIT caller scope changed")
    actor = values["actor_id"]
    _require(policy["allowAnyApproverId"] or actor in policy["allowedApproverIds"],
        "JIT actor is outside the exact approver set")
    roles = policy["requiredRoles"]
    if roles:
        _require(actor.startswith("oidc:"), "JIT approver role requires its OIDC identity")
        binding = shared._row(context.exact("rbac_role_bindings", {"subject_id": actor}), "JIT current roles")
        raw = binding["roles_json"]
        try:
            actual = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise core.TransitionKernelError("JIT current roles are invalid") from exc
        _require(core.canonical_bytes(actual).decode("ascii") == raw and type(actual) is list
            and all(type(role) is str for role in actual) and binding["status"] == "active"
            and bool(set(roles).intersection(actual)), "JIT current roles do not satisfy any required role")
    high_water = shared._row(context.exact("policy_high_water", {"scope": "global"}), "JIT current policy")
    _require(high_water["policy_hash"] == approval["policy_hash"], "JIT policy is no longer current")
    return policy, digest


def _assertion(context, values, policy, *, replay):
    operation = context.operation
    _require(operation in {OPERATION, "jit.deny"}, "JIT assertion operation is not admitted")
    evidence = context.verified_webauthn_evidence
    _require(isinstance(evidence, Mapping), "JIT requires independently verified assertion evidence")
    credential = shared._row(context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]}),
        "JIT current credential")
    challenge = shared._row(context.exact("webauthn_challenges", {"id": evidence["challengeId"]}),
        "JIT current challenge")
    raw = values["authn"]["assertion"]
    response = raw.get("response", raw)
    _require(isinstance(response, Mapping) and values["authn"]["credential_id"] == evidence["credentialId"]
        and raw.get("id", raw.get("rawId", raw.get("credentialId"))) == evidence["credentialId"]
        and values["challenge_id"] == evidence["challengeId"]
        and all(response.get(source) == evidence[target] for source, target in (
            ("authenticatorData", "authenticatorDataBase64url"), ("clientDataJSON", "clientDataJSONBase64url"),
            ("signature", "signatureBase64url"))), "JIT raw assertion differs from verified original")
    current = policy["credentialPolicy"]
    now = shared._database_epoch_ns(context.database_now)
    payload = shared._canonical_stored_mapping(challenge["payload_json"], "JIT assertion challenge")
    issued = core.require_integer(payload.get("issuedAtEpochNs"), "JIT challenge issuance", minimum=0, maximum=2**63-1)
    _require(credential["user_id"] == challenge["user_id"] == values["actor_id"]
        and credential["revoked_at"] is None and evidence["userPresent"] is True and evidence["userVerified"] is True
        and credential["authenticator_class"] in current["allowedAuthenticatorClasses"]
        and (not current["allowedCredentialRecordIds"] or credential["id"] in current["allowedCredentialRecordIds"])
        and (not current["allowedAaguids"] or credential["aaguid"] in current["allowedAaguids"])
        and (not current["requireAttestationTrusted"] or credential["attestation_trusted"] in (1, True))
        and (current["requiredTrustBundleDigest"] is None
            or credential["attestation_trust_bundle_digest"] == current["requiredTrustBundleDigest"])
        and (current["minimumTrustBundleSequence"] is None
            or credential["attestation_trust_bundle_sequence"] >= current["minimumTrustBundleSequence"])
        and evidence["rpId"] == current["rpId"] and evidence["origin"] in current["origins"]
        and issued <= evidence["verifiedAtEpochNs"] <= now < evidence["expiresAtEpochNs"]
        and now - issued <= current["maxAssertionAgeSeconds"] * 1_000_000_000,
        "JIT current hardware, actor or original assertion deadline changed")
    if not replay:
        mutations = assertions._assertion_mutations(context, {"actor_id": values["actor_id"]})
        receipt, digest = raw_receipt_from_originals(evidence, challenge, credential)
        return evidence, receipt, digest, mutations
    # An exact retained decision may be observed again, never consume a second
    # counter or renew a grant. Reconstruct only fields changed by that original
    # assertion, then check its exact retained receipt below and current trust.
    _require(challenge["used_at"] is not None and credential["sign_count"] >= evidence["counter"],
        "JIT replay lacks its consumed original assertion")
    original_challenge = {**challenge, "used_at": None}
    original_credential = {**credential, "sign_count": evidence["priorCounter"]}
    operation_id = core.framed_digest("serverware.policyAuthorityOperation/v2", operation.encode("ascii"),
        context.request_digest.encode("ascii"))
    public_challenge = {**payload, "challengeId": challenge["id"], "challenge": challenge["challenge"],
        "challengeRowDigest": assertions._challenge_row_digest(original_challenge, work=None)}
    _require(evidence["operation"] == operation and evidence["operationId"] == operation_id
        and evidence["requestDigest"] == context.request_digest
        and challenge["challenge_type"] == "policy_authority" and challenge["scope_key"] == operation_id
        and evidence["challengeDigest"] == assertions._challenge_public_digest(public_challenge, work=None),
        "JIT replay original challenge binding changed")
    assertions._assertion_trust(context, credential, evidence, work=None)
    receipt, digest = raw_receipt_from_originals(evidence, original_challenge, original_credential)
    return evidence, receipt, digest, ()


def _prior(context, item_id, policy_digest):
    selected = context.present_rows("approval_request_decisions")
    rows = [shared._row(item, "JIT prior decision") for item in selected]
    actors = [row["approver_id"] for row in rows]
    _require(len(rows) <= MAX_DECISIONS and len(set(actors)) == len(actors)
        and all(row["approval_request_id"] == item_id and row["decision"] == "approved"
            and row["approver_policy_digest"] == policy_digest for row in rows),
        "JIT prior decision roster is not exact")
    aggregate_id, partition = shared._aggregate_key("jit-approval-decisions", item_id)
    aggregate_selected = context.exact("policy_authority_bounded_aggregate_states", {"aggregate_id": aggregate_id})
    if aggregate_selected["present"]:
        aggregate = context.bounded_aggregate(aggregate_id=aggregate_id, aggregate_kind="jit-approval-decisions",
            partition_digest=partition)
        _require(aggregate["live_count"] == aggregate["active_count"] == len(rows)
            and aggregate["capacity_limit"] == MAX_DECISIONS, "JIT complete prior roster count changed")
    else:
        _require(not rows, "JIT absent decision aggregate has prior voters")
    # The framework additionally compares this roster with the actual locked
    # partition and revalidates every history; a LIMIT result is not absence.
    return rows, aggregate_selected


def _add_vote(context, item_id, selected):
    if selected["present"]:
        return shared._aggregate_update(context, kind="jit-approval-decisions", partition=item_id,
            live_delta=1, active_delta=1, next_sequence_delta=1)
    aggregate_id, partition = shared._aggregate_key("jit-approval-decisions", item_id)
    row = {"aggregate_id": aggregate_id, "aggregate_kind": "jit-approval-decisions", "partition_digest": partition,
        "revision": 1, "live_count": 1, "active_count": 1, "capacity_limit": MAX_DECISIONS,
        "reserved_units_json": "{}", "committed_units_json": "{}", "next_sequence": 1,
        "minimum_expiry_epoch_ns": None, "expiry_index_root_digest": shared._EMPTY_DIGEST,
        "work_page_id": None, "updated_at_epoch_ns": shared._database_epoch_ns(context.database_now),
        "source_revision": contract.SOURCE_REVISION}
    material = core._aggregate_state_material(row, reserved_units={}, committed_units={})
    row["state_json"] = core.canonical_bytes(material).decode("ascii")
    row["state_digest"] = core.framed_digest("serverware.policyAuthorityAggregateState/v1", core.canonical_bytes(material))
    return core.mutation(operation=OPERATION, selected=selected, row=row)


@dataclass(frozen=True, slots=True)
class JitDecideKernel:
    operation: str = OPERATION
    handler: str = "approve_request"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(OPERATION, "approve_request")

    def queries(self, **kwargs):
        raise core.TransitionKernelError("JIT approval requires independently verified raw assertion evidence")

    def queries_with_evidence(self, *, arguments: Mapping, database_now, request_digest, evidence):
        del database_now
        values = _arguments(arguments)
        item_id, actor = values["item_id"], values["actor_id"]
        queries = [shared._query(operation=OPERATION, name=name, table=table, key=key) for name, table, key in (
            ("approval", "approval_requests", {"id": item_id}),
            ("decision", "approval_request_decisions", {"approval_request_id": item_id, "approver_id": actor}),
            ("grant", "approval_grants", {"id": "approval:" + item_id}),
            ("policy_high_water", "policy_high_water", {"scope": "global"}),
            ("actor_hardware", "webauthn_credentials", {"id": evidence["credentialRecordId"]}),
            ("actor_challenge", "webauthn_challenges", {"id": evidence["challengeId"]}))]
        queries += [shared._role_query(OPERATION, "approver_role", actor),
            shared._aggregate_query(OPERATION, "decision_capacity", "jit-approval-decisions", item_id),
            core.BoundedQuery(query_id=core.query_program_id(OPERATION, "prior_decisions", "approval_request_decisions"),
                table="approval_request_decisions", predicates=(core.QueryPredicate("approval_request_id", "eq", item_id),),
                order_by=(core.QueryOrder("approver_id"),), maximum_rows=MAX_DECISIONS),
            *assertions._trust_queries(OPERATION, work=None), shared._audit_query(OPERATION, request_digest)]
        if values["require_review_receipt"]:
            queries.append(shared._query(operation=OPERATION, name="review_receipt", table="approval_review_receipts",
                key={"id": values["review_receipt_id"]}))
        return tuple(queries)

    def transition(self, context):
        values = arguments(context.arguments)
        item_id, actor = values["item_id"], values["actor_id"]
        approval_selected = context.exact("approval_requests", {"id": item_id})
        approval = shared._row(approval_selected, "JIT approval")
        _require_legacy_decision(approval)
        policy, policy_digest = _policy(context, values, approval)
        _require(approval["status"] in {"pending", "approved"}, "JIT approval is terminal")
        _require(approval["status"] != "pending" or _time(approval["expires_at"]) > context.database_now,
            "JIT pending approval expired")
        _require(all(approval.get(name) is not None for name in ("principal_id", "route_id", "credential_id",
            "credential_version", "policy_hash", "request_digest")), "JIT grant scope is incomplete")
        core.require_digest(approval["request_digest"], "JIT approved request")
        prior, aggregate = _prior(context, item_id, policy_digest)
        decision_selected, decision = shared._selected_or_none(context, "approval_request_decisions",
            {"approval_request_id": item_id, "approver_id": actor})
        replay = decision is not None
        evidence, receipt, receipt_digest, assertion_mutations = _assertion(context, values, policy, replay=replay)
        immutable = {"approval_request_id": item_id, "approver_id": actor, "approver_policy_digest": policy_digest,
            "verified_assertion_receipt_digest": receipt_digest, "authority_capability_id": evidence["capabilityId"],
            "authority_request_digest": context.request_digest, "review_receipt_id": values["review_receipt_id"],
            "review_digest": values["review_digest"], "require_review_receipt": int(values["require_review_receipt"]),
            "decision": "approved", "decision_note": values["note"]}
        grant_id = "approval:" + item_id
        grant_selected, grant = shared._selected_or_none(context, "approval_grants", {"id": grant_id})
        now_s = context.database_now.astimezone(timezone.utc).isoformat()
        mutations = list(assertion_mutations)
        if replay:
            _require(all(decision.get(name) == value for name, value in immutable.items()), "JIT decision replay conflicts")
            if values["require_review_receipt"]:
                review = shared._row(context.exact("approval_review_receipts",
                    {"id": values["review_receipt_id"]}), "JIT original review")
                _require(review["approval_request_id"] == item_id and review["reviewer_id"] == actor
                    and review["review_digest"] == values["review_digest"]
                    and review["used_at"] == decision["created_at"], "JIT replay review binding changed")
        else:
            _require(approval["status"] == "pending" and _time(approval["expires_at"]) > context.database_now
                and len(prior) < policy["threshold"] and grant is None, "JIT approval is not live and pending")
            if values["require_review_receipt"]:
                selected = context.exact("approval_review_receipts", {"id": values["review_receipt_id"]})
                review = shared._row(selected, "JIT review receipt")
                _require(review["approval_request_id"] == item_id and review["reviewer_id"] == actor
                    and review["review_digest"] == values["review_digest"] and review["used_at"] is None
                    and _time(review["expires_at"]) > context.database_now, "JIT review receipt is not current")
                mutations.append(core.mutation(operation=OPERATION, selected=selected, row={**review, "used_at": now_s}))
            mutations += [core.mutation(operation=OPERATION, selected=decision_selected,
                row={**immutable, "created_at": now_s}), _add_vote(context, item_id, aggregate)]
        count = len(prior) + (0 if replay else 1)
        reached = count >= policy["threshold"]
        result = approval
        if reached and not replay:
            ttl = core.require_integer(approval["grant_ttl_seconds"], "JIT stored TTL", minimum=1, maximum=3600)
            uses = core.require_integer(approval["grant_max_uses"], "JIT stored uses", minimum=1, maximum=1_000_000)
            expiry = (context.database_now + timedelta(seconds=ttl)).isoformat()
            authn = {"schema": "serverware.jitApprovalAuthnReceipt/v1", "approverPolicyDigest": policy_digest,
                "verifiedAssertionReceiptDigest": receipt_digest}
            result = {**approval, "status": "approved", "approved_until": expiry, "decision_note": values["note"],
                "approved_by": actor, "approval_authn": core.canonical_bytes(authn).decode("ascii"),
                "approver_webauthn_credential_id": evidence["credentialRecordId"],
                "verified_assertion_receipt_digest": receipt_digest, "approval_challenge_id": evidence["challengeId"]}
            grant_row = {"id": grant_id, "approval_request_id": item_id, "state": "active",
                **{name: approval[name] for name in ("principal_id", "route_id", "credential_id", "credential_version",
                    "policy_hash", "request_digest", "operation_digest", "approver_policy_json", "approver_policy_digest")},
                "approver_webauthn_credential_id": evidence["credentialRecordId"], "verified_assertion_receipt_digest": receipt_digest,
                "uses_remaining": uses, "valid_from": now_s, "expires_at": expiry, "consumed_at": None,
                "consumed_by_flow_id": None, "reserved_attempt_id": None, "reserved_at_epoch_ms": None,
                "reservation_expires_at_epoch_ms": None, "created_at": now_s, "updated_at": now_s}
            mutations += [core.mutation(operation=OPERATION, selected=approval_selected, row=result),
                core.mutation(operation=OPERATION, selected=grant_selected, row=grant_row)]
        elif replay:
            _require((reached and approval["status"] == "approved" and grant is not None)
                or (not reached and approval["status"] == "pending" and grant is None), "JIT replay grant state changed")
            if grant is not None:
                _require(grant["approval_request_id"] == item_id
                    and all(grant[name] == approval[name] for name in ("principal_id", "route_id", "credential_id",
                        "credential_version", "policy_hash", "request_digest", "operation_digest",
                        "approver_policy_json", "approver_policy_digest", "verified_assertion_receipt_digest"))
                    and grant["expires_at"] == approval["approved_until"], "JIT replay grant scope changed")
        elif grant is not None:
            raise core.TransitionKernelError("JIT grant exists before its threshold")
        event = {"schema": "serverware.jitApprovalDecision/v3", "approvalRequestId": item_id,
            "approverPolicyDigest": policy_digest, "approverThreshold": policy["threshold"], "decisionCount": count,
            "thresholdReached": reached, "verifiedAssertionReceiptDigest": receipt_digest,
            "verifiedEvidenceDigest": evidence["verifiedAssertionReceiptDigest"],
            "reviewReceiptId": values["review_receipt_id"], "reviewDigest": values["review_digest"], "note": values["note"]}
        if replay:
            audit = shared._row(context.exact("metadata_audit_outbox", {"id": shared._audit_identity(OPERATION,
                context.request_digest)}), "JIT original audit")
            original = shared._canonical_stored_mapping(audit["event_json"], "JIT original event")
            _require(set(original) == set(event) and all(original[name] == value for name, value in event.items()
                if name not in {"decisionCount", "thresholdReached"}) and type(original["decisionCount"]) is int
                and 1 <= original["decisionCount"] <= count
                and original["thresholdReached"] is (original["decisionCount"] >= policy["threshold"]),
                "JIT replay audit differs from original decision")
            event = original
        audit_mutations, audit_digest, audit_replay = shared._audit_mutations(context,
            event_type="approval.decision_recorded", actor_type="admin", actor_id=actor, event=event)
        _require(audit_replay == replay, "JIT decision lost its audit replay")
        mutations.extend(audit_mutations)
        return core.KernelTransition(mutations=tuple(mutations), result={**shared._jit_public(result),
            "approver_policy": policy, "decision_count": count, "threshold_reached": reached,
            "grant_id": grant_id if reached else None, "audit_event_digest": audit_digest, "idempotent_replay": replay},
            work_units=96 + 4 * len(prior) + len(mutations))
