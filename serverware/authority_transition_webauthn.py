"""UNREGISTERED candidate for bounded explicit self-revocation.

Address lists are signed hints, never row-selection authority. The measured
planner queries the complete live predicates, including GLOBAL registration
challenges, and rejects overflow. Audits use exact absent keys. Capacity uses
complete pending/claimed outbox reads, not an unmaintained aggregate counter.
Consequently a busy outbox can deny this bounded operation well below its
legacy 100,000-row capacity. The old aggregate HTTP route remains unchanged.

The current reader's measured SQL predicates and LIMIT+1 provide completeness
only if PostgreSQL query semantics are trusted. Selected-row membership proofs
do not prove predicate completeness against a malicious database. Therefore
this kernel is deliberately NOT registered, pending authenticated predicate /
secondary-index completeness integration. Four startup gaps remain visible.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from serverware import authority_contract
from serverware import authority_transition_core as core


OPERATION = "webauthn.credential.revoke"
REVOKE_FIELDS = frozenset({
    "record_id", "actor_id", "reason", "source", "audit_event",
    "approval_grant_ids", "control_plane_approval_ids", "oidc_session_ids",
    "registration_challenge_ids",
})
CASCADE_MAX = 32
AUDIT_CAPACITY = 100_000
_CHALLENGE_FIELDS = frozenset({
    "id", "challenge", "challenge_type", "user_id", "scope_key",
    "approval_request_id", "payload_json", "expires_at", "used_at", "created_at",
})
_LIST_FIELDS = (
    "approval_grant_ids", "control_plane_approval_ids", "oidc_session_ids",
    "registration_challenge_ids",
)


def prepare_revocation_input(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Close semantic input before challenge issuance and request signing."""
    if not isinstance(arguments, Mapping) or set(arguments) != REVOKE_FIELDS:
        raise core.TransitionKernelError("revocation input fields are not exact")
    values = dict(arguments)
    for name in ("record_id", "actor_id"):
        core.require_text(values[name], name, maximum_bytes=1024)
    if values["source"] != "explicit":
        raise core.TransitionKernelError(
            "standalone revocation supports explicit self-service only"
        )
    reason = values["reason"]
    if reason is not None and (
        not isinstance(reason, str) or len(reason.encode("utf-8")) > 16_384
    ):
        raise core.TransitionKernelError("revocation reason exceeds its bound")
    event = values["audit_event"]
    if event is not None:
        if not isinstance(event, Mapping) or len(core.canonical_bytes(event)) > 2 * 1024 * 1024:
            raise core.TransitionKernelError("revocation audit event exceeds its bound")
        values["audit_event"] = dict(event)
    for name in _LIST_FIELDS:
        ids = values[name]
        if not isinstance(ids, list) or len(ids) > CASCADE_MAX:
            raise core.TransitionKernelError("revocation address set exceeds its bound")
        for item in ids:
            core.require_text(item, name, maximum_bytes=1024)
        if ids != sorted(set(ids)):
            raise core.TransitionKernelError("revocation address set is not sorted and unique")
        values[name] = list(ids)
    # Reserve both assertion writes even when signer == revoked credential.
    mutation_bound = (
        3 + len(values["oidc_session_ids"]) + len(values["approval_grant_ids"])
        + 2 * len(values["control_plane_approval_ids"])
        + len(values["registration_challenge_ids"]) + int(event is not None)
    )
    if mutation_bound > authority_contract.operation_spec(OPERATION)["maximumMutations"]:
        raise core.TransitionKernelError("revocation aggregate mutation bound exceeded")
    core.canonical_bytes(values)
    return values


def _arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    core.require_exact_arguments(arguments, REVOKE_FIELDS)
    values = prepare_revocation_input({key: arguments[key] for key in REVOKE_FIELDS})
    if arguments["businessIntent"] != authority_contract.synthesize_business_intent(OPERATION, values):
        raise core.TransitionKernelError("revocation business intent changed")
    return values


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise core.TransitionKernelError(f"{label} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise core.TransitionKernelError(f"{label} is not a UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise core.TransitionKernelError(f"{label} is not a UTC timestamp")
    return parsed


def _exact_query(operation: str, name: str, table: str, item_id: str) -> core.BoundedQuery:
    return core.BoundedQuery(
        query_id=core.query_program_id(operation, name, table), table=table,
        predicates=(core.QueryPredicate("id", "eq", item_id),),
        order_by=(core.QueryOrder("id"),), maximum_rows=1, absent_key={"id": item_id},
    )


def _complete_query(
    operation: str, name: str, table: str,
    predicates: tuple[core.QueryPredicate, ...], maximum_rows: int,
) -> core.BoundedQuery:
    # _read_bounded_transition_rows always fetches maximum_rows + 1 and denies
    # overflow. No continuation or partial page is accepted for revocation.
    return core.BoundedQuery(
        query_id=core.query_program_id(operation, name, table), table=table,
        predicates=predicates, order_by=(core.QueryOrder("id"),),
        maximum_rows=max(1, maximum_rows), proof_primitive="ordered-exact-page",
        exact_page=True,
    )


def audit_id(operation: str, request_digest: str, approval_id: str | None) -> str:
    subject = "credential" if approval_id is None else "approval:" + approval_id
    subject_digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()
    return core.deterministic_uuid(
        operation=operation, request_digest=request_digest,
        purpose="webauthn-revocation-audit:" + subject_digest,
    )


def cascade_queries(
    *, operation: str, values: Mapping[str, Any], database_now: datetime,
    request_digest: str,
) -> tuple[core.BoundedQuery, ...]:
    """Reusable dependency/audit queries; caller owns its aggregate authority."""
    record_id = values["record_id"]
    queries = [_exact_query(operation, "revoked_credential", "webauthn_credentials", record_id)]
    for status in ("pending_webauthn", "active"):
        queries.append(_complete_query(
            operation, "sessions_" + status, "oidc_browser_sessions",
            (core.QueryPredicate("bound_webauthn_credential_id", "eq", record_id),
             core.QueryPredicate("status", "eq", status)),
            len(values["oidc_session_ids"]),
        ))
    for name, table, column, state_column, state, hint in (
        ("grants", "approval_grants", "approver_webauthn_credential_id", "state", "active", "approval_grant_ids"),
        ("approvals", "control_plane_approvals", "approver_webauthn_credential_id", "status", "approved", "control_plane_approval_ids"),
    ):
        queries.append(_complete_query(
            operation, name, table,
            (core.QueryPredicate(column, "eq", record_id), core.QueryPredicate(state_column, "eq", state)),
            len(values[hint]),
        ))
    if values["source"] == "explicit":
        queries.append(_complete_query(
            operation, "global_registration_challenges", "webauthn_challenges",
            (core.QueryPredicate("challenge_type", "eq", "registration"),
             core.QueryPredicate("used_at", "is-null"),
             core.QueryPredicate("expires_at", "gt", database_now.astimezone(timezone.utc).isoformat())),
            len(values["registration_challenge_ids"]),
        ))
    elif values["registration_challenge_ids"]:
        raise core.TransitionKernelError("non-explicit cascade cannot select registration challenges")
    audit_subjects = list(values["control_plane_approval_ids"])
    if values["audit_event"] is not None:
        audit_subjects.append(None)
    for ordinal, subject in enumerate(audit_subjects):
        queries.append(_exact_query(
            operation, f"audit_{ordinal}", "metadata_audit_outbox",
            audit_id(operation, request_digest, subject),
        ))
    return tuple(queries)


def _row(selected: Mapping[str, Any]) -> dict[str, Any]:
    value = selected.get("row")
    if selected.get("present") is not True or not isinstance(value, Mapping):
        raise core.TransitionKernelError("revocation dependency row is absent")
    return dict(value)


def _exact_set(
    context: core.KernelContext, table: str, hint: list[str], predicate: Any,
) -> tuple[dict[str, Any], ...]:
    selected = tuple(item for item in context.present_rows(table) if predicate(_row(item)))
    actual = [item["key"].get("id") for item in selected]
    if len(actual) != len(set(actual)) or sorted(actual) != hint:
        raise core.TransitionKernelError("revocation complete dependency set changed")
    return tuple(sorted(selected, key=lambda item: item["key"]["id"]))


def _audit_mutation(
    context: core.KernelContext, *, subject: str | None, event_type: str,
    actor_type: str, actor_id: str | None, event: Mapping[str, Any],
) -> dict[str, Any]:
    item_id = audit_id(context.operation, context.request_digest, subject)
    selected = context.exact("metadata_audit_outbox", {"id": item_id})
    # Exact transport replay is served by the execution envelope. Re-deriving a
    # committed business transition must never overwrite/re-emit an audit.
    if selected.get("present") is not False:
        raise core.TransitionKernelError("revocation audit identity was already used")
    event_bytes = core.canonical_bytes(dict(event))
    if len(event_bytes) > 2 * 1024 * 1024:
        raise core.TransitionKernelError("revocation audit event exceeds its bound")
    return core.mutation(operation=context.operation, selected=selected, row={
        "id": item_id, "event_type": event_type, "actor_type": actor_type,
        "actor_id": actor_id, "event_json": event_bytes.decode("ascii"),
        "event_digest": core.framed_digest("serverware.metadataAuditOutboxEvent/v1", event_bytes),
        "storage_format_version": 2, "status": "pending", "claim_id": None,
        "claimed_at": None, "attempts": 0, "audited_at": None,
        "audit_event_hash": None, "last_error": None,
        "created_at": context.database_now.astimezone(timezone.utc).isoformat(),
    })


def plan_credential_cascade(
    context: core.KernelContext, values: Mapping[str, Any],
) -> core.KernelTransition:
    """Pure legacy cascade semantics; authorization/capacity belong to caller.

    This helper performs no writes and is not itself an admission entry point.
    A future aggregate trust operation must supply its own complete selection,
    authorization, journal and total budget before using these mutations.
    """
    record_id = values["record_id"]
    credential = context.exact("webauthn_credentials", {"id": record_id})
    row = _row(credential)
    if row.get("revoked_at") is not None:
        raise core.TransitionKernelError("credential is already revoked")
    now = context.database_now
    now_s = now.astimezone(timezone.utc).isoformat()
    sessions = _exact_set(context, "oidc_browser_sessions", values["oidc_session_ids"], lambda r: (
        r.get("bound_webauthn_credential_id") == record_id and r.get("status") in {"pending_webauthn", "active"}
    ))
    grants = _exact_set(context, "approval_grants", values["approval_grant_ids"], lambda r: (
        r.get("approver_webauthn_credential_id") == record_id and r.get("state") == "active"
    ))
    approvals = _exact_set(context, "control_plane_approvals", values["control_plane_approval_ids"], lambda r: (
        r.get("approver_webauthn_credential_id") == record_id and r.get("status") == "approved"
    ))
    registrations = _exact_set(context, "webauthn_challenges", values["registration_challenge_ids"], lambda r: (
        values["source"] == "explicit" and r.get("challenge_type") == "registration"
        and r.get("used_at") is None and _utc(r.get("expires_at"), "registration expiry") > now
    ))
    updated = {**row, "revoked_at": now_s, "revoked_by": values["actor_id"],
               "revocation_reason": values["reason"], "revocation_source": values["source"], "updated_at": now_s}
    mutations = [core.mutation(operation=context.operation, selected=credential, row=updated)]
    for selected in sessions:
        mutations.append(core.mutation(operation=context.operation, selected=selected, row={
            **_row(selected), "status": "revoked", "revoked_at": now_s, "updated_at": now_s,
            "revocation_reason": "bound_webauthn_credential_revoked",
        }))
    for selected in grants:
        mutations.append(core.mutation(operation=context.operation, selected=selected, row={
            **_row(selected), "state": "revoked", "uses_remaining": 0,
            "reserved_attempt_id": None, "reserved_at_epoch_ms": None,
            "reservation_expires_at_epoch_ms": None,
        }))
    for selected in approvals:
        approval = _row(selected)
        mutations.append(core.mutation(operation=context.operation, selected=selected, row={**approval, "status": "invalidated"}))
        mutations.append(_audit_mutation(
            context, subject=approval["id"], event_type="control_plane.approval.invalidated",
            actor_type="system", actor_id=None, event={
                **{key: approval.get(key) for key in ("action", "resource_id", "payload_digest", "requester_id", "approved_by")},
                "approval_id": approval["id"], "approver_webauthn_credential_id": record_id,
                "reason": "approver_webauthn_credential_revoked",
            },
        ))
    for selected in registrations:
        mutations.append(core.mutation(operation=context.operation, selected=selected, row={**_row(selected), "used_at": now_s}))
    counts = {
        "revoked_grant_count": len(grants), "revoked_control_plane_approval_count": len(approvals),
        "revoked_oidc_browser_session_count": len(sessions),
        "invalidated_registration_challenge_count": len(registrations),
    }
    if values["audit_event"] is not None:
        mutations.append(_audit_mutation(
            context, subject=None, event_type="webauthn.credential_revoked", actor_type="admin",
            actor_id=values["actor_id"], event={**values["audit_event"], "revoked_at": now_s,
                "revoked_by": values["actor_id"], **counts},
        ))
    public = dict(updated)
    for key in ("transports", "attestation_trust_path"):
        try:
            public[key] = json.loads(public.get(key) or "[]")
        except (TypeError, ValueError) as exc:
            raise core.TransitionKernelError("stored credential JSON is invalid") from exc
    public["attestation_trusted"] = bool(public.get("attestation_trusted"))
    return core.KernelTransition(mutations=tuple(mutations), result={"ok": True, "credential": public, **counts}, work_units=8 + 4 * len(mutations))


def _assertion_mutations(context: core.KernelContext, values: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    evidence = context.verified_webauthn_evidence
    if not isinstance(evidence, Mapping):
        raise core.TransitionKernelError("revocation requires planner-verified assertion evidence")
    operation_id = core.framed_digest("serverware.policyAuthorityOperation/v2", context.operation.encode("ascii"), context.request_digest.encode("ascii"))
    credential = context.exact("webauthn_credentials", {"id": evidence["credentialRecordId"]})
    credential_row = _row(credential)
    challenge = context.exact("webauthn_challenges", {"id": evidence["challengeId"]})
    challenge_row = _row(challenge)
    try:
        payload = json.loads(challenge_row["payload_json"])
    except (KeyError, TypeError, ValueError) as exc:
        raise core.TransitionKernelError("assertion challenge payload is invalid") from exc
    if not isinstance(payload, dict):
        raise core.TransitionKernelError("assertion challenge payload is invalid")
    challenge_public = {**payload, "challengeId": challenge_row.get("id"), "challenge": challenge_row.get("challenge"),
        "challengeRowDigest": core.framed_digest("serverware.policyAuthorityWebAuthnChallengeRow/v1", core.canonical_bytes(challenge_row))}
    challenge_value = challenge_row.get("challenge")
    try:
        if not isinstance(challenge_value, str):
            raise ValueError("challenge is not encoded text")
        challenge_bytes = base64.b64decode(
            challenge_value + "=" * (-len(challenge_value) % 4),
            altchars=b"-_", validate=True,
        )
        if base64.urlsafe_b64encode(challenge_bytes).decode("ascii").rstrip("=") != challenge_value:
            raise ValueError("challenge encoding is not canonical")
    except (ValueError, UnicodeError) as exc:
        raise core.TransitionKernelError("assertion challenge encoding changed") from exc
    if (
        set(challenge_row) != _CHALLENGE_FIELDS or evidence.get("operation") != context.operation
        or evidence.get("operationId") != operation_id or evidence.get("requestDigest") != context.request_digest
        or credential_row.get("user_id") != values["actor_id"] or challenge_row.get("user_id") != values["actor_id"]
        or credential_row.get("credential_id") != evidence.get("credentialId")
        or credential_row.get("sign_count") != evidence.get("priorCounter") or credential_row.get("revoked_at") is not None
        or challenge_row.get("challenge_type") != "policy_authority" or challenge_row.get("scope_key") != operation_id
        or challenge_row.get("used_at") is not None or _utc(challenge_row.get("expires_at"), "assertion expiry") <= context.database_now
        or payload.get("operationId") != operation_id or payload.get("credentialId") != evidence.get("credentialId")
        or payload.get("rpId") != evidence.get("rpId") or payload.get("origin") != evidence.get("origin")
        or evidence.get("challengeDigest") != "sha256:" + hashlib.sha256(core.canonical_bytes(challenge_public)).hexdigest()
        or evidence.get("clientChallengeDigest") != "sha256:" + hashlib.sha256(challenge_bytes).hexdigest()
    ):
        raise core.TransitionKernelError("revocation assertion row binding changed")
    prior = core.require_integer(evidence.get("priorCounter"), "assertion prior counter", minimum=0, maximum=2_147_483_647)
    counter = core.require_integer(evidence.get("counter"), "assertion next counter", minimum=1, maximum=2_147_483_647)
    if counter <= prior:
        raise core.TransitionKernelError("revocation assertion counter is not monotonic")
    now_s = context.database_now.astimezone(timezone.utc).isoformat()
    return (
        core.mutation(operation=context.operation, selected=credential, row={**credential_row, "sign_count": counter, "last_used_at": now_s, "updated_at": now_s}),
        core.mutation(operation=context.operation, selected=challenge, row={**challenge_row, "used_at": now_s}),
    )


class WebAuthnCredentialRevokeKernel:
    operation = OPERATION
    handler = "revoke_webauthn_credential"
    program_id = core.transition_program_id(operation, handler)
    permits_empty_mutation = False

    def queries(self, *, arguments: Mapping[str, Any], database_now: datetime, request_digest: str) -> tuple[core.BoundedQuery, ...]:
        values = _arguments(arguments)
        return cascade_queries(operation=self.operation, values=values, database_now=database_now, request_digest=request_digest)

    def queries_with_evidence(self, *, arguments: Mapping[str, Any], database_now: datetime, request_digest: str, evidence: Mapping[str, Any]) -> tuple[core.BoundedQuery, ...]:
        values = _arguments(arguments)
        queries = list(self.queries(arguments=arguments, database_now=database_now, request_digest=request_digest))
        signer = core.require_text(evidence.get("credentialRecordId"), "assertion credential", maximum_bytes=1024)
        challenge = core.require_text(evidence.get("challengeId"), "assertion challenge", maximum_bytes=1024)
        if signer != values["record_id"]:
            queries.append(_exact_query(self.operation, "assertion_credential", "webauthn_credentials", signer))
        queries.append(_exact_query(self.operation, "assertion_challenge", "webauthn_challenges", challenge))
        audit_count = len(values["control_plane_approval_ids"]) + int(values["audit_event"] is not None)
        if audit_count:
            remaining = authority_contract.operation_spec(self.operation)["maximumQueryRows"] - sum(query.maximum_rows for query in queries)
            if remaining < 2:
                raise core.TransitionKernelError("revocation has no complete audit capacity query budget")
            for status, limit in (("pending", remaining // 2), ("claimed", remaining - remaining // 2)):
                queries.append(_complete_query(self.operation, "audit_capacity_" + status, "metadata_audit_outbox",
                    (core.QueryPredicate("status", "eq", status),), limit))
        return core.close_queries(self.operation, tuple(queries))

    def transition(self, context: core.KernelContext) -> core.KernelTransition:
        values = _arguments(context.arguments)
        target = _row(context.exact("webauthn_credentials", {"id": values["record_id"]}))
        if target.get("user_id") != values["actor_id"]:
            raise core.TransitionKernelError("standalone revocation cannot revoke another user's credential")
        assertion = _assertion_mutations(context, values)
        cascade = plan_credential_cascade(context, values)
        mutations = {(item["table"], item["keyDigest"]): dict(item) for item in cascade.mutations}
        for item in assertion:
            key = (item["table"], item["keyDigest"])
            if key in mutations:
                current = mutations[key]
                if item["table"] != "webauthn_credentials" or current["expectedRow"] != item["expectedRow"]:
                    raise core.TransitionKernelError("revocation assertion mutation overlap is invalid")
                current["row"] = {**current["row"], **{field: item["row"][field] for field in ("sign_count", "last_used_at", "updated_at")}}
            else:
                mutations[key] = dict(item)
        audits = sum(item["table"] == "metadata_audit_outbox" for item in mutations.values())
        outstanding = sum(_row(item).get("status") in {"pending", "claimed"} for item in context.present_rows("metadata_audit_outbox"))
        if audits and outstanding + audits > AUDIT_CAPACITY:
            raise core.TransitionKernelError("metadata audit outbox is at capacity")
        result = dict(cascade.result)
        result["credential"] = dict(result["credential"])
        final_credential = next(item["row"] for item in mutations.values() if item["table"] == "webauthn_credentials" and item["key"] == {"id": values["record_id"]})
        for field in ("sign_count", "last_used_at", "updated_at"):
            result["credential"][field] = final_credential.get(field)
        planned = tuple(sorted(mutations.values(), key=lambda item: (item["table"], item["keyDigest"], item["operation"])))
        work = cascade.work_units + 8 + len(context.selected_rows)
        spec = authority_contract.operation_spec(self.operation)
        if len(planned) > spec["maximumMutations"] or len(context.selected_rows) > spec["maximumQueryRows"] or work > spec["maximumWorkUnits"]:
            raise core.TransitionKernelError("revocation aggregate plan exceeds its manifest")
        return core.KernelTransition(mutations=planned, result=result, work_units=work)
