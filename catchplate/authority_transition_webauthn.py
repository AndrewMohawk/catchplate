"""UNREGISTERED candidate for bounded explicit self-revocation.

Address lists are signed hints, never row-selection authority. The candidate
declares source-fixed complete index queries, including GLOBAL registration
challenges, and rejects overflow. Audits use exact absent keys. The common
planner owns the initialized global audit-capacity query, counter CAS and
framework budget; this business kernel does not scan or count the outbox.
The old aggregate HTTP route remains unchanged.

The current reader rejects these declarations before business/proof SQL: real
frontier production, maintained indexes and independent root-pair admission are
not yet available. Selected-row membership is not predicate completeness. This
kernel remains deliberately NOT registered; four startup gaps remain visible.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from catchplate import authority_contract
from catchplate import authority_audit_capacity
from catchplate import authority_challenge_retention
from catchplate import authority_complete_query
from catchplate import authority_transition_core as core
from catchplate import authority_webauthn_trust as trust
from catchplate.authority_query_read_work import _ValidationWork, QueryReadWorkError


OPERATION = "webauthn.credential.revoke"
REVOKE_FIELDS = frozenset({
    "record_id", "actor_id", "reason", "source", "audit_event",
    "approval_grant_ids", "control_plane_approval_ids", "oidc_session_ids",
    "registration_challenge_ids",
})
CASCADE_MAX = 32
_CHALLENGE_FIELDS = authority_challenge_retention.ROW_FIELDS
_LIST_FIELDS = (
    "approval_grant_ids", "control_plane_approval_ids", "oidc_session_ids",
    "registration_challenge_ids",
)


def prepare_revocation_input(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Close semantic input before challenge issuance and request signing."""
    return _prepare_revocation_input(arguments, work=None)


def _prepare_revocation_input(
    arguments: Mapping[str, Any], *, work: _ValidationWork | None,
) -> dict[str, Any]:
    if work is not None and (type(arguments) is not dict or len(arguments) != len(REVOKE_FIELDS)):
        raise core.TransitionKernelError("revocation input fields are not exact")
    if not isinstance(arguments, Mapping) or set(arguments) != REVOKE_FIELDS:
        raise core.TransitionKernelError("revocation input fields are not exact")
    if work is not None:
        work.prepare_copy(arguments)
    values = dict(arguments)
    for name in ("record_id", "actor_id"):
        if work is not None:
            work.prepare_utf8(values[name])
        core.require_text(values[name], name, maximum_bytes=1024)
    if values["source"] != "explicit":
        raise core.TransitionKernelError(
            "standalone revocation supports explicit self-service only"
        )
    reason = values["reason"]
    if work is not None and isinstance(reason, str):
        work.prepare_utf8(reason)
    if reason is not None and (
        not isinstance(reason, str) or len(reason.encode("utf-8")) > 16_384
    ):
        raise core.TransitionKernelError("revocation reason exceeds its bound")
    event = values["audit_event"]
    if event is not None:
        if work is not None and isinstance(event, Mapping):
            work.prepare_encoding(event)
        if not isinstance(event, Mapping) or len(core.canonical_bytes(event)) > 2 * 1024 * 1024:
            raise core.TransitionKernelError("revocation audit event exceeds its bound")
        if work is not None:
            work.prepare_copy(event)
        values["audit_event"] = dict(event)
    for name in _LIST_FIELDS:
        ids = values[name]
        if not isinstance(ids, list) or len(ids) > CASCADE_MAX:
            raise core.TransitionKernelError("revocation address set exceeds its bound")
        for item in ids:
            if work is not None:
                work.prepare_utf8(item)
            core.require_text(item, name, maximum_bytes=1024)
        if work is not None:
            # Full-list units conservatively bound the set and sorted copy;
            # a rejected duplicate list receives no discount for fewer items.
            work.prepare_copy(ids)
            work.prepare_copy(ids)
        ordered = sorted(set(ids))
        if work is not None:
            work.prepare_comparison(ids, ordered)
        if ids != ordered:
            raise core.TransitionKernelError("revocation address set is not sorted and unique")
        if work is not None:
            work.prepare_copy(ids)
        values[name] = list(ids)
    # Reserve both assertion writes even when signer == revoked credential.
    mutation_bound = (
        3 + len(values["oidc_session_ids"]) + len(values["approval_grant_ids"])
        + 2 * len(values["control_plane_approval_ids"])
        + len(values["registration_challenge_ids"]) + int(event is not None)
    )
    if mutation_bound > authority_contract.operation_spec(OPERATION)["maximumBusinessMutations"]:
        raise core.TransitionKernelError("revocation aggregate mutation bound exceeded")
    if work is not None:
        work.prepare_encoding(values)
    core.canonical_bytes(values)
    return values


def _arguments(
    arguments: Mapping[str, Any], *, work: _ValidationWork | None = None,
) -> dict[str, Any]:
    if work is not None and (type(arguments) is not dict or len(arguments) != len(REVOKE_FIELDS) + 1):
        raise core.TransitionKernelError("authority transition arguments are not exact")
    core.require_exact_arguments(arguments, REVOKE_FIELDS)
    if work is not None:
        # The full input is a conservative bound for the semantic-field copy.
        work.prepare_copy(arguments)
    semantic = {key: arguments[key] for key in REVOKE_FIELDS}
    values = (prepare_revocation_input(semantic) if work is None else
              _prepare_revocation_input(semantic, work=work))
    expected = (authority_contract.synthesize_business_intent(OPERATION, values)
                if work is None else authority_contract._synthesize_business_intent(
                    OPERATION, values, work=work))
    if work is not None:
        work.prepare_comparison(arguments["businessIntent"], expected)
    if arguments["businessIntent"] != expected:
        raise core.TransitionKernelError("revocation business intent changed")
    return values


def _utc(value: Any, label: str, *, work: _ValidationWork | None = None) -> datetime:
    if not isinstance(value, str):
        raise core.TransitionKernelError(f"{label} is not a UTC timestamp")
    if work is not None:
        work.prepare_scan(value)
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


def _trust_queries(operation: str, *, work: _ValidationWork | None) -> tuple[core.BoundedQuery, ...]:
    """Select the fixed high-water, then its mandatory matching publication.

    Publication IDs are stored random UUIDs, not receipt-derived primary keys.
    The second query is a present-row join only: its zero-row result is never
    promoted to an authenticated absence or generic predicate-completeness.
    """
    key = {"authority_scope": trust.AUTHORITY_SCOPE}
    high_water = core.BoundedQuery(
        query_id=core.query_program_id(operation, "webauthn_trust_high_water", trust.HIGH_WATER_TABLE),
        table=trust.HIGH_WATER_TABLE,
        predicates=(core.QueryPredicate("authority_scope", "eq", trust.AUTHORITY_SCOPE),),
        order_by=(core.QueryOrder("authority_scope"),), maximum_rows=1, absent_key=key,
    )
    predicates = [core.QueryPredicate("scope", "eq", "global"), core.QueryPredicate("status", "eq", "published")]
    for column, source in (("bundle_digest", "publication_digest"), ("payload_digest", "metadata_blob_digest"),
                           ("rollback_epoch", "rollback_epoch"), ("sequence", "publication_sequence")):
        if work is not None:
            # The actual reference constructor copies the fixed key then
            # canonicalizes it. Preserve both hidden passes, not just a DTO.
            work.prepare_encoding(key, shallow_copies=1)
        reference = core.SelectedRowFieldReference(trust.HIGH_WATER_TABLE, key, source)
        predicates.append(core.QueryPredicate(column, "eq", reference))
    publication = core.BoundedQuery(
        query_id=core.query_program_id(operation, "webauthn_trust_publication", trust.PUBLICATION_TABLE),
        table=trust.PUBLICATION_TABLE, predicates=tuple(predicates), order_by=(core.QueryOrder("id"),),
        maximum_rows=1,
    )
    return high_water, publication


def audit_id(operation: str, request_digest: str, approval_id: str | None) -> str:
    return _audit_id(operation, request_digest, approval_id, work=None)


def _audit_id(
    operation: str, request_digest: str, approval_id: str | None,
    *, work: _ValidationWork | None,
) -> str:
    subject = "credential" if approval_id is None else "approval:" + approval_id
    if work is not None:
        work.prepare_utf8(subject)
        work.charge(hashes=1)
    subject_digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()
    purpose = "webauthn-revocation-audit:" + subject_digest
    if work is None:
        return core.deterministic_uuid(
            operation=operation, request_digest=request_digest, purpose=purpose,
        )
    return core._deterministic_uuid(
        operation=operation, request_digest=request_digest, purpose=purpose, work=work,
    )


def cascade_queries(
    *, operation: str, values: Mapping[str, Any], database_now: datetime,
    request_digest: str,
) -> tuple[core.Query, ...]:
    """Convert supplied aware time exactly, then use the shared source recipe."""
    try:
        cutoff_us = authority_complete_query.cutoff_microseconds(database_now)
    except authority_complete_query.CompleteQueryError as exc:
        raise core.TransitionKernelError("revocation complete query binding failed") from exc
    return cascade_queries_at_cutoff(
        operation=operation, values=values, cutoff_us=cutoff_us,
        request_digest=request_digest,
    )


def cascade_queries_at_cutoff(
    *, operation: str, values: Mapping[str, Any], cutoff_us: int,
    request_digest: str,
) -> tuple[core.Query, ...]:
    """Declare the explicit-revocation cascade from prepared semantic values.

    Callers retain the existing prepare_revocation_input/_arguments precondition.
    The signed-int64 cutoff is a supplied input, not authenticated time. This
    source recipe is not aggregate withdrawal authority or work accounting.
    """
    return _cascade_queries_at_cutoff(
        operation=operation, values=values, cutoff_us=cutoff_us,
        request_digest=request_digest, work=None,
    )


def _cascade_queries_at_cutoff(
    *, operation: str, values: Mapping[str, Any], cutoff_us: int,
    request_digest: str, work: _ValidationWork | None,
) -> tuple[core.Query, ...]:
    record_id = values["record_id"]
    queries = [_exact_query(operation, "revoked_credential", "webauthn_credentials", record_id)]
    try:
        for role in (
            "sessions_pending_webauthn", "sessions_active", "grants", "approvals",
            "global_registration_challenges",
        ):
            queries.append(
                authority_complete_query.bind_query(
                    operation, role, arguments=values, cutoff_us=cutoff_us,
                ) if work is None else authority_complete_query._bind_query(
                    operation, role, arguments=values, cutoff_us=cutoff_us, work=work,
                )
            )
    except authority_complete_query.CompleteQueryError as exc:
        raise core.TransitionKernelError("revocation complete query binding failed") from exc
    if work is not None:
        work.prepare_copy(values["control_plane_approval_ids"])
    audit_subjects = list(values["control_plane_approval_ids"])
    if values["audit_event"] is not None:
        audit_subjects.append(None)
    for ordinal, subject in enumerate(audit_subjects):
        queries.append(_exact_query(
            operation, f"audit_{ordinal}", "metadata_audit_outbox",
            audit_id(operation, request_digest, subject) if work is None else
            _audit_id(operation, request_digest, subject, work=work),
        ))
    return tuple(queries)


def _prepare_complete_copies(queries: tuple[core.Query, ...], work: _ValidationWork) -> None:
    for query in queries:
        if type(query) is authority_complete_query.CompleteIndexQuery:
            authority_complete_query._prepare_constructor_work(query.index_id, query.selector_items, work)


def _revocation_query_program(
    *, arguments: Mapping[str, Any], cutoff_us: int, request_digest: str,
    evidence: Mapping[str, Any], work: _ValidationWork,
) -> tuple[core.Query, ...]:
    """Privately generate real source declarations under one supplied meter.

    The future composer must already own all input graphs and give this phase
    only its remaining budget. This function neither captures those graphs nor
    authenticates assertion identities, request digests, time, rows or proofs.
    Its result is ordinary declaration data, not an admission token.
    """
    if type(work) is not _ValidationWork:
        raise QueryReadWorkError("revocation query generation requires the real private work meter")
    queries = WebAuthnCredentialRevokeKernel()._queries_with_evidence_at_cutoff(
        arguments=arguments, cutoff_us=cutoff_us, request_digest=request_digest,
        evidence=evidence, work=work,
    )
    # The genuine capacity helper snapshots every complete declaration and its
    # final close_queries snapshots them again. Reserve both actual passes,
    # without a cache discount, before entering that unchanged helper.
    _prepare_complete_copies(queries, work)
    _prepare_complete_copies(queries, work)
    return authority_audit_capacity.add_capacity_query(OPERATION, queries)


def _kernel_work(context: core.KernelContext, work: _ValidationWork | None) -> None:
    if work is None:
        return
    if type(work) is not _ValidationWork:
        raise QueryReadWorkError("revocation kernel requires the real private work meter")
    if (type(context) is not core.KernelContext or type(context.operation) is not str
            or not 1 <= len(context.operation) <= 128
            or type(context.selected_rows) is not tuple):
        raise core.TransitionKernelError("revocation kernel context is not an owned source input")
    try:
        spec = authority_contract.operation_spec(context.operation)
    except ValueError as exc:
        raise core.TransitionKernelError("revocation kernel context operation is not source declared") from exc
    if (len(context.selected_rows) > spec["maximumQueryRows"]
            or any(type(item) is not dict for item in context.selected_rows)):
        raise core.TransitionKernelError("revocation selected inventory exceeds its source bound")


def _exact(context: core.KernelContext, table: str, key: Mapping[str, Any], *, work: _ValidationWork | None):
    return context.exact(table, key) if work is None else context._exact(table, key, work=work)


def _same(left: Any, right: Any, *, work: _ValidationWork | None) -> bool:
    if work is not None:
        work.prepare_comparison(left, right)
    return left == right


def _different(left: Any, right: Any, *, work: _ValidationWork | None) -> bool:
    if work is not None:
        work.prepare_comparison(left, right)
    return left != right


def _member(value: Any, choices: set[str], *, work: _ValidationWork | None) -> bool:
    if work is not None:
        work.prepare_scan(value)
    return value in choices


def _stored_json(value: Any, *, work: _ValidationWork | None) -> Any:
    if work is not None:
        if type(value) is not str:
            raise TypeError("stored JSON is not exact text")
        work.charge(json_nodes=1)
        if len(value) > work.limits.max_input_bytes - work.input_bytes:
            raise QueryReadWorkError("stored JSON exceeds remaining work")
        size = nesting = 0
        quoted = escaped = False
        # One actual text walk measures raw UTF-8 units and bounds nesting.
        # It is not a parser; the existing json.loads(str) still runs below.
        for character in value:
            point = ord(character)
            if 0xD800 <= point <= 0xDFFF:
                raise QueryReadWorkError("stored JSON contains a Unicode surrogate")
            width = 1 if point < 128 else 2 if point < 2048 else 3 if point < 65536 else 4
            work.charge(input_bytes=width)
            size += width
            if quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    quoted = False
            elif character == '"':
                quoted = True
            elif character in "[{":
                nesting += 1
                if nesting > 128:
                    raise ValueError("stored JSON exceeds its container nesting bound")
            elif character in "]}":
                nesting -= 1
                if nesting < 0:
                    raise ValueError("stored JSON has invalid container nesting")
        # U+1 is a conservative semantic-node bound including object keys.
        # No duplicate-object hook or bytes-to-text decode exists at this site.
        work.charge(input_bytes=size, json_nodes=size + 1)
    return json.loads(value)


def _challenge_bytes(value: Any, *, work: _ValidationWork | None) -> bytes:
    try:
        if not isinstance(value, str):
            raise ValueError("challenge is not encoded text")
        if work is not None:
            length = len(value)
            padded = 4 * ((length + 3) // 4)
            decoded_bound = 3 * (padded // 4)
            reencoded_bound = 4 * ((decoded_bound + 2) // 3)
            # Unlike the receipt codec, this original validate=True decoder
            # has no separate alphabet scan. All roundtrip allocations and
            # both comparison operands are conservatively prepared in advance.
            work.charge(input_bytes=length + 4 * padded + 2 * decoded_bound + 5 * reencoded_bound)
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
            raise ValueError("challenge encoding is not canonical")
        return decoded
    except QueryReadWorkError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise core.TransitionKernelError("assertion challenge encoding changed") from exc


def _mutation(context: core.KernelContext, selected: Mapping[str, Any], row: Mapping[str, Any], *, work: _ValidationWork | None):
    if work is not None:
        work.prepare_copy(selected["key"])
        if selected.get("present") is True:
            work.prepare_copy(selected["row"])
        work.prepare_copy(row)
    return core.mutation(operation=context.operation, selected=selected, row=row)


def _transition_result(*, mutations, result, work_units: int, work: _ValidationWork | None):
    if work is not None:
        work.prepare_encoding(result)
    return core.KernelTransition(mutations=mutations, result=result, work_units=work_units)


def _challenge_row_digest(row, *, work: _ValidationWork | None) -> str:
    from catchplate.authority_webauthn_bindings import challenge_row_digest
    return challenge_row_digest(row, work=work)


def _sha256_bytes(value: bytes, *, work: _ValidationWork | None) -> str:
    if work is not None:
        work.charge(hashes=1)
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _challenge_public_digest(value, *, work: _ValidationWork | None) -> str:
    if work is not None:
        work.prepare_encoding(value)
    return _sha256_bytes(core.canonical_bytes(value), work=work)


def _row(selected: Mapping[str, Any], *, work: _ValidationWork | None = None) -> dict[str, Any]:
    value = selected.get("row")
    if selected.get("present") is not True or not isinstance(value, Mapping):
        raise core.TransitionKernelError("revocation dependency row is absent")
    if work is not None:
        work.prepare_copy(value)
    return dict(value)


def _exact_set(
    context: core.KernelContext, table: str, hint: list[str], predicate: Any,
    *, work: _ValidationWork | None = None,
) -> tuple[dict[str, Any], ...]:
    if work is not None:
        # Conservative full-source units for both actual rows/present filters.
        work.prepare_copy(context.selected_rows)
        work.prepare_copy(context.selected_rows)
    present = context.present_rows(table)
    if work is not None:
        work.prepare_copy(present)
    selected = tuple(item for item in present if predicate(_row(item, work=work)))
    if work is not None:
        work.prepare_copy(selected)
    actual = [item["key"].get("id") for item in selected]
    if work is not None:
        work.prepare_copy(actual)
    if len(actual) != len(set(actual)):
        raise core.TransitionKernelError("revocation complete dependency set changed")
    if work is not None:
        work.prepare_copy(actual)
    ordered = sorted(actual)
    if _different(ordered, hint, work=work):
        raise core.TransitionKernelError("revocation complete dependency set changed")
    if work is not None:
        work.prepare_copy(selected)
    ordered_selected = sorted(selected, key=lambda item: item["key"]["id"])
    if work is not None:
        work.prepare_copy(ordered_selected)
    return tuple(ordered_selected)


def _audit_mutation(
    context: core.KernelContext, *, subject: str | None, event_type: str,
    actor_type: str, actor_id: str | None, event: Mapping[str, Any],
    work: _ValidationWork | None = None,
) -> dict[str, Any]:
    item_id = (audit_id(context.operation, context.request_digest, subject) if work is None else
               _audit_id(context.operation, context.request_digest, subject, work=work))
    selected = _exact(context, "metadata_audit_outbox", {"id": item_id}, work=work)
    # Exact transport replay is served by the execution envelope. Re-deriving a
    # committed business transition must never overwrite/re-emit an audit.
    if selected.get("present") is not False:
        raise core.TransitionKernelError("revocation audit identity was already used")
    if work is not None:
        # One real preparation walk, the actual dict copy and actual encoding.
        event_size, _ = work.prepare_encoding(event, shallow_copies=1)
        if event_size > 2 * 1024 * 1024:
            raise core.TransitionKernelError("revocation audit event exceeds its bound")
    event_bytes = core.canonical_bytes(dict(event))
    if len(event_bytes) > 2 * 1024 * 1024:
        raise core.TransitionKernelError("revocation audit event exceeds its bound")
    if work is not None:
        work.charge(input_bytes=len(event_bytes), hashes=1)
    return _mutation(context, selected, {
        "id": item_id, "event_type": event_type, "actor_type": actor_type,
        "actor_id": actor_id, "event_json": event_bytes.decode("ascii"),
        "event_digest": core.framed_digest("catchplate.metadataAuditOutboxEvent/v1", event_bytes),
        "storage_format_version": 2, "status": "pending", "claim_id": None,
        "claimed_at": None, "attempts": 0, "audited_at": None,
        "audit_event_hash": None, "last_error": None,
        "created_at": context.database_now.astimezone(timezone.utc).isoformat(),
    }, work=work)


def plan_credential_cascade(
    context: core.KernelContext, values: Mapping[str, Any],
) -> core.KernelTransition:
    """Pure legacy cascade semantics; authorization/capacity belong to caller.

    This helper performs no writes and is not itself an admission entry point.
    A future aggregate trust operation must supply its own complete selection,
    authorization, journal and total budget before using these mutations.
    """
    return _plan_credential_cascade(context, values, work=None)


def _plan_credential_cascade(
    context: core.KernelContext, values: Mapping[str, Any], *, work: _ValidationWork | None,
    consumed_approval_id: str | None = None,
) -> core.KernelTransition:
    """The actual cascade body; callers own inputs and all admission duties."""
    _kernel_work(context, work)
    record_id = values["record_id"]
    credential = _exact(context, "webauthn_credentials", {"id": record_id}, work=work)
    row = _row(credential, work=work)
    if row.get("revoked_at") is not None:
        raise core.TransitionKernelError("credential is already revoked")
    now = context.database_now
    now_s = now.astimezone(timezone.utc).isoformat()
    sessions = _exact_set(context, "oidc_browser_sessions", values["oidc_session_ids"], lambda r: (
        _same(r.get("bound_webauthn_credential_id"), record_id, work=work)
        and _member(r.get("status"), {"pending_webauthn", "active"}, work=work)
    ), work=work)
    grants = _exact_set(context, "approval_grants", values["approval_grant_ids"], lambda r: (
        _same(r.get("approver_webauthn_credential_id"), record_id, work=work)
        and _same(r.get("state"), "active", work=work)
    ), work=work)
    approvals = _exact_set(context, "control_plane_approvals", values["control_plane_approval_ids"], lambda r: (
        _same(r.get("approver_webauthn_credential_id"), record_id, work=work)
        and _same(r.get("status"), "approved", work=work)
    ), work=work)
    registrations = _exact_set(context, "webauthn_challenges", values["registration_challenge_ids"], lambda r: (
        _same(values["source"], "explicit", work=work)
        and _same(r.get("challenge_type"), "registration", work=work)
        and r.get("used_at") is None
        and _utc(r.get("expires_at"), "registration expiry", work=work) > now
    ), work=work)
    if consumed_approval_id is not None:
        # Validate completeness against the untouched prestate first. Only
        # the authenticated public aggregate consumes this row atomically;
        # legacy consume-before-cascade behavior remains the final result.
        if work is None:
            raise core.TransitionKernelError("public approval consumption requires retained proof work")
        work.prepare_copy(approvals)
        approvals = tuple(item for item in approvals if item["key"]["id"] != consumed_approval_id)
    if work is not None:
        work.prepare_copy(row)
    updated = {**row, "revoked_at": now_s, "revoked_by": values["actor_id"],
               "revocation_reason": values["reason"], "revocation_source": values["source"], "updated_at": now_s}
    mutations = [_mutation(context, credential, updated, work=work)]
    for selected in sessions:
        session = _row(selected, work=work)
        if work is not None:
            work.prepare_copy(session)
        mutations.append(_mutation(context, selected, {
            **session, "status": "revoked", "revoked_at": now_s, "updated_at": now_s,
            "revocation_reason": "bound_webauthn_credential_revoked",
        }, work=work))
    for selected in grants:
        grant = _row(selected, work=work)
        if work is not None:
            work.prepare_copy(grant)
        mutations.append(_mutation(context, selected, {
            **grant, "state": "revoked", "uses_remaining": 0,
            "reserved_attempt_id": None, "reserved_at_epoch_ms": None,
            "reservation_expires_at_epoch_ms": None,
        }, work=work))
    for selected in approvals:
        approval = _row(selected, work=work)
        if work is not None:
            work.prepare_copy(approval)
        mutations.append(_mutation(context, selected, {**approval, "status": "invalidated"}, work=work))
        if work is not None:
            # Conservative source-row units for the event projection and its
            # spread into the enclosing event, without a second field recipe.
            work.prepare_copy(approval)
            work.prepare_copy(approval)
        mutations.append(_audit_mutation(
            context, subject=approval["id"], event_type="control_plane.approval.invalidated",
            actor_type="system", actor_id=None, event={
                **{key: approval.get(key) for key in ("action", "resource_id", "payload_digest", "requester_id", "approved_by")},
                "approval_id": approval["id"], "approver_webauthn_credential_id": record_id,
                "reason": "approver_webauthn_credential_revoked",
            }, work=work,
        ))
    for selected in registrations:
        registration = _row(selected, work=work)
        if work is not None:
            work.prepare_copy(registration)
        mutations.append(_mutation(context, selected, {**registration, "used_at": now_s}, work=work))
    counts = {
        "revoked_grant_count": len(grants), "revoked_control_plane_approval_count": len(approvals),
        "revoked_oidc_browser_session_count": len(sessions),
        "invalidated_registration_challenge_count": len(registrations),
    }
    if values["audit_event"] is not None:
        if work is not None:
            work.prepare_copy(values["audit_event"])
            work.prepare_copy(counts)
        mutations.append(_audit_mutation(
            context, subject=None, event_type="webauthn.credential_revoked", actor_type="admin",
            actor_id=values["actor_id"], event={**values["audit_event"], "revoked_at": now_s,
                "revoked_by": values["actor_id"], **counts}, work=work,
        ))
    if work is not None:
        work.prepare_copy(updated)
    public = dict(updated)
    for key in ("transports", "attestation_trust_path"):
        try:
            public[key] = _stored_json(public.get(key) or "[]", work=work)
        except QueryReadWorkError:
            raise
        except (TypeError, ValueError) as exc:
            raise core.TransitionKernelError("stored credential JSON is invalid") from exc
    public["attestation_trusted"] = bool(public.get("attestation_trusted"))
    if work is not None:
        work.prepare_copy(mutations)
        work.prepare_copy(counts)
    return _transition_result(mutations=tuple(mutations), result={"ok": True, "credential": public, **counts},
                              work_units=8 + 4 * len(mutations), work=work)


def _assertion_mutations(
    context: core.KernelContext, values: Mapping[str, Any], *, work: _ValidationWork | None = None,
) -> tuple[dict[str, Any], ...]:
    evidence = context.verified_webauthn_evidence
    if not isinstance(evidence, Mapping):
        raise core.TransitionKernelError("revocation requires planner-verified assertion evidence")
    if work is not None:
        work.prepare_utf8(context.operation)
        work.prepare_utf8(context.request_digest)
        work.charge(hashes=1)
    operation_id = core.framed_digest("catchplate.policyAuthorityOperation/v2", context.operation.encode("ascii"), context.request_digest.encode("ascii"))
    credential = _exact(context, "webauthn_credentials", {"id": evidence["credentialRecordId"]}, work=work)
    credential_row = _row(credential, work=work)
    challenge = _exact(context, "webauthn_challenges", {"id": evidence["challengeId"]}, work=work)
    challenge_row = _row(challenge, work=work)
    try:
        payload = _stored_json(challenge_row["payload_json"], work=work)
    except QueryReadWorkError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise core.TransitionKernelError("assertion challenge payload is invalid") from exc
    if not isinstance(payload, dict):
        raise core.TransitionKernelError("assertion challenge payload is invalid")
    if work is not None:
        work.prepare_copy(payload)
    challenge_public = {**payload, "challengeId": challenge_row.get("id"), "challenge": challenge_row.get("challenge"),
        "challengeRowDigest": _challenge_row_digest(challenge_row, work=work)}
    challenge_value = challenge_row.get("challenge")
    challenge_bytes = _challenge_bytes(challenge_value, work=work)
    if work is not None:
        work.prepare_copy(challenge_row)
    if (
        len(challenge_row) != len(_CHALLENGE_FIELDS) or set(challenge_row) != _CHALLENGE_FIELDS
        or _different(evidence.get("operation"), context.operation, work=work)
        or _different(evidence.get("operationId"), operation_id, work=work)
        or _different(evidence.get("requestDigest"), context.request_digest, work=work)
        or _different(credential_row.get("user_id"), values["actor_id"], work=work)
        or _different(challenge_row.get("user_id"), values["actor_id"], work=work)
        or _different(credential_row.get("credential_id"), evidence.get("credentialId"), work=work)
        or _different(credential_row.get("sign_count"), evidence.get("priorCounter"), work=work)
        or credential_row.get("revoked_at") is not None
        or _different(challenge_row.get("challenge_type"), "policy_authority", work=work)
        or _different(challenge_row.get("scope_key"), operation_id, work=work)
        or challenge_row.get("used_at") is not None
        or _utc(challenge_row.get("expires_at"), "assertion expiry", work=work) <= context.database_now
        or _different(payload.get("operationId"), operation_id, work=work)
        or _different(payload.get("credentialId"), evidence.get("credentialId"), work=work)
        or _different(payload.get("rpId"), evidence.get("rpId"), work=work)
        or _different(payload.get("origin"), evidence.get("origin"), work=work)
        or _different(evidence.get("challengeDigest"), _challenge_public_digest(challenge_public, work=work), work=work)
        or _different(evidence.get("clientChallengeDigest"), _sha256_bytes(challenge_bytes, work=work), work=work)
    ):
        raise core.TransitionKernelError("revocation assertion row binding changed")
    _assertion_trust(context, credential_row, evidence, work=work)
    prior = core.require_integer(evidence.get("priorCounter"), "assertion prior counter", minimum=0, maximum=2_147_483_647)
    counter = core.require_integer(evidence.get("counter"), "assertion next counter", minimum=1, maximum=2_147_483_647)
    if counter <= prior:
        raise core.TransitionKernelError("revocation assertion counter is not monotonic")
    now_s = context.database_now.astimezone(timezone.utc).isoformat()
    if work is not None:
        work.prepare_copy(credential_row)
    credential_mutation = _mutation(context, credential,
        {**credential_row, "sign_count": counter, "last_used_at": now_s, "updated_at": now_s}, work=work)
    if work is not None:
        work.prepare_copy(challenge_row)
    challenge_mutation = _mutation(context, challenge, {**challenge_row, "used_at": now_s}, work=work)
    return credential_mutation, challenge_mutation


def _assertion_trust(context, credential, evidence, *, work: _ValidationWork | None) -> None:
    """Bind the signed verifier policy to the actual proved trust rows.

    The genuine complete join and retained observation closure place every
    pending member in this selected union. The proof worker may validly report
    a pending member; this business kernel must then deny the revocation.
    A bare kernel context does not itself prove predicate absence.
    """
    high_water = _row(_exact(context, trust.HIGH_WATER_TABLE,
        {"authority_scope": trust.AUTHORITY_SCOPE}, work=work), work=work)
    if work is not None:
        # Actual rows() and present_rows() each allocate a filtered tuple.
        work.prepare_copy(context.selected_rows)
        work.prepare_copy(context.selected_rows)
    publications = context.present_rows(trust.PUBLICATION_TABLE)
    for selected in publications:
        row = selected.get("row")
        if type(row) is not dict:
            raise core.TransitionKernelError("revocation trust publication row is invalid")
        if _same(row.get("status"), "pending", work=work):
            raise core.TransitionKernelError("revocation is blocked by a pending trust publication")
    if len(publications) != 1:
        raise core.TransitionKernelError("revocation trust publication is absent or ambiguous")
    publication = _row(publications[0], work=work)
    try:
        document = trust.high_water_document(
            rollback_epoch=high_water.get("rollback_epoch"), sequence=high_water.get("publication_sequence"),
            publication_digest=high_water.get("publication_digest"), metadata_blob_digest=high_water.get("metadata_blob_digest"),
            revocation_set_digest=high_water.get("revocation_set_digest"), witness_receipt_digest=high_water.get("witness_receipt_digest"),
            witness_sequence=high_water.get("witness_sequence"))
        high_water_digest = trust.high_water_digest(document, work=work)
        policy = trust.credential_policy_document(credential=credential, high_water=document,
            trust_high_water_digest=high_water_digest, work=work)
        policy_digest = trust.credential_policy_digest(policy, work=work)
    except QueryReadWorkError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise core.TransitionKernelError("revocation trust or credential policy is invalid") from exc
    for actual, expected in (
        (high_water.get("authority_scope"), trust.AUTHORITY_SCOPE),
        (publication.get("scope"), "global"), (publication.get("status"), "published"),
        (publication.get("bundle_digest"), high_water["publication_digest"]),
        (publication.get("payload_digest"), high_water["metadata_blob_digest"]),
        (publication.get("rollback_epoch"), high_water["rollback_epoch"]),
        (publication.get("sequence"), high_water["publication_sequence"]),
        (evidence.get("trustHighWaterDigest"), high_water_digest),
        (evidence.get("metadataPublicationSequence"), high_water["publication_sequence"]),
        (evidence.get("credentialPolicyDigest"), policy_digest),
        (credential.get("attestation_trust_bundle_digest"), publication.get("bundle_digest")),
        (credential.get("attestation_trust_bundle_sequence"), publication.get("sequence")),
    ):
        if type(actual) is not type(expected) or _different(actual, expected, work=work):
            raise core.TransitionKernelError("revocation assertion trust binding changed")
    try:
        withdrawn = _stored_json(publication.get("withdrawn_credential_ids_json"), work=work)
    except QueryReadWorkError:
        raise
    except (TypeError, ValueError) as exc:
        raise core.TransitionKernelError("revocation withdrawn credential inventory is invalid") from exc
    if type(withdrawn) is not list:
        raise core.TransitionKernelError("revocation withdrawn credential inventory is not a list")
    for identifier in (credential["credential_id"], credential["id"]):
        if work is not None:
            work.prepare_scan(withdrawn)
            work.prepare_scan(identifier)
        if identifier in withdrawn:
            raise core.TransitionKernelError("revocation assertion credential is withdrawn")


class WebAuthnCredentialRevokeKernel:
    operation = OPERATION
    handler = "revoke_webauthn_credential"
    program_id = core.transition_program_id(operation, handler)
    permits_empty_mutation = False

    def queries(self, *, arguments: Mapping[str, Any], database_now: datetime, request_digest: str) -> tuple[core.Query, ...]:
        values = _arguments(arguments)
        return cascade_queries(operation=self.operation, values=values, database_now=database_now, request_digest=request_digest)

    def queries_with_evidence(self, *, arguments: Mapping[str, Any], database_now: datetime, request_digest: str, evidence: Mapping[str, Any]) -> tuple[core.Query, ...]:
        """Convert supplied aware time and delegate to the cutoff-native recipe."""
        try:
            cutoff_us = authority_complete_query.cutoff_microseconds(database_now)
        except authority_complete_query.CompleteQueryError as exc:
            raise core.TransitionKernelError("revocation complete query binding failed") from exc
        return self.queries_with_evidence_at_cutoff(
            arguments=arguments, cutoff_us=cutoff_us,
            request_digest=request_digest, evidence=evidence,
        )

    def queries_with_evidence_at_cutoff(
        self, *, arguments: Mapping[str, Any], cutoff_us: int,
        request_digest: str, evidence: Mapping[str, Any],
    ) -> tuple[core.Query, ...]:
        """Regenerate the closed business program; assertion IDs remain inputs."""
        return self._queries_with_evidence_at_cutoff(
            arguments=arguments, cutoff_us=cutoff_us, request_digest=request_digest,
            evidence=evidence, work=None,
        )

    def _queries_with_evidence_at_cutoff(
        self, *, arguments: Mapping[str, Any], cutoff_us: int,
        request_digest: str, evidence: Mapping[str, Any], work: _ValidationWork | None,
    ) -> tuple[core.Query, ...]:
        from catchplate import authority_public_webauthn_revocation as public
        if public.is_public(evidence) or evidence.get("schema") == public.BINDING_SCHEMA:
            from catchplate import authority_public_webauthn_revocation_kernel as aggregate
            return aggregate.queries(arguments=arguments, cutoff_us=cutoff_us,
                request_digest=request_digest, evidence=evidence, work=work)
        values = _arguments(arguments) if work is None else _arguments(arguments, work=work)
        queries = list(
            cascade_queries_at_cutoff(
                operation=self.operation, values=values, cutoff_us=cutoff_us,
                request_digest=request_digest,
            ) if work is None else _cascade_queries_at_cutoff(
                operation=self.operation, values=values, cutoff_us=cutoff_us,
                request_digest=request_digest, work=work,
            )
        )
        if work is not None:
            work.prepare_utf8(evidence.get("credentialRecordId"))
        signer = core.require_text(evidence.get("credentialRecordId"), "assertion credential", maximum_bytes=1024)
        if work is not None:
            work.prepare_utf8(evidence.get("challengeId"))
        challenge = core.require_text(evidence.get("challengeId"), "assertion challenge", maximum_bytes=1024)
        if signer != values["record_id"]:
            queries.append(_exact_query(self.operation, "assertion_credential", "webauthn_credentials", signer))
        queries.append(_exact_query(self.operation, "assertion_challenge", "webauthn_challenges", challenge))
        queries.extend(_trust_queries(self.operation, work=work))
        queries.append(
            authority_complete_query.bind_query(self.operation, "pending_trust_publications",
                arguments=values, cutoff_us=cutoff_us) if work is None else
            authority_complete_query._bind_query(self.operation, "pending_trust_publications",
                arguments=values, cutoff_us=cutoff_us, work=work)
        )
        spec = authority_contract.operation_spec(self.operation)
        if (sum(query.maximum_rows for query in queries) > spec["maximumBusinessQueryRows"]
                or sum(query.work_units for query in queries) > spec["maximumBusinessWorkUnits"]):
            raise core.TransitionKernelError("revocation query program exceeds its business bound")
        if work is not None:
            _prepare_complete_copies(tuple(queries), work)
        return core.close_queries(self.operation, tuple(queries))

    def transition(self, context: core.KernelContext) -> core.KernelTransition:
        return self._transition(context, work=None)

    def _transition(self, context: core.KernelContext, *, work: _ValidationWork | None) -> core.KernelTransition:
        """Run the actual business kernel, with optional shared accounting.

        The measured caller must already own all graphs and independently
        authenticate assertion evidence, request bindings and time. This is
        neither proof verification nor a registered planner entry point.
        """
        _kernel_work(context, work)
        if work is not None and context.operation != self.operation:
            raise core.TransitionKernelError("revocation kernel context operation changed")
        values = _arguments(context.arguments) if work is None else _arguments(context.arguments, work=work)
        from catchplate import authority_public_webauthn_revocation as public
        if public.is_public(context.verified_webauthn_evidence):
            from catchplate import authority_public_webauthn_revocation_kernel as aggregate
            return aggregate.transition(context, values, work=work)
        target = _row(_exact(context, "webauthn_credentials", {"id": values["record_id"]}, work=work), work=work)
        if _different(target.get("user_id"), values["actor_id"], work=work):
            raise core.TransitionKernelError("standalone revocation cannot revoke another user's credential")
        assertion = (_assertion_mutations(context, values) if work is None else
                     _assertion_mutations(context, values, work=work))
        cascade = (plan_credential_cascade(context, values) if work is None else
                   _plan_credential_cascade(context, values, work=work))
        if work is not None:
            for item in cascade.mutations:
                work.prepare_copy(item)
        mutations = {(item["table"], item["keyDigest"]): dict(item) for item in cascade.mutations}
        for item in assertion:
            key = (item["table"], item["keyDigest"])
            if key in mutations:
                current = mutations[key]
                if (item["table"] != "webauthn_credentials"
                        or _different(current["expectedRow"], item["expectedRow"], work=work)):
                    raise core.TransitionKernelError("revocation assertion mutation overlap is invalid")
                if work is not None:
                    work.prepare_copy(current["row"])
                    work.prepare_copy(item["row"])
                updates = {field: item["row"][field] for field in ("sign_count", "last_used_at", "updated_at")}
                if work is not None:
                    work.prepare_copy(updates)
                current["row"] = {**current["row"], **updates}
            else:
                if work is not None:
                    work.prepare_copy(item)
                mutations[key] = dict(item)
        if work is not None:
            work.prepare_copy(cascade.result)
        result = dict(cascade.result)
        if work is not None:
            work.prepare_copy(result["credential"])
        result["credential"] = dict(result["credential"])
        final_credential = next(item["row"] for item in mutations.values()
            if item["table"] == "webauthn_credentials"
            and _same(item["key"], {"id": values["record_id"]}, work=work))
        for field in ("sign_count", "last_used_at", "updated_at"):
            result["credential"][field] = final_credential.get(field)
        if work is not None:
            for item in mutations.values():
                work.prepare_copy(item)
        ordered_mutations = sorted(mutations.values(), key=lambda item: (item["table"], item["keyDigest"], item["operation"]))
        if work is not None:
            work.prepare_copy(ordered_mutations)
        planned = tuple(ordered_mutations)
        # Only the exact common-framework address is outside business accounting.
        # The common finalizer still requires and validates that row, including
        # no-audit plans, and alone may append its counter mutation.
        if work is not None:
            work.prepare_copy(context.selected_rows)
        business_rows = tuple(item for item in context.selected_rows if not (
            item.get("table") == authority_audit_capacity.AGGREGATE_TABLE
            and item.get("key") == {"aggregate_id": authority_audit_capacity.AGGREGATE_ID}
        ))
        signed_work = cascade.work_units + 8 + len(business_rows)
        spec = authority_contract.operation_spec(self.operation)
        if len(planned) > spec["maximumBusinessMutations"] or len(business_rows) > spec["maximumBusinessQueryRows"] or signed_work > spec["maximumBusinessWorkUnits"]:
            raise core.TransitionKernelError("revocation aggregate plan exceeds its manifest")
        return _transition_result(mutations=planned, result=result, work_units=signed_work, work=work)
