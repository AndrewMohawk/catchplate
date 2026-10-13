from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Mapping

from serverware import authority_transition_core as core
from serverware import authority_jit_request as jit_request


QUOTA_TRANSITION_OPERATIONS = frozenset(
    {
        "control-approval.request",
        "control-approval.decide",
        "control-approval.consume",
        "control-approval.deny",
        "jit.request",
        "jit.review-receipt.issue",
        "jit.decide",
        "jit.deny",
        "quota.rate.consume",
        "quota.budget.reserve",
        "quota.budget.dispatch",
        "quota.budget.commit",
        "quota.budget.cancel",
        "quota.traversal.reserve",
        "quota.traversal.dispatch",
        "quota.traversal.complete",
        "quota.traversal.terminate",
        "quota.policy-state.reserve",
        "quota.policy-state.dispatch",
        "quota.policy-state.complete",
        "quota.policy-state.abort",
        "quota.policy-state.fail",
        "quota.policy-state.reconcile",
    }
)


_TRAVERSAL_TERMINATE_REQUIRED_FIELDS = frozenset(
    {"reservation_id", "chain_key", "request_digest", "outcome"}
)
_TRAVERSAL_DISPATCH_REQUIRED_FIELDS = frozenset(
    {"reservation_id", "chain_key", "request_digest"}
)
_SIGNED_BIGINT_MAX = 2**63 - 1
_MAX_MAINTENANCE_ITEMS = 32
_EMPTY_DIGEST = core.framed_digest(
    "serverware.policyAuthorityEmptySet/v1",
    b"",
)
_WEBAUTHN_FIELDS = frozenset(
    {
        "evidence_digest",
        "credential_record_id",
        "credential_id",
        "credential_id_digest",
        "challenge_id",
        "ceremony_id",
        "challenge_digest",
        "authenticator_data_digest",
        "client_data_digest",
        "assertion_signature_digest",
        "prior_counter",
        "new_counter",
        "trust_generation",
        "trust_root_digest",
    }
)


def _exact_arguments(
    arguments: Mapping[str, Any],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    if not isinstance(arguments, Mapping):
        raise core.TransitionKernelError(
            "authority operation arguments are not exact"
        )
    fields = set(arguments)
    if (
        "businessIntent" not in fields
        or not required <= fields
        or fields - required - optional - {"businessIntent"}
    ):
        raise core.TransitionKernelError(
            "authority operation arguments are not exact"
        )


def _text(
    value: Any,
    label: str,
    *,
    maximum_bytes: int = 512,
    allow_empty: bool = False,
) -> str:
    return core.require_text(
        value,
        label,
        maximum_bytes=maximum_bytes,
        allow_empty=allow_empty,
    )


def _digest(value: Any, label: str) -> str:
    return core.require_digest(value, label)


def _optional_digest(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _digest(value, label)


def _integer(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = _SIGNED_BIGINT_MAX,
) -> int:
    return core.require_integer(
        value,
        label,
        minimum=minimum,
        maximum=maximum,
    )


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise core.TransitionKernelError(f"{label} is not boolean")
    return value


def _canonical_mapping(
    value: Any,
    label: str,
    *,
    maximum_bytes: int = 64 * 1024,
) -> tuple[dict[str, Any], str]:
    if not isinstance(value, Mapping):
        raise core.TransitionKernelError(f"{label} is not an exact object")
    normalized = dict(value)
    encoded = core.canonical_bytes(normalized)
    if len(encoded) > maximum_bytes:
        raise core.TransitionKernelError(f"{label} exceeds its bound")
    return normalized, encoded.decode("ascii")


def _canonical_stored_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise core.TransitionKernelError(f"{label} is not canonical JSON")
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise core.TransitionKernelError(
            f"{label} is not canonical JSON"
        ) from exc
    if (
        not isinstance(parsed, Mapping)
        or core.canonical_bytes(parsed).decode("ascii") != value
    ):
        raise core.TransitionKernelError(
            f"{label} is not canonical JSON"
        )
    return dict(parsed)


def _database_epoch_ns(database_now: datetime) -> int:
    normalized = database_now.astimezone(timezone.utc)
    delta = normalized - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (
        delta.days * 86_400_000_000_000
        + delta.seconds * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _iso_from_epoch_ms(epoch_ms: int) -> str:
    return (
        datetime(1970, 1, 1, tzinfo=timezone.utc)
        + timedelta(milliseconds=epoch_ms)
    ).isoformat()


def _query(
    *,
    operation: str,
    name: str,
    table: str,
    key: Mapping[str, Any],
    require_absence: bool = False,
) -> core.BoundedQuery:
    normalized = dict(key)
    return core.BoundedQuery(
        query_id=core.query_program_id(operation, name, table),
        table=table,
        predicates=tuple(
            core.QueryPredicate(column, "eq", normalized[column])
            for column in sorted(normalized)
        ),
        order_by=tuple(
            core.QueryOrder(column) for column in sorted(normalized)
        ),
        maximum_rows=1,
        absent_key=normalized,
        require_absence=require_absence,
    )


def _selected_or_none(
    context: core.KernelContext,
    table: str,
    key: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    selected = context.exact(table, key)
    if selected.get("present") is False:
        return selected, None
    return selected, _row(selected, table)


def _partition_digest(kind: str, partition: str) -> str:
    return core.framed_digest(
        "serverware.policyAuthorityAggregatePartition/v1",
        kind.encode("ascii"),
        partition.encode("utf-8"),
    )


def _aggregate_key(kind: str, partition: str) -> tuple[str, str]:
    partition_digest = _partition_digest(kind, partition)
    return f"{kind}:{partition_digest}", partition_digest


def _aggregate_query(
    operation: str,
    name: str,
    kind: str,
    partition: str,
) -> core.BoundedQuery:
    aggregate_id, _ = _aggregate_key(kind, partition)
    return _query(
        operation=operation,
        name=name,
        table="policy_authority_bounded_aggregate_states",
        key={"aggregate_id": aggregate_id},
    )


def _aggregate_maps(row: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    return (
        _canonical_stored_mapping(
            row.get("reserved_units_json"),
            "bounded aggregate reserved units",
        ),
        _canonical_stored_mapping(
            row.get("committed_units_json"),
            "bounded aggregate committed units",
        ),
    )


def _aggregate_update(
    context: core.KernelContext,
    *,
    kind: str,
    partition: str,
    live_delta: int = 0,
    active_delta: int = 0,
    reserved_units: Mapping[str, Any] | None = None,
    committed_units: Mapping[str, Any] | None = None,
    next_sequence_delta: int = 0,
    minimum_expiry_epoch_ns: int | None | object = ...,
    expiry_index_root_digest: str | None = None,
    work_page_id: str | None | object = ...,
) -> dict[str, Any]:
    aggregate_id, partition_digest = _aggregate_key(kind, partition)
    row = context.bounded_aggregate(
        aggregate_id=aggregate_id,
        aggregate_kind=kind,
        partition_digest=partition_digest,
    )
    current_reserved, current_committed = _aggregate_maps(row)
    return context.update_bounded_aggregate(
        aggregate_id=aggregate_id,
        aggregate_kind=kind,
        partition_digest=partition_digest,
        live_delta=live_delta,
        active_delta=active_delta,
        reserved_units=(
            current_reserved
            if reserved_units is None
            else dict(reserved_units)
        ),
        committed_units=(
            current_committed
            if committed_units is None
            else dict(committed_units)
        ),
        next_sequence_delta=next_sequence_delta,
        minimum_expiry_epoch_ns=(
            row.get("minimum_expiry_epoch_ns")
            if minimum_expiry_epoch_ns is ...
            else minimum_expiry_epoch_ns
        ),
        expiry_index_root_digest=(
            str(row["expiry_index_root_digest"])
            if expiry_index_root_digest is None
            else _digest(
                expiry_index_root_digest,
                "aggregate expiry root",
            )
        ),
        work_page_id=(
            row.get("work_page_id")
            if work_page_id is ...
            else work_page_id
        ),
    )


def _audit_identity(
    operation: str,
    request_digest: str,
) -> str:
    return core.deterministic_uuid(
        operation=operation,
        request_digest=request_digest,
        purpose="metadata-audit-outbox",
    )


def _audit_query(
    operation: str,
    request_digest: str,
) -> core.BoundedQuery:
    return _query(
        operation=operation,
        name="audit_outbox",
        table="metadata_audit_outbox",
        key={"id": _audit_identity(operation, request_digest)},
    )


def _audit_mutations(
    context: core.KernelContext,
    *,
    event_type: str,
    actor_type: str,
    actor_id: str | None,
    event: Mapping[str, Any],
) -> tuple[tuple[dict[str, Any], ...], str, bool]:
    event_value, event_json = _canonical_mapping(
        event,
        "authority audit event",
        maximum_bytes=2 * 1024 * 1024,
    )
    event_digest = core.framed_digest(
        "serverware.metadataAuditOutboxEvent/v1",
        event_json.encode("ascii"),
    )
    audit_id = _audit_identity(
        context.operation,
        context.request_digest,
    )
    selected, existing = _selected_or_none(
        context,
        "metadata_audit_outbox",
        {"id": audit_id},
    )
    if existing is not None:
        if (
            existing.get("event_type") != event_type
            or existing.get("actor_type") != actor_type
            or existing.get("actor_id") != actor_id
            or existing.get("event_json") != event_json
            or existing.get("event_digest") != event_digest
        ):
            raise core.TransitionKernelError(
                "audit outbox replay conflicts with its prior event"
            )
        return (), event_digest, True
    if (
        selected.get("present") is not False
        or "row" not in selected
        or selected["row"] is not None
    ):
        raise core.TransitionKernelError(
            "fresh audit identity is not proven absent"
        )
    now_s = context.database_now.astimezone(timezone.utc).isoformat()
    row = {
        "id": audit_id,
        "event_type": _text(
            event_type,
            "audit event type",
            maximum_bytes=128,
        ),
        "actor_type": _text(
            actor_type,
            "audit actor type",
            maximum_bytes=64,
        ),
        "actor_id": actor_id,
        "event_json": core.canonical_bytes(event_value).decode("ascii"),
        "event_digest": event_digest,
        "storage_format_version": 1,
        "status": "pending",
        "claim_id": None,
        "claimed_at": None,
        "attempts": 0,
        "audited_at": None,
        "audit_event_hash": None,
        "last_error": None,
        "created_at": now_s,
    }
    return (
        (
            core.mutation(
                operation=context.operation,
                selected=selected,
                row=row,
            ),
        ),
        event_digest,
        False,
    )


def _webauthn_queries(
    operation: str,
    arguments: Mapping[str, Any],
) -> tuple[core.BoundedQuery, ...]:
    evidence_digest = _digest(
        arguments["evidence_digest"],
        "WebAuthn evidence digest",
    )
    credential_record_id = _text(
        arguments["credential_record_id"],
        "WebAuthn credential record",
        maximum_bytes=256,
    )
    challenge_id = _text(
        arguments["challenge_id"],
        "WebAuthn challenge",
        maximum_bytes=256,
    )
    return (
        _query(
            operation=operation,
            name="webauthn_evidence",
            table="policy_authority_external_evidence_receipts",
            key={"evidence_digest": evidence_digest},
        ),
        _query(
            operation=operation,
            name="webauthn_credential",
            table="webauthn_credentials",
            key={"id": credential_record_id},
        ),
        _query(
            operation=operation,
            name="webauthn_challenge",
            table="webauthn_challenges",
            key={"id": challenge_id},
        ),
        _query(
            operation=operation,
            name="webauthn_trust_high_water",
            table="webauthn_trust_publication_high_water",
            key={"authority_scope": "webauthn-metadata"},
        ),
    )


def _webauthn_statement(
    context: core.KernelContext,
    *,
    actor_id: str,
    subject_kind: str,
    subject_id: str,
    decision: str,
    replay: bool = False,
    business_binding: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], ...]:
    arguments = context.arguments
    credential_record_id = _text(
        arguments["credential_record_id"],
        "WebAuthn credential record",
        maximum_bytes=256,
    )
    credential_id = _text(
        arguments["credential_id"],
        "WebAuthn credential",
        maximum_bytes=4096,
    )
    challenge_id = _text(
        arguments["challenge_id"],
        "WebAuthn challenge",
        maximum_bytes=256,
    )
    sign_count_before = _integer(
        arguments["prior_counter"],
        "WebAuthn prior counter",
    )
    sign_count_after = _integer(
        arguments["new_counter"],
        "WebAuthn next counter",
    )
    if sign_count_after <= sign_count_before:
        raise core.TransitionKernelError(
            "WebAuthn counter is not monotonic"
        )
    trust_root_digest = _digest(
        arguments["trust_root_digest"],
        "WebAuthn trust root",
    )
    trust_generation = _integer(
        arguments["trust_generation"],
        "WebAuthn trust generation",
    )
    exact_business_binding = dict(business_binding or {})
    business_binding_digest = core.framed_digest(
        "serverware.policyAuthorityPhysicalWebAuthnBusinessBinding/v1",
        core.canonical_bytes(exact_business_binding),
    )
    bound_grant_id = exact_business_binding.get("grantId", subject_id)
    if not isinstance(bound_grant_id, str) or not bound_grant_id:
        raise core.TransitionKernelError(
            "physical WebAuthn grant identity is invalid"
        )
    binding = {
        "operation": context.operation,
        "operationId": business_binding_digest,
        "requestDigest": context.request_digest,
        "credentialRecordId": credential_record_id,
        "credentialIdDigest": _digest(
            arguments["credential_id_digest"],
            "WebAuthn credential identity digest",
        ),
        "grantId": bound_grant_id,
        "actorId": actor_id,
        "ceremonyId": _text(
            arguments["ceremony_id"],
            "WebAuthn ceremony",
            maximum_bytes=256,
        ),
        "challengeDigest": _digest(
            arguments["challenge_digest"],
            "WebAuthn challenge digest",
        ),
        "authenticatorDataDigest": _digest(
            arguments["authenticator_data_digest"],
            "WebAuthn authenticator data",
        ),
        "clientDataDigest": _digest(
            arguments["client_data_digest"],
            "WebAuthn client data",
        ),
        "assertionSignatureDigest": _digest(
            arguments["assertion_signature_digest"],
            "WebAuthn assertion signature",
        ),
        "priorCounter": sign_count_before,
        "newCounter": sign_count_after,
        "trustGeneration": trust_generation,
        "trustRootDigest": trust_root_digest,
    }
    evidence_digest = _digest(
        arguments["evidence_digest"],
        "WebAuthn evidence digest",
    )
    operation_id = f"{context.operation}:{context.request_digest}"
    evidence_row = (
        context.physical_webauthn_evidence(
            evidence_digest=evidence_digest,
            expected_binding=binding,
            consumed_operation_id=operation_id,
        )
        if replay
        else context.physical_webauthn_evidence(
            evidence_digest=evidence_digest,
            expected_binding=binding,
        )
    )
    del evidence_row, subject_kind, decision
    credential_selected = context.exact(
        "webauthn_credentials",
        {"id": credential_record_id},
    )
    credential = _row(
        credential_selected,
        "WebAuthn credential",
    )
    challenge_selected = context.exact(
        "webauthn_challenges",
        {"id": challenge_id},
    )
    challenge = _row(challenge_selected, "WebAuthn challenge")
    trust = _row(
        context.exact(
            "webauthn_trust_publication_high_water",
            {"authority_scope": "webauthn-metadata"},
        ),
        "WebAuthn trust high water",
    )
    if (
        credential.get("credential_id") != credential_id
        or arguments["credential_id_digest"]
            != core.framed_digest(
                "serverware.policyAuthorityWebAuthnCredentialId/v1",
                credential_id.encode("utf-8"),
            )
        or credential.get("user_id") != actor_id
        or credential.get("revoked_at") is not None
        or credential.get("sign_count")
            != (sign_count_after if replay else sign_count_before)
        or challenge.get("user_id") != actor_id
        or arguments["ceremony_id"] != challenge_id
        or arguments["challenge_digest"]
            != core.framed_digest(
                "serverware.policyAuthorityWebAuthnChallenge/v1",
                str(challenge.get("challenge")).encode("utf-8"),
            )
        or (
            replay
            and challenge.get("used_at") is None
        )
        or (
            not replay
            and challenge.get("used_at") is not None
        )
        or challenge.get("expires_at")
            <= context.database_now.astimezone(timezone.utc).isoformat()
        or trust.get("publication_digest") != trust_root_digest
        or trust.get("rollback_epoch") != trust_generation
    ):
        raise core.TransitionKernelError(
            "WebAuthn evidence is no longer current"
        )
    if replay:
        return ()
    now_s = context.database_now.astimezone(timezone.utc).isoformat()
    evidence_mutation = context.consume_physical_webauthn_evidence(
        evidence_digest=evidence_digest,
        expected_binding=binding,
        operation_id=operation_id,
    )
    credential_mutation = core.mutation(
        operation=context.operation,
        selected=credential_selected,
        row={
            **credential,
            "sign_count": sign_count_after,
            "last_used_at": now_s,
            "updated_at": now_s,
        },
    )
    challenge_mutation = core.mutation(
        operation=context.operation,
        selected=challenge_selected,
        row={**challenge, "used_at": now_s},
    )
    return (
        evidence_mutation,
        credential_mutation,
        challenge_mutation,
    )


def _row(selected: Mapping[str, Any], label: str) -> dict[str, Any]:
    value = selected.get("row")
    if selected.get("present") is not True or not isinstance(value, Mapping):
        raise core.TransitionKernelError(f"{label} is absent")
    return dict(value)


def _traversal_termination_arguments(
    arguments: Mapping[str, Any],
) -> tuple[str, str, str, str, int | None]:
    if not isinstance(arguments, Mapping):
        raise core.TransitionKernelError(
            "traversal termination arguments are not exact"
        )
    argument_fields = frozenset(arguments)
    allowed = (
        _TRAVERSAL_TERMINATE_REQUIRED_FIELDS
        | {"now_epoch_ms", "businessIntent"}
    )
    if (
        argument_fields - allowed
        or not _TRAVERSAL_TERMINATE_REQUIRED_FIELDS
            <= argument_fields
        or argument_fields
            not in (
                _TRAVERSAL_TERMINATE_REQUIRED_FIELDS
                    | {"businessIntent"},
                allowed,
            )
    ):
        raise core.TransitionKernelError(
            "traversal termination arguments are not exact"
        )
    reservation_id = core.require_text(
        arguments["reservation_id"],
        "traversal reservation",
        maximum_bytes=256,
    )
    chain_key = core.require_digest(
        arguments["chain_key"],
        "traversal chain key",
    )
    request_digest = core.require_digest(
        arguments["request_digest"],
        "traversal request digest",
    )
    outcome = arguments["outcome"]
    if outcome not in {"not_forwarded", "indeterminate"}:
        raise core.TransitionKernelError(
            "traversal termination outcome is invalid"
        )
    now_epoch_ms = arguments.get("now_epoch_ms")
    if now_epoch_ms is not None:
        now_epoch_ms = core.require_integer(
            now_epoch_ms,
            "traversal termination time",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        )
    return (
        reservation_id,
        chain_key,
        request_digest,
        str(outcome),
        now_epoch_ms,
    )


def _database_epoch_ms(database_now: datetime) -> int:
    normalized = database_now.astimezone(timezone.utc)
    delta = normalized - datetime(1970, 1, 1, tzinfo=timezone.utc)
    microseconds = (
        delta.days * 86_400_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )
    return (microseconds + 500) // 1000


def _traversal_dispatch_arguments(
    arguments: Mapping[str, Any],
) -> tuple[str, str, str, int | None]:
    if not isinstance(arguments, Mapping):
        raise core.TransitionKernelError(
            "traversal dispatch arguments are not exact"
        )
    argument_fields = frozenset(arguments)
    allowed = (
        _TRAVERSAL_DISPATCH_REQUIRED_FIELDS
        | {"now_epoch_ms", "businessIntent"}
    )
    if (
        argument_fields - allowed
        or not _TRAVERSAL_DISPATCH_REQUIRED_FIELDS
            <= argument_fields
        or argument_fields
            not in (
                _TRAVERSAL_DISPATCH_REQUIRED_FIELDS
                    | {"businessIntent"},
                allowed,
            )
    ):
        raise core.TransitionKernelError(
            "traversal dispatch arguments are not exact"
        )
    reservation_id = core.require_text(
        arguments["reservation_id"],
        "traversal reservation",
        maximum_bytes=256,
    )
    chain_key = core.require_digest(
        arguments["chain_key"],
        "traversal chain key",
    )
    request_digest = core.require_digest(
        arguments["request_digest"],
        "traversal request digest",
    )
    now_epoch_ms = arguments.get("now_epoch_ms")
    if now_epoch_ms is not None:
        now_epoch_ms = core.require_integer(
            now_epoch_ms,
            "traversal dispatch time",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        )
    return reservation_id, chain_key, request_digest, now_epoch_ms


def _traversal_dispatch_result(
    *,
    chain: Mapping[str, Any],
    reservation_id: str,
    page_number: int,
    idempotent_replay: bool,
) -> dict[str, Any]:
    result = _traversal_result(
        chain=chain,
        reservation_id=reservation_id,
        target="dispatched",
        page_number=page_number,
        idempotent_replay=idempotent_replay,
    )
    return {
        **result,
        "allowed": True,
        "reason": "dispatched",
    }


def _traversal_result(
    *,
    chain: Mapping[str, Any],
    reservation_id: str,
    target: str,
    page_number: int,
    idempotent_replay: bool,
) -> dict[str, Any]:
    integer_fields = (
        "page_count",
        "record_count",
        "byte_count",
        "max_pages",
        "max_records",
        "max_bytes",
        "started_at_epoch_ms",
        "expires_at_epoch_ms",
    )
    if any(
        not isinstance(chain.get(field), int)
        or isinstance(chain.get(field), bool)
        for field in integer_fields
    ):
        raise core.TransitionKernelError(
            "traversal chain counters are invalid"
        )
    return {
        "allowed": False,
        "reason": target,
        "chain_key": str(chain["chain_key"]),
        "lineage_digest": str(chain["lineage_digest"]),
        "chain_state": str(chain["state"]),
        "reservation_id": reservation_id,
        "reservation_state": target,
        "page_number": page_number,
        "page_count": int(chain["page_count"]),
        "record_count": int(chain["record_count"]),
        "byte_count": int(chain["byte_count"]),
        "max_pages": int(chain["max_pages"]),
        "max_records": int(chain["max_records"]),
        "max_bytes": int(chain["max_bytes"]),
        "started_at_epoch_ms": int(chain["started_at_epoch_ms"]),
        "expires_at_epoch_ms": int(chain["expires_at_epoch_ms"]),
        "idempotent_replay": idempotent_replay,
        "traversal_budget_store_backend": "postgres",
        "traversal_budget_store_ha": True,
    }


def _role_query(
    operation: str,
    name: str,
    subject_id: Any,
) -> core.BoundedQuery:
    return _query(
        operation=operation,
        name=name,
        table="rbac_role_bindings",
        key={"subject_id": subject_id},
    )


def _require_role(
    context: core.KernelContext,
    *,
    subject_id: str,
    required_role: str | None,
) -> None:
    selected = context.exact(
        "rbac_role_bindings",
        {"subject_id": subject_id},
    )
    if required_role is None:
        return
    required_role = _text(
        required_role,
        "required RBAC role",
        maximum_bytes=128,
    )
    binding = _row(selected, "RBAC binding")
    roles = _canonical_stored_mapping(
        binding.get("roles_json"),
        "RBAC roles",
    ) if str(binding.get("roles_json", "")).startswith("{") else None
    if roles is not None:
        role_values = roles.get("roles")
    else:
        try:
            role_values = json.loads(str(binding.get("roles_json")))
        except (TypeError, ValueError) as exc:
            raise core.TransitionKernelError(
                "RBAC roles are not canonical"
            ) from exc
        if (
            core.canonical_bytes(role_values).decode("ascii")
            != binding.get("roles_json")
        ):
            raise core.TransitionKernelError(
                "RBAC roles are not canonical"
            )
    if (
        binding.get("status") != "active"
        or not isinstance(role_values, list)
        or required_role not in role_values
    ):
        raise core.TransitionKernelError(
            "current RBAC binding does not authorize the operation"
        )


def _control_public(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        field: row.get(field)
        for field in (
            "id",
            "action",
            "resource_id",
            "payload_digest",
            "status",
            "requester_id",
            "requested_at",
            "expires_at",
            "approved_by",
            "approved_at",
            "consumed_by",
            "consumed_at",
            "decision_note",
            "approver_webauthn_credential_id",
        )
    }


@dataclass(frozen=True, slots=True)
class _ControlApprovalRequestKernel:
    operation: str = "control-approval.request"
    handler: str = "ensure_control_plane_approval"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "control-approval.request",
        "ensure_control_plane_approval",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "control approval request digest")
        _exact_arguments(
            arguments,
            required=frozenset(
                {
                    "action",
                    "resource_id",
                    "payload_digest",
                    "requester_id",
                    "request",
                    "ttl_seconds",
                    "require_webauthn",
                }
            ),
        )
        item_id = core.deterministic_uuid(
            operation=self.operation,
            request_digest=request_digest,
            purpose="control-plane-approval",
        )
        return (
            _query(
                operation=self.operation,
                name="approval",
                table="control_plane_approvals",
                key={"id": item_id},
            ),
            _aggregate_query(
                self.operation,
                "approval_capacity",
                "control-plane-approvals",
                "global",
            ),
            _audit_query(self.operation, request_digest),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        _exact_arguments(
            context.arguments,
            required=frozenset(
                {
                    "action",
                    "resource_id",
                    "payload_digest",
                    "requester_id",
                    "request",
                    "ttl_seconds",
                    "require_webauthn",
                }
            ),
        )
        action = _text(
            context.arguments["action"],
            "control approval action",
            maximum_bytes=128,
        )
        resource_id = context.arguments["resource_id"]
        if resource_id is not None:
            resource_id = _text(
                resource_id,
                "control approval resource",
                maximum_bytes=512,
            )
        payload_digest = _digest(
            context.arguments["payload_digest"],
            "control approval payload",
        )
        requester_id = _text(
            context.arguments["requester_id"],
            "control approval requester",
            maximum_bytes=512,
        )
        request, request_json = _canonical_mapping(
            context.arguments["request"],
            "control approval request",
            maximum_bytes=1024 * 1024,
        )
        ttl_seconds = _integer(
            context.arguments["ttl_seconds"],
            "control approval TTL",
            minimum=1,
            maximum=3600,
        )
        require_webauthn = _boolean(
            context.arguments["require_webauthn"],
            "control approval WebAuthn requirement",
        )
        item_id = core.deterministic_uuid(
            operation=self.operation,
            request_digest=context.request_digest,
            purpose="control-plane-approval",
        )
        selected, existing = _selected_or_none(
            context,
            "control_plane_approvals",
            {"id": item_id},
        )
        if existing is None:
            requested_at = context.database_now.astimezone(
                timezone.utc
            ).isoformat()
            expires_at = (
                context.database_now.astimezone(timezone.utc)
                + timedelta(seconds=ttl_seconds)
            ).isoformat()
            row = {
                "id": item_id,
                "action": action,
                "resource_id": resource_id,
                "payload_digest": payload_digest,
                "status": "pending",
                "requester_id": requester_id,
                "requested_at": requested_at,
                "expires_at": expires_at,
                "request_json": request_json,
                "approved_by": None,
                "approved_at": None,
                "consumed_by": None,
                "consumed_at": None,
                "decision_note": None,
                "approval_authn": core.canonical_bytes(
                    {
                        "schema":
                            "serverware.controlApprovalRequirement/v1",
                        "requireWebAuthn": require_webauthn,
                    }
                ).decode("ascii"),
                "approver_webauthn_credential_id": None,
            }
            primary_mutations: tuple[dict[str, Any], ...] = (
                core.mutation(
                    operation=self.operation,
                    selected=selected,
                    row=row,
                ),
                _aggregate_update(
                    context,
                    kind="control-plane-approvals",
                    partition="global",
                    live_delta=1,
                    active_delta=1,
                    next_sequence_delta=1,
                    minimum_expiry_epoch_ns=int(
                        (
                            context.database_now.astimezone(timezone.utc)
                            + timedelta(seconds=ttl_seconds)
                        ).timestamp()
                        * 1_000_000_000
                    ),
                ),
            )
            replay = False
        else:
            expected = {
                "action": action,
                "resource_id": resource_id,
                "payload_digest": payload_digest,
                "requester_id": requester_id,
                "request_json": request_json,
            }
            if any(existing.get(field) != value for field, value in expected.items()):
                raise core.TransitionKernelError(
                    "control approval request identity was rebound"
                )
            authn = _canonical_stored_mapping(
                existing.get("approval_authn"),
                "control approval requirement",
            )
            if authn != {
                "schema": "serverware.controlApprovalRequirement/v1",
                "requireWebAuthn": require_webauthn,
            }:
                raise core.TransitionKernelError(
                    "control approval requirement changed on replay"
                )
            row = existing
            primary_mutations = ()
            replay = True
        audit_mutations, audit_digest, audit_replay = _audit_mutations(
            context,
            event_type="control_plane.approval.requested",
            actor_type="admin",
            actor_id=requester_id,
            event={
                "schema": "serverware.controlApprovalRequested/v1",
                "approvalId": item_id,
                "action": action,
                "resourceId": resource_id,
                "payloadDigest": payload_digest,
                "requesterId": requester_id,
                "request": request,
                "requestedAt": row["requested_at"],
                "expiresAt": row["expires_at"],
                "requireWebAuthn": require_webauthn,
            },
        )
        if replay != audit_replay:
            raise core.TransitionKernelError(
                "control approval replay lost its audit event"
            )
        return core.KernelTransition(
            mutations=primary_mutations + audit_mutations,
            result={
                "ok": True,
                "approval": _control_public(row),
                "audit_event_digest": audit_digest,
                "idempotent_replay": replay,
            },
            work_units=16 + len(primary_mutations) + len(audit_mutations),
        )


@dataclass(frozen=True, slots=True)
class _ControlApprovalDecisionKernel:
    operation: str
    handler: str
    decision: str
    permits_empty_mutation: bool = True

    @property
    def program_id(self) -> str:
        return core.transition_program_id(self.operation, self.handler)

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "control approval decision request")
        _exact_arguments(
            arguments,
            required=frozenset(
                {
                    "item_id",
                    "actor_id",
                    "note",
                    "required_role",
                }
            )
            | _WEBAUTHN_FIELDS,
        )
        item_id = _text(
            arguments["item_id"],
            "control approval",
            maximum_bytes=256,
        )
        actor_id = _text(
            arguments["actor_id"],
            "control approval actor",
            maximum_bytes=512,
        )
        queries: list[core.BoundedQuery] = [
            _query(
                operation=self.operation,
                name="approval",
                table="control_plane_approvals",
                key={"id": item_id},
            ),
            _role_query(
                self.operation,
                "actor_role",
                actor_id,
            ),
            *_webauthn_queries(self.operation, arguments),
            _audit_query(self.operation, request_digest),
        ]
        if self.decision == "deny":
            queries.append(
                _query(
                    operation=self.operation,
                    name="pending_oauth",
                    table="pending_oauth_credentials",
                    key={
                        "id": core.SelectedRowFieldReference(
                            table="control_plane_approvals",
                            key={"id": item_id},
                            column="resource_id",
                        )
                    },
                )
            )
        return tuple(queries)

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        _exact_arguments(
            context.arguments,
            required=frozenset(
                {
                    "item_id",
                    "actor_id",
                    "note",
                    "required_role",
                }
            )
            | _WEBAUTHN_FIELDS,
        )
        item_id = _text(
            context.arguments["item_id"],
            "control approval",
            maximum_bytes=256,
        )
        actor_id = _text(
            context.arguments["actor_id"],
            "control approval actor",
            maximum_bytes=512,
        )
        note = context.arguments["note"]
        if note is not None:
            note = _text(
                note,
                "control approval note",
                maximum_bytes=500,
                allow_empty=True,
            )
        required_role = context.arguments["required_role"]
        if required_role is not None:
            required_role = _text(
                required_role,
                "control approval role",
                maximum_bytes=128,
            )
        _require_role(
            context,
            subject_id=actor_id,
            required_role=required_role,
        )
        selected = context.exact(
            "control_plane_approvals",
            {"id": item_id},
        )
        approval = _row(selected, "control approval")
        if approval.get("requester_id") == actor_id:
            raise core.TransitionKernelError(
                "control approval self-decision is forbidden"
            )
        target = "approved" if self.decision == "approve" else "denied"
        replay = approval.get("status") == target
        expected_authn = {
            "schema": "serverware.controlApprovalWebAuthnDecision/v1",
            "decision": self.decision,
            "evidenceDigest": context.arguments["evidence_digest"],
            "requestDigest": context.request_digest,
        }
        if replay:
            if (
                approval.get("approved_by") != actor_id
                or approval.get("decision_note") != note
                or _canonical_stored_mapping(
                    approval.get("approval_authn"),
                    "control approval authentication",
                )
                != expected_authn
            ):
                raise core.TransitionKernelError(
                    "control approval decision replay conflicts"
                )
            webauthn_mutations = _webauthn_statement(
                context,
                actor_id=actor_id,
                subject_kind="control-approval",
                subject_id=item_id,
                decision=self.decision,
                replay=True,
            )
            decision_mutations: tuple[dict[str, Any], ...] = ()
            row = approval
        else:
            if (
                approval.get("status") != "pending"
                or approval.get("expires_at")
                    <= context.database_now.astimezone(
                        timezone.utc
                    ).isoformat()
            ):
                raise core.TransitionKernelError(
                    "control approval is not live and pending"
                )
            webauthn_mutations = _webauthn_statement(
                context,
                actor_id=actor_id,
                subject_kind="control-approval",
                subject_id=item_id,
                decision=self.decision,
            )
            now_s = context.database_now.astimezone(timezone.utc).isoformat()
            row = {
                **approval,
                "status": target,
                "approved_by": actor_id,
                "approved_at": now_s if target == "approved" else None,
                "decision_note": note,
                "approval_authn":
                    core.canonical_bytes(expected_authn).decode("ascii"),
                "approver_webauthn_credential_id":
                    context.arguments["credential_record_id"],
            }
            decision_mutations = (
                core.mutation(
                    operation=self.operation,
                    selected=selected,
                    row=row,
                ),
            )
            if (
                self.decision == "deny"
                and approval.get("action") == "credential.oauth.activate"
                and approval.get("resource_id") is not None
            ):
                pending_selected = context.exact(
                    "pending_oauth_credentials",
                    {"id": approval["resource_id"]},
                )
                pending = _row(
                    pending_selected,
                    "pending OAuth credential",
                )
                if (
                    pending.get("payload_digest")
                        != approval.get("payload_digest")
                    or pending.get("status") != "pending"
                ):
                    raise core.TransitionKernelError(
                        "OAuth denial target does not match the approval"
                    )
                decision_mutations += (
                    core.mutation(
                        operation=self.operation,
                        selected=pending_selected,
                        row={
                            **pending,
                            "status": "rejected",
                            "revocation_status": "pending",
                            "revocation_error": None,
                            "revocation_next_attempt_at": now_s,
                            "revocation_lease_owner": None,
                            "revocation_lease_until": None,
                            "updated_at": now_s,
                        },
                    ),
                )
        audit_mutations, audit_digest, audit_replay = _audit_mutations(
            context,
            event_type=f"control_plane.approval.{target}",
            actor_type="admin",
            actor_id=actor_id,
            event={
                "schema": "serverware.controlApprovalDecision/v1",
                "approvalId": item_id,
                "action": approval.get("action"),
                "resourceId": approval.get("resource_id"),
                "payloadDigest": approval.get("payload_digest"),
                "requesterId": approval.get("requester_id"),
                "decision": self.decision,
                "decisionBy": actor_id,
                "evidenceDigest": context.arguments["evidence_digest"],
                "note": note,
            },
        )
        if replay != audit_replay:
            raise core.TransitionKernelError(
                "control approval decision lost its audit replay"
            )
        return core.KernelTransition(
            mutations=(
                tuple(webauthn_mutations)
                + decision_mutations
                + audit_mutations
            ),
            result={
                "ok": True,
                "approval": _control_public(row),
                "audit_event_digest": audit_digest,
                "idempotent_replay": replay,
            },
            work_units=28
                + len(webauthn_mutations)
                + len(decision_mutations)
                + len(audit_mutations),
        )


@dataclass(frozen=True, slots=True)
class _ControlApprovalConsumeKernel:
    operation: str = "control-approval.consume"
    handler: str = "consume_control_plane_approval"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "control-approval.consume",
        "consume_control_plane_approval",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "control approval consumption request")
        _exact_arguments(
            arguments,
            required=frozenset(
                {
                    "item_id",
                    "action",
                    "resource_id",
                    "payload_digest",
                    "actor_id",
                    "requester_role",
                    "approver_role",
                }
            )
            | _WEBAUTHN_FIELDS,
        )
        item_id = _text(
            arguments["item_id"],
            "control approval",
            maximum_bytes=256,
        )
        actor_id = _text(
            arguments["actor_id"],
            "control approval consumer",
            maximum_bytes=512,
        )
        return (
            _query(
                operation=self.operation,
                name="approval",
                table="control_plane_approvals",
                key={"id": item_id},
            ),
            _role_query(
                self.operation,
                "requester_role",
                actor_id,
            ),
            _role_query(
                self.operation,
                "approver_role",
                core.SelectedRowFieldReference(
                    table="control_plane_approvals",
                    key={"id": item_id},
                    column="approved_by",
                ),
            ),
            *_webauthn_queries(self.operation, arguments),
            _audit_query(self.operation, request_digest),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        required = frozenset(
            {
                "item_id",
                "action",
                "resource_id",
                "payload_digest",
                "actor_id",
                "requester_role",
                "approver_role",
            }
        ) | _WEBAUTHN_FIELDS
        _exact_arguments(context.arguments, required=required)
        item_id = _text(
            context.arguments["item_id"],
            "control approval",
            maximum_bytes=256,
        )
        actor_id = _text(
            context.arguments["actor_id"],
            "control approval consumer",
            maximum_bytes=512,
        )
        selected = context.exact(
            "control_plane_approvals",
            {"id": item_id},
        )
        approval = _row(selected, "control approval")
        resource_id = context.arguments["resource_id"]
        if resource_id is not None:
            resource_id = _text(
                resource_id,
                "control approval resource",
                maximum_bytes=512,
            )
        if (
            approval.get("action")
                != _text(
                    context.arguments["action"],
                    "control approval action",
                    maximum_bytes=128,
                )
            or approval.get("resource_id") != resource_id
            or approval.get("payload_digest")
                != _digest(
                    context.arguments["payload_digest"],
                    "control approval payload",
                )
            or approval.get("requester_id") != actor_id
            or approval.get("approved_by") == actor_id
        ):
            raise core.TransitionKernelError(
                "control approval consumption binding differs"
            )
        _require_role(
            context,
            subject_id=actor_id,
            required_role=context.arguments["requester_role"],
        )
        approver_id = _text(
            approval.get("approved_by"),
            "control approval approver",
            maximum_bytes=512,
        )
        _require_role(
            context,
            subject_id=approver_id,
            required_role=context.arguments["approver_role"],
        )
        replay = approval.get("status") == "consumed"
        if replay:
            if approval.get("consumed_by") != actor_id:
                raise core.TransitionKernelError(
                    "control approval consumption replay conflicts"
                )
            webauthn_mutations = _webauthn_statement(
                context,
                actor_id=actor_id,
                subject_kind="control-approval-consumption",
                subject_id=item_id,
                decision="consume",
                replay=True,
            )
            row = approval
            approval_mutations: tuple[dict[str, Any], ...] = ()
        else:
            if (
                approval.get("status") != "approved"
                or approval.get("expires_at")
                    <= context.database_now.astimezone(
                        timezone.utc
                    ).isoformat()
            ):
                raise core.TransitionKernelError(
                    "control approval is not consumable"
                )
            webauthn_mutations = _webauthn_statement(
                context,
                actor_id=actor_id,
                subject_kind="control-approval-consumption",
                subject_id=item_id,
                decision="consume",
            )
            now_s = context.database_now.astimezone(timezone.utc).isoformat()
            row = {
                **approval,
                "status": "consumed",
                "consumed_by": actor_id,
                "consumed_at": now_s,
            }
            approval_mutations = (
                core.mutation(
                    operation=self.operation,
                    selected=selected,
                    row=row,
                ),
            )
        audit_mutations, audit_digest, audit_replay = _audit_mutations(
            context,
            event_type="control_plane.approval.consumed",
            actor_type="admin",
            actor_id=actor_id,
            event={
                "schema": "serverware.controlApprovalConsumed/v1",
                "approvalId": item_id,
                "action": approval.get("action"),
                "resourceId": approval.get("resource_id"),
                "payloadDigest": approval.get("payload_digest"),
                "requesterId": actor_id,
                "approvedBy": approver_id,
                "evidenceDigest": context.arguments["evidence_digest"],
            },
        )
        if replay != audit_replay:
            raise core.TransitionKernelError(
                "control approval consumption lost its audit replay"
            )
        return core.KernelTransition(
            mutations=(
                tuple(webauthn_mutations)
                + approval_mutations
                + audit_mutations
            ),
            result={
                "ok": True,
                "approval": _control_public(row),
                "audit_event_digest": audit_digest,
                "idempotent_replay": replay,
            },
            work_units=32
                + len(webauthn_mutations)
                + len(approval_mutations)
                + len(audit_mutations),
        )


def _opaque_evidence_query(
    operation: str,
    *,
    name: str,
    opaque_id: str,
) -> core.BoundedQuery:
    return _query(
        operation=operation,
        name=name,
        table="policy_authority_external_evidence_receipts",
        key={
            "evidence_digest": core.SelectedRowFieldReference(
                table="policy_authority_opaque_values",
                key={"opaque_id": opaque_id},
                column="producer_evidence_digest",
            )
        },
    )


def _jit_opaque_binding(
    *,
    value_kind: str,
    item_id: str,
    request_digest: str,
    plaintext_digest: str,
) -> str:
    return core.framed_digest(
        "serverware.policyAuthorityJitOpaqueValueBinding/v1",
        core.canonical_bytes(
            {
                "schema":
                    "serverware.policyAuthorityJitOpaqueValueBinding/v1",
                "valueKind": value_kind,
                "approvalRequestId": item_id,
                "requestDigest": request_digest,
                "plaintextDigest": plaintext_digest,
            }
        ),
    )


def _jit_public(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        field: row.get(field)
        for field in (
            "id",
            "route_id",
            "method",
            "url",
            "status",
            "requested_at",
            "expires_at",
            "approved_until",
            "decision_note",
            "principal_id",
            "credential_id",
            "credential_version",
            "policy_hash",
            "request_digest",
            "operation_digest",
            "grant_ttl_seconds",
            "grant_max_uses",
            "approver_policy_digest",
            "verified_assertion_receipt_digest",
            "approved_by",
        )
    }


@dataclass(frozen=True, slots=True)
class _JitRequestKernel:
    operation: str = "jit.request"
    handler: str = "ensure_jit_approval_request"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "jit.request",
        "ensure_jit_approval_request",
    )

    _FIELDS = jit_request.FIELDS

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        arguments = jit_request.normalize(arguments, request_digest=request_digest)
        item_id = core.deterministic_uuid(
            operation=self.operation,
            request_digest=request_digest,
            purpose="jit-approval-request",
        )
        route_id = _text(
            arguments["route_id"],
            "JIT route",
            maximum_bytes=512,
        )
        canonical_id = _text(
            arguments["canonical_request_opaque_id"],
            "JIT canonical request opaque value",
            maximum_bytes=256,
        )
        display_id = _text(
            arguments["redacted_display_opaque_id"],
            "JIT display opaque value",
            maximum_bytes=256,
        )
        return (
            _query(
                operation=self.operation,
                name="approval",
                table="approval_requests",
                key={"id": item_id},
            ),
            _query(
                operation=self.operation,
                name="route",
                table="routes",
                key={"id": route_id},
            ),
            _query(
                operation=self.operation,
                name="canonical_value",
                table="policy_authority_opaque_values",
                key={"opaque_id": canonical_id},
            ),
            _opaque_evidence_query(
                self.operation,
                name="canonical_value_evidence",
                opaque_id=canonical_id,
            ),
            _query(
                operation=self.operation,
                name="display_value",
                table="policy_authority_opaque_values",
                key={"opaque_id": display_id},
            ),
            _opaque_evidence_query(
                self.operation,
                name="display_value_evidence",
                opaque_id=display_id,
            ),
            _aggregate_query(
                self.operation,
                "pending_capacity",
                "jit-pending-approvals",
                "global",
            ),
            _audit_query(self.operation, request_digest),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        arguments = jit_request.normalize(
            context.arguments, request_digest=context.request_digest,
        )
        route_id = _text(
            arguments["route_id"],
            "JIT route",
            maximum_bytes=512,
        )
        method = _text(
            arguments["method"],
            "JIT method",
            maximum_bytes=32,
        ).upper()
        if method != arguments["method"]:
            raise core.TransitionKernelError(
                "JIT method is not canonical uppercase"
            )
        url_commitment = _digest(
            arguments["url_commitment"],
            "JIT URL commitment",
        )
        principal_id = _text(
            arguments["principal_id"],
            "JIT principal",
            maximum_bytes=512,
        )
        credential_id = _text(
            arguments["credential_id"],
            "JIT credential",
            maximum_bytes=512,
            allow_empty=True,
        )
        credential_version = _integer(
            arguments["credential_version"],
            "JIT credential version",
        )
        policy_hash = _digest(
            arguments["policy_hash"],
            "JIT policy",
        )
        bound_request_digest = _digest(
            arguments["request_digest"],
            "JIT bound request",
        )
        operation_digest = _optional_digest(
            arguments["operation_digest"],
            "JIT operation",
        )
        canonical_digest = _digest(
            arguments["canonical_request_digest"],
            "JIT canonical request plaintext",
        )
        display_digest = _digest(
            arguments["redacted_display_digest"],
            "JIT redacted display plaintext",
        )
        pending_ttl = _integer(
            arguments["pending_ttl_seconds"],
            "JIT pending TTL",
            minimum=1,
            maximum=3600,
        )
        grant_ttl = _integer(
            arguments["grant_ttl_seconds"],
            "JIT grant TTL",
            minimum=1,
            maximum=3600,
        )
        grant_max_uses = _integer(
            arguments["grant_max_uses"],
            "JIT grant uses",
            minimum=1,
            maximum=1_000_000,
        )
        approver_policy, approver_policy_json = _canonical_mapping(
            arguments["approver_policy"],
            "JIT approver policy",
        )
        if (
            approver_policy.get("schema")
                != "serverware.jitApproverPolicy/v1"
            or approver_policy.get("requireWebAuthn") is not True
            or not isinstance(approver_policy.get("threshold"), int)
            or isinstance(approver_policy.get("threshold"), bool)
            or not 1 <= approver_policy["threshold"] <= 16
        ):
            raise core.TransitionKernelError(
                "JIT approver policy is not closed"
            )
        approver_policy_digest = _digest(
            arguments["approver_policy_digest"],
            "JIT approver policy digest",
        )
        if approver_policy_digest != core.framed_digest(
            "serverware.jitApproverPolicy/v1",
            approver_policy_json.encode("ascii"),
        ):
            raise core.TransitionKernelError(
                "JIT approver policy digest differs"
            )
        item_id = core.deterministic_uuid(
            operation=self.operation,
            request_digest=context.request_digest,
            purpose="jit-approval-request",
        )
        canonical_id = _text(
            arguments["canonical_request_opaque_id"],
            "JIT canonical request opaque value",
            maximum_bytes=256,
        )
        display_id = _text(
            arguments["redacted_display_opaque_id"],
            "JIT display opaque value",
            maximum_bytes=256,
        )
        canonical_value = context.opaque_value(
            value_kind="approval-secret-json/v1",
            opaque_id=canonical_id,
            binding_digest=_jit_opaque_binding(
                value_kind="approval-secret-json/v1",
                item_id=item_id,
                request_digest=bound_request_digest,
                plaintext_digest=canonical_digest,
            ),
        )
        display_value = context.opaque_value(
            value_kind="approval-review-json/v1",
            opaque_id=display_id,
            binding_digest=_jit_opaque_binding(
                value_kind="approval-review-json/v1",
                item_id=item_id,
                request_digest=bound_request_digest,
                plaintext_digest=display_digest,
            ),
        )
        # The custody owner fixed both document lifetimes before planning.
        # Neither delayed admission nor replay may restart that original TTL.
        document_expiry_ns = min(
            _integer(value.get("expires_at_epoch_ns"),
                "JIT original document expiry", minimum=1,
                maximum=_SIGNED_BIGINT_MAX)
            for value in (canonical_value, display_value)
        )
        now_ns = core._epoch_nanoseconds(context.database_now)
        expiry_ns = min(now_ns + pending_ttl * 1_000_000_000,
            document_expiry_ns)
        # PostgreSQL timestamps and datetime represent microseconds. Round
        # down, never past either authenticated nanosecond document bound.
        expiry = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
            microseconds=expiry_ns // 1_000)
        stored_expiry_ns = core._epoch_nanoseconds(expiry)
        if stored_expiry_ns <= now_ns:
            raise core.TransitionKernelError(
                "JIT original document lifetime has no usable remainder"
            )
        pending_key = core.framed_digest(
            "serverware.jitPendingApproval/v2",
            core.canonical_bytes(
                {
                    "routeId": route_id,
                    "method": method,
                    "urlCommitment": url_commitment,
                    "principalId": principal_id,
                    "credentialId": credential_id,
                    "credentialVersion": credential_version,
                    "policyHash": policy_hash,
                    "requestDigest": bound_request_digest,
                    "operationDigest": operation_digest,
                    "grantTtlSeconds": grant_ttl,
                    "grantMaxUses": grant_max_uses,
                    "approverPolicyDigest": approver_policy_digest,
                }
            ),
        )
        selected, existing = _selected_or_none(
            context,
            "approval_requests",
            {"id": item_id},
        )
        route_selected, route = _selected_or_none(
            context,
            "routes",
            {"id": route_id},
        )
        now_s = context.database_now.astimezone(timezone.utc).isoformat()
        if route is None:
            route_mutations: tuple[dict[str, Any], ...] = (
                core.mutation(
                    operation=self.operation,
                    selected=route_selected,
                    row={
                        "id": route_id,
                        "name": f"Policy bundle route {route_id}",
                        "enabled": 0,
                        "match_host": "__policy_bundle__",
                        "match_path_prefix": "/",
                        "credential_id": None,
                        "injection": "{}",
                        "policies": "[]",
                        "created_at": now_s,
                        "updated_at": now_s,
                    },
                ),
            )
        else:
            route_mutations = ()
        immutable = {
            "route_id": route_id,
            "method": method,
            "url": url_commitment,
            "principal_id": principal_id,
            "credential_id": credential_id,
            "credential_version": credential_version,
            "policy_hash": policy_hash,
            "request_digest": bound_request_digest,
            "operation_digest": operation_digest,
            "canonical_request": canonical_value["ciphertext_base64url"],
            "redacted_display": display_value["ciphertext_base64url"],
            "grant_ttl_seconds": grant_ttl,
            "grant_max_uses": grant_max_uses,
            "pending_key": pending_key,
            "approver_policy_json": approver_policy_json,
            "approver_policy_digest": approver_policy_digest,
        }
        if existing is None:
            row = {
                "id": item_id,
                **immutable,
                "status": "pending",
                "requested_at": now_s,
                "expires_at": expiry.isoformat(),
                "approved_until": None,
                "decision_note": None,
                "approved_by": None,
                "approval_authn": None,
                "approver_webauthn_credential_id": None,
                "verified_assertion_receipt_digest": None,
                "approval_challenge_id": None,
            }
            request_mutations: tuple[dict[str, Any], ...] = (
                core.mutation(
                    operation=self.operation,
                    selected=selected,
                    row=row,
                ),
                _aggregate_update(
                    context,
                    kind="jit-pending-approvals",
                    partition="global",
                    live_delta=1,
                    active_delta=1,
                    next_sequence_delta=1,
                    minimum_expiry_epoch_ns=stored_expiry_ns,
                ),
            )
            replay = False
        else:
            if any(
                existing.get(field) != value
                for field, value in immutable.items()
            ):
                raise core.TransitionKernelError(
                    "JIT request identity was rebound"
                )
            try:
                retained_expiry_ns = core._epoch_nanoseconds(
                    datetime.fromisoformat(existing["expires_at"]))
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                raise core.TransitionKernelError(
                    "JIT retained request expiry is invalid"
                ) from exc
            if not 0 < retained_expiry_ns <= document_expiry_ns:
                raise core.TransitionKernelError(
                    "JIT retained request exceeds its original document lifetime"
                )
            row = existing
            request_mutations = ()
            replay = True
        audit_mutations, audit_digest, audit_replay = _audit_mutations(
            context,
            event_type="approval.requested",
            actor_type="proxy",
            actor_id=principal_id,
            event={
                "schema": "serverware.jitApprovalRequested/v2",
                "approvalRequestId": item_id,
                "routeId": route_id,
                "principalId": principal_id,
                "credentialId": credential_id,
                "credentialVersion": credential_version,
                "policyHash": policy_hash,
                "requestDigest": bound_request_digest,
                "operationDigest": operation_digest,
                "method": method,
                "urlCommitment": url_commitment,
                "expiresAt": row["expires_at"],
                "grantTtlSeconds": grant_ttl,
                "grantMaxUses": grant_max_uses,
                "approverPolicyDigest": approver_policy_digest,
            },
        )
        if replay != audit_replay:
            raise core.TransitionKernelError(
                "JIT request lost its audit replay"
            )
        return core.KernelTransition(
            mutations=route_mutations + request_mutations + audit_mutations,
            result={
                **_jit_public(row),
                "approval_created": not replay,
                "audit_event_digest": audit_digest,
                "idempotent_replay": replay,
            },
            work_units=40
                + len(route_mutations)
                + len(request_mutations)
                + len(audit_mutations),
        )


@dataclass(frozen=True, slots=True)
class _JitReviewReceiptKernel:
    operation: str = "jit.review-receipt.issue"
    handler: str = "issue_approval_review_receipt"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "jit.review-receipt.issue",
        "issue_approval_review_receipt",
    )

    _FIELDS = frozenset(
        {
            "approval_request_id",
            "reviewer_id",
            "review_digest",
            "ttl_seconds",
        }
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "JIT review receipt request")
        _exact_arguments(arguments, required=self._FIELDS)
        approval_id = _text(
            arguments["approval_request_id"],
            "JIT approval request",
            maximum_bytes=512,
        )
        receipt_id = core.deterministic_uuid(
            operation=self.operation,
            request_digest=request_digest,
            purpose="jit-review-receipt",
        )
        return (
            _query(
                operation=self.operation,
                name="approval",
                table="approval_requests",
                key={"id": approval_id},
            ),
            _query(
                operation=self.operation,
                name="receipt",
                table="approval_review_receipts",
                key={"id": receipt_id},
            ),
            _aggregate_query(
                self.operation,
                "receipt_capacity",
                "jit-review-receipts",
                "global",
            ),
            _audit_query(self.operation, request_digest),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        _exact_arguments(context.arguments, required=self._FIELDS)
        approval_id = _text(
            context.arguments["approval_request_id"],
            "JIT approval request",
            maximum_bytes=512,
        )
        reviewer_id = _text(
            context.arguments["reviewer_id"],
            "JIT reviewer",
            maximum_bytes=512,
        )
        review_digest = _digest(
            context.arguments["review_digest"],
            "JIT review digest",
        )
        ttl_seconds = _integer(
            context.arguments["ttl_seconds"],
            "JIT review receipt TTL",
            minimum=30,
            maximum=300,
        )
        approval = _row(
            context.exact(
                "approval_requests",
                {"id": approval_id},
            ),
            "JIT approval request",
        )
        now_s = context.database_now.astimezone(timezone.utc).isoformat()
        if (
            approval.get("status") != "pending"
            or approval.get("expires_at") <= now_s
        ):
            raise core.TransitionKernelError(
                "JIT review receipt requires a live pending approval"
            )
        receipt_id = core.deterministic_uuid(
            operation=self.operation,
            request_digest=context.request_digest,
            purpose="jit-review-receipt",
        )
        selected, existing = _selected_or_none(
            context,
            "approval_review_receipts",
            {"id": receipt_id},
        )
        immutable = {
            "approval_request_id": approval_id,
            "reviewer_id": reviewer_id,
            "review_digest": review_digest,
        }
        if existing is None:
            row = {
                "id": receipt_id,
                **immutable,
                "expires_at": (
                    context.database_now.astimezone(timezone.utc)
                    + timedelta(seconds=ttl_seconds)
                ).isoformat(),
                "used_at": None,
                "created_at": now_s,
            }
            receipt_mutations: tuple[dict[str, Any], ...] = (
                core.mutation(
                    operation=self.operation,
                    selected=selected,
                    row=row,
                ),
                _aggregate_update(
                    context,
                    kind="jit-review-receipts",
                    partition="global",
                    live_delta=1,
                    active_delta=1,
                    next_sequence_delta=1,
                    minimum_expiry_epoch_ns=int(
                        (
                            context.database_now.astimezone(timezone.utc)
                            + timedelta(seconds=ttl_seconds)
                        ).timestamp()
                        * 1_000_000_000
                    ),
                ),
            )
            replay = False
        else:
            if any(
                existing.get(field) != value
                for field, value in immutable.items()
            ):
                raise core.TransitionKernelError(
                    "JIT review receipt identity was rebound"
                )
            row = existing
            receipt_mutations = ()
            replay = True
        audit_mutations, audit_digest, audit_replay = _audit_mutations(
            context,
            event_type="approval.review_opened",
            actor_type="admin",
            actor_id=reviewer_id,
            event={
                "schema": "serverware.jitApprovalReviewReceipt/v1",
                "approvalRequestId": approval_id,
                "reviewDigest": review_digest,
                "reviewReceiptId": receipt_id,
                "expiresAt": row["expires_at"],
            },
        )
        if replay != audit_replay:
            raise core.TransitionKernelError(
                "JIT review receipt lost its audit replay"
            )
        return core.KernelTransition(
            mutations=receipt_mutations + audit_mutations,
            result={
                **row,
                "audit_event_digest": audit_digest,
                "idempotent_replay": replay,
            },
            work_units=24
                + len(receipt_mutations)
                + len(audit_mutations),
        )


def _stored_jit_policy(
    approval: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    policy = _canonical_stored_mapping(
        approval.get("approver_policy_json"),
        "stored JIT approver policy",
    )
    policy_json = core.canonical_bytes(policy).decode("ascii")
    policy_digest = core.framed_digest(
        "serverware.jitApproverPolicy/v1",
        policy_json.encode("ascii"),
    )
    if (
        approval.get("approver_policy_digest") != policy_digest
        or policy.get("schema") != "serverware.jitApproverPolicy/v1"
        or policy.get("requireWebAuthn") is not True
        or not isinstance(policy.get("threshold"), int)
        or isinstance(policy.get("threshold"), bool)
        or not 1 <= policy["threshold"] <= 16
        or not isinstance(policy.get("allowedApproverIds"), list)
        or not isinstance(policy.get("requiredRoles"), list)
    ):
        raise core.TransitionKernelError(
            "stored JIT approver policy is not authoritative"
        )
    return policy, policy_digest


def _authorize_jit_actor(
    context: core.KernelContext,
    *,
    approval: Mapping[str, Any],
    actor_id: str,
    required_role: str | None,
) -> tuple[dict[str, Any], str]:
    policy, policy_digest = _stored_jit_policy(approval)
    allowed = policy["allowedApproverIds"]
    if policy.get("allowAnyApproverId") is not True and actor_id not in allowed:
        raise core.TransitionKernelError(
            "JIT actor is outside the exact approver set"
        )
    policy_roles = policy["requiredRoles"]
    if required_role is not None and required_role not in policy_roles:
        raise core.TransitionKernelError(
            "JIT caller role differs from the stored policy"
        )
    effective_role = (
        required_role
        if required_role is not None
        else policy_roles[0] if policy_roles else None
    )
    _require_role(
        context,
        subject_id=actor_id,
        required_role=effective_role,
    )
    return policy, policy_digest


def _jit_hardware_binding(
    approval: Mapping[str, Any],
    *,
    grant_id: str,
    actor_id: str,
    verified_assertion_receipt_digest: str,
    authority_capability_id: str | None = None,
) -> dict[str, Any]:
    return {
        "approvalRequestId": approval.get("id"),
        "grantId": grant_id,
        "actorId": actor_id,
        "principalId": approval.get("principal_id"),
        "routeId": approval.get("route_id"),
        "credentialId": approval.get("credential_id"),
        "credentialVersion": approval.get("credential_version"),
        "policyHash": approval.get("policy_hash"),
        "requestDigest": approval.get("request_digest"),
        "operationDigest": approval.get("operation_digest"),
        "approverPolicyDigest": approval.get("approver_policy_digest"),
        "verifiedAssertionReceiptDigest":
            verified_assertion_receipt_digest,
        "authorityCapabilityId": authority_capability_id,
    }


@dataclass(frozen=True, slots=True)
class _JitDecideKernel:
    operation: str = "jit.decide"
    handler: str = "approve_request"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id("jit.decide", "approve_request")

    def queries(self, **kwargs):
        from serverware.authority_transition_jit_approval import JitDecideKernel
        return JitDecideKernel().queries(**kwargs)

    def queries_with_evidence(self, **kwargs):
        from serverware.authority_transition_jit_approval import JitDecideKernel
        return JitDecideKernel().queries_with_evidence(**kwargs)

    def transition(self, context):
        from serverware.authority_transition_jit_approval import JitDecideKernel
        return JitDecideKernel().transition(context)


@dataclass(frozen=True, slots=True)
class _JitDenyKernel:
    operation: str = "jit.deny"
    handler: str = "deny_request"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id("jit.deny", "deny_request")

    def queries(self, **kwargs):
        from serverware.authority_transition_jit_denial import JitDenyKernel
        return JitDenyKernel().queries(**kwargs)

    def queries_with_evidence(self, **kwargs):
        from serverware.authority_transition_jit_denial import JitDenyKernel
        return JitDenyKernel().queries_with_evidence(**kwargs)

    def transition(self, context):
        from serverware.authority_transition_jit_denial import JitDenyKernel
        return JitDenyKernel().transition(context)


@dataclass(frozen=True, slots=True)
class _JitConsumeKernel:
    operation: str = "jit.consume"
    handler: str = "consume_jit_grant_result"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "jit.consume",
        "consume_jit_grant_result",
    )

    _FIELDS = (
        frozenset(
            {
                "grant_id",
                "principal_id",
                "route_id",
                "bound_credential_id",
                "credential_version",
                "policy_hash",
                "bound_request_digest",
                "operation_digest",
                "flow_id",
                "attempt_id",
                "verified_assertion_receipt_digest",
                "authority_capability_id",
            }
        )
        | _WEBAUTHN_FIELDS
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "JIT consumption request")
        _exact_arguments(arguments, required=self._FIELDS)
        grant_id = _text(
            arguments["grant_id"],
            "JIT grant",
            maximum_bytes=512,
        )
        consumption_id = core.deterministic_uuid(
            operation=self.operation,
            request_digest=request_digest,
            purpose="jit-grant-consumption",
        )
        return (
            _query(
                operation=self.operation,
                name="grant",
                table="approval_grants",
                key={"id": grant_id},
            ),
            _query(
                operation=self.operation,
                name="consumption",
                table="approval_grant_consumptions",
                key={"id": consumption_id},
            ),
            *_webauthn_queries(self.operation, arguments),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        _exact_arguments(context.arguments, required=self._FIELDS)
        grant_id = _text(
            context.arguments["grant_id"],
            "JIT grant",
            maximum_bytes=512,
        )
        principal_id = _text(
            context.arguments["principal_id"],
            "JIT principal",
            maximum_bytes=512,
        )
        route_id = _text(
            context.arguments["route_id"],
            "JIT route",
            maximum_bytes=512,
        )
        credential_id = _text(
            context.arguments["bound_credential_id"],
            "JIT bound credential",
            maximum_bytes=512,
        )
        credential_version = _integer(
            context.arguments["credential_version"],
            "JIT credential version",
        )
        policy_hash = _digest(
            context.arguments["policy_hash"],
            "JIT policy",
        )
        bound_request_digest = _digest(
            context.arguments["bound_request_digest"],
            "JIT bound request",
        )
        operation_digest = _optional_digest(
            context.arguments["operation_digest"],
            "JIT operation",
        )
        flow_id = _text(
            context.arguments["flow_id"],
            "JIT flow",
            maximum_bytes=512,
        )
        attempt_id = _text(
            context.arguments["attempt_id"],
            "JIT attempt",
            maximum_bytes=512,
        )
        grant_selected = context.exact(
            "approval_grants",
            {"id": grant_id},
        )
        grant = _row(grant_selected, "JIT grant")
        binding = {
            "principal_id": principal_id,
            "route_id": route_id,
            "credential_id": credential_id,
            "credential_version": credential_version,
            "policy_hash": policy_hash,
            "request_digest": bound_request_digest,
            "operation_digest": operation_digest,
        }
        if any(grant.get(field) != value for field, value in binding.items()):
            raise core.TransitionKernelError(
                "JIT grant binding differs from the request"
            )
        consumption_id = core.deterministic_uuid(
            operation=self.operation,
            request_digest=context.request_digest,
            purpose="jit-grant-consumption",
        )
        consumption_selected, prior = _selected_or_none(
            context,
            "approval_grant_consumptions",
            {"id": consumption_id},
        )
        replay = prior is not None
        hardware_binding = {
            "grantId": grant_id,
            "approvalRequestId": grant.get("approval_request_id"),
            "attemptId": attempt_id,
            "flowId": flow_id,
            "principalId": principal_id,
            "routeId": route_id,
            "credentialId": credential_id,
            "credentialVersion": credential_version,
            "policyHash": policy_hash,
            "requestDigest": bound_request_digest,
            "operationDigest": operation_digest,
        }
        if replay:
            expected = {
                "grant_id": grant_id,
                "approval_request_id": grant.get("approval_request_id"),
                "attempt_id": attempt_id,
                "flow_id": flow_id,
                **binding,
                "approver_policy_digest":
                    grant.get("approver_policy_digest"),
                "verified_assertion_receipt_digest":
                    context.arguments[
                        "verified_assertion_receipt_digest"
                    ],
                "authority_capability_id":
                    context.arguments["authority_capability_id"],
                "authority_request_digest": context.request_digest,
                "outcome": "consumed",
            }
            if any(prior.get(field) != value for field, value in expected.items()):
                raise core.TransitionKernelError(
                    "JIT consumption replay conflicts"
                )
            webauthn_mutations = _webauthn_statement(
                context,
                actor_id=principal_id,
                subject_kind="jit-grant",
                subject_id=grant_id,
                decision="consume",
                replay=True,
                business_binding=hardware_binding,
            )
            mutations: tuple[dict[str, Any], ...] = tuple(
                webauthn_mutations
            )
            result_row = prior
        else:
            now_s = context.database_now.astimezone(timezone.utc).isoformat()
            uses_before = _integer(
                grant.get("uses_remaining"),
                "JIT grant uses",
                minimum=1,
                maximum=1_000_000,
            )
            if (
                grant.get("state") != "active"
                or not grant.get("valid_from") <= now_s < grant.get("expires_at")
            ):
                raise core.TransitionKernelError(
                    "JIT grant is not live and active"
                )
            uses_after = uses_before - 1
            webauthn_mutations = _webauthn_statement(
                context,
                actor_id=principal_id,
                subject_kind="jit-grant",
                subject_id=grant_id,
                decision="consume",
                business_binding=hardware_binding,
            )
            grant_after = {
                **grant,
                "state": "consumed" if uses_after == 0 else "active",
                "uses_remaining": uses_after,
                "consumed_at": now_s if uses_after == 0 else None,
                "consumed_by_flow_id": flow_id if uses_after == 0 else None,
                "updated_at": now_s,
            }
            result_row = {
                "id": consumption_id,
                "grant_id": grant_id,
                "approval_request_id": grant.get("approval_request_id"),
                "attempt_id": attempt_id,
                "flow_id": flow_id,
                **binding,
                "approver_policy_digest":
                    grant.get("approver_policy_digest"),
                "verified_assertion_receipt_digest":
                    context.arguments[
                        "verified_assertion_receipt_digest"
                    ],
                "authority_capability_id":
                    context.arguments["authority_capability_id"],
                "authority_request_digest": context.request_digest,
                "outcome": "consumed",
                "uses_remaining_before": uses_before,
                "uses_remaining_after": uses_after,
                "created_at": now_s,
                "audited_at": None,
                "audit_event_hash": None,
            }
            mutations = (
                tuple(webauthn_mutations)
                + (
                    core.mutation(
                        operation=self.operation,
                        selected=grant_selected,
                        row=grant_after,
                    ),
                    core.mutation(
                        operation=self.operation,
                        selected=consumption_selected,
                        row=result_row,
                    ),
                )
            )
        return core.KernelTransition(
            mutations=mutations,
            result={
                "ok": True,
                "grant_id": grant_id,
                "consumption_id": consumption_id,
                "outcome": "consumed",
                "uses_remaining_before":
                    result_row.get("uses_remaining_before"),
                "uses_remaining_after":
                    result_row.get("uses_remaining_after"),
                "idempotent_replay": replay,
            },
            work_units=36 + len(mutations),
        )


def _consume_exact_evidence(
    context: core.KernelContext,
    *,
    evidence_type: str,
    evidence_digest: str,
    binding: Mapping[str, Any],
    replay: bool = False,
) -> tuple[dict[str, Any], ...]:
    binding_value = dict(binding)
    binding_digest = core.framed_digest(
        "serverware.policyAuthorityTypedExternalEvidenceBinding/v1",
        evidence_type.encode("ascii"),
        core.canonical_bytes(binding_value),
    )
    operation_id = f"{context.operation}:{context.request_digest}"
    row = (
        context.consumed_evidence(
            evidence_type=evidence_type,
            evidence_digest=evidence_digest,
            binding_digest=binding_digest,
            consumed_operation_id=operation_id,
        )
        if replay
        else context.evidence(
            evidence_type=evidence_type,
            evidence_digest=evidence_digest,
            binding_digest=binding_digest,
        )
    )
    statement = _canonical_stored_mapping(
        row.get("statement_json"),
        f"{evidence_type} statement",
    )
    if (
        set(statement)
        != set(binding_value) | {"issuedAtEpochNs", "expiresAtEpochNs"}
        or any(
            statement.get(field) != value
            for field, value in binding_value.items()
        )
        or not isinstance(statement.get("issuedAtEpochNs"), int)
        or isinstance(statement.get("issuedAtEpochNs"), bool)
        or not isinstance(statement.get("expiresAtEpochNs"), int)
        or isinstance(statement.get("expiresAtEpochNs"), bool)
        or not statement["issuedAtEpochNs"]
            <= _database_epoch_ns(context.database_now)
            < statement["expiresAtEpochNs"]
    ):
        raise core.TransitionKernelError(
            f"{evidence_type} statement is not exact"
        )
    if replay:
        return ()
    return (
        context.consume_evidence(
            evidence_type=evidence_type,
            evidence_digest=evidence_digest,
            binding_digest=binding_digest,
            operation_id=operation_id,
        ),
    )


def _calendar_window_bounds(
    window_kind: str,
    now_ms: int,
) -> tuple[int, int]:
    now = (
        datetime(1970, 1, 1, tzinfo=timezone.utc)
        + timedelta(milliseconds=now_ms)
    )
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if window_kind == "utcDay":
        start = day
        end = start + timedelta(days=1)
    elif window_kind == "utcIsoWeek":
        start = day - timedelta(days=day.weekday())
        end = start + timedelta(days=7)
    elif window_kind == "utcMonth":
        start = day.replace(day=1)
        end = (
            start.replace(year=start.year + 1, month=1)
            if start.month == 12
            else start.replace(month=start.month + 1)
        )
    else:
        raise core.TransitionKernelError(
            "rate limit calendar window is invalid"
        )
    return (
        int(start.timestamp() * 1000),
        int(end.timestamp() * 1000),
    )


def _rate_result(
    *,
    counter_key: str,
    window_kind: str,
    window_start: int,
    window_end: int,
    max_count: int,
    count: int,
    now_ms: int,
    consumed: bool,
) -> dict[str, Any]:
    allowed = count <= max_count and (not consumed or count > 0)
    if count >= max_count and not consumed:
        allowed = False
    return {
        "allowed": allowed,
        "consumed": consumed,
        "reason": (
            "consumed"
            if consumed
            else "available" if allowed
            else "rate_limited"
        ),
        "counter_key": counter_key,
        "window_kind": window_kind,
        "window_start_epoch_ms": window_start,
        "window_end_epoch_ms": window_end,
        "window_seconds": (
            (window_end - window_start) // 1000
            if window_kind == "fixed"
            else None
        ),
        "calendar_window": (
            window_kind if window_kind != "fixed" else None
        ),
        "window_span_seconds": (window_end - window_start) // 1000,
        "max": max_count,
        "count": count,
        "remaining": max(max_count - count, 0),
        "retry_after_seconds": (
            0
            if allowed
            else max(1, (window_end - now_ms + 999) // 1000)
        ),
        "rate_limit_store_backend": "postgres",
        "rate_limit_store_ha": True,
    }


@dataclass(frozen=True, slots=True)
class _RateConsumeKernel:
    operation: str = "quota.rate.consume"
    handler: str = "consume_rate_limit"
    permits_empty_mutation: bool = False
    program_id: str = core.transition_program_id(
        "quota.rate.consume",
        "consume_rate_limit",
    )

    _FIELDS = frozenset(
        {
            "counter_key",
            "principal_id",
            "route_id",
            "credential_id",
            "credential_version",
            "policy_hash",
            "constraint_id",
            "operation_digest",
            "operation_opaque_id",
            "window_seconds",
            "calendar_window",
            "max_count",
            "consume",
            "now_epoch_ms",
            "audit_evidence_digest",
        }
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "rate limit request")
        _exact_arguments(arguments, required=self._FIELDS)
        counter_key = _digest(
            arguments["counter_key"],
            "rate limit counter",
        )
        audit_evidence = _digest(
            arguments["audit_evidence_digest"],
            "rate limit audit evidence",
        )
        queries: list[core.BoundedQuery] = [
            _query(
                operation=self.operation,
                name="counter",
                table="rate_limit_counters",
                key={"counter_key": counter_key},
            ),
            _aggregate_query(
                self.operation,
                "counter_capacity",
                "rate-limit-counters",
                "global",
            ),
            _query(
                operation=self.operation,
                name="audit_evidence",
                table="policy_authority_external_evidence_receipts",
                key={"evidence_digest": audit_evidence},
            ),
        ]
        opaque_id = arguments["operation_opaque_id"]
        if opaque_id is not None:
            opaque_id = _text(
                opaque_id,
                "rate limit operation opaque value",
                maximum_bytes=256,
            )
            queries.extend(
                (
                    _query(
                        operation=self.operation,
                        name="operation_value",
                        table="policy_authority_opaque_values",
                        key={"opaque_id": opaque_id},
                    ),
                    _opaque_evidence_query(
                        self.operation,
                        name="operation_value_evidence",
                        opaque_id=opaque_id,
                    ),
                )
            )
        return tuple(queries)

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        _exact_arguments(context.arguments, required=self._FIELDS)
        counter_key = _digest(
            context.arguments["counter_key"],
            "rate limit counter",
        )
        principal_id = _text(
            context.arguments["principal_id"],
            "rate limit principal",
            maximum_bytes=512,
        )
        route_id = _text(
            context.arguments["route_id"],
            "rate limit route",
            maximum_bytes=512,
        )
        credential_id = _text(
            context.arguments["credential_id"],
            "rate limit credential",
            maximum_bytes=512,
            allow_empty=True,
        )
        credential_version = _integer(
            context.arguments["credential_version"],
            "rate limit credential version",
        )
        policy_hash = _digest(
            context.arguments["policy_hash"],
            "rate limit policy",
        )
        constraint_id = _text(
            context.arguments["constraint_id"],
            "rate limit constraint",
            maximum_bytes=512,
        )
        operation_digest = _optional_digest(
            context.arguments["operation_digest"],
            "rate limit operation",
        )
        max_count = _integer(
            context.arguments["max_count"],
            "rate limit maximum",
            minimum=1,
            maximum=1_000_000_000,
        )
        consume = _boolean(
            context.arguments["consume"],
            "rate limit consumption mode",
        )
        now_ms = (
            _database_epoch_ms(context.database_now)
            if context.arguments["now_epoch_ms"] is None
            else _integer(
                context.arguments["now_epoch_ms"],
                "rate limit observation time",
            )
        )
        fixed_seconds = context.arguments["window_seconds"]
        calendar_window = context.arguments["calendar_window"]
        if (fixed_seconds is None) == (calendar_window is None):
            raise core.TransitionKernelError(
                "rate limit requires exactly one window"
            )
        if fixed_seconds is not None:
            fixed_seconds = _integer(
                fixed_seconds,
                "rate limit fixed window",
                minimum=1,
                maximum=31_536_000,
            )
            window_kind = "fixed"
        else:
            window_kind = _text(
                calendar_window,
                "rate limit calendar window",
                maximum_bytes=32,
            )
            if window_kind not in {"utcDay", "utcIsoWeek", "utcMonth"}:
                raise core.TransitionKernelError(
                    "rate limit calendar window is invalid"
                )
        opaque_id = context.arguments["operation_opaque_id"]
        encrypted_operation = None
        operation_storage_version = None
        if operation_digest is not None:
            opaque_id = _text(
                opaque_id,
                "rate limit operation opaque value",
                maximum_bytes=256,
            )
            opaque = context.opaque_value(
                value_kind="quota-operation-recovery/v1",
                opaque_id=opaque_id,
                binding_digest=core.framed_digest(
                    "serverware.policyAuthorityQuotaOperationBinding/v1",
                    core.canonical_bytes(
                        {
                            "counterKey": counter_key,
                            "operationDigest": operation_digest,
                            "requestDigest": context.request_digest,
                        }
                    ),
                ),
            )
            encrypted_operation = opaque["ciphertext_base64url"]
            operation_storage_version = 1
        elif opaque_id is not None:
            raise core.TransitionKernelError(
                "rate limit opaque value has no operation digest"
            )
        selected, existing = _selected_or_none(
            context,
            "rate_limit_counters",
            {"counter_key": counter_key},
        )
        identity = {
            "principal_id": principal_id,
            "route_id": route_id,
            "credential_id": credential_id,
            "credential_version": credential_version,
            "policy_hash": policy_hash,
            "constraint_id": constraint_id,
            "operation": operation_digest,
        }
        reset = existing is None
        if existing is not None:
            if any(existing.get(field) != value for field, value in identity.items()):
                raise core.TransitionKernelError(
                    "rate limit counter identity was rebound"
                )
            stored_start = _integer(
                existing.get("window_start_epoch_ms"),
                "stored rate window start",
            )
            stored_end = _integer(
                existing.get("window_end_epoch_ms"),
                "stored rate window end",
                minimum=1,
            )
            if now_ms < stored_start:
                raise core.TransitionKernelError(
                    "rate limit clock moved backwards"
                )
            reset = now_ms >= stored_end
            if not reset and existing.get("window_kind") != window_kind:
                raise core.TransitionKernelError(
                    "live rate limit window kind changed"
                )
        if reset:
            if window_kind == "fixed":
                window_start = now_ms
                window_end = now_ms + int(fixed_seconds) * 1000
            else:
                window_start, window_end = _calendar_window_bounds(
                    window_kind,
                    now_ms,
                )
            count_before = 0
        else:
            window_start = int(existing["window_start_epoch_ms"])
            window_end = int(existing["window_end_epoch_ms"])
            count_before = _integer(
                existing.get("count"),
                "stored rate count",
                maximum=1_000_000_000,
            )
        allowed = count_before < max_count
        consumed = allowed and consume
        count_after = count_before + (1 if consumed else 0)
        result = _rate_result(
            counter_key=counter_key,
            window_kind=window_kind,
            window_start=window_start,
            window_end=window_end,
            max_count=max_count,
            count=count_after,
            now_ms=now_ms,
            consumed=consumed,
        )
        result["allowed"] = allowed
        result["reason"] = (
            "consumed"
            if consumed
            else "available" if allowed
            else "rate_limited"
        )
        result_digest = core.framed_digest(
            "serverware.policyAuthorityRateLimitResult/v1",
            core.canonical_bytes(result),
        )
        evidence_mutations = _consume_exact_evidence(
            context,
            evidence_type="audit-ledger-append/v1",
            evidence_digest=_digest(
                context.arguments["audit_evidence_digest"],
                "rate limit audit evidence",
            ),
            binding={
                "schema":
                    "serverware.policyAuthorityRateLimitAuditBinding/v1",
                "operation": self.operation,
                "requestDigest": context.request_digest,
                "counterKey": counter_key,
                "resultDigest": result_digest,
            },
        )
        counter_mutations: tuple[dict[str, Any], ...] = ()
        if existing is None and not consume:
            pass
        elif consumed or reset:
            now_s = _iso_from_epoch_ms(now_ms)
            row = {
                "counter_key": counter_key,
                **identity,
                "encrypted_operation": encrypted_operation,
                "operation_storage_version": operation_storage_version,
                "window_start_epoch_ms": window_start,
                "window_end_epoch_ms": window_end,
                "window_kind": window_kind,
                "window_seconds": (window_end - window_start) // 1000,
                "max_count": max_count,
                "count": count_after,
                "created_at": (
                    now_s
                    if existing is None
                    else existing.get("created_at")
                ),
                "updated_at": now_s,
            }
            counter_mutations = (
                core.mutation(
                    operation=self.operation,
                    selected=selected,
                    row=row,
                ),
            )
            if existing is None:
                counter_mutations += (
                    _aggregate_update(
                        context,
                        kind="rate-limit-counters",
                        partition="global",
                        live_delta=1,
                        active_delta=1,
                        next_sequence_delta=1,
                    ),
                )
        mutations = counter_mutations + evidence_mutations
        return core.KernelTransition(
            mutations=mutations,
            result={
                **result,
                "audit_evidence_digest":
                    context.arguments["audit_evidence_digest"],
            },
            work_units=32 + len(mutations),
        )


def _budget_definition(
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "budget_key": _digest(
            arguments["budget_key"],
            "durable budget key",
        ),
        "principal_id": _text(
            arguments["principal_id"],
            "durable budget principal",
            maximum_bytes=512,
        ),
        "route_id": _text(
            arguments["route_id"],
            "durable budget route",
            maximum_bytes=512,
        ),
        "credential_id": _text(
            arguments["credential_id"],
            "durable budget credential",
            maximum_bytes=512,
            allow_empty=True,
        ),
        "credential_version": _integer(
            arguments["credential_version"],
            "durable budget credential version",
        ),
        "policy_hash": _digest(
            arguments["policy_hash"],
            "durable budget policy",
        ),
        "constraint_id": _text(
            arguments["constraint_id"],
            "durable budget constraint",
            maximum_bytes=512,
        ),
        "unit_field": _text(
            arguments["unit_field"],
            "durable budget unit field",
            maximum_bytes=256,
        ),
        "window_kind": "sliding",
        "window_seconds": _integer(
            arguments["window_seconds"],
            "durable budget window",
            minimum=1,
            maximum=31_536_000,
        ),
        "max_units": _integer(
            arguments["max_units"],
            "durable budget maximum",
            minimum=1,
        ),
    }


def _budget_units(
    aggregate: Mapping[str, Any],
) -> tuple[int, int]:
    reserved, committed = _aggregate_maps(aggregate)
    if set(reserved) != {"units"} or set(committed) != {"units"}:
        raise core.TransitionKernelError(
            "durable budget aggregate units are not exact"
        )
    return (
        _integer(reserved["units"], "reserved durable budget units"),
        _integer(committed["units"], "committed durable budget units"),
    )


def _budget_result(
    *,
    definition: Mapping[str, Any],
    event: Mapping[str, Any] | None,
    reservation_id: str,
    units: int,
    total_units: int,
    now_ms: int,
    allowed: bool,
    reason: str,
    replay: bool,
) -> dict[str, Any]:
    return {
        "allowed": allowed,
        "reason": reason,
        "budget_key": definition["budget_key"],
        "reservation_id": reservation_id,
        "state": (
            reason if event is None else str(event.get("state"))
        ),
        "window_kind": "sliding",
        "window_seconds": definition["window_seconds"],
        "max_units": definition["max_units"],
        "units": units,
        "total_units": total_units,
        "remaining_units": max(
            int(definition["max_units"]) - total_units,
            0,
        ),
        "expires_at_epoch_ms": (
            None if event is None else event.get("expires_at_epoch_ms")
        ),
        "retry_after_seconds": (
            0
            if allowed or event is None
            else max(
                1,
                (
                    int(event.get("expires_at_epoch_ms", now_ms))
                    - now_ms
                    + 999
                )
                // 1000,
            )
        ),
        "idempotent_replay": replay,
        "observed_at_epoch_ms": now_ms,
        "durable_budget_store_backend": "postgres",
        "durable_budget_store_ha": True,
    }


@dataclass(frozen=True, slots=True)
class _BudgetReserveKernel:
    operation: str = "quota.budget.reserve"
    handler: str = "reserve_durable_budget"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "quota.budget.reserve",
        "reserve_durable_budget",
    )

    _FIELDS = frozenset(
        {
            "reservation_id",
            "budget_key",
            "principal_id",
            "route_id",
            "credential_id",
            "credential_version",
            "policy_hash",
            "constraint_id",
            "operation_digest",
            "request_digest",
            "unit_field",
            "units",
            "window_seconds",
            "max_units",
            "reservation_ttl_seconds",
            "now_epoch_ms",
        }
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "durable budget authority request")
        _exact_arguments(arguments, required=self._FIELDS)
        reservation_id = _text(
            arguments["reservation_id"],
            "durable budget reservation",
            maximum_bytes=512,
        )
        budget_key = _digest(
            arguments["budget_key"],
            "durable budget key",
        )
        return (
            _query(
                operation=self.operation,
                name="definition",
                table="durable_budget_definitions",
                key={"budget_key": budget_key},
            ),
            _query(
                operation=self.operation,
                name="event",
                table="durable_budget_events",
                key={"reservation_id": reservation_id},
            ),
            _aggregate_query(
                self.operation,
                "budget_high_water",
                "durable-budget",
                budget_key,
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        _exact_arguments(context.arguments, required=self._FIELDS)
        definition = _budget_definition(context.arguments)
        reservation_id = _text(
            context.arguments["reservation_id"],
            "durable budget reservation",
            maximum_bytes=512,
        )
        request_digest = _digest(
            context.arguments["request_digest"],
            "durable budget request",
        )
        operation_digest = _optional_digest(
            context.arguments["operation_digest"],
            "durable budget operation",
        )
        units = _integer(
            context.arguments["units"],
            "durable budget units",
        )
        ttl_seconds = _integer(
            context.arguments["reservation_ttl_seconds"],
            "durable budget reservation TTL",
            minimum=1,
            maximum=300,
        )
        now_ms = (
            _database_epoch_ms(context.database_now)
            if context.arguments["now_epoch_ms"] is None
            else _integer(
                context.arguments["now_epoch_ms"],
                "durable budget observation time",
            )
        )
        definition_selected, stored_definition = _selected_or_none(
            context,
            "durable_budget_definitions",
            {"budget_key": definition["budget_key"]},
        )
        event_selected, event = _selected_or_none(
            context,
            "durable_budget_events",
            {"reservation_id": reservation_id},
        )
        aggregate_id, partition_digest = _aggregate_key(
            "durable-budget",
            definition["budget_key"],
        )
        aggregate = context.bounded_aggregate(
            aggregate_id=aggregate_id,
            aggregate_kind="durable-budget",
            partition_digest=partition_digest,
        )
        reserved_units, committed_units = _budget_units(aggregate)
        minimum_expiry = aggregate.get("minimum_expiry_epoch_ns")
        if (
            minimum_expiry is not None
            and minimum_expiry <= now_ms * 1_000_000
            and aggregate.get("active_count", 0) > 0
        ):
            raise core.TransitionKernelError(
                "durable budget expiry page must be committed first"
            )
        now_s = _iso_from_epoch_ms(now_ms)
        definition_mutations: tuple[dict[str, Any], ...] = ()
        if stored_definition is None:
            stored_definition = {
                **definition,
                "last_observed_epoch_ms": now_ms,
                "created_at": now_s,
                "updated_at": now_s,
            }
            definition_mutations = (
                core.mutation(
                    operation=self.operation,
                    selected=definition_selected,
                    row=stored_definition,
                ),
            )
        else:
            if any(
                stored_definition.get(field) != value
                for field, value in definition.items()
            ):
                raise core.TransitionKernelError(
                    "durable budget key was rebound"
                )
            if now_ms < int(stored_definition["last_observed_epoch_ms"]):
                raise core.TransitionKernelError(
                    "durable budget clock moved backwards"
                )
        immutable_event = {
            "budget_key": definition["budget_key"],
            "request_digest": request_digest,
            "operation_digest": operation_digest,
            "units": units,
        }
        if event is not None:
            if any(
                event.get(field) != value
                for field, value in immutable_event.items()
            ):
                raise core.TransitionKernelError(
                    "durable budget reservation identity was rebound"
                )
            state = str(event.get("state"))
            active = state in {"reserved", "dispatched"} or (
                state == "committed"
                and int(event["expires_at_epoch_ms"]) > now_ms
            )
            return core.KernelTransition(
                mutations=(),
                result=_budget_result(
                    definition=definition,
                    event=event,
                    reservation_id=reservation_id,
                    units=units,
                    total_units=reserved_units + committed_units,
                    now_ms=now_ms,
                    allowed=active,
                    reason=state,
                    replay=True,
                ),
                work_units=12,
            )
        total_before = core.checked_u64_add(
            reserved_units,
            committed_units,
            "durable budget total",
        )
        total_after = core.checked_u64_add(
            total_before,
            units,
            "durable budget requested total",
        )
        if units > int(definition["max_units"]):
            return core.KernelTransition(
                mutations=definition_mutations,
                result=_budget_result(
                    definition=definition,
                    event=None,
                    reservation_id=reservation_id,
                    units=units,
                    total_units=total_before,
                    now_ms=now_ms,
                    allowed=False,
                    reason="requested_units_exceed_budget",
                    replay=False,
                ),
                work_units=12 + len(definition_mutations),
            )
        if total_after > int(definition["max_units"]):
            return core.KernelTransition(
                mutations=definition_mutations,
                result=_budget_result(
                    definition=definition,
                    event=None,
                    reservation_id=reservation_id,
                    units=units,
                    total_units=total_before,
                    now_ms=now_ms,
                    allowed=False,
                    reason="sliding_budget_exceeded",
                    replay=False,
                ),
                work_units=12 + len(definition_mutations),
            )
        expires_at = now_ms + int(definition["window_seconds"]) * 1000
        reservation_expires = min(
            expires_at,
            now_ms + ttl_seconds * 1000,
        )
        event = {
            "reservation_id": reservation_id,
            "bundle_reservation_id": None,
            **immutable_event,
            "state": "reserved",
            "occurred_at_epoch_ms": now_ms,
            "expires_at_epoch_ms": expires_at,
            "reservation_expires_at_epoch_ms": reservation_expires,
            "created_at": now_s,
            "updated_at": now_s,
        }
        definition_after = {
            **stored_definition,
            "last_observed_epoch_ms": now_ms,
            "updated_at": now_s,
        }
        if definition_mutations:
            definition_mutations = (
                core.mutation(
                    operation=self.operation,
                    selected=definition_selected,
                    row=definition_after,
                ),
            )
        else:
            definition_mutations = (
                core.mutation(
                    operation=self.operation,
                    selected=definition_selected,
                    row=definition_after,
                ),
            )
        next_minimum = (
            reservation_expires * 1_000_000
            if minimum_expiry is None
            else min(minimum_expiry, reservation_expires * 1_000_000)
        )
        mutations = (
            *definition_mutations,
            core.mutation(
                operation=self.operation,
                selected=event_selected,
                row=event,
            ),
            _aggregate_update(
                context,
                kind="durable-budget",
                partition=definition["budget_key"],
                live_delta=1,
                active_delta=1,
                reserved_units={"units": total_after - committed_units},
                committed_units={"units": committed_units},
                next_sequence_delta=1,
                minimum_expiry_epoch_ns=next_minimum,
                expiry_index_root_digest=core.framed_digest(
                    "serverware.policyAuthorityBudgetExpiryIndexDelta/v1",
                    str(aggregate["expiry_index_root_digest"]).encode(
                        "ascii"
                    ),
                    reservation_id.encode("utf-8"),
                    str(reservation_expires).encode("ascii"),
                ),
            ),
        )
        return core.KernelTransition(
            mutations=tuple(mutations),
            result=_budget_result(
                definition=definition,
                event=event,
                reservation_id=reservation_id,
                units=units,
                total_units=total_after,
                now_ms=now_ms,
                allowed=True,
                reason="reserved",
                replay=False,
            ),
            work_units=24 + len(mutations),
        )


@dataclass(frozen=True, slots=True)
class _BudgetStateKernel:
    operation: str
    handler: str
    target: str
    permits_empty_mutation: bool = True

    @property
    def program_id(self) -> str:
        return core.transition_program_id(self.operation, self.handler)

    _FIELDS = frozenset(
        {
            "reservation_id",
            "budget_key",
            "request_digest",
            "operation_digest",
            "now_epoch_ms",
        }
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "durable budget transition request")
        _exact_arguments(arguments, required=self._FIELDS)
        reservation_id = _text(
            arguments["reservation_id"],
            "durable budget reservation",
            maximum_bytes=512,
        )
        budget_key = _digest(
            arguments["budget_key"],
            "durable budget key",
        )
        return (
            _query(
                operation=self.operation,
                name="definition",
                table="durable_budget_definitions",
                key={"budget_key": budget_key},
            ),
            _query(
                operation=self.operation,
                name="event",
                table="durable_budget_events",
                key={"reservation_id": reservation_id},
            ),
            _aggregate_query(
                self.operation,
                "budget_high_water",
                "durable-budget",
                budget_key,
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        _exact_arguments(context.arguments, required=self._FIELDS)
        reservation_id = _text(
            context.arguments["reservation_id"],
            "durable budget reservation",
            maximum_bytes=512,
        )
        budget_key = _digest(
            context.arguments["budget_key"],
            "durable budget key",
        )
        request_digest = _digest(
            context.arguments["request_digest"],
            "durable budget request",
        )
        operation_digest = _optional_digest(
            context.arguments["operation_digest"],
            "durable budget operation",
        )
        now_ms = (
            _database_epoch_ms(context.database_now)
            if context.arguments["now_epoch_ms"] is None
            else _integer(
                context.arguments["now_epoch_ms"],
                "durable budget observation time",
            )
        )
        definition_selected = context.exact(
            "durable_budget_definitions",
            {"budget_key": budget_key},
        )
        definition = _row(
            definition_selected,
            "durable budget definition",
        )
        event_selected = context.exact(
            "durable_budget_events",
            {"reservation_id": reservation_id},
        )
        event = _row(event_selected, "durable budget event")
        if (
            event.get("budget_key") != budget_key
            or event.get("request_digest") != request_digest
            or event.get("operation_digest") != operation_digest
        ):
            raise core.TransitionKernelError(
                "durable budget transition binding differs"
            )
        if now_ms < int(definition.get("last_observed_epoch_ms", -1)):
            raise core.TransitionKernelError(
                "durable budget clock moved backwards"
            )
        aggregate_id, partition_digest = _aggregate_key(
            "durable-budget",
            budget_key,
        )
        aggregate = context.bounded_aggregate(
            aggregate_id=aggregate_id,
            aggregate_kind="durable-budget",
            partition_digest=partition_digest,
        )
        reserved, committed = _budget_units(aggregate)
        state = str(event.get("state"))
        replay = state == self.target
        if replay:
            return core.KernelTransition(
                mutations=(),
                result=_budget_result(
                    definition=definition,
                    event=event,
                    reservation_id=reservation_id,
                    units=int(event["units"]),
                    total_units=reserved + committed,
                    now_ms=now_ms,
                    allowed=self.target in {"dispatched", "committed"},
                    reason=self.target,
                    replay=True,
                ),
                work_units=10,
            )
        units = _integer(event.get("units"), "durable budget event units")
        if self.target == "dispatched":
            if state != "reserved":
                raise core.TransitionKernelError(
                    "durable budget cannot dispatch from its state"
                )
            reserved_after = core.checked_u64_sub(
                reserved,
                units,
                "durable budget reserved units",
            )
            committed_after = core.checked_u64_add(
                committed,
                units,
                "durable budget dispatched units",
            )
            active_delta = 0
        elif self.target == "committed":
            if state not in {"reserved", "dispatched"}:
                raise core.TransitionKernelError(
                    "durable budget cannot commit from its state"
                )
            if state == "reserved":
                reserved_after = core.checked_u64_sub(
                    reserved,
                    units,
                    "durable budget reserved units",
                )
                committed_after = core.checked_u64_add(
                    committed,
                    units,
                    "durable budget committed units",
                )
            else:
                reserved_after, committed_after = reserved, committed
            active_delta = 0
        elif self.target == "cancelled":
            if state not in {"reserved", "dispatched"}:
                raise core.TransitionKernelError(
                    "durable budget cannot cancel from its state"
                )
            if state == "reserved":
                reserved_after = core.checked_u64_sub(
                    reserved,
                    units,
                    "durable budget reserved units",
                )
                committed_after = committed
            else:
                reserved_after = reserved
                committed_after = core.checked_u64_sub(
                    committed,
                    units,
                    "durable budget dispatched units",
                )
            active_delta = -1
        else:
            raise core.TransitionKernelError(
                "durable budget target is invalid"
            )
        now_s = _iso_from_epoch_ms(now_ms)
        expires_at = int(event["expires_at_epoch_ms"])
        if self.target in {"dispatched", "committed"}:
            expires_at = now_ms + int(definition["window_seconds"]) * 1000
        event_after = {
            **event,
            "state": self.target,
            "occurred_at_epoch_ms": (
                now_ms if self.target in {"dispatched", "committed"} else
                event["occurred_at_epoch_ms"]
            ),
            "expires_at_epoch_ms": expires_at,
            "reservation_expires_at_epoch_ms": None,
            "updated_at": now_s,
        }
        definition_after = {
            **definition,
            "last_observed_epoch_ms": now_ms,
            "updated_at": now_s,
        }
        mutations = (
            core.mutation(
                operation=self.operation,
                selected=event_selected,
                row=event_after,
            ),
            core.mutation(
                operation=self.operation,
                selected=definition_selected,
                row=definition_after,
            ),
            _aggregate_update(
                context,
                kind="durable-budget",
                partition=budget_key,
                active_delta=active_delta,
                reserved_units={"units": reserved_after},
                committed_units={"units": committed_after},
                minimum_expiry_epoch_ns=(
                    expires_at * 1_000_000
                    if self.target in {"dispatched", "committed"}
                    else None
                ),
                expiry_index_root_digest=core.framed_digest(
                    "serverware.policyAuthorityBudgetExpiryIndexDelta/v1",
                    str(aggregate["expiry_index_root_digest"]).encode(
                        "ascii"
                    ),
                    reservation_id.encode("utf-8"),
                    self.target.encode("ascii"),
                    str(expires_at).encode("ascii"),
                ),
            ),
        )
        total = core.checked_u64_add(
            reserved_after,
            committed_after,
            "durable budget total",
        )
        return core.KernelTransition(
            mutations=mutations,
            result=_budget_result(
                definition=definition,
                event=event_after,
                reservation_id=reservation_id,
                units=units,
                total_units=total,
                now_ms=now_ms,
                allowed=self.target in {"dispatched", "committed"},
                reason=self.target,
                replay=False,
            ),
            work_units=24 + len(mutations),
        )


def _traversal_identity(
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "chain_key": _digest(
            arguments["chain_key"],
            "traversal chain key",
        ),
        "lineage_digest": _digest(
            arguments["lineage_digest"],
            "traversal lineage",
        ),
        "principal_id": _text(
            arguments["principal_id"],
            "traversal principal",
            maximum_bytes=512,
        ),
        "route_id": _text(
            arguments["route_id"],
            "traversal route",
            maximum_bytes=512,
        ),
        "credential_id": _text(
            arguments["credential_id"],
            "traversal credential",
            maximum_bytes=512,
            allow_empty=True,
        ),
        "credential_version": _integer(
            arguments["credential_version"],
            "traversal credential version",
        ),
        "policy_hash": _digest(
            arguments["policy_hash"],
            "traversal policy",
        ),
        "constraint_id": _text(
            arguments["constraint_id"],
            "traversal constraint",
            maximum_bytes=512,
        ),
        "max_pages": _integer(
            arguments["max_pages"],
            "traversal maximum pages",
            minimum=1,
            maximum=1_000_000,
        ),
        "max_records": _integer(
            arguments["max_records"],
            "traversal maximum records",
            minimum=1,
        ),
        "max_bytes": _integer(
            arguments["max_bytes"],
            "traversal maximum bytes",
            minimum=1,
        ),
        "lifetime_seconds": _integer(
            arguments["lifetime_seconds"],
            "traversal lifetime",
            minimum=1,
            maximum=31_536_000,
        ),
    }


def _traversal_aggregate_units(
    row: Mapping[str, Any],
) -> tuple[int, int, int, int, int]:
    reserved, committed = _aggregate_maps(row)
    if set(reserved) != {"pages"} or set(committed) != {
        "pages",
        "records",
        "bytes",
        "rootHistory",
    }:
        raise core.TransitionKernelError(
            "traversal aggregate units are not exact"
        )
    return (
        _integer(reserved["pages"], "reserved traversal pages"),
        _integer(committed["pages"], "committed traversal pages"),
        _integer(committed["records"], "committed traversal records"),
        _integer(committed["bytes"], "committed traversal bytes"),
        _integer(committed["rootHistory"], "traversal root history"),
    )


@dataclass(frozen=True, slots=True)
class _TraversalReserveKernel:
    operation: str = "quota.traversal.reserve"
    handler: str = "reserve_traversal_page"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "quota.traversal.reserve",
        "reserve_traversal_page",
    )

    _FIELDS = frozenset(
        {
            "reservation_id",
            "chain_key",
            "lineage_digest",
            "principal_id",
            "route_id",
            "credential_id",
            "credential_version",
            "policy_hash",
            "constraint_id",
            "request_digest",
            "request_cursor_digest",
            "max_pages",
            "max_records",
            "max_bytes",
            "lifetime_seconds",
            "reservation_ttl_seconds",
            "now_epoch_ms",
        }
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "traversal reserve request")
        _exact_arguments(arguments, required=self._FIELDS)
        reservation_id = _text(
            arguments["reservation_id"],
            "traversal reservation",
            maximum_bytes=512,
        )
        chain_key = _digest(
            arguments["chain_key"],
            "traversal chain key",
        )
        queries: list[core.BoundedQuery] = [
            _query(
                operation=self.operation,
                name="chain",
                table="traversal_budget_chains",
                key={"chain_key": chain_key},
            ),
            _query(
                operation=self.operation,
                name="page",
                table="traversal_budget_page_reservations",
                key={"reservation_id": reservation_id},
            ),
            _aggregate_query(
                self.operation,
                "chain_high_water",
                "traversal-chain",
                chain_key,
            ),
        ]
        cursor_digest = arguments["request_cursor_digest"]
        if cursor_digest is not None:
            queries.append(
                _query(
                    operation=self.operation,
                    name="request_cursor",
                    table="traversal_budget_cursors",
                    key={
                        "cursor_digest": _digest(
                            cursor_digest,
                            "traversal request cursor",
                        )
                    },
                )
            )
        return tuple(queries)

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        _exact_arguments(context.arguments, required=self._FIELDS)
        identity = _traversal_identity(context.arguments)
        reservation_id = _text(
            context.arguments["reservation_id"],
            "traversal reservation",
            maximum_bytes=512,
        )
        request_digest = _digest(
            context.arguments["request_digest"],
            "traversal request",
        )
        cursor_digest = _optional_digest(
            context.arguments["request_cursor_digest"],
            "traversal request cursor",
        )
        ttl_seconds = _integer(
            context.arguments["reservation_ttl_seconds"],
            "traversal reservation TTL",
            minimum=1,
            maximum=300,
        )
        now_ms = (
            _database_epoch_ms(context.database_now)
            if context.arguments["now_epoch_ms"] is None
            else _integer(
                context.arguments["now_epoch_ms"],
                "traversal observation time",
            )
        )
        chain_selected, chain = _selected_or_none(
            context,
            "traversal_budget_chains",
            {"chain_key": identity["chain_key"]},
        )
        page_selected, page = _selected_or_none(
            context,
            "traversal_budget_page_reservations",
            {"reservation_id": reservation_id},
        )
        aggregate_id, partition_digest = _aggregate_key(
            "traversal-chain",
            identity["chain_key"],
        )
        aggregate = context.bounded_aggregate(
            aggregate_id=aggregate_id,
            aggregate_kind="traversal-chain",
            partition_digest=partition_digest,
        )
        (
            reserved_pages,
            committed_pages,
            committed_records,
            committed_bytes,
            root_history,
        ) = _traversal_aggregate_units(aggregate)
        minimum_expiry = aggregate.get("minimum_expiry_epoch_ns")
        if (
            minimum_expiry is not None
            and minimum_expiry <= now_ms * 1_000_000
            and reserved_pages > 0
        ):
            raise core.TransitionKernelError(
                "traversal expiry page must be committed first"
            )
        now_s = _iso_from_epoch_ms(now_ms)
        if chain is None:
            if cursor_digest is not None:
                raise core.TransitionKernelError(
                    "new traversal chain cannot begin from a cursor"
                )
            chain = {
                **{
                    field: value
                    for field, value in identity.items()
                    if field != "lifetime_seconds"
                },
                "state": "active",
                "started_at_epoch_ms": now_ms,
                "expires_at_epoch_ms":
                    now_ms + identity["lifetime_seconds"] * 1000,
                "last_observed_epoch_ms": now_ms,
                "page_count": 0,
                "record_count": 0,
                "byte_count": 0,
                "created_at": now_s,
                "updated_at": now_s,
            }
            chain_was_absent = True
        else:
            expected = {
                field: value
                for field, value in identity.items()
                if field != "lifetime_seconds"
            }
            if any(chain.get(field) != value for field, value in expected.items()):
                raise core.TransitionKernelError(
                    "traversal chain identity was rebound"
                )
            if (
                int(chain["expires_at_epoch_ms"])
                - int(chain["started_at_epoch_ms"])
                != identity["lifetime_seconds"] * 1000
            ):
                raise core.TransitionKernelError(
                    "traversal chain lifetime was rebound"
                )
            chain_was_absent = False
        if now_ms < int(chain["last_observed_epoch_ms"]):
            raise core.TransitionKernelError(
                "traversal clock moved backwards"
            )
        if page is not None:
            if (
                page.get("chain_key") != identity["chain_key"]
                or page.get("lineage_digest") != identity["lineage_digest"]
                or page.get("request_digest") != request_digest
                or page.get("request_cursor_digest") != cursor_digest
            ):
                raise core.TransitionKernelError(
                    "traversal reservation identity was rebound"
                )
            return core.KernelTransition(
                mutations=(),
                result=_traversal_result(
                    chain=chain,
                    reservation_id=reservation_id,
                    target=str(page["state"]),
                    page_number=int(page["page_number"]),
                    idempotent_replay=True,
                )
                | {
                    "allowed": page["state"]
                        in {"reserved", "dispatched", "committed"},
                    "reason": str(page["state"]),
                },
                work_units=12,
            )
        if (
            now_ms >= int(chain["expires_at_epoch_ms"])
            or chain.get("state") != "active"
        ):
            raise core.TransitionKernelError(
                "traversal chain is not live and active"
            )
        if cursor_digest is None and root_history > 0:
            raise core.TransitionKernelError(
                "traversal root request cannot be replayed"
            )
        if committed_pages + reserved_pages >= identity["max_pages"]:
            raise core.TransitionKernelError(
                "traversal page budget is exhausted"
            )
        if (
            committed_records >= identity["max_records"]
            or committed_bytes >= identity["max_bytes"]
        ):
            raise core.TransitionKernelError(
                "traversal result budget is exhausted"
            )
        cursor_mutations: tuple[dict[str, Any], ...] = ()
        if cursor_digest is not None:
            cursor_selected = context.exact(
                "traversal_budget_cursors",
                {"cursor_digest": cursor_digest},
            )
            cursor = _row(cursor_selected, "traversal request cursor")
            if (
                cursor.get("chain_key") != identity["chain_key"]
                or cursor.get("lineage_digest") != identity["lineage_digest"]
                or cursor.get("state") != "available"
                or int(cursor.get("expires_at_epoch_ms", -1)) <= now_ms
            ):
                raise core.TransitionKernelError(
                    "traversal request cursor is unavailable"
                )
            cursor_mutations = (
                core.mutation(
                    operation=self.operation,
                    selected=cursor_selected,
                    row={
                        **cursor,
                        "state": "reserved",
                        "reserved_by": reservation_id,
                        "updated_at": now_s,
                    },
                ),
            )
        page_number = committed_pages + reserved_pages + 1
        reservation_expiry = min(
            int(chain["expires_at_epoch_ms"]),
            now_ms + ttl_seconds * 1000,
        )
        page = {
            "reservation_id": reservation_id,
            "bundle_reservation_id": None,
            "chain_key": identity["chain_key"],
            "lineage_digest": identity["lineage_digest"],
            "request_digest": request_digest,
            "request_cursor_digest": cursor_digest,
            "page_number": page_number,
            "state": "reserved",
            "response_digest": None,
            "response_records": None,
            "response_bytes": None,
            "next_cursor_digest": None,
            "reservation_expires_at_epoch_ms": reservation_expiry,
            "created_at": now_s,
            "updated_at": now_s,
        }
        chain_after = {
            **chain,
            "last_observed_epoch_ms": now_ms,
            "updated_at": now_s,
        }
        mutations = (
            core.mutation(
                operation=self.operation,
                selected=chain_selected,
                row=chain_after,
            ),
            *cursor_mutations,
            core.mutation(
                operation=self.operation,
                selected=page_selected,
                row=page,
            ),
            _aggregate_update(
                context,
                kind="traversal-chain",
                partition=identity["chain_key"],
                live_delta=1,
                active_delta=1,
                reserved_units={"pages": reserved_pages + 1},
                committed_units={
                    "pages": committed_pages,
                    "records": committed_records,
                    "bytes": committed_bytes,
                    "rootHistory": (
                        root_history + 1
                        if cursor_digest is None
                        else root_history
                    ),
                },
                next_sequence_delta=1,
                minimum_expiry_epoch_ns=reservation_expiry * 1_000_000,
                expiry_index_root_digest=core.framed_digest(
                    "serverware.policyAuthorityTraversalExpiryIndexDelta/v1",
                    str(aggregate["expiry_index_root_digest"]).encode(
                        "ascii"
                    ),
                    reservation_id.encode("utf-8"),
                    str(reservation_expiry).encode("ascii"),
                ),
            ),
        )
        return core.KernelTransition(
            mutations=tuple(mutations),
            result=_traversal_dispatch_result(
                chain=chain_after,
                reservation_id=reservation_id,
                page_number=page_number,
                idempotent_replay=False,
            )
            | {"reason": "reserved"},
            work_units=32 + len(mutations),
        )


@dataclass(frozen=True, slots=True)
class _TraversalCompleteKernel:
    operation: str = "quota.traversal.complete"
    handler: str = "complete_traversal_page"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "quota.traversal.complete",
        "complete_traversal_page",
    )

    _FIELDS = frozenset(
        {
            "reservation_id",
            "chain_key",
            "request_digest",
            "response_digest",
            "response_records",
            "response_bytes",
            "next_cursor_digest",
            "now_epoch_ms",
            "evidence_digest",
        }
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "traversal completion request")
        _exact_arguments(arguments, required=self._FIELDS)
        reservation_id = _text(
            arguments["reservation_id"],
            "traversal reservation",
            maximum_bytes=512,
        )
        chain_key = _digest(
            arguments["chain_key"],
            "traversal chain key",
        )
        queries: list[core.BoundedQuery] = [
            _query(
                operation=self.operation,
                name="page",
                table="traversal_budget_page_reservations",
                key={"reservation_id": reservation_id},
            ),
            _query(
                operation=self.operation,
                name="chain",
                table="traversal_budget_chains",
                key={"chain_key": chain_key},
            ),
            _query(
                operation=self.operation,
                name="request_cursor",
                table="traversal_budget_cursors",
                key={
                    "cursor_digest": core.SelectedRowFieldReference(
                        table="traversal_budget_page_reservations",
                        key={"reservation_id": reservation_id},
                        column="request_cursor_digest",
                    )
                },
            ),
            _aggregate_query(
                self.operation,
                "chain_high_water",
                "traversal-chain",
                chain_key,
            ),
            _query(
                operation=self.operation,
                name="response_evidence",
                table="policy_authority_external_evidence_receipts",
                key={
                    "evidence_digest": _digest(
                        arguments["evidence_digest"],
                        "traversal response evidence",
                    )
                },
            ),
        ]
        next_cursor = arguments["next_cursor_digest"]
        if next_cursor is not None:
            queries.append(
                _query(
                    operation=self.operation,
                    name="next_cursor",
                    table="traversal_budget_cursors",
                    key={
                        "cursor_digest": _digest(
                            next_cursor,
                            "traversal next cursor",
                        )
                    },
                )
            )
        return tuple(queries)

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        _exact_arguments(context.arguments, required=self._FIELDS)
        reservation_id = _text(
            context.arguments["reservation_id"],
            "traversal reservation",
            maximum_bytes=512,
        )
        chain_key = _digest(
            context.arguments["chain_key"],
            "traversal chain key",
        )
        request_digest = _digest(
            context.arguments["request_digest"],
            "traversal request",
        )
        response_digest = _digest(
            context.arguments["response_digest"],
            "traversal response",
        )
        response_records = _integer(
            context.arguments["response_records"],
            "traversal response records",
        )
        response_bytes = _integer(
            context.arguments["response_bytes"],
            "traversal response bytes",
        )
        next_cursor_digest = _optional_digest(
            context.arguments["next_cursor_digest"],
            "traversal next cursor",
        )
        now_ms = (
            _database_epoch_ms(context.database_now)
            if context.arguments["now_epoch_ms"] is None
            else _integer(
                context.arguments["now_epoch_ms"],
                "traversal observation time",
            )
        )
        page_selected = context.exact(
            "traversal_budget_page_reservations",
            {"reservation_id": reservation_id},
        )
        page = _row(page_selected, "traversal page")
        chain_selected = context.exact(
            "traversal_budget_chains",
            {"chain_key": chain_key},
        )
        chain = _row(chain_selected, "traversal chain")
        if (
            page.get("chain_key") != chain_key
            or page.get("request_digest") != request_digest
            or page.get("lineage_digest") != chain.get("lineage_digest")
        ):
            raise core.TransitionKernelError(
                "traversal completion binding differs"
            )
        evidence_binding = {
            "schema": "serverware.traversalResponseValidation/v2",
            "operation": self.operation,
            "requestDigest": context.request_digest,
            "reservationId": reservation_id,
            "chainKey": chain_key,
            "lineageDigest": chain.get("lineage_digest"),
            "pageNumber": page.get("page_number"),
            "responseDigest": response_digest,
            "recordCount": response_records,
            "decodedBytes": response_bytes,
            "nextCursorDigest": next_cursor_digest,
            "validation": "passed",
        }
        replay = page.get("state") == "committed"
        evidence_mutations = _consume_exact_evidence(
            context,
            evidence_type="response-validation/v2",
            evidence_digest=_digest(
                context.arguments["evidence_digest"],
                "traversal response evidence",
            ),
            binding=evidence_binding,
            replay=replay,
        )
        if replay:
            if (
                page.get("response_digest") != response_digest
                or page.get("response_records") != response_records
                or page.get("response_bytes") != response_bytes
                or page.get("next_cursor_digest") != next_cursor_digest
            ):
                raise core.TransitionKernelError(
                    "traversal completion replay conflicts"
                )
            return core.KernelTransition(
                mutations=evidence_mutations,
                result=_traversal_result(
                    chain=chain,
                    reservation_id=reservation_id,
                    target="committed",
                    page_number=int(page["page_number"]),
                    idempotent_replay=True,
                )
                | {"allowed": True, "reason": "committed"},
                work_units=16 + len(evidence_mutations),
            )
        if page.get("state") != "dispatched":
            raise core.TransitionKernelError(
                "traversal page is not dispatched"
            )
        aggregate_id, partition_digest = _aggregate_key(
            "traversal-chain",
            chain_key,
        )
        aggregate = context.bounded_aggregate(
            aggregate_id=aggregate_id,
            aggregate_kind="traversal-chain",
            partition_digest=partition_digest,
        )
        (
            reserved_pages,
            committed_pages,
            committed_records,
            committed_bytes,
            root_history,
        ) = _traversal_aggregate_units(aggregate)
        pages_after = core.checked_u64_add(
            committed_pages,
            1,
            "traversal committed pages",
        )
        records_after = core.checked_u64_add(
            committed_records,
            response_records,
            "traversal committed records",
        )
        bytes_after = core.checked_u64_add(
            committed_bytes,
            response_bytes,
            "traversal committed bytes",
        )
        if (
            pages_after > int(chain["max_pages"])
            or records_after > int(chain["max_records"])
            or bytes_after > int(chain["max_bytes"])
        ):
            raise core.TransitionKernelError(
                "traversal response exceeds its exact budget"
            )
        now_s = _iso_from_epoch_ms(now_ms)
        cursor_mutations: tuple[dict[str, Any], ...] = ()
        request_cursor = page.get("request_cursor_digest")
        if request_cursor is not None:
            cursor_selected = context.exact(
                "traversal_budget_cursors",
                {"cursor_digest": request_cursor},
            )
            cursor = _row(cursor_selected, "traversal request cursor")
            if (
                cursor.get("state") != "reserved"
                or cursor.get("reserved_by") != reservation_id
            ):
                raise core.TransitionKernelError(
                    "traversal request cursor lost its reservation"
                )
            cursor_mutations += (
                core.mutation(
                    operation=self.operation,
                    selected=cursor_selected,
                    row={
                        **cursor,
                        "state": "consumed",
                        "reserved_by": None,
                        "updated_at": now_s,
                    },
                ),
            )
        exhausted = (
            pages_after >= int(chain["max_pages"])
            or records_after >= int(chain["max_records"])
            or bytes_after >= int(chain["max_bytes"])
            or next_cursor_digest is None
        )
        if next_cursor_digest is not None:
            next_selected, next_cursor = _selected_or_none(
                context,
                "traversal_budget_cursors",
                {"cursor_digest": next_cursor_digest},
            )
            next_row = {
                "cursor_digest": next_cursor_digest,
                "chain_key": chain_key,
                "lineage_digest": chain["lineage_digest"],
                "state": "available",
                "reserved_by": None,
                "issued_at_epoch_ms": now_ms,
                "expires_at_epoch_ms": chain["expires_at_epoch_ms"],
                "updated_at": now_s,
            }
            if next_cursor is None:
                cursor_mutations += (
                    core.mutation(
                        operation=self.operation,
                        selected=next_selected,
                        row=next_row,
                    ),
                )
            elif any(
                next_cursor.get(field) != value
                for field, value in next_row.items()
            ):
                raise core.TransitionKernelError(
                    "traversal next cursor identity was rebound"
                )
        page_after = {
            **page,
            "state": "committed",
            "response_digest": response_digest,
            "response_records": response_records,
            "response_bytes": response_bytes,
            "next_cursor_digest": next_cursor_digest,
            "updated_at": now_s,
        }
        chain_after = {
            **chain,
            "state": "exhausted" if exhausted else "active",
            "page_count": pages_after,
            "record_count": records_after,
            "byte_count": bytes_after,
            "last_observed_epoch_ms": now_ms,
            "updated_at": now_s,
        }
        mutations = (
            *evidence_mutations,
            *cursor_mutations,
            core.mutation(
                operation=self.operation,
                selected=page_selected,
                row=page_after,
            ),
            core.mutation(
                operation=self.operation,
                selected=chain_selected,
                row=chain_after,
            ),
            _aggregate_update(
                context,
                kind="traversal-chain",
                partition=chain_key,
                active_delta=-1,
                reserved_units={
                    "pages": core.checked_u64_sub(
                        reserved_pages,
                        1,
                        "traversal reserved pages",
                    )
                },
                committed_units={
                    "pages": pages_after,
                    "records": records_after,
                    "bytes": bytes_after,
                    "rootHistory": root_history,
                },
                minimum_expiry_epoch_ns=None,
                expiry_index_root_digest=core.framed_digest(
                    "serverware.policyAuthorityTraversalExpiryIndexDelta/v1",
                    str(aggregate["expiry_index_root_digest"]).encode(
                        "ascii"
                    ),
                    reservation_id.encode("utf-8"),
                    b"committed",
                ),
            ),
        )
        return core.KernelTransition(
            mutations=tuple(mutations),
            result=_traversal_result(
                chain=chain_after,
                reservation_id=reservation_id,
                target="committed",
                page_number=int(page["page_number"]),
                idempotent_replay=False,
            )
            | {"allowed": True, "reason": "committed"},
            work_units=48 + len(mutations),
        )


_POLICY_BUDGET_FIELDS = frozenset(
    {
        "type",
        "constraint_id",
        "budget_key",
        "principal_id",
        "route_id",
        "credential_id",
        "credential_version",
        "policy_hash",
        "operation",
        "window_semantics",
        "measure",
        "reservation_mode",
        "on_overflow",
        "unit_field",
        "units",
        "window_seconds",
        "max_units",
    }
)
_POLICY_TRAVERSAL_FIELDS = frozenset(
    {
        "type",
        "constraint_id",
        "chain_key",
        "lineage_digest",
        "principal_id",
        "route_id",
        "credential_id",
        "credential_version",
        "policy_hash",
        "operation",
        "store",
        "phases",
        "on_replay",
        "on_cross_lineage",
        "on_missing_evidence",
        "request_cursor_digest",
        "request_cursor_source",
        "request_cursor_field",
        "response_cursor_field",
        "record_count_field",
        "byte_source",
        "commit_mode",
        "max_pages",
        "max_records",
        "max_bytes",
        "lifetime_seconds",
    }
)


def _plain_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(core.canonical_bytes(value)).hexdigest()


def _policy_claims(
    value: Any,
    *,
    policy_hash: str | None = None,
) -> tuple[dict[str, Any], ...]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 12
    ):
        raise core.TransitionKernelError(
            "policy-state claims are not a bounded non-empty array"
        )
    claims: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    aggregate_partitions: set[tuple[str, str]] = set()
    for raw in value:
        if not isinstance(raw, Mapping):
            raise core.TransitionKernelError(
                "policy-state claim is not an exact object"
            )
        claim = dict(raw)
        claim_type = claim.get("type")
        if claim_type in {"slidingWindowLimit", "weightedBudget"}:
            if (
                set(claim) != _POLICY_BUDGET_FIELDS
                or claim.get("window_semantics") != "sliding"
                or claim.get("reservation_mode")
                    != "atomicReserveCommitRelease"
                or claim.get("on_overflow") != "deny"
            ):
                raise core.TransitionKernelError(
                    "policy-state budget claim is not exact"
                )
            _digest(claim.get("budget_key"), "policy budget key")
            _integer(claim.get("units"), "policy budget units")
            _integer(
                claim.get("window_seconds"),
                "policy budget window",
                minimum=1,
                maximum=31_536_000,
            )
            _integer(
                claim.get("max_units"),
                "policy budget maximum",
                minimum=1,
            )
            operation = _text(
                claim.get("operation"),
                "policy budget operation",
                maximum_bytes=512,
                allow_empty=True,
            )
            units = _integer(
                claim.get("units"),
                "policy budget units",
            )
            maximum = _integer(
                claim.get("max_units"),
                "policy budget maximum",
                minimum=1,
            )
            if (
                claim.get("measure")
                != (
                    "weightedCanonicalInteger"
                    if claim_type == "weightedBudget"
                    else "operationCount"
                )
                or units > maximum
                or (
                    claim_type == "slidingWindowLimit"
                    and (
                        units != 1
                        or claim.get("unit_field") != "operations"
                    )
                )
                or operation != claim.get("operation")
            ):
                raise core.TransitionKernelError(
                    "policy-state budget claim semantics differ"
                )
            aggregate_partition = (
                "durable-budget",
                str(claim["budget_key"]),
            )
        elif claim_type == "traversalBudget":
            if (
                set(claim) != _POLICY_TRAVERSAL_FIELDS
                or claim.get("store") != "shared"
                or claim.get("phases") != ["request", "response"]
                or claim.get("on_replay") != "deny"
                or claim.get("on_cross_lineage") != "deny"
                or claim.get("on_missing_evidence") != "deny"
                or claim.get("byte_source")
                    != "validatedDecodedResponseBytes"
                or claim.get("commit_mode")
                    != "atomicAfterResponseValidation"
            ):
                raise core.TransitionKernelError(
                    "policy-state traversal claim is not exact"
                )
            _digest(claim.get("chain_key"), "policy traversal chain")
            _digest(claim.get("lineage_digest"), "policy traversal lineage")
            _optional_digest(
                claim.get("request_cursor_digest"),
                "policy traversal cursor",
            )
            _text(
                claim.get("operation"),
                "policy traversal operation",
                maximum_bytes=512,
            )
            request_source = _text(
                claim.get("request_cursor_source"),
                "policy traversal cursor source",
                maximum_bytes=32,
            )
            for field in (
                "request_cursor_field",
                "response_cursor_field",
                "record_count_field",
            ):
                _text(
                    claim.get(field),
                    f"policy traversal {field}",
                    maximum_bytes=256,
                )
            _integer(
                claim.get("max_pages"),
                "policy traversal maximum pages",
                minimum=1,
                maximum=1_000_000,
            )
            _integer(
                claim.get("max_records"),
                "policy traversal maximum records",
                minimum=1,
            )
            _integer(
                claim.get("max_bytes"),
                "policy traversal maximum bytes",
                minimum=1,
            )
            _integer(
                claim.get("lifetime_seconds"),
                "policy traversal lifetime",
                minimum=1,
                maximum=31_536_000,
            )
            if request_source not in {"query", "header"}:
                raise core.TransitionKernelError(
                    "policy traversal cursor source is invalid"
                )
            aggregate_partition = (
                "traversal-chain",
                str(claim["chain_key"]),
            )
        else:
            raise core.TransitionKernelError(
                "policy-state claim type is unsupported"
            )
        if policy_hash is not None and claim.get("policy_hash") != policy_hash:
            raise core.TransitionKernelError(
                "policy-state claim policy differs"
            )
        constraint_id = _text(
            claim.get("constraint_id"),
            "policy-state constraint",
            maximum_bytes=512,
        )
        identity = (str(claim_type), constraint_id)
        if identity in identities:
            raise core.TransitionKernelError(
                "policy-state claim identity is duplicated"
            )
        identities.add(identity)
        if aggregate_partition in aggregate_partitions:
            raise core.TransitionKernelError(
                "policy-state aggregate partition is duplicated"
            )
        aggregate_partitions.add(aggregate_partition)
        claims.append(claim)
    if len(core.canonical_bytes(claims)) > 256 * 1024:
        raise core.TransitionKernelError(
            "policy-state claims exceed their bound"
        )
    return tuple(claims)


def _policy_child_id(
    reservation_id: str,
    index: int,
    claim: Mapping[str, Any],
) -> str:
    return _plain_digest(
        {
            "bundleReservationId": reservation_id,
            "claimIndex": index,
            "claim": dict(claim),
        }
    )


def _policy_reservation_id(
    *,
    attempt_id: str,
    policy_hash: str,
    request_digest: str,
    operation_digest: str,
    claim_digest: str,
) -> str:
    return _plain_digest(
        {
            "attemptId": attempt_id,
            "policyHash": policy_hash,
            "requestDigest": request_digest,
            "operationDigest": operation_digest,
            "claimDigest": claim_digest,
        }
    )


def _policy_state_result(
    *,
    state: str,
    attempt_id: str,
    claim_digest: str,
    reservation_id: str,
    reason: str | None = None,
    replay: bool = False,
) -> dict[str, Any]:
    return {
        "ok": state not in {"denied", "indeterminate"},
        "state": state,
        "attempt_id": attempt_id,
        "claim_digest": claim_digest,
        "reservation_id": reservation_id,
        "reason": reason or state,
        "idempotent_replay": replay,
        "policy_state_store_backend": "postgres",
        "policy_state_store_ha": True,
    }


def _policy_child_queries(
    *,
    operation: str,
    reservation_id: str,
    claims: tuple[dict[str, Any], ...],
    traversal_evidence: tuple[dict[str, Any], ...] = (),
) -> tuple[core.BoundedQuery, ...]:
    queries: list[core.BoundedQuery] = []
    traversal_index = 0
    for index, claim in enumerate(claims):
        child_id = _policy_child_id(reservation_id, index, claim)
        if claim["type"] in {"slidingWindowLimit", "weightedBudget"}:
            budget_key = str(claim["budget_key"])
            queries.extend(
                (
                    _query(
                        operation=operation,
                        name=f"budget_definition_{index}",
                        table="durable_budget_definitions",
                        key={"budget_key": budget_key},
                    ),
                    _query(
                        operation=operation,
                        name=f"budget_event_{index}",
                        table="durable_budget_events",
                        key={"reservation_id": child_id},
                    ),
                    _aggregate_query(
                        operation,
                        f"budget_high_water_{index}",
                        "durable-budget",
                        budget_key,
                    ),
                )
            )
        else:
            chain_key = str(claim["chain_key"])
            queries.extend(
                (
                    _query(
                        operation=operation,
                        name=f"traversal_chain_{index}",
                        table="traversal_budget_chains",
                        key={"chain_key": chain_key},
                    ),
                    _query(
                        operation=operation,
                        name=f"traversal_page_{index}",
                        table="traversal_budget_page_reservations",
                        key={"reservation_id": child_id},
                    ),
                    _aggregate_query(
                        operation,
                        f"traversal_high_water_{index}",
                        "traversal-chain",
                        chain_key,
                    ),
                )
            )
            cursor_digest = claim.get("request_cursor_digest")
            if cursor_digest is not None:
                queries.append(
                    _query(
                        operation=operation,
                        name=f"traversal_cursor_{index}",
                        table="traversal_budget_cursors",
                        key={"cursor_digest": cursor_digest},
                    )
                )
            if traversal_index < len(traversal_evidence):
                next_cursor = traversal_evidence[traversal_index].get(
                    "next_cursor_digest"
                )
                if next_cursor is not None:
                    queries.append(
                        _query(
                            operation=operation,
                            name=f"traversal_next_cursor_{index}",
                            table="traversal_budget_cursors",
                            key={"cursor_digest": next_cursor},
                        )
                    )
            traversal_index += 1
    return tuple(queries)


@dataclass(frozen=True, slots=True)
class _PolicyStateReserveKernel:
    operation: str = "quota.policy-state.reserve"
    handler: str = "reserve_policy_state_bundle"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "quota.policy-state.reserve",
        "reserve_policy_state_bundle",
    )

    _FIELDS = frozenset(
        {
            "attempt_id",
            "policy_hash",
            "request_digest",
            "operation_digest",
            "release_binding_digest",
            "claims",
            "claim_digest",
            "actor_id",
            "reservation_deadline_at_epoch_ms",
            "now_epoch_ms",
        }
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "policy-state reserve request")
        _exact_arguments(arguments, required=self._FIELDS)
        attempt_id = _text(
            arguments["attempt_id"],
            "policy-state attempt",
            maximum_bytes=512,
        )
        policy_hash = _digest(
            arguments["policy_hash"],
            "policy-state policy",
        )
        claims = _policy_claims(
            arguments["claims"],
            policy_hash=policy_hash,
        )
        claim_digest = _digest(
            arguments["claim_digest"],
            "policy-state claim digest",
        )
        if claim_digest != _plain_digest(list(claims)):
            raise core.TransitionKernelError(
                "policy-state claim digest differs"
            )
        reservation_id = _policy_reservation_id(
            attempt_id=attempt_id,
            policy_hash=policy_hash,
            request_digest=_digest(
                arguments["request_digest"],
                "policy-state request",
            ),
            operation_digest=_digest(
                arguments["operation_digest"],
                "policy-state operation",
            ),
            claim_digest=claim_digest,
        )
        return (
            _query(
                operation=self.operation,
                name="release",
                table="release_authorization_attempts",
                key={"attempt_id": attempt_id},
            ),
            _query(
                operation=self.operation,
                name="bundle",
                table="policy_state_bundles",
                key={"reservation_id": reservation_id},
            ),
            *_policy_child_queries(
                operation=self.operation,
                reservation_id=reservation_id,
                claims=claims,
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        _exact_arguments(context.arguments, required=self._FIELDS)
        attempt_id = _text(
            context.arguments["attempt_id"],
            "policy-state attempt",
            maximum_bytes=512,
        )
        policy_hash = _digest(
            context.arguments["policy_hash"],
            "policy-state policy",
        )
        request_digest = _digest(
            context.arguments["request_digest"],
            "policy-state request",
        )
        operation_digest = _digest(
            context.arguments["operation_digest"],
            "policy-state operation",
        )
        release_binding_digest = _digest(
            context.arguments["release_binding_digest"],
            "policy-state release binding",
        )
        claims = _policy_claims(
            context.arguments["claims"],
            policy_hash=policy_hash,
        )
        claims_json = core.canonical_bytes(list(claims)).decode("ascii")
        claim_digest = _digest(
            context.arguments["claim_digest"],
            "policy-state claim digest",
        )
        if claim_digest != _plain_digest(list(claims)):
            raise core.TransitionKernelError(
                "policy-state claim digest differs"
            )
        actor_id = _text(
            context.arguments["actor_id"],
            "policy-state actor",
            maximum_bytes=512,
        )
        deadline = _integer(
            context.arguments["reservation_deadline_at_epoch_ms"],
            "policy-state reservation deadline",
            minimum=1,
        )
        now_ms = (
            _database_epoch_ms(context.database_now)
            if context.arguments["now_epoch_ms"] is None
            else _integer(
                context.arguments["now_epoch_ms"],
                "policy-state observation time",
            )
        )
        if not now_ms < deadline <= now_ms + 300_000:
            raise core.TransitionKernelError(
                "policy-state reservation deadline is invalid"
            )
        reservation_id = _policy_reservation_id(
            attempt_id=attempt_id,
            policy_hash=policy_hash,
            request_digest=request_digest,
            operation_digest=operation_digest,
            claim_digest=claim_digest,
        )
        release = _row(
            context.exact(
                "release_authorization_attempts",
                {"attempt_id": attempt_id},
            ),
            "release authorization",
        )
        if (
            release.get("state") != "reserved"
            or release.get("binding_digest") != release_binding_digest
            or release.get("policy_hash") != policy_hash
            or release.get("request_digest") != request_digest
            or release.get("operation_digest") != operation_digest
            or release.get("reservation_expires_at_epoch_ms") != deadline
        ):
            raise core.TransitionKernelError(
                "policy-state release authority is not exact"
            )
        bundle_selected, bundle = _selected_or_none(
            context,
            "policy_state_bundles",
            {"reservation_id": reservation_id},
        )
        binding = {
            "reservation_id": reservation_id,
            "attempt_id": attempt_id,
            "policy_hash": policy_hash,
            "request_digest": request_digest,
            "operation_digest": operation_digest,
            "claim_digest": claim_digest,
            "claims_json": claims_json,
            "release_binding_digest": release_binding_digest,
            "reservation_deadline_at_epoch_ms": deadline,
            "actor_id": actor_id,
        }
        if bundle is not None:
            if any(bundle.get(field) != value for field, value in binding.items()):
                raise core.TransitionKernelError(
                    "policy-state bundle identity was rebound"
                )
            if bundle.get("state") != "reserved":
                raise core.TransitionKernelError(
                    "policy-state reserve replay is terminal"
                )
            return core.KernelTransition(
                mutations=(),
                result=_policy_state_result(
                    state="reserved",
                    attempt_id=attempt_id,
                    claim_digest=claim_digest,
                    reservation_id=reservation_id,
                    reason="idempotent_replay",
                    replay=True,
                ),
                work_units=16,
            )
        now_s = _iso_from_epoch_ms(now_ms)
        mutations: list[dict[str, Any]] = []
        for index, claim in enumerate(claims):
            child_id = _policy_child_id(reservation_id, index, claim)
            if claim["type"] in {"slidingWindowLimit", "weightedBudget"}:
                budget_key = str(claim["budget_key"])
                definition_selected, definition = _selected_or_none(
                    context,
                    "durable_budget_definitions",
                    {"budget_key": budget_key},
                )
                definition_binding = {
                    "budget_key": budget_key,
                    "principal_id": claim["principal_id"],
                    "route_id": claim["route_id"],
                    "credential_id": claim["credential_id"],
                    "credential_version": claim["credential_version"],
                    "policy_hash": claim["policy_hash"],
                    "constraint_id": claim["constraint_id"],
                    "unit_field": claim["unit_field"],
                    "window_kind": "sliding",
                    "window_seconds": claim["window_seconds"],
                    "max_units": claim["max_units"],
                }
                if definition is None:
                    definition = {
                        **definition_binding,
                        "last_observed_epoch_ms": now_ms,
                        "created_at": now_s,
                        "updated_at": now_s,
                    }
                elif any(
                    definition.get(field) != value
                    for field, value in definition_binding.items()
                ):
                    raise core.TransitionKernelError(
                        "policy-state budget definition was rebound"
                    )
                aggregate_id, partition_digest = _aggregate_key(
                    "durable-budget",
                    budget_key,
                )
                aggregate = context.bounded_aggregate(
                    aggregate_id=aggregate_id,
                    aggregate_kind="durable-budget",
                    partition_digest=partition_digest,
                )
                reserved, committed = _budget_units(aggregate)
                units = _integer(
                    claim["units"],
                    "policy-state budget units",
                )
                total = core.checked_u64_add(
                    core.checked_u64_add(
                        reserved,
                        committed,
                        "policy-state budget total",
                    ),
                    units,
                    "policy-state budget requested total",
                )
                if total > int(claim["max_units"]):
                    return core.KernelTransition(
                        mutations=(),
                        result=_policy_state_result(
                            state="denied",
                            attempt_id=attempt_id,
                            claim_digest=claim_digest,
                            reservation_id=reservation_id,
                            reason="sliding_budget_exceeded",
                        ),
                        work_units=24,
                    )
                event_selected, event = _selected_or_none(
                    context,
                    "durable_budget_events",
                    {"reservation_id": child_id},
                )
                if event is not None:
                    raise core.TransitionKernelError(
                        "policy-state child identity already exists"
                    )
                expiry = now_ms + int(claim["window_seconds"]) * 1000
                mutations.extend(
                    (
                        core.mutation(
                            operation=self.operation,
                            selected=definition_selected,
                            row={
                                **definition,
                                "last_observed_epoch_ms": now_ms,
                                "updated_at": now_s,
                            },
                        ),
                        core.mutation(
                            operation=self.operation,
                            selected=event_selected,
                            row={
                                "reservation_id": child_id,
                                "bundle_reservation_id": reservation_id,
                                "budget_key": budget_key,
                                "request_digest": request_digest,
                                "operation_digest": operation_digest,
                                "units": units,
                                "state": "reserved",
                                "occurred_at_epoch_ms": now_ms,
                                "expires_at_epoch_ms": expiry,
                                "reservation_expires_at_epoch_ms":
                                    deadline,
                                "created_at": now_s,
                                "updated_at": now_s,
                            },
                        ),
                        _aggregate_update(
                            context,
                            kind="durable-budget",
                            partition=budget_key,
                            live_delta=1,
                            active_delta=1,
                            reserved_units={
                                "units": reserved + units
                            },
                            committed_units={"units": committed},
                            next_sequence_delta=1,
                            minimum_expiry_epoch_ns=deadline * 1_000_000,
                            expiry_index_root_digest=core.framed_digest(
                                (
                                    "serverware."
                                    "policyAuthorityBudgetExpiryIndexDelta/v1"
                                ),
                                str(
                                    aggregate[
                                        "expiry_index_root_digest"
                                    ]
                                ).encode("ascii"),
                                child_id.encode("ascii"),
                            ),
                        ),
                    )
                )
                continue
            chain_key = str(claim["chain_key"])
            chain_selected, chain = _selected_or_none(
                context,
                "traversal_budget_chains",
                {"chain_key": chain_key},
            )
            aggregate_id, partition_digest = _aggregate_key(
                "traversal-chain",
                chain_key,
            )
            aggregate = context.bounded_aggregate(
                aggregate_id=aggregate_id,
                aggregate_kind="traversal-chain",
                partition_digest=partition_digest,
            )
            (
                reserved_pages,
                committed_pages,
                committed_records,
                committed_bytes,
                root_history,
            ) = _traversal_aggregate_units(aggregate)
            if committed_pages + reserved_pages >= int(claim["max_pages"]):
                return core.KernelTransition(
                    mutations=(),
                    result=_policy_state_result(
                        state="denied",
                        attempt_id=attempt_id,
                        claim_digest=claim_digest,
                        reservation_id=reservation_id,
                        reason="traversal_page_budget_exceeded",
                    ),
                    work_units=24,
                )
            if chain is None:
                if claim.get("request_cursor_digest") is not None:
                    raise core.TransitionKernelError(
                        "policy-state new traversal has a cursor"
                    )
                chain = {
                    "chain_key": chain_key,
                    "lineage_digest": claim["lineage_digest"],
                    "principal_id": claim["principal_id"],
                    "route_id": claim["route_id"],
                    "credential_id": claim["credential_id"],
                    "credential_version": claim["credential_version"],
                    "policy_hash": claim["policy_hash"],
                    "constraint_id": claim["constraint_id"],
                    "state": "active",
                    "started_at_epoch_ms": now_ms,
                    "expires_at_epoch_ms":
                        now_ms + int(claim["lifetime_seconds"]) * 1000,
                    "last_observed_epoch_ms": now_ms,
                    "max_pages": claim["max_pages"],
                    "max_records": claim["max_records"],
                    "max_bytes": claim["max_bytes"],
                    "page_count": 0,
                    "record_count": 0,
                    "byte_count": 0,
                    "created_at": now_s,
                    "updated_at": now_s,
                }
            elif (
                chain.get("lineage_digest") != claim["lineage_digest"]
                or chain.get("policy_hash") != policy_hash
                or chain.get("state") != "active"
            ):
                raise core.TransitionKernelError(
                    "policy-state traversal chain differs"
                )
            cursor_digest = claim.get("request_cursor_digest")
            if cursor_digest is None and root_history > 0:
                return core.KernelTransition(
                    mutations=(),
                    result=_policy_state_result(
                        state="denied",
                        attempt_id=attempt_id,
                        claim_digest=claim_digest,
                        reservation_id=reservation_id,
                        reason="root_request_replayed",
                    ),
                    work_units=24,
                )
            if cursor_digest is not None:
                cursor_selected = context.exact(
                    "traversal_budget_cursors",
                    {"cursor_digest": cursor_digest},
                )
                cursor = _row(
                    cursor_selected,
                    "policy-state traversal cursor",
                )
                if (
                    cursor.get("state") != "available"
                    or cursor.get("chain_key") != chain_key
                    or cursor.get("lineage_digest")
                        != claim["lineage_digest"]
                ):
                    raise core.TransitionKernelError(
                        "policy-state traversal cursor is unavailable"
                    )
                mutations.append(
                    core.mutation(
                        operation=self.operation,
                        selected=cursor_selected,
                        row={
                            **cursor,
                            "state": "reserved",
                            "reserved_by": child_id,
                            "updated_at": now_s,
                        },
                    )
                )
            page_selected, page = _selected_or_none(
                context,
                "traversal_budget_page_reservations",
                {"reservation_id": child_id},
            )
            if page is not None:
                raise core.TransitionKernelError(
                    "policy-state traversal child already exists"
                )
            mutations.extend(
                (
                    core.mutation(
                        operation=self.operation,
                        selected=chain_selected,
                        row={
                            **chain,
                            "last_observed_epoch_ms": now_ms,
                            "updated_at": now_s,
                        },
                    ),
                    core.mutation(
                        operation=self.operation,
                        selected=page_selected,
                        row={
                            "reservation_id": child_id,
                            "bundle_reservation_id": reservation_id,
                            "chain_key": chain_key,
                            "lineage_digest": claim["lineage_digest"],
                            "request_digest": request_digest,
                            "request_cursor_digest": cursor_digest,
                            "page_number":
                                committed_pages + reserved_pages + 1,
                            "state": "reserved",
                            "response_digest": None,
                            "response_records": None,
                            "response_bytes": None,
                            "next_cursor_digest": None,
                            "reservation_expires_at_epoch_ms": deadline,
                            "created_at": now_s,
                            "updated_at": now_s,
                        },
                    ),
                    _aggregate_update(
                        context,
                        kind="traversal-chain",
                        partition=chain_key,
                        live_delta=1,
                        active_delta=1,
                        reserved_units={"pages": reserved_pages + 1},
                        committed_units={
                            "pages": committed_pages,
                            "records": committed_records,
                            "bytes": committed_bytes,
                            "rootHistory": (
                                root_history + 1
                                if cursor_digest is None
                                else root_history
                            ),
                        },
                        next_sequence_delta=1,
                        minimum_expiry_epoch_ns=deadline * 1_000_000,
                        expiry_index_root_digest=core.framed_digest(
                            (
                                "serverware."
                                "policyAuthorityTraversalExpiryIndexDelta/v1"
                            ),
                            str(
                                aggregate["expiry_index_root_digest"]
                            ).encode("ascii"),
                            child_id.encode("ascii"),
                        ),
                    ),
                )
            )
        bundle = {
            **binding,
            "state": "reserved",
            "dispatch_started_at_epoch_ms": None,
            "dispatch_deadline_at_epoch_ms": None,
            "completion_dispatch_deadline_at_epoch_ms": None,
            "response_evidence_digest": None,
            "response_evidence_json": None,
            "terminal_reason": None,
            "response_body_sha256": None,
            "uncertainty": None,
            "created_at": now_s,
            "updated_at": now_s,
        }
        mutations.append(
            core.mutation(
                operation=self.operation,
                selected=bundle_selected,
                row=bundle,
            )
        )
        return core.KernelTransition(
            mutations=tuple(mutations),
            result=_policy_state_result(
                state="reserved",
                attempt_id=attempt_id,
                claim_digest=claim_digest,
                reservation_id=reservation_id,
            ),
            work_units=64 + len(mutations) * 4,
        )


@dataclass(frozen=True, slots=True)
class _PolicyStateLifecycleKernel:
    operation: str
    handler: str
    mode: str
    permits_empty_mutation: bool = True

    @property
    def program_id(self) -> str:
        return core.transition_program_id(self.operation, self.handler)

    _FIELDS = frozenset(
        {
            "reservation_id",
            "attempt_id",
            "claim_digest",
            "actor_id",
            "claims",
            "now_epoch_ms",
            "response_evidence_digest",
            "traversal_evidence",
            "terminal_reason",
            "response_body_sha256",
        }
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        _digest(request_digest, "policy-state lifecycle request")
        _exact_arguments(arguments, required=self._FIELDS)
        reservation_id = _digest(
            arguments["reservation_id"],
            "policy-state reservation",
        )
        attempt_id = _text(
            arguments["attempt_id"],
            "policy-state attempt",
            maximum_bytes=512,
        )
        claims = _policy_claims(arguments["claims"])
        traversal_evidence_value = arguments["traversal_evidence"]
        if not isinstance(traversal_evidence_value, list):
            raise core.TransitionKernelError(
                "policy-state traversal evidence is not an array"
            )
        traversal_evidence = tuple(
            dict(item)
            for item in traversal_evidence_value
            if isinstance(item, Mapping)
        )
        if len(traversal_evidence) != len(traversal_evidence_value):
            raise core.TransitionKernelError(
                "policy-state traversal evidence is not exact"
            )
        queries: list[core.BoundedQuery] = [
            _query(
                operation=self.operation,
                name="bundle",
                table="policy_state_bundles",
                key={"reservation_id": reservation_id},
            ),
        ]
        if self.mode in {"dispatch", "complete", "reconcile"}:
            queries.append(
                _query(
                    operation=self.operation,
                    name="release",
                    table="release_authorization_attempts",
                    key={"attempt_id": attempt_id},
                )
            )
        queries.extend(
            _policy_child_queries(
                operation=self.operation,
                reservation_id=reservation_id,
                claims=claims,
                traversal_evidence=traversal_evidence,
            )
        )
        evidence_digest = arguments["response_evidence_digest"]
        if self.mode in {"complete", "fail"} or (
            self.mode == "reconcile" and evidence_digest is not None
        ):
            queries.append(
                _query(
                    operation=self.operation,
                    name="response_evidence",
                    table="policy_authority_external_evidence_receipts",
                    key={
                        "evidence_digest": _digest(
                            evidence_digest,
                            "policy-state response evidence",
                        )
                    },
                )
            )
        elif evidence_digest is not None:
            raise core.TransitionKernelError(
                "policy-state evidence exceeds this lifecycle mode"
            )
        return tuple(queries)

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        _exact_arguments(context.arguments, required=self._FIELDS)
        reservation_id = _digest(
            context.arguments["reservation_id"],
            "policy-state reservation",
        )
        attempt_id = _text(
            context.arguments["attempt_id"],
            "policy-state attempt",
            maximum_bytes=512,
        )
        claim_digest = _digest(
            context.arguments["claim_digest"],
            "policy-state claim digest",
        )
        actor_id = _text(
            context.arguments["actor_id"],
            "policy-state actor",
            maximum_bytes=512,
        )
        claims = _policy_claims(context.arguments["claims"])
        claims_json = core.canonical_bytes(list(claims)).decode("ascii")
        if claim_digest != _plain_digest(list(claims)):
            raise core.TransitionKernelError(
                "policy-state claim digest differs"
            )
        now_ms = (
            _database_epoch_ms(context.database_now)
            if context.arguments["now_epoch_ms"] is None
            else _integer(
                context.arguments["now_epoch_ms"],
                "policy-state observation time",
            )
        )
        bundle_selected = context.exact(
            "policy_state_bundles",
            {"reservation_id": reservation_id},
        )
        bundle = _row(bundle_selected, "policy-state bundle")
        if (
            bundle.get("attempt_id") != attempt_id
            or bundle.get("claim_digest") != claim_digest
            or bundle.get("claims_json") != claims_json
            or bundle.get("actor_id") != actor_id
        ):
            raise core.TransitionKernelError(
                "policy-state lifecycle binding differs"
            )
        source_state = str(bundle.get("state"))
        mode = self.mode
        if mode == "reconcile":
            if (
                source_state == "reserved"
                and int(bundle["reservation_deadline_at_epoch_ms"])
                    <= now_ms
            ):
                mode = "abort"
            elif (
                source_state == "dispatched"
                and int(bundle["dispatch_deadline_at_epoch_ms"])
                    <= now_ms
            ):
                mode = "fail"
            else:
                return core.KernelTransition(
                    mutations=(),
                    result=_policy_state_result(
                        state=source_state,
                        attempt_id=attempt_id,
                        claim_digest=claim_digest,
                        reservation_id=reservation_id,
                        reason="not_due",
                        replay=True,
                    ),
                    work_units=16,
                )
        target = {
            "dispatch": "dispatched",
            "complete": "committed",
            "abort": "aborted",
            "fail": "indeterminate",
        }[mode]
        replay = source_state == target
        expected_source = (
            "reserved" if mode in {"dispatch", "abort"} else "dispatched"
        )
        if not replay and source_state != expected_source:
            raise core.TransitionKernelError(
                "policy-state lifecycle source state is invalid"
            )
        if not replay and mode in {"dispatch", "complete"}:
            release = _row(
                context.exact(
                    "release_authorization_attempts",
                    {"attempt_id": attempt_id},
                ),
                "release authorization",
            )
            required_release_state = (
                "dispatching" if mode == "dispatch" else "committed"
            )
            if release.get("state") != required_release_state:
                raise core.TransitionKernelError(
                    "policy-state release lifecycle differs"
                )
        traversal_evidence_raw = context.arguments["traversal_evidence"]
        if not isinstance(traversal_evidence_raw, list):
            raise core.TransitionKernelError(
                "policy-state traversal evidence is not an array"
            )
        traversal_evidence = [
            dict(item)
            for item in traversal_evidence_raw
            if isinstance(item, Mapping)
        ]
        traversal_claim_count = sum(
            1 for claim in claims if claim["type"] == "traversalBudget"
        )
        if (
            mode == "complete"
            and len(traversal_evidence) != traversal_claim_count
            or mode != "complete"
            and traversal_evidence
        ):
            raise core.TransitionKernelError(
                "policy-state traversal evidence coverage differs"
            )
        response_evidence_digest = context.arguments[
            "response_evidence_digest"
        ]
        evidence_mutations: tuple[dict[str, Any], ...] = ()
        if mode in {"complete", "fail"}:
            response_evidence_digest = _digest(
                response_evidence_digest,
                "policy-state response evidence",
            )
            evidence_mutations = _consume_exact_evidence(
                context,
                evidence_type=(
                    "response-validation/v2"
                    if mode == "complete"
                    else "dispatcher-forwarding/v1"
                ),
                evidence_digest=response_evidence_digest,
                binding={
                    "schema":
                        "serverware.policyStateExternalResult/v2",
                    "operation": self.operation,
                    "requestDigest": context.request_digest,
                    "reservationId": reservation_id,
                    "attemptId": attempt_id,
                    "claimDigest": claim_digest,
                    "outcome": (
                        "validated"
                        if mode == "complete"
                        else "indeterminate"
                    ),
                    "traversalEvidence": traversal_evidence,
                    "responseBodySha256":
                        context.arguments["response_body_sha256"],
                },
                replay=replay,
            )
        elif response_evidence_digest is not None:
            raise core.TransitionKernelError(
                "policy-state evidence exceeds this lifecycle mode"
            )
        terminal_reason = context.arguments["terminal_reason"]
        if terminal_reason is not None:
            terminal_reason = _text(
                terminal_reason,
                "policy-state terminal reason",
                maximum_bytes=256,
            )
        response_body_sha256 = _optional_digest(
            context.arguments["response_body_sha256"],
            "policy-state response body",
        )
        response_evidence_json = (
            core.canonical_bytes(traversal_evidence).decode("ascii")
            if traversal_evidence
            else None
        )
        if replay:
            if (
                bundle.get("response_evidence_digest")
                    != response_evidence_digest
                or bundle.get("response_evidence_json")
                    != response_evidence_json
                or bundle.get("terminal_reason") != terminal_reason
                or bundle.get("response_body_sha256")
                    != response_body_sha256
                or bundle.get("uncertainty")
                    != (
                        "unknown-result-charged"
                        if mode == "fail"
                        else None
                    )
            ):
                raise core.TransitionKernelError(
                    "policy-state lifecycle replay conflicts"
                )
            return core.KernelTransition(
                mutations=evidence_mutations,
                result=_policy_state_result(
                    state=target,
                    attempt_id=attempt_id,
                    claim_digest=claim_digest,
                    reservation_id=reservation_id,
                    reason=terminal_reason or "idempotent_replay",
                    replay=True,
                ),
                work_units=24 + len(evidence_mutations),
            )
        now_s = _iso_from_epoch_ms(now_ms)
        mutations: list[dict[str, Any]] = list(evidence_mutations)
        traversal_index = 0
        for index, claim in enumerate(claims):
            child_id = _policy_child_id(reservation_id, index, claim)
            if claim["type"] in {"slidingWindowLimit", "weightedBudget"}:
                event_selected = context.exact(
                    "durable_budget_events",
                    {"reservation_id": child_id},
                )
                event = _row(
                    event_selected,
                    "policy-state budget child",
                )
                definition_selected = context.exact(
                    "durable_budget_definitions",
                    {"budget_key": claim["budget_key"]},
                )
                definition = _row(
                    definition_selected,
                    "policy-state budget definition",
                )
                aggregate_id, partition_digest = _aggregate_key(
                    "durable-budget",
                    claim["budget_key"],
                )
                aggregate = context.bounded_aggregate(
                    aggregate_id=aggregate_id,
                    aggregate_kind="durable-budget",
                    partition_digest=partition_digest,
                )
                reserved, committed = _budget_units(aggregate)
                units = int(event["units"])
                if event.get("state") != expected_source:
                    raise core.TransitionKernelError(
                        "policy-state budget child state differs"
                    )
                if mode == "dispatch":
                    event_target = "dispatched"
                    reserved_after = core.checked_u64_sub(
                        reserved,
                        units,
                        "policy-state reserved budget",
                    )
                    committed_after = core.checked_u64_add(
                        committed,
                        units,
                        "policy-state dispatched budget",
                    )
                    active_delta = 0
                elif mode == "abort":
                    event_target = "cancelled"
                    reserved_after = core.checked_u64_sub(
                        reserved,
                        units,
                        "policy-state reserved budget",
                    )
                    committed_after = committed
                    active_delta = -1
                else:
                    event_target = "committed"
                    reserved_after = reserved
                    committed_after = committed
                    active_delta = 0
                mutations.extend(
                    (
                        core.mutation(
                            operation=self.operation,
                            selected=event_selected,
                            row={
                                **event,
                                "state": event_target,
                                "reservation_expires_at_epoch_ms":
                                    None,
                                "updated_at": now_s,
                            },
                        ),
                        core.mutation(
                            operation=self.operation,
                            selected=definition_selected,
                            row={
                                **definition,
                                "last_observed_epoch_ms": now_ms,
                                "updated_at": now_s,
                            },
                        ),
                        _aggregate_update(
                            context,
                            kind="durable-budget",
                            partition=claim["budget_key"],
                            active_delta=active_delta,
                            reserved_units={
                                "units": reserved_after
                            },
                            committed_units={
                                "units": committed_after
                            },
                            minimum_expiry_epoch_ns=(
                                None
                                if mode == "abort"
                                else int(event["expires_at_epoch_ms"])
                                    * 1_000_000
                            ),
                            expiry_index_root_digest=core.framed_digest(
                                (
                                    "serverware."
                                    "policyAuthorityBudgetExpiryIndexDelta/v1"
                                ),
                                str(
                                    aggregate[
                                        "expiry_index_root_digest"
                                    ]
                                ).encode("ascii"),
                                child_id.encode("ascii"),
                                event_target.encode("ascii"),
                            ),
                        ),
                    )
                )
                continue
            page_selected = context.exact(
                "traversal_budget_page_reservations",
                {"reservation_id": child_id},
            )
            page = _row(
                page_selected,
                "policy-state traversal child",
            )
            chain_selected = context.exact(
                "traversal_budget_chains",
                {"chain_key": claim["chain_key"]},
            )
            chain = _row(
                chain_selected,
                "policy-state traversal chain",
            )
            aggregate_id, partition_digest = _aggregate_key(
                "traversal-chain",
                claim["chain_key"],
            )
            aggregate = context.bounded_aggregate(
                aggregate_id=aggregate_id,
                aggregate_kind="traversal-chain",
                partition_digest=partition_digest,
            )
            (
                reserved_pages,
                committed_pages,
                committed_records,
                committed_bytes,
                root_history,
            ) = _traversal_aggregate_units(aggregate)
            if page.get("state") != expected_source:
                raise core.TransitionKernelError(
                    "policy-state traversal child state differs"
                )
            cursor_digest = page.get("request_cursor_digest")
            cursor_mutations: tuple[dict[str, Any], ...] = ()
            if mode == "abort":
                page_target = "cancelled"
                if cursor_digest is not None:
                    cursor_selected = context.exact(
                        "traversal_budget_cursors",
                        {"cursor_digest": cursor_digest},
                    )
                    cursor = _row(
                        cursor_selected,
                        "policy-state traversal cursor",
                    )
                    if (
                        cursor.get("state") != "reserved"
                        or cursor.get("reserved_by") != child_id
                    ):
                        raise core.TransitionKernelError(
                            "policy-state traversal cursor changed"
                        )
                    cursor_mutations = (
                        core.mutation(
                            operation=self.operation,
                            selected=cursor_selected,
                            row={
                                **cursor,
                                "state": "available",
                                "reserved_by": None,
                                "updated_at": now_s,
                            },
                        ),
                    )
                reserved_after = core.checked_u64_sub(
                    reserved_pages,
                    1,
                    "policy-state reserved traversal pages",
                )
                pages_after = committed_pages
                records_after = committed_records
                bytes_after = committed_bytes
                active_delta = -1
            elif mode == "dispatch":
                page_target = "dispatched"
                reserved_after = reserved_pages
                pages_after = committed_pages
                records_after = committed_records
                bytes_after = committed_bytes
                active_delta = 0
            elif mode == "fail":
                page_target = "indeterminate"
                if cursor_digest is not None:
                    cursor_selected = context.exact(
                        "traversal_budget_cursors",
                        {"cursor_digest": cursor_digest},
                    )
                    cursor = _row(
                        cursor_selected,
                        "policy-state traversal cursor",
                    )
                    if (
                        cursor.get("state") != "reserved"
                        or cursor.get("reserved_by") != child_id
                    ):
                        raise core.TransitionKernelError(
                            "policy-state traversal cursor changed"
                        )
                    cursor_mutations = (
                        core.mutation(
                            operation=self.operation,
                            selected=cursor_selected,
                            row={
                                **cursor,
                                "state": "consumed",
                                "reserved_by": None,
                                "updated_at": now_s,
                            },
                        ),
                    )
                reserved_after = core.checked_u64_sub(
                    reserved_pages,
                    1,
                    "policy-state reserved traversal pages",
                )
                pages_after = core.checked_u64_add(
                    committed_pages,
                    1,
                    "policy-state indeterminate traversal pages",
                )
                records_after = committed_records
                bytes_after = committed_bytes
                active_delta = -1
            else:
                evidence = traversal_evidence[traversal_index]
                traversal_index += 1
                expected_evidence_fields = {
                    "constraint_id",
                    "lineage_digest",
                    "request_cursor_digest",
                    "response_digest",
                    "next_cursor_digest",
                    "record_count",
                    "decoded_bytes",
                    "validation",
                }
                if (
                    set(evidence) != expected_evidence_fields
                    or evidence.get("constraint_id")
                        != claim["constraint_id"]
                    or evidence.get("lineage_digest")
                        != claim["lineage_digest"]
                    or evidence.get("request_cursor_digest")
                        != claim["request_cursor_digest"]
                    or evidence.get("validation") != "passed"
                ):
                    raise core.TransitionKernelError(
                        "policy-state traversal evidence differs"
                    )
                response_records = _integer(
                    evidence["record_count"],
                    "policy-state traversal records",
                )
                response_bytes = _integer(
                    evidence["decoded_bytes"],
                    "policy-state traversal bytes",
                )
                response_digest = _digest(
                    evidence["response_digest"],
                    "policy-state traversal response",
                )
                next_cursor = _optional_digest(
                    evidence.get("next_cursor_digest"),
                    "policy-state traversal next cursor",
                )
                page_target = "committed"
                reserved_after = core.checked_u64_sub(
                    reserved_pages,
                    1,
                    "policy-state reserved traversal pages",
                )
                pages_after = core.checked_u64_add(
                    committed_pages,
                    1,
                    "policy-state committed traversal pages",
                )
                records_after = core.checked_u64_add(
                    committed_records,
                    response_records,
                    "policy-state committed traversal records",
                )
                bytes_after = core.checked_u64_add(
                    committed_bytes,
                    response_bytes,
                    "policy-state committed traversal bytes",
                )
                if (
                    pages_after > int(chain["max_pages"])
                    or records_after > int(chain["max_records"])
                    or bytes_after > int(chain["max_bytes"])
                ):
                    raise core.TransitionKernelError(
                        "policy-state traversal response exceeds budget"
                    )
                active_delta = -1
                if cursor_digest is not None:
                    cursor_selected = context.exact(
                        "traversal_budget_cursors",
                        {"cursor_digest": cursor_digest},
                    )
                    cursor = _row(
                        cursor_selected,
                        "policy-state traversal cursor",
                    )
                    if (
                        cursor.get("state") != "reserved"
                        or cursor.get("reserved_by") != child_id
                    ):
                        raise core.TransitionKernelError(
                            "policy-state traversal cursor changed"
                        )
                    cursor_mutations += (
                        core.mutation(
                            operation=self.operation,
                            selected=cursor_selected,
                            row={
                                **cursor,
                                "state": "consumed",
                                "reserved_by": None,
                                "updated_at": now_s,
                            },
                        ),
                    )
                if next_cursor is not None:
                    next_selected, next_row = _selected_or_none(
                        context,
                        "traversal_budget_cursors",
                        {"cursor_digest": next_cursor},
                    )
                    expected_next = {
                        "cursor_digest": next_cursor,
                        "chain_key": claim["chain_key"],
                        "lineage_digest": claim["lineage_digest"],
                        "state": "available",
                        "reserved_by": None,
                        "issued_at_epoch_ms": now_ms,
                        "expires_at_epoch_ms":
                            chain["expires_at_epoch_ms"],
                        "updated_at": now_s,
                    }
                    if next_row is None:
                        cursor_mutations += (
                            core.mutation(
                                operation=self.operation,
                                selected=next_selected,
                                row=expected_next,
                            ),
                        )
                    elif any(
                        next_row.get(field) != value
                        for field, value in expected_next.items()
                    ):
                        raise core.TransitionKernelError(
                            "policy-state next cursor was rebound"
                        )
                page = {
                    **page,
                    "response_digest": response_digest,
                    "response_records": response_records,
                    "response_bytes": response_bytes,
                    "next_cursor_digest": next_cursor,
                }
            chain_after = {
                **chain,
                "state": (
                    "poisoned"
                    if mode == "fail"
                    else "exhausted"
                    if mode == "complete"
                    and (
                        pages_after >= int(chain["max_pages"])
                        or records_after >= int(chain["max_records"])
                        or bytes_after >= int(chain["max_bytes"])
                    )
                    else chain["state"]
                ),
                "page_count": pages_after,
                "record_count": records_after,
                "byte_count": bytes_after,
                "last_observed_epoch_ms": now_ms,
                "updated_at": now_s,
            }
            mutations.extend(
                (
                    *cursor_mutations,
                    core.mutation(
                        operation=self.operation,
                        selected=page_selected,
                        row={
                            **page,
                            "state": page_target,
                            "updated_at": now_s,
                        },
                    ),
                    core.mutation(
                        operation=self.operation,
                        selected=chain_selected,
                        row=chain_after,
                    ),
                    _aggregate_update(
                        context,
                        kind="traversal-chain",
                        partition=claim["chain_key"],
                        active_delta=active_delta,
                        reserved_units={"pages": reserved_after},
                        committed_units={
                            "pages": pages_after,
                            "records": records_after,
                            "bytes": bytes_after,
                            "rootHistory": root_history,
                        },
                        minimum_expiry_epoch_ns=(
                            None
                            if mode in {"abort", "complete", "fail"}
                            else aggregate.get(
                                "minimum_expiry_epoch_ns"
                            )
                        ),
                        expiry_index_root_digest=core.framed_digest(
                            (
                                "serverware."
                                "policyAuthorityTraversalExpiryIndexDelta/v1"
                            ),
                            str(
                                aggregate["expiry_index_root_digest"]
                            ).encode("ascii"),
                            child_id.encode("ascii"),
                            page_target.encode("ascii"),
                        ),
                    ),
                )
            )
        bundle_after = {
            **bundle,
            "state": target,
            "dispatch_started_at_epoch_ms": (
                now_ms
                if mode == "dispatch"
                else bundle.get("dispatch_started_at_epoch_ms")
            ),
            "dispatch_deadline_at_epoch_ms": (
                int(bundle["reservation_deadline_at_epoch_ms"])
                if mode == "dispatch"
                else bundle.get("dispatch_deadline_at_epoch_ms")
            ),
            "response_evidence_digest": response_evidence_digest,
            "response_evidence_json": response_evidence_json,
            "terminal_reason": terminal_reason,
            "response_body_sha256": response_body_sha256,
            "uncertainty": (
                "unknown-result-charged"
                if mode == "fail"
                else None
            ),
            "updated_at": now_s,
        }
        mutations.append(
            core.mutation(
                operation=self.operation,
                selected=bundle_selected,
                row=bundle_after,
            )
        )
        return core.KernelTransition(
            mutations=tuple(mutations),
            result=_policy_state_result(
                state=target,
                attempt_id=attempt_id,
                claim_digest=claim_digest,
                reservation_id=reservation_id,
                reason=terminal_reason or target,
            ),
            work_units=96 + len(mutations) * 4,
        )


@dataclass(frozen=True, slots=True)
class _TraversalDispatchKernel:
    operation: str = "quota.traversal.dispatch"
    handler: str = "mark_traversal_page_dispatched"
    permits_empty_mutation: bool = False
    program_id: str = core.transition_program_id(
        "quota.traversal.dispatch",
        "mark_traversal_page_dispatched",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        core.require_digest(
            request_digest,
            "traversal dispatch request digest",
        )
        reservation_id, chain_key, _, _ = (
            _traversal_dispatch_arguments(arguments)
        )
        return (
            core.BoundedQuery(
                query_id=core.query_program_id(
                    self.operation,
                    "page",
                    "traversal_budget_page_reservations",
                ),
                table="traversal_budget_page_reservations",
                predicates=(
                    core.QueryPredicate(
                        "reservation_id",
                        "eq",
                        reservation_id,
                    ),
                ),
                order_by=(core.QueryOrder("reservation_id"),),
                maximum_rows=1,
                absent_key={"reservation_id": reservation_id},
            ),
            core.BoundedQuery(
                query_id=core.query_program_id(
                    self.operation,
                    "chain",
                    "traversal_budget_chains",
                ),
                table="traversal_budget_chains",
                predicates=(
                    core.QueryPredicate("chain_key", "eq", chain_key),
                ),
                order_by=(core.QueryOrder("chain_key"),),
                maximum_rows=1,
                absent_key={"chain_key": chain_key},
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        reservation_id, chain_key, request_digest, explicit_now_ms = (
            _traversal_dispatch_arguments(context.arguments)
        )
        page_selected = context.exact(
            "traversal_budget_page_reservations",
            {"reservation_id": reservation_id},
        )
        chain_selected = context.exact(
            "traversal_budget_chains",
            {"chain_key": chain_key},
        )
        page = _row(page_selected, "traversal page")
        chain = _row(chain_selected, "traversal chain")
        if (
            page.get("chain_key") != chain_key
            or page.get("request_digest") != request_digest
        ):
            raise core.TransitionKernelError(
                "traversal dispatch evidence does not match"
            )
        now_ms = (
            explicit_now_ms
            if explicit_now_ms is not None
            else _database_epoch_ms(context.database_now)
        )
        last_observed = chain.get("last_observed_epoch_ms")
        if (
            not isinstance(last_observed, int)
            or isinstance(last_observed, bool)
            or now_ms < last_observed
        ):
            raise core.TransitionKernelError(
                "traversal clock moved before its last observation"
            )
        page_number = page.get("page_number")
        if (
            not isinstance(page_number, int)
            or isinstance(page_number, bool)
            or page_number < 1
        ):
            raise core.TransitionKernelError(
                "traversal page number is invalid"
            )
        state = page.get("state")
        now_s = (
            datetime(1970, 1, 1, tzinfo=timezone.utc)
            + timedelta(milliseconds=now_ms)
        ).isoformat()
        chain_after = {
            **chain,
            "last_observed_epoch_ms": now_ms,
            "updated_at": now_s,
        }
        mutations: list[dict[str, Any]] = []
        if state == "dispatched":
            idempotent_replay = True
        elif state != "reserved":
            raise core.TransitionKernelError(
                "traversal page cannot dispatch from its current state"
            )
        else:
            reservation_expiry = page.get(
                "reservation_expires_at_epoch_ms"
            )
            chain_expiry = chain.get("expires_at_epoch_ms")
            if (
                not isinstance(reservation_expiry, int)
                or isinstance(reservation_expiry, bool)
                or not isinstance(chain_expiry, int)
                or isinstance(chain_expiry, bool)
                or reservation_expiry <= now_ms
                or chain_expiry <= now_ms
            ):
                raise core.TransitionKernelError(
                    "traversal reservation expired before dispatch"
                )
            mutations.append(
                core.mutation(
                    operation=self.operation,
                    selected=page_selected,
                    row={
                        **page,
                        "state": "dispatched",
                        "updated_at": now_s,
                    },
                )
            )
            idempotent_replay = False
        mutations.append(
            core.mutation(
                operation=self.operation,
                selected=chain_selected,
                row=chain_after,
            )
        )
        return core.KernelTransition(
            mutations=tuple(mutations),
            result=_traversal_dispatch_result(
                chain=chain_after,
                reservation_id=reservation_id,
                page_number=page_number,
                idempotent_replay=idempotent_replay,
            ),
            work_units=10 + len(mutations),
        )


@dataclass(frozen=True, slots=True)
class _TraversalTerminateKernel:
    operation: str = "quota.traversal.terminate"
    handler: str = "terminate_traversal_page"
    permits_empty_mutation: bool = False
    program_id: str = core.transition_program_id(
        "quota.traversal.terminate",
        "terminate_traversal_page",
    )

    def queries(
        self,
        *,
        arguments: Mapping[str, Any],
        database_now: datetime,
        request_digest: str,
    ) -> tuple[core.BoundedQuery, ...]:
        del database_now
        core.require_digest(
            request_digest,
            "traversal termination request digest",
        )
        reservation_id, chain_key, _, _, _ = (
            _traversal_termination_arguments(arguments)
        )
        cursor_reference = core.SelectedRowFieldReference(
            table="traversal_budget_page_reservations",
            key={"reservation_id": reservation_id},
            column="request_cursor_digest",
        )
        return (
            core.BoundedQuery(
                query_id=core.query_program_id(
                    self.operation,
                    "page",
                    "traversal_budget_page_reservations",
                ),
                table="traversal_budget_page_reservations",
                predicates=(
                    core.QueryPredicate(
                        "reservation_id",
                        "eq",
                        reservation_id,
                    ),
                ),
                order_by=(core.QueryOrder("reservation_id"),),
                maximum_rows=1,
                absent_key={"reservation_id": reservation_id},
            ),
            core.BoundedQuery(
                query_id=core.query_program_id(
                    self.operation,
                    "chain",
                    "traversal_budget_chains",
                ),
                table="traversal_budget_chains",
                predicates=(
                    core.QueryPredicate("chain_key", "eq", chain_key),
                ),
                order_by=(core.QueryOrder("chain_key"),),
                maximum_rows=1,
                absent_key={"chain_key": chain_key},
            ),
            core.BoundedQuery(
                query_id=core.query_program_id(
                    self.operation,
                    "request_cursor",
                    "traversal_budget_cursors",
                ),
                table="traversal_budget_cursors",
                predicates=(
                    core.QueryPredicate(
                        "cursor_digest",
                        "eq",
                        cursor_reference,
                    ),
                ),
                order_by=(core.QueryOrder("cursor_digest"),),
                maximum_rows=1,
                absent_key={"cursor_digest": cursor_reference},
            ),
            _aggregate_query(
                self.operation,
                "chain_high_water",
                "traversal-chain",
                chain_key,
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        (
            reservation_id,
            chain_key,
            request_digest,
            outcome,
            explicit_now_ms,
        ) = _traversal_termination_arguments(context.arguments)
        page_selected = context.exact(
            "traversal_budget_page_reservations",
            {"reservation_id": reservation_id},
        )
        chain_selected = context.exact(
            "traversal_budget_chains",
            {"chain_key": chain_key},
        )
        page = _row(page_selected, "traversal page")
        chain = _row(chain_selected, "traversal chain")
        if (
            page.get("chain_key") != chain_key
            or page.get("request_digest") != request_digest
        ):
            raise core.TransitionKernelError(
                "traversal termination evidence does not match"
            )
        now_ms = (
            explicit_now_ms
            if explicit_now_ms is not None
            else _database_epoch_ms(context.database_now)
        )
        last_observed = chain.get("last_observed_epoch_ms")
        if (
            not isinstance(last_observed, int)
            or isinstance(last_observed, bool)
            or now_ms < last_observed
        ):
            raise core.TransitionKernelError(
                "traversal clock moved before its last observation"
            )
        page_number = page.get("page_number")
        if (
            not isinstance(page_number, int)
            or isinstance(page_number, bool)
            or page_number < 1
        ):
            raise core.TransitionKernelError(
                "traversal page number is invalid"
            )
        now_s = (
            datetime(1970, 1, 1, tzinfo=timezone.utc)
            + timedelta(milliseconds=now_ms)
        ).isoformat()
        state = page.get("state")
        target = (
            "cancelled" if outcome == "not_forwarded"
            else "indeterminate"
        )
        aggregate_id, partition_digest = _aggregate_key(
            "traversal-chain",
            chain_key,
        )
        aggregate = context.bounded_aggregate(
            aggregate_id=aggregate_id,
            aggregate_kind="traversal-chain",
            partition_digest=partition_digest,
        )
        (
            reserved_pages,
            committed_pages,
            committed_records,
            committed_bytes,
            root_history,
        ) = _traversal_aggregate_units(aggregate)
        mutations: list[dict[str, Any]] = []
        chain_after = {
            **chain,
            "last_observed_epoch_ms": now_ms,
            "updated_at": now_s,
        }
        if state == target:
            idempotent_replay = True
        elif outcome == "not_forwarded" and state == "reserved":
            cursor_digest = page.get("request_cursor_digest")
            if cursor_digest is not None:
                cursor_selected = context.exact(
                    "traversal_budget_cursors",
                    {"cursor_digest": cursor_digest},
                )
                if cursor_selected.get("present") is True:
                    cursor = _row(
                        cursor_selected,
                        "traversal request cursor",
                    )
                    if (
                        cursor.get("state") == "reserved"
                        and cursor.get("reserved_by") == reservation_id
                    ):
                        mutations.append(
                            core.mutation(
                                operation=self.operation,
                                selected=cursor_selected,
                                row={
                                    **cursor,
                                    "state": "available",
                                    "reserved_by": None,
                                    "updated_at": now_s,
                                },
                            )
                        )
            mutations.append(
                core.mutation(
                    operation=self.operation,
                    selected=page_selected,
                    row={
                        **page,
                        "state": "cancelled",
                        "updated_at": now_s,
                    },
                )
            )
            idempotent_replay = False
        elif (
            outcome == "indeterminate"
            and state in {"reserved", "dispatched"}
        ):
            cursor_digest = page.get("request_cursor_digest")
            if cursor_digest is not None:
                cursor_selected = context.exact(
                    "traversal_budget_cursors",
                    {"cursor_digest": cursor_digest},
                )
                if state == "dispatched":
                    cursor = _row(
                        cursor_selected,
                        "traversal request cursor",
                    )
                    if (
                        cursor.get("state") != "reserved"
                        or cursor.get("reserved_by") != reservation_id
                    ):
                        raise core.TransitionKernelError(
                            "traversal request cursor lost its reservation"
                        )
                    mutations.append(
                        core.mutation(
                            operation=self.operation,
                            selected=cursor_selected,
                            row={
                                **cursor,
                                "state": "consumed",
                                "reserved_by": None,
                                "updated_at": now_s,
                            },
                        )
                    )
                elif cursor_selected.get("present") is True:
                    cursor = _row(
                        cursor_selected,
                        "traversal request cursor",
                    )
                    if (
                        cursor.get("state") == "reserved"
                        and cursor.get("reserved_by") == reservation_id
                    ):
                        mutations.append(
                            core.mutation(
                                operation=self.operation,
                                selected=cursor_selected,
                                row={
                                    **cursor,
                                    "state": "consumed",
                                    "reserved_by": None,
                                    "updated_at": now_s,
                                },
                            )
                        )
            mutations.append(
                core.mutation(
                    operation=self.operation,
                    selected=page_selected,
                    row={
                        **page,
                        "state": "indeterminate",
                        "updated_at": now_s,
                    },
                )
            )
            page_count = chain.get("page_count")
            if (
                not isinstance(page_count, int)
                or isinstance(page_count, bool)
                or page_count < 0
                or page_count >= _SIGNED_BIGINT_MAX
            ):
                raise core.TransitionKernelError(
                    "traversal page count is invalid"
                )
            chain_after = {
                **chain_after,
                "state": "poisoned",
                "page_count": page_count + 1,
            }
            idempotent_replay = False
        else:
            raise core.TransitionKernelError(
                "traversal page cannot terminate from its current state"
            )
        if not idempotent_replay:
            mutations.append(
                _aggregate_update(
                    context,
                    kind="traversal-chain",
                    partition=chain_key,
                    active_delta=-1,
                    reserved_units={
                        "pages": core.checked_u64_sub(
                            reserved_pages,
                            1,
                            "traversal reserved pages",
                        )
                    },
                    committed_units={
                        "pages": (
                            core.checked_u64_add(
                                committed_pages,
                                1,
                                "traversal indeterminate pages",
                            )
                            if outcome == "indeterminate"
                            else committed_pages
                        ),
                        "records": committed_records,
                        "bytes": committed_bytes,
                        "rootHistory": root_history,
                    },
                    minimum_expiry_epoch_ns=None,
                    expiry_index_root_digest=core.framed_digest(
                        (
                            "serverware."
                            "policyAuthorityTraversalExpiryIndexDelta/v1"
                        ),
                        str(
                            aggregate["expiry_index_root_digest"]
                        ).encode("ascii"),
                        reservation_id.encode("utf-8"),
                        target.encode("ascii"),
                    ),
                )
            )
        mutations.append(
            core.mutation(
                operation=self.operation,
                selected=chain_selected,
                row=chain_after,
            )
        )
        return core.KernelTransition(
            mutations=tuple(mutations),
            result=_traversal_result(
                chain=chain_after,
                reservation_id=reservation_id,
                target=target,
                page_number=page_number,
                idempotent_replay=idempotent_replay,
            ),
            work_units=12 + len(mutations),
        )


_KERNEL_VALUES: tuple[core.TransitionKernel, ...] = (
    _ControlApprovalRequestKernel(),
    _ControlApprovalDecisionKernel(
        operation="control-approval.decide",
        handler="approve_control_plane_approval",
        decision="approve",
    ),
    _ControlApprovalConsumeKernel(),
    _ControlApprovalDecisionKernel(
        operation="control-approval.deny",
        handler="deny_control_plane_approval",
        decision="deny",
    ),
    _JitRequestKernel(),
    _JitReviewReceiptKernel(),
    _JitDecideKernel(),
    _JitDenyKernel(),
    _RateConsumeKernel(),
    _BudgetReserveKernel(),
    _BudgetStateKernel(
        operation="quota.budget.dispatch",
        handler="mark_durable_budget_dispatched",
        target="dispatched",
    ),
    _BudgetStateKernel(
        operation="quota.budget.commit",
        handler="commit_durable_budget_reservation",
        target="committed",
    ),
    _BudgetStateKernel(
        operation="quota.budget.cancel",
        handler="cancel_durable_budget_reservation",
        target="cancelled",
    ),
    _TraversalReserveKernel(),
    _TraversalDispatchKernel(),
    _TraversalCompleteKernel(),
    _TraversalTerminateKernel(),
    _PolicyStateReserveKernel(),
    _PolicyStateLifecycleKernel(
        operation="quota.policy-state.dispatch",
        handler="dispatch_policy_state_bundle",
        mode="dispatch",
    ),
    _PolicyStateLifecycleKernel(
        operation="quota.policy-state.complete",
        handler="complete_policy_state_bundle",
        mode="complete",
    ),
    _PolicyStateLifecycleKernel(
        operation="quota.policy-state.abort",
        handler="abort_policy_state_bundle",
        mode="abort",
    ),
    _PolicyStateLifecycleKernel(
        operation="quota.policy-state.fail",
        handler="fail_policy_state_bundle",
        mode="fail",
    ),
    _PolicyStateLifecycleKernel(
        operation="quota.policy-state.reconcile",
        handler="reconcile_policy_state_bundles",
        mode="reconcile",
    ),
)
KERNELS: Mapping[str, core.TransitionKernel] = MappingProxyType(
    {kernel.operation: kernel for kernel in _KERNEL_VALUES}
)


if set(KERNELS) != QUOTA_TRANSITION_OPERATIONS:
    raise RuntimeError("quota transition coverage is not closed")
