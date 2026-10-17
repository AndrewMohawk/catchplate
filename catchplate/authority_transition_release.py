from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Callable, Final, Mapping

from catchplate import authority_transition_core as core


RELEASE_TRANSITION_OPERATIONS: Final[frozenset[str]] = frozenset(
    {
        "release.reserve",
        "release.v1.reserve",
        "release.dispatch",
        "release.v1.dispatch",
        "release.complete",
        "release.v1.complete",
        "release.cancel",
        "release.reconcile",
        "release.credential-claim",
        "release.audit-drain",
        "credential-nonce.reserve",
    }
)

_SIGNED_BIGINT_MAX = 2**63 - 1
_MAX_RELEASE_QUOTAS = 12
_MAX_GRANT_CANDIDATES = 4
_MAX_PHYSICAL_WEBAUTHN_CANDIDATES = 4
_MAX_NONCE_EXPIRY_PAGE = 32
_TRANSITION_RECEIPT_SCHEMA = (
    "catchplate.policyAuthorityReleaseTransitionReceipt/v1"
)
_TRANSITION_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "operation",
        "operationId",
        "requestDigest",
        "bindingDigest",
        "selectedRowsDigest",
        "authorityComponents",
        "mutations",
        "resultDigest",
        "transitionDigest",
        "issuedAtEpochNs",
        "expiresAtEpochNs",
    }
)
_RECEIPT_MUTATION_FIELDS = frozenset(
    {
        "operation",
        "table",
        "key",
        "beforeRowDigest",
        "afterRow",
        "afterRowDigest",
    }
)
_PHYSICAL_WEBAUTHN_BINDING_FIELDS = frozenset(
    {
        "operation",
        "operationId",
        "requestDigest",
        "credentialRecordId",
        "credentialIdDigest",
        "grantId",
        "actorId",
        "ceremonyId",
        "challengeDigest",
        "authenticatorDataDigest",
        "clientDataDigest",
        "assertionSignatureDigest",
        "priorCounter",
        "newCounter",
        "trustGeneration",
        "trustRootDigest",
    }
)
_PHYSICAL_WEBAUTHN_CONSUMING_OPERATIONS: Final[frozenset[str]] = frozenset()
_PRIMARY_KEYS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "approval_grants": ("id",),
        "approval_grant_consumptions": ("id",),
        "approval_requests": ("id",),
        "credential_lease_nonces": (
            "recipient_key_id",
            "nonce_sha256",
        ),
        "credential_lease_replay_state": ("scope",),
        "policy_state_bundles": ("reservation_id",),
        "rate_limit_counters": ("counter_key",),
        "release_authorization_attempts": ("attempt_id",),
        "release_authorization_credential_issuances": ("attempt_id",),
        "release_authorization_events": ("id",),
        "release_authorization_quota_reservations": (
            "attempt_id",
            "counter_key",
        ),
        "webauthn_trust_publication_high_water": ("authority_scope",),
    }
)
_EVIDENCE_TYPES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "release.reserve": "release-reservation-authority/v1",
        "release.v1.reserve": "release-reservation-authority/v1",
        "release.dispatch": "release-dispatch-authority/v1",
        "release.v1.dispatch": "release-dispatch-authority/v1",
        "release.complete": "response-validation/v2",
        "release.v1.complete": "dispatcher-forwarding/v1",
        "release.cancel": "release-cancellation-authority/v1",
        "release.reconcile": "release-reconciliation-authority/v1",
        "release.credential-claim": "credential-issuer/v1",
        "release.audit-drain": "audit-ledger-append/v1",
    }
)
_AUTHORITY_COMPONENTS: Final[
    Mapping[str, frozenset[str]]
] = MappingProxyType(
    {
        "release.reserve": frozenset(
            {
                "encryptionAuthorityReceiptDigest",
                "jitAuthorityReceiptDigest",
                "quotaAuthorityReceiptDigest",
            }
        ),
        "release.v1.reserve": frozenset(
            {
                "encryptionAuthorityReceiptDigest",
                "jitAuthorityReceiptDigest",
                "quotaAuthorityReceiptDigest",
            }
        ),
        "release.dispatch": frozenset(
            {
                "dispatcherAuthorityReceiptDigest",
                "jitAuthorityReceiptDigest",
                "quotaAuthorityReceiptDigest",
            }
        ),
        "release.v1.dispatch": frozenset(
            {
                "dispatcherAuthorityReceiptDigest",
                "jitAuthorityReceiptDigest",
                "quotaAuthorityReceiptDigest",
            }
        ),
        "release.complete": frozenset(
            {
                "dispatcherForwardingReceiptDigest",
                "jitAuthorityReceiptDigest",
                "quotaAuthorityReceiptDigest",
                "responseValidationReceiptDigest",
            }
        ),
        "release.v1.complete": frozenset(
            {
                "dispatcherForwardingReceiptDigest",
                "jitAuthorityReceiptDigest",
                "quotaAuthorityReceiptDigest",
            }
        ),
        "release.cancel": frozenset(
            {
                "jitAuthorityReceiptDigest",
                "quotaAuthorityReceiptDigest",
            }
        ),
        "release.reconcile": frozenset(
            {
                "jitAuthorityReceiptDigest",
                "quotaAuthorityReceiptDigest",
            }
        ),
        "release.credential-claim": frozenset(
            {
                "credentialIssuerReceiptDigest",
                "encryptionAuthorityReceiptDigest",
                "jitAuthorityReceiptDigest",
                "quotaAuthorityReceiptDigest",
            }
        ),
        "release.audit-drain": frozenset(
            {"auditLedgerAppendReceiptDigest"}
        ),
    }
)
_MUTATION_TABLES: Final[
    Mapping[str, Mapping[str, frozenset[str]]]
] = MappingProxyType(
    {
        "release.reserve": MappingProxyType(
            {
                "approval_grants": frozenset({"UPDATE"}),
                "policy_state_bundles": frozenset({"INSERT"}),
                "rate_limit_counters": frozenset(
                    {"INSERT", "UPDATE"}
                ),
                "release_authorization_attempts": frozenset({"INSERT"}),
                "release_authorization_events": frozenset({"INSERT"}),
                "release_authorization_quota_reservations": frozenset(
                    {"INSERT"}
                ),
            }
        ),
        "release.v1.reserve": MappingProxyType(
            {
                "approval_grants": frozenset({"UPDATE"}),
                "rate_limit_counters": frozenset(
                    {"INSERT", "UPDATE"}
                ),
                "release_authorization_attempts": frozenset({"INSERT"}),
                "release_authorization_events": frozenset({"INSERT"}),
                "release_authorization_quota_reservations": frozenset(
                    {"INSERT"}
                ),
            }
        ),
        "release.dispatch": MappingProxyType(
            {
                "policy_state_bundles": frozenset({"UPDATE"}),
                "release_authorization_attempts": frozenset({"UPDATE"}),
                "release_authorization_events": frozenset({"INSERT"}),
            }
        ),
        "release.v1.dispatch": MappingProxyType(
            {
                "release_authorization_attempts": frozenset({"UPDATE"}),
                "release_authorization_events": frozenset({"INSERT"}),
            }
        ),
        "release.complete": MappingProxyType(
            {
                "approval_grants": frozenset({"UPDATE"}),
                "approval_grant_consumptions": frozenset({"INSERT"}),
                "policy_state_bundles": frozenset({"UPDATE"}),
                "rate_limit_counters": frozenset({"UPDATE"}),
                "release_authorization_attempts": frozenset({"UPDATE"}),
                "release_authorization_events": frozenset({"INSERT"}),
                "release_authorization_quota_reservations": frozenset(
                    {"UPDATE"}
                ),
            }
        ),
        "release.v1.complete": MappingProxyType(
            {
                "approval_grants": frozenset({"UPDATE"}),
                "approval_grant_consumptions": frozenset({"INSERT"}),
                "rate_limit_counters": frozenset({"UPDATE"}),
                "release_authorization_attempts": frozenset({"UPDATE"}),
                "release_authorization_events": frozenset({"INSERT"}),
                "release_authorization_quota_reservations": frozenset(
                    {"UPDATE"}
                ),
            }
        ),
        "release.cancel": MappingProxyType(
            {
                "approval_grants": frozenset({"UPDATE"}),
                "rate_limit_counters": frozenset({"UPDATE"}),
                "release_authorization_attempts": frozenset({"UPDATE"}),
                "release_authorization_events": frozenset({"INSERT"}),
                "release_authorization_quota_reservations": frozenset(
                    {"UPDATE"}
                ),
            }
        ),
        "release.reconcile": MappingProxyType(
            {
                "approval_grants": frozenset({"UPDATE"}),
                "approval_grant_consumptions": frozenset({"INSERT"}),
                "policy_state_bundles": frozenset({"UPDATE"}),
                "rate_limit_counters": frozenset({"UPDATE"}),
                "release_authorization_attempts": frozenset({"UPDATE"}),
                "release_authorization_events": frozenset({"INSERT"}),
                "release_authorization_quota_reservations": frozenset(
                    {"UPDATE"}
                ),
            }
        ),
        "release.credential-claim": MappingProxyType(
            {
                "release_authorization_credential_issuances": frozenset(
                    {"INSERT"}
                ),
            }
        ),
        "release.audit-drain": MappingProxyType(
            {
                "approval_grant_consumptions": frozenset({"UPDATE"}),
                "release_authorization_events": frozenset({"UPDATE"}),
            }
        ),
    }
)


def _row(
    selected: Mapping[str, Any],
    label: str,
) -> dict[str, Any]:
    row = selected.get("row")
    if selected.get("present") is not True or not isinstance(row, Mapping):
        raise core.TransitionKernelError(f"{label} is absent")
    return dict(row)


def _optional_row(
    context: core.KernelContext,
    table: str,
    key: Mapping[str, Any],
) -> dict[str, Any] | None:
    selected = context.exact(table, key)
    if selected.get("present") is not True:
        return None
    return _row(selected, table)


def _database_epoch_ms(value: datetime) -> int:
    normalized = value.astimezone(timezone.utc)
    delta = normalized - datetime(1970, 1, 1, tzinfo=timezone.utc)
    microseconds = (
        delta.days * 86_400_000_000
        + delta.seconds * 1_000_000
        + delta.microseconds
    )
    return (microseconds + 500) // 1000


def _database_epoch_ns(value: datetime) -> int:
    normalized = value.astimezone(timezone.utc)
    delta = normalized - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1_000
    )


def _iso_from_epoch_ms(value: int) -> str:
    return (
        datetime(1970, 1, 1, tzinfo=timezone.utc)
        + timedelta(milliseconds=value)
    ).isoformat()


def _sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(core.canonical_bytes(value)).hexdigest()


def _business_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(arguments, Mapping)
        or "businessIntent" not in arguments
        or any(not isinstance(key, str) for key in arguments)
    ):
        raise core.TransitionKernelError(
            "release transition arguments are not exact"
        )
    value = {
        key: item
        for key, item in sorted(arguments.items())
        if key != "businessIntent"
    }
    core.canonical_bytes(value)
    return value


def _argument_text(
    arguments: Mapping[str, Any],
    field: str,
    *,
    maximum_bytes: int = 512,
) -> str:
    if field not in arguments:
        raise core.TransitionKernelError(
            f"release transition {field} is absent"
        )
    return core.require_text(
        arguments[field],
        f"release transition {field}",
        maximum_bytes=maximum_bytes,
    )


def _argument_digest(
    arguments: Mapping[str, Any],
    field: str,
) -> str:
    if field not in arguments:
        raise core.TransitionKernelError(
            f"release transition {field} is absent"
        )
    return core.require_digest(
        arguments[field],
        f"release transition {field}",
    )


def _release_business_binding(
    operation: str,
    arguments: Mapping[str, Any],
) -> str:
    business = _business_arguments(arguments)
    if operation in {"release.reserve", "release.v1.reserve"}:
        for transient in (
            "actor_id",
            "authority_policy_hash",
            "authority_route_id",
            "jit_approval_request",
            "now_epoch_ms",
            "reservation_ttl_seconds",
        ):
            business.pop(transient, None)
    return core.framed_digest(
        "catchplate.policyAuthorityReleaseBusinessBinding/v1",
        operation.encode("ascii"),
        core.canonical_bytes(business),
    )


def _operation_binding(
    operation: str,
    arguments: Mapping[str, Any],
    request_digest: str,
) -> str:
    core.require_digest(request_digest, "release planner request digest")
    return core.framed_digest(
        "catchplate.policyAuthorityReleaseEvidenceBinding/v1",
        operation.encode("ascii"),
        request_digest.encode("ascii"),
        _release_business_binding(
            operation,
            arguments,
        ).encode("ascii"),
        core.canonical_bytes(_business_arguments(arguments)),
    )


def _operation_id(
    operation: str,
    request_digest: str,
) -> str:
    return core.deterministic_uuid(
        operation=operation,
        request_digest=request_digest,
        purpose="release-transition",
    )


def _query(
    operation: str,
    name: str,
    table: str,
    *,
    predicates: tuple[core.QueryPredicate, ...],
    maximum_rows: int,
    order_by: tuple[core.QueryOrder, ...] = (),
    absent_key: Mapping[str, Any] | None = None,
    proof_primitive: str = "primary-key-row",
    page_size: int | None = None,
) -> core.BoundedQuery:
    return core.BoundedQuery(
        query_id=core.query_program_id(operation, name, table),
        table=table,
        predicates=predicates,
        order_by=order_by,
        maximum_rows=maximum_rows,
        absent_key=absent_key,
        proof_primitive=proof_primitive,
        page_size=page_size,
    )


def _exact_query(
    operation: str,
    name: str,
    table: str,
    key: Mapping[str, Any],
) -> core.BoundedQuery:
    return _query(
        operation,
        name,
        table,
        predicates=tuple(
            core.QueryPredicate(column, "eq", value)
            for column, value in key.items()
        ),
        order_by=tuple(core.QueryOrder(column) for column in key),
        maximum_rows=1,
        absent_key=key,
    )


def _receipt_query(
    operation: str,
    arguments: Mapping[str, Any],
    request_digest: str,
) -> core.BoundedQuery:
    binding_digest = _operation_binding(
        operation,
        arguments,
        request_digest,
    )
    return _query(
        operation,
        "transition_evidence",
        "policy_authority_external_evidence_receipts",
        predicates=(
            core.QueryPredicate(
                "evidence_type",
                "eq",
                _EVIDENCE_TYPES[operation],
            ),
            core.QueryPredicate(
                "binding_digest",
                "eq",
                binding_digest,
            ),
            core.QueryPredicate("status", "eq", "verified"),
        ),
        order_by=(core.QueryOrder("evidence_digest"),),
        maximum_rows=1,
    )


def _event_id(operation: str, request_digest: str) -> str:
    return core.deterministic_uuid(
        operation=operation,
        request_digest=request_digest,
        purpose="release-event",
    )


def _consumption_id(operation: str, request_digest: str) -> str:
    return core.deterministic_uuid(
        operation=operation,
        request_digest=request_digest,
        purpose="grant-consumption",
    )


def _reserve_quotas(
    arguments: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    raw = arguments.get("shared_quotas")
    if (
        not isinstance(raw, list)
        or len(raw) > _MAX_RELEASE_QUOTAS
        or any(not isinstance(item, Mapping) for item in raw)
    ):
        raise core.TransitionKernelError(
            "release quota set exceeds its exact bound"
        )
    quotas: list[dict[str, Any]] = []
    identities: set[str] = set()
    for item in raw:
        quota = dict(item)
        counter_key = core.require_digest(
            quota.get("counter_key"),
            "release quota counter key",
        )
        if counter_key in identities:
            raise core.TransitionKernelError(
                "release quota counter is duplicated"
            )
        identities.add(counter_key)
        core.require_text(
            quota.get("constraint_id"),
            "release quota constraint",
            maximum_bytes=256,
        )
        maximum = core.require_integer(
            quota.get("max_count"),
            "release quota maximum",
            minimum=1,
            maximum=1_000_000_000,
        )
        del maximum
        quotas.append(quota)
    return tuple(sorted(quotas, key=lambda item: item["counter_key"]))


def _durable_reservation_id(arguments: Mapping[str, Any]) -> str:
    durable = arguments.get("durable_policy_binding")
    if not isinstance(durable, Mapping):
        raise core.TransitionKernelError(
            "release durable policy binding is absent"
        )
    claim_digest = core.require_digest(
        durable.get("claimDigest"),
        "release durable claim digest",
    )
    material = {
        "attemptId": _argument_text(arguments, "attempt_id"),
        "policyHash": _argument_digest(arguments, "policy_hash"),
        "requestDigest": _argument_digest(arguments, "request_digest"),
        "operationDigest": _argument_digest(
            arguments,
            "operation_digest",
        ),
        "claimDigest": claim_digest,
    }
    return _sha256(material)


def _reserve_queries(
    operation: str,
    arguments: Mapping[str, Any],
    request_digest: str,
) -> tuple[core.BoundedQuery, ...]:
    business = _business_arguments(arguments)
    attempt_id = _argument_text(business, "attempt_id")
    quotas = _reserve_quotas(business)
    queries: list[core.BoundedQuery] = [
        _exact_query(
            operation,
            "attempt",
            "release_authorization_attempts",
            {"attempt_id": attempt_id},
        )
    ]
    for ordinal, quota in enumerate(quotas):
        counter_key = str(quota["counter_key"])
        queries.extend(
            (
                _exact_query(
                    operation,
                    f"counter_{ordinal}",
                    "rate_limit_counters",
                    {"counter_key": counter_key},
                ),
                _exact_query(
                    operation,
                    f"quota_{ordinal}",
                    "release_authorization_quota_reservations",
                    {
                        "attempt_id": attempt_id,
                        "counter_key": counter_key,
                    },
                ),
            )
        )
    if bool(business.get("require_jit_grant")):
        predicates = (
            core.QueryPredicate("state", "eq", "active"),
            core.QueryPredicate(
                "principal_id",
                "eq",
                _argument_text(business, "principal_id"),
            ),
            core.QueryPredicate(
                "route_id",
                "eq",
                _argument_text(business, "route_id"),
            ),
            core.QueryPredicate(
                "credential_id",
                "eq",
                _argument_text(business, "credential_id"),
            ),
            core.QueryPredicate(
                "credential_version",
                "eq",
                core.require_integer(
                    business.get("credential_version"),
                    "release credential version",
                    minimum=1,
                    maximum=_SIGNED_BIGINT_MAX,
                ),
            ),
            core.QueryPredicate(
                "policy_hash",
                "eq",
                _argument_digest(business, "policy_hash"),
            ),
            core.QueryPredicate(
                "request_digest",
                "eq",
                _argument_digest(business, "request_digest"),
            ),
            core.QueryPredicate("reserved_attempt_id", "is-null"),
        )
        queries.append(
            _query(
                operation,
                "grant_candidates",
                "approval_grants",
                predicates=predicates,
                order_by=(
                    core.QueryOrder("created_at"),
                    core.QueryOrder("id"),
                ),
                maximum_rows=_MAX_GRANT_CANDIDATES,
            )
        )
    if operation == "release.reserve":
        queries.append(
            _exact_query(
                operation,
                "durable_bundle",
                "policy_state_bundles",
                {
                    "reservation_id":
                        _durable_reservation_id(business)
                },
            )
        )
    queries.extend(
        (
            _exact_query(
                operation,
                "event",
                "release_authorization_events",
                {"id": _event_id(operation, request_digest)},
            ),
            _receipt_query(operation, arguments, request_digest),
        )
    )
    return tuple(queries)


def _attempt_id_for_operation(
    operation: str,
    arguments: Mapping[str, Any],
) -> str:
    business = _business_arguments(arguments)
    if operation == "release.reconcile":
        field = (
            "candidate_attempt_id"
            if "candidate_attempt_id" in business
            else "attempt_id"
        )
        return _argument_text(business, field)
    return _argument_text(business, "attempt_id")


def _attempt_queries(
    operation: str,
    arguments: Mapping[str, Any],
    request_digest: str,
    *,
    include_issuance: bool = False,
) -> tuple[core.BoundedQuery, ...]:
    attempt_id = _attempt_id_for_operation(operation, arguments)
    attempt_key = {"attempt_id": attempt_id}
    attempt_reference = lambda column: core.SelectedRowFieldReference(
        table="release_authorization_attempts",
        key=attempt_key,
        column=column,
    )
    queries: list[core.BoundedQuery] = [
        _exact_query(
            operation,
            "attempt",
            "release_authorization_attempts",
            attempt_key,
        ),
        _query(
            operation,
            "quotas",
            "release_authorization_quota_reservations",
            predicates=(
                core.QueryPredicate("attempt_id", "eq", attempt_id),
            ),
            order_by=(core.QueryOrder("counter_key"),),
            maximum_rows=_MAX_RELEASE_QUOTAS,
        ),
        _query(
            operation,
            "counters",
            "rate_limit_counters",
            predicates=(
                core.QueryPredicate(
                    "principal_id",
                    "eq",
                    attempt_reference("principal_id"),
                ),
                core.QueryPredicate(
                    "route_id",
                    "eq",
                    attempt_reference("route_id"),
                ),
                core.QueryPredicate(
                    "credential_id",
                    "eq",
                    attempt_reference("credential_id"),
                ),
                core.QueryPredicate(
                    "policy_hash",
                    "eq",
                    attempt_reference("policy_hash"),
                ),
            ),
            order_by=(core.QueryOrder("counter_key"),),
            maximum_rows=_MAX_RELEASE_QUOTAS,
        ),
        _query(
            operation,
            "grant",
            "approval_grants",
            predicates=(
                core.QueryPredicate(
                    "id",
                    "eq",
                    attempt_reference("grant_id"),
                ),
            ),
            order_by=(core.QueryOrder("id"),),
            maximum_rows=1,
        ),
        _query(
            operation,
            "approval",
            "approval_requests",
            predicates=(
                core.QueryPredicate(
                    "id",
                    "eq",
                    attempt_reference("approval_request_id"),
                ),
            ),
            order_by=(core.QueryOrder("id"),),
            maximum_rows=1,
        ),
        _query(
            operation,
            "existing_consumption",
            "approval_grant_consumptions",
            predicates=(
                core.QueryPredicate("attempt_id", "eq", attempt_id),
            ),
            order_by=(core.QueryOrder("id"),),
            maximum_rows=1,
        ),
        _exact_query(
            operation,
            "new_consumption",
            "approval_grant_consumptions",
            {"id": _consumption_id(operation, request_digest)},
        ),
        _query(
            operation,
            "durable_bundle",
            "policy_state_bundles",
            predicates=(
                core.QueryPredicate("attempt_id", "eq", attempt_id),
            ),
            order_by=(core.QueryOrder("reservation_id"),),
            maximum_rows=1,
        ),
    ]
    if operation in _PHYSICAL_WEBAUTHN_CONSUMING_OPERATIONS:
        queries.extend(
            (
                _exact_query(
                    operation,
                    "webauthn_trust_high_water",
                    "webauthn_trust_publication_high_water",
                    {"authority_scope": "webauthn-metadata"},
                ),
                _query(
                    operation,
                    "physical_webauthn_candidates",
                    "policy_authority_external_evidence_receipts",
                    predicates=(
                        core.QueryPredicate(
                            "evidence_type",
                            "eq",
                            "webauthn-hardware-authorization/v1",
                        ),
                        core.QueryPredicate("status", "eq", "verified"),
                    ),
                    order_by=(
                        core.QueryOrder("verified_at_epoch_ns"),
                        core.QueryOrder("evidence_digest"),
                    ),
                    maximum_rows=_MAX_PHYSICAL_WEBAUTHN_CANDIDATES,
                ),
            )
        )
    if operation != "release.credential-claim":
        queries.append(
            _exact_query(
                operation,
                "event",
                "release_authorization_events",
                {"id": _event_id(operation, request_digest)},
            )
        )
    if include_issuance:
        queries.append(
            _exact_query(
                operation,
                "issuance",
                "release_authorization_credential_issuances",
                {"attempt_id": attempt_id},
            )
        )
        business = _business_arguments(arguments)
        queries.append(
            _query(
                operation,
                "issuance_recipient",
                "release_authorization_credential_issuances",
                predicates=(
                    core.QueryPredicate(
                        "recipient_key_id",
                        "eq",
                        _argument_digest(business, "recipient_key_id"),
                    ),
                    core.QueryPredicate(
                        "recipient_nonce_sha256",
                        "eq",
                        _argument_digest(
                            business,
                            "recipient_nonce_sha256",
                        ),
                    ),
                ),
                order_by=(core.QueryOrder("attempt_id"),),
                maximum_rows=1,
            )
        )
    queries.append(_receipt_query(operation, arguments, request_digest))
    return tuple(queries)


def _audit_queries(
    operation: str,
    arguments: Mapping[str, Any],
    request_digest: str,
) -> tuple[core.BoundedQuery, ...]:
    _business_arguments(arguments)
    return (
        _query(
            operation,
            "grant_candidate",
            "approval_grant_consumptions",
            predicates=(core.QueryPredicate("audited_at", "is-null"),),
            order_by=(
                core.QueryOrder("created_at"),
                core.QueryOrder("id"),
            ),
            maximum_rows=1,
        ),
        _query(
            operation,
            "lifecycle_candidate",
            "release_authorization_events",
            predicates=(core.QueryPredicate("audited_at", "is-null"),),
            order_by=(
                core.QueryOrder("created_at"),
                core.QueryOrder("id"),
            ),
            maximum_rows=1,
        ),
        _receipt_query(operation, arguments, request_digest),
    )


def _selected_row_digest(selected: Mapping[str, Any]) -> str:
    row = selected.get("row")
    return core.framed_digest(
        "catchplate.policyAuthorityReleaseSelectedRow/v1",
        core.canonical_bytes(
            {
                "table": selected.get("table"),
                "key": selected.get("key"),
                "keyDigest": selected.get("keyDigest"),
                "present": selected.get("present"),
                "row": row,
            }
        ),
    )


def _selected_rows_digest(context: core.KernelContext) -> str:
    material = [
        {
            "table": selected["table"],
            "key": dict(selected["key"]),
            "keyDigest": selected["keyDigest"],
            "rowDigest": _selected_row_digest(selected),
        }
        for selected in context.selected_rows
        if not (
            selected.get("table")
                == "policy_authority_external_evidence_receipts"
            and isinstance(selected.get("row"), Mapping)
            and selected["row"].get("evidence_type")
                == _EVIDENCE_TYPES[context.operation]
        )
    ]
    material.sort(
        key=lambda item: (item["table"], item["keyDigest"])
    )
    return core.framed_digest(
        "catchplate.policyAuthorityReleaseSelectedRows/v1",
        core.canonical_bytes(material),
    )


def _evidence_row(
    context: core.KernelContext,
    *,
    evidence_type: str,
    binding_digest: str,
) -> dict[str, Any]:
    matches = tuple(
        selected
        for selected in context.present_rows(
            "policy_authority_external_evidence_receipts"
        )
        if isinstance(selected.get("row"), Mapping)
        and selected["row"].get("evidence_type") == evidence_type
        and selected["row"].get("binding_digest") == binding_digest
    )
    if len(matches) != 1:
        raise core.TransitionKernelError(
            "release transition evidence is absent or ambiguous"
        )
    return _row(matches[0], "release transition evidence")


def _canonical_statement(row: Mapping[str, Any]) -> dict[str, Any]:
    value = row.get("statement_json")
    if not isinstance(value, str):
        raise core.TransitionKernelError(
            "release transition evidence statement is absent"
        )
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise core.TransitionKernelError(
            "release transition evidence statement is invalid"
        ) from exc
    if (
        not isinstance(parsed, Mapping)
        or core.canonical_bytes(parsed).decode("ascii") != value
    ):
        raise core.TransitionKernelError(
            "release transition evidence statement is not canonical"
        )
    return dict(parsed)


def _projected_rows(
    context: core.KernelContext,
    mutations: tuple[Mapping[str, Any], ...],
) -> dict[tuple[str, str], dict[str, Any] | None]:
    projected: dict[tuple[str, str], dict[str, Any] | None] = {
        (
            str(selected["table"]),
            str(selected["keyDigest"]),
        ): (
            dict(selected["row"])
            if selected.get("present") is True
            and isinstance(selected.get("row"), Mapping)
            else None
        )
        for selected in context.selected_rows
        if selected.get("table")
            != "policy_authority_external_evidence_receipts"
    }
    for mutation in mutations:
        identity = (
            str(mutation["table"]),
            str(mutation["keyDigest"]),
        )
        projected[identity] = (
            None
            if mutation["operation"] == "DELETE"
            else dict(mutation["row"])
        )
    return projected


def _projected_table(
    context: core.KernelContext,
    projected: Mapping[tuple[str, str], dict[str, Any] | None],
    table: str,
) -> tuple[dict[str, Any], ...]:
    rows = [
        row
        for (row_table, _), row in projected.items()
        if row_table == table and row is not None
    ]
    return tuple(
        sorted(
            (dict(row) for row in rows),
            key=lambda row: core.canonical_bytes(
                {
                    field: row.get(field)
                    for field in _PRIMARY_KEYS[table]
                }
            ),
        )
    )


def _release_result(
    *,
    operation: str,
    arguments: Mapping[str, Any],
    context: core.KernelContext,
    projected: Mapping[tuple[str, str], dict[str, Any] | None],
    business_mutation_count: int,
) -> dict[str, Any]:
    attempt_id = _attempt_id_for_operation(operation, arguments)
    attempts = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "release_authorization_attempts",
        )
        if row.get("attempt_id") == attempt_id
    )
    binding_digest = (
        _release_business_binding(operation, arguments)
        if operation in {"release.reserve", "release.v1.reserve"}
        else _argument_digest(
            _business_arguments(arguments),
            "binding_digest",
        )
    )
    if not attempts:
        return {
            "authorized": False,
            "state": "denied",
            "reason": "authority_receipt_denied",
            "attempt_id": attempt_id,
            "binding_digest": binding_digest,
            "idempotent_replay": business_mutation_count == 0,
            "grant_id": None,
            "approval_request_id": None,
            "approver_policy": None,
            "approver_policy_digest": None,
            "reservation_expires_at_epoch_ms": None,
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "completion_outcome": None,
            "retry_after_seconds": 1,
            "quotas": [],
            "release_authorization_store_backend": "postgres",
            "release_authorization_store_ha": True,
        }
    if len(attempts) != 1:
        raise core.TransitionKernelError(
            "release transition attempt projection is ambiguous"
        )
    attempt = attempts[0]
    if attempt.get("binding_digest") != binding_digest:
        raise core.TransitionKernelError(
            "release transition binding conflicts with its attempt"
        )
    quotas = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "release_authorization_quota_reservations",
        )
        if row.get("attempt_id") == attempt_id
    )
    quota_results: list[dict[str, Any]] = []
    for row in quotas:
        for field in (
            "window_start_epoch_ms",
            "window_end_epoch_ms",
            "window_seconds",
            "max_count",
            "count_after",
        ):
            core.require_integer(
                row.get(field),
                f"release quota {field}",
                minimum=0,
                maximum=_SIGNED_BIGINT_MAX,
            )
        quota_results.append(
            {
                "counter_key": row["counter_key"],
                "constraint_id": row["constraint_id"],
                "operation": row.get("operation"),
                "window_kind": row["window_kind"],
                "window_start_epoch_ms": row[
                    "window_start_epoch_ms"
                ],
                "window_end_epoch_ms": row["window_end_epoch_ms"],
                "window_seconds": row["window_seconds"],
                "calendar_window": (
                    row["window_kind"]
                    if row["window_kind"] != "fixed"
                    else None
                ),
                "window_span_seconds": (
                    row["window_end_epoch_ms"]
                    - row["window_start_epoch_ms"]
                )
                // 1000,
                "max": row["max_count"],
                "count": row["count_after"],
                "remaining": max(
                    row["max_count"] - row["count_after"],
                    0,
                ),
                "reservation_state": row["reservation_state"],
            }
        )
    approver_policy = None
    if attempt.get("approver_policy_json") is not None:
        try:
            approver_policy = json.loads(
                str(attempt["approver_policy_json"])
            )
        except (TypeError, ValueError) as exc:
            raise core.TransitionKernelError(
                "release approver policy is invalid"
            ) from exc
    state = str(attempt.get("state"))
    reason = {
        "reserved": "reserved",
        "dispatching": "dispatching",
        "committed": "forwarded",
        "cancelled": "cancelled",
        "committed_indeterminate": "forward_outcome_indeterminate",
    }.get(state)
    if reason is None:
        raise core.TransitionKernelError(
            "release transition produced an invalid state"
        )
    result = {
        "authorized": state != "cancelled",
        "state": state,
        "reason": reason,
        "attempt_id": attempt_id,
        "binding_digest": binding_digest,
        "idempotent_replay": business_mutation_count == 0,
        "grant_id": attempt.get("grant_id"),
        "approval_request_id": attempt.get("approval_request_id"),
        "approver_policy": approver_policy,
        "approver_policy_digest":
            attempt.get("approver_policy_digest"),
        "reservation_expires_at_epoch_ms":
            attempt.get("reservation_expires_at_epoch_ms"),
        "dispatch_started_at_epoch_ms":
            attempt.get("dispatch_started_at_epoch_ms"),
        "dispatch_expires_at_epoch_ms":
            attempt.get("dispatch_expires_at_epoch_ms"),
        "completion_outcome": attempt.get("completion_outcome"),
        "quotas": quota_results,
        "release_authorization_store_backend": "postgres",
        "release_authorization_store_ha": True,
    }
    bundles = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "policy_state_bundles",
        )
        if row.get("attempt_id") == attempt_id
    )
    if bundles:
        if len(bundles) != 1:
            raise core.TransitionKernelError(
                "release durable policy projection is ambiguous"
            )
        bundle = bundles[0]
        result["durable_policy"] = {
            "reservation_id": bundle.get("reservation_id"),
            "attempt_id": bundle.get("attempt_id"),
            "claim_digest": bundle.get("claim_digest"),
            "actor_id": bundle.get("actor_id"),
            "state": bundle.get("state"),
            "reservation_deadline_at_epoch_ms":
                bundle.get("reservation_deadline_at_epoch_ms"),
            "dispatch_deadline_at_epoch_ms":
                bundle.get("dispatch_deadline_at_epoch_ms"),
            "response_evidence_digest":
                bundle.get("response_evidence_digest"),
            "response_body_sha256":
                bundle.get("response_body_sha256"),
            "failure_reason": bundle.get("terminal_reason"),
            "uncertainty": bundle.get("uncertainty"),
            "release_binding_digest":
                bundle.get("release_binding_digest"),
        }
    return result


def _claim_result(
    *,
    operation: str,
    arguments: Mapping[str, Any],
    context: core.KernelContext,
    projected: Mapping[tuple[str, str], dict[str, Any] | None],
    business_mutation_count: int,
) -> dict[str, Any]:
    del business_mutation_count
    attempt_id = _attempt_id_for_operation(operation, arguments)
    rows = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "release_authorization_credential_issuances",
        )
        if row.get("attempt_id") == attempt_id
    )
    if len(rows) != 1:
        raise core.TransitionKernelError(
            "credential issuance projection is absent or ambiguous"
        )
    row = rows[0]
    fields = (
        "release_kind",
        "attempt_id",
        "reservation_id",
        "binding_digest",
        "request_digest",
        "operation_digest",
        "quota_claims_digest",
        "request_binding_sha256",
        "request_authority_sha256",
        "recipient_key_id",
        "recipient_nonce_sha256",
        "reservation_expires_at_epoch_ms",
        "claimed_at_epoch_ms",
    )
    result = {field: row.get(field) for field in fields}
    business = _business_arguments(arguments)
    for field in (
        "release_kind",
        "attempt_id",
        "reservation_id",
        "binding_digest",
        "request_digest",
        "operation_digest",
        "request_binding_sha256",
        "recipient_key_id",
        "recipient_nonce_sha256",
        "reservation_expires_at_epoch_ms",
    ):
        if field in business and result[field] != business[field]:
            raise core.TransitionKernelError(
                "credential issuance result diverged from its request"
            )
    return result


def _audit_result(
    *,
    operation: str,
    arguments: Mapping[str, Any],
    context: core.KernelContext,
    projected: Mapping[tuple[str, str], dict[str, Any] | None],
    business_mutation_count: int,
) -> dict[str, Any]:
    del operation, arguments
    candidates = tuple(
        selected
        for selected in context.selected_rows
        if selected.get("table")
            in {
                "approval_grant_consumptions",
                "release_authorization_events",
            }
        and selected.get("present") is True
    )
    completed_by_kind = {
        "grant_consumption": 0,
        "lifecycle": 0,
    }
    for selected in candidates:
        before = _row(selected, "release audit candidate")
        if before.get("audited_at") is not None:
            continue
        identity = (selected["table"], selected["keyDigest"])
        after = projected.get(identity)
        if (
            after is not None
            and after.get("audited_at") is not None
            and core.require_digest(
                after.get("audit_event_hash"),
                "release audit event hash",
            )
                == after.get("audit_event_hash")
        ):
            kind = (
                "grant_consumption"
                if selected["table"] == "approval_grant_consumptions"
                else "lifecycle"
            )
            completed_by_kind[kind] += 1
    completed = sum(completed_by_kind.values())
    if completed > 1:
        raise core.TransitionKernelError(
            "release audit drain exceeded one candidate"
        )
    return {
        "ok": True,
        "claimed": min(len(candidates), 1),
        "completed": completed,
        "pending": max(min(len(candidates), 1) - completed, 0),
        "grant_consumptions_completed":
            completed_by_kind["grant_consumption"],
        "lifecycle_events_completed":
            completed_by_kind["lifecycle"],
        "bounded_one_candidate": True,
        "idempotent_replay": business_mutation_count == 0,
    }


_RESULT_BUILDERS: Final[
    Mapping[
        str,
        Callable[
            ...,
            dict[str, Any],
        ],
    ]
] = MappingProxyType(
    {
        "release.reserve": _release_result,
        "release.v1.reserve": _release_result,
        "release.dispatch": _release_result,
        "release.v1.dispatch": _release_result,
        "release.complete": _release_result,
        "release.v1.complete": _release_result,
        "release.cancel": _release_result,
        "release.reconcile": _release_result,
        "release.credential-claim": _claim_result,
        "release.audit-drain": _audit_result,
    }
)


def _validate_primary_key(
    table: str,
    key: Mapping[str, Any],
    row: Mapping[str, Any],
) -> None:
    fields = _PRIMARY_KEYS.get(table)
    if (
        fields is None
        or set(key) != set(fields)
        or any(row.get(field) != key[field] for field in fields)
    ):
        raise core.TransitionKernelError(
            "release transition row changed its primary key"
        )


def _release_reservation_id(
    attempt_id: str,
    binding_digest: str,
) -> str:
    return _sha256(
        {
            "apiVersion": "catchplate.releaseReservationIdentity/v1",
            "attemptId": attempt_id,
            "bindingDigest": binding_digest,
        }
    )


def _quota_claims(
    arguments: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    raw = arguments.get("quota_claims")
    if (
        not isinstance(raw, list)
        or len(raw) > _MAX_RELEASE_QUOTAS
        or any(not isinstance(item, Mapping) for item in raw)
    ):
        raise core.TransitionKernelError(
            "credential issuance quota claims exceed their exact bound"
        )
    claims = tuple(dict(item) for item in raw)
    core.canonical_bytes(list(claims))
    return claims


def _validate_claim_semantics(
    arguments: Mapping[str, Any],
    context: core.KernelContext,
    projected: Mapping[tuple[str, str], dict[str, Any] | None],
    business_mutations: tuple[Mapping[str, Any], ...],
) -> None:
    business = _business_arguments(arguments)
    attempt_id = _argument_text(business, "attempt_id")
    binding_digest = _argument_digest(business, "binding_digest")
    selected_attempt = context.exact(
        "release_authorization_attempts",
        {"attempt_id": attempt_id},
    )
    attempt = _row(selected_attempt, "credential issuance attempt")
    now_ms = (
        core.require_integer(
            business["now_epoch_ms"],
            "credential issuance time",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        )
        if business.get("now_epoch_ms") is not None
        else _database_epoch_ms(context.database_now)
    )
    expiry = core.require_integer(
        business.get("reservation_expires_at_epoch_ms"),
        "credential issuance reservation expiry",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    expected_attempt = {
        "attempt_id": attempt_id,
        "binding_digest": binding_digest,
        "request_digest": _argument_digest(business, "request_digest"),
        "operation_digest": business.get("operation_digest"),
        "principal_id": _argument_text(business, "principal_id"),
        "route_id": _argument_text(business, "route_id"),
        "credential_id": _argument_text(business, "credential_id"),
        "credential_version": core.require_integer(
            business.get("credential_version"),
            "credential issuance credential version",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        ),
        "policy_hash": _argument_digest(business, "policy_hash"),
        "reservation_expires_at_epoch_ms": expiry,
        "state": "reserved",
    }
    operation_digest = expected_attempt["operation_digest"]
    if operation_digest is not None:
        expected_attempt["operation_digest"] = core.require_digest(
            operation_digest,
            "credential issuance operation digest",
        )
    if (
        any(attempt.get(field) != value for field, value in expected_attempt.items())
        or not now_ms < expiry
    ):
        raise core.TransitionKernelError(
            "credential issuance attempt is not an active exact reservation"
        )
    expected_reservation_id = _release_reservation_id(
        attempt_id,
        binding_digest,
    )
    if (
        _argument_digest(business, "reservation_id")
        != expected_reservation_id
    ):
        raise core.TransitionKernelError(
            "credential issuance reservation identity changed"
        )

    claims = _quota_claims(business)
    claim_by_counter: dict[str, dict[str, Any]] = {}
    for claim in claims:
        counter_key = core.require_digest(
            claim.get("counterKey"),
            "credential issuance quota counter",
        )
        if counter_key in claim_by_counter:
            raise core.TransitionKernelError(
                "credential issuance quota counter is duplicated"
            )
        claim_by_counter[counter_key] = claim
    quota_rows = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "release_authorization_quota_reservations",
        )
        if row.get("attempt_id") == attempt_id
    )
    quota_by_counter = {
        str(row.get("counter_key")): row for row in quota_rows
    }
    if (
        len(quota_by_counter) != len(quota_rows)
        or set(quota_by_counter) != set(claim_by_counter)
    ):
        raise core.TransitionKernelError(
            "credential issuance quota claims changed"
        )
    for counter_key, claim in claim_by_counter.items():
        row = quota_by_counter[counter_key]
        operation = claim.get("operation")
        operation_digest_value = (
            None
            if operation is None
            else "sha256:"
                + hashlib.sha256(
                    core.require_text(
                        operation,
                        "credential issuance quota operation",
                        maximum_bytes=4096,
                    ).encode("utf-8")
                ).hexdigest()
        )
        expected_claim = {
            "constraint_id": claim.get("constraintId"),
            "operation": operation_digest_value,
            "window_kind": claim.get("windowKind"),
            "window_start_epoch_ms": claim.get("windowStartEpochMs"),
            "window_end_epoch_ms": claim.get("windowEndEpochMs"),
            "max_count": claim.get("max"),
            "count_after": claim.get("count"),
            "reservation_state": claim.get("reservationState"),
        }
        expected_window_seconds = claim.get("windowSeconds")
        if expected_window_seconds is not None:
            expected_claim["window_seconds"] = expected_window_seconds
        count = core.checked_u64(
            claim.get("count"),
            "credential issuance quota count",
        )
        maximum = core.checked_u64(
            claim.get("max"),
            "credential issuance quota maximum",
        )
        if (
            count > maximum
            or claim.get("remaining") != maximum - count
            or claim.get("reservationState") != "reserved"
            or any(
                row.get(field) != value
                for field, value in expected_claim.items()
            )
        ):
            raise core.TransitionKernelError(
                "credential issuance quota claim diverged from storage"
            )

    bundles = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "policy_state_bundles",
        )
        if row.get("attempt_id") == attempt_id
    )
    durable = business.get("durable_policy")
    if durable is not None and not isinstance(durable, Mapping):
        raise core.TransitionKernelError(
            "credential issuance durable policy is invalid"
        )
    if durable is None:
        if bundles:
            raise core.TransitionKernelError(
                "credential issuance omitted durable policy state"
            )
    elif (
        len(bundles) != 1
        or bundles[0].get("state") != "reserved"
        or bundles[0].get("reservation_id")
            != durable.get("reservationId")
        or bundles[0].get("claim_digest") != durable.get("claimDigest")
        or bundles[0].get("actor_id") != durable.get("actorId")
        or bundles[0].get("release_binding_digest")
            != durable.get("releaseBindingDigest")
        or bundles[0].get("reservation_deadline_at_epoch_ms")
            != durable.get("reservationDeadlineAtEpochMs")
        or durable.get("releaseBindingDigest") != binding_digest
        or durable.get("reservationDeadlineAtEpochMs") != expiry
    ):
        raise core.TransitionKernelError(
            "credential issuance durable policy state changed"
        )

    release_kind = _argument_text(business, "release_kind")
    grant_id = business.get("grant_id")
    approval_request_id = business.get("approval_request_id")
    if release_kind == "jitGrant":
        if (
            not isinstance(grant_id, str)
            or not grant_id
            or not isinstance(approval_request_id, str)
            or not approval_request_id
            or attempt.get("grant_id") != grant_id
            or attempt.get("approval_request_id") != approval_request_id
        ):
            raise core.TransitionKernelError(
                "credential issuance JIT binding changed"
            )
        grant = _row(
            context.exact("approval_grants", {"id": grant_id}),
            "credential issuance JIT grant",
        )
        approval = _row(
            context.exact(
                "approval_requests",
                {"id": approval_request_id},
            ),
            "credential issuance JIT approval",
        )
        if (
            grant.get("state") != "active"
            or core.checked_u64(
                grant.get("uses_remaining"),
                "credential issuance JIT uses",
            ) < 1
            or grant.get("reserved_attempt_id") != attempt_id
            or grant.get("approval_request_id") != approval_request_id
            or approval.get("status") != "approved"
            or approval.get("id") != approval_request_id
        ):
            raise core.TransitionKernelError(
                "credential issuance JIT authority is not active"
            )
    elif release_kind == "atomicReservation":
        if (
            grant_id is not None
            or approval_request_id is not None
            or attempt.get("grant_id") is not None
            or attempt.get("approval_request_id") is not None
            or not claims and durable is None
        ):
            raise core.TransitionKernelError(
                "atomic credential issuance authority changed"
            )
    elif release_kind == "decisionBound":
        if (
            grant_id is not None
            or approval_request_id is not None
            or attempt.get("grant_id") is not None
            or attempt.get("approval_request_id") is not None
            or claims
            or durable is not None
        ):
            raise core.TransitionKernelError(
                "decision-bound credential issuance carries durable authority"
            )
    else:
        raise core.TransitionKernelError(
            "credential issuance release kind is invalid"
        )

    issuance_selected = context.exact(
        "release_authorization_credential_issuances",
        {"attempt_id": attempt_id},
    )
    issuance_mutations = tuple(
        mutation
        for mutation in business_mutations
        if mutation["table"]
            == "release_authorization_credential_issuances"
    )
    issuances = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "release_authorization_credential_issuances",
        )
        if row.get("attempt_id") == attempt_id
    )
    if len(issuances) != 1:
        raise core.TransitionKernelError(
            "credential issuance projection is absent or ambiguous"
        )
    issuance = issuances[0]
    recipient_matches = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "release_authorization_credential_issuances",
        )
        if row.get("recipient_key_id")
            == _argument_digest(business, "recipient_key_id")
        and row.get("recipient_nonce_sha256")
            == _argument_digest(business, "recipient_nonce_sha256")
    )
    expected_issuance = {
        "release_kind": release_kind,
        "attempt_id": attempt_id,
        "reservation_id": expected_reservation_id,
        "binding_digest": binding_digest,
        "request_digest": expected_attempt["request_digest"],
        "operation_digest": expected_attempt["operation_digest"],
        "quota_claims_digest": _sha256(list(claims)),
        "request_binding_sha256":
            _argument_digest(business, "request_binding_sha256"),
        "request_authority_sha256":
            _argument_digest(business, "request_authority_sha256"),
        "recipient_key_id":
            _argument_digest(business, "recipient_key_id"),
        "recipient_nonce_sha256":
            _argument_digest(business, "recipient_nonce_sha256"),
        "reservation_expires_at_epoch_ms": expiry,
    }
    claimed_at = core.require_integer(
        issuance.get("claimed_at_epoch_ms"),
        "credential issuance claim time",
        minimum=0,
        maximum=_SIGNED_BIGINT_MAX,
    )
    if issuance_selected.get("present") is not True:
        expected_issuance["claimed_at_epoch_ms"] = now_ms
    if (
        len(recipient_matches) != 1
        or recipient_matches[0].get("attempt_id") != attempt_id
        or not claimed_at <= now_ms
        or not claimed_at < expiry
        or any(
            issuance.get(field) != value
            for field, value in expected_issuance.items()
        )
    ):
        raise core.TransitionKernelError(
            "credential issuance row changed its exact authority"
        )
    if issuance_selected.get("present") is True:
        if issuance_mutations:
            raise core.TransitionKernelError(
                "credential issuance replay attempted a second write"
            )
    elif (
        len(issuance_mutations) != 1
        or issuance_mutations[0]["operation"] != "INSERT"
    ):
        raise core.TransitionKernelError(
            "credential issuance did not perform its one-shot insert"
        )


def _validate_release_event(
    *,
    operation: str,
    arguments: Mapping[str, Any],
    context: core.KernelContext,
    projected: Mapping[tuple[str, str], dict[str, Any] | None],
    business_mutations: tuple[Mapping[str, Any], ...],
    attempt_id: str,
    state: str,
    state_changed: bool,
) -> None:
    event_mutations = tuple(
        mutation
        for mutation in business_mutations
        if mutation["table"] == "release_authorization_events"
    )
    if not state_changed:
        if event_mutations:
            raise core.TransitionKernelError(
                "release replay emitted a second lifecycle event"
            )
        return
    event_id = _event_id(operation, context.request_digest)
    if (
        len(event_mutations) != 1
        or event_mutations[0]["operation"] != "INSERT"
        or event_mutations[0]["key"] != {"id": event_id}
    ):
        raise core.TransitionKernelError(
            "release lifecycle event is absent or not one-shot"
        )
    events = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "release_authorization_events",
        )
        if row.get("id") == event_id
    )
    if len(events) != 1:
        raise core.TransitionKernelError(
            "release lifecycle event projection is ambiguous"
        )
    event = events[0]
    raw_event = event.get("event_json")
    try:
        event_payload = (
            json.loads(raw_event) if isinstance(raw_event, str) else None
        )
    except (TypeError, ValueError) as exc:
        raise core.TransitionKernelError(
            "release lifecycle event payload is invalid"
        ) from exc
    business = _business_arguments(arguments)
    if (
        not isinstance(event_payload, Mapping)
        or core.canonical_bytes(event_payload).decode("ascii") != raw_event
        or event.get("attempt_id") != attempt_id
        or event.get("event_type")
            != f"release_authorization.{state}"
        or event.get("audited_at") is not None
        or event.get("audit_event_hash") is not None
        or event_payload.get("attempt_id") != attempt_id
        or event_payload.get("binding_digest")
            != (
                _release_business_binding(operation, arguments)
                if operation in {"release.reserve", "release.v1.reserve"}
                else _argument_digest(business, "binding_digest")
            )
        or (
            business.get("actor_id") is not None
            and event.get("actor_id") != business.get("actor_id")
        )
    ):
        raise core.TransitionKernelError(
            "release lifecycle event changed its exact binding"
        )


def _validate_release_state_semantics(
    operation: str,
    arguments: Mapping[str, Any],
    context: core.KernelContext,
    projected: Mapping[tuple[str, str], dict[str, Any] | None],
    business_mutations: tuple[Mapping[str, Any], ...],
) -> None:
    if operation == "release.credential-claim":
        _validate_claim_semantics(
            arguments,
            context,
            projected,
            business_mutations,
        )
        return
    if operation == "release.audit-drain":
        return
    attempt_id = _attempt_id_for_operation(operation, arguments)
    selected_attempt = context.exact(
        "release_authorization_attempts",
        {"attempt_id": attempt_id},
    )
    before = (
        _row(selected_attempt, "release attempt")
        if selected_attempt.get("present") is True
        else None
    )
    attempts = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "release_authorization_attempts",
        )
        if row.get("attempt_id") == attempt_id
    )
    after = attempts[0] if len(attempts) == 1 else None
    attempt_mutations = tuple(
        mutation
        for mutation in business_mutations
        if mutation["table"] == "release_authorization_attempts"
    )
    if operation in {"release.reserve", "release.v1.reserve"}:
        if before is not None:
            binding = _release_business_binding(
                operation,
                arguments,
            )
            if (
                before.get("binding_digest") != binding
                or business_mutations
            ):
                raise core.TransitionKernelError(
                    "release reserve replay conflicts with its binding"
                )
            return
        if after is None:
            if business_mutations:
                raise core.TransitionKernelError(
                    "release reserve denial mutated durable state"
                )
            return
        business = _business_arguments(arguments)
        required = {
            "attempt_id": attempt_id,
            "flow_id": _argument_text(business, "flow_id"),
            "principal_id": _argument_text(business, "principal_id"),
            "route_id": _argument_text(business, "route_id"),
            "credential_id": _argument_text(
                business,
                "credential_id",
            ),
            "credential_version": core.require_integer(
                business.get("credential_version"),
                "release credential version",
                minimum=0,
                maximum=_SIGNED_BIGINT_MAX,
            ),
            "policy_hash": _argument_digest(business, "policy_hash"),
            "request_digest": _argument_digest(
                business,
                "request_digest",
            ),
            "binding_digest": _release_business_binding(
                operation,
                arguments,
            ),
            "state": "reserved",
        }
        reserve_now_ms = (
            core.require_integer(
                business["now_epoch_ms"],
                "release reserve time",
                minimum=0,
                maximum=_SIGNED_BIGINT_MAX,
            )
            if business.get("now_epoch_ms") is not None
            else _database_epoch_ms(context.database_now)
        )
        reservation_ttl_seconds = core.require_integer(
            business.get("reservation_ttl_seconds"),
            "release reservation TTL",
            minimum=1,
            maximum=86_400,
        )
        ttl_ms = reservation_ttl_seconds * 1000
        if reserve_now_ms > _SIGNED_BIGINT_MAX - ttl_ms:
            raise core.TransitionKernelError(
                "release reservation expiry overflows"
            )
        reservation_expiry = core.require_integer(
            after.get("reservation_expires_at_epoch_ms"),
            "release reservation expiry",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        )
        if (
            len(attempt_mutations) != 1
            or attempt_mutations[0]["operation"] != "INSERT"
            or any(after.get(field) != value for field, value in required.items())
            or not reserve_now_ms < reservation_expiry
            or reservation_expiry > reserve_now_ms + ttl_ms
        ):
            raise core.TransitionKernelError(
                "release reserve receipt changed its lifecycle"
            )
        expected_quotas = {
            str(quota["counter_key"]): quota
            for quota in _reserve_quotas(business)
        }
        projected_quotas = {
            str(row["counter_key"]): row
            for row in _projected_table(
                context,
                projected,
                "release_authorization_quota_reservations",
            )
            if row.get("attempt_id") == attempt_id
        }
        if set(projected_quotas) != set(expected_quotas):
            raise core.TransitionKernelError(
                "release reserve quota set diverged"
            )
        projected_counters = {
            str(row["counter_key"]): row
            for row in _projected_table(
                context,
                projected,
                "rate_limit_counters",
            )
            if row.get("counter_key") in expected_quotas
        }
        if set(projected_counters) != set(expected_quotas):
            raise core.TransitionKernelError(
                "release reserve counter set diverged"
            )
        quota_mutations = tuple(
            mutation
            for mutation in business_mutations
            if mutation["table"]
                == "release_authorization_quota_reservations"
        )
        counter_mutations = tuple(
            mutation
            for mutation in business_mutations
            if mutation["table"] == "rate_limit_counters"
        )
        if (
            len(quota_mutations) != len(expected_quotas)
            or {
                str(mutation["key"]["counter_key"])
                for mutation in quota_mutations
                if mutation["operation"] == "INSERT"
            }
                != set(expected_quotas)
            or len(counter_mutations) != len(expected_quotas)
            or {
                str(mutation["key"]["counter_key"])
                for mutation in counter_mutations
            }
                != set(expected_quotas)
        ):
            raise core.TransitionKernelError(
                "release reserve quota mutation set diverged"
            )
        for counter_key, quota in expected_quotas.items():
            reservation = projected_quotas[counter_key]
            counter = projected_counters[counter_key]
            counter_selected = context.exact(
                "rate_limit_counters",
                {"counter_key": counter_key},
            )
            counter_before = (
                _row(counter_selected, "release reserve counter")
                if counter_selected.get("present") is True
                else None
            )
            same_window = (
                counter_before is not None
                and counter_before.get("window_kind")
                    == counter.get("window_kind")
                and counter_before.get("window_start_epoch_ms")
                    == counter.get("window_start_epoch_ms")
                and counter_before.get("window_end_epoch_ms")
                    == counter.get("window_end_epoch_ms")
            )
            count_before = (
                core.checked_u64(
                    counter_before.get("count"),
                    "release reserve counter count",
                )
                if same_window and counter_before is not None
                else 0
            )
            expected_count = core.checked_u64_add(
                count_before,
                1,
                "release reserve counter increment",
            )
            if (
                reservation.get("constraint_id")
                    != quota.get("constraint_id")
                or reservation.get("max_count")
                    != quota.get("max_count")
                or reservation.get("reservation_state") != "reserved"
                or counter.get("max_count") != quota.get("max_count")
                or counter.get("count")
                    != reservation.get("count_after")
                or counter.get("count") != expected_count
                or counter.get("principal_id")
                    != required["principal_id"]
                or counter.get("route_id") != required["route_id"]
                or counter.get("credential_id")
                    != required["credential_id"]
                or counter.get("credential_version")
                    != required["credential_version"]
                or counter.get("policy_hash") != required["policy_hash"]
                or counter.get("constraint_id")
                    != quota.get("constraint_id")
                or not 1
                    <= counter["count"]
                    <= counter["max_count"]
            ):
                raise core.TransitionKernelError(
                    "release reserve quota arithmetic diverged"
                )
        grants = tuple(
            row
            for row in _projected_table(
                context,
                projected,
                "approval_grants",
            )
            if row.get("reserved_attempt_id") == attempt_id
        )
        grant_mutations = tuple(
            mutation
            for mutation in business_mutations
            if mutation["table"] == "approval_grants"
        )
        require_jit = business.get("require_jit_grant")
        if (
            not isinstance(require_jit, bool)
            or require_jit and (
                len(grants) != 1
                or len(grant_mutations) != 1
                or after.get("grant_id") != grants[0].get("id")
                or after.get("approval_request_id")
                    != grants[0].get("approval_request_id")
            )
            or not require_jit
                and (
                    grants
                    or grant_mutations
                    or after.get("grant_id") is not None
                    or after.get("approval_request_id") is not None
                )
        ):
            raise core.TransitionKernelError(
                "release reserve JIT authority diverged"
            )
        if require_jit:
            grant_after = grants[0]
            grant_selected = context.exact(
                "approval_grants",
                {"id": str(grant_after["id"])},
            )
            grant_before = _row(
                grant_selected,
                "release reserve JIT grant",
            )
            if (
                grant_before.get("state") != "active"
                or core.checked_u64(
                    grant_before.get("uses_remaining"),
                    "release reserve JIT grant uses",
                ) < 1
                or grant_before.get("reserved_attempt_id") is not None
                or grant_before.get("principal_id")
                    != required["principal_id"]
                or grant_before.get("route_id") != required["route_id"]
                or grant_before.get("credential_id")
                    != required["credential_id"]
                or grant_before.get("credential_version")
                    != required["credential_version"]
                or grant_before.get("policy_hash")
                    != required["policy_hash"]
                or grant_before.get("request_digest")
                    != required["request_digest"]
                or grant_after.get("reserved_attempt_id") != attempt_id
                or grant_after.get("reserved_at_epoch_ms")
                    != reserve_now_ms
                or grant_after.get("reservation_expires_at_epoch_ms")
                    != after.get("reservation_expires_at_epoch_ms")
                or any(
                    grant_after.get(field) != value
                    for field, value in grant_before.items()
                    if field not in {
                        "reserved_attempt_id",
                        "reserved_at_epoch_ms",
                        "reservation_expires_at_epoch_ms",
                    }
                )
            ):
                raise core.TransitionKernelError(
                    "release reserve JIT grant CAS diverged"
                )
        bundles = tuple(
            row
            for row in _projected_table(
                context,
                projected,
                "policy_state_bundles",
            )
            if row.get("attempt_id") == attempt_id
        )
        if (
            operation == "release.reserve"
            and (
                len(bundles) != 1
                or bundles[0].get("release_binding_digest")
                    != after.get("binding_digest")
                or bundles[0].get("state") != "reserved"
            )
            or operation == "release.v1.reserve" and bundles
        ):
            raise core.TransitionKernelError(
                "release reserve protocol binding diverged"
            )
        bundle_mutations = tuple(
            mutation
            for mutation in business_mutations
            if mutation["table"] == "policy_state_bundles"
        )
        if (
            operation == "release.reserve"
            and (
                len(bundle_mutations) != 1
                or bundle_mutations[0]["operation"] != "INSERT"
                or bundles[0].get("reservation_id")
                    != _durable_reservation_id(business)
                or bundles[0].get("policy_hash")
                    != required["policy_hash"]
                or bundles[0].get("request_digest")
                    != required["request_digest"]
                or bundles[0].get("operation_digest")
                    != business.get("operation_digest")
                or bundles[0].get("claim_digest")
                    != business["durable_policy_binding"].get(
                        "claimDigest"
                    )
                or bundles[0].get("reservation_deadline_at_epoch_ms")
                    != after.get("reservation_expires_at_epoch_ms")
            )
            or operation == "release.v1.reserve" and bundle_mutations
        ):
            raise core.TransitionKernelError(
                "release reserve durable policy mutation diverged"
            )
        _validate_release_event(
            operation=operation,
            arguments=arguments,
            context=context,
            projected=projected,
            business_mutations=business_mutations,
            attempt_id=attempt_id,
            state="reserved",
            state_changed=True,
        )
        return
    if before is None or after is None:
        raise core.TransitionKernelError(
            "release lifecycle transition lost its attempt"
        )
    business = _business_arguments(arguments)
    binding = _argument_digest(business, "binding_digest")
    if before.get("binding_digest") != binding:
        raise core.TransitionKernelError(
            "release lifecycle binding conflicts"
        )
    bundles = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "policy_state_bundles",
        )
        if row.get("attempt_id") == attempt_id
    )
    if (
        operation in {"release.dispatch", "release.complete"}
        and len(bundles) != 1
        or operation
            in {
                "release.v1.dispatch",
                "release.v1.complete",
                "release.cancel",
            }
            and bundles
    ):
        raise core.TransitionKernelError(
            "release lifecycle protocol was substituted"
        )
    if not attempt_mutations:
        if after != before:
            raise core.TransitionKernelError(
                "release replay changed its attempt"
            )
        _validate_release_event(
            operation=operation,
            arguments=arguments,
            context=context,
            projected=projected,
            business_mutations=business_mutations,
            attempt_id=attempt_id,
            state=str(before.get("state")),
            state_changed=False,
        )
        return
    if len(attempt_mutations) != 1:
        raise core.TransitionKernelError(
            "release lifecycle mutated its attempt more than once"
        )
    before_state = str(before.get("state"))
    after_state = str(after.get("state"))
    business_now = business.get("now_epoch_ms")
    now_ms = (
        core.require_integer(
            business_now,
            "release transition time",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        )
        if business_now is not None
        else _database_epoch_ms(context.database_now)
    )
    if operation in {"release.dispatch", "release.v1.dispatch"}:
        allowed = {("reserved", "dispatching")}
    elif operation == "release.cancel":
        allowed = {("reserved", "cancelled")}
    elif operation == "release.reconcile":
        deadline_field = (
            "reservation_expires_at_epoch_ms"
            if before_state == "reserved"
            else "dispatch_expires_at_epoch_ms"
        )
        deadline = before.get(deadline_field)
        if (
            not isinstance(deadline, int)
            or isinstance(deadline, bool)
            or deadline > now_ms
        ):
            raise core.TransitionKernelError(
                "release reconciliation candidate is not due"
            )
        allowed = (
            {("reserved", "cancelled")}
            if before_state == "reserved"
            else {("dispatching", "committed_indeterminate")}
        )
    else:
        outcome = business.get("outcome")
        if outcome not in {"forwarded", "not_forwarded", "unknown"}:
            raise core.TransitionKernelError(
                "release completion outcome is invalid"
            )
        dispatch_stale = (
            before_state == "dispatching"
            and isinstance(before.get("dispatch_expires_at_epoch_ms"), int)
            and not isinstance(
                before.get("dispatch_expires_at_epoch_ms"),
                bool,
            )
            and before["dispatch_expires_at_epoch_ms"] <= now_ms
        )
        if outcome == "not_forwarded" and before_state == "reserved":
            allowed = {("reserved", "cancelled")}
        elif (
            outcome == "forwarded"
            and before_state == "dispatching"
            and not dispatch_stale
        ):
            allowed = {("dispatching", "committed")}
        else:
            allowed = {
                ("reserved", "committed_indeterminate"),
                ("dispatching", "committed_indeterminate"),
            }
    if (before_state, after_state) not in allowed:
        raise core.TransitionKernelError(
            "release receipt changed the conservative lifecycle"
        )
    mutable_attempt_fields = {
        "state",
        "updated_at",
    }
    if after_state == "dispatching":
        mutable_attempt_fields.update(
            {
                "dispatch_started_at_epoch_ms",
                "dispatch_expires_at_epoch_ms",
            }
        )
    else:
        mutable_attempt_fields.update(
            {
                "completion_outcome",
                "completed_at_epoch_ms",
            }
        )
    if any(
        after.get(field) != value
        for field, value in before.items()
        if field not in mutable_attempt_fields
    ):
        raise core.TransitionKernelError(
            "release lifecycle changed immutable attempt authority"
        )
    if after_state == "dispatching":
        dispatch_expiry = core.require_integer(
            after.get("dispatch_expires_at_epoch_ms"),
            "release dispatch expiry",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        )
        if (
            after.get("dispatch_started_at_epoch_ms") != now_ms
            or dispatch_expiry <= now_ms
        ):
            raise core.TransitionKernelError(
                "release dispatch timing changed"
            )
    else:
        expected_outcome = (
            business.get("outcome")
            if operation
                in {"release.complete", "release.v1.complete"}
            else "not_forwarded"
            if after_state == "cancelled"
            else "unknown"
        )
        if (
            after.get("completion_outcome") != expected_outcome
            or after.get("completed_at_epoch_ms") != now_ms
        ):
            raise core.TransitionKernelError(
                "release terminal outcome changed"
            )
    bundle_mutations = tuple(
        mutation
        for mutation in business_mutations
        if mutation["table"] == "policy_state_bundles"
    )
    if bundles:
        before_bundles = tuple(
            dict(selected["row"])
            for selected in context.present_rows("policy_state_bundles")
            if isinstance(selected.get("row"), Mapping)
            and selected["row"].get("attempt_id") == attempt_id
        )
        if (
            len(before_bundles) != 1
            or len(bundle_mutations) != 1
            or bundle_mutations[0]["operation"] != "UPDATE"
        ):
            raise core.TransitionKernelError(
                "release durable lifecycle is not an exact CAS"
            )
        bundle_before = before_bundles[0]
        bundle_after = bundles[0]
        expected_bundle_states = (
            {"dispatched"}
            if after_state == "dispatching"
            else {"aborted"}
            if after_state == "cancelled"
            else {"committed", "denied"}
            if after_state == "committed"
            else {"indeterminate"}
        )
        if (
            bundle_after.get("state") not in expected_bundle_states
            or any(
                bundle_after.get(field) != value
                for field, value in bundle_before.items()
                if field
                    not in {
                        "state",
                        "dispatch_started_at_epoch_ms",
                        "dispatch_deadline_at_epoch_ms",
                        "completion_dispatch_deadline_at_epoch_ms",
                        "response_evidence_digest",
                        "response_evidence_json",
                        "terminal_reason",
                        "response_body_sha256",
                        "uncertainty",
                        "updated_at",
                    }
            )
            or bundle_after.get("release_binding_digest") != binding
        ):
            raise core.TransitionKernelError(
                "release durable lifecycle changed immutable authority"
            )
        if after_state == "dispatching" and (
            bundle_after.get("dispatch_started_at_epoch_ms") != now_ms
            or bundle_after.get("dispatch_deadline_at_epoch_ms")
                != after.get("dispatch_expires_at_epoch_ms")
        ):
            raise core.TransitionKernelError(
                "release durable dispatch timing changed"
            )
    elif bundle_mutations:
        raise core.TransitionKernelError(
            "release v1 transition introduced durable policy state"
        )
    _validate_release_event(
        operation=operation,
        arguments=arguments,
        context=context,
        projected=projected,
        business_mutations=business_mutations,
        attempt_id=attempt_id,
        state=after_state,
        state_changed=True,
    )
    quota_target = (
        "committed"
        if after_state in {"committed", "committed_indeterminate"}
        else None
    )
    quota_mutations = tuple(
        mutation
        for mutation in business_mutations
        if mutation["table"]
            == "release_authorization_quota_reservations"
    )
    counter_mutations = tuple(
        mutation
        for mutation in business_mutations
        if mutation["table"] == "rate_limit_counters"
    )
    grant_mutations = tuple(
        mutation
        for mutation in business_mutations
        if mutation["table"] == "approval_grants"
    )
    consumption_mutations = tuple(
        mutation
        for mutation in business_mutations
        if mutation["table"] == "approval_grant_consumptions"
    )
    before_quotas = {
        str(selected["row"]["counter_key"]): dict(selected["row"])
        for selected in context.present_rows(
            "release_authorization_quota_reservations"
        )
        if isinstance(selected.get("row"), Mapping)
        and selected["row"].get("attempt_id") == attempt_id
    }
    after_quotas = {
        str(row["counter_key"]): row
        for row in _projected_table(
            context,
            projected,
            "release_authorization_quota_reservations",
        )
        if row.get("attempt_id") == attempt_id
    }
    quota_mutation_keys = {
        str(mutation["key"]["counter_key"])
        for mutation in quota_mutations
    }
    if set(after_quotas) != set(before_quotas):
        raise core.TransitionKernelError(
            "release lifecycle changed its quota row set"
        )
    if after_state == "dispatching":
        if (
            quota_mutations
            or counter_mutations
            or grant_mutations
            or consumption_mutations
        ):
            raise core.TransitionKernelError(
                "release dispatch changed terminal accounting"
            )
    elif quota_mutation_keys != {
        counter_key
        for counter_key, row in before_quotas.items()
        if row.get("reservation_state") == "reserved"
    }:
        raise core.TransitionKernelError(
            "release terminal transition did not close every quota exactly"
        )
    counter_mutations_by_key = {
        str(mutation["key"]["counter_key"]): mutation
        for mutation in counter_mutations
    }
    if len(counter_mutations_by_key) != len(counter_mutations):
        raise core.TransitionKernelError(
            "release lifecycle counter mutation is duplicated"
        )
    expected_counter_mutation_keys: set[str] = set()
    for mutation in quota_mutations:
        before_quota = mutation["expectedRow"]
        after_quota = mutation["row"]
        if (
            not isinstance(before_quota, Mapping)
            or not isinstance(after_quota, Mapping)
            or before_quota.get("attempt_id") != attempt_id
            or before_quota.get("reservation_state") != "reserved"
        ):
            raise core.TransitionKernelError(
                "release quota transition is not exact"
            )
        after_quota_state = after_quota.get("reservation_state")
        if any(
            after_quota.get(field) != value
            for field, value in before_quota.items()
            if field not in {"reservation_state", "updated_at"}
        ):
            raise core.TransitionKernelError(
                "release quota transition changed immutable authority"
            )
        counter_key = str(before_quota["counter_key"])
        selected_counter = context.exact(
            "rate_limit_counters",
            {"counter_key": counter_key},
        )
        counter_before = (
            _row(selected_counter, "release lifecycle counter")
            if selected_counter.get("present") is True
            else None
        )
        if quota_target is not None:
            if (
                after_quota_state != quota_target
                or counter_key in counter_mutations_by_key
            ):
                raise core.TransitionKernelError(
                    "release uncertainty did not conservatively charge quota"
                )
        else:
            matching_window = (
                counter_before is not None
                and counter_before.get("window_kind")
                    == before_quota.get("window_kind")
                and counter_before.get("window_start_epoch_ms")
                    == before_quota.get("window_start_epoch_ms")
                and counter_before.get("window_end_epoch_ms")
                    == before_quota.get("window_end_epoch_ms")
            )
            expected_quota_state = (
                "refunded"
                if matching_window
                else "refund_skipped_window"
            )
            if after_quota_state != expected_quota_state:
                raise core.TransitionKernelError(
                    "release cancellation did not close quota"
                )
            counter_mutation = counter_mutations_by_key.get(counter_key)
            if not matching_window:
                if counter_mutation is not None:
                    raise core.TransitionKernelError(
                        "release cancellation changed a different quota window"
                    )
                continue
            expected_counter_mutation_keys.add(counter_key)
            if (
                counter_mutation is None
                or not isinstance(counter_mutation.get("expectedRow"), Mapping)
                or not isinstance(counter_mutation.get("row"), Mapping)
            ):
                raise core.TransitionKernelError(
                    "release cancellation omitted its exact quota refund"
                )
            counter_after = counter_mutation["row"]
            expected_count = core.checked_u64_sub(
                core.checked_u64(
                    counter_before.get("count"),
                    "release refund counter count",
                ),
                min(
                    core.checked_u64(
                        counter_before.get("count"),
                        "release refund counter count",
                    ),
                    1,
                ),
                "release refund counter decrement",
            )
            if (
                counter_mutation["expectedRow"] != counter_before
                or counter_after.get("count") != expected_count
                or any(
                    counter_after.get(field) != value
                    for field, value in counter_before.items()
                    if field not in {"count", "updated_at"}
                )
            ):
                raise core.TransitionKernelError(
                    "release cancellation quota refund is not exact"
                )
    if set(counter_mutations_by_key) != expected_counter_mutation_keys:
        raise core.TransitionKernelError(
            "release lifecycle counter mutation set changed"
        )
    if after_state in {"committed", "committed_indeterminate"}:
        remaining_reserved = tuple(
            row
            for row in _projected_table(
                context,
                projected,
                "release_authorization_quota_reservations",
            )
            if row.get("attempt_id") == attempt_id
            and row.get("reservation_state") == "reserved"
        )
        if remaining_reserved:
            raise core.TransitionKernelError(
                "release terminal state retained reserved quota"
            )
    grant_id = before.get("grant_id")
    if grant_id is None:
        if grant_mutations or consumption_mutations:
            raise core.TransitionKernelError(
                "release without JIT authority changed grant state"
            )
        return
    grants = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "approval_grants",
        )
        if row.get("id") == grant_id
    )
    if len(grants) != 1:
        raise core.TransitionKernelError(
            "release JIT grant projection is absent or ambiguous"
        )
    grant_after = grants[0]
    if after_state == "cancelled":
        if (
            len(grant_mutations) != 1
            or consumption_mutations
            or grant_after.get("reserved_attempt_id") is not None
            or grant_after.get("reserved_at_epoch_ms") is not None
            or grant_after.get("reservation_expires_at_epoch_ms")
                is not None
        ):
            raise core.TransitionKernelError(
                "release cancellation retained its JIT reservation"
            )
        return
    if after_state not in {"committed", "committed_indeterminate"}:
        return
    grant_selected = tuple(
        selected
        for selected in context.present_rows("approval_grants")
        if isinstance(selected.get("row"), Mapping)
        and selected["row"].get("id") == grant_id
    )
    if len(grant_selected) != 1:
        raise core.TransitionKernelError(
            "release JIT grant source is absent or ambiguous"
        )
    grant_before = _row(grant_selected[0], "release JIT grant")
    if (
        len(grant_mutations) != 1
        or grant_before.get("reserved_attempt_id") != attempt_id
        or grant_before.get("state") != "active"
    ):
        raise core.TransitionKernelError(
            "release terminal transition lost its reserved JIT grant"
        )
    uses_before = core.require_integer(
        grant_before.get("uses_remaining"),
        "release JIT grant uses",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    uses_after = core.checked_u64_sub(
        uses_before,
        1,
        "release JIT grant consumption",
    )
    if (
        grant_after.get("uses_remaining") != uses_after
        or grant_after.get("state")
            != ("consumed" if uses_after == 0 else "active")
        or grant_after.get("reserved_attempt_id") is not None
        or grant_after.get("reserved_at_epoch_ms") is not None
        or grant_after.get("reservation_expires_at_epoch_ms") is not None
    ):
        raise core.TransitionKernelError(
            "release terminal transition did not consume its JIT grant"
        )
    consumptions = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "approval_grant_consumptions",
        )
        if row.get("attempt_id") == attempt_id
    )
    if (
        len(consumptions) != 1
        or len(consumption_mutations) != 1
        or consumption_mutations[0]["operation"] != "INSERT"
        or consumptions[0].get("id")
            != _consumption_id(operation, context.request_digest)
        or consumptions[0].get("grant_id") != grant_id
        or consumptions[0].get("outcome") != "consumed"
        or consumptions[0].get("uses_remaining_before") != uses_before
        or consumptions[0].get("uses_remaining_after") != uses_after
        or consumptions[0].get("verified_assertion_receipt_digest")
            != grant_before.get("verified_assertion_receipt_digest")
    ):
        raise core.TransitionKernelError(
            "release terminal transition lost its JIT consumption record"
        )


def _physical_webauthn_consume(
    *,
    context: core.KernelContext,
    statement: Mapping[str, Any],
    projected: Mapping[tuple[str, str], dict[str, Any] | None],
    operation_id: str,
) -> dict[str, Any] | None:
    if context.operation not in _PHYSICAL_WEBAUTHN_CONSUMING_OPERATIONS:
        return None
    attempt_id = _attempt_id_for_operation(
        context.operation,
        context.arguments,
    )
    attempt_selected = context.exact(
        "release_authorization_attempts",
        {"attempt_id": attempt_id},
    )
    attempt_before = _row(attempt_selected, "release attempt")
    if attempt_before.get("state") in {
        "committed",
        "cancelled",
        "committed_indeterminate",
    }:
        return None
    attempts = tuple(
        row
        for row in _projected_table(
            context,
            projected,
            "release_authorization_attempts",
        )
        if row.get("attempt_id") == attempt_id
    )
    if len(attempts) != 1:
        raise core.TransitionKernelError(
            "release physical authorization lost its attempt"
        )
    attempt_after = attempts[0]
    if attempt_after.get("state") not in {
        "committed",
        "committed_indeterminate",
    }:
        return None
    grant_id = attempt_before.get("grant_id")
    if not isinstance(grant_id, str) or not grant_id:
        return None
    grant_selected = tuple(
        selected
        for selected in context.present_rows("approval_grants")
        if isinstance(selected.get("row"), Mapping)
        and selected["row"].get("id") == grant_id
    )
    approval_selected = tuple(
        selected
        for selected in context.present_rows("approval_requests")
        if isinstance(selected.get("row"), Mapping)
        and selected["row"].get("id")
            == attempt_before.get("approval_request_id")
    )
    if len(grant_selected) != 1 or len(approval_selected) != 1:
        raise core.TransitionKernelError(
            "release physical authorization lost its JIT authority"
        )
    grant = _row(grant_selected[0], "release JIT grant")
    approval = _row(approval_selected[0], "release JIT approval")
    evidence_digest = core.require_digest(
        statement["authorityComponents"].get(
            "jitAuthorityReceiptDigest"
        ),
        "release physical WebAuthn evidence digest",
    )
    if grant.get("verified_assertion_receipt_digest") != evidence_digest:
        raise core.TransitionKernelError(
            "release physical evidence diverged from its JIT grant"
        )
    evidence_matches = tuple(
        selected
        for selected in context.present_rows(
            "policy_authority_external_evidence_receipts"
        )
        if isinstance(selected.get("row"), Mapping)
        and selected["row"].get("evidence_digest") == evidence_digest
        and selected["row"].get("evidence_type")
            == "webauthn-hardware-authorization/v1"
    )
    if len(evidence_matches) != 1:
        raise core.TransitionKernelError(
            "release physical WebAuthn evidence is absent or ambiguous"
        )
    physical_statement = _canonical_statement(
        _row(evidence_matches[0], "release physical WebAuthn evidence")
    )
    if not _PHYSICAL_WEBAUTHN_BINDING_FIELDS <= set(physical_statement):
        raise core.TransitionKernelError(
            "release physical WebAuthn binding is incomplete"
        )
    binding = {
        field: physical_statement[field]
        for field in _PHYSICAL_WEBAUTHN_BINDING_FIELDS
    }
    credential_record_id = core.require_text(
        grant.get("approver_webauthn_credential_id"),
        "release physical credential record",
        maximum_bytes=256,
    )
    actor_id = core.require_text(
        approval.get("approved_by"),
        "release physical approver",
        maximum_bytes=512,
    )
    trust = _row(
        context.exact(
            "webauthn_trust_publication_high_water",
            {"authority_scope": "webauthn-metadata"},
        ),
        "release WebAuthn trust high-water",
    )
    expected = {
        "operation": context.operation,
        "operationId": operation_id,
        "requestDigest": core.require_digest(
            attempt_before.get("request_digest"),
            "release physical request digest",
        ),
        "credentialRecordId": credential_record_id,
        "grantId": grant_id,
        "actorId": actor_id,
        "trustGeneration": core.require_integer(
            trust.get("publication_sequence"),
            "release WebAuthn trust generation",
            minimum=1,
            maximum=_SIGNED_BIGINT_MAX,
        ),
        "trustRootDigest": core.require_digest(
            trust.get("publication_digest"),
            "release WebAuthn trust root",
        ),
    }
    if any(binding.get(field) != value for field, value in expected.items()):
        raise core.TransitionKernelError(
            "release physical WebAuthn evidence changed its authority binding"
        )
    for field in (
        "credentialIdDigest",
        "challengeDigest",
        "authenticatorDataDigest",
        "clientDataDigest",
        "assertionSignatureDigest",
    ):
        core.require_digest(
            binding.get(field),
            f"release physical WebAuthn {field}",
        )
    core.require_text(
        binding.get("ceremonyId"),
        "release physical WebAuthn ceremony",
        maximum_bytes=256,
    )
    for field in ("priorCounter", "newCounter"):
        core.require_integer(
            binding.get(field),
            f"release physical WebAuthn {field}",
            minimum=0,
            maximum=_SIGNED_BIGINT_MAX,
        )
    return context.consume_physical_webauthn_evidence(
        evidence_digest=evidence_digest,
        expected_binding=binding,
        operation_id=operation_id,
    )


def _receipt_mutations(
    *,
    context: core.KernelContext,
    statement: Mapping[str, Any],
) -> tuple[dict[str, Any], ...]:
    raw_mutations = statement.get("mutations")
    if (
        not isinstance(raw_mutations, list)
        or len(raw_mutations) > 64
        or any(not isinstance(item, Mapping) for item in raw_mutations)
    ):
        raise core.TransitionKernelError(
            "release transition receipt mutations are not bounded"
        )
    allowed = _MUTATION_TABLES[context.operation]
    identities: set[tuple[str, str]] = set()
    mutations: list[dict[str, Any]] = []
    for raw in raw_mutations:
        item = dict(raw)
        table = item.get("table")
        kind = item.get("operation")
        key = item.get("key")
        after_row = item.get("afterRow")
        if (
            set(item) != _RECEIPT_MUTATION_FIELDS
            or table not in allowed
            or kind not in allowed[table]
            or not isinstance(key, Mapping)
            or (
                kind == "DELETE"
                and after_row is not None
            )
            or (
                kind != "DELETE"
                and not isinstance(after_row, Mapping)
            )
        ):
            raise core.TransitionKernelError(
                "release receipt mutation escaped its typed allowlist"
            )
        selected = context.exact(str(table), dict(key))
        identity = (str(table), str(selected["keyDigest"]))
        if identity in identities:
            raise core.TransitionKernelError(
                "release receipt mutates one row more than once"
            )
        identities.add(identity)
        before_digest = _selected_row_digest(selected)
        if item.get("beforeRowDigest") != before_digest:
            raise core.TransitionKernelError(
                "release receipt before-row digest changed"
            )
        after_digest = core.framed_digest(
            "catchplate.policyAuthorityReleaseAfterRow/v1",
            core.canonical_bytes(after_row),
        )
        if item.get("afterRowDigest") != after_digest:
            raise core.TransitionKernelError(
                "release receipt after-row digest changed"
            )
        if kind == "DELETE":
            mutation = core.delete_mutation(
                operation=context.operation,
                selected=selected,
            )
        else:
            _validate_primary_key(
                str(table),
                dict(key),
                dict(after_row),
            )
            mutation = core.mutation(
                operation=context.operation,
                selected=selected,
                row=dict(after_row),
            )
            if mutation["operation"] != kind:
                raise core.TransitionKernelError(
                    "release receipt mutation kind changed"
                )
        mutations.append(mutation)
    return tuple(mutations)


def _transition_from_receipt(
    context: core.KernelContext,
) -> core.KernelTransition:
    operation = context.operation
    binding_digest = _operation_binding(
        operation,
        context.arguments,
        context.request_digest,
    )
    evidence_type = _EVIDENCE_TYPES[operation]
    evidence = _evidence_row(
        context,
        evidence_type=evidence_type,
        binding_digest=binding_digest,
    )
    evidence_digest = core.require_digest(
        evidence.get("evidence_digest"),
        "release transition evidence digest",
    )
    context.evidence(
        evidence_type=evidence_type,
        evidence_digest=evidence_digest,
        binding_digest=binding_digest,
    )
    statement = _canonical_statement(evidence)
    operation_id = _operation_id(operation, context.request_digest)
    components = statement.get("authorityComponents")
    now_ns = _database_epoch_ns(context.database_now)
    if (
        set(statement) != _TRANSITION_RECEIPT_FIELDS
        or statement.get("schema") != _TRANSITION_RECEIPT_SCHEMA
        or statement.get("operation") != operation
        or statement.get("operationId") != operation_id
        or statement.get("requestDigest") != context.request_digest
        or statement.get("bindingDigest") != binding_digest
        or statement.get("selectedRowsDigest")
            != _selected_rows_digest(context)
        or not isinstance(components, Mapping)
        or set(components) != _AUTHORITY_COMPONENTS[operation]
        or any(
            core.require_digest(
                value,
                f"release authority component {name}",
            )
                != value
            for name, value in components.items()
        )
    ):
        raise core.TransitionKernelError(
            "release transition receipt binding diverged"
        )
    issued_at = core.require_integer(
        statement.get("issuedAtEpochNs"),
        "release transition receipt issuance",
        minimum=0,
        maximum=_SIGNED_BIGINT_MAX,
    )
    expires_at = core.require_integer(
        statement.get("expiresAtEpochNs"),
        "release transition receipt expiry",
        minimum=1,
        maximum=_SIGNED_BIGINT_MAX,
    )
    if not issued_at <= now_ns < expires_at:
        raise core.TransitionKernelError(
            "release transition receipt is outside its validity"
        )
    business_mutations = _receipt_mutations(
        context=context,
        statement=statement,
    )
    projected = _projected_rows(context, business_mutations)
    _validate_release_state_semantics(
        operation,
        context.arguments,
        context,
        projected,
        business_mutations,
    )
    result = _RESULT_BUILDERS[operation](
        operation=operation,
        arguments=context.arguments,
        context=context,
        projected=projected,
        business_mutation_count=len(business_mutations),
    )
    result_digest = core.framed_digest(
        "catchplate.policyAuthorityReleaseResult/v1",
        core.canonical_bytes(result),
    )
    transition_digest = core.framed_digest(
        "catchplate.policyAuthorityReleaseTransition/v1",
        operation.encode("ascii"),
        binding_digest.encode("ascii"),
        core.canonical_bytes(statement["mutations"]),
        result_digest.encode("ascii"),
    )
    if (
        statement.get("resultDigest") != result_digest
        or statement.get("transitionDigest") != transition_digest
    ):
        raise core.TransitionKernelError(
            "release transition result cannot be recomputed"
        )
    physical_webauthn_consume = _physical_webauthn_consume(
        context=context,
        statement=statement,
        projected=projected,
        operation_id=operation_id,
    )
    consume = context.consume_evidence(
        evidence_type=evidence_type,
        evidence_digest=evidence_digest,
        binding_digest=binding_digest,
        operation_id=operation_id,
    )
    authority_mutations = (
        (consume,)
        if physical_webauthn_consume is None
        else (physical_webauthn_consume, consume)
    )
    return core.KernelTransition(
        mutations=business_mutations + authority_mutations,
        result=result,
        work_units=(
            32
            + 3 * len(business_mutations)
            + int(physical_webauthn_consume is not None) * 8
        ),
    )


@dataclass(frozen=True, slots=True)
class _ReleaseReceiptKernel:
    operation: str
    handler: str
    query_builder: Callable[
        [str, Mapping[str, Any], str],
        tuple[core.BoundedQuery, ...],
    ]
    permits_empty_mutation: bool = False

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
        if self.operation == "release.reserve":
            from catchplate import authority_transition_native_jit_pending as pending
            if pending.is_profile(arguments):
                return pending.queries(arguments=arguments, database_now=database_now,
                    request_digest=request_digest)
        del database_now
        return self.query_builder(
            self.operation,
            arguments,
            request_digest,
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        if self.operation == "release.reserve":
            from catchplate import authority_transition_native_jit_pending as pending
            if pending.is_profile(context.arguments):
                return pending.transition(context)
        if context.native_jit_pending is not None:
            raise core.TransitionKernelError("native JIT retention is outside its release branch")
        if self.operation == "release.audit-drain" and not any(
            selected.get("present") is True
            for selected in context.selected_rows
            if selected.get("table")
                in {
                    "approval_grant_consumptions",
                    "release_authorization_events",
                }
        ):
            return core.KernelTransition(
                mutations=(),
                result={
                    "ok": True,
                    "claimed": 0,
                    "completed": 0,
                    "pending": 0,
                    "grant_consumptions_completed": 0,
                    "lifecycle_events_completed": 0,
                    "bounded_one_candidate": True,
                    "idempotent_replay": True,
                },
                work_units=1,
            )
        return _transition_from_receipt(context)


def _lifecycle_query_builder(
    operation: str,
    arguments: Mapping[str, Any],
    request_digest: str,
) -> tuple[core.BoundedQuery, ...]:
    return _attempt_queries(
        operation,
        arguments,
        request_digest,
        include_issuance=operation == "release.credential-claim",
    )


def _nonce_arguments(
    arguments: Mapping[str, Any],
) -> tuple[str, str, int, int, int]:
    business = _business_arguments(arguments)
    if set(business) != {
        "recipientKeyId",
        "nonceSha256",
        "nowEpochMs",
        "retentionMs",
        "maximumEntries",
    }:
        raise core.TransitionKernelError(
            "credential nonce arguments are not exact"
        )
    recipient_key_id = core.require_digest(
        business["recipientKeyId"],
        "credential nonce recipient key",
    )
    nonce_digest = core.require_digest(
        business["nonceSha256"],
        "credential nonce digest",
    )
    now_ms = core.require_integer(
        business["nowEpochMs"],
        "credential nonce time",
        minimum=0,
        maximum=_SIGNED_BIGINT_MAX,
    )
    retention_ms = core.require_integer(
        business["retentionMs"],
        "credential nonce retention",
        minimum=1,
        maximum=86_400_000,
    )
    maximum_entries = core.require_integer(
        business["maximumEntries"],
        "credential nonce capacity",
        minimum=1,
        maximum=10_000_000,
    )
    if now_ms > _SIGNED_BIGINT_MAX - retention_ms:
        raise core.TransitionKernelError(
            "credential nonce expiry overflows"
        )
    return (
        recipient_key_id,
        nonce_digest,
        now_ms,
        retention_ms,
        maximum_entries,
    )


@dataclass(frozen=True, slots=True)
class _CredentialNonceReserveKernel:
    operation: str = "credential-nonce.reserve"
    handler: str = "reserve_credential_lease_nonce"
    permits_empty_mutation: bool = True
    program_id: str = core.transition_program_id(
        "credential-nonce.reserve",
        "reserve_credential_lease_nonce",
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
            "credential nonce planner request",
        )
        recipient, nonce, now_ms, _, _ = _nonce_arguments(arguments)
        key = {
            "recipient_key_id": recipient,
            "nonce_sha256": nonce,
        }
        return (
            _exact_query(
                self.operation,
                "replay_state",
                "credential_lease_replay_state",
                {"scope": "global"},
            ),
            _exact_query(
                self.operation,
                "requested_nonce",
                "credential_lease_nonces",
                key,
            ),
            _query(
                self.operation,
                "expired_page",
                "credential_lease_nonces",
                predicates=(
                    core.QueryPredicate(
                        "expires_at_epoch_ms",
                        "lte",
                        now_ms,
                    ),
                ),
                order_by=(
                    core.QueryOrder("expires_at_epoch_ms"),
                    core.QueryOrder("recipient_key_id"),
                    core.QueryOrder("nonce_sha256"),
                ),
                maximum_rows=_MAX_NONCE_EXPIRY_PAGE + 1,
                proof_primitive="bounded-limit-plus-one",
                page_size=_MAX_NONCE_EXPIRY_PAGE,
            ),
        )

    def transition(
        self,
        context: core.KernelContext,
    ) -> core.KernelTransition:
        (
            recipient,
            nonce,
            now_ms,
            retention_ms,
            maximum_entries,
        ) = _nonce_arguments(context.arguments)
        replay_selected = context.exact(
            "credential_lease_replay_state",
            {"scope": "global"},
        )
        replay = _row(replay_selected, "credential nonce replay state")
        previous_count = core.require_integer(
            replay.get("nonce_count"),
            "credential nonce replay count",
            minimum=0,
            maximum=maximum_entries,
        )
        requested_key = {
            "recipient_key_id": recipient,
            "nonce_sha256": nonce,
        }
        requested_selected = context.exact(
            "credential_lease_nonces",
            requested_key,
        )
        expired_selected_all = tuple(
            sorted(
                (
                    selected
                    for selected in context.present_rows(
                        "credential_lease_nonces"
                    )
                    if core.require_integer(
                        _row(selected, "credential nonce").get(
                            "expires_at_epoch_ms"
                        ),
                        "credential nonce expiry",
                        minimum=0,
                        maximum=_SIGNED_BIGINT_MAX,
                    )
                        <= now_ms
                ),
                key=lambda selected: core.canonical_bytes(
                    {
                        "expiresAtEpochMs":
                            selected["row"]["expires_at_epoch_ms"],
                        "recipientKeyId":
                            selected["row"]["recipient_key_id"],
                        "nonceSha256": selected["row"]["nonce_sha256"],
                        "keyDigest": selected["keyDigest"],
                    }
                ),
            )
        )
        maintenance_complete = (
            len(expired_selected_all) <= _MAX_NONCE_EXPIRY_PAGE
        )
        expired_selected = expired_selected_all[
            :_MAX_NONCE_EXPIRY_PAGE
        ]
        continuation_digest = (
            None
            if maintenance_complete
            else core.framed_digest(
                "catchplate.policyAuthorityCredentialNonceContinuation/v1",
                context.request_digest.encode("ascii"),
                core.canonical_bytes(
                    {
                        "expiresAtEpochMs":
                            expired_selected_all[
                                _MAX_NONCE_EXPIRY_PAGE
                            ]["row"]["expires_at_epoch_ms"],
                        "recipientKeyId":
                            expired_selected_all[
                                _MAX_NONCE_EXPIRY_PAGE
                            ]["row"]["recipient_key_id"],
                        "nonceSha256":
                            expired_selected_all[
                                _MAX_NONCE_EXPIRY_PAGE
                            ]["row"]["nonce_sha256"],
                        "keyDigest":
                            expired_selected_all[
                                _MAX_NONCE_EXPIRY_PAGE
                            ]["keyDigest"],
                    }
                ),
            )
        )
        expired_identities = {
            (selected["table"], selected["keyDigest"])
            for selected in expired_selected
        }
        pruned_count = max(
            0,
            previous_count - len(expired_identities),
        )
        mutations: list[dict[str, Any]] = []
        requested_identity = (
            requested_selected["table"],
            requested_selected["keyDigest"],
        )
        for selected in expired_selected:
            identity = (selected["table"], selected["keyDigest"])
            if identity == requested_identity and maintenance_complete:
                continue
            mutations.append(
                core.delete_mutation(
                    operation=self.operation,
                    selected=selected,
                )
            )
        requested = (
            _row(requested_selected, "credential nonce")
            if requested_selected.get("present") is True
            else None
        )
        active_replay = (
            requested is not None
            and requested_identity not in expired_identities
            and requested["expires_at_epoch_ms"] > now_ms
        )
        if not maintenance_complete:
            outcome = "maintenance-required"
            next_count = pruned_count
        elif active_replay:
            outcome: str | None = "replay"
            next_count = pruned_count
        elif pruned_count >= maximum_entries:
            outcome = "capacity"
            next_count = pruned_count
        else:
            now_s = _iso_from_epoch_ms(now_ms)
            nonce_row = {
                "recipient_key_id": recipient,
                "nonce_sha256": nonce,
                "expires_at_epoch_ms": now_ms + retention_ms,
                "created_at": now_s,
            }
            mutations.append(
                core.mutation(
                    operation=self.operation,
                    selected=requested_selected,
                    row=nonce_row,
                )
            )
            outcome = None
            next_count = pruned_count + 1
        if next_count != previous_count:
            mutations.append(
                core.mutation(
                    operation=self.operation,
                    selected=replay_selected,
                    row={
                        **replay,
                        "nonce_count": next_count,
                    },
                )
            )
        return core.KernelTransition(
            mutations=tuple(mutations),
            result={
                "outcome": outcome,
                "nonceCount": next_count,
                "maximumEntries": maximum_entries,
                "expiredRowsPruned": len(expired_identities),
                "maintenanceComplete": maintenance_complete,
                "continuationDigest": continuation_digest,
                "boundedPageMaximum": _MAX_NONCE_EXPIRY_PAGE,
            },
            work_units=16 + 3 * len(mutations),
        )


_KERNEL_VALUES: Final[tuple[core.TransitionKernel, ...]] = (
    _ReleaseReceiptKernel(
        operation="release.reserve",
        handler="reserve_release_authorization_v2",
        query_builder=_reserve_queries,
    ),
    _ReleaseReceiptKernel(
        operation="release.v1.reserve",
        handler="reserve_release_authorization",
        query_builder=_reserve_queries,
    ),
    _ReleaseReceiptKernel(
        operation="release.dispatch",
        handler="dispatch_release_authorization_v2",
        query_builder=_lifecycle_query_builder,
    ),
    _ReleaseReceiptKernel(
        operation="release.v1.dispatch",
        handler="dispatch_release_authorization",
        query_builder=_lifecycle_query_builder,
    ),
    _ReleaseReceiptKernel(
        operation="release.complete",
        handler="complete_release_authorization_v2",
        query_builder=_lifecycle_query_builder,
    ),
    _ReleaseReceiptKernel(
        operation="release.v1.complete",
        handler="complete_release_authorization",
        query_builder=_lifecycle_query_builder,
    ),
    _ReleaseReceiptKernel(
        operation="release.cancel",
        handler="cancel_release_authorization_if_present",
        query_builder=_lifecycle_query_builder,
    ),
    _ReleaseReceiptKernel(
        operation="release.reconcile",
        handler="reconcile_release_authorizations",
        query_builder=_lifecycle_query_builder,
    ),
    _ReleaseReceiptKernel(
        operation="release.credential-claim",
        handler="claim_release_credential_issuance",
        query_builder=_lifecycle_query_builder,
    ),
    _ReleaseReceiptKernel(
        operation="release.audit-drain",
        handler="drain_release_authorization_audit_outbox",
        query_builder=_audit_queries,
        permits_empty_mutation=True,
    ),
    _CredentialNonceReserveKernel(),
)
KERNELS: Final[
    Mapping[str, core.TransitionKernel]
] = MappingProxyType(
    {kernel.operation: kernel for kernel in _KERNEL_VALUES}
)


if set(KERNELS) != RELEASE_TRANSITION_OPERATIONS:
    raise RuntimeError("release transition coverage is not closed")
