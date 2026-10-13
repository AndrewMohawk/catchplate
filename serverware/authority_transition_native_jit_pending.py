"""Source-owned pending-review transition for the native release channel.

This branch only retains an already independently admitted encrypted pair and
creates its pending approval. It cannot reserve a release, consume a grant,
open a review, or authorize dispatch. Service and planner custody admission
precede it; parsing retained originals here is not a substitute for admission.
Committed execution-owner replay stays in the executor, before this fresh-only
transition. Retained rows are never interpreted as a reusable success token.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Mapping

from serverware import authority_contract as contract
from serverware import authority_jit_private_request as jit
from serverware import authority_native_jit_retention_contract as storage
from serverware import authority_native_jit_submission as submission
from serverware import authority_release_private_request as private
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as quota
from serverware import release_authorization_profiles as profiles

OPERATION = "release.reserve"
REFERENCE_PREFIX = "native-jit:v1:"
REFERENCE_SCHEMA = "serverware.nativeJitReviewReference/v1"
KINDS = ("approval-secret-json/v1", "approval-review-json/v1")
MAX_GRANT_CANDIDATES = 4


def _require(value: bool) -> None:
    if not value:
        raise core.TransitionKernelError("native JIT pending transition is unavailable")


def is_profile(arguments: Mapping[str, Any]) -> bool:
    """Recognize the public grammar, not admission or a request to enable it."""
    return isinstance(arguments, Mapping) and arguments.get("schema") == private.PUBLIC_SCHEMA


def _requests(arguments: Mapping[str, Any], request_digest: str):
    public = private.public_arguments(arguments, typed=True)
    _require(public["native_profile"] is True and public["policy_aware_profile"] is False
        and public["require_jit_grant"] is True and public["now_epoch_ms"] is None)
    for field in ("route_id", "credential_id"):
        core.require_text(public[field], "native JIT release identity", maximum_bytes=256,
            allow_empty=field == "credential_id")
    try:
        profiles.native_principal(public["principal_id"])
    except ValueError:
        raise core.TransitionKernelError("native JIT release principal is invalid") from None
    public.pop("businessIntent")
    parent = private._derive_request(OPERATION, public)
    _require(parent["requestDigest"] == request_digest)
    child = private._derive_request(jit.OPERATION, public["jit_approval_request"])
    normalized = jit.public_arguments(child["arguments"], typed=True,
        request_digest=child["requestDigest"])
    approval_id = core.deterministic_uuid(operation=jit.OPERATION,
        request_digest=child["requestDigest"], purpose="jit-approval-request")
    return parent, child, normalized, approval_id


def queries(*, arguments: Mapping[str, Any], database_now: datetime,
        request_digest: str) -> tuple[core.BoundedQuery, ...]:
    parent, _child, normalized, approval_id = _requests(arguments, request_digest)
    business = parent["arguments"]
    exact = lambda name, table, key: quota._query(
        operation=OPERATION, name="native_jit_" + name, table=table, key=key)
    predicates = tuple(core.QueryPredicate(field, "eq", business[field]) for field in (
        "principal_id", "route_id", "credential_id", "credential_version", "policy_hash", "request_digest"))
    # A currently live matching grant belongs to the normal release owner. This
    # branch never clears its reservation, consumes it, or creates a replacement.
    grants = core.BoundedQuery(
        query_id=core.query_program_id(OPERATION, "native_jit_grants", "approval_grants"),
        table="approval_grants", predicates=predicates + (
            core.QueryPredicate("state", "eq", "active"),
            core.QueryPredicate("uses_remaining", "gt", 0),
            core.QueryPredicate("expires_at", "gt", database_now.astimezone(timezone.utc).isoformat()),
            core.QueryPredicate("approver_policy_digest", "eq", normalized["approver_policy_digest"]),
        ), order_by=(core.QueryOrder("created_at"), core.QueryOrder("id")),
        maximum_rows=MAX_GRANT_CANDIDATES)
    return (
        exact("attempt", "release_authorization_attempts", {"attempt_id": business["attempt_id"]}),
        exact("approval", "approval_requests", {"id": approval_id}),
        exact("pair", storage.TABLE, {"approval_request_id": approval_id}),
        exact("route", "routes", {"id": normalized["route_id"]}),
        quota._aggregate_query(OPERATION, "native_jit_capacity", "jit-pending-approvals", "global"),
        quota._audit_query(OPERATION, request_digest),
        grants,
    )


def reference(*, approval_id: str, parent_digest: str, pair_digest: str, value_kind: str) -> str:
    """A bounded opaque locator, not a ciphertext, plaintext, or open capability."""
    _require(value_kind in KINDS)
    core.require_text(approval_id, "native JIT approval identity", maximum_bytes=36)
    core.require_digest(parent_digest, "native JIT parent")
    core.require_digest(pair_digest, "native JIT pair")
    value = {"schema": REFERENCE_SCHEMA, "approvalRequestId": approval_id,
        "parentRequestDigest": parent_digest, "pairSha256": pair_digest, "valueKind": value_kind}
    encoded = REFERENCE_PREFIX + core.canonical_bytes(value).decode("ascii")
    _require(len(encoded) <= 1024)
    return encoded


def _require_absent(context: core.KernelContext, table: str, key: Mapping[str, Any]):
    selected = context.exact(table, key)
    _require(selected.get("present") is False and selected.get("row") is None)
    return selected


def _durable(business: Mapping[str, Any]) -> dict[str, Any]:
    value = business["durable_policy_binding"]
    _require(isinstance(value, Mapping) and set(value) == {"actorId", "claimDigest", "claims"}
        and value["actorId"] == business["actor_id"])
    core.require_text(value["actorId"], "native JIT durable actor", maximum_bytes=256)
    core.require_digest(value["claimDigest"], "native JIT durable claim")
    claims = list(quota._policy_claims(value["claims"], policy_hash=business["policy_hash"]))
    for claim in claims:
        # Preserve the reserve facade's canonical business bounds, without
        # importing its database layer or treating claims as policy admission.
        if claim["type"] in {"slidingWindowLimit", "weightedBudget"}:
            definition = quota._budget_definition(claim)
            _require(all(claim[name] == item for name, item in definition.items() if name != "window_kind"))
            for field in ("units", "max_units"):
                core.require_integer(claim[field], "native JIT budget units",
                    minimum=0 if field == "units" else 1, maximum=9_007_199_254_740_991)
            if claim["type"] == "weightedBudget":
                _require(re.fullmatch(r"[a-z][a-z0-9._-]{0,31}:(?:requestValue|operationField):"
                    r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", claim["unit_field"]) is not None)
        else:
            identity = quota._traversal_identity(claim)
            _require(all(claim[name] == item for name, item in identity.items()))
            for field, maximum in (("max_pages", 10_000), ("max_records", 10_000_000),
                    ("max_bytes", 1_073_741_824), ("lifetime_seconds", 86_400)):
                core.require_integer(claim[field], "native JIT traversal bound", minimum=1, maximum=maximum)
            for field in ("request_cursor_field", "response_cursor_field", "record_count_field"):
                _require(re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", claim[field]) is not None)
    _require(value["claimDigest"] == private._sha(core.canonical_bytes(claims)))
    return {"actorId": value["actorId"], "claimDigest": value["claimDigest"], "claims": claims}


def _quotas(business: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Same bounded wire normalization as the existing reserve facade."""
    source = business["shared_quotas"]
    _require(type(source) is list and len(source) <= 12)
    values: dict[str, dict[str, Any]] = {}
    for item in source:
        _require(isinstance(item, Mapping))
        key = core.require_digest(item.get("counter_key"), "native JIT quota key")
        operation = item.get("operation")
        if operation is not None:
            core.require_text(operation, "native JIT quota operation", maximum_bytes=256)
        kind = item.get("window_kind")
        if kind is None and item.get("window_seconds") is not None:
            kind = "fixed"
        _require(kind in {"fixed", "utcDay", "utcIsoWeek", "utcMonth"})
        normalized = {"counter_key": key,
            "constraint_id": core.require_text(item.get("constraint_id"), "native JIT quota constraint", maximum_bytes=256),
            "operation": operation, "window_kind": kind,
            "max_count": core.require_integer(item.get("max_count"), "native JIT quota maximum",
                minimum=1, maximum=1_000_000_000)}
        if kind == "fixed":
            normalized["window_seconds"] = core.require_integer(item.get("window_seconds"),
                "native JIT quota window", minimum=1, maximum=31_536_000)
        _require(key not in values or values[key] == normalized)
        values[key] = normalized
    return [values[key] for key in sorted(values)]


def pending_binding_digest(*, business: Mapping[str, Any],
        normalized_child: Mapping[str, Any]) -> str:
    """Recompute the native wire binding; this conveys no transition authority."""
    durable = _durable(business)
    binding = {field: business[field] for field in (
        "attempt_id", "flow_id", "principal_id", "route_id", "credential_id", "credential_version",
        "policy_hash", "request_digest", "operation_digest", "operation_context", "require_jit_grant")}
    binding.update(api_version=profiles.NATIVE_BINDING_V2, durable_policy=durable,
        approver_policy=dict(normalized_child["approver_policy"]), shared_quotas=_quotas(business))
    encoded = core.canonical_bytes(binding)
    _require(len(encoded) <= 64 * 1024)
    return private._sha(encoded)


def pending_result(*, business: Mapping[str, Any], normalized_child: Mapping[str, Any],
        approval: Mapping[str, Any], audit_digest: str) -> dict[str, Any]:
    durable = _durable(business)
    return {
        "authorized": False, "state": "denied", "reason": "jit_grant_unavailable",
        "attempt_id": business["attempt_id"], "binding_digest": pending_binding_digest(
            business=business, normalized_child=normalized_child),
        "binding_api_version": profiles.NATIVE_BINDING_V2, "idempotent_replay": False,
        "grant_id": None, "approval_request_id": approval["id"],
        "approval_status": "pending", "approval_expires_at": approval["expires_at"], "approval_created": True,
        "approver_policy": dict(normalized_child["approver_policy"]),
        "approver_policy_digest": normalized_child["approver_policy_digest"],
        "reservation_expires_at_epoch_ms": None, "dispatch_started_at_epoch_ms": None,
        "dispatch_expires_at_epoch_ms": None, "completion_outcome": None, "retry_after_seconds": 3,
        "quotas": [], "release_authorization_store_backend": "postgres", "release_authorization_store_ha": True,
        "audit_event_digest": audit_digest,
        "durable_policy": {"state": "denied", "attempt_id": business["attempt_id"],
            "claim_digest": durable["claimDigest"], "reservation_id": None, "actor_id": durable["actorId"],
            "reservation_deadline_at_epoch_ms": None, "dispatch_deadline_at_epoch_ms": None,
            "response_evidence_digest": None, "failure_reason": None, "response_body_sha256": None, "uncertainty": None},
    }


def transition(context: core.KernelContext) -> core.KernelTransition:
    _require(context.operation == OPERATION)
    parent, child, normalized, approval_id = _requests(context.arguments, context.request_digest)
    retained = context.native_jit_pending
    try:
        _parent, _child, pair, proof = submission.retained_documents(retained, typed_request=parent)
    except submission.SubmissionError:
        raise core.TransitionKernelError("native JIT pending transition is unavailable") from None
    scope, statement = pair["scope"], proof["statement"]
    now_ns = core._epoch_nanoseconds(context.database_now)
    _require(scope["issuedAtEpochNs"] <= now_ns < scope["sealExpiresAtEpochNs"]
        <= scope["documentExpiresAtEpochNs"])
    business = parent["arguments"]
    # Presence is never an idempotency verdict. The executor returns its exact
    # earlier committed execution receipt; a new owner must not overwrite it.
    _require_absent(context, "release_authorization_attempts", {"attempt_id": business["attempt_id"]})
    approval_selected = _require_absent(context, "approval_requests", {"id": approval_id})
    pair_selected = _require_absent(context, storage.TABLE, {"approval_request_id": approval_id})
    _require_absent(context, "metadata_audit_outbox", {"id": quota._audit_identity(OPERATION, context.request_digest)})
    _require(not context.present_rows("approval_grants"))
    pair_digest = private._sha(retained["pairOriginal"].encode("ascii"))
    values = [{"ciphertext_base64url": reference(approval_id=approval_id,
        parent_digest=context.request_digest, pair_digest=pair_digest, value_kind=kind),
        "expires_at_epoch_ns": scope["documentExpiresAtEpochNs"]} for kind in KINDS]
    projection = quota.jit_pending_projection(normalized, approval_id=approval_id,
        canonical_value=values[0], display_value=values[1], database_now=context.database_now)
    row = dict(projection.row)
    pair_row = {"approval_request_id": approval_id,
        "parent_request_digest": parent["requestDigest"], "parent_operation_id": parent["operationId"],
        "child_request_digest": child["requestDigest"], "child_operation_id": child["operationId"],
        "parent_request_original": retained["parentOriginal"], "child_request_original": retained["childOriginal"],
        "pair_original": retained["pairOriginal"], "proof_original": retained["evidenceOriginal"],
        "pair_sha256": pair_digest, "proof_sha256": private._sha(retained["evidenceOriginal"].encode("ascii")),
        "source_contract_digest": statement["sourceContractDigest"],
        "control_plane_configuration_digest": statement["controlPlaneConfigurationDigest"],
        "owner_scope_digest": statement["ownerScopeDigest"], "secret_kek_id": pair["keyId"],
        "issued_at_epoch_ns": scope["issuedAtEpochNs"], "seal_expires_at_epoch_ns": scope["sealExpiresAtEpochNs"],
        "document_expires_at_epoch_ns": scope["documentExpiresAtEpochNs"],
        "recorded_at_epoch_ns": now_ns, "source_revision": contract.SOURCE_REVISION}
    _require(set(pair_row) == set(storage.COLUMNS))
    aggregate_id, partition = quota._aggregate_key("jit-pending-approvals", "global")
    aggregate = context.bounded_aggregate(aggregate_id=aggregate_id,
        aggregate_kind="jit-pending-approvals", partition_digest=partition)
    prior_expiry = aggregate["minimum_expiry_epoch_ns"]
    minimum_expiry = (projection.expiry_epoch_ns if prior_expiry is None
        else min(prior_expiry, projection.expiry_epoch_ns))
    mutations = [core.mutation(operation=OPERATION, selected=pair_selected, row=pair_row),
        core.mutation(operation=OPERATION, selected=approval_selected, row=row),
        quota._aggregate_update(context, kind="jit-pending-approvals", partition="global",
            live_delta=1, active_delta=1, next_sequence_delta=1,
            minimum_expiry_epoch_ns=minimum_expiry)]
    route_selected = context.exact("routes", {"id": normalized["route_id"]})
    if route_selected.get("present") is False:
        _require(route_selected.get("row") is None)
        mutations.append(core.mutation(operation=OPERATION, selected=route_selected, row={
            "id": normalized["route_id"], "name": "Policy bundle route " + normalized["route_id"],
            "enabled": 0, "match_host": "__policy_bundle__", "match_path_prefix": "/", "credential_id": None,
            "injection": "{}", "policies": "[]", "created_at": row["requested_at"], "updated_at": row["requested_at"]}))
    else:
        _require(route_selected.get("present") is True and isinstance(route_selected.get("row"), Mapping))
    audit_mutations, audit_digest, audit_replay = quota._audit_mutations(context,
        event_type="approval.requested", actor_type="proxy", actor_id=normalized["principal_id"], event={
            "schema": "serverware.jitApprovalRequested/v2", "approvalRequestId": approval_id,
            "routeId": normalized["route_id"], "principalId": normalized["principal_id"],
            "credentialId": normalized["credential_id"], "credentialVersion": normalized["credential_version"],
            "policyHash": normalized["policy_hash"], "requestDigest": normalized["request_digest"],
            "operationDigest": normalized["operation_digest"], "method": normalized["method"],
            "urlCommitment": normalized["url_commitment"], "expiresAt": row["expires_at"],
            "grantTtlSeconds": normalized["grant_ttl_seconds"], "grantMaxUses": normalized["grant_max_uses"],
            "approverPolicyDigest": normalized["approver_policy_digest"],
        })
    _require(not audit_replay and len(audit_mutations) == 1)
    mutations.extend(audit_mutations)
    # The framework alone appends the sixth, global audit-capacity mutation.
    _require(4 <= len(mutations) <= 5)
    return core.KernelTransition(mutations=tuple(mutations), result=pending_result(
        business=business, normalized_child=normalized, approval=row, audit_digest=audit_digest),
        work_units=64 + len(mutations))
