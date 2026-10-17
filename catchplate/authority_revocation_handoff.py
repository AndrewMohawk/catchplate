"""Authenticate the original planner cutoff, then genuinely replay raw custody.

The existing v4 payload signature covers both cutoff fields. A bounded private
bootstrap authenticates that measured-planner claim before using it as the
historical replay instant. It does not prove independent database-clock truth,
freshness, persistence or the planner's comparison of an unused counted head.
No new signed format, role grant, service route, clock or SQL is introduced.

Independent request/context and full reader observations are owned before key
callbacks. Authenticated mutation/query hints select source index identities;
every expected root VALUE comes from those independent observations. Genuine
retained replay must still establish the exact source union and actual effects.
No caller-provided successful observation is accepted in place of original
bytes. Success performs two actual planner signature verifications and one
genuine semantic/proof replay, all charged on the existing remaining work.
Fixed source inventories, UTC arithmetic and DTO scaffolding are not H/B/N.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_revocation_capability as capability
from catchplate import authority_revocation_observed as observed
from catchplate import authority_revocation_plan as plan
from catchplate import authority_revocation_retention as retention
from catchplate import authority_revocation_wire as wire
from catchplate.authority_query_read_work import QueryReadValidationMetrics, _ValidationWork


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class RevocationHandoffError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RevocationHandoffMetrics:
    capture: QueryReadValidationMetrics
    transport: QueryReadValidationMetrics
    authentication: QueryReadValidationMetrics
    bindings: QueryReadValidationMetrics
    projection: QueryReadValidationMetrics
    replay: QueryReadValidationMetrics
    planner_signature_attempts: int
    semantic_replays: int
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class _ObservedPlanHandoff:
    """Ordinary owned observations; no downstream API admits this as a token."""

    retained_record: retention._RetainedRevocationRecord
    database_now: datetime
    expected_context: dict
    metrics: RevocationHandoffMetrics


def _bind_independent(envelope, request, context, ledger):
    """Bind signed identities/reservation/source fields before cutoff use.

    Historical evaluation clocks and maximum-age/skew policy remain original
    caller inputs; the signed payload does not contain them all. The genuine
    retained worker later compares every original context field byte-for-byte.
    """
    work, payload = ledger.work, envelope["payload"]
    plan._expectations({"envelope": envelope, "expectedRequest": request, **context}, ledger)
    measured, authorization = payload["measuredPlan"], payload["authorizationProjection"]
    expected_source = {
        "operationContractDigest": plan.authority_contract.OPERATION_MANIFEST_DIGEST,
        "operationManifestDigest": plan.authority_contract.OPERATION_MANIFEST_DIGEST,
        "handlerContractDigest": plan._HANDLER_DIGEST,
        "queryManifestDigest": plan._QUERY_MANIFEST_DIGEST,
        "operationId": request["operationId"], "requestDigest": request["requestDigest"],
    }
    plan._same({name: measured[name] for name in expected_source}, expected_source, work,
        "planner handoff differs from independent request or source bindings")
    identity = context["expectedVerifierIdentity"]
    expected_authorization = {
        "verifierSessionIdentityDigest": identity["sessionIdentityDigest"],
        "verifierMeasurementDigest": identity["measurementDigest"],
        "verifierAttestationReceiptDigest": identity["attestationReceiptDigest"],
        "approverPolicyDigest": context["expectedApproverPolicyDigest"],
        "createdAtEpochNs": context["reservedAtEpochNs"],
        "expiresAtEpochNs": context["deadlineEpochNs"],
    }
    plan._same({name: authorization[name] for name in expected_authorization}, expected_authorization, work,
        "planner handoff differs from independent authorization bindings")


def _authenticated_cutoff(payload, work):
    """Use only an authenticated payload; integer UTC conversion samples no clock."""
    cutoff = payload["revocationProofBundle"]["inputs"]["cutoffUs"]
    transition_cutoff = payload["rootTransition"]["cutoffUs"]
    for value in (cutoff, transition_cutoff):
        if type(value) is not int or not -(2**63) <= value < 2**63:
            raise RevocationHandoffError("planner cutoff is not an exact signed int64")
    plan._same(cutoff, transition_cutoff, work, "authenticated planner cutoff fields disagree")
    instant = _EPOCH + timedelta(microseconds=cutoff)
    if plan.semantics.complete.cutoff_microseconds(instant) != cutoff:
        raise RevocationHandoffError("authenticated planner cutoff is not exact UTC")
    return instant


def _project_independent(context, inventory, payload, work):
    """Select IDs from bounded signed hints, never their claimed root values.

    This does NOT call the observed producer's full-acquisition comparator:
    an unused ninth head is absent from a smaller signed plan. Full role/query
    binding and mutation correctness remain mandatory genuine replay work.
    """
    roles = tuple(query["role"] for query in payload["revocationProofBundle"]["inputs"]["queries"])
    if len(roles) != len(observed.complete.ROLES) or set(roles) != set(observed.complete.ROLES):
        raise RevocationHandoffError("planner handoff query hints are not the exact six source roles")
    tables = tuple(mutation["table"] for mutation in payload["mutationPlan"])
    if any(table not in observed._MUTATION_TABLES for table in tables):
        raise RevocationHandoffError("planner handoff mutation hint is outside source write tables")
    selected = {observed.complete._role(observed.complete.OPERATION, role).index_id for role in roles}
    selected.update(identity for table in tables for identity in observed.projection.index_ids_for_table(table))
    full = observed._inventory_before(inventory)
    before = {"businessBeforeRoots": full["businessBeforeRoots"],
        "authorizationBeforeRoots": full["authorizationBeforeRoots"],
        "indexBeforeHeads": [row for row in full["indexBeforeHeads"] if row["indexId"] in selected]}
    projected = observed.reads._CopyBudget(work).copy({**context, "expectedBefore": before})
    retention.production._validate_context(projected, work)
    return projected


def _verify_observed_plan_handoff_on_work(*, envelope_bytes, evaluation_context_bytes,
        expected_request, context, root_inventory, planner_public_key, verifier_public_key,
        work: _ValidationWork) -> _ObservedPlanHandoff:
    """Authenticate cutoff origin and replay original bytes with independent roots.

    Caller context is exactly fourteen fields without expectedBefore. Neither
    stored context nor the authenticated plan supplies other external pins.
    Repeated planner authentication is deliberate and fully charged; there is
    no cheaper approved-observation path into the real retained verifier.
    """
    try:
        ledger = plan.capture._SharedLedger(work)
        if (not isinstance(planner_public_key, Ed25519PublicKey)
                or not isinstance(verifier_public_key, Ed25519PublicKey)
                or type(expected_request) is not dict or type(context) is not dict
                or type(envelope_bytes) is not bytes or not 2 <= len(envelope_bytes) <= plan.contract.MAX_PAYLOAD_BYTES
                or type(evaluation_context_bytes) is not bytes
                or not 2 <= len(evaluation_context_bytes) <= retention.MAX_CONTEXT_BYTES):
            raise RevocationHandoffError("planner handoff inputs are not exact bounded original data")
        before = work.metrics
        owned = observed.reads._CopyBudget(work).copy({"expectedRequest": expected_request, "context": context})
        inventory = observed._capture_root_inventory(root_inventory, work=work)
        request, independent = owned["expectedRequest"], owned["context"]
        observed._validate_partial_context(independent, work)
        plan.contract._request(request)
        captured = plan.mixed._delta(before, work.metrics)

        before = work.metrics
        envelope = wire._decode_envelope(envelope_bytes, work=work)
        plan.contract.validate_signed_envelope_shape(envelope)
        capability._canonical(envelope_bytes, envelope, ledger,
            plan.contract.MAX_PAYLOAD_BYTES, plan.contract.MAX_JSON_NODES)
        payload = envelope["payload"]
        payload_wire = capability._wire(payload, ledger, plan.contract.MAX_PAYLOAD_BYTES,
            plan.contract.MAX_JSON_NODES)
        transported = plan.mixed._delta(before, work.metrics)

        before = work.metrics
        capability._signature(planner_public_key, envelope["signatureBase64Url"],
            plan.contract.SIGNED_MEASURED_PLAN_SCHEMA, payload_wire, ledger)
        authenticated = plan.mixed._delta(before, work.metrics)

        before = work.metrics
        _bind_independent(envelope, request, independent, ledger)
        database_now = _authenticated_cutoff(payload, work)
        bound = plan.mixed._delta(before, work.metrics)

        before = work.metrics
        expected_context = _project_independent(independent, inventory, payload, work)
        projected = plan.mixed._delta(before, work.metrics)

        before = work.metrics
        expectations = {argument: expected_context[name] for name, argument in retention._CONTEXT_PAIRS}
        retained = retention._verify_record_on_work(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, expected_request=request,
            planner_public_key=planner_public_key, verifier_public_key=verifier_public_key,
            database_now=database_now, work=work, **expectations)
        replayed = plan.mixed._delta(before, work.metrics)
        return _ObservedPlanHandoff(retained, database_now, expected_context,
            RevocationHandoffMetrics(captured, transported, authenticated, bound, projected, replayed,
                2, 1, work.hash_work, work.input_bytes, work.json_nodes))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature,
            plan.core.TransitionKernelError) as exc:
        if isinstance(exc, RevocationHandoffError):
            raise
        raise RevocationHandoffError("observed planner handoff verification failed") from exc
