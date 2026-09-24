"""Private registry-free construction of the existing revocation v4 envelope.

The coordinator must jointly own every raw graph and genuinely acquire the
request/receipt/effects/proofs before calling this helper. No public API accepts
a successful-result token. This builder does not establish key enrollment,
current-root/time provenance, transaction isolation or permission to persist.
It reuses actual v4 commitments, and reserves exact output encodings plus
bounded signature transport on the original work object before signing.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_complete_query_batch as batch
from serverware import authority_contract
from serverware import authority_revocation_plan as plan
from serverware import authority_revocation_plan_contract as contract
from serverware import authority_transition_core as core
from serverware.authority_query_read_work import QueryReadValidationMetrics, QueryReadWorkError, _ValidationWork


_CONTEXT_FIELDS = frozenset({
    "expectedPlannerIdentity", "expectedVerifierIdentity", "expectedCapabilityId",
    "expectedPlannerTransactionId", "expectedFence", "reservedAtEpochNs",
    "deadlineEpochNs", "deadlineMonotonicNs", "nowEpochNs", "nowMonotonicNs",
    "maximumAssertionAgeNs", "maximumPlanAgeNs", "maximumClockSkewNs",
    "expectedBefore", "expectedApproverPolicyDigest",
})
_SIGNATURE_PLACEHOLDER = "A" * 86
# Exact signature64 output, encoder input64, padded base64 output88,
# URL translation88, ASCII decode88, rstrip88 and final alphabet scan86.
_SIGNATURE_TRANSPORT_BYTES = 2 * 64 + 4 * 88 + 86


@dataclass(frozen=True, slots=True)
class _ProducedPlan:
    """Owned raw/wire observations, freely constructible and never authority."""

    payload: dict
    envelope: dict
    payload_bytes: bytes
    envelope_bytes: bytes
    metrics: QueryReadValidationMetrics
    signing_attempts: int
    signature_verifications: int


def _validate_context(context, work):
    """Check the closed independent context before SQL; never mint authority."""
    batch._SharedLedger(work)  # Validate exact existing work/counters; no allowance.
    contract._object(context, _CONTEXT_FIELDS, "production context")
    plan._expectation_context(context)
    plan.semantics._expected_before(context["expectedBefore"])


def _list(values, maximum, work):
    if type(values) not in (tuple, list) or len(values) > maximum:
        raise plan.RevocationPlanError("revocation production inventory is not a bounded owned sequence")
    work.prepare_copy(values)
    return list(values)


def _sign_and_verify(private_key, public_key, message):
    """One real signing attempt followed by the independently pinned verifier."""
    signature = private_key.sign(message)
    if type(signature) is not bytes or len(signature) != 64:
        raise plan.RevocationPlanError("revocation production signer returned a noncanonical signature")
    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise plan.RevocationPlanError("revocation production signing key differs from its pinned public key") from exc
    return signature


def _build_and_sign(
    *, request, selected_rows, mutations, before_proofs, trace, evidence, result,
    work_units, bundle, transition, transition_digest, context,
    planner_private_key, planner_public_key, work: _ValidationWork,
) -> _ProducedPlan:
    """Build from this invocation's owned raw data, never a caller success DTO.

    The transition digest and corresponding raw graphs come together from
    genuine local proof packaging. This is not a second semantic/proof worker.
    Failure aborts the coordinator: reserved/spent work is never refunded.
    Metrics exclude fixed schema scaffolding and cryptographic implementation
    CPU, and report one sign plus one paired-key verification on success.
    """
    _validate_context(context, work)
    if (not isinstance(planner_private_key, Ed25519PrivateKey)
            or not isinstance(planner_public_key, Ed25519PublicKey)):
        raise plan.RevocationPlanError("revocation production requires actual Ed25519 keys")
    before = work.metrics
    entering_limits = work.limits
    limit_values = (entering_limits.max_hashes, entering_limits.max_input_bytes,
                    entering_limits.max_json_nodes)
    ledger = batch._SharedLedger(work)
    contract._request(request)
    contract._evidence(evidence)
    contract.retained.validate_bundle_shape(bundle)
    contract.retained.validate_transition_shape(transition)
    contract._digest(transition_digest)
    contract._integer(work_units, contract.MAX_WORK_UNITS, minimum=1)
    inputs, expected_before = bundle["inputs"], context["expectedBefore"]
    for supplied, proved in (
        (selected_rows, inputs["selectedRows"]), (mutations, inputs["mutations"]),
        (before_proofs, inputs["beforeProofs"]),
        (expected_before["businessBeforeRoots"], inputs["businessBeforeRoots"]),
        (expected_before["authorizationBeforeRoots"], inputs["authorizationBeforeRoots"]),
        (expected_before["indexBeforeHeads"], inputs["countedBeforeHeads"]),
        (request["requestDigest"], inputs["requestDigest"]),
        (request["requestDigest"], transition["requestDigest"]),
    ):
        plan._same(supplied, proved, work, "revocation production raw views diverged")
    transaction = plan._frame("serverware.policyAuthorityPlannerTransaction/v1",
        tuple(plan._ascii(value, work) for value in (request["operationId"],
            request["requestDigest"], context["expectedCapabilityId"])), work)
    plan._same(transaction, context["expectedPlannerTransactionId"], work,
               "revocation production differs from the independent reservation")
    measured = {
        "schema": contract.MEASURED_PLAN_SCHEMA, "plannerTransactionId": transaction,
        "operation": contract.OPERATION, "operationId": request["operationId"],
        "requestDigest": request["requestDigest"], "capabilityId": context["expectedCapabilityId"],
        "sourceRevision": authority_contract.SOURCE_REVISION,
        "authoritySchemaVersion": authority_contract.SCHEMA_VERSION,
        "operationContractDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
        "handlerContractDigest": plan._HANDLER_DIGEST, "queryManifestDigest": plan._QUERY_MANIFEST_DIGEST,
        "workUnits": work_units, "rootTransitionDigest": transition_digest,
        "deadlineMonotonicNs": context["deadlineMonotonicNs"],
        "deadlineEpochNs": context["deadlineEpochNs"], "fence": context["expectedFence"],
    }
    authorization = {
        **{name: measured[name] for name in ("plannerTransactionId", "operation", "operationId",
                                            "requestDigest", "capabilityId")},
        "authorizationReads": list(plan._SPEC["authorizationReads"]),
        "sourceRows": plan._authorization_sources(selected_rows, work),
        "sourceHighWaterDigest": plan._json_digest("serverware.policyAuthorityAuthorizationRootSet/v1",
            expected_before["authorizationBeforeRoots"], ledger),
        "approverPolicyDigest": context["expectedApproverPolicyDigest"],
        "assertionEvidenceDigest": plan._json_digest("serverware.policyAuthorityWebAuthnAssertionEvidence/v1",
            evidence, ledger),
        "verifierSessionIdentityDigest": context["expectedVerifierIdentity"]["sessionIdentityDigest"],
        "verifierMeasurementDigest": context["expectedVerifierIdentity"]["measurementDigest"],
        "verifierAttestationReceiptDigest": context["expectedVerifierIdentity"]["attestationReceiptDigest"],
        "createdAtEpochNs": context["reservedAtEpochNs"], "expiresAtEpochNs": context["deadlineEpochNs"],
    }
    payload = {
        "schema": contract.PLANNER_RESPONSE_SCHEMA, "measuredPlan": measured, "typedRequest": request,
        "selectedBusinessRows": _list(selected_rows, contract.MAX_SELECTED_ROWS, work),
        "mutationPlan": _list(mutations, contract.MAX_MUTATIONS, work),
        "queryMultiproofs": _list(before_proofs, contract.MAX_SELECTED_ROWS, work),
        "plannerTrace": {"schema": contract.PLANNER_TRACE_SCHEMA, "operation": contract.OPERATION,
                         "entries": _list(trace, contract.MAX_TRACE_ENTRIES, work)},
        "authorizationProjection": authorization, "webauthnEvidence": evidence,
        "expectedResult": result, "plannerIdentity": context["expectedPlannerIdentity"],
        "rootTransition": transition, "revocationProofBundle": bundle,
    }
    for destination, field, domain, graph in (
        (measured, "selectedBusinessRowsDigest", "serverware.policyAuthoritySelectedBusinessRows/v1", payload["selectedBusinessRows"]),
        (measured, "mutationPlanDigest", "serverware.policyAuthorityMutationPlan/v3", payload["mutationPlan"]),
        (measured, "authorizationProjectionDigest", "serverware.policyAuthorityAuthorizationProjection/v1", authorization),
        (measured, "authorityRootSetBeforeDigest", "serverware.policyAuthorityRootSet/v1", expected_before["businessBeforeRoots"]),
        (payload, "queryMultiproofsDigest", "serverware.policyAuthorityRadixMultiproofSet/v3", payload["queryMultiproofs"]),
        (payload, "plannerTraceDigest", contract.PLANNER_TRACE_SCHEMA, payload["plannerTrace"]),
        (payload, "expectedResultDigest", "serverware.policyAuthorityControlledWriterResult/v2", result),
    ):
        destination[field] = plan._json_digest(domain, graph, ledger)
    measured["authoritySnapshotDigest"] = plan._frame(contract.SNAPSHOT_DOMAIN,
        tuple(plan._ascii(measured[name], work) for name in contract.SNAPSHOT_FRAME_FIELDS), work)
    contract.validate_payload_shape(payload)

    # Measure both complete buffers before either encoder or the signer. The
    # literal placeholder has exactly the real signature's ASCII JSON size;
    # it is never signed, returned, or used as a claimed verification result.
    envelope = {"schema": contract.SIGNED_MEASURED_PLAN_SCHEMA, "payload": payload,
                "signatureBase64Url": _SIGNATURE_PLACEHOLDER}
    payload_size, payload_nodes = work.measure(payload)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(payload_size, envelope_size) > contract.MAX_PAYLOAD_BYTES
            or max(payload_nodes, envelope_nodes) > contract.MAX_JSON_NODES):
        raise plan.RevocationPlanError("revocation production transport exceeds its closed bound")
    # Also reserve a second payload encoder and both comparison scans. The
    # actual post-key-callback measurement uses remaining capacity checked
    # below, so even same-length mutation of a reachable private graph denies.
    work.charge(input_bytes=4 * payload_size + envelope_size + _SIGNATURE_TRANSPORT_BYTES,
                json_nodes=2 * payload_nodes + envelope_nodes)
    # Existing _frame/_ascii below perform their real debits. Check their exact
    # pending units before allocating either final wire buffer, not a fresh
    # allowance or a refund of the already spent measurement/encoding reserve.
    frame_bytes = 2 * len(contract.SIGNED_MEASURED_PLAN_SCHEMA) + 9 + payload_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + payload_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + payload_nodes):
        raise QueryReadWorkError("revocation production cannot reserve its actual signature message")
    payload_wire = core.canonical_bytes(payload)
    if len(payload_wire) != payload_size:
        raise plan.RevocationPlanError("revocation production payload changed after measurement")
    message = plan._ascii(plan._frame(contract.SIGNED_MEASURED_PLAN_SCHEMA, (payload_wire,), work), work)
    signing_metrics = work.metrics
    if (work.limits is not entering_limits
            or (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes) != limit_values):
        raise plan.RevocationPlanError("revocation production work limits changed before signing")
    signature = _sign_and_verify(planner_private_key, planner_public_key, message)
    batch._SharedLedger(work)  # Recheck exact scalar types, not int/float equality aliases.
    if (work.limits is not entering_limits or work.metrics != signing_metrics
            or (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes) != limit_values):
        raise plan.RevocationPlanError("revocation production work changed during signing")
    current_size, current_nodes = work.measure(payload)
    if (current_size, current_nodes) != (payload_size, payload_nodes):
        raise plan.RevocationPlanError("revocation production payload changed during signing")
    current_wire = core.canonical_bytes(payload)
    if current_wire != payload_wire:
        raise plan.RevocationPlanError("revocation production payload changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    contract._base64url(encoded, signature=True)
    envelope["signatureBase64Url"] = encoded
    envelope_wire = core.canonical_bytes(envelope)
    if len(envelope_wire) != envelope_size:
        raise plan.RevocationPlanError("revocation production envelope changed after measurement")
    return _ProducedPlan(payload, envelope, payload_wire, envelope_wire,
        plan.mixed._delta(before, work.metrics), 1, 1)
