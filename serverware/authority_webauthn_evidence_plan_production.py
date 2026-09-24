"""Produce an original signed plan from actual evidence-admission acquisition.

The exact acquisition class is only an ordinary carrier, never proof authority.
The fixed plan producer independently replays all memberships, query bindings,
original-input semantics and primary effects before its actual signature. Its
expectations and signing/key provenance remain independently admitted inputs.

This adapter captures every mutable field it uses before codecs or key/native
callbacks. It preserves the original input bytes and spends only the caller's
remaining work and holds the configured producer's mandatory live clock window
through actual signing and final encoding. No SQL, persistence, operation
activation or replacement allowance is introduced. The real acquisition/planner import gate
is retained lazily, not replaced by an accepted result or registry placeholder.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_webauthn_evidence_plan as plan


contract, evidence = plan.contract, plan.evidence


class WebAuthnEvidencePlanProductionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ProducedEvidencePlan:
    """Exact immutable originals, not custody or execution authority."""

    envelope_bytes: bytes
    inputs_bytes: bytes


def _list(values, maximum, work):
    if type(values) is not tuple or len(values) > maximum:
        raise WebAuthnEvidencePlanProductionError("evidence acquisition inventory is not an exact bounded tuple")
    work.prepare_copy(values)
    return list(values)


def _roots(values, tables):
    """Admit fixed scalar projection bounds, not root provenance or membership."""
    if type(values) is not tuple or len(values) != len(tables):
        raise WebAuthnEvidencePlanProductionError("evidence acquisition after-root inventory changed")
    for root, table in zip(values, tables):
        if type(root) is not plan.proofs.primary.PrimaryRoot:
            raise WebAuthnEvidencePlanProductionError("evidence acquisition root is not an actual primary root")
        contract.shape._literal(root.table, table)
        contract.shape._digest(root.root_digest)
        contract.shape._integer(root.root_revision)
        contract.shape._integer(root.leaf_count)


def _produce_from_acquisition_on_work(acquisition, *, expectations,
        planner_private_key, planner_public_key, evidence_public_key, live_window, work):
    """Replay actual raw acquisition data before returning signed originals."""
    ledger = evidence.capture._SharedLedger(work)
    live_window = plan.clock._validate(live_window)
    # This imports the genuine planner/registry boundary. An unavailable
    # registered program remains a real failure, not a synthetic success.
    from serverware import authority_webauthn_evidence_acquisition as acquired

    if type(acquisition) is not acquired._EvidenceAdmissionAcquisition:
        raise WebAuthnEvidencePlanProductionError("evidence production needs the exact acquisition carrier")
    # Hold every field used below once, before any codec or native callback.
    request, selected = acquisition.request, acquisition.selected_rows
    state, kernel = acquisition.state, acquisition.kernel
    mutations, total_work = acquisition.mutations, acquisition.work_units
    write = acquisition.write_evidence
    business_before, authorization_before = acquisition.business_before_roots, acquisition.authorization_before_roots
    before_proofs = acquisition.before_proofs
    inputs_bytes, inputs_digest = acquisition.original_inputs_bytes, acquisition.original_inputs_digest
    if (type(state) is not acquired.planner.PlanningState
            or type(kernel) is not evidence.plan.core.KernelTransition
            or type(write) is not acquired.planner.authority_index_mutation_reader.AcquiredIndexedMutation):
        raise WebAuthnEvidencePlanProductionError("evidence acquisition state or proof carrier changed")
    database_now, query_reads = state.database_now, state.query_reads
    kernel_mutations, kernel_result, kernel_work = kernel.mutations, kernel.result, kernel.work_units
    written, index_inputs, read_metrics = write.result, write.index_inputs, write.metrics
    if (type(written) is not plan.proofs.indexed.IndexedMutationResult
            or type(read_metrics) is not acquired.planner.authority_index_mutation_reader.IndexMutationReadMetrics):
        raise WebAuthnEvidencePlanProductionError("evidence acquisition write result changed")
    primary_result, before_heads, after_heads, write_metrics = (
        written.primary, written.before_heads, written.after_heads, written.metrics)
    if (type(primary_result) is not plan.proofs.primary.PrimaryRadixBatchResult
            or type(write_metrics) is not plan.proofs.indexed.IndexedMutationMetrics
            or any(type(values) is not tuple or values for values in
                (index_inputs, before_heads, after_heads, write_metrics.indexes))):
        raise WebAuthnEvidencePlanProductionError("evidence plan cannot contain counted-index evidence")
    for field in ("sql_reads", "leaf_reads", "node_reads", "requested_targets",
            "requested_siblings", "returned_rows", "parameter_bytes", "transport_bytes"):
        value = getattr(read_metrics, field)
        if type(value) is not int or value != 0:
            raise WebAuthnEvidencePlanProductionError("evidence acquisition contains counted-index SQL observations")
    business_after, authorization_after = (
        primary_result.business_after_roots, primary_result.authorization_after_roots)
    if (type(request) is not dict or type(request.get("operation")) is not str
            or request["operation"] not in contract.OPERATIONS):
        raise WebAuthnEvidencePlanProductionError("evidence acquisition operation is not source fixed")
    operation = request["operation"]
    spec = contract._SPECS[operation]
    contract.shape._object(expectations, plan._EXPECTATION_FIELDS, "evidence production expectations")
    plan.inputs_wire._raw(inputs_bytes, 2, plan.inputs_wire.MAX_BYTES)
    cutoff_us = plan.inputs_wire._to_epoch_us(database_now)
    _roots(business_after, contract._BUSINESS_TABLES[operation])
    _roots(authorization_after, contract._AUTHORIZATION_TABLES[operation])
    maximum = spec["maximumBusinessQueryRows"]
    owned = evidence.capture._JSONCapture(ledger).visit({
        "request": request, "selectedRows": _list(selected, maximum, work),
        "beforeProofs": _list(before_proofs, maximum, work),
        "businessBeforeRoots": _list(business_before, len(contract._BUSINESS_TABLES[operation]), work),
        "authorizationBeforeRoots": _list(authorization_before, len(contract._AUTHORIZATION_TABLES[operation]), work),
        "mutations": _list(kernel_mutations, spec["maximumBusinessMutations"], work),
        "acquisitionMutations": _list(mutations, spec["maximumBusinessMutations"], work),
        "result": kernel_result, "kernelWorkUnits": kernel_work, "workUnits": total_work,
        "inputsDigest": inputs_digest, "databaseCutoffUs": cutoff_us, "expectations": expectations})
    evidence.plan._same(owned["acquisitionMutations"], owned["mutations"], work,
        "evidence acquisition and kernel mutation views differ")
    expected = owned["expectations"]
    for field in ("nowEpochNs", "deadlineEpochNs"):
        contract.shape._integer(expected[field], minimum=1)
    contract.shape._integer(expected["maximumPlanAgeNs"], evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    issued = expected["nowEpochNs"]
    expires = min(expected["deadlineEpochNs"], issued + expected["maximumPlanAgeNs"])
    payload = {"schema": contract.PLAN_SCHEMA, "sourceRevision": evidence.authority.SOURCE_REVISION,
        "protocol": contract.PROTOCOL, "operation": operation,
        "operationManifestDigest": evidence.authority.OPERATION_MANIFEST_DIGEST,
        "queryManifestDigest": contract.QUERY_MANIFEST_DIGEST,
        "authorizationManifestDigest": contract.AUTHORIZATION_MANIFEST_DIGEST,
        "handlerContractDigest": contract.HANDLER_DIGESTS[operation],
        "configurationDigest": expected["configurationDigest"],
        "plannerIdentity": expected["plannerIdentity"], "plannerSpkiDigest": expected["plannerSpkiDigest"],
        "request": owned["request"], "databaseCutoffUs": owned["databaseCutoffUs"],
        "inputsDigest": owned["inputsDigest"], "businessBeforeRoots": owned["businessBeforeRoots"],
        "authorizationBeforeRoots": owned["authorizationBeforeRoots"],
        "businessAfterRoots": plan._root_documents(business_after, work),
        "authorizationAfterRoots": plan._root_documents(authorization_after, work),
        "selectedRows": owned["selectedRows"], "beforeProofs": owned["beforeProofs"],
        "queryReads": plan.reads_wire._encode_reads_on_work(query_reads, maximum_rows=maximum, work=work),
        "transition": {"mutations": owned["mutations"], "result": owned["result"],
            "kernelWorkUnits": owned["kernelWorkUnits"], "workUnits": owned["workUnits"]},
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    contract.validate_payload_shape(payload)
    original = plan._produce_on_work(payload=payload, inputs_bytes=inputs_bytes,
        expectations=expected, planner_private_key=planner_private_key,
        planner_public_key=planner_public_key, evidence_public_key=evidence_public_key,
        live_window=live_window, work=work)
    return _ProducedEvidencePlan(original, inputs_bytes)
