"""Retain actual acquisition proofs and replay them from canonical originals.

An exact acquisition class is an ordinary carrier, not trusted proof success.
The retained-proof path genuinely replays its bytes against held request/root/
head/policy expectations before return. A separate encoding-only seam supplies
unverified originals to the signed producer, which performs its own mandatory
replay. Their cutoff is an actual acquisition observation; independent history,
signatures and durable custody remain outside this module. No trace or
successful-result object substitutes for raw primary proofs, counted query
frontiers or indexed write frontiers.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_radix_mutation as primary
from serverware import authority_webauthn_transition_proof as proof


contract, evidence, wire = proof.contract, proof.evidence, proof.wire


class WebAuthnTransitionProofProductionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _EncodedTransitionProof:
    """Unverified originals and owned expectations, never a proof-success token."""

    proof_bytes: bytes
    expectations: dict


def _list(values, maximum, work):
    if type(values) is not tuple or len(values) > maximum:
        raise WebAuthnTransitionProofProductionError("acquisition proof inventory is not an exact bounded tuple")
    work.prepare_copy(values)
    return list(values)


def _expected_array(values, maximum, work):
    if type(values) not in (tuple, list) or len(values) > maximum:
        raise WebAuthnTransitionProofProductionError("independent proof roots are not a bounded array")
    work.prepare_copy(values)
    return list(values)


def _encode_from_acquisition_on_work(*, acquisition, inputs_bytes, inputs_digest, request,
        business_before_roots, authorization_before_roots, counted_before_heads, policy, work):
    """Encode ordinary acquisition claims; callers must genuinely replay them.

    This private seam lets a signed producer perform its own mandatory raw
    replay once, without mistaking an acquisition or retained carrier for
    proof authority. Merely receiving these bytes establishes no validity.
    """
    ledger = evidence.capture._SharedLedger(work)
    wire._raw(inputs_bytes, 2, wire.MAX_BYTES)
    # The actual planner remains a lazy import, with its genuine source closure.
    from serverware import authority_planner as planner

    types = {
        planner.authority_transition_webauthn_registration.OPERATION: planner._RegistrationAcquisition,
        planner.authority_transition_webauthn_trust_stage.OPERATION: planner._TrustStageAcquisition,
        planner.authority_transition_webauthn_completion.OPERATION: planner._TrustCompletionAcquisition,
    }
    if type(request) is not dict or type(request.get("operation")) is not str:
        raise WebAuthnTransitionProofProductionError("proof production requires a held typed request")
    operation = request["operation"]
    if operation not in types or type(acquisition) is not types[operation]:
        raise WebAuthnTransitionProofProductionError("proof production requires its actual operation acquisition")
    actual_request, selected = acquisition.request, acquisition.selected_rows
    state, kernel, mutations = acquisition.state, acquisition.kernel, acquisition.mutations
    total_work, write = acquisition.work_units, acquisition.write_evidence
    if (type(state) is not planner.PlanningState or type(kernel) is not proof.inputs.core.KernelTransition
            or type(write) is not planner.authority_index_mutation_reader.AcquiredIndexedMutation):
        raise WebAuthnTransitionProofProductionError("proof acquisition state or write carrier changed")
    cutoff, records, complete = state.database_now, state.query_reads, state.complete_query_evidence
    kernel_result, kernel_work = kernel.result, kernel.work_units
    written, index_inputs = write.result, write.index_inputs
    if type(written) is not planner.authority_indexed_mutation.IndexedMutationResult:
        raise WebAuthnTransitionProofProductionError("acquisition indexed output type changed")
    primary_result, actual_after_heads = written.primary, written.after_heads
    if type(primary_result) is not primary.PrimaryRadixBatchResult:
        raise WebAuthnTransitionProofProductionError("acquisition primary output type changed")
    business_after, authorization_after = primary_result.business_after_roots, primary_result.authorization_after_roots
    if operation == proof.completion.OPERATION:
        if complete is not None:
            raise WebAuthnTransitionProofProductionError("completion cannot retain complete-query evidence")
        business, authorization = acquisition.business_before_roots, acquisition.authorization_before_roots
        before_proofs, heads = acquisition.before_proofs, acquisition.counted_before_heads
        frontiers = ()
    else:
        if type(complete) is not planner.authority_complete_acquisition.CompleteAcquisitionEvidence:
            raise WebAuthnTransitionProofProductionError("complete transition requires its actual retained raw evidence")
        business, authorization = complete.business_before_roots, complete.authorization_before_roots
        before_proofs, heads, frontiers = complete.before_proofs, complete.heads, complete.frontiers
        if complete.cutoff_us != wire._to_epoch_us(cutoff):
            raise WebAuthnTransitionProofProductionError("acquisition complete and database cutoffs differ")
    spec = contract.SPECS[operation]
    if (type(heads) is not tuple or not 1 <= len(heads) <= planner.authority_index_heads.MAX_HEADS
            or any(type(head) is not planner.authority_index_heads.CapturedIndexHead for head in heads)
            or type(actual_after_heads) is not tuple or len(actual_after_heads) > len(heads)
            or any(type(head) is not planner.authority_indexed_mutation.IndexedMutationHead
                for head in actual_after_heads)):
        raise WebAuthnTransitionProofProductionError("acquisition counted head inventory changed")
    for roots, tables in ((business_after, contract.BUSINESS_TABLES[operation]),
            (authorization_after, contract.AUTHORIZATION_TABLES[operation])):
        if (type(roots) is not tuple or len(roots) != len(tables)
                or any(type(root) is not primary.PrimaryRoot
                    or root.table != table for root, table in zip(roots, tables))):
            raise WebAuthnTransitionProofProductionError("acquisition primary after-root inventory changed")
    before_heads_json = proof._head_documents(heads, work)
    after_heads_json = proof._head_documents(actual_after_heads, work)
    # All mutable acquisition/request/policy/root graphs are detached before
    # query-record codecs or genuine proof/native/key callbacks. Actual typed
    # frontier and QueryRead originals are held separately and copied by their
    # fixed source codecs before replay starts.
    owned = evidence.capture._JSONCapture(ledger).visit({"request": actual_request,
        "selectedRows": _list(selected, spec["maximumQueryRows"], work),
        "beforeProofs": _list(before_proofs, spec["maximumQueryRows"], work),
        "businessBeforeRoots": _list(business, len(contract.BUSINESS_TABLES[operation]), work),
        "authorizationBeforeRoots": _list(authorization, len(contract.AUTHORIZATION_TABLES[operation]), work),
        "countedBeforeHeads": before_heads_json, "writtenAfterHeads": after_heads_json,
        "businessAfterRoots": proof._root_documents(business_after, work),
        "authorizationAfterRoots": proof._root_documents(authorization_after, work),
        "transition": {"mutations": _list(mutations, spec["maximumMutations"], work),
            "result": kernel_result, "kernelWorkUnits": kernel_work, "workUnits": total_work},
        "inputsDigest": inputs_digest, "databaseCutoffUs": wire._to_epoch_us(cutoff),
        "expectations": {"request": request, "inputsDigest": inputs_digest,
            "databaseCutoffUs": wire._to_epoch_us(cutoff),
            "businessBeforeRoots": _expected_array(business_before_roots, len(contract.BUSINESS_TABLES[operation]), work),
            "authorizationBeforeRoots": _expected_array(authorization_before_roots, len(contract.AUTHORIZATION_TABLES[operation]), work),
            "countedBeforeHeads": _expected_array(counted_before_heads, planner.authority_index_heads.MAX_HEADS, work),
            "policy": policy}})
    before_ids = tuple(head["indexId"] for head in owned["countedBeforeHeads"])
    after_ids = tuple(head["indexId"] for head in owned["writtenAfterHeads"])
    if (len(set(before_ids)) != len(before_ids) or len(set(after_ids)) != len(after_ids)
            or set(after_ids) - set(before_ids)):
        raise WebAuthnTransitionProofProductionError("acquisition changed an uncaptured counted head")
    # Unused potential heads are retained unchanged. Genuine write replay will
    # independently determine the exact used subset and compare every result.
    after_map = {head["indexId"]: head for head in owned["countedBeforeHeads"]}
    after_map.update({head["indexId"]: head for head in owned["writtenAfterHeads"]})
    work.prepare_copy(owned["countedBeforeHeads"])
    counted_after = [after_map[index_id] for index_id in before_ids]
    document = {"schema": contract.SCHEMA, "sourceRevision": proof.inputs.authority.SOURCE_REVISION,
        "operation": operation, "operationManifestDigest": proof.inputs.authority.OPERATION_MANIFEST_DIGEST,
        "queryManifestDigest": contract.QUERY_MANIFEST_DIGEST,
        "authorizationManifestDigest": contract.AUTHORIZATION_MANIFEST_DIGEST,
        "handlerContractDigest": contract.HANDLER_DIGESTS[operation],
        "request": owned["request"], "inputsDigest": owned["inputsDigest"],
        "databaseCutoffUs": owned["databaseCutoffUs"],
        "businessBeforeRoots": owned["businessBeforeRoots"],
        "authorizationBeforeRoots": owned["authorizationBeforeRoots"],
        "selectedRows": owned["selectedRows"], "beforeProofs": owned["beforeProofs"],
        "queryReads": proof.proof_wire._encode_reads_on_work(records, operation=operation, work=work),
        "countedBeforeHeads": owned["countedBeforeHeads"],
        "queryFrontiers": proof.proof_wire._encode_query_frontiers_on_work(frontiers,
            operation=operation, arguments=owned["request"]["arguments"], work=work),
        "writeFrontiers": proof.proof_wire._encode_write_frontiers_on_work(index_inputs, operation=operation, work=work),
        "transition": owned["transition"], "businessAfterRoots": owned["businessAfterRoots"],
        "authorizationAfterRoots": owned["authorizationAfterRoots"], "countedAfterHeads": counted_after}
    contract.validate_payload_shape(document)
    original = evidence.capability._wire(document, ledger, contract.MAX_BYTES, contract.MAX_NODES)
    return _EncodedTransitionProof(original, owned["expectations"])


def _package_from_acquisition_on_work(*, acquisition, inputs_bytes, inputs_digest, request,
        business_before_roots, authorization_before_roots, counted_before_heads, policy, public_key, work):
    """Retain unsigned originals only after genuine raw proof/semantic replay."""
    encoded = _encode_from_acquisition_on_work(acquisition=acquisition,
        inputs_bytes=inputs_bytes, inputs_digest=inputs_digest, request=request,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        counted_before_heads=counted_before_heads, policy=policy, work=work)
    replayed = proof._replay_on_work(proof_bytes=encoded.proof_bytes, inputs_bytes=inputs_bytes,
        expectations=encoded.expectations, public_key=public_key, work=work)
    return proof._RetainedProofAcquisition(acquisition, inputs_bytes, encoded.expectations["inputsDigest"],
        replayed.semantics, replayed.proof_bytes, replayed.proof_digest)
