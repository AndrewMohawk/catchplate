"""Actual original-byte invalidation acquisition on a borrowed snapshot.

The native caller admits the real cursor, manifest, complete original roots,
database cutoff, request authority and claimed recovery witness. This component
opens no connection, samples no clock and supplies none of that admission.
Every physical row, primary-proof and sparse-write read spends the caller's
one existing acquisition/work pair. Target membership is proved before any
target-derived secondary query. Absent/inactive targets remain proved no-ops.

Only canonical raw proof bytes leave this call: no mutation/after-root DTO,
signature, witness verdict, registry activation or completed global trace.
The independent consumer must replay those bytes against its own context.
"""
from __future__ import annotations

from serverware import authority_index_mutation_reader as mutation_reader
from serverware import authority_index_reader as reader
from serverware import authority_primary_original_reader as physical
from serverware import authority_recovery_invalidation as proof
from serverware import authority_request_commitment as commitment
from serverware import authority_revocation_plan_contract as shape
from serverware.authority_index_contract import IndexLeaf, OpaqueSubtree
from serverware.authority_query_read_work import _ValidationWork


OPERATION = proof.OPERATION
_require, _own, _same = proof._require, proof._own, proof._same


def _request(value, work):
    shape._object(value, shape.TYPED_REQUEST_FIELDS, "invalidation typed request")
    _require(type(value["operation"]) is str and value["operation"] == OPERATION)
    for name in ("requestDigest", "operationId", "operationManifestDigest"):
        shape._digest(value[name])
    # The genuine shared commitment checks the source handler/manifest,
    # closed business intent and original typed arguments, not just shape.
    actual = commitment._typed_request_digest(value, work=work)
    _same(actual, value["requestDigest"], work)
    work.prepare_utf8(OPERATION)
    work.prepare_utf8(actual)
    work.charge(hashes=1, input_bytes=len("serverware.policyAuthorityOperation/v2") + 17)
    _same(commitment.operation_id(OPERATION, actual), value["operationId"], work)


def _root_objects(values, work):
    _require(type(values) is tuple and len(values) <= 5)
    for value in values:
        proof._object(value, proof._ROOT)
    work.charge(hashes=(proof.contract.TREE_DEPTH + 1) * len(values))
    return proof.batch._roots(values)


def _heads(cursor, *, expected, trace, work, acquisition):
    _require(type(expected) is tuple and len(expected) == 9)
    for value in expected:
        proof._object(value, proof._HEAD)
    _require(tuple(value["indexId"] for value in expected)
        == proof.heads._recovery_write_ids(OPERATION))
    actual = proof.heads.read_operation_index_heads(cursor, operation=OPERATION,
        trace=trace, work=work, acquisition=acquisition, include_write_heads=True)
    work.charge(json_nodes=9 * 9)
    documents = tuple(dict(indexId=head.index_id, indexRevision=head.index_revision,
        rootDigest=head.index_root.digest, leafCount=head.index_root.count) for head in actual)
    _same(documents, expected, work)
    _require(len(actual) == 9)
    return actual


def _frontier_originals(inputs, *, expected_ids, captured, work):
    _require(type(inputs) is tuple and len(inputs) == len(expected_ids)
        and tuple(item.index_id for item in inputs) == expected_ids)
    known = {head.index_id: head for head in captured}
    maximum = proof.read_write._source_sizes(proof.contract.operation_spec(OPERATION))[2]
    result = []
    for item in inputs:
        _require(type(item) is proof.indexed.IndexedMutationInput
            and item.index_id in known and type(item.frontier) is tuple
            and len(item.frontier) <= maximum)
        head = known[item.index_id]
        _require(item.index_revision == head.index_revision and item.index_root == head.index_root)
        records = []
        for node in item.frontier:
            if type(node) is IndexLeaf:
                values = _own((node.key, node.primary_key_digest, node.primary_row_digest), work)
                work.charge(json_nodes=9)
                records.append(dict(kind="leaf", key=values[0],
                    primaryKeyDigest=values[1], primaryRowDigest=values[2]))
            elif type(node) is OpaqueSubtree:
                values = _own((node.prefix, node.digest, node.count), work)
                work.charge(json_nodes=9)
                records.append(dict(kind="opaque", prefix=values[0], digest=values[1], count=values[2]))
            else:
                raise proof.RecoveryInvalidationError("invalidation frontier is not a source record")
        work.prepare_copy((item.index_id, item.index_revision, item.index_root.digest, item.index_root.count))
        work.charge(json_nodes=11)
        result.append(dict(indexId=item.index_id, indexRevision=item.index_revision,
            rootDigest=item.index_root.digest, leafCount=item.index_root.count, frontier=records))
    return tuple(result)


def acquire_originals(cursor, *, request, manifest, business_before_roots,
        authorization_before_roots, expected_counted_heads, database_now,
        terminal_retention_seconds, maximum_retained, trace, work, acquisition):
    """Read genuine originals once using the caller's original paired ledgers.

    Roots are exact tuples of root documents; counted heads are an exact tuple
    of all nine indexId/indexRevision/rootDigest/leafCount documents. Manifest
    is the actual caller-admitted planner manifest, not a selected-row carrier.
    The caller retains snapshot/clock/currentness checks around every physical
    cursor callback; a read-only fragment cannot manufacture those guarantees.
    """
    # Keep the genuine registry/startup gate. No successful DTO substitutes for
    # the real source planner type, and no import-time registration is added.
    from serverware import authority_planner as planner

    if (type(work) is not _ValidationWork
            or type(acquisition) is not reader._ReadAcquisitionBudget):
        if type(acquisition) is reader._ReadAcquisitionBudget:
            acquisition.failed = True
        raise proof.RecoveryInvalidationError("invalidation requires the original acquisition pair")
    try:
        _require(type(trace) is planner.PlannerTrace and trace.operation == OPERATION
            and trace._recovery_successor is True)
        # Copy every variable caller graph before the first cursor callback.
        request, manifest, business, authorization, expected = _own((request, manifest,
            business_before_roots, authorization_before_roots, expected_counted_heads), work)
        _request(request, work)
        _require(type(manifest) is tuple and 1 <= len(manifest) <= 5)
        business, authorization = _root_objects(business, work), _root_objects(authorization, work)
        root_by_table = {root.table: root for root in (*business, *authorization)}
        with acquisition.read_phase(cursor, trace, work):
            captured = _heads(cursor, expected=expected, trace=trace, work=work, acquisition=acquisition)
            work.charge(json_nodes=9 * 4)
            original_heads = tuple(proof.read_write.CompleteReadWriteHead(
                head.index_id, head.index_revision, head.index_root) for head in captured)
            context = proof.context_document(arguments=request["arguments"],
                request_digest=request["requestDigest"], database_now=database_now,
                business_before_roots=business, authorization_before_roots=authorization,
                counted_before_heads=original_heads, terminal_retention_seconds=terminal_retention_seconds,
                maximum_retained=maximum_retained, work=work)

            def read(query):
                _require(query.table in root_by_table)
                selected, before = physical.acquire_exact_primary(cursor, operation=OPERATION,
                    query=query, manifest=manifest, primary_root=root_by_table[query.table],
                    trace=trace, work=work, acquisition=acquisition)
                acquisition.require_idle(cursor, trace, work)
                return selected, before

            target, target_proof = read(proof.target_query(request["arguments"], work=work))
            # This performs genuine membership again against our full original
            # context before the target row may select a challenge/audit key.
            following = proof.followup_queries(context=context, target_selected=target,
                target_proof=target_proof, work=work)
            selected, before = [target], [target_proof]
            for query in following:
                row, original = read(query)
                selected.append(row)
                before.append(original)
            selected, before = tuple(selected), tuple(before)
            call = proof.core.KernelContext(OPERATION, request["arguments"], selected,
                database_now, request["requestDigest"])
            effects = proof.terminal.evaluate_row(phase="invalidate", context=call,
                business_before_roots=business, authorization_before_roots=authorization,
                before_proofs=before, terminal_retention_seconds=terminal_retention_seconds,
                maximum_retained=maximum_retained, work=work)
            # Derive the complete affected inventory from actual semantic
            # mutations. Challenge changes always require all nine profiles.
            expected_ids = tuple(sorted({identity for mutation in effects.mutations
                for identity in proof.projection.index_ids_for_table(mutation["table"])}))
            _require(set(expected_ids) <= set(proof.heads._recovery_write_ids(OPERATION)))
            work.charge(json_nodes=4 * len(expected_ids))
            write_heads = tuple(proof.indexed.IndexedMutationHead(
                head.index_id, head.index_revision, head.index_root)
                for head in captured if head.index_id in expected_ids)
            actual = mutation_reader._acquire_indexed_primary_batch(cursor,
                table_contracts=proof.terminal.contracts.primary_table_contracts(OPERATION),
                business_before_roots=business, authorization_before_roots=authorization,
                selected_rows=selected, before_proofs=before, mutations=effects.mutations,
                index_before_heads=write_heads,
                limits=proof.read_write._write_limits(proof.contract.operation_spec(OPERATION),
                    proof.batch._SharedLedger(work)), trace=trace,
                acquisition_budget=mutation_reader._AcquisitionBudget(
                    shared_acquisition=acquisition, work=work))
            acquisition.require_idle(cursor, trace, work)
            originals = _frontier_originals(actual.index_inputs, expected_ids=expected_ids,
                captured=captured, work=work)
            raw = proof.produce_originals(context=context, selected_rows=selected,
                before_proofs=before, index_inputs=originals, work=work)
            acquisition.require_idle(cursor, trace, work)
        return raw
    except BaseException:
        acquisition.failed = True
        raise
