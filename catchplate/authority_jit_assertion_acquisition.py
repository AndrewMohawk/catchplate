"""Actual two-stage JIT read/proof acquisition, returning only raw originals.

The native caller owns the admitted database, original snapshot, configured
assertion policy and live window. Neither this private component nor its raw
output is a signer, current-root admission or receipt-verification token.
Replay must independently select its policy and rerun the real assertion and
primary/counted engines; the embedded policy is only an exact input record.
The original 4 MiB physical collector remains an aggregate refusal ceiling;
worst-case composition of individually allowed large rows is not established.
The shared reader's 1 MiB row ceiling also excludes genuinely source-supported
larger trust-publication rows (the bundle alone may be 2 MiB). This draft fixes
physical accounting for supported sizes; it is not complete JIT capacity parity.
"""
from __future__ import annotations

from contextlib import nullcontext

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_complete_query_batch as batch
from catchplate import authority_complete_read_write as read_write
from catchplate import authority_contract as authority
from catchplate import authority_index_heads as heads
from catchplate import authority_index_mutation_reader as mutation_reader
from catchplate import authority_index_reader as reader
from catchplate import authority_indexed_mutation as indexed
from catchplate import authority_jit_assertion_receipt as receipt
from catchplate import authority_mutation_reservation_guard as reservations
from catchplate import authority_primary_contract as primary_contract
from catchplate import authority_primary_original_reader as primary_reader
from catchplate import authority_query_reads as reads
from catchplate import authority_request_commitment as commitment
from catchplate import authority_revocation_plan_contract as shape
from catchplate import authority_transition_core as core
from catchplate.authority_index_contract import IndexLeaf, OpaqueSubtree
from catchplate.authority_query_read_work import _ValidationWork, MAX_INPUT_BYTES


OPERATION = receipt.OPERATION
SCHEMA = "catchplate.policyAuthorityJitAssertionOriginals/v1"
_POLICY_FIELDS = ("rp_id", "origin", "maximum_assertion_age_seconds")
FIELDS = frozenset({"schema", "sourceRevision", "operation", "operationManifestDigest",
    "queryManifestDigest", "authorizationManifestDigest", "handlerContractDigest", "request",
    "assertionPolicy", "databaseCutoffUs", "businessBeforeRoots", "authorizationBeforeRoots",
    "countedBeforeHeads", "selectedRows", "beforeProofs", "queryReads", "writeFrontiers"})


class JitAssertionAcquisitionError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitAssertionAcquisitionError("JIT originals differ from their fixed source acquisition")


def _owned(value, work):
    return batch._JSONCapture(batch._SharedLedger(work)).visit(value)


def _same(left, right, work):
    a, b = work.wire(left), work.wire(right)
    work.charge(input_bytes=len(a) + len(b))
    _require(a == b)


def _policy(value):
    _require(type(value) is dict and set(value) == set(_POLICY_FIELDS))
    for name, maximum in (("rp_id", 253), ("origin", 2048)):
        core.require_text(value[name], name, maximum_bytes=maximum)
    _require(type(value["maximum_assertion_age_seconds"]) is int
        and 1 <= value["maximum_assertion_age_seconds"] <= 30)


def _handler_contract_on_work(work):
    """Meter the actual source JSON projection, not its read-only spec map.

    The fixed source projector constructs two bounded JSON graphs and hashes
    its genuine handler material internally. Reserve that construction before
    calling it, then measure the exact returned projection on the same work.
    No generic Mapping object is treated as caller-admitted lossless JSON.
    """
    _require(type(work) is _ValidationWork)
    work.charge(hashes=1, input_bytes=4 * 16384, json_nodes=4 * 2048)
    entry = authority._operation_manifest_entry(OPERATION, authority.operation_spec(OPERATION))
    size, nodes = work.measure(entry)
    _require(size <= 16384 and nodes <= 2048)
    shape._digest(entry["handlerDigest"])
    return entry["handlerDigest"]


def _request(request, work):
    shape._object(request, shape.TYPED_REQUEST_FIELDS, "JIT typed request")
    _require(request["operation"] == OPERATION and type(request["operation"]) is str)
    for name in ("requestDigest", "operationId", "operationManifestDigest"):
        shape._digest(request[name])
    receipt._arguments(request["arguments"])
    work.prepare_copy(request["arguments"])
    arguments = {name: value for name, value in request["arguments"].items() if name != "businessIntent"}
    intent = authority._synthesize_business_intent(OPERATION, arguments, work=work)
    _same(request["arguments"]["businessIntent"], intent, work)
    actual = commitment._typed_request_digest(request, work=work)
    _same(actual, request["requestDigest"], work)
    work.prepare_utf8(OPERATION)
    work.prepare_utf8(actual)
    work.charge(hashes=1, input_bytes=len("catchplate.policyAuthorityOperation/v2") + 17)
    _same(commitment.operation_id(OPERATION, actual), request["operationId"], work)


def _memberships(selected, proofs, business, authorization, work):
    ledger = batch._SharedLedger(work)
    ledger.charge(hashes=authority.TREE_DEPTH + 2)
    before_business, before_authorization = batch._roots(business), batch._roots(authorization)
    spec = authority.operation_spec(OPERATION)
    actual = batch.primary.evaluate_primary_radix_memberships(
        table_contracts=primary_contract.primary_table_contracts(OPERATION),
        business_before_roots=before_business, authorization_before_roots=before_authorization,
        selected_rows=selected, before_proofs=proofs,
        limits=batch._primary_limits(spec, spec["maximumQueryRows"], ledger))
    measured = actual.result.metrics
    ledger.charge(hashes=measured.hash_work, input_bytes=measured.input_bytes, json_nodes=measured.json_nodes)
    _require(actual.result.business_after_roots == before_business
        and actual.result.authorization_after_roots == before_authorization
        and measured.mutations == 0 and measured.recomputed_ancestors == 0)
    return actual.selected_rows, actual.before_proofs


def _stage(cursor, *, queries, request, manifest, business, authorization, trace, work, acquisition):
    queries = reads._snapshot_queries(OPERATION, queries, work=work)
    work.charge(hashes=66)
    roots = batch._roots(business) + batch._roots(authorization)
    work.charge(json_nodes=2 * len(roots) + 4)
    by_table = {root.table: root for root in roots}
    selected, proofs, records = [], [], []
    for query in queries:
        # The source caller derives these exact PKs; the reader performs both
        # business and proof SQL against this SAME original physical collector.
        row, proof = primary_reader.acquire_exact_primary(cursor, operation=OPERATION,
            query=query, manifest=manifest, primary_root=by_table[query.table],
            trace=trace, work=work, acquisition=acquisition)
        record = reads._capture_query_read(OPERATION, query, resolved_query=query,
            ordered_selected_rows=(row,), returned_row_count=int(row["present"]), work=work)
        selected.append(row)
        proofs.append(proof)
        records.append(record)
    work.prepare_copy(selected)
    selected = tuple(sorted(selected, key=lambda row: (row["table"], row["keyDigest"])))
    proofs, records = tuple(proofs), tuple(records)
    selected, proofs = _memberships(selected, proofs, business, authorization, work)
    _, records = reads._validate_query_reads(OPERATION, queries=queries,
        query_reads=records, selected_rows=selected, work=work)
    return selected, proofs, queries, records


def _encode_reads(records, work):
    _require(type(records) is tuple and len(records) == 8)
    values = []
    for original in records:
        record = reads._copy_read(original, work)
        _require(len(record.addresses) == 1 and record.returned_row_count in (0, 1))
        address = record.addresses[0]
        # Reserve the concrete scalar copies and dictionaries before creation.
        work.charge(json_nodes=20, input_bytes=len(record.declared_query_json)
            + len(record.resolved_query_json) + len(address.key_json))
        declared = record.declared_query_json.decode("ascii")
        resolved = record.resolved_query_json.decode("ascii")
        key = address.key_json.decode("ascii")
        work.prepare_copy((record.query_id, declared, resolved, address.table,
            key, address.key_digest, address.present, record.returned_row_count))
        values.append({"queryId": record.query_id,
            "declaredQueryJson": declared, "resolvedQueryJson": resolved,
            "addresses": [{"table": address.table, "keyJson": key,
                "keyDigest": address.key_digest, "present": address.present}],
            "returnedRowCount": record.returned_row_count})
    return values


def _encode_frontiers(inputs, captured, work):
    _require(type(inputs) is tuple and len(inputs) == len(captured) == 12)
    maximum = read_write._source_sizes(authority.operation_spec(OPERATION))[2]
    values, total = [], 0
    for item, head in zip(inputs, captured):
        _require(type(item) is indexed.IndexedMutationInput and item.index_id == head.index_id
            and item.index_revision == head.index_revision and item.index_root == head.index_root
            and type(item.frontier) is tuple and len(item.frontier) <= maximum)
        total += len(item.frontier)
        _require(total <= batch.MAX_TOTAL_JSON_NODES // 9)
        work.prepare_copy((item.index_id,))
        work.charge(json_nodes=4)
        frontier = []
        for node in item.frontier:
            if type(node) is IndexLeaf:
                work.prepare_copy((node.key, node.primary_key_digest, node.primary_row_digest))
                work.charge(json_nodes=9)
                value = {"kind": "leaf", "key": node.key,
                    "primaryKeyDigest": node.primary_key_digest, "primaryRowDigest": node.primary_row_digest}
            elif type(node) is OpaqueSubtree:
                work.prepare_copy((node.prefix, node.digest, node.count))
                work.charge(json_nodes=9)
                value = {"kind": "opaque", "prefix": node.prefix, "digest": node.digest, "count": node.count}
            else:
                raise JitAssertionAcquisitionError("JIT write frontier has an unknown native record")
            frontier.append(value)
        values.append({"indexId": item.index_id, "frontier": frontier})
    return values


def _acquire_on_work(cursor, *, request, assertion_policy, manifest, manifest_digest,
        business_before_roots, authorization_before_roots, expected_counted_heads,
        now_epoch_ns, deadline_epoch_ns, deadline_monotonic_ns, maximum_clock_skew_ns,
        trace, check_snapshot, work, reservation_guard=None):
    """One genuine native owner's acquisition; no connection or new allowance."""
    from catchplate import authority_planner as planner

    _require(type(work) is _ValidationWork and type(trace) is planner.PlannerTrace
        and trace.operation == OPERATION and trace._jit_successor is True)
    _require(reservation_guard is None or type(reservation_guard) is reservations._MutationReservationGuard)
    _request(request, work)
    _policy(assertion_policy)
    spec = authority.operation_spec(OPERATION)
    _require((spec["maximumQueryRows"], spec["maximumMutations"], spec["maximumWorkUnits"]) == (16, 3, 512)
        and not spec["globalAuditCapacity"])
    acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work)
    try:
        with acquisition.read_phase(cursor, trace, work):
            business, authorization, _ = planner._read_root_set(cursor, operation=OPERATION,
                manifest=manifest, trace=trace, work=work, deadline_epoch_ns=deadline_epoch_ns,
                deadline_monotonic_ns=deadline_monotonic_ns)
            _same((business, authorization), (business_before_roots, authorization_before_roots), work)
            database_now = planner._read_database_now_on_work(cursor, work)
            cutoff = planner.authority_transition_webauthn_registration._now(database_now)
            _require(abs(cutoff - now_epoch_ns) <= maximum_clock_skew_ns and cutoff < deadline_epoch_ns)
            captured = heads.read_operation_index_heads(cursor, operation=OPERATION, trace=trace,
                work=work, acquisition=acquisition, include_write_heads=True)
            work.charge(json_nodes=12 * 9)
            actual_heads = tuple({"indexId": head.index_id, "indexRevision": head.index_revision,
                "rootDigest": head.index_root.digest, "leafCount": head.index_root.count} for head in captured)
            _require(len(captured) == 12)
            _same(actual_heads, expected_counted_heads, work)
            first = _stage(cursor, queries=receipt.queries(request["arguments"]), request=request,
                manifest=manifest, business=business, authorization=authorization, trace=trace, work=work,
                acquisition=acquisition)
            check_snapshot()
            context = core.KernelContext(OPERATION, request["arguments"], first[0], database_now,
                request["requestDigest"], query_reads=first[3])
            actual_receipt = receipt.receipt_from_context(context, assertion_policy=assertion_policy, work=work)
            # No SQL selected by an unverified assertion or caller receipt DTO.
            second = _stage(cursor, queries=(receipt.receipt_query(actual_receipt["assertion_receipt_digest"]),),
                request=request, manifest=manifest, business=business, authorization=authorization,
                trace=trace, work=work, acquisition=acquisition)
            work.prepare_copy((first[0], second[0], first[1], second[1]))
            selected = tuple(sorted(first[0] + second[0], key=lambda row: (row["table"], row["keyDigest"])))
            proofs = first[1] + second[1]
            selected, proofs = _memberships(selected, proofs, business, authorization, work)
            queries, records = first[2] + second[2], first[3] + second[3]
            _, records = reads._validate_query_reads(OPERATION, queries=queries,
                query_reads=records, selected_rows=selected, work=work)
            acquisition.require_idle(cursor, trace, work)
        check_snapshot()
        context = core.KernelContext(OPERATION, request["arguments"], selected, database_now,
            request["requestDigest"], query_reads=records)
        transition = receipt.transition(context, assertion_policy=assertion_policy, work=work)
        _require(len(transition.mutations) == 3)
        units = capacity.transition_work_units(operation=OPERATION,
            query_work_units=sum(query.work_units for query in queries),
            kernel_work_units=transition.work_units, mutations=transition.mutations)
        capacity.validate_transition_work_units(OPERATION, units, transition.mutations)
        work.prepare_copy(transition.mutations)
        mutations = tuple(sorted(transition.mutations, key=lambda row: (row["table"], row["keyDigest"], row["operation"])))
        work.charge(json_nodes=12 * 5)
        before_heads = tuple(indexed.IndexedMutationHead(head.index_id, head.index_revision, head.index_root)
            for head in captured)
        mutation_acquisition = mutation_reader._AcquisitionBudget(shared_acquisition=acquisition, work=work)
        with (nullcontext() if reservation_guard is None else reservation_guard.hold(mutation_acquisition)):
            actual = mutation_reader._acquire_indexed_primary_batch(cursor,
                table_contracts=primary_contract.primary_table_contracts(OPERATION),
                business_before_roots=batch._roots(business), authorization_before_roots=batch._roots(authorization),
                selected_rows=selected, before_proofs=proofs, mutations=mutations, index_before_heads=before_heads,
                limits=read_write._write_limits(spec, batch._SharedLedger(work)), trace=trace,
                acquisition_budget=mutation_acquisition)
        acquisition.require_idle(cursor, trace, work)
        check_snapshot()
        for mutation in mutations:
            trace.write(mutation["table"], mutation["key"])
        work.prepare_copy(trace._entries)
        trace.close(selected_rows=selected, mutation_plan=mutations)
        raw_reads = _encode_reads(records, work)
        frontiers = _encode_frontiers(actual.index_inputs, captured, work)
        # Source documents are metered before their actual digest reconstruction.
        auth_source = primary_contract.source_authorization_manifest()
        work.prepare_copy(auth_source)
        work.prepare_encoding(auth_source)
        handler_digest = _handler_contract_on_work(work)
        work.charge(hashes=1, input_bytes=256)
        document = {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION, "operation": OPERATION,
            "operationManifestDigest": authority.OPERATION_MANIFEST_DIGEST, "queryManifestDigest": manifest_digest,
            "authorizationManifestDigest": primary_contract.source_authorization_manifest_digest(),
            "handlerContractDigest": handler_digest, "request": request,
            "assertionPolicy": assertion_policy, "databaseCutoffUs": cutoff // 1000,
            "businessBeforeRoots": business, "authorizationBeforeRoots": authorization,
            "countedBeforeHeads": actual_heads, "selectedRows": selected, "beforeProofs": proofs,
            "queryReads": raw_reads, "writeFrontiers": frontiers}
        _require(set(document) == FIELDS)
        raw = work.wire(document)
        _require(2 <= len(raw) <= MAX_INPUT_BYTES)
        check_snapshot()
        return raw
    except BaseException:
        acquisition.failed = True
        raise
