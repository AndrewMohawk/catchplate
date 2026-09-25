"""Metered ordinary QueryRead and counted-frontier wire projections.

Only the three source-fixed successor operations are supported. Embedded query
JSON stays opaque: genuine replay regenerates declarations and verifies their
associations. These helpers neither verify roots nor accept proof-success
objects. All ownership, conversions and constructor scans use the caller's
existing cumulative work; there is no SQL, planner import or new allowance.
"""
from __future__ import annotations

from serverware import authority_complete_query_batch as capture
from serverware import authority_complete_read_write as read_write
from serverware import authority_index_projection as projection
from serverware import authority_indexed_mutation as indexed
from serverware import authority_query_reads as reads
from serverware import authority_revocation_read_write as mixed
from serverware import authority_webauthn_transition_proof_contract as contract
from serverware.authority_index_contract import CountedNode, IndexLeaf, OpaqueSubtree


_MAX_FRONTIER = max(read_write._source_sizes(spec)[2] for spec in contract.SPECS.values())


class WebAuthnTransitionProofWireError(ValueError):
    pass


def _capture(value, work):
    return capture._JSONCapture(capture._SharedLedger(work)).visit(value)


def _encode_reads_on_work(query_reads, *, operation, work):
    """Project actual records, including empty ranges and absence addresses."""
    capture._SharedLedger(work)
    maximum = contract._operation(operation)["maximumQueryRows"]
    if type(query_reads) is not tuple or not 1 <= len(query_reads) <= maximum:
        raise WebAuthnTransitionProofWireError("transition query records are not a bounded exact tuple")
    total = 0
    for record in query_reads:
        if (type(record) is not reads.QueryRead or type(record.addresses) is not tuple
                or len(record.addresses) > maximum - total
                or type(record.returned_row_count) is not int
                or not 0 <= record.returned_row_count <= maximum
                or operation == "webauthn.trust.complete" and len(record.addresses) != 1):
            raise WebAuthnTransitionProofWireError("transition query record inventory is invalid")
        total += len(record.addresses)
    # The genuine copier prepays constructors and owns all immutable fields.
    owned = tuple(reads._copy_read(record, work) for record in query_reads)
    raw_bytes = sum(len(record.declared_query_json) + len(record.resolved_query_json)
        + sum(len(address.key_json) for address in record.addresses) for record in owned)
    work.charge(input_bytes=raw_bytes)
    values = [{"queryId": record.query_id,
        "declaredQueryJson": record.declared_query_json.decode("ascii"),
        "resolvedQueryJson": record.resolved_query_json.decode("ascii"),
        "addresses": [{"table": address.table, "keyJson": address.key_json.decode("ascii"),
            "keyDigest": address.key_digest, "present": address.present} for address in record.addresses],
        "returnedRowCount": record.returned_row_count} for record in owned]
    values = _capture(values, work)
    contract._reads(values, operation)
    return values


def _decode_reads_on_work(values, *, operation, work):
    """Restore real QueryRead records without adopting their query meaning."""
    contract._operation(operation)
    contract._reads(values, operation)
    owned = _capture(values, work)
    # This existing generic body charges strict ASCII encoding and calls the
    # actual metered QueryRead and QueryReadAddress constructors; its enclosing
    # revocation-only orchestration is not invoked.
    return mixed._restore_reads(owned, work)


def _frontier_limit(maximum_entries):
    if type(maximum_entries) is not int or not 1 <= maximum_entries <= _MAX_FRONTIER:
        raise WebAuthnTransitionProofWireError("frontier ceiling is outside the source operations")
    return min(maximum_entries, contract.MAX_NODES // 9)


def _encode_frontier_on_work(frontier, *, maximum_entries, work):
    maximum = _frontier_limit(maximum_entries)
    capture._SharedLedger(work)
    if type(frontier) is not tuple or len(frontier) > maximum:
        raise WebAuthnTransitionProofWireError("frontier is not a bounded exact tuple")
    values = []
    for terminal in frontier:
        if type(terminal) is IndexLeaf:
            key, primary_key, primary_row = terminal.key, terminal.primary_key_digest, terminal.primary_row_digest
            value = {"kind": "leaf", "key": key,
                "primaryKeyDigest": primary_key, "primaryRowDigest": primary_row}
        elif type(terminal) is OpaqueSubtree:
            prefix, digest, count = terminal.prefix, terminal.digest, terminal.count
            value = {"kind": "opaque", "prefix": prefix, "digest": digest, "count": count}
        else:
            raise WebAuthnTransitionProofWireError("frontier contains an unexpected exact record type")
        # Own scalar fields before their validation scans. The subsequent
        # constructor rejects malformed native records, including impossible
        # opaque subtree counts; no hashing occurs in these constructors.
        value = _capture(value, work)
        contract.retained._frontier([value], 1)
        work.prepare_scan(value)
        if value["kind"] == "leaf":
            IndexLeaf(value["key"], value["primaryKeyDigest"], value["primaryRowDigest"])
        else:
            OpaqueSubtree(value["prefix"], value["digest"], value["count"])
        values.append(value)
    return _capture(values, work)


def _decode_frontier_on_work(values, *, maximum_entries, work):
    maximum = _frontier_limit(maximum_entries)
    contract.retained._frontier(values, maximum)
    owned = _capture(values, work)
    records = []
    for value in owned:
        work.prepare_scan(value)
        if value["kind"] == "leaf":
            record = IndexLeaf(value["key"], value["primaryKeyDigest"], value["primaryRowDigest"])
        else:
            record = OpaqueSubtree(value["prefix"], value["digest"], value["count"])
        records.append(record)
    return tuple(records)


def _encode_query_frontiers_on_work(frontiers, *, operation, arguments, work):
    """Package actual observations; the receiver rebinds complete declarations."""
    contract._operation(operation)
    arguments = _capture(arguments, work)
    family = contract._family(operation, arguments)
    if type(frontiers) is not tuple or len(frontiers) != family["query_count"]:
        raise WebAuthnTransitionProofWireError("query frontiers differ from the source family inventory")
    maximum = capture.MAX_OUTSIDE_PREFIXES + family["max_frontier_rows"]
    held, total, identities = [], 0, set()
    for item in frontiers:
        if type(item) is not capture.CompleteQueryFrontier:
            raise WebAuthnTransitionProofWireError("query frontier has an unexpected exact type")
        query_id, frontier = item.query_id, item.frontier
        contract.shape._text(query_id, reads.MAX_QUERY_ID_BYTES)
        if (query_id in identities or type(frontier) is not tuple or len(frontier) > maximum):
            raise WebAuthnTransitionProofWireError("query frontier identity or local ceiling is invalid")
        identities.add(query_id)
        total += len(frontier)
        if total > contract.MAX_NODES // 9:
            raise WebAuthnTransitionProofWireError("query frontier normalization exceeds the shared node ceiling")
        held.append((query_id, frontier))
    values = [{"queryId": query_id, "frontier": _encode_frontier_on_work(frontier,
        maximum_entries=maximum, work=work)} for query_id, frontier in held]
    return _capture(values, work)


def _encode_write_frontiers_on_work(index_inputs, *, operation, work):
    """Package real indexed-engine inputs, never a fabricated affected set."""
    spec = contract._operation(operation)
    capture._SharedLedger(work)
    allowed = frozenset(index_id for table in spec["businessWrites"]
        for index_id in projection.index_ids_for_table(table))
    if type(index_inputs) is not tuple or len(index_inputs) > len(allowed):
        raise WebAuthnTransitionProofWireError("write frontiers exceed the source index inventory")
    maximum = read_write._source_sizes(spec)[2]
    held, total, previous = [], 0, ""
    for item in index_inputs:
        if type(item) is not indexed.IndexedMutationInput:
            raise WebAuthnTransitionProofWireError("write frontier has an unexpected exact type")
        identity, revision, node, frontier = item.index_id, item.index_revision, item.index_root, item.frontier
        if (type(identity) is not str or identity not in allowed or identity <= previous
                or type(node) is not CountedNode or type(frontier) is not tuple or len(frontier) > maximum):
            raise WebAuthnTransitionProofWireError("write frontier identity or local ceiling is invalid")
        digest, count = node.digest, node.count
        contract.shape._integer(revision)
        contract.shape._digest(digest)
        contract.shape._integer(count)
        work.prepare_scan({"indexId": identity, "indexRevision": revision, "rootDigest": digest, "leafCount": count})
        CountedNode(digest, count)
        total += len(frontier)
        if total > contract.MAX_NODES // 9:
            raise WebAuthnTransitionProofWireError("write frontier normalization exceeds the shared node ceiling")
        held.append((identity, frontier))
        previous = identity
    values = [{"indexId": identity, "frontier": _encode_frontier_on_work(frontier,
        maximum_entries=maximum, work=work)} for identity, frontier in held]
    return _capture(values, work)
