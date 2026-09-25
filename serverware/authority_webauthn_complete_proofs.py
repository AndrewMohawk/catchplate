"""Genuine complete-read and counted-write replay for two WebAuthn successors.

Registration and aggregate trust stage regenerate their source declarations;
no transported declaration or successful read-result object is admitted. The
entire raw proof graph is owned before profile/hash/engine work. Actual primary
memberships and counted joins establish the ordered leaves used to reconstruct
each complete query observation, including empty results.

The full potential head inventory is source fixed. Only the actual read/write
subset enters the existing mathematical engines; unused heads are validated
against source profiles and primary populations and remain unchanged. Write
derivation repeats original read proofs and accepts raw semantic mutations,
never a prior successful read carrier. Semantic authority, ordinary-query
association, independent root/time/request provenance and signed transport
remain the owning composition's responsibility. No SQL, clock, signature,
registry activation, revocation protocol or replacement allowance is used.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as batch
from serverware import authority_complete_read_write as read_write
from serverware import authority_index_heads as heads
from serverware import authority_query_reads as reads
from serverware import authority_webauthn_transition_proof_contract as contract
from serverware import authority_webauthn_transition_proof_wire as wire


_OPERATIONS = frozenset({complete.REGISTRATION_OPERATION, complete.STAGE_OPERATION})


class WebAuthnCompleteProofError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _CompleteWriteObservation:
    """Actual mathematical results, not a successful-proof input token."""

    primary: read_write.primary.PrimaryRadixBatchResult
    before_heads: tuple[read_write.CompleteReadWriteHead, ...]
    after_heads: tuple[read_write.CompleteReadWriteHead, ...]
    write: read_write.indexed.IndexedMutationResult


def _capture(document, work, mutations=None):
    ledger = batch._SharedLedger(work)
    if (type(document) is not dict or type(document.get("operation")) is not str
            or document["operation"] not in _OPERATIONS):
        raise WebAuthnCompleteProofError("complete proof operation is not registration or trust stage")
    contract.validate_payload_shape(document)
    if mutations is None:
        owned = batch._JSONCapture(ledger).visit(document)
        actual_mutations = None
    else:
        spec = batch.authority_contract.operation_spec(document["operation"])
        if type(mutations) is not tuple or len(mutations) > spec["maximumMutations"]:
            raise WebAuthnCompleteProofError("semantic mutations exceed their exact source inventory")
        work.prepare_copy(mutations)
        captured = batch._JSONCapture(ledger).visit({"document": document, "mutations": list(mutations)})
        owned, actual_mutations = captured["document"], captured["mutations"]
    contract.validate_payload_shape(owned)
    return owned, actual_mutations, ledger


def _queries(owned, work):
    operation, arguments = owned["operation"], owned["request"]["arguments"]
    return tuple(complete._bind_query(operation, role, arguments=arguments,
        cutoff_us=owned["databaseCutoffUs"], work=work)
        for role in complete.family_roles(operation, arguments=arguments))


def _full_heads(owned, queries, ledger, work):
    expected_ids = heads.required_index_ids(owned["operation"], arguments=owned["request"]["arguments"],
        queries=queries, include_write_heads=True)
    raw_heads = owned["countedBeforeHeads"]
    actual_ids = tuple(item["indexId"] for item in raw_heads)
    work.prepare_comparison(actual_ids, expected_ids)
    if actual_ids != expected_ids:
        raise WebAuthnCompleteProofError("counted heads are not the full sorted potential source inventory")
    primary_counts = {root["table"]: root["leafCount"]
        for root in owned["businessBeforeRoots"] + owned["authorizationBeforeRoots"]}
    # Exactly one real source profile and one real empty-root computation for
    # every potential head, including those unused by this invocation.
    ledger.charge(hashes=2 * len(raw_heads))
    result = []
    for item in raw_heads:
        profile = read_write.projection.profile_for(item["indexId"])
        root = read_write.CountedNode(item["rootDigest"], item["leafCount"])
        revision = item["indexRevision"]
        empty = read_write.empty_node(profile, "")
        if (type(revision) is not int or not 0 <= revision <= read_write.I64_MAX
                or revision == 0 and root.count != 0
                or (root.count == 0) != (root.digest == empty.digest)
                or root.count > primary_counts[profile.table]):
            raise WebAuthnCompleteProofError("potential counted head differs from source emptiness or primary population")
        result.append(read_write.CompleteReadWriteHead(profile.index_id, revision, root))
    return tuple(result)


def _query_frontiers(owned, queries, work):
    raw = owned["queryFrontiers"]
    if len(raw) != len(queries):
        raise WebAuthnCompleteProofError("complete query frontier count differs from the actual family")
    result = []
    for item, query in zip(raw, queries):
        work.prepare_comparison(item["queryId"], query.query_id)
        if item["queryId"] != query.query_id:
            raise WebAuthnCompleteProofError("complete frontier order differs from the source query recipe")
        frontier = wire._decode_frontier_on_work(item["frontier"],
            maximum_entries=batch.MAX_OUTSIDE_PREFIXES + query.maximum_rows, work=work)
        result.append(batch.CompleteQueryFrontier(query.query_id, frontier))
    return tuple(result)


def _bind_read_records(proved, records, operation, work):
    by_query = {record.query_id: record for record in records}
    if len(by_query) != len(records):
        raise WebAuthnCompleteProofError("query observations contain duplicate identities")
    by_address = {(item["table"], item["keyDigest"]): item for item in proved.selected_rows}
    joined = dict(proved.joined_reads)
    for query in proved.queries:
        if query.query_id not in by_query:
            raise WebAuthnCompleteProofError("query observations omit a complete source role")
        leaves = joined[query.query_id].leaves
        # The real join fixes ordered leaf/key/row bijection. Regenerate the
        # entire actual query record from its proof-owned ordered rows, not a
        # set comparison or a caller-supplied predicate-success statement.
        selected = tuple(by_address[(query.table, leaf.primary_key_digest)] for leaf in leaves)
        expected = reads._capture_query_read(operation, query, resolved_query=query,
            ordered_selected_rows=selected, returned_row_count=len(leaves), work=work)
        actual = by_query[query.query_id]
        work.charge(input_bytes=reads._read_size(actual) + reads._read_size(expected))
        if actual != expected:
            raise WebAuthnCompleteProofError("complete query observation differs from genuine joined leaf order")


def _verify_reads_on_work(*, document, work):
    """Return actual proof-owned rows and complete read-engine observations."""
    owned, _mutations, ledger = _capture(document, work)
    queries = _queries(owned, work)
    full_heads = _full_heads(owned, queries, ledger, work)
    frontiers = _query_frontiers(owned, queries, work)
    read_ids = {query.index_id for query in queries}
    read_heads = tuple(batch.CompleteQueryHead(item.index_id, item.index_revision, item.index_root)
        for item in full_heads if item.index_id in read_ids)
    records = wire._decode_reads_on_work(owned["queryReads"], operation=owned["operation"], work=work)
    work.prepare_copy(owned["selectedRows"])
    work.prepare_copy(owned["beforeProofs"])
    proved = batch._verify_complete_query_batch(operation=owned["operation"],
        arguments=owned["request"]["arguments"], cutoff_us=owned["databaseCutoffUs"], queries=queries,
        business_before_roots=owned["businessBeforeRoots"], authorization_before_roots=owned["authorizationBeforeRoots"],
        selected_rows=tuple(owned["selectedRows"]), before_proofs=tuple(owned["beforeProofs"]),
        read_heads=read_heads, query_frontiers=frontiers, work=work)
    _bind_read_records(proved, records, owned["operation"], work)
    return proved


def _derive_writes_on_work(*, document, mutations, work):
    """Reverify raw reads and derive real writes, preserving unused heads."""
    owned, actual_mutations, ledger = _capture(document, work, mutations)
    work.prepare_comparison(actual_mutations, owned["transition"]["mutations"])
    if actual_mutations != owned["transition"]["mutations"]:
        raise WebAuthnCompleteProofError("semantic mutations differ from the original transition claim")
    queries = _queries(owned, work)
    full_heads = _full_heads(owned, queries, ledger, work)
    query_frontiers = _query_frontiers(owned, queries, work)
    records = wire._decode_reads_on_work(owned["queryReads"], operation=owned["operation"], work=work)
    # This is raw, locally owned data, not a successful read result. The actual
    # source admission checks mutation templates/addresses before the engine
    # repeats all primary memberships, complete joins and indexed writes.
    raw_mutations = {"operation": owned["operation"], "selectedRows": owned["selectedRows"],
        "beforeProofs": owned["beforeProofs"], "mutations": actual_mutations}
    write_ids = read_write._admit_mutations(raw_mutations,
        read_write.primary_table_contracts(owned["operation"]))
    actual_ids = tuple(item["indexId"] for item in owned["writeFrontiers"])
    work.prepare_comparison(actual_ids, write_ids)
    if actual_ids != write_ids:
        raise WebAuthnCompleteProofError("write frontiers are not the exact actual mutation profile closure")
    maximum = read_write._source_sizes(batch.authority_contract.operation_spec(owned["operation"]))[2]
    write_frontiers = tuple(read_write.CompleteWriteFrontier(item["indexId"],
        wire._decode_frontier_on_work(item["frontier"], maximum_entries=maximum, work=work))
        for item in owned["writeFrontiers"])
    used_ids = {query.index_id for query in queries} | set(write_ids)
    used_heads = tuple(item for item in full_heads if item.index_id in used_ids)
    for values in (owned["selectedRows"], owned["beforeProofs"], actual_mutations):
        work.prepare_copy(values)
    captured = read_write._capture(ledger=ledger, operation=owned["operation"],
        arguments=owned["request"]["arguments"], cutoff_us=owned["databaseCutoffUs"], queries=queries,
        business_before_roots=owned["businessBeforeRoots"], authorization_before_roots=owned["authorizationBeforeRoots"],
        selected_rows=tuple(owned["selectedRows"]), before_proofs=tuple(owned["beforeProofs"]),
        mutations=tuple(actual_mutations), counted_before_heads=used_heads,
        query_frontiers=query_frontiers, write_frontiers=write_frontiers)
    proved = read_write._verify(captured, ledger, ledger.input_bytes, ledger.json_nodes)
    _bind_read_records(proved, records, owned["operation"], work)
    after_by_id = {item.index_id: item for item in proved.after_heads}
    full_after = tuple(after_by_id.get(item.index_id, item) for item in full_heads)
    return _CompleteWriteObservation(proved.write.primary, full_heads, full_after, proved.write)
