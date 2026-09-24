"""Private source binding for the inactive signed revocation writer trace.

Call only after genuine semantic proof/effect verification, with its owned raw
mutations/proofs and actual primary after roots. These ordinary values are not
authority tokens. The existing indexed preparation recomputes NEW commitments
and OLD/NEW projections; it does not repeat primary or sparse proof evaluation.
Its historical hash/framed-input accounting is not a whole-process allocation
meter. Marker copies and comparisons are separately charged by this consumer.
"""
from __future__ import annotations

from serverware import authority_complete_read_write as complete_write
from serverware import authority_contract
from serverware import authority_index_mutation_reader as reader
from serverware import authority_index_projection as projection
from serverware import authority_indexed_mutation as indexed
from serverware.authority_index_contract import CountedNode
from serverware import authority_complete_query as complete


def _prepare(*, mutations, before_proofs, business_after_roots, before_heads, ledger):
    """Prepare every actual source profile and its complete SQL target cover."""
    spec = authority_contract.operation_spec(complete.OPERATION)
    tables = {item["table"] for item in mutations}
    if not tables <= set(spec["businessWrites"]):
        raise indexed.IndexedMutationError("revocation write trace has a foreign mutation table")
    index_ids = tuple(sorted(index_id for table in tables
                             for index_id in projection.index_ids_for_table(table)))
    heads = {item["indexId"]: item for item in before_heads}
    budget = indexed._Budget(complete_write._write_limits(spec, ledger), work=ledger.work)
    prepared = indexed._prepare_owned_primary_changes(mutations=mutations,
        before_proofs=before_proofs, business_after_roots=business_after_roots,
        index_ids=index_ids, budget=budget)
    plans = []
    reads = parameters = 0
    for index_id in index_ids:
        head = heads[index_id]
        item = indexed.IndexedMutationInput(index_id, head["indexRevision"],
            CountedNode(head["rootDigest"], head["leafCount"]), ())
        profile, changes, _, _ = indexed._prepare_index_changes(item, prepared, budget)
        geometry = reader._target_geometry(index_id, changes, limits=budget.limits.index,
            remaining_reads=reader.MAX_SQL_READS,
            remaining_parameter_bytes=reader.MAX_PARAMETER_BYTES,
            earlier_reads=reads, earlier_parameters=parameters)
        reads += geometry.sql_reads
        parameters += geometry.parameter_bytes
        plans.append((item, profile, geometry))
    return tuple(plans), reads


def _markers(plans, work):
    """Yield the source's sorted profiles, target batches, then sibling batches.

    The source batch is traversed/copied before allocating its marker list.
    Prefix objects add a conservative 64 bytes/eight nodes per item: twice
    their at-most-27-byte extra canonical shape and four added JSON nodes.
    Fixed eight-field context scaffolding is bounded source metadata.
    """
    for item, profile, geometry in plans:
        context = {"profile": reader.READ_PROFILE, "indexId": item.index_id,
            "projectionDigest": profile.projection_digest,
            "indexRevision": item.index_revision, "rootDigest": item.index_root.digest,
            "rootCount": item.index_root.count}
        for batch in reader._batches(geometry.targets):
            work.prepare_copy(batch)
            yield reader.transport.LEAF_TABLE, {**context, "targets": list(batch),
                                                "limit": len(batch) + 1}
        for batch in reader._batches(geometry.siblings):
            work.prepare_copy(batch)
            work.charge(input_bytes=64 * len(batch), json_nodes=8 * len(batch))
            yield reader.transport.NODE_TABLE, {**context,
                "prefixes": [{"depth": len(prefix), "pathPrefix": prefix} for prefix in batch],
                "limit": len(batch) + 1}
