"""Original-only recovery invalidation proof production and independent replay.

This is a relative proof computation, not a witness claim or execution grant.
The caller must independently admit request/configuration, original time, the
complete current root vector, and the real claimed recovery authorization.
Neither an authorization JSON object nor this module's output supplies that
custody. No SQL, clock sampling, signature, registry or commit occurs here.

Target membership precedes derivation of every secondary exact-key read. Real
terminal semantics derive the mutations; the unchanged indexed writer verifies
all affected profiles, including all nine challenge profiles. No caller query,
mutation, after-root, verification result or witness Boolean is accepted.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from serverware import authority_complete_query_batch as batch
from serverware import authority_complete_read_write as read_write
from serverware import authority_index_heads as heads
from serverware import authority_index_projection as projection
from serverware import authority_indexed_mutation as indexed
from serverware import authority_query_reads as reads
from serverware import authority_recovery_terminal as terminal
from serverware import authority_revocation_wire as wire
from serverware.authority_index_contract import CountedNode, IndexLeaf, OpaqueSubtree, empty_node
from serverware.authority_query_read_work import MAX_INPUT_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES

core, primary, contract = terminal.core, terminal.primary, terminal.contract
OPERATION = terminal.recovery.INVALIDATE
SCHEMA = "serverware.recoveryInvalidationProof/v1"
_FIELDS = frozenset({"schema", "context", "selectedRows", "beforeProofs", "indexInputs"})
_CONTEXT = frozenset({"sourceRevision", "operation", "arguments", "requestDigest", "databaseNow",
    "businessBeforeRoots", "authorizationBeforeRoots", "countedBeforeHeads",
    "terminalRetentionSeconds", "maximumRetained"})
_ROOT = frozenset({"table", "rootRevision", "rootDigest", "leafCount"})
_HEAD = frozenset({"indexId", "indexRevision", "rootDigest", "leafCount"})
_INDEX = _HEAD | {"frontier"}


class RecoveryInvalidationError(core.TransitionKernelError):
    pass


@dataclass(frozen=True, slots=True)
class _Computation:
    """Same-invocation outputs only; never accepted in place of originals."""

    queries: tuple
    mutations: tuple
    affected: bool
    write: indexed.IndexedMutationResult
    counted_after_heads: tuple


def _require(value):
    if not value:
        raise RecoveryInvalidationError("recovery invalidation originals differ from their source contract")


def _object(value, fields):
    _require(type(value) is dict and set(value) == fields)


def _own(value, work):
    batch._SharedLedger(work)
    return reads._CopyBudget(work).copy(value)


def _same(left, right, work):
    # Canonical comparison keeps booleans distinct from numeric commitments.
    first, second = work.wire(left), work.wire(right)
    work.charge(input_bytes=len(first) + len(second))
    _require(first == second)


def context_document(*, arguments, request_digest, database_now, business_before_roots,
        authorization_before_roots, counted_before_heads, terminal_retention_seconds,
        maximum_retained, work):
    """Own the independently supplied context, without claiming its admission."""
    batch._SharedLedger(work)
    _require(type(database_now) is datetime and database_now.tzinfo is timezone.utc)
    for roots in (business_before_roots, authorization_before_roots):
        _require(type(roots) is tuple and len(roots) <= 5
            and all(type(root) is primary.PrimaryRoot for root in roots))
    _require(type(counted_before_heads) is tuple and len(counted_before_heads) == 9
        and all(type(head) is read_write.CompleteReadWriteHead
            and type(head.index_root) is CountedNode for head in counted_before_heads))
    value = _own(dict(sourceRevision=contract.SOURCE_REVISION, operation=OPERATION,
        arguments=arguments, requestDigest=request_digest, databaseNow=database_now.isoformat(),
        businessBeforeRoots=[root.json_projection() for root in business_before_roots],
        authorizationBeforeRoots=[root.json_projection() for root in authorization_before_roots],
        countedBeforeHeads=[dict(indexId=head.index_id, indexRevision=head.index_revision,
            rootDigest=head.index_root.digest, leafCount=head.index_root.count)
            for head in counted_before_heads], terminalRetentionSeconds=terminal_retention_seconds,
        maximumRetained=maximum_retained), work)
    _parts(value, work)
    return value


def _parts(value, work):
    _object(value, _CONTEXT)
    _require(value["sourceRevision"] == contract.SOURCE_REVISION and value["operation"] == OPERATION)
    core.require_digest(value["requestDigest"], "invalidation request")
    _require(type(value["databaseNow"]) is str and len(value["databaseNow"]) <= 40)
    now = datetime.fromisoformat(value["databaseNow"])
    _require(now.tzinfo is timezone.utc and now.isoformat() == value["databaseNow"])
    terminal._settings(now, value["terminalRetentionSeconds"], value["maximumRetained"], work)
    context = core.KernelContext(OPERATION, value["arguments"], (), now, value["requestDigest"])
    terminal._invalidate_arguments(context, work)
    root_sets = []
    source = terminal.contracts.primary_table_contracts(OPERATION)
    for name, kind in (("businessBeforeRoots", "business"), ("authorizationBeforeRoots", "authorization")):
        raw = value[name]
        _require(type(raw) is list and len(raw) <= 5)
        for item in raw:
            _object(item, _ROOT)
        _require(tuple(item["table"] for item in raw) == tuple(item.table for item in source if item.root_class == kind))
        # Constructor checks genuinely hash the canonical empty primary tree.
        work.charge(hashes=(contract.TREE_DEPTH + 1) * len(raw))
        root_sets.append(tuple(primary.PrimaryRoot(item["table"], item["rootRevision"],
            item["rootDigest"], item["leafCount"]) for item in raw))
    raw_heads = value["countedBeforeHeads"]
    _require(type(raw_heads) is list and len(raw_heads) == 9)
    for item in raw_heads:
        _object(item, _HEAD)
    _require(tuple(item["indexId"] for item in raw_heads) == heads._recovery_write_ids(OPERATION))
    table_roots = {root.table: root for roots in root_sets for root in roots}
    for item in raw_heads:
        for name in ("indexRevision", "leafCount"):
            _require(type(item[name]) is int and 0 <= item[name] < 2**63)
        core.require_digest(item["rootDigest"], "invalidation counted head")
        definition = projection._definition(item["indexId"])
        work.prepare_encoding(definition.document(), ensure_ascii=False)
        work.charge(hashes=projection.PROFILE_HASH_WORK + 1)
        profile = projection.profile_for(item["indexId"])
        empty = empty_node(profile, "")
        _require((item["leafCount"] == 0) == (item["rootDigest"] == empty.digest)
            and (item["indexRevision"] != 0 or item["leafCount"] == 0)
            and item["leafCount"] <= table_roots[profile.table].leaf_count)
    return context, root_sets[0], root_sets[1]


def _query(name, table, key, work):
    owned = _own(key, work)
    return core.BoundedQuery(query_id=core.query_program_id(OPERATION, name, table), table=table,
        predicates=tuple(core.QueryPredicate(column, "eq", value) for column, value in sorted(owned.items())),
        order_by=tuple(core.QueryOrder(column) for column in sorted(owned)), maximum_rows=1,
        absent_key=owned)


def target_query(arguments, *, work):
    """The sole initial read is source-fixed from the original request IDs."""
    arguments = _own(arguments, work)
    _object(arguments, terminal._INVALIDATE_FIELDS)
    identity = terminal._text(arguments["recovery_id"], work, 128)
    _require(arguments["ceremony_type"] in ("replacement-registration", "lost-active-key-decommission"))
    table = terminal.CEREMONIES if arguments["ceremony_type"] == "replacement-registration" else terminal.REVOCATIONS
    return _query("invalidation_target", table, {"id": identity}, work)


def _following(context, business, authorization, selected, proof, work):
    query = target_query(context.arguments, work=work)
    _require(type(selected) is dict and selected.get("table") == query.table)
    _same(selected.get("key"), query.absent_key, work)
    target_context = core.KernelContext(OPERATION, context.arguments, (selected,),
        context.database_now, context.request_digest)
    owned = terminal._membership(target_context, business, authorization, (proof,), work)
    target = owned.selected_rows[0]
    live = terminal.LIVE if query.table == terminal.CEREMONIES else ("prepared",)
    if not target["present"] or target["row"]["status"] not in live:
        return ()
    queries = []
    if query.table == terminal.CEREMONIES:
        identity = terminal._text(target["row"]["challenge_id"], work)
        queries.append(_query("invalidation_challenge", terminal.retention.CHALLENGE_TABLE, {"id": identity}, work))
    queries.append(_query("invalidation_audit", terminal.capacity.OUTBOX_TABLE,
        {"id": "webauthn-recovery-burned:" + owned.arguments["recovery_id"]}, work))
    queries.append(_query("invalidation_capacity", terminal.capacity.AGGREGATE_TABLE,
        {"aggregate_id": terminal.capacity.AGGREGATE_ID}, work))
    return tuple(queries)


def followup_queries(*, context, target_selected, target_proof, work):
    """Reauthenticate the target; its row alone cannot select secondary reads."""
    owned = _own(dict(context=context, selected=target_selected, proof=target_proof), work)
    call, business, authorization = _parts(owned["context"], work)
    return _following(call, business, authorization, owned["selected"], owned["proof"], work)


def _index_inputs(values, expected_ids, before, work):
    _require(type(values) is list and len(values) == len(expected_ids))
    result = []
    for value, identity in zip(values, expected_ids):
        _object(value, _INDEX)
        _same({name: value[name] for name in _HEAD}, before[identity], work)
        raw = value["frontier"]
        _require(type(raw) is list and len(raw) <= read_write._source_sizes(contract.operation_spec(OPERATION))[2])
        records = []
        for record in raw:
            _require(type(record) is dict)
            if record.get("kind") == "leaf":
                _object(record, {"kind", "key", "primaryKeyDigest", "primaryRowDigest"})
                records.append(IndexLeaf(record["key"], record["primaryKeyDigest"], record["primaryRowDigest"]))
            else:
                _object(record, {"kind", "prefix", "digest", "count"})
                _require(record["kind"] == "opaque")
                records.append(OpaqueSubtree(record["prefix"], record["digest"], record["count"]))
        result.append(indexed.IndexedMutationInput(identity, value["indexRevision"],
            CountedNode(value["rootDigest"], value["leafCount"]), tuple(records)))
    return tuple(result)


def _evaluate(document, work):
    _object(document, _FIELDS)
    _require(document["schema"] == SCHEMA)
    context, business, authorization = _parts(document["context"], work)
    selected, proofs = document["selectedRows"], document["beforeProofs"]
    _require(type(selected) is list and 1 <= len(selected) <= 4
        and type(proofs) is list and len(proofs) == len(selected))
    first = target_query(context.arguments, work=work)
    queries = (first, *_following(context, business, authorization, selected[0], proofs[0], work))
    _require(len(selected) == len(queries))
    for row, query in zip(selected, queries):
        _require(type(row) is dict and row.get("table") == query.table)
        _same(row.get("key"), query.absent_key, work)
    call = core.KernelContext(OPERATION, context.arguments, tuple(selected),
        context.database_now, context.request_digest)
    effects = terminal.evaluate_row(phase="invalidate", context=call,
        business_before_roots=business, authorization_before_roots=authorization,
        before_proofs=tuple(proofs), terminal_retention_seconds=document["context"]["terminalRetentionSeconds"],
        maximum_retained=document["context"]["maximumRetained"], work=work)
    expected_ids = tuple(sorted({identity for mutation in effects.mutations
        for identity in projection.index_ids_for_table(mutation["table"])}))
    before = {head["indexId"]: head for head in document["context"]["countedBeforeHeads"]}
    inputs = _index_inputs(document["indexInputs"], expected_ids, before, work)
    ledger = batch._SharedLedger(work)
    write = indexed.evaluate_indexed_primary_batch(
        table_contracts=terminal.contracts.primary_table_contracts(OPERATION),
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=tuple(selected), before_proofs=tuple(proofs), mutations=effects.mutations,
        index_inputs=inputs, limits=read_write._write_limits(contract.operation_spec(OPERATION), ledger))
    ledger.charge(hashes=write.metrics.hashes, input_bytes=write.metrics.input_bytes,
        json_nodes=write.metrics.primary.json_nodes)
    after = dict(before)
    for head in write.after_heads:
        after[head.index_id] = dict(indexId=head.index_id, indexRevision=head.index_revision,
            rootDigest=head.index_root.digest, leafCount=head.index_root.count)
    return _Computation(queries, effects.mutations, effects.affected, write,
        tuple(_own(after[identity], work) for identity in sorted(after)))


def produce_originals(*, context, selected_rows, before_proofs, index_inputs, work):
    """Encode actual raw evidence only after real semantic and proof computation.

    Inputs are JSON graphs from the acquisition owner, never prior-success
    carriers. selected_rows follow target then the derived query order.
    index_inputs contain the original head descriptors and raw sparse records.
    """
    _require(type(selected_rows) is tuple and type(before_proofs) is tuple
        and 1 <= len(selected_rows) <= 4 and len(before_proofs) == len(selected_rows)
        and type(index_inputs) is tuple and len(index_inputs) <= 9)
    owned = _own(dict(schema=SCHEMA, context=context, selectedRows=list(selected_rows),
        beforeProofs=list(before_proofs), indexInputs=list(index_inputs)), work)
    _evaluate(owned, work)
    raw = work.wire(owned)
    _require(len(raw) <= MAX_INPUT_BYTES)
    return raw


def replay_originals(raw, *, expected_context, work):
    """Compare independent context before repeating genuine raw proof engines."""
    expected = _own(expected_context, work)
    _parts(expected, work)
    document = wire._decode_object(raw, work=work, maximum_bytes=MAX_INPUT_BYTES,
        maximum_nodes=MAX_JSON_NODES, maximum_depth=MAX_JSON_DEPTH)
    owned = _own(document, work)
    _object(owned, _FIELDS)
    canonical = work.wire(owned)
    work.charge(input_bytes=len(raw) + len(canonical))
    _require(raw == canonical)
    _same(owned["context"], expected, work)
    return _evaluate(owned, work)
