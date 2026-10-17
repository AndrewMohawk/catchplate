"""Independent raw JIT assertion replay relative to separately admitted pins.

The actual request, assertion policy, cutoff and complete original root/head
inventory are independent inputs. Embedded copies are only records which must
match them. Seven genuine memberships precede real ES256 verification; only
that computation selects the eighth receipt-absence key. The real inline and
indexed engines rederive all three mutations and every affected counted root.

No SQL, key lookup, clock, signing, current-root admission, successful DTO,
query-program override or registry activation exists here. Returned values are
relative observations only. The original generic raw/proof/work ceilings stay
unchanged. They do not establish worst-case capacity for all source-valid
large business rows; the physical producer's capacity gap remains separate.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from catchplate import authority_index_projection as projection
from catchplate import authority_jit_assertion_acquisition as source
from catchplate import authority_radix_mutation as primary
from catchplate import authority_revocation_wire as wire
from catchplate.authority_index_contract import CountedNode, IndexLeaf, OpaqueSubtree, empty_node
from catchplate.authority_query_read_work import (
    _ValidationWork, QueryReadValidationMetrics, MAX_INPUT_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES,
)


OPERATION = source.OPERATION
_ROOT = frozenset({"table", "rootRevision", "rootDigest", "leafCount"})
_HEAD = frozenset({"indexId", "indexRevision", "rootDigest", "leafCount"})
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class JitAssertionReplayError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class JitAssertionReplayObservation:
    """Same-call outputs only; no API accepts this object as evidence."""

    result: dict
    mutations: tuple
    indexed_result: source.indexed.IndexedMutationResult
    queries: tuple
    query_reads: tuple
    metrics: QueryReadValidationMetrics


def _require(value):
    if not value:
        raise JitAssertionReplayError("JIT raw replay differs from its independent source inputs")


def _object(value, fields):
    _require(type(value) is dict and len(value) == len(fields)
        and all(type(name) is str for name in value) and set(value) == fields)


def _own(value, work):
    return source.reads._CopyBudget(work).copy(value)


def _same(left, right, work):
    # Canonical equality deliberately distinguishes booleans and integers.
    first, second = work.wire(left), work.wire(right)
    work.charge(input_bytes=len(first) + len(second))
    _require(first == second)


def _anchors(*, request, assertion_policy, business_before_roots,
        authorization_before_roots, counted_before_heads, database_cutoff_us, work):
    _require(type(work) is _ValidationWork)
    source.batch._SharedLedger(work)
    _require(type(database_cutoff_us) is int and 0 <= database_cutoff_us < 2**63
        and type(counted_before_heads) is tuple and len(counted_before_heads) == 12)
    roots = []
    for values in (business_before_roots, authorization_before_roots):
        _require(type(values) is tuple and len(values) <= 8
            and all(type(item) is primary.PrimaryRoot for item in values))
        records = []
        for item in values:
            work.prepare_copy((item.table, item.root_revision, item.root_digest, item.leaf_count))
            work.charge(json_nodes=9)
            records.append(item.json_projection())
        roots.append(records)
    heads = []
    for item in counted_before_heads:
        _require(type(item) is source.read_write.CompleteReadWriteHead
            and type(item.index_root) is CountedNode)
        work.prepare_copy((item.index_id, item.index_revision, item.index_root.digest, item.index_root.count))
        work.charge(json_nodes=9)
        heads.append(dict(indexId=item.index_id, indexRevision=item.index_revision,
            rootDigest=item.index_root.digest, leafCount=item.index_root.count))
    # All caller graphs are detached before any request/profile/proof hash.
    expected = _own(dict(request=request, assertionPolicy=assertion_policy,
        businessBeforeRoots=roots[0], authorizationBeforeRoots=roots[1],
        countedBeforeHeads=heads, databaseCutoffUs=database_cutoff_us), work)
    source._request(expected["request"], work)
    source._policy(expected["assertionPolicy"])
    contracts = source.primary_contract.primary_table_contracts(OPERATION)
    _require(len(contracts) == 8)
    rebuilt = []
    for name, kind in (("businessBeforeRoots", "business"), ("authorizationBeforeRoots", "authorization")):
        values = expected[name]
        _require(tuple(item["table"] for item in values)
            == tuple(item.table for item in contracts if item.root_class == kind))
        for item in values:
            _object(item, _ROOT)
        work.charge(hashes=(source.authority.TREE_DEPTH + 2) * len(values))
        rebuilt.append(source.batch._roots(values))
    _require(tuple(item["indexId"] for item in heads) == source.heads._jit_receipt_ids())
    by_table = {root.table: root for group in rebuilt for root in group}
    for item in expected["countedBeforeHeads"]:
        _object(item, _HEAD)
        _require(type(item["indexRevision"]) is int and 0 <= item["indexRevision"] < 2**63
            and type(item["leafCount"]) is int and 0 <= item["leafCount"] < 2**63)
        source.shape._digest(item["rootDigest"])
        definition = projection._definition(item["indexId"])
        work.prepare_encoding(definition.document(), ensure_ascii=False)
        work.charge(hashes=projection.PROFILE_HASH_WORK + 1)
        profile = projection.profile_for(item["indexId"])
        empty = empty_node(profile, "")
        _require((item["leafCount"] == 0) == (item["rootDigest"] == empty.digest)
            and (item["indexRevision"] != 0 or item["leafCount"] == 0)
            and item["leafCount"] <= by_table[profile.table].leaf_count)
    try:
        now = _EPOCH + timedelta(microseconds=database_cutoff_us)
    except OverflowError as exc:
        raise JitAssertionReplayError("JIT original cutoff is outside the datetime source domain") from exc
    return expected, rebuilt[0], rebuilt[1], now


def _source_bindings(work):
    spec = source.authority.operation_spec(OPERATION)
    _require((spec["maximumQueryRows"], spec["maximumMutations"], spec["maximumWorkUnits"])
        == (16, 3, 512) and spec["globalAuditCapacity"] is False)
    values = dict(schema=source.SCHEMA, sourceRevision=source.authority.SOURCE_REVISION,
        operation=OPERATION, operationManifestDigest=source.authority.OPERATION_MANIFEST_DIGEST)
    for field, domain, manifest in (
            ("queryManifestDigest", "catchplate.policyAuthorityQueryManifest/v1",
                source.primary_contract.source_query_manifest()),
            ("authorizationManifestDigest", "catchplate.policyAuthorityAuthorizationManifest/v1",
                source.primary_contract.source_authorization_manifest())):
        size, _ = work.prepare_encoding(manifest)
        domain_size = work.prepare_utf8(domain)
        work.charge(hashes=1, input_bytes=16 + domain_size + size)
        values[field] = source.primary_contract._manifest_digest(domain, manifest)
    values["handlerContractDigest"] = source._handler_contract_on_work(work)
    return values, spec


def _inventory(document, work):
    selected, proofs = document["selectedRows"], document["beforeProofs"]
    _require(type(selected) is list and len(selected) == 8
        and type(proofs) is list and len(proofs) == 8
        and type(document["queryReads"]) is list and len(document["queryReads"]) == 8
        and type(document["writeFrontiers"]) is list and len(document["writeFrontiers"]) == 12)
    by_table, by_address, previous = {}, {}, None
    for row in selected:
        _object(row, source.reads._SELECTED_FIELDS)
        _require(type(row["table"]) is str and 1 <= len(row["table"]) <= 128
            and row["table"] not in by_table and row["contractSelector"] is None)
        source.shape._digest(row["keyDigest"])
        address = row["table"], row["keyDigest"]
        _require(previous is None or previous < address)
        previous = address
        by_table[row["table"]] = row
    for proof in proofs:
        _require(type(proof) is dict and type(proof.get("table")) is str
            and 1 <= len(proof["table"]) <= 128)
        source.shape._digest(proof.get("keyDigest"))
        address = proof["table"], proof["keyDigest"]
        _require(address not in by_address and proof["table"] in by_table
            and by_table[proof["table"]]["keyDigest"] == proof["keyDigest"])
        by_address[address] = proof
    work.charge(json_nodes=2 * (len(by_table) + len(by_address)))
    return by_table, by_address


def _stage(queries, rows, proofs, business, authorization, work):
    queries = source.reads._snapshot_queries(OPERATION, queries, work=work)
    selected, before = [], []
    for query in queries:
        _require(query.table in rows)
        row = rows[query.table]
        _same(row["key"], query.absent_key, work)
        selected.append(row)
        before.append(proofs[(row["table"], row["keyDigest"])])
    # Genuine membership/absence precedes creation of bookkeeping records.
    work.prepare_copy((selected, before))
    ordered = tuple(sorted(selected, key=lambda row: (row["table"], row["keyDigest"])))
    checked = source.batch.primary.evaluate_primary_radix_memberships(
        table_contracts=source.primary_contract.primary_table_contracts(OPERATION),
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=ordered, before_proofs=tuple(before),
        limits=source.batch._primary_limits(source.authority.operation_spec(OPERATION),
            len(ordered), source.batch._SharedLedger(work)))
    metrics = checked.result.metrics
    work.charge(hashes=metrics.hash_work, input_bytes=metrics.input_bytes, json_nodes=metrics.json_nodes)
    _require(checked.result.business_after_roots == business
        and checked.result.authorization_after_roots == authorization
        and metrics.mutations == 0 and metrics.recomputed_ancestors == 0)
    checked_rows = {row["table"]: row for row in checked.selected_rows}
    records = []
    for query in queries:
        row = checked_rows[query.table]
        records.append(source.reads._capture_query_read(OPERATION, query, resolved_query=query,
            ordered_selected_rows=(row,), returned_row_count=int(row["present"]), work=work))
    _, records = source.reads._validate_query_reads(OPERATION, queries=queries,
        query_reads=tuple(records), selected_rows=checked.selected_rows, work=work)
    return checked.selected_rows, checked.before_proofs, queries, records


def _frontiers(values, heads, spec, work):
    identities = source.heads._jit_receipt_ids()
    _require(len(values) == len(heads) == len(identities) == 12)
    maximum = source.read_write._source_sizes(spec)[2]
    inputs, total = [], 0
    for value, head, identity in zip(values, heads, identities, strict=True):
        _object(value, frozenset({"indexId", "frontier"}))
        _require(type(value["indexId"]) is str and value["indexId"] == head["indexId"] == identity
            and type(value["frontier"]) is list and len(value["frontier"]) <= maximum)
        total += len(value["frontier"])
        _require(total <= MAX_JSON_NODES // 9)
        work.prepare_copy(value)
        records = []
        for raw in value["frontier"]:
            _require(type(raw) is dict)
            if raw.get("kind") == "leaf":
                _object(raw, frozenset({"kind", "key", "primaryKeyDigest", "primaryRowDigest"}))
                records.append(IndexLeaf(raw["key"], raw["primaryKeyDigest"], raw["primaryRowDigest"]))
            else:
                _object(raw, frozenset({"kind", "prefix", "digest", "count"}))
                _require(raw["kind"] == "opaque")
                records.append(OpaqueSubtree(raw["prefix"], raw["digest"], raw["count"]))
        inputs.append(source.indexed.IndexedMutationInput(identity, head["indexRevision"],
            CountedNode(head["rootDigest"], head["leafCount"]), tuple(records)))
    return tuple(inputs)


def replay_originals(raw_bytes, *, request, assertion_policy, business_before_roots,
        authorization_before_roots, counted_before_heads, database_cutoff_us, work):
    """Independently recompute originals; expected anchors are not enrolled here."""
    expected, business, authorization, now = _anchors(request=request, assertion_policy=assertion_policy,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        counted_before_heads=counted_before_heads, database_cutoff_us=database_cutoff_us, work=work)
    decoded = wire._decode_object(raw_bytes, work=work, maximum_bytes=MAX_INPUT_BYTES,
        maximum_nodes=MAX_JSON_NODES, maximum_depth=MAX_JSON_DEPTH)
    document = _own(decoded, work)
    _object(document, source.FIELDS)
    canonical = work.wire(document)
    work.charge(input_bytes=len(raw_bytes) + len(canonical))
    _require(type(raw_bytes) is bytes and canonical == raw_bytes)
    bindings, spec = _source_bindings(work)
    for name, value in (*bindings.items(), *expected.items()):
        _same(document[name], value, work)
    rows, proofs = _inventory(document, work)
    source.batch._selected_envelopes(document, source.batch._SharedLedger(work))
    arguments = expected["request"]["arguments"]
    request_digest = expected["request"]["requestDigest"]
    first = _stage(source.receipt.queries(arguments), rows, proofs, business, authorization, work)
    _require(len(first[2]) == 7)
    context = source.core.KernelContext(OPERATION, arguments, first[0], now,
        request_digest, query_reads=first[3])
    actual_receipt = source.receipt.receipt_from_context(context,
        assertion_policy=expected["assertionPolicy"], work=work)
    second = _stage((source.receipt.receipt_query(actual_receipt["assertion_receipt_digest"]),),
        rows, proofs, business, authorization, work)
    queries, records = first[2] + second[2], first[3] + second[3]
    selected = tuple(sorted(first[0] + second[0], key=lambda row: (row["table"], row["keyDigest"])))
    before = first[1] + second[1]
    _require(len(selected) == 8 and set(rows) == {query.table for query in queries})
    _, records = source.reads._validate_query_reads(OPERATION, queries=queries,
        query_reads=records, selected_rows=selected, work=work)
    _same(document["queryReads"], source._encode_reads(records, work), work)
    context = source.core.KernelContext(OPERATION, arguments, selected, now,
        request_digest, query_reads=records)
    transition = source.receipt.transition(context, assertion_policy=expected["assertionPolicy"], work=work)
    _require(len(transition.mutations) == 3)
    units = source.capacity.transition_work_units(operation=OPERATION,
        query_work_units=sum(query.work_units for query in queries),
        kernel_work_units=transition.work_units, mutations=transition.mutations)
    source.capacity.validate_transition_work_units(OPERATION, units, transition.mutations)
    work.prepare_copy(transition.mutations)
    mutations = tuple(sorted(transition.mutations,
        key=lambda row: (row["table"], row["keyDigest"], row["operation"])))
    inputs = _frontiers(document["writeFrontiers"], expected["countedBeforeHeads"], spec, work)
    indexed_result = source.indexed.evaluate_indexed_primary_batch(
        table_contracts=source.primary_contract.primary_table_contracts(OPERATION),
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=selected, before_proofs=before, mutations=mutations, index_inputs=inputs,
        limits=source.read_write._write_limits(spec, source.batch._SharedLedger(work)))
    work.charge(hashes=indexed_result.metrics.hashes, input_bytes=indexed_result.metrics.input_bytes,
        json_nodes=indexed_result.metrics.primary.json_nodes)
    _require(tuple(head.index_id for head in indexed_result.before_heads) == source.heads._jit_receipt_ids())
    result = _own(transition.result, work)
    return JitAssertionReplayObservation(result, mutations, indexed_result, queries, records, work.metrics)
