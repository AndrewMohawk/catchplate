"""Original-only indexed replay of protected activation-delivery consumption.

The actual private transition replays current reads and pending-token possession.
This adapter then evaluates its three real mutations against original primary
and counted-index proofs. No supplied transition, claimed consumed flag, signed
activation ACK or previous success substitutes for those inputs. Root/population,
caller, completion provenance and database-clock admission belong to the composing
owner. These derived commitments neither execute SQL nor release a token.
"""
from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Callable

from catchplate import authority_complete_read_write as combined
from catchplate import authority_indexed_mutation as indexed
from catchplate import authority_index_projection as projection
from catchplate import authority_oidc_session_activation_writes as head_wire
from catchplate import authority_transition_oidc_session_activation_delivery as consumption
from catchplate.authority_index_contract import CountedNode, IndexLeaf, OpaqueSubtree, I64_MAX
from catchplate.authority_primary_contract import primary_table_contracts


registration, reads = consumption.registration, consumption.reads
batch, core = reads.batch, consumption.core
OPERATION = "oidc.session.activation-delivery.consume"
SCHEMA = "catchplate.oidcSessionActivationDeliveryWriteProof/v1"
IDENTITY_DOMAIN = "catchplate.oidcSessionActivationDeliveryWriteProofIdentity/v1"
TRANSITION_SCHEMA = "catchplate.oidcSessionActivationDeliveryIndexedTransition/v1"
TRANSITION_DOMAIN = "catchplate.oidcSessionActivationDeliveryIndexedTransitionIdentity/v1"
MAX_WRITE_PROOF_BYTES = batch.MAX_TOTAL_INPUT_BYTES
MAX_TRANSITION_BYTES = registration.authority.MAX_RESULT_BYTES
MAX_NODES, MAX_DEPTH = batch.MAX_TOTAL_JSON_NODES, 8
HEAD_COUNT, WRITE_COUNT = 7, 5
_HEAD_FIELDS = frozenset({"indexId", "indexRevision", "rootDigest", "leafCount"})
_DOCUMENT_FIELDS = frozenset({"schema", "sourceRevision", "operation", "requestDigest",
    "beforeHeads", "writeFrontiers"})


class OidcSessionActivationDeliveryWriteError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class _DecodedWrites:
    request_digest: str
    counted_before_heads: tuple
    write_inputs: tuple


@dataclass(frozen=True, slots=True, repr=False)
class _ReplayedWrites:
    transition: core.KernelTransition
    write_proof_bytes: bytes
    write_proof_digest: str
    transition_bytes: bytes
    transition_digest: str
    business_after_roots: tuple
    authorization_after_roots: tuple
    counted_after_heads: tuple
    live: Callable[[], int]
    valid_until_epoch_ns: int


@dataclass(frozen=True, slots=True, repr=False)
class _HistoricalReplayedWrites:
    transition: core.KernelTransition
    write_proof_bytes: bytes
    write_proof_digest: str
    transition_bytes: bytes
    transition_digest: str
    business_after_roots: tuple
    authorization_after_roots: tuple
    counted_after_heads: tuple
    live: Callable[[], int]
    valid_until_epoch_ns: int
    historical_plan_interval: tuple


def _fail(message):
    raise OidcSessionActivationDeliveryWriteError(message)


def _identities():
    # consumed_at does not remove a delivery from any of its five indexes.
    # Its primary row digest changes, so all five still require real writes.
    writes = tuple(sorted(projection.index_ids_for_table("oidc_session_activation_deliveries")))
    heads = tuple(sorted((*writes, "oidc_session_token_digest", "webauthn_publication_status")))
    if len(writes) != WRITE_COUNT or len(set(heads)) != HEAD_COUNT:
        _fail("delivery consumption counted-profile inventory changed")
    return heads, writes


def _heads(values):
    expected, _ = _identities()
    if type(values) is not list or len(values) != HEAD_COUNT:
        _fail("delivery consumption needs its exact seven independent heads")
    result = []
    for identity, value in zip(expected, values):
        registration._closed(value, _HEAD_FIELDS, "delivery consumption head")
        if type(value["indexId"]) is not str or value["indexId"] != identity:
            _fail("delivery consumption heads are not the fixed sorted union")
        revision = registration._integer(value["indexRevision"], "index revision", 0, I64_MAX)
        count = registration._integer(value["leafCount"], "index count", 0, I64_MAX)
        digest = registration._digest(value["rootDigest"])
        if revision == 0 and count != 0:
            _fail("delivery consumption head has nonempty zero revision")
        result.append(combined.CompleteReadWriteHead(identity, revision, CountedNode(digest, count)))
    return tuple(result)


def _raw_document(request_digest, counted_before_heads, write_inputs):
    if (type(counted_before_heads) is not tuple or len(counted_before_heads) != HEAD_COUNT
            or type(write_inputs) is not tuple or len(write_inputs) != WRITE_COUNT):
        _fail("delivery consumption write originals have the wrong fixed inventory")
    # Reuse only the operation-neutral closed head record helper, not the
    # activation codec's thirteen-head inventory or semantic replay.
    heads = [head_wire._head_record(head) for head in counted_before_heads]
    maximum = combined._source_sizes(registration.authority.operation_spec(OPERATION))[2]
    frontiers, total = [], 0
    for item in write_inputs:
        if (type(item) is not indexed.IndexedMutationInput or type(item.index_root) is not CountedNode
                or type(item.frontier) is not tuple or len(item.frontier) > maximum):
            _fail("delivery consumption write frontier exceeds its fixed source ceiling")
        total += len(item.frontier)
        if total > MAX_NODES // 9:
            _fail("delivery consumption frontier inventory exceeds the shared node ceiling")
        descriptor = head_wire._head_record(combined.CompleteReadWriteHead(
            item.index_id, item.index_revision, item.index_root))
        if sum(head == descriptor for head in heads) != 1:
            _fail("delivery consumption frontier head differs from its original head")
        frontiers.append({"indexId": item.index_id, "frontier": combined._raw_records(item.frontier)})
    return {"schema": SCHEMA, "sourceRevision": registration.authority.SOURCE_REVISION,
        "operation": OPERATION, "requestDigest": request_digest,
        "beforeHeads": heads, "writeFrontiers": frontiers}


def _document(value):
    registration._closed(value, _DOCUMENT_FIELDS, "delivery consumption write original")
    if (value["schema"] != SCHEMA or value["operation"] != OPERATION
            or value["sourceRevision"] != registration.authority.SOURCE_REVISION):
        _fail("delivery consumption write original source or operation differs")
    request = registration._digest(value["requestDigest"])
    heads = _heads(value["beforeHeads"])
    by_id = {head.index_id: head for head in heads}
    _, identities = _identities()
    values = value["writeFrontiers"]
    if type(values) is not list or len(values) != WRITE_COUNT:
        _fail("delivery consumption frontier inventory is not exact")
    maximum = combined._source_sizes(registration.authority.operation_spec(OPERATION))[2]
    total, inputs = 0, []
    for identity, item in zip(identities, values):
        registration._closed(item, frozenset({"indexId", "frontier"}), "delivery consumption frontier")
        if (type(item["indexId"]) is not str or item["indexId"] != identity
                or type(item["frontier"]) is not list or len(item["frontier"]) > maximum):
            _fail("delivery consumption frontiers are not source sorted and bounded")
        total += len(item["frontier"])
        if total > MAX_NODES // 9:
            _fail("delivery consumption frontiers exceed their aggregate node ceiling")
        records = []
        for record in item["frontier"]:
            if type(record) is not dict or type(record.get("kind")) is not str:
                _fail("delivery consumption frontier record is not closed")
            if record["kind"] == "leaf":
                registration._closed(record, frozenset({"kind", "key", "primaryKeyDigest", "primaryRowDigest"}),
                    "delivery consumption index leaf")
                records.append(IndexLeaf(record["key"], record["primaryKeyDigest"], record["primaryRowDigest"]))
            elif record["kind"] == "opaque":
                registration._closed(record, frozenset({"kind", "prefix", "digest", "count"}),
                    "delivery consumption opaque subtree")
                records.append(OpaqueSubtree(record["prefix"], record["digest"], record["count"]))
            else:
                _fail("delivery consumption frontier kind is not admitted")
        head = by_id[identity]
        inputs.append(indexed.IndexedMutationInput(identity, head.index_revision, head.index_root, tuple(records)))
    return _DecodedWrites(request, heads, tuple(inputs))


def _encode_on_work(*, request_digest, counted_before_heads, write_inputs, work):
    """Encode original proof data only; a canonical codec is not admission."""
    ledger = batch._SharedLedger(work)
    raw = _raw_document(request_digest, counted_before_heads, write_inputs)
    owned = batch._JSONCapture(ledger, maximum_bytes=MAX_WRITE_PROOF_BYTES).visit(raw)
    _document(owned)
    result = registration._wire(owned, work)
    if len(result) > MAX_WRITE_PROOF_BYTES:
        _fail("delivery consumption write original exceeds its fixed byte ceiling")
    return result


def _decode_on_work(original, *, work):
    batch._SharedLedger(work)
    value = registration.evidence.wire._decode_object(original, work=work,
        maximum_bytes=MAX_WRITE_PROOF_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    decoded = _document(value)
    canonical = registration._wire(value, work)
    work.charge(input_bytes=len(original) + len(canonical))
    if original != canonical:
        _fail("delivery consumption write original is not canonical")
    return decoded


def _replay_originals_on_work(context, *, old_token_bytes, expected_delivery_id,
        expected_user_id, expected_session_id, expected_credential_id,
        expected_credential_record_id, expected_challenge_id, authn_policy, trust_policy,
        business_before_roots, authorization_before_roots, before_proofs,
        read_heads, query_frontiers, expected_counted_heads, write_proof_bytes,
        live_window, transport_deadline_ns, work, historical_plan_interval, _current=None):
    """Derive actual current consumption and indexed effects from originals.

    All roots, counted heads, policy and subject expectations are independent
    inputs, not learned from the write proof. No successful transition enters.
    """
    ledger = batch._SharedLedger(work)
    historical = (None if historical_plan_interval is None
        else consumption._historical_interval(historical_plan_interval))
    if historical is not None and _current is not None:
        _fail("historical consume replay cannot select a live delivery continuation")
    if (type(context) is not core.KernelContext or context.operation != OPERATION
            or context.verified_webauthn_evidence is not None
            or type(expected_counted_heads) is not tuple or len(expected_counted_heads) != HEAD_COUNT
            or type(write_proof_bytes) is not bytes or not 2 <= len(write_proof_bytes) <= MAX_WRITE_PROOF_BYTES):
        _fail("delivery consumption indexed replay input inventory differs")
    old = consumption.assertion._token(old_token_bytes, work)
    window = consumption.assertion.clock._validate(live_window)
    registration._integer(transport_deadline_ns, "delivery consumption inherited deadline", 1)
    bound, database_now = min(window[4], transport_deadline_ns), context.database_now
    scope = consumption.assertion._Capture(ledger,
        maximum_bytes=consumption.assertion.MAX_CONTEXT_BYTES).visit({
            "delivery": expected_delivery_id, "user": expected_user_id, "session": expected_session_id,
            "credential": expected_credential_id, "record": expected_credential_record_id,
            "challenge": expected_challenge_id, "policy": authn_policy, "trust": trust_policy,
            "heads": list(expected_counted_heads)})
    owned, records, heads, frontiers = reads._capture(arguments=context.arguments,
        request_digest=context.request_digest, selected_rows=context.selected_rows, query_reads=context.query_reads,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        before_proofs=before_proofs, read_heads=read_heads, query_frontiers=query_frontiers, work=work)
    expected = _heads(scope["heads"])
    last_epoch, last_monotonic = window[0], window[2]
    full = None

    def live():
        nonlocal last_epoch, last_monotonic
        checked = last_epoch if full is None else full.live()
        now = consumption.assertion.clock._check_on_work(window, work=work)
        monotonic = registration.evidence.production._callback(work, time.monotonic_ns)
        registration._integer(monotonic, "delivery consumption monotonic sample", 1)
        if (now < checked or now < last_epoch or monotonic < last_monotonic or monotonic >= bound
                or (historical is None and full is not None and now >= full.valid_until_epoch_ns)):
            _fail("delivery consumption indexed replay expired or clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    live = consumption.delivery._join_current(live, _current, work)
    live()
    decoded = _decode_on_work(write_proof_bytes, work=work)
    registration._same(decoded.request_digest, owned["request_digest"], work,
        "delivery consumption write request identity")
    registration._same([head_wire._head_record(head) for head in decoded.counted_before_heads],
        scope["heads"], work, "delivery consumption independent counted heads")
    by_id = {head.index_id: head for head in expected}
    if len(heads) != HEAD_COUNT or {head.index_id for head in heads} != set(by_id):
        _fail("delivery consumption reads do not cover every write/read head")
    for head in heads:
        admitted = by_id[head.index_id]
        if head.index_revision != admitted.index_revision or head.index_root != admitted.index_root:
            _fail("delivery consumption read head differs from its independently admitted head")
    live()
    current = core.KernelContext(OPERATION, owned["arguments"], owned["selected_rows"], database_now,
        owned["request_digest"], query_reads=records)
    # These two source-fixed workers receive original inputs, not a supplied
    # transition or callback. Historical expiry remains algebraic metadata.
    worker = (consumption._full_transition_with_liveness_on_work if historical is None
        else consumption._full_transition_historical_on_work)
    # Pass the upstream guard, not this closure: live() begins calling
    # full.live() after assignment and must never become its own descendant.
    extra = {"_current": _current} if historical is None else {"historical_plan_interval": historical}
    full = worker(current,
        old_token_bytes=old, expected_delivery_id=scope["delivery"], expected_user_id=scope["user"],
        expected_session_id=scope["session"], expected_credential_id=scope["credential"],
        expected_credential_record_id=scope["record"], expected_challenge_id=scope["challenge"],
        authn_policy=scope["policy"], trust_policy=scope["trust"],
        business_before_roots=owned["business_before_roots"], authorization_before_roots=owned["authorization_before_roots"],
        before_proofs=owned["before_proofs"], read_heads=heads, query_frontiers=frontiers,
        live_window=window, transport_deadline_ns=bound, work=work, **extra)
    expected_type = consumption._FullTransition if historical is None else consumption._HistoricalFullTransition
    if type(full) is not expected_type or type(full.transition) is not core.KernelTransition:
        _fail("delivery consumption returned another semantic result family")
    if historical is not None and (full.historical_plan_interval != historical
            or historical[1] > full.valid_until_epoch_ns):
        _fail("historical indexed consumption changed or exceeded its original lifetime")
    live()
    actual = full.transition
    actual_ids = tuple(sorted(identity for table in {item["table"] for item in actual.mutations}
        for identity in projection.index_ids_for_table(table)))
    if actual_ids != tuple(item.index_id for item in decoded.write_inputs):
        _fail("delivery consumption mutations differ from the complete write profile closure")
    # The current read worker genuinely authenticated these same original
    # primary roots and all seven counted heads. Constructors hash empties.
    ledger.charge(hashes=len(owned["business_before_roots"]) + len(owned["authorization_before_roots"]))
    business = batch._roots(owned["business_before_roots"])
    authorization = batch._roots(owned["authorization_before_roots"])
    live()
    calculated = indexed.evaluate_indexed_primary_batch(
        table_contracts=primary_table_contracts(OPERATION), business_before_roots=business,
        authorization_before_roots=authorization, selected_rows=owned["selected_rows"],
        before_proofs=owned["before_proofs"], mutations=actual.mutations, index_inputs=decoded.write_inputs,
        limits=combined._write_limits(registration.authority.operation_spec(OPERATION), ledger))
    ledger.charge(hashes=calculated.metrics.hashes, input_bytes=calculated.metrics.input_bytes,
        json_nodes=calculated.metrics.primary.json_nodes)
    live()
    after = dict(by_id)
    for head in calculated.after_heads:
        after[head.index_id] = combined.CompleteReadWriteHead(head.index_id, head.index_revision, head.index_root)
    after_heads = tuple(after[head.index_id] for head in expected)
    proof_digest = registration.evidence.plan._frame(IDENTITY_DOMAIN, (write_proof_bytes,), work)
    commitment = {"schema": TRANSITION_SCHEMA, "sourceRevision": registration.authority.SOURCE_REVISION,
        "operation": OPERATION, "requestDigest": owned["request_digest"], "writeProofDigest": proof_digest,
        "mutations": list(actual.mutations), "result": actual.result, "workUnits": actual.work_units,
        "businessAfterRoots": [root.json_projection() for root in calculated.primary.business_after_roots],
        "authorizationAfterRoots": [root.json_projection() for root in calculated.primary.authorization_after_roots],
        "countedAfterHeads": [head_wire._head_record(head) for head in after_heads]}
    original = registration._wire(commitment, work)
    if len(original) > MAX_TRANSITION_BYTES:
        _fail("delivery consumption indexed commitment exceeds its source byte ceiling")
    digest = registration.evidence.plan._frame(TRANSITION_DOMAIN, (original,), work)
    live()
    result_type = _ReplayedWrites if historical is None else _HistoricalReplayedWrites
    suffix = () if historical is None else (historical,)
    result = result_type(actual, write_proof_bytes, proof_digest, original, digest,
        calculated.primary.business_after_roots, calculated.primary.authorization_after_roots,
        after_heads, live, full.valid_until_epoch_ns, *suffix)
    live()
    return result


def _replay_on_work(context, *, old_token_bytes, expected_delivery_id,
        expected_user_id, expected_session_id, expected_credential_id,
        expected_credential_record_id, expected_challenge_id, authn_policy, trust_policy,
        business_before_roots, authorization_before_roots, before_proofs,
        read_heads, query_frontiers, expected_counted_heads, write_proof_bytes,
        live_window, transport_deadline_ns, work, _current=None):
    return _replay_originals_on_work(context, old_token_bytes=old_token_bytes,
        expected_delivery_id=expected_delivery_id, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, expected_credential_id=expected_credential_id,
        expected_credential_record_id=expected_credential_record_id, expected_challenge_id=expected_challenge_id,
        authn_policy=authn_policy, trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, expected_counted_heads=expected_counted_heads,
        write_proof_bytes=write_proof_bytes, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, historical_plan_interval=None, _current=_current)


def _replay_historical_on_work(context, *, old_token_bytes, expected_delivery_id,
        expected_user_id, expected_session_id, expected_credential_id,
        expected_credential_record_id, expected_challenge_id, authn_policy, trust_policy,
        business_before_roots, authorization_before_roots, before_proofs,
        read_heads, query_frontiers, expected_counted_heads, write_proof_bytes,
        historical_plan_interval, live_window, transport_deadline_ns, work):
    interval = consumption._historical_interval(historical_plan_interval)
    return _replay_originals_on_work(context, old_token_bytes=old_token_bytes,
        expected_delivery_id=expected_delivery_id, expected_user_id=expected_user_id,
        expected_session_id=expected_session_id, expected_credential_id=expected_credential_id,
        expected_credential_record_id=expected_credential_record_id, expected_challenge_id=expected_challenge_id,
        authn_policy=authn_policy, trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, expected_counted_heads=expected_counted_heads,
        write_proof_bytes=write_proof_bytes, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, historical_plan_interval=interval)
