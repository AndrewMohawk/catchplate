"""Fixed activation write originals and genuine same-call indexed replay.

The codec is ordinary bounded data, not admission. Replay derives the original
assertion's six-mutation kernel itself and checks all thirteen heads against
independent expectations. No supplied transition/result carrier is accepted.
No signing, SQL, currentness, population authority or token delivery occurs.
"""
from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Callable

from serverware import authority_complete_read_write as combined
from serverware import authority_indexed_mutation as indexed
from serverware import authority_index_projection as projection
from serverware import authority_transition_oidc_session_activation as activation
from serverware.authority_index_contract import CountedNode, IndexLeaf, OpaqueSubtree, I64_MAX, empty_node
from serverware.authority_primary_contract import primary_table_contracts


registration, reads = activation.registration, activation.reads
batch, core = reads.batch, activation.core
OPERATION = activation.OPERATION
SCHEMA = "serverware.oidcSessionActivationWriteProof/v1"
IDENTITY_DOMAIN = "serverware.oidcSessionActivationWriteProofIdentity/v1"
TRANSITION_SCHEMA = "serverware.oidcSessionActivationIndexedTransition/v1"
TRANSITION_DOMAIN = "serverware.oidcSessionActivationIndexedTransitionIdentity/v1"
MAX_WRITE_PROOF_BYTES = batch.MAX_TOTAL_INPUT_BYTES
MAX_TRANSITION_BYTES = registration.authority.MAX_RESULT_BYTES
MAX_NODES = batch.MAX_TOTAL_JSON_NODES
MAX_DEPTH = 8
HEAD_COUNT, WRITE_COUNT = 13, 12
_HEAD_FIELDS = frozenset({"indexId", "indexRevision", "rootDigest", "leafCount"})
_DOCUMENT_FIELDS = frozenset({"schema", "sourceRevision", "operation", "requestDigest",
    "beforeHeads", "writeFrontiers"})
_WRITE_TABLES = ("oidc_browser_sessions", "oidc_session_activation_deliveries",
    "webauthn_credentials", "webauthn_challenges")
_READ_ONLY_ID = "webauthn_publication_status"


class OidcSessionActivationWriteError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class _DecodedWrites:
    request_digest: str
    counted_before_heads: tuple[combined.CompleteReadWriteHead, ...]
    write_inputs: tuple[indexed.IndexedMutationInput, ...]


@dataclass(frozen=True, slots=True, repr=False)
class _ReplayedWrites:
    transition: core.KernelTransition
    write_proof_bytes: bytes
    write_proof_digest: str
    transition_bytes: bytes
    transition_digest: str
    business_after_roots: tuple
    authorization_after_roots: tuple
    counted_after_heads: tuple[combined.CompleteReadWriteHead, ...]
    live: Callable[[], int]
    valid_until_epoch_ns: int


@dataclass(frozen=True, slots=True, repr=False)
class _HistoricalReplayedWrites:
    """Historical facts only; live guards current processing, not old expiry."""

    transition: core.KernelTransition
    write_proof_bytes: bytes
    write_proof_digest: str
    transition_bytes: bytes
    transition_digest: str
    business_after_roots: tuple
    authorization_after_roots: tuple
    counted_after_heads: tuple[combined.CompleteReadWriteHead, ...]
    live: Callable[[], int]
    valid_until_epoch_ns: int
    historical_plan_interval: tuple[int, int]


def _fail(message):
    raise OidcSessionActivationWriteError(message)


def _identities():
    writes = tuple(sorted(identity for table in _WRITE_TABLES
        for identity in projection.index_ids_for_table(table)))
    heads = tuple(sorted((*writes, _READ_ONLY_ID)))
    if len(writes) != WRITE_COUNT or len(set(heads)) != HEAD_COUNT:
        _fail("activation source counted-profile inventory changed")
    return heads, writes


def _head_record(head):
    if type(head) is not combined.CompleteReadWriteHead or type(head.index_root) is not CountedNode:
        _fail("activation write head has an unexpected exact type")
    if (type(head.index_id) is not str or not 1 <= len(head.index_id) <= 128
            or type(head.index_revision) is not int or not 0 <= head.index_revision <= I64_MAX
            or type(head.index_root.digest) is not str or len(head.index_root.digest) != 71
            or type(head.index_root.count) is not int or not 0 <= head.index_root.count <= I64_MAX):
        _fail("activation write head scalars are not bounded exact values")
    return {"indexId": head.index_id, "indexRevision": head.index_revision,
        "rootDigest": head.index_root.digest, "leafCount": head.index_root.count}


def _heads(values):
    expected, _ = _identities()
    if type(values) is not list or len(values) != HEAD_COUNT:
        _fail("activation write head inventory is not exact")
    heads = []
    for identity, value in zip(expected, values):
        registration._closed(value, _HEAD_FIELDS, "activation write head")
        if value["indexId"] != identity or type(value["indexId"]) is not str:
            _fail("activation write heads are not the fixed sorted union")
        revision = registration._integer(value["indexRevision"], "index revision", 0, I64_MAX)
        count = registration._integer(value["leafCount"], "index count", 0, I64_MAX)
        digest = registration._digest(value["rootDigest"])
        if revision == 0 and count != 0:
            _fail("activation write head has nonempty zero revision")
        heads.append(combined.CompleteReadWriteHead(identity, revision, CountedNode(digest, count)))
    return tuple(heads)


def _raw_document(request_digest, counted_before_heads, write_inputs):
    """Bound and normalize without hashing, encoding or claiming proof success."""
    if (type(counted_before_heads) is not tuple or len(counted_before_heads) != HEAD_COUNT
            or type(write_inputs) is not tuple or len(write_inputs) != WRITE_COUNT):
        _fail("activation write originals do not have thirteen heads and twelve frontiers")
    heads = [_head_record(head) for head in counted_before_heads]
    maximum = combined._source_sizes(registration.authority.operation_spec(OPERATION))[2]
    frontiers, total = [], 0
    for item in write_inputs:
        if (type(item) is not indexed.IndexedMutationInput or type(item.index_root) is not CountedNode
                or type(item.frontier) is not tuple or len(item.frontier) > maximum):
            _fail("activation write frontier exceeds its fixed source profile")
        total += len(item.frontier)
        if total > MAX_NODES // 9:
            _fail("activation write frontier normalization exceeds the shared node ceiling")
        descriptor = {"indexId": item.index_id, "indexRevision": item.index_revision,
            "rootDigest": item.index_root.digest, "leafCount": item.index_root.count}
        # Compare only bounded scalar descriptors; no encoder/hash can run
        # while a later caller-owned frontier still has not been captured.
        if any(type(descriptor[field]) not in (str, int) for field in _HEAD_FIELDS):
            _fail("activation write frontier head scalars are not exact")
        matches = [head for head in heads if head["indexId"] == descriptor["indexId"]]
        if len(matches) != 1 or matches[0] != descriptor:
            _fail("activation write frontier head differs from its original head")
        frontiers.append({"indexId": item.index_id, "frontier": combined._raw_records(item.frontier)})
    return {"schema": SCHEMA, "sourceRevision": registration.authority.SOURCE_REVISION,
        "operation": OPERATION, "requestDigest": request_digest,
        "beforeHeads": heads, "writeFrontiers": frontiers}


def _document(value, work):
    registration._closed(value, _DOCUMENT_FIELDS, "activation write original")
    if (value["schema"] != SCHEMA or value["operation"] != OPERATION
            or value["sourceRevision"] != registration.authority.SOURCE_REVISION):
        _fail("activation write original scope or source differs")
    request_digest = registration._digest(value["requestDigest"])
    heads = _heads(value["beforeHeads"])
    head_map = {head.index_id: head for head in heads}
    _, expected = _identities()
    values = value["writeFrontiers"]
    if type(values) is not list or len(values) != WRITE_COUNT:
        _fail("activation write frontier inventory is not exact")
    maximum = combined._source_sizes(registration.authority.operation_spec(OPERATION))[2]
    total, inputs = 0, []
    for identity, item in zip(expected, values):
        registration._closed(item, frozenset({"indexId", "frontier"}), "activation write frontier")
        if (type(item["indexId"]) is not str or item["indexId"] != identity
                or type(item["frontier"]) is not list or len(item["frontier"]) > maximum):
            _fail("activation write frontier is not source sorted and bounded")
        total += len(item["frontier"])
        if total > MAX_NODES // 9:
            _fail("activation write frontier exceeds the aggregate node ceiling")
        records = []
        for record in item["frontier"]:
            if type(record) is not dict or type(record.get("kind")) is not str:
                _fail("activation write frontier record is not closed")
            if record["kind"] == "leaf":
                registration._closed(record, frozenset({"kind", "key", "primaryKeyDigest", "primaryRowDigest"}),
                    "activation write leaf")
                records.append(IndexLeaf(record["key"], record["primaryKeyDigest"], record["primaryRowDigest"]))
            elif record["kind"] == "opaque":
                registration._closed(record, frozenset({"kind", "prefix", "digest", "count"}),
                    "activation write opaque subtree")
                records.append(OpaqueSubtree(record["prefix"], record["digest"], record["count"]))
            else:
                _fail("activation write frontier kind is not source admitted")
        head = head_map[identity]
        inputs.append(indexed.IndexedMutationInput(identity, head.index_revision, head.index_root, tuple(records)))
    return _DecodedWrites(request_digest, heads, tuple(inputs))


def _encode_on_work(*, request_digest, counted_before_heads, write_inputs, work) -> bytes:
    """Canonical original encoding only; requires actual replay after authentication."""
    ledger = batch._SharedLedger(work)
    document = _raw_document(request_digest, counted_before_heads, write_inputs)
    owned = batch._JSONCapture(ledger, maximum_bytes=MAX_WRITE_PROOF_BYTES).visit(document)
    _document(owned, work)
    raw = registration._wire(owned, work)
    if len(raw) > MAX_WRITE_PROOF_BYTES:
        _fail("activation encoded write original exceeds its byte ceiling")
    return raw


def _decode_on_work(raw, *, work) -> _DecodedWrites:
    """Bounded canonical decoding, never a signature, intent or proof verdict."""
    batch._SharedLedger(work)
    value = registration.evidence.wire._decode_object(raw, work=work,
        maximum_bytes=MAX_WRITE_PROOF_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    result = _document(value, work)
    canonical = registration._wire(value, work)
    work.charge(input_bytes=len(raw) + len(canonical))
    if raw != canonical:
        _fail("activation write original is not canonical")
    return result


def _replay_originals_on_work(context, *, assertion_bytes, old_token_bytes, new_token_bytes,
        delivery_envelope_bytes, delivery_custody_key, expected_user_id, expected_session_id,
        expected_credential_id, expected_credential_record_id, expected_challenge_id,
        rp_id, origin, authn_policy, trust_policy, business_before_roots, authorization_before_roots,
        before_proofs, read_heads, query_frontiers, expected_counted_heads, write_proof_bytes,
        live_window, work, transport_deadline_ns, historical_plan_interval):
    """Replay all original semantics and writes relative to independent roots/heads.

    The expected thirteen closed head dictionaries are independent inputs, not
    copied from this signed original. No transition or proof-result DTO enters.
    The output commitments are not a signed plan or committed session result.
    """
    ledger = batch._SharedLedger(work)
    if (type(context) is not core.KernelContext or context.operation != OPERATION
            or context.verified_webauthn_evidence is not None
            or type(expected_counted_heads) is not tuple or len(expected_counted_heads) != HEAD_COUNT
            or type(write_proof_bytes) is not bytes or not 2 <= len(write_proof_bytes) <= MAX_WRITE_PROOF_BYTES):
        _fail("activation indexed replay input profile is not exact")
    # Immutable byte originals are held; every mutable policy, row, root,
    # proof and head graph is detached before decoding/hashing/native work.
    if (type(assertion_bytes) is not bytes or not 2 <= len(assertion_bytes) <= activation.assertion.MAX_ASSERTION_BYTES
            or type(delivery_envelope_bytes) is not bytes or len(delivery_envelope_bytes) != activation.delivery.ENVELOPE_BYTES
            or type(delivery_custody_key) is not bytes or len(delivery_custody_key) != 32):
        _fail("activation indexed replay originals exceed their source bounds")
    old_token_bytes = activation.assertion._token(old_token_bytes, work)
    new_token_bytes = activation.assertion._token(new_token_bytes, work)
    window = activation.assertion.clock._validate(live_window)
    if transport_deadline_ns is not None:
        registration._integer(transport_deadline_ns, "activation inherited deadline", 1)
    interval = historical_plan_interval
    if interval is not None:
        if type(interval) is not tuple or len(interval) != 2:
            _fail("activation historical plan interval must be the exact signed pair")
        for item in interval:
            registration._integer(item, "activation historical plan time", 1)
        if not 0 < interval[1] - interval[0] <= registration.authority.VERIFIER_RESPONSE_MAX_AGE_NS:
            _fail("activation historical plan interval exceeds its original bound")
        registration._integer(transport_deadline_ns, "activation historical processing deadline", 1)
    database_now = context.database_now
    scope = activation.assertion._Capture(ledger,
        maximum_bytes=activation.assertion.MAX_CONTEXT_BYTES).visit({
            "user": expected_user_id, "session": expected_session_id, "credential": expected_credential_id,
            "record": expected_credential_record_id, "challenge": expected_challenge_id,
            "rpId": rp_id, "origin": origin, "policy": authn_policy, "trust": trust_policy,
            "expectedHeads": list(expected_counted_heads)})
    owned, records, heads, frontiers = reads._capture(arguments=context.arguments,
        request_digest=context.request_digest, selected_rows=context.selected_rows, query_reads=context.query_reads,
        business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
        before_proofs=before_proofs, read_heads=read_heads, query_frontiers=query_frontiers, work=work)
    expected = _heads(scope["expectedHeads"])
    epoch, monotonic = window[0], window[2]
    bound = min(window[4], transport_deadline_ns) if transport_deadline_ns is not None else window[4]

    def processing_live():
        nonlocal epoch, monotonic
        now = activation.assertion.clock._check_on_work(window, work=work)
        observed = registration.evidence.production._callback(work, time.monotonic_ns)
        registration._integer(observed, "activation historical monotonic sample", 1)
        if now < epoch or observed < monotonic or observed >= bound:
            _fail("activation historical processing expired or clocks reversed")
        epoch, monotonic = now, observed
        return now

    if interval is not None:
        processing_live()
    decoded = _decode_on_work(write_proof_bytes, work=work)
    registration._same(decoded.request_digest, owned["request_digest"], work, "write request identity")
    registration._same([_head_record(head) for head in decoded.counted_before_heads],
        scope["expectedHeads"], work, "independent counted before heads")
    head_map = {head.index_id: head for head in expected}
    for head in heads:
        expected_head = head_map.get(head.index_id)
        if (expected_head is None or head.index_revision != expected_head.index_revision
                or head.index_root != expected_head.index_root):
            _fail("activation read head differs from the independent write union")
    current = core.KernelContext(OPERATION, owned["arguments"], owned["selected_rows"], database_now,
        owned["request_digest"], query_reads=records)
    # Only these fixed original-only entrypoints are selected. A successful
    # transition or externally supplied verifier callback is never an input.
    transition_originals = dict(
        assertion_bytes=assertion_bytes, old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes,
        delivery_envelope_bytes=delivery_envelope_bytes, delivery_custody_key=delivery_custody_key,
        expected_user_id=scope["user"], expected_session_id=scope["session"], expected_credential_id=scope["credential"],
        expected_credential_record_id=scope["record"], expected_challenge_id=scope["challenge"],
        rp_id=scope["rpId"], origin=scope["origin"], authn_policy=scope["policy"], trust_policy=scope["trust"],
        business_before_roots=owned["business_before_roots"], authorization_before_roots=owned["authorization_before_roots"],
        before_proofs=owned["before_proofs"], read_heads=heads, query_frontiers=frontiers,
        live_window=window, work=work, transport_deadline_ns=transport_deadline_ns)
    if interval is None:
        full = activation._full_transition_with_liveness_on_work(current, **transition_originals)
    else:
        processing_live()
        full = activation._full_transition_historical_on_work(current,
            **transition_originals, historical_plan_interval=interval)
        if type(full) is not activation._HistoricalFullTransition:
            _fail("activation historical transition returned another result family")
        registration._same(full.historical_plan_interval, interval, work, "historical transition interval")
        if interval[1] > full.valid_until_epoch_ns:
            _fail("activation historical plan exceeds original row or delivery expiry")

    def replay_live():
        if interval is None:
            now = full.live()
            if now >= full.valid_until_epoch_ns:
                _fail("activation originals expired during indexed replay")
            return now
        processing_live()
        checked = full.live()
        now = processing_live()
        if now < checked:
            _fail("activation historical processing clock reversed after transition")
        return now

    actual = full.transition
    actual_ids = tuple(sorted(identity for table in {item["table"] for item in actual.mutations}
        for identity in projection.index_ids_for_table(table)))
    if actual_ids != tuple(item.index_id for item in decoded.write_inputs):
        _fail("activation actual mutations differ from the complete write profile closure")
    # The real read worker has checked these same owned root descriptors. These
    # fresh PrimaryRoot constructors each perform one canonical empty hash.
    ledger.charge(hashes=len(owned["business_before_roots"]) + len(owned["authorization_before_roots"]))
    business = batch._roots(owned["business_before_roots"])
    authorization = batch._roots(owned["authorization_before_roots"])
    primary_by_table = {root.table: root for root in (*business, *authorization)}
    read_ids = {head.index_id for head in heads}
    for head in expected:
        if head.index_id in read_ids:
            continue
        ledger.charge(hashes=projection.PROFILE_HASH_WORK + 1)
        profile = projection.profile_for(head.index_id)
        empty = empty_node(profile, "")
        if ((head.index_root.count == 0) != (head.index_root.digest == empty.digest)
                or head.index_root.count > primary_by_table[profile.table].leaf_count):
            _fail("activation independent write head population or empty root differs")
    replay_live()
    calculated = indexed.evaluate_indexed_primary_batch(
        table_contracts=primary_table_contracts(OPERATION), business_before_roots=business,
        authorization_before_roots=authorization, selected_rows=owned["selected_rows"],
        before_proofs=owned["before_proofs"], mutations=actual.mutations, index_inputs=decoded.write_inputs,
        limits=combined._write_limits(registration.authority.operation_spec(OPERATION), ledger))
    # Existing pure evaluator metrics, charged back to the SAME caller ledger;
    # source limits were clipped to its actual remaining budget before entry.
    ledger.charge(hashes=calculated.metrics.hashes, input_bytes=calculated.metrics.input_bytes,
        json_nodes=calculated.metrics.primary.json_nodes)
    replay_live()
    after = dict(head_map)
    for head in calculated.after_heads:
        after[head.index_id] = combined.CompleteReadWriteHead(head.index_id, head.index_revision, head.index_root)
    after_heads = tuple(after[head.index_id] for head in expected)
    write_digest = registration.evidence.plan._frame(IDENTITY_DOMAIN, (write_proof_bytes,), work)
    commitment = {"schema": TRANSITION_SCHEMA, "sourceRevision": registration.authority.SOURCE_REVISION,
        "operation": OPERATION, "requestDigest": owned["request_digest"], "writeProofDigest": write_digest,
        "mutations": list(actual.mutations), "result": actual.result, "workUnits": actual.work_units,
        "businessAfterRoots": [root.json_projection() for root in calculated.primary.business_after_roots],
        "authorizationAfterRoots": [root.json_projection() for root in calculated.primary.authorization_after_roots],
        "countedAfterHeads": [_head_record(head) for head in after_heads]}
    raw = registration._wire(commitment, work)
    if len(raw) > MAX_TRANSITION_BYTES:
        _fail("activation transition commitment exceeds its source byte ceiling")
    digest = registration.evidence.plan._frame(TRANSITION_DOMAIN, (raw,), work)
    replay_live()
    if interval is None:
        return _ReplayedWrites(actual, write_proof_bytes, write_digest, raw, digest,
            calculated.primary.business_after_roots, calculated.primary.authorization_after_roots,
            after_heads, full.live, full.valid_until_epoch_ns)
    result = _HistoricalReplayedWrites(actual, write_proof_bytes, write_digest, raw, digest,
        calculated.primary.business_after_roots, calculated.primary.authorization_after_roots,
        after_heads, replay_live, full.valid_until_epoch_ns, interval)
    replay_live()
    return result


def _replay_on_work(context, *, assertion_bytes, old_token_bytes, new_token_bytes,
        delivery_envelope_bytes, delivery_custody_key, expected_user_id, expected_session_id,
        expected_credential_id, expected_credential_record_id, expected_challenge_id,
        rp_id, origin, authn_policy, trust_policy, business_before_roots, authorization_before_roots,
        before_proofs, read_heads, query_frontiers, expected_counted_heads, write_proof_bytes,
        live_window, work, transport_deadline_ns=None) -> _ReplayedWrites:
    """Preserved live entrypoint; expired originals still fail closed."""
    return _replay_originals_on_work(context, assertion_bytes=assertion_bytes,
        old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes,
        delivery_envelope_bytes=delivery_envelope_bytes, delivery_custody_key=delivery_custody_key,
        expected_user_id=expected_user_id, expected_session_id=expected_session_id,
        expected_credential_id=expected_credential_id, expected_credential_record_id=expected_credential_record_id,
        expected_challenge_id=expected_challenge_id, rp_id=rp_id, origin=origin,
        authn_policy=authn_policy, trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, expected_counted_heads=expected_counted_heads,
        write_proof_bytes=write_proof_bytes, live_window=live_window, work=work,
        transport_deadline_ns=transport_deadline_ns, historical_plan_interval=None)


def _replay_historical_on_work(context, *, assertion_bytes, old_token_bytes, new_token_bytes,
        delivery_envelope_bytes, delivery_custody_key, expected_user_id, expected_session_id,
        expected_credential_id, expected_credential_record_id, expected_challenge_id,
        rp_id, origin, authn_policy, trust_policy, business_before_roots, authorization_before_roots,
        before_proofs, read_heads, query_frontiers, expected_counted_heads, write_proof_bytes,
        historical_plan_interval, live_window, work, transport_deadline_ns=None) -> _HistoricalReplayedWrites:
    """Rebuild original indexed effects; caller authenticates the signed interval.

    The current supplied allowance stays live. Original lifetimes are checked
    algebraically by the genuine historical semantic worker, never by passing
    an old issue time as a current clock. This is not execution authority.
    """
    if historical_plan_interval is None:
        _fail("activation historical replay requires its authenticated original interval")
    return _replay_originals_on_work(context, assertion_bytes=assertion_bytes,
        old_token_bytes=old_token_bytes, new_token_bytes=new_token_bytes,
        delivery_envelope_bytes=delivery_envelope_bytes, delivery_custody_key=delivery_custody_key,
        expected_user_id=expected_user_id, expected_session_id=expected_session_id,
        expected_credential_id=expected_credential_id, expected_credential_record_id=expected_credential_record_id,
        expected_challenge_id=expected_challenge_id, rp_id=rp_id, origin=origin,
        authn_policy=authn_policy, trust_policy=trust_policy, business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, before_proofs=before_proofs,
        read_heads=read_heads, query_frontiers=query_frontiers, expected_counted_heads=expected_counted_heads,
        write_proof_bytes=write_proof_bytes, live_window=live_window, work=work,
        transport_deadline_ns=transport_deadline_ns, historical_plan_interval=historical_plan_interval)
