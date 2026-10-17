"""Purpose-fixed current PostgreSQL originals for native review opening.

This owner reads one admitted SERIALIZABLE READ ONLY DEFERRABLE snapshot. A
fresh nonce joins its complete vector to the configured, root-enrolled latest
head service before any dependent selector. Every selected row is authenticated
before its fields can select another row. The original browser secret is only
hashed transiently; neither it nor an authorization verdict is an output.

Independent replay consumes original chunk/proof/head bytes, not a successful
reader object. Local enrolled-head continuity is not off-host antirollback.
The bounded child schedule is specific to these two operations: old assertion
codecs and global 1/4/64 MiB ceilings are unchanged. SQL/driver allocation and
TLS/catalog admission are outside canonical work accounting, as in the existing
root reader. Chunk limits bound transferred/decoded bytes, not PostgreSQL's
initial to_jsonb materialization of an oversized stored row. No injectable
connection, clock, verifier or retry is exposed.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import secrets
import threading
import time

from catchplate import authority_audit_capacity as audit_capacity
from catchplate import authority_current_root_head as head
from catchplate import authority_current_root_transport as transport
from catchplate import authority_current_root_vector as vector
from catchplate import authority_index_reader as physical
from catchplate import authority_native_jit_review_current_chunks as chunks
from catchplate import authority_native_jit_review_open_contract as contract
from catchplate import authority_primary_contract as primary_contract
from catchplate import authority_primary_original_reader as primary_reader
from catchplate import authority_query_reads as reads
from catchplate import authority_radix_proof as radix
from catchplate import authority_request_commitment as commitment
from catchplate import authority_revocation_root_reader as connection_owner
from catchplate import authority_transition_core as core
from catchplate import authority_transition_quota as quota
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from catchplate.authority_store import current_root_observation as observation
from catchplate.authority_store.verifier_read_sql import verifier_read_privilege_check


SCHEMA = "catchplate.nativeJitReviewCurrentOriginals/v1"
MAX_SELECTED_BYTES = chunks.MAX_TOTAL_SELECTED_BYTES
MAX_ORIGINAL_BYTES = 96 * 1024 * 1024
MAX_WORK_BYTES = 1024 * 1024 * 1024
MAX_SQL_READS = 1500
MAX_PROOF_BYTES = 128 * 1024
_TOKEN_CHARACTERS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_BASE_NAMES = tuple(chunks._QUERIES)[:9]
_NAMES = tuple(chunks._QUERIES)
_KERNEL_STAGES = frozenset({"input-capture", "native-challenge", "current-reviewer", "retained-history",
    "native-preparation", "receipt-effects", "receipt-roots", "complete-vector"})
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ORIGINAL_FIELDS = frozenset({"schema", "operation", "requestDigest", "databaseNowEpochNs",
    "completeRootVectorOriginal", "headQueryOriginal", "headObservationOriginal",
    "finalHeadQueryOriginal", "finalHeadObservationOriginal", "trustPublicationId", "rows"})


class NativeJitReviewCurrentReadError(ValueError):
    pass


def _require(condition):
    if not condition:
        raise NativeJitReviewCurrentReadError("Native review current read lost its original source binding")


def _pin(work):
    _require(type(work) is _ValidationWork)
    return (work.limits, work.limits.max_hashes, work.limits.max_input_bytes,
        work.limits.max_json_nodes, work.hash_work, work.input_bytes, work.json_nodes)


class NativeJitReviewReadBudget:
    """One source-fixed pass, holding rather than resetting the parent ledger."""

    def __init__(self, operation, *, parent_work, live_window, deadline_ns):
        _require(operation in contract.OPERATIONS and type(operation) is str
            and type(deadline_ns) is int and deadline_ns > 0)
        self.operation = operation
        self.parent_work, self.live_window = parent_work, head.clock._validate(live_window)
        self.deadline_ns = min(deadline_ns, live_window[4])
        self._process = os.getpid(), threading.get_ident()
        self._parent_pin = _pin(parent_work)
        self._held = (operation, parent_work, self.live_window, self.deadline_ns)
        self._stages, self._active = {}, None
        self._failed = False
        self.selected_bytes, self.native_bytes, self.data_chunks = 2, 0, 0
        self.original_bytes = self.sql_reads = 0
        self._last_epoch, self._last_monotonic = live_window[0], live_window[2]

    def _check(self):
        parent = _pin(self.parent_work)
        _require(type(self) is NativeJitReviewReadBudget and not self._failed
            and self._process == (os.getpid(), threading.get_ident())
            and self._held == (self.operation, self.parent_work, self.live_window, self.deadline_ns)
            and parent[0] is self._parent_pin[0] and parent == self._parent_pin)
        total = 0
        for work, previous in self._stages.values():
            pin = _pin(work)
            _require(pin[0] is previous[0] and pin[:4] == previous[:4]
                and all(a >= b for a, b in zip(pin[4:], previous[4:])))
            if work is not self._active:
                _require(pin == previous)
            total += work.input_bytes
        _require(total <= MAX_WORK_BYTES and self.sql_reads <= MAX_SQL_READS
            and self.original_bytes <= MAX_ORIGINAL_BYTES
            and self.selected_bytes <= MAX_SELECTED_BYTES
            and self.native_bytes <= chunks.MAX_TOTAL_NATIVE_BYTES
            and self.data_chunks <= chunks.MAX_TOTAL_DATA_CHUNKS)
        _require(time.monotonic_ns() < self.deadline_ns)

    def current(self, work):
        self._check()
        now = head.clock._check_on_work(self.live_window, work=work)
        monotonic = time.monotonic_ns()
        _require(now >= self._last_epoch and monotonic >= self._last_monotonic
            and monotonic < self.deadline_ns)
        self._last_epoch, self._last_monotonic = now, monotonic
        return now

    @contextmanager
    def stage(self, name):
        try:
            self._check()
            allowed = name in _KERNEL_STAGES or name in {
                "original-capture", "admission", "roots", "head", "trust-selector", "final-roots", "final-head", "finish"}
            if type(name) is tuple and len(name) == 3:
                kind, slot, ordinal = name
                count = 13 if self.operation == contract.RECEIPT else 9
                allowed = (kind in {"row-open", "chunk", "decode", "proof", "membership", "transaction"}
                    and type(slot) is int and 0 <= slot < count and type(ordinal) is int
                    and (0 <= ordinal < 98 if kind == "chunk" else ordinal == 0))
            _require(allowed and name not in self._stages and self._active is None)
            work = _ValidationWork(QueryReadValidationLimits())
            self._stages[name] = (work, _pin(work))
            self._active = work
            self.current(work)
            yield work
            self.current(work)
            self._stages[name] = (work, _pin(work))
            self._active = None
            self._check()
        except BaseException:
            self._failed = True
            raise
        finally:
            self._active = None


def _request(request, work):
    _require(type(request) is dict and request.get("operation") in contract.OPERATIONS)
    args = request.get("arguments")
    fields = contract.RECEIPT_ARGUMENTS if request["operation"] == contract.RECEIPT else contract.AUTHORIZE_ARGUMENTS
    _require(type(args) is dict and set(args) == fields)
    for name in ("approval_request_id", "session_id"):
        _require(type(args[name]) is str and 1 <= len(args[name]) <= 128 and "\x00" not in args[name])
    for name in fields - {"approval_request_id", "session_id", "businessIntent"}:
        _require(primary_reader._digest(args[name]))
    actual = commitment._typed_request_digest(request, work=work)
    _require(request["requestDigest"] == actual
        and request["operationId"] == commitment.operation_id(request["operation"], actual))
    return request["operation"]


def _token_digest(original, work):
    _require(type(original) is bytes and len(original) == 64
        and all(character in _TOKEN_CHARACTERS for character in original))
    work.charge(input_bytes=128, hashes=1, json_nodes=1)
    return "sha256:" + hashlib.sha256(original).hexdigest()


def _query(operation, name, value):
    table, column, fixed = chunks._QUERIES[name]
    if fixed is not None:
        _require(type(value) is type(fixed) and value == fixed)
    return core.BoundedQuery(query_id=core.query_program_id(operation, name, table),
        table=table, predicates=(core.QueryPredicate(column, "eq", value),),
        order_by=(core.QueryOrder(column),), maximum_rows=1, absent_key={column: value})


def _selector(name, request, owned, publication_id):
    args, operation = request["arguments"], request["operation"]
    if name == "session":
        return args["session_id"]
    if name == "credential":
        return owned["session"]["bound_webauthn_credential_id"]
    if name == "reviewer_role":
        return owned["session"]["user_id"]
    if name == "trust_publication":
        return publication_id
    if name in {"approval", "retained_pair"}:
        return args["approval_request_id"]
    if name == "receipt":
        return core.deterministic_uuid(operation=operation, request_digest=request["requestDigest"],
            purpose="native-jit-review-opening-receipt")
    if name == "receipt_capacity":
        return quota._aggregate_key("jit-review-receipts", "global")[0]
    if name == "audit":
        return quota._audit_identity(operation, request["requestDigest"])
    if name == "audit_capacity":
        return audit_capacity.AGGREGATE_ID
    return chunks._QUERIES[name][2]


def _session(row, token_digest, now):
    _require(type(row) is dict and type(row["token_digest"]) is str
        and hmac.compare_digest(row["token_digest"], token_digest)
        and row["status"] == "active" and row["revoked_at"] is None
        and type(row["bound_webauthn_credential_id"]) is str
        and 1 <= len(row["bound_webauthn_credential_id"]) <= 1024
        and type(row["user_id"]) is str and 1 <= len(row["user_id"]) <= 1024)
    for field in ("expires_at", "provider_expires_at"):
        try:
            parsed = datetime.fromisoformat(row[field].replace("Z", "+00:00"))
        except (ValueError, OverflowError):
            raise NativeJitReviewCurrentReadError("Native review session expiry is invalid") from None
        _require(parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)
            and parsed > _EPOCH + timedelta(microseconds=now // 1000))


def _publication(row, high_water):
    _require(type(row) is dict and type(high_water) is dict)
    for name, expected in (("scope", "global"), ("status", "published"),
            ("bundle_digest", high_water["publication_digest"]),
            ("payload_digest", high_water["metadata_blob_digest"]),
            ("rollback_epoch", high_water["rollback_epoch"]),
            ("sequence", high_water["publication_sequence"])):
        _require(type(row[name]) is type(expected) and row[name] == expected)


def _selection(query, row, work):
    work.prepare_encoding(query.absent_key)
    work.charge(hashes=1, input_bytes=512, json_nodes=16)
    digest = core.framed_digest("catchplate.policyAuthorityBusinessKey/v1",
        query.table.encode("ascii"), core.canonical_bytes(query.absent_key))
    return {"table": query.table, "key": dict(query.absent_key), "keyDigest": digest,
        "present": row is not None, "row": row, "contractSelector": None}


def _membership(selected, proof, root, canonical_size, work):
    """Real v3 radix reconstruction, with its large flat row walks prepaid.

    Codec already measured the full flat row. Four canonical row lengths cover
    normalization, JSON emission, UTF-8 and hash material. Eight proof lengths
    plus 2MiB cover fixed 64x16 ladders and exact digest/shape comparisons. This
    separate stage fits the 12MiB trust row under the unchanged 64MiB ceiling.
    """
    _require(type(canonical_size) is int and 0 <= canonical_size <= 12 * 1024 * 1024 + 16384)
    proof_size, proof_nodes = work.measure(proof)
    _require(proof_size <= MAX_PROOF_BYTES and type(proof) is dict)
    work.charge(input_bytes=4 * canonical_size + 8 * proof_size + 2 * 1024 * 1024,
        json_nodes=4 * len(selected["row"] or {}) + 8 * proof_nodes + 32768, hashes=136)
    unsigned = {key: value for key, value in proof.items() if key != "proofDigest"}
    expected = core.framed_digest("catchplate.policyAuthorityRadixMultiproof/v3", core.canonical_bytes(unsigned))
    _require(proof.get("proofDigest") == expected and proof.get("rootRevision") == root.root_revision
        and proof.get("rootDigest") == root.root_digest)
    _require(radix.reconstruct_multiproof_root(proof, selected=selected) == root.root_digest)
    for key, value in selected["key"].items():
        _require(selected["row"] is None or type(selected["row"][key]) is type(value)
            and selected["row"][key] == value)


def _record(query, selected, work):
    query_wire = work.wire(query.contract_value())
    key_wire = work.wire(selected["key"])
    address = reads.QueryReadAddress(query.table, key_wire, selected["keyDigest"], selected["present"])
    return reads.QueryRead(query.query_id, query_wire, query_wire, (address,), int(selected["present"]))


def _read_json(original, maximum, work):
    return vector.wire._decode_object(original, work=work, maximum_bytes=maximum,
        maximum_nodes=32768, maximum_depth=8)


def _root_map(original, work):
    document = vector._decode_on_work(original, work=work)
    return {row["table"]: primary_reader.primary.PrimaryRoot(row["table"], row["rootRevision"],
        row["rootDigest"], row["leafCount"]) for row in document["primaryRoots"]}


def _head_originals(originals, request, root_public_key, enrollment_original, budget, work, *, final):
    prefix = "finalHead" if final else "head"
    query = originals[prefix + "QueryOriginal"]
    observed = originals[prefix + "ObservationOriginal"]
    payload = head._verify_on_work(observation_bytes=observed, query_bytes=query,
        enrollment_bytes=enrollment_original, root_public_key=root_public_key,
        now_epoch_ns=budget.current(work), work=work, operation=request["operation"])
    digest = vector._digest_on_work(originals["completeRootVectorOriginal"], work=work)
    _require(payload["contextDigest"] == request["requestDigest"] and payload["vectorDigest"] == digest
        and payload["pendingRequestDigest"] is None and payload["pendingDecisionDigest"] is None)
    return payload


def _count_root_originals(originals, budget):
    # Each is already bounded by its genuine original verifier. Count retained
    # bytes exactly once, in addition to every row chunk/proof frame above.
    budget.original_bytes += sum(len(originals[name]) for name in (
        "completeRootVectorOriginal", "headQueryOriginal", "headObservationOriginal",
        "finalHeadQueryOriginal", "finalHeadObservationOriginal"))


def _snapshot_originals(originals, operation, work):
    """Own bounded containers without traversing/copying large immutable bytes."""
    _require(type(originals) is dict and len(originals) == len(_ORIGINAL_FIELDS)
        and all(type(name) is str and len(name) <= 64 for name in originals)
        and set(originals) == _ORIGINAL_FIELDS)
    # This fixed reservation covers at most 13 row mappings and 282 frame
    # references. It does not claim to hash/copy their up-to-96MiB byte leaves;
    # the subsequent genuine per-frame decode/hash stages pay those walks.
    work.charge(input_bytes=256 * 1024, json_nodes=16384)
    result = {name: value for name, value in originals.items() if name != "rows"}
    for name in ("schema", "operation", "requestDigest", "trustPublicationId"):
        _require(type(result[name]) is str and len(result[name]) <= 1024)
    _require(type(result["databaseNowEpochNs"]) is int
        and 0 < result["databaseNowEpochNs"] < 2**63)
    total = 0
    for name, maximum in (("completeRootVectorOriginal", vector.MAX_BYTES),
            ("headQueryOriginal", head.MAX_QUERY_BYTES), ("headObservationOriginal", head.MAX_BYTES),
            ("finalHeadQueryOriginal", head.MAX_QUERY_BYTES), ("finalHeadObservationOriginal", head.MAX_BYTES)):
        raw = result[name]
        _require(type(raw) is bytes and 2 <= len(raw) <= maximum)
        total += len(raw)
    expected = 13 if operation == contract.RECEIPT else 9
    supplied = originals["rows"]
    _require(type(supplied) is tuple and len(supplied) == expected)
    rows, count = [], 0
    for row in supplied:
        _require(type(row) is dict and len(row) == 2
            and all(type(name) is str for name in row) and set(row) == {"chunks", "proof"})
        proof, frames = row["proof"], row["chunks"]
        _require(type(proof) is bytes and 2 <= len(proof) <= MAX_PROOF_BYTES
            and type(frames) is tuple and 1 <= len(frames) <= 98)
        total += len(proof)
        held = []
        for raw in frames:
            _require(type(raw) is bytes and 2 <= len(raw) <= 2 * chunks.CHUNK_BYTES + 2048)
            total += len(raw)
            count += 1
            _require(total <= MAX_ORIGINAL_BYTES and count <= chunks.MAX_TOTAL_DATA_CHUNKS + 13)
            held.append(raw)
        rows.append({"chunks": tuple(held), "proof": proof})
    result["rows"] = tuple(rows)
    return result


@dataclass(frozen=True, slots=True)
class NativeJitReviewReadData:
    """Output-only reconstructed data; callers must invoke original replay."""

    selected_rows: tuple
    query_reads: tuple
    before_proofs: tuple
    business_before_roots: tuple
    authorization_before_roots: tuple
    database_now: datetime
    complete_root_vector_original: bytes
    head_observation_original: bytes
    head_query_original: bytes


def _rows(request, token_digest, roots, originals, budget, *, cursor=None):
    owned, selected_rows, proofs, records, row_originals = {}, [], [], [], []
    names = _NAMES if request["operation"] == contract.RECEIPT else _BASE_NAMES
    publication_id = originals.get("trustPublicationId")
    if cursor is None:
        _require(type(originals["rows"]) is tuple and len(originals["rows"]) == len(names))
    for slot, name in enumerate(names):
        if cursor is not None:
            with budget.stage(("transaction", slot, 0)) as work:
                cursor.require_transaction(work)
        if name == "trust_publication":
            with budget.stage("trust-selector") as work:
                if cursor is not None:
                    high = owned["trust_high_water"]
                    sql = ("SELECT CASE WHEN pg_catalog.octet_length(id) BETWEEN 1 AND 1024 THEN id ELSE NULL END AS id "
                        "FROM catchplate_metadata.webauthn_trust_publications WHERE scope = %s AND status = %s "
                        "AND bundle_digest = %s AND payload_digest = %s AND rollback_epoch = %s AND sequence = %s "
                        "ORDER BY id LIMIT %s")
                    rows = cursor.read(sql, ("global", "published", high["publication_digest"],
                        high["metadata_blob_digest"], high["rollback_epoch"], high["publication_sequence"], 2), 2, work)
                    _require(len(rows) == 1 and type(rows[0]) is dict and set(rows[0]) == {"id"})
                    publication_id = rows[0]["id"]
                _require(type(publication_id) is str and 1 <= len(publication_id) <= 1024
                    and "\x00" not in publication_id)
        with budget.stage(("row-open", slot, 0)) as work:
            query = _query(request["operation"], name, _selector(name, request, owned, publication_id))
            codec = chunks.NativeJitReviewRowChunks(request["operation"], query, work=work)
        retained_chunks = []
        supplied = None if cursor is not None else originals["rows"][slot]
        if supplied is not None:
            _require(type(supplied) is dict and set(supplied) == {"chunks", "proof"}
                and type(supplied["chunks"]) is tuple and 1 <= len(supplied["chunks"]) <= 98)
        while not codec.complete:
            ordinal = codec.next_ordinal
            with budget.stage(("chunk", slot, ordinal)) as work:
                sql, params, *_ = codec._next_query(work=work)
                if cursor is not None:
                    raw = cursor.read(sql, params, 1, work)
                    frame = work.wire({"rows": raw})
                else:
                    _require(ordinal < len(supplied["chunks"]))
                    frame = supplied["chunks"][ordinal]
                    decoded = _read_json(frame, 2 * chunks.CHUNK_BYTES + 2048, work)
                    _require(set(decoded) == {"rows"})
                    raw = decoded["rows"]
                _require(type(frame) is bytes and len(frame) <= 2 * chunks.CHUNK_BYTES + 2048)
                budget.original_bytes += len(frame)
                codec.accept(raw, work=work)
                retained_chunks.append(frame)
        _require(supplied is None or len(supplied["chunks"]) == len(retained_chunks))
        with budget.stage(("decode", slot, 0)) as work:
            row = codec.finish(work=work)
            budget.native_bytes += codec.native_bytes
            budget.data_chunks += codec.data_chunks
            selected = _selection(query, row, work)
            # Count the actual envelope scaffolding as well as the large row;
            # no caller-provided byte count selects the aggregate allowance.
            scaffold = {**selected, "row": None}
            scaffold_size, _ = work.measure(scaffold)
            budget.selected_bytes += codec.canonical_bytes + scaffold_size - 4 + 1
        with budget.stage(("proof", slot, 0)) as work:
            if cursor is not None:
                adapter = cursor.adapter(work)
                trace = _Trace()
                acquisition = physical._ReadAcquisitionBudget(adapter, trace, work=work)
                with acquisition.read_phase(adapter, trace, work):
                    proof = primary_reader._before_proof(adapter, selected=selected, root=roots[query.table],
                        trace=trace, work=work, acquisition=acquisition)
                proof_original = work.wire(proof)
            else:
                proof_original = supplied["proof"]
                proof = _read_json(proof_original, MAX_PROOF_BYTES, work)
            _require(type(proof_original) is bytes and len(proof_original) <= MAX_PROOF_BYTES)
            budget.original_bytes += len(proof_original)
        with budget.stage(("membership", slot, 0)) as work:
            _membership(selected, proof, roots[query.table], codec.canonical_bytes, work)
            if name in _BASE_NAMES:
                _require(row is not None)
            if name == "session":
                _session(row, token_digest, budget.current(work))
            elif name == "credential":
                _require(row["user_id"] == owned["session"]["user_id"] and row["revoked_at"] is None)
            elif name == "trust_publication":
                _publication(row, owned["trust_high_water"])
            records.append(_record(query, selected, work))
            owned[name] = row
        selected_rows.append(selected)
        proofs.append(proof)
        row_originals.append({"chunks": tuple(retained_chunks), "proof": proof_original})
    return tuple(selected_rows), tuple(proofs), tuple(records), tuple(row_originals), publication_id


def admit_original_reads_on_work(originals, *, request, session_token_original, root_public_key,
        enrollment_original, live_window, work, budget):
    """Independently authenticate literal originals under the actual parent pins."""
    try:
        return _admit_original_reads(originals, request=request, session_token_original=session_token_original,
            root_public_key=root_public_key, enrollment_original=enrollment_original,
            live_window=live_window, work=work, budget=budget)
    except BaseException:
        if type(budget) is NativeJitReviewReadBudget:
            budget._failed = True
        raise


def _admit_original_reads(originals, *, request, session_token_original, root_public_key,
        enrollment_original, live_window, work, budget):
    _require(type(budget) is NativeJitReviewReadBudget and budget.parent_work is work
        and budget.live_window is live_window and type(request) is dict
        and budget.operation == request.get("operation")
        and type(originals) is dict and len(originals) == len(_ORIGINAL_FIELDS))
    # No original signature/proof is inspected before this detached graph is
    # held. Later callbacks cannot replace a verified head before its return.
    with budget.stage("original-capture") as stage:
        originals = _snapshot_originals(originals, budget.operation, stage)
    with budget.stage("admission") as stage:
        request = reads._CopyBudget(stage).copy(request)
        operation = _request(request, stage)
        token_digest = _token_digest(session_token_original, stage)
        _require(originals["schema"] == SCHEMA and originals["operation"] == operation
            and originals["requestDigest"] == request["requestDigest"]
            and type(originals["databaseNowEpochNs"]) is int
            and live_window[0] <= originals["databaseNowEpochNs"] <= budget.current(stage))
    with budget.stage("roots") as stage:
        roots = _root_map(originals["completeRootVectorOriginal"], stage)
    with budget.stage("head") as stage:
        first = _head_originals(originals, request, root_public_key, enrollment_original, budget, stage, final=False)
    selected, proofs, records, _, _ = _rows(request, token_digest, roots, originals, budget)
    with budget.stage("final-head") as stage:
        final = _head_originals(originals, request, root_public_key, enrollment_original, budget, stage, final=True)
        _require(all(first[name] == final[name] for name in ("sequence", "headDigest", "vectorDigest", "fence")))
    with budget.stage("finish") as stage:
        _count_root_originals(originals, budget)
        contracts = primary_contract.primary_table_contracts(operation)
        tables = {row["table"] for row in selected}
        _require({item.table for item in contracts} == tables)
        business = tuple(roots[item.table] for item in contracts if item.root_class == "business")
        authorization = tuple(roots[item.table] for item in contracts if item.root_class == "authorization")
        now = _EPOCH + timedelta(microseconds=originals["databaseNowEpochNs"] // 1000)
    return NativeJitReviewReadData(selected, records, proofs, business, authorization, now,
        originals["completeRootVectorOriginal"], originals["finalHeadObservationOriginal"],
        originals["finalHeadQueryOriginal"])


class _Trace:
    def read(self, table, key):
        _require(type(table) is str and type(key) is dict)


class _Cursor:
    """Exact actual connection checks around every physical execute/fetch."""

    def __init__(self, raw, connection, identity, budget):
        self.raw, self.connection, self.identity, self.budget = raw, connection, identity, budget
        self._held = raw, connection, identity, budget
        self._transaction = None

    def require_transaction(self, work):
        adapter, trace = self.adapter(work), _Trace()
        acquisition = physical._ReadAcquisitionBudget(adapter, trace, work=work)
        with acquisition.read_phase(adapter, trace, work):
            with acquisition.scope(adapter, trace, work):
                marker = observation._transaction(acquisition, work)
        _require(marker[4:6] == ("on", "on"))
        if self._transaction is None:
            self._transaction = marker
        else:
            _require(marker == self._transaction)

    def read(self, sql, params, maximum, work):
        _require(all(a is b for a, b in zip((self.raw, self.connection, self.identity, self.budget), self._held))
            and type(sql) is str and len(sql) <= 8192
            and sql.startswith(("SELECT ", "WITH native_row AS MATERIALIZED (SELECT "))
            and type(params) is tuple
            and type(maximum) is int and 1 <= maximum <= 17)
        self.budget.current(work)
        work.prepare_scan(sql)
        work.prepare_scan(params)
        self.budget.sql_reads += 1
        self.budget._check()
        connection_owner._require_connection(self.connection, self.identity, 2)
        rows = connection_owner.roots._callback(work,
            lambda: self.raw.execute(sql, params).fetchmany(maximum + 1))
        connection_owner._require_connection(self.connection, self.identity, 2)
        self.budget.current(work)
        _require(type(rows) is list and len(rows) <= maximum)
        return rows

    def adapter(self, work):
        outer = self

        class Bound:
            def execute(self, sql, params):
                class Result:
                    def fetchmany(self, maximum):
                        return outer.read(sql, params, maximum - 1, work)
                return Result()
        return Bound()


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class NativeJitReviewCurrentReader:
    """Previously admitted cold scalars, never a request-selected opener."""

    _configuration: tuple
    _operation: str
    _root_public_key: object
    _enrollment: bytes
    _client_configuration: tuple
    _pid: int

    def __init__(self, *, operation, dsn, connect_timeout_seconds, database_role, tls_client_dn,
            tls_client_serial, tls_issuer_dn, query_manifest_digest, root_public_key,
            enrollment_original, current_root_client):
        _require(type(operation) is str and operation in contract.OPERATIONS)
        configured = (dsn, connect_timeout_seconds, database_role, tls_client_dn,
            tls_client_serial, tls_issuer_dn, query_manifest_digest)
        connection_owner._validate_configuration(configured)
        head.authorization._public(root_public_key)
        _require(type(enrollment_original) is bytes and 2 <= len(enrollment_original) <= 128 * 1024
            and type(current_root_client) is transport.CurrentRootDecisionClient)
        client = transport.CurrentRootDecisionClient._snapshot_configuration(current_root_client)
        for name, value in (("_operation", operation), ("_configuration", configured), ("_root_public_key", root_public_key),
                ("_enrollment", enrollment_original), ("_client_configuration", client), ("_pid", os.getpid())):
            object.__setattr__(self, name, value)

    def acquire(self, request, *, session_token_original, live_window, deadline_ns, work):
        _require(type(self) is NativeJitReviewCurrentReader and self._pid == os.getpid()
            and type(request) is dict and request.get("operation") == self._operation)
        configured = self._configuration
        owner_pins = (self._operation, configured, self._root_public_key, self._enrollment,
            self._client_configuration, self._pid)
        connection_owner._validate_configuration(configured)
        budget = NativeJitReviewReadBudget(request.get("operation"), parent_work=work,
            live_window=live_window, deadline_ns=deadline_ns)
        connection = None
        try:
            with budget.stage("admission") as stage:
                request = reads._CopyBudget(stage).copy(request)
                operation = _request(request, stage)
                token_digest = _token_digest(session_token_original, stage)
                bindings = vector._source_bindings_on_work(work=stage)
                _require(configured[6] == bindings["queryManifestDigest"])
                # No external dependency is imported or connection opened until
                # the request, raw-secret shape and source purpose are bounded.
                import psycopg
                from psycopg.rows import dict_row
                connection = connection_owner._connect(stage, lambda: psycopg.connect(configured[0],
                    row_factory=dict_row, connect_timeout=configured[1], autocommit=False,
                    options="-c search_path=pg_catalog"))
                identity = connection_owner._connection_identity(connection, 0)
                cursor = connection.cursor()
                guard = connection_owner._ConnectionCursor(cursor, connection, identity, stage)
                guard.execute(connection_owner._SET_TRANSACTION)
                connection_owner._admit_identity(guard.execute(connection_owner._IDENTITY_SQL).fetchone(), configured)
                _require(guard.execute(*verifier_read_privilege_check(role=configured[2],
                    namespace="catchplate_metadata")).fetchone() is None)
                budget.sql_reads += 2
                snapshot_guard = _Cursor(cursor, connection, identity, budget)
                snapshot_guard.require_transaction(stage)
                transaction = snapshot_guard._transaction
                cursor.close()
                _require(cursor.closed is True)
                cutoff = budget.current(stage)
            originals = {"schema": SCHEMA, "operation": operation, "requestDigest": request["requestDigest"],
                "databaseNowEpochNs": cutoff}
            with budget.stage("roots") as stage:
                budget.sql_reads += 5  # Source-exact complete-vector observer.
                original = observation._observe_on_work(connection, work=stage)
                originals["completeRootVectorOriginal"] = original
                roots = _root_map(original, stage)
            with budget.stage("head") as stage:
                self._observe_head(originals, request, budget, stage, final=False)
                first = _head_originals(originals, request, self._root_public_key, self._enrollment, budget, stage, final=False)
            cursor = connection.cursor()
            guarded = _Cursor(cursor, connection, identity, budget)
            guarded._transaction = transaction
            try:
                _, _, _, rows, publication_id = _rows(request, token_digest, roots, originals, budget, cursor=guarded)
            finally:
                cursor.close()
            _require(cursor.closed is True)
            originals["rows"], originals["trustPublicationId"] = rows, publication_id
            with budget.stage("final-roots") as stage:
                cursor = connection.cursor()
                try:
                    final_cursor = _Cursor(cursor, connection, identity, budget)
                    final_cursor._transaction = guarded._transaction
                    final_cursor.require_transaction(stage)
                finally:
                    cursor.close()
                _require(cursor.closed is True)
                budget.sql_reads += 5
                final_vector = observation._observe_on_work(connection, work=stage)
                stage.charge(input_bytes=len(final_vector) + len(original))
                _require(final_vector == original)
            with budget.stage("final-head") as stage:
                self._observe_head(originals, request, budget, stage, final=True)
                final = _head_originals(originals, request, self._root_public_key, self._enrollment, budget, stage, final=True)
                _require(all(first[name] == final[name] for name in ("sequence", "headDigest", "vectorDigest", "fence")))
            with budget.stage("finish") as stage:
                _count_root_originals(originals, budget)
                _require(all(current is original for current, original in zip(
                    (self._operation, self._configuration, self._root_public_key, self._enrollment,
                        self._client_configuration, self._pid), owner_pins)))
                connection_owner._require_connection(connection, identity, 2)
                # This is a read-only acquisition, not a receipt commit. Closing
                # the snapshot cannot grant a write or an acknowledgment.
                connection.rollback()
                connection.close()
                _require(connection.closed is True)
            return originals
        except BaseException:
            budget._failed = True
            if connection is not None:
                connection_owner._close_after_failure(connection)
            raise

    def _observe_head(self, originals, request, budget, work, *, final):
        material = head.authorization._admit_enrollment_on_work(enrollment_bytes=self._enrollment,
            root_public_key=self._root_public_key, work=work)
        digest = vector._digest_on_work(originals["completeRootVectorOriginal"], work=work)
        query = head._encode_query_on_work(enrollment_digest=material.enrollment_digest,
            context_digest=request["requestDigest"], expected_vector_digest=digest,
            challenge=secrets.token_hex(32), work=work, operation=request["operation"])
        observed = transport._native_jit_review_head_on_work(self._client_configuration, query_bytes=query,
            deadline_ns=budget.deadline_ns, work=work, current=lambda: budget.current(work), operation=request["operation"])
        prefix = "finalHead" if final else "head"
        originals[prefix + "QueryOriginal"], originals[prefix + "ObservationOriginal"] = query, observed
