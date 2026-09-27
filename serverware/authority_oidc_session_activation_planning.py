"""Fixed read-only OIDC activation read/write-proof acquisition, not authority.

The owner holds its real PostgreSQL reader configuration. Each call owns its
request, independent root expectations and original lifetime before callbacks,
then uses the actual source query/primary/range acquisition machinery in one
read-only snapshot. The separate full method derives a genuine envelope and
transition, then acquires actual indexed write proofs without performing DML.
Detached observations escape only after normal cleanup and original expiry.
No caller cursor, proof result, SQL, callback, signing key or new work/window
is accepted. Caller/current-root/index-population authority remains separate.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from serverware import authority_complete_acquisition as acquisition
from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as batch
from serverware import authority_complete_read_write as read_write
from serverware import authority_contract as authority
from serverware import authority_index_heads as index_heads
from serverware import authority_index_mutation_reader as mutation_reader
from serverware import authority_index_projection as projection
from serverware import authority_index_reader as index_reader
from serverware import authority_indexed_mutation as indexed
from serverware import authority_oidc_session_activation_reads as reads
from serverware import authority_query_reads as query_reads
from serverware import authority_query_staging as staging
from serverware import authority_primary_contract as primary
from serverware import authority_request_commitment as commitment
from serverware import authority_revocation_planning as planning
from serverware import authority_revocation_semantics as semantics
from serverware import authority_transition_oidc_session_activation as transition
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware.authority_query_read_work import _ValidationWork


OPERATION = reads.OPERATION
_HEAD_FIELDS = frozenset({"indexId", "indexRevision", "rootDigest", "leafCount"})
_LOCK_TYPE = type(threading.Lock())


class OidcSessionActivationPlanningError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class _AcquiredActivationReads:
    """Original observations only; no consumer may substitute this for proofs."""

    request: dict
    database_now: datetime
    selected_rows: tuple
    query_reads: tuple
    business_before_roots: tuple
    authorization_before_roots: tuple
    before_proofs: tuple
    read_heads: tuple
    query_frontiers: tuple
    trace: tuple


@dataclass(frozen=True, slots=True, repr=False)
class _AcquiredActivationTransition(_AcquiredActivationReads):
    """Same-call observations/effects; offline consumers reverify originals."""

    delivery_envelope_bytes: bytes
    transition: transition.core.KernelTransition
    counted_before_heads: tuple
    write_inputs: tuple


def _configuration(value):
    if type(value) is not tuple or len(value) != 4:
        raise OidcSessionActivationPlanningError("activation read configuration is not exact")
    planning._validate_read_scope_configuration(value[:3])
    dsn, timeout, identity, skew = value
    planning.reader._bounded_text(dsn, 65536)
    if timeout < 2 or "\n" in dsn or "\r" in dsn:
        raise OidcSessionActivationPlanningError("activation connection settings are invalid")
    planning.reader._bounded_text(identity[0], 63)
    for item in identity[1:4]:
        planning.reader._bounded_text(item, 4096)
    if type(skew) is not int or not 0 <= skew <= authority.VERIFIER_MAX_CLOCK_SKEW_NS:
        raise OidcSessionActivationPlanningError("activation clock policy is not source bounded")
    return value


def _capture(*, request, business_before_roots, authorization_before_roots,
             expected_counted_heads, live_window, transport_deadline_ns, work,
             transition_inputs=None):
    batch._SharedLedger(work)
    head_count = 7 if transition_inputs is None else index_heads.MAX_ACTIVATION_HEADS
    if (type(request) is not dict or len(request) != 7
            or type(expected_counted_heads) is not tuple or len(expected_counted_heads) != head_count
            or type(live_window) is not tuple or len(live_window) != 7
            or type(transport_deadline_ns) is not int or transport_deadline_ns <= 0):
        raise OidcSessionActivationPlanningError("activation read originals are not source bounded")
    for roots in (business_before_roots, authorization_before_roots):
        if type(roots) not in (list, tuple) or len(roots) > authority.MAX_QUERY_PROOFS:
            raise OidcSessionActivationPlanningError("activation primary expectations are not bounded")
    owned = query_reads._CopyBudget(work).copy({
        "request": request, "businessBeforeRoots": business_before_roots,
        "authorizationBeforeRoots": authorization_before_roots,
        "expectedCountedHeads": expected_counted_heads, "liveWindow": live_window,
        "transportDeadlineNs": transport_deadline_ns, "transitionInputs": transition_inputs,
    })
    window = clock._validate(owned["liveWindow"])
    actual = owned["request"]
    if (type(actual.get("operation")) is not str or actual["operation"] != OPERATION
            or actual.get("handler") != authority.operation_spec(OPERATION)["handler"]):
        raise OidcSessionActivationPlanningError("activation request operation changed")
    complete._activation_binding_inputs(actual.get("arguments"), window[0] // 1000, work=work)
    request_digest = commitment._typed_request_digest(actual, work=work)
    if commitment._request_different(request_digest, actual.get("requestDigest"), work=work):
        raise OidcSessionActivationPlanningError("activation request commitment changed")
    work.prepare_utf8(OPERATION)
    work.prepare_utf8(request_digest)
    work.charge(hashes=1)
    if commitment._request_different(commitment.operation_id(OPERATION, request_digest),
                                     actual.get("operationId"), work=work):
        raise OidcSessionActivationPlanningError("activation operation commitment changed")
    wanted = index_heads._activation_ids(include_write_heads=transition_inputs is not None)
    for item, identifier in zip(owned["expectedCountedHeads"], wanted):
        if (type(item) is not dict or set(item) != _HEAD_FIELDS
                or type(item["indexId"]) is not str or item["indexId"] != identifier
                or type(item["indexRevision"]) is not int or not 0 <= item["indexRevision"] < 2**63
                or type(item["leafCount"]) is not int or not 0 <= item["leafCount"] < 2**63):
            raise OidcSessionActivationPlanningError("activation counted expectations differ from the fixed inventory")
        planning.retention.plan.contract._digest(item["rootDigest"])
    return owned


def _originals(*, assertion_bytes, old_token_bytes, new_token_bytes, delivery_custody_key, work):
    """Hold exact immutable originals before any invocation callback."""
    batch._SharedLedger(work)
    if (type(assertion_bytes) is not bytes
            or not 2 <= len(assertion_bytes) <= transition.assertion.MAX_ASSERTION_BYTES
            or type(delivery_custody_key) is not bytes
            or len(delivery_custody_key) != transition.delivery.KEY_BYTES):
        raise OidcSessionActivationPlanningError("activation write originals exceed their source bounds")
    work.charge(input_bytes=len(assertion_bytes) + len(delivery_custody_key))
    return (assertion_bytes, transition.assertion._token(old_token_bytes, work),
            transition.assertion._token(new_token_bytes, work), delivery_custody_key)


class _Lifetime:
    """Invocation-local sticky checks; never supplied by an external caller."""

    def __init__(self, owner, configured, window, bound, work, lock):
        self.owner, self.configured, self.window = owner, configured, window
        self.bound, self.work, self.lock = min(bound, window[4]), work, lock
        self.limits = work.limits
        self.ceilings = (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes)
        self.metrics = work.metrics
        self.last_epoch, self.last_monotonic = window[0], window[2]

    def _require(self):
        if (OidcSessionActivationReadPlanner._snapshot_configuration(self.owner) is not self.configured
                or self.owner._lock is not self.lock or not self.lock.locked()
                or self.work.limits is not self.limits
                or self.ceilings != (self.limits.max_hashes, self.limits.max_input_bytes,
                                     self.limits.max_json_nodes)):
            raise OidcSessionActivationPlanningError("activation acquisition owner or allowance changed")
        batch._SharedLedger(self.work)
        current = self.work.metrics
        if (current.hash_work < self.metrics.hash_work or current.input_bytes < self.metrics.input_bytes
                or current.json_nodes < self.metrics.json_nodes):
            raise OidcSessionActivationPlanningError("activation acquisition allowance was replenished")
        self.metrics = current

    def check(self):
        self._require()
        epoch = clock._check_on_work(self.window, work=self.work)
        monotonic = planning.reader.roots._callback(self.work, time.monotonic_ns)
        self._require()
        if (type(monotonic) is not int or monotonic < self.last_monotonic
                or monotonic >= self.bound or epoch < self.last_epoch):
            raise OidcSessionActivationPlanningError("activation original read lifetime expired or reversed")
        self.last_epoch, self.last_monotonic = epoch, monotonic
        return epoch


class _Result:
    __slots__ = ("_result", "_cursor", "_identity")

    def __init__(self, result, cursor):
        self._result, self._cursor = result, cursor
        self._identity = result, cursor

    def _call(self, name, *arguments):
        result, cursor = self._identity
        if self._result is not result or self._cursor is not cursor:
            raise OidcSessionActivationPlanningError("activation result handle changed")
        value = cursor._call(lambda: getattr(result, name)(*arguments))
        if self._result is not result or self._cursor is not cursor:
            raise OidcSessionActivationPlanningError("activation result handle changed")
        return value

    def fetchone(self):
        return self._call("fetchone")

    def fetchall(self):
        return self._call("fetchall")

    def fetchmany(self, size):
        return self._call("fetchmany", size)


class _Cursor:
    __slots__ = ("_cursor", "_lifetime", "_identity")

    def __init__(self, cursor, lifetime):
        self._cursor, self._lifetime = cursor, lifetime
        self._identity = cursor, lifetime

    def _call(self, callback):
        cursor, lifetime = self._identity
        if self._cursor is not cursor or self._lifetime is not lifetime:
            raise OidcSessionActivationPlanningError("activation cursor lifetime changed")
        lifetime.check()
        try:
            return planning.reader.roots._callback(lifetime.work, callback)
        finally:
            lifetime.check()
            if self._cursor is not cursor or self._lifetime is not lifetime:
                raise OidcSessionActivationPlanningError("activation cursor lifetime changed")

    def execute(self, sql, parameters=None):
        arguments = (sql,) if parameters is None else (sql, parameters)
        cursor = self._cursor
        return _Result(self._call(lambda: cursor.execute(*arguments)), self)


def _acquire(cursor, manifest, trace, owned, lifetime, work, originals=None):
    from serverware import authority_planner as planner

    physical = index_reader._ReadAcquisitionBudget(cursor, trace, work=work)
    request = owned["request"]
    full = originals is not None
    try:
        with physical.read_phase(cursor, trace, work):
            observed_business, observed_authorization, _ = planner._read_root_set(
                cursor, operation=OPERATION, manifest=manifest, trace=trace, work=work)
            semantics._canonical_equal((observed_business, observed_authorization),
                (owned["businessBeforeRoots"], owned["authorizationBeforeRoots"]), work=work,
                label="activation observed roots differ from independent expectations")
            database_now = planner._read_database_now_on_work(cursor, work)
            epoch = lifetime.check()
            database_ns = complete.cutoff_microseconds(database_now) * 1000
            if (abs(database_ns - epoch) > lifetime.configured[3]
                    or database_ns >= lifetime.window[3]):
                raise OidcSessionActivationPlanningError("activation database clock differs from original lifetime")
            queries = reads._queries(arguments=request["arguments"],
                cutoff_us=complete.cutoff_microseconds(database_now),
                request_digest=request["requestDigest"], work=work)
            collector = acquisition._CompleteQueryAcquisition(cursor, operation=OPERATION,
                arguments=request["arguments"], cutoff_us=complete.cutoff_microseconds(database_now),
                queries=tuple(query for query in queries if type(query) is complete.CompleteIndexQuery),
                business_before_roots=observed_business, authorization_before_roots=observed_authorization,
                trace=trace, work=work, acquisition=physical, include_write_heads=full)
            sources = staging.StagedQueryProofs(operation=OPERATION,
                business_before_roots=observed_business, authorization_before_roots=observed_authorization,
                query_work=work)
            selected, _, records = planner._read_bounded_transition_rows(cursor,
                operation=OPERATION, request=request, queries=queries, manifest=manifest,
                trace=trace, query_sources=sources, query_work=work, complete_acquisition=collector)
            retained = collector.retained_evidence()
            actual_heads = tuple({"indexId": head.index_id, "indexRevision": head.index_revision,
                "rootDigest": head.index_root.digest, "leafCount": head.index_root.count}
                for head in retained.heads)
            semantics._canonical_equal(actual_heads, owned["expectedCountedHeads"], work=work,
                label="activation observed counted heads differ from independent expectations")
            physical.require_idle(cursor, trace, work)
        lifetime.check()
        read_ids = {complete._role(OPERATION, role).index_id for role in complete.ACTIVATION_ROLES}
        read_heads = tuple(batch.CompleteQueryHead(head.index_id, head.index_revision, head.index_root)
                          for head in retained.heads if head.index_id in read_ids)
        if full:
            envelope, actual, writes = _write_evidence(cursor, trace, physical, request, database_now,
                selected, records, retained, read_heads, owned["transitionInputs"], originals, lifetime, work)
            for mutation in actual.transition.mutations:
                trace.write(mutation["table"], mutation["key"])
            closed_trace = trace.close(selected_rows=selected, mutation_plan=actual.transition.mutations)
        else:
            actual = None
            closed_trace = trace.close(selected_rows=selected, mutation_plan=())
        copier = query_reads._CopyBudget(work)
        raw = (copier.copy(request), database_now,
            copier.copy(selected), tuple(query_reads._copy_read(record, work) for record in records),
            retained.business_before_roots, retained.authorization_before_roots, retained.before_proofs,
            read_heads, retained.frontiers, copier.copy(closed_trace))
        if not full:
            return _AcquiredActivationReads(*raw), None
        counted = tuple(read_write.CompleteReadWriteHead(head.index_id, head.index_revision, head.index_root)
                        for head in retained.heads)
        _fresh_transition(actual, lifetime)
        return _AcquiredActivationTransition(*raw, envelope, actual.transition, counted, writes.index_inputs), actual
    except BaseException:
        physical.failed = True
        raise


def _fresh_transition(actual, lifetime):
    lifetime.check()
    if actual.live() >= actual.valid_until_epoch_ns:
        raise OidcSessionActivationPlanningError("activation originals expired during write acquisition")
    lifetime.check()


def _write_evidence(cursor, trace, physical, request, database_now, selected, records,
                    retained, read_heads, inputs, originals, lifetime, work):
    """Derive the envelope/effects and read real write proofs in this snapshot."""
    registration, core = transition.registration, transition.core
    context = core.KernelContext(OPERATION, request["arguments"], selected, database_now,
                                 request["requestDigest"], query_reads=records)
    # Real primary/range acquisition has already proved these original rows.
    # Semantic caller/assertion/token/trust admission still runs below before
    # any mutation-frontier query and before any result can escape.
    values = transition._arguments(context.arguments, work)
    session = context._exact("oidc_browser_sessions", {"id": values["session_id"]}, work=work)
    if session["present"] is not True or type(session["row"]) is not dict:
        raise OidcSessionActivationPlanningError("activation delivery requires the exact proved session row")
    delivery_id = core._deterministic_uuid(operation=OPERATION, request_digest=context.request_digest,
        purpose=reads.DELIVERY_PURPOSE, work=work)
    expiry = min(database_now + timedelta(seconds=values["delivery_ttl_seconds"]),
                 registration._utc(session["row"].get("expires_at"), "session expiry", work))
    scope = {"deliveryId": delivery_id, "userId": values["user_id"], "sessionId": values["session_id"],
        "credentialId": values["credential_id"], "credentialRecordId": values["credential_record_id"],
        "challengeId": values["challenge_id"], "assertionDigest": values["assertion_digest"],
        "oldTokenDigest": values["old_token_digest"], "newTokenDigest": values["new_token_digest"],
        "createdAt": database_now.isoformat(), "expiresAt": expiry.isoformat()}
    lifetime.check()
    envelope = transition.delivery._seal_on_work(new_token_bytes=originals[2], custody_key=originals[3],
        scope=scope, live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    lifetime.check()
    actual = transition._full_transition_with_liveness_on_work(context,
        assertion_bytes=originals[0], old_token_bytes=originals[1], new_token_bytes=originals[2],
        delivery_envelope_bytes=envelope, delivery_custody_key=originals[3],
        expected_user_id=inputs["userId"], expected_session_id=inputs["sessionId"],
        expected_credential_id=inputs["credentialId"],
        expected_credential_record_id=inputs["credentialRecordId"], expected_challenge_id=inputs["challengeId"],
        rp_id=inputs["rpId"], origin=inputs["origin"], authn_policy=inputs["authnPolicy"],
        trust_policy=inputs["trustPolicy"], business_before_roots=retained.business_before_roots,
        authorization_before_roots=retained.authorization_before_roots, before_proofs=retained.before_proofs,
        read_heads=read_heads, query_frontiers=retained.frontiers, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work)
    _fresh_transition(actual, lifetime)
    mutations = actual.transition.mutations
    write_ids = {index_id for item in mutations for index_id in projection.index_ids_for_table(item["table"])}
    expected_write_ids = set(index_heads._activation_ids(include_write_heads=True)) - {
        "webauthn_publication_status"}
    if len(mutations) != 6 or write_ids != expected_write_ids or len(write_ids) != 12:
        raise OidcSessionActivationPlanningError("activation effects differ from the fixed indexed write closure")
    heads = tuple(indexed.IndexedMutationHead(head.index_id, head.index_revision, head.index_root)
                  for head in retained.heads if head.index_id in write_ids)
    limits = read_write._write_limits(authority.operation_spec(OPERATION), batch._SharedLedger(work))
    writer = mutation_reader._AcquisitionBudget(shared_acquisition=physical, work=work)
    writes = mutation_reader._acquire_indexed_primary_batch(cursor,
        table_contracts=primary.primary_table_contracts(OPERATION),
        business_before_roots=batch._roots(retained.business_before_roots),
        authorization_before_roots=batch._roots(retained.authorization_before_roots),
        selected_rows=selected, before_proofs=retained.before_proofs, mutations=mutations,
        index_before_heads=heads, limits=limits, trace=trace, acquisition_budget=writer)
    physical.require_idle(cursor, trace, work)
    _fresh_transition(actual, lifetime)
    return envelope, actual, writes


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class OidcSessionActivationReadPlanner:
    _configured: tuple
    _pid: int
    _lock: object

    def __init__(self, *, read_dsn, connect_timeout_seconds, database_identity, maximum_clock_skew_ns):
        configured = _configuration((read_dsn, connect_timeout_seconds,
                                     database_identity, maximum_clock_skew_ns))
        object.__setattr__(self, "_configured", configured)
        object.__setattr__(self, "_pid", os.getpid())
        object.__setattr__(self, "_lock", threading.Lock())

    def _snapshot_configuration(self):
        if (type(self) is not OidcSessionActivationReadPlanner or type(self._pid) is not int
                or self._pid != os.getpid() or type(self._lock) is not _LOCK_TYPE):
            raise OidcSessionActivationPlanningError("activation read owner process changed")
        return _configuration(self._configured)

    def acquire(self, *, request, business_before_roots, authorization_before_roots,
                expected_counted_heads, live_window, transport_deadline_ns, work: _ValidationWork):
        return OidcSessionActivationReadPlanner._run(self, request=request,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work)

    def acquire_transition(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, assertion_bytes, old_token_bytes, new_token_bytes, delivery_custody_key,
            expected_user_id, expected_session_id, expected_credential_id, expected_credential_record_id,
            expected_challenge_id, rp_id, origin, authn_policy, trust_policy,
            live_window, transport_deadline_ns, work: _ValidationWork):
        originals = _originals(assertion_bytes=assertion_bytes, old_token_bytes=old_token_bytes,
            new_token_bytes=new_token_bytes, delivery_custody_key=delivery_custody_key, work=work)
        inputs = {"userId": expected_user_id, "sessionId": expected_session_id,
            "credentialId": expected_credential_id, "credentialRecordId": expected_credential_record_id,
            "challengeId": expected_challenge_id, "rpId": rp_id, "origin": origin,
            "authnPolicy": authn_policy, "trustPolicy": trust_policy}
        return OidcSessionActivationReadPlanner._run(self, request=request,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work, transition_inputs=inputs, originals=originals)

    def _run(self, *, request, business_before_roots, authorization_before_roots,
             expected_counted_heads, live_window, transport_deadline_ns, work,
             transition_inputs=None, originals=None):
        configured = OidcSessionActivationReadPlanner._snapshot_configuration(self)
        lock = self._lock
        if not lock.acquire(blocking=False):
            raise OidcSessionActivationPlanningError("activation read owner is already in use")
        try:
            owned = _capture(request=request, business_before_roots=business_before_roots,
                authorization_before_roots=authorization_before_roots,
                expected_counted_heads=expected_counted_heads, live_window=live_window,
                transport_deadline_ns=transport_deadline_ns, work=work, transition_inputs=transition_inputs)
            window = owned["liveWindow"]
            if window[6] != configured[3]:
                raise OidcSessionActivationPlanningError("activation live clock policy differs from its owner")
            lifetime = _Lifetime(self, configured, window, owned["transportDeadlineNs"], work, lock)
            lifetime.check()
            timeout = min(configured[1], (lifetime.bound - lifetime.last_monotonic) // 1_000_000_000)
            if timeout < 2:
                raise OidcSessionActivationPlanningError("activation lifetime cannot cover libpq minimum timeout")
            read_configuration = (configured[0], timeout, configured[2])
            with planning._read_scope(read_configuration, operation=OPERATION, work=work) as (
                    cursor, manifest, trace):
                lifetime.check()
                guarded = _Cursor(cursor, lifetime)
                result, actual = _acquire(guarded, manifest, trace, owned, lifetime, work, originals)
                lifetime.check()
            # An actual result cannot escape a failed cursor/transaction/
            # connection exit, a replaced owner or the original elapsed bound.
            lifetime.check()
            if actual is not None:
                _fresh_transition(actual, lifetime)
            return result
        finally:
            lock.release()
