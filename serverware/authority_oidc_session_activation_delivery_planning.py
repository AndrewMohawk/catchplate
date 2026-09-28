"""Configured read-only original acquisition for delivery consumption.

One real PostgreSQL snapshot supplies primary, complete-range and counted-write
proof originals. Independent roots/heads, original old-token possession and
current policy are retained before callbacks; the full method invokes genuine
consume semantics before acquiring its five write frontiers. No AES, token
generation, signing, DML, caller cursor or successful proof carrier is accepted.
Returned detached data must be genuinely replayed by any downstream planner.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime

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
from serverware import authority_oidc_session_activation_delivery_reads as reads
from serverware import authority_oidc_session_activation_planning as read_support
from serverware import authority_query_reads as query_reads
from serverware import authority_query_staging as staging
from serverware import authority_primary_contract as primary
from serverware import authority_request_commitment as commitment
from serverware import authority_revocation_planning as planning
from serverware import authority_revocation_semantics as semantics
from serverware import authority_transition_oidc_session_activation_delivery as transition
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware.authority_query_read_work import _ValidationWork


OPERATION = reads.OPERATION
_HEAD_FIELDS = frozenset({"indexId", "indexRevision", "rootDigest", "leafCount"})
_LOCK_TYPE = type(threading.Lock())


class OidcSessionActivationDeliveryPlanningError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class _AcquiredDeliveryReads:
    """Owned original observations, never a transferable admission capability."""

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
class _AcquiredDeliveryTransition(_AcquiredDeliveryReads):
    """Actual derived effects and original write proofs; not committed SQL."""

    transition: transition.core.KernelTransition
    counted_before_heads: tuple
    write_inputs: tuple


def _configuration(value):
    # Only the existing operation-neutral immutable DB/TLS scope grammar is
    # shared. No activation operation, key, semantic worker or result is reused.
    try:
        return read_support._configuration(value)
    except ValueError as exc:
        raise OidcSessionActivationDeliveryPlanningError("delivery read configuration is invalid") from exc


def _capture(*, request, business_before_roots, authorization_before_roots,
             expected_counted_heads, live_window, transport_deadline_ns, work,
             transition_inputs=None):
    batch._SharedLedger(work)
    if (type(request) is not dict or len(request) != 7
            or type(expected_counted_heads) is not tuple or len(expected_counted_heads) != 7
            or type(live_window) is not tuple or len(live_window) != 7
            or type(transport_deadline_ns) is not int or transport_deadline_ns <= 0):
        raise OidcSessionActivationDeliveryPlanningError("delivery read originals are not source bounded")
    for roots in (business_before_roots, authorization_before_roots):
        if type(roots) not in (list, tuple) or len(roots) > authority.MAX_QUERY_PROOFS:
            raise OidcSessionActivationDeliveryPlanningError("delivery primary expectations are not bounded")
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
        raise OidcSessionActivationDeliveryPlanningError("delivery request operation changed")
    complete._delivery_binding_inputs(actual.get("arguments"), window[0] // 1000, work=work)
    request_digest = commitment._typed_request_digest(actual, work=work)
    if commitment._request_different(request_digest, actual.get("requestDigest"), work=work):
        raise OidcSessionActivationDeliveryPlanningError("delivery request commitment changed")
    work.prepare_utf8(OPERATION)
    work.prepare_utf8(request_digest)
    work.charge(hashes=1)
    if commitment._request_different(commitment.operation_id(OPERATION, request_digest),
                                     actual.get("operationId"), work=work):
        raise OidcSessionActivationDeliveryPlanningError("delivery operation commitment changed")
    for item, identifier in zip(owned["expectedCountedHeads"], index_heads._delivery_ids()):
        if (type(item) is not dict or set(item) != _HEAD_FIELDS
                or type(item["indexId"]) is not str or item["indexId"] != identifier
                or type(item["indexRevision"]) is not int or not 0 <= item["indexRevision"] < 2**63
                or type(item["leafCount"]) is not int or not 0 <= item["leafCount"] < 2**63
                or item["indexRevision"] == 0 and item["leafCount"] != 0):
            raise OidcSessionActivationDeliveryPlanningError("delivery counted expectations differ from their inventory")
        planning.retention.plan.contract._digest(item["rootDigest"])
    return owned


class _Lifetime:
    """Current processing guard owned by this invocation, never caller supplied."""

    def __init__(self, owner, configured, window, bound, work, lock, *, _current=None):
        self.owner, self.configured, self.window = owner, configured, window
        self.bound, self.work, self.lock = min(bound, window[4]), work, lock
        self.limits = work.limits
        self.ceilings = (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes)
        self.metrics = work.metrics
        self.last_epoch, self.last_monotonic = window[0], window[2]
        self.external_current = _current
        self.current = transition.delivery._join_current(self._check, _current, work)

    def _require(self):
        if (OidcSessionActivationDeliveryReadPlanner._snapshot_configuration(self.owner) is not self.configured
                or self.owner._lock is not self.lock or not self.lock.locked()
                or self.work.limits is not self.limits
                or self.ceilings != (self.limits.max_hashes, self.limits.max_input_bytes,
                                     self.limits.max_json_nodes)):
            raise OidcSessionActivationDeliveryPlanningError("delivery read owner or allowance changed")
        batch._SharedLedger(self.work)
        current = self.work.metrics
        if (current.hash_work < self.metrics.hash_work or current.input_bytes < self.metrics.input_bytes
                or current.json_nodes < self.metrics.json_nodes):
            raise OidcSessionActivationDeliveryPlanningError("delivery read allowance was replenished")
        self.metrics = current

    def check(self):
        return self.current()

    def _check(self):
        self._require()
        epoch = clock._check_on_work(self.window, work=self.work)
        monotonic = planning.reader.roots._callback(self.work, time.monotonic_ns)
        self._require()
        if (type(monotonic) is not int or monotonic < self.last_monotonic
                or monotonic >= self.bound or epoch < self.last_epoch):
            raise OidcSessionActivationDeliveryPlanningError("delivery read lifetime expired or reversed")
        self.last_epoch, self.last_monotonic = epoch, monotonic
        return epoch


def _fresh_transition(actual, lifetime):
    lifetime.check()
    if type(actual) is not transition._FullTransition or actual.live() >= actual.valid_until_epoch_ns:
        raise OidcSessionActivationDeliveryPlanningError("delivery originals expired during write acquisition")
    lifetime.check()


def _write_evidence(cursor, trace, physical, request, database_now, selected, records,
                    retained, read_heads, inputs, token, lifetime, work):
    context = transition.core.KernelContext(OPERATION, request["arguments"], selected,
        database_now, request["requestDigest"], query_reads=records)
    actual = transition._full_transition_with_liveness_on_work(context,
        old_token_bytes=token, expected_delivery_id=inputs["deliveryId"],
        expected_user_id=inputs["userId"], expected_session_id=inputs["sessionId"],
        expected_credential_id=inputs["credentialId"],
        expected_credential_record_id=inputs["credentialRecordId"], expected_challenge_id=inputs["challengeId"],
        authn_policy=inputs["authnPolicy"], trust_policy=inputs["trustPolicy"],
        business_before_roots=retained.business_before_roots,
        authorization_before_roots=retained.authorization_before_roots, before_proofs=retained.before_proofs,
        read_heads=read_heads, query_frontiers=retained.frontiers, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _current=lifetime.external_current)
    _fresh_transition(actual, lifetime)
    mutations = actual.transition.mutations
    write_ids = {identifier for item in mutations for identifier in projection.index_ids_for_table(item["table"])}
    expected = set(projection.index_ids_for_table("oidc_session_activation_deliveries"))
    if len(mutations) != 3 or len(expected) != 5 or write_ids != expected:
        raise OidcSessionActivationDeliveryPlanningError("delivery effects differ from the five-index write closure")
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
    return actual, writes


def _acquire(cursor, manifest, trace, owned, lifetime, work, token=None):
    from serverware import authority_planner as planner

    physical = index_reader._ReadAcquisitionBudget(cursor, trace, work=work)
    request, full = owned["request"], token is not None
    try:
        with physical.read_phase(cursor, trace, work):
            business, authorization, _ = planner._read_root_set(
                cursor, operation=OPERATION, manifest=manifest, trace=trace, work=work)
            semantics._canonical_equal((business, authorization),
                (owned["businessBeforeRoots"], owned["authorizationBeforeRoots"]), work=work,
                label="delivery observed roots differ from independent expectations")
            database_now = planner._read_database_now_on_work(cursor, work)
            epoch = lifetime.check()
            database_ns = complete.cutoff_microseconds(database_now) * 1000
            if (abs(database_ns - epoch) > lifetime.configured[3] or database_ns >= lifetime.window[3]):
                raise OidcSessionActivationDeliveryPlanningError("delivery database time differs from original lifetime")
            queries = reads._queries(arguments=request["arguments"],
                cutoff_us=complete.cutoff_microseconds(database_now), request_digest=request["requestDigest"], work=work)
            collector = acquisition._CompleteQueryAcquisition(cursor, operation=OPERATION,
                arguments=request["arguments"], cutoff_us=complete.cutoff_microseconds(database_now),
                queries=tuple(query for query in queries if type(query) is complete.CompleteIndexQuery),
                business_before_roots=business, authorization_before_roots=authorization,
                trace=trace, work=work, acquisition=physical, include_write_heads=full)
            sources = staging.StagedQueryProofs(operation=OPERATION, business_before_roots=business,
                authorization_before_roots=authorization, query_work=work)
            selected, _, records = planner._read_bounded_transition_rows(cursor,
                operation=OPERATION, request=request, queries=queries, manifest=manifest,
                trace=trace, query_sources=sources, query_work=work, complete_acquisition=collector)
            retained = collector.retained_evidence()
            actual_heads = tuple({"indexId": head.index_id, "indexRevision": head.index_revision,
                "rootDigest": head.index_root.digest, "leafCount": head.index_root.count} for head in retained.heads)
            semantics._canonical_equal(actual_heads, owned["expectedCountedHeads"], work=work,
                label="delivery observed counted heads differ from independent expectations")
            physical.require_idle(cursor, trace, work)
        lifetime.check()
        read_heads = tuple(batch.CompleteQueryHead(head.index_id, head.index_revision, head.index_root)
                           for head in retained.heads)
        if full:
            actual, writes = _write_evidence(cursor, trace, physical, request, database_now,
                selected, records, retained, read_heads, owned["transitionInputs"], token, lifetime, work)
            for mutation in actual.transition.mutations:
                trace.write(mutation["table"], mutation["key"])
            closed_trace = trace.close(selected_rows=selected, mutation_plan=actual.transition.mutations)
        else:
            actual = None
            closed_trace = trace.close(selected_rows=selected, mutation_plan=())
        copier = query_reads._CopyBudget(work)
        raw = (copier.copy(request), database_now, copier.copy(selected),
            tuple(query_reads._copy_read(record, work) for record in records),
            retained.business_before_roots, retained.authorization_before_roots, retained.before_proofs,
            read_heads, retained.frontiers, copier.copy(closed_trace))
        if not full:
            return _AcquiredDeliveryReads(*raw), None
        counted = tuple(read_write.CompleteReadWriteHead(head.index_id, head.index_revision, head.index_root)
                        for head in retained.heads)
        _fresh_transition(actual, lifetime)
        return _AcquiredDeliveryTransition(*raw, actual.transition, counted, writes.index_inputs), actual
    except BaseException:
        physical.failed = True
        raise


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class OidcSessionActivationDeliveryReadPlanner:
    _configured: tuple
    _pid: int
    _lock: object

    def __init__(self, *, read_dsn, connect_timeout_seconds, database_identity, maximum_clock_skew_ns):
        configured = _configuration((read_dsn, connect_timeout_seconds, database_identity, maximum_clock_skew_ns))
        object.__setattr__(self, "_configured", configured)
        object.__setattr__(self, "_pid", os.getpid())
        object.__setattr__(self, "_lock", threading.Lock())

    def _snapshot_configuration(self):
        if (type(self) is not OidcSessionActivationDeliveryReadPlanner or type(self._pid) is not int
                or self._pid != os.getpid() or type(self._lock) is not _LOCK_TYPE):
            raise OidcSessionActivationDeliveryPlanningError("delivery read owner process changed")
        return _configuration(self._configured)

    def acquire(self, *, request, business_before_roots, authorization_before_roots,
                expected_counted_heads, live_window, transport_deadline_ns, work: _ValidationWork):
        return OidcSessionActivationDeliveryReadPlanner._run(self, request=request,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work)

    def acquire_transition(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, old_token_bytes, expected_delivery_id, expected_user_id,
            expected_session_id, expected_credential_id, expected_credential_record_id,
            expected_challenge_id, authn_policy, trust_policy,
            live_window, transport_deadline_ns, work: _ValidationWork, _current=None):
        token = transition.assertion._token(old_token_bytes, work)
        inputs = {"deliveryId": expected_delivery_id, "userId": expected_user_id, "sessionId": expected_session_id,
            "credentialId": expected_credential_id, "credentialRecordId": expected_credential_record_id,
            "challengeId": expected_challenge_id, "authnPolicy": authn_policy, "trustPolicy": trust_policy}
        return OidcSessionActivationDeliveryReadPlanner._run(self, request=request,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work, transition_inputs=inputs, token=token,
            _current=_current)

    def _run(self, *, request, business_before_roots, authorization_before_roots,
             expected_counted_heads, live_window, transport_deadline_ns, work,
             transition_inputs=None, token=None, _current=None):
        configured = OidcSessionActivationDeliveryReadPlanner._snapshot_configuration(self)
        lock = self._lock
        if not lock.acquire(blocking=False):
            raise OidcSessionActivationDeliveryPlanningError("delivery read owner is already in use")
        try:
            owned = _capture(request=request, business_before_roots=business_before_roots,
                authorization_before_roots=authorization_before_roots, expected_counted_heads=expected_counted_heads,
                live_window=live_window, transport_deadline_ns=transport_deadline_ns,
                work=work, transition_inputs=transition_inputs)
            window = owned["liveWindow"]
            if window[6] != configured[3]:
                raise OidcSessionActivationDeliveryPlanningError("delivery clock policy differs from its owner")
            lifetime = _Lifetime(self, configured, window, owned["transportDeadlineNs"], work, lock,
                _current=_current)
            lifetime.check()
            timeout = min(configured[1], (lifetime.bound - lifetime.last_monotonic) // 1_000_000_000)
            if timeout < 2:
                raise OidcSessionActivationDeliveryPlanningError("delivery lifetime cannot cover libpq minimum timeout")
            with planning._read_scope((configured[0], timeout, configured[2]), operation=OPERATION,
                    work=work, _current=lifetime.check if _current is not None else None) as (
                    cursor, manifest, trace):
                lifetime.check()
                # This wrapper owns only native cursor/result identity and
                # supplied lifetime checks; no activation purpose is adopted.
                guarded = read_support._Cursor(cursor, lifetime)
                result, actual = _acquire(guarded, manifest, trace, owned, lifetime, work, token)
                lifetime.check()
            # Failed cursor/transaction/connection cleanup cannot return data.
            lifetime.check()
            if actual is not None:
                _fresh_transition(actual, lifetime)
            return result
        finally:
            lock.release()
