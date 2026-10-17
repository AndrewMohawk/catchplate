"""One actual invalidation read, genuine replay and original-interval signer.

The measured caller must already admit protected read credentials, signing
keys/configuration, current roots, the request and its claimed recovery witness.
The real native owner remains the only acquisition path, and its existing
registry gate is not bypassed here. No supplied proof/result/native DTO, writer
connection, persistence, execution grant, replacement meter or clock is used.

The original generic work is shared across capture, native setup/acquisition,
replay and signing. Exhaustion refuses; no maximum-size capacity claim is made.
"""
from __future__ import annotations

import os
import threading
import time

from catchplate import authority_recovery_invalidation_planning as planning
from catchplate import authority_recovery_invalidation_plan as plan
from catchplate.authority_query_read_work import _ValidationWork


proof, acquisition, evidence, clock = plan.proof, plan.acquisition, plan.evidence, plan.clock
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_require = plan._require


def _configuration(value):
    _require(type(value) is tuple and len(value) == 8)
    reader, original, private, public, identity, spki, configuration, policy = value
    _require(type(reader) is planning.RecoveryInvalidationReadPlanner and reader._configured is original)
    planning._configuration(original)
    _require(isinstance(private, plan.Ed25519PrivateKey) and isinstance(public, plan.Ed25519PublicKey)
        and type(identity) is tuple and len(identity) == 3 and identity == original[2][4:]
        and type(policy) is tuple and len(policy) == 2)
    for digest in (*identity, spki, configuration):
        plan.shape._digest(digest)
    plan.shape._integer(policy[0], proof.contract.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    plan.shape._integer(policy[1], proof.contract.VERIFIER_MAX_CLOCK_SKEW_NS)
    return value


class _Invocation:
    def __init__(self, owner, configured, window, deadline, check, work):
        _require(type(work) is _ValidationWork and callable(check))
        window = clock._validate(window)
        plan.shape._integer(deadline, minimum=1)
        _require(window[1] < deadline <= window[4]
            and window[5] <= configured[7][0] and window[6] <= configured[7][1])
        self.owner, self.configured, self.window, self.deadline = owner, configured, window, deadline
        self.callback, self.work, self.limits = check, work, work.limits
        self.original = owner, configured, window, deadline, check, work, work.limits
        self.maximums = work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes
        self.metrics = work.hash_work, work.input_bytes, work.json_nodes
        self.identity = os.getpid(), threading.get_ident()
        self.expires = window[0] + deadline - window[1]
        self.last = 0
        self.busy = self.failed = self.native = False

    def local(self):
        _require(not self.failed and not self.owner._failed
            and type(self.owner) is RecoveryInvalidationPlanOwner
            and self.owner._configured is self.configured and self.owner._held is self.configured
            and self.configured[0]._configured is self.configured[1]
            and self.identity == (os.getpid(), threading.get_ident())
            and all(actual is original for actual, original in zip((self.owner, self.configured,
                self.window, self.deadline, self.callback, self.work, self.limits), self.original))
            and (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes) == self.maximums)
        # Only the direct genuine native call may hold mutation reservations.
        # Its own _Guard checks the exact source-created collector/formula on
        # both sides of this neutral external callback. Do not introduce a
        # weaker generic <=limit admission or reject that legitimate hold.
        if not self.native:
            _require(self.work.limits is self.limits)
        proof.batch._SharedLedger(self.work)
        actual = self.work.hash_work, self.work.input_bytes, self.work.json_nodes
        _require(all(type(value) is int and value >= before for value, before in zip(actual, self.metrics)))
        self.metrics = actual
        epoch = clock._check_on_work(self.window, work=self.work)
        mono = evidence.production._callback(self.work, time.monotonic_ns)
        _require(epoch < self.expires and type(mono) is int and self.last <= mono < self.deadline)
        self.last = mono

    def checked(self):
        try:
            _require(not self.busy)
            self.busy = True
            self.local()
            _require(evidence.production._callback(self.work, self.callback) is None)
            self.local()
        except BaseException:
            self.failed = self.owner._failed = True
            raise
        finally:
            self.busy = False


def _native_context(raw, owned, configured, guard, work):
    """Use only the actual returned native cutoff; reconstruct all other pins."""
    document = plan._decode(raw, proof.MAX_INPUT_BYTES, work)
    proof._object(document, proof._FIELDS)
    proof._object(document["context"], proof._CONTEXT)
    _require(document["schema"] == proof.SCHEMA)
    raw_cutoff = document["context"]["databaseNow"]
    cutoff = plan._cutoff_ns(raw_cutoff)
    _require(abs(cutoff - guard.window[0]) <= guard.window[6] and cutoff < guard.expires)
    # The native database sampled this cutoff after admitting these exact
    # before anchors. Embedded roots, arguments and policy never select pins.
    business = acquisition._root_objects(owned[1], work)
    authorization = acquisition._root_objects(owned[2], work)
    work.prepare_copy(owned[3])
    heads = tuple(proof.read_write.CompleteReadWriteHead(value["indexId"], value["indexRevision"],
        proof.CountedNode(value["rootDigest"], value["leafCount"])) for value in owned[3])
    now = plan.datetime.fromisoformat(raw_cutoff)
    context = proof.context_document(arguments=owned[0]["arguments"],
        request_digest=owned[0]["requestDigest"], database_now=now,
        business_before_roots=business, authorization_before_roots=authorization,
        counted_before_heads=heads, terminal_retention_seconds=configured[1][3],
        maximum_retained=configured[1][4], work=work)
    proof._same(document["context"], context, work)
    return context


class RecoveryInvalidationPlanOwner:
    """Inert exact reader/signer configuration; each owner produces once."""

    __slots__ = ("_configured", "_held", "_used", "_failed")

    def __init__(self, *, read_planner, planner_private_key, planner_public_key,
            expected_planner_identity, expected_planner_spki_digest, configuration_digest,
            maximum_plan_age_ns, maximum_clock_skew_ns):
        _require(type(read_planner) is planning.RecoveryInvalidationReadPlanner)
        evidence._identity(expected_planner_identity)
        values = (read_planner, read_planner._configured, planner_private_key, planner_public_key,
            tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS), expected_planner_spki_digest,
            configuration_digest, (maximum_plan_age_ns, maximum_clock_skew_ns))
        self._configured = self._held = _configuration(values)
        self._used = self._failed = False

    @property
    def operation(self):
        self._snapshot()
        return plan.OPERATION

    def _snapshot(self):
        _require(type(self) is RecoveryInvalidationPlanOwner and self._configured is self._held)
        return _configuration(self._configured)

    def produce(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, live_window, original_deadline_ns, check, work):
        try:
            _require(not self._used and not self._failed and type(work) is _ValidationWork)
            self._used = True
            configured = self._snapshot()
            _require(type(request) is dict and type(business_before_roots) is tuple
                and len(business_before_roots) == 5 and type(authorization_before_roots) is tuple
                and not authorization_before_roots and type(expected_counted_heads) is tuple
                and len(expected_counted_heads) == 9)
            owned = proof._own((request, business_before_roots, authorization_before_roots, expected_counted_heads), work)
            acquisition._request(owned[0], work)
            request_bytes = work.wire(owned[0])
            _require(len(request_bytes) <= proof.contract.MAX_REQUEST_BYTES)
            work.charge(input_bytes=8192, json_nodes=512)
            guard = _Invocation(self, configured, live_window, original_deadline_ns, check, work)
            guard.checked()
            evidence.keys._public_binding(configured[3], configured[5], work)
            evidence.keys._pair_on_work(configured[2], configured[3], work)
            guard.checked()
            guard.native = True
            try:
                raw = planning.RecoveryInvalidationReadPlanner.acquire_originals(configured[0],
                    request=owned[0], business_before_roots=owned[1], authorization_before_roots=owned[2],
                    expected_counted_heads=owned[3], now_epoch_ns=guard.window[0],
                    deadline_epoch_ns=guard.expires, live_window=guard.window, check=guard.checked, work=work)
            finally:
                guard.native = False
            _require(type(raw) is bytes)
            guard.checked()
            context = _native_context(raw, owned, configured, guard, work)
            work.charge(input_bytes=2048, json_nodes=96)
            expected = {"context": context, "configurationDigest": configured[6],
                "plannerIdentity": dict(zip(_IDENTITY_FIELDS, configured[4])),
                "plannerSpkiDigest": configured[5], "operationId": owned[0]["operationId"],
                "originalDeadlineNs": guard.deadline, "maximumPlanAgeNs": guard.window[5],
                "maximumClockSkewNs": guard.window[6]}
            guard.checked()
            result = plan._produce_on_work(request_bytes=request_bytes, proof_bytes=raw, expectations=expected,
                planner_private_key=configured[2], planner_public_key=configured[3],
                issued_at_epoch_ns=guard.window[0], expires_at_epoch_ns=guard.expires,
                live_window=guard.window, check=guard.checked, work=work)
            _require(type(result) is plan.VerifiedRecoveryInvalidationPlan)
            guard.checked()
            return result
        except BaseException:
            self._failed = True
            raise
