"""Configured one-key invalidation custody, through real commit and close.

Each invocation borrows its original window/work and independently admitted
context. Received intervals can only narrow it. The store authenticates raw4
and replays proofs before any INSERT or successful read. An exception after
commit dispatch is indeterminate, never rollback proof or retry permission.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from catchplate import authority_recovery_invalidation_retention as retention
from catchplate import authority_revocation_writer_connection as writer
from catchplate.authority_store import recovery_invalidation_retention as store

plan, proof = retention.plan, retention.plan.proof
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_require = plan._require


def _configuration(values):
    _require(type(values) is tuple and len(values) == 11)
    dsn, timeout, database, key, identity, spki, configuration, age, skew, seconds, maximum = values
    writer.reader._bounded_text(dsn, 65536)
    _require("\n" not in dsn and "\r" not in dsn and type(timeout) is int and 2 <= timeout <= 300)
    writer._validate_database_identity(database)
    _require(isinstance(key, plan.Ed25519PublicKey) and type(identity) is tuple and len(identity) == 3)
    for value in (*identity, spki, configuration):
        plan.shape._digest(value)
    plan.shape._integer(age, proof.contract.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    plan.shape._integer(skew, proof.contract.VERIFIER_MAX_CLOCK_SKEW_NS)
    _require(type(seconds) is int and 86400 <= seconds <= 31536000
        and type(maximum) is int and 100 <= maximum <= 1000000)
    return values


def _expectations(configured, expectations, work):
    plan._object(expectations, plan.EXPECTATION_FIELDS)
    owned = proof._own(expectations, work)
    for name in ("configurationDigest", "plannerSpkiDigest", "operationId"):
        plan.shape._digest(owned[name])
    plan.evidence._identity(owned["plannerIdentity"])
    plan.shape._integer(owned["originalDeadlineNs"], minimum=1)
    plan.shape._integer(owned["maximumPlanAgeNs"], configured[7], minimum=1)
    plan.shape._integer(owned["maximumClockSkewNs"], configured[8])
    proof._parts(owned["context"], work)
    for actual, expected in ((owned["configurationDigest"], configured[6]),
            (owned["plannerSpkiDigest"], configured[5]),
            (tuple(owned["plannerIdentity"][name] for name in _IDENTITY_FIELDS), configured[4]),
            (owned["context"]["terminalRetentionSeconds"], configured[9]),
            (owned["context"]["maximumRetained"], configured[10])):
        proof._same(actual, expected, work)
    return owned


class _Invocation:
    def __init__(self, owner, configured, expected, window, check, work):
        _require(callable(check))
        self.window = plan.clock._validate(window)
        _require(window[5] <= expected["maximumPlanAgeNs"] and window[6] <= expected["maximumClockSkewNs"])
        self.owner, self.configured, self.expected = owner, configured, expected
        self.check, self.work, self.limits = check, work, work.limits
        self.held = owner, configured, expected, window, check, work, work.limits
        self.process = os.getpid(), threading.get_ident()
        self.deadline = min(expected["originalDeadlineNs"], window[4])
        self.epoch_deadline = min(window[3], window[0] + self.deadline - window[1])
        self.last = window[2]
        self.live = None
        self.failed = False

    def _local(self):
        _require(not self.failed and self.process == (os.getpid(), threading.get_ident())
            and type(self.owner) is RecoveryInvalidationPlanPersistence
            and self.owner._configured is self.configured
            and all(a is b for a, b in zip((self.owner, self.configured, self.expected,
                self.window, self.check, self.work, self.limits), self.held, strict=True))
            and self.work.limits is self.limits)
        proof.batch._SharedLedger(self.work)
        now = plan.clock._check_on_work(self.window, work=self.work)
        mono = plan.evidence.production._callback(self.work, time.monotonic_ns)
        _require(type(mono) is int and self.last <= mono < self.deadline and now < self.epoch_deadline)
        self.last = mono

    def _base(self):
        self._local()
        _require(plan.evidence.production._callback(self.work, self.check) is None)
        self._local()

    def checked(self):
        try:
            if self.live is None:
                self._base()
            else:
                self.live.checked()
        except BaseException:
            self.failed = True
            raise

    def bind(self, originals):
        """Only decode original bytes; an unverified interval can only refuse."""
        _require(self.live is None)
        self.checked()
        owned, request, context = plan._originals(originals[1], originals[2], self.expected, self.work)
        self.work.charge(input_bytes=len(context) + len(originals[3]))
        _require(context == originals[3])
        envelope = plan._decode(originals[0], plan.MAX_PARENT_BYTES, self.work, nodes=2048, depth=8)
        plan._object(envelope, {"schema", "payload", "signatureBase64Url"})
        _require(envelope["schema"] == plan.ENVELOPE_SCHEMA)
        plan._bind(envelope["payload"], owned, request, *originals[1:], self.work)
        self.live = plan._Live(owned, envelope["payload"], self.window, self._base, self.work)
        self.checked()


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class RecoveryInvalidationPlanPersistence:
    _configured: tuple

    def __init__(self, *, writer_dsn, connect_timeout_seconds, database_identity,
            planner_public_key, planner_identity, planner_spki_digest, configuration_digest,
            maximum_plan_age_ns, maximum_clock_skew_ns, terminal_retention_seconds, maximum_retained):
        plan.evidence._identity(planner_identity)
        configured = (writer_dsn, connect_timeout_seconds, database_identity, planner_public_key,
            tuple(planner_identity[name] for name in _IDENTITY_FIELDS), planner_spki_digest,
            configuration_digest, maximum_plan_age_ns, maximum_clock_skew_ns,
            terminal_retention_seconds, maximum_retained)
        object.__setattr__(self, "_configured", _configuration(configured))

    def _run(self, *, originals, retained_record_digest, expectations, live_window, check, work):
        _require(type(self) is RecoveryInvalidationPlanPersistence)
        configured = _configuration(self._configured)
        owned = _expectations(configured, expectations, work)
        if originals is not None:
            originals = store._raw4(originals)
        else:
            plan.shape._digest(retained_record_digest)
        invocation = _Invocation(self, configured, owned, live_window, check, work)
        invocation.checked()
        if originals is not None:
            invocation.bind(originals)
        plan.evidence.keys._public_binding(configured[3], configured[5], work)
        invocation.checked()
        from catchplate import db
        import psycopg
        from psycopg.rows import dict_row

        _require(configured[2][0] == db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE)
        connection = None
        # One held bound-method identity reaches both store and native proxy.
        current = invocation.checked

        def connect():
            nonlocal connection
            connection = psycopg.connect(configured[0], row_factory=dict_row,
                connect_timeout=configured[1], autocommit=False, options="-c search_path=pg_catalog")
            return connection

        def retain(*, connection, work):
            fixed = dict(expectations=owned, planner_public_key=configured[3],
                live_window=live_window, check=current, connection=connection, work=work)
            if originals is None:
                result = store.read_record(retained_record_digest=retained_record_digest, **fixed)
                invocation.bind(result["originals"])
            else:
                result = store.persist_record(originals=originals, **fixed)
            current()
            return result

        try:
            writer._checked(work, current, connect)
            result = writer._run_on_connection(connection, database_identity=configured[2],
                work=work, operation=retain, arguments={}, expectations={}, check=current)
            current()
            return result
        except BaseException:
            invocation.failed = True
            if connection is not None:
                writer.reader._close_after_failure(connection)
            raise

    def persist(self, *, originals, expectations, live_window, check, work):
        return self._run(originals=originals, retained_record_digest=None, expectations=expectations,
            live_window=live_window, check=check, work=work)

    def read(self, *, retained_record_digest, expectations, live_window, check, work):
        return self._run(originals=None, retained_record_digest=retained_record_digest, expectations=expectations,
            live_window=live_window, check=check, work=work)
