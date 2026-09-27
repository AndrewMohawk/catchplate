"""Genuine consume issuance followed by one IDs-only protected SQL attempt.

All public inputs are originals and independently held scope. The actual
issuer authenticates/replays once and inserts its resulting custody packet;
only that same call's returned IDs reach the executor. No supplied successful
carrier, sampled-head authority, fresh allowance or automatic retry is accepted.
An observed commit is unsigned local evidence, never token-release authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_oidc_session_activation_delivery_pending_admission as admission
from serverware import authority_successor_execution_owner as owners


evidence, clock, shape = owners.evidence, owners.clock, owners.authorization.shape
OPERATION = admission.OPERATION


class DeliverySqlError(RuntimeError):
    pass


class DeliverySqlOutcomeError(DeliverySqlError):
    """Actual locators and optional same-call guard, never retry permission."""

    def __init__(self, pending_decision_digest, packet_digest, *,
            live_window=None, deadline_ns=None, live=None):
        shape._digest(pending_decision_digest)
        shape._digest(packet_digest)
        super().__init__("consume SQL outcome is not established; original custody locators retained")
        self.pending_decision_digest = pending_decision_digest
        self.packet_digest = packet_digest
        self.live_window = live_window
        self.deadline_ns = deadline_ns
        self.live = live


@dataclass(frozen=True, slots=True)
class _ExecutedSql:
    observation: owners.SuccessorExecutionObservation
    live_window: tuple
    deadline_ns: int
    live: object


def _held_configuration(value):
    if (type(value) is not tuple or len(value) != 8 or type(value[1]) is not int
            or any(type(value[index]) is not str for index in (0, 2, 3, 4, 5, 6, 7))):
        raise DeliverySqlError("consume SQL configuration is not immutable scalars")
    return value


def _marker_matches(original, expected, work):
    if type(original) is not bytes or not 2 <= len(original) <= 4096:
        raise DeliverySqlError("consume SQL marker exceeds its original bound")
    actual = owners.authorization.wire._decode_object(original, work=work,
        maximum_bytes=4096, maximum_nodes=64, maximum_depth=2)
    shape._object(actual, frozenset(owners.markers.FIELDS), "consume SQL commit marker")
    owners.authorization.capability._canonical(original, actual,
        evidence.capture._SharedLedger(work), 4096, 64)
    for name in owners.markers.FIELDS:
        if type(actual[name]) is not type(expected[name]):
            raise DeliverySqlError("consume SQL marker scalar type differs")
        evidence.plan._same(actual[name], expected[name], work,
            "consume SQL marker differs from genuine same-call pending admission")


def _execute_on_configuration(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        receiving_custody, live_window, transport_deadline_ns, work, issuer, executor):
    """Original pending admission/issuance once, then one actual durable attempt."""
    if type(issuer) is not owners.SuccessorExecutionIssuer or type(executor) is not owners.SuccessorExecutionExecutor:
        raise DeliverySqlError("consume SQL requires the actual issuer and executor owners")
    # Hold native configuration scalars without invoking callbacks before the
    # dedicated issuer has captured all mutable original caller graphs.
    issuer_configuration = _held_configuration(issuer._configuration)
    executor_configuration = _held_configuration(executor._configuration)
    issuer_pid, executor_pid, attempt_owner = issuer._pid, executor._pid, executor._attempts
    if (type(issuer_pid) is not int or type(executor_pid) is not int
            or type(attempt_owner) is not owners.attempts.SuccessorExecutionAttempts):
        raise DeliverySqlError("consume SQL process or durable attempt owner differs")
    independent_pending_head = expected_pending_head_digest
    # A distinct original-input issuer entry owns genuine consume replay and
    # pending admission. The generic operation dispatcher is not widened here.
    try:
        issued = owners.SuccessorExecutionIssuer._issue_delivery_on_work(issuer,
            originals=originals, expectations=expectations, before_vector_bytes=before_vector_bytes,
            authorization_bytes=authorization_bytes, grant_bytes=grant_bytes,
            response_originals=response_originals, authorization_enrollment_bytes=authorization_enrollment_bytes,
            grant_enrollment_bytes=grant_enrollment_bytes,
            current_root_enrollment_bytes=current_root_enrollment_bytes, root_public_key=root_public_key,
            planner_public_key=planner_public_key, operation_public_key=operation_public_key,
            configuration_digest=configuration_digest,
            expected_predecessor_sequence=expected_predecessor_sequence,
            expected_predecessor_head_digest=expected_predecessor_head_digest,
            expected_database_id=expected_database_id, expected_generation_digest=expected_generation_digest,
            expected_pending_sequence=expected_pending_sequence,
            expected_pending_head_digest=independent_pending_head, expected_fence=expected_fence,
            receiving_custody=receiving_custody, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work)
    except Exception:
        # No confirmed issuer return means no invented custody locator, even
        # when the database may have accepted publication before a lost reply.
        raise DeliverySqlError("consume SQL issuance outcome is not established") from None
    if type(issued) is not owners._IssuedDelivery or type(issued.observation) is not owners.SuccessorCustodyObservation:
        raise DeliverySqlError("consume SQL issuer returned no actual custody observation")
    observed_issue = issued.observation
    shape._digest(observed_issue.pending_decision_digest)
    shape._digest(observed_issue.packet_digest)
    pending_digest, packet_digest = observed_issue.pending_decision_digest, observed_issue.packet_digest
    guarded = False
    try:
        window = clock._validate(issued.live_window)
        shape._integer(issued.deadline_ns, minimum=1)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(transport_deadline_ns, issued.deadline_ns, window[4])
        shape._object(issued.marker_expectation, frozenset(owners.markers.FIELDS), "consume admitted marker")
        work.prepare_copy(issued.marker_expectation)
        marker = issued.marker_expectation.copy()
        shape._literal(marker["operation"], OPERATION)
        last_epoch, last_monotonic = window[0], window[2]
        callback = evidence.production._callback

        def live():
            nonlocal last_epoch, last_monotonic
            admitted_epoch = issued.live()
            shape._integer(admitted_epoch, minimum=1)
            actual_issuer = callback(work, lambda: owners.SuccessorExecutionIssuer._snapshot_configuration(issuer))
            actual_executor = callback(work, lambda: owners.SuccessorExecutionExecutor._snapshot_configuration(executor))
            if (actual_issuer != issuer_configuration or actual_executor != executor_configuration
                    or issuer._pid != issuer_pid or executor._pid != executor_pid
                    or executor._attempts is not attempt_owner):
                raise DeliverySqlError("consume SQL actual owners changed")
            checked = issued.live()
            shape._integer(checked, minimum=1)
            now = clock._check_on_work(window, work=work)
            monotonic = callback(work, time.monotonic_ns)
            shape._integer(monotonic, minimum=1)
            if (checked < admitted_epoch or now < checked or now < last_epoch
                    or monotonic < last_monotonic or monotonic >= bound):
                raise DeliverySqlError("consume SQL original clocks expired or reversed")
            last_epoch, last_monotonic = now, monotonic
            return now

        live()
        guarded = True
        for index in (6, 7):
            evidence.plan._same(issuer_configuration[index], executor_configuration[index], work,
                "consume SQL owners differ from independent query/catalog pins")
        evidence.plan._same(pending_digest, independent_pending_head, work,
            "consume SQL custody differs from independently admitted current pending scope")
        shape._integer(observed_issue.issued_at_epoch_ns, minimum=1)
        shape._integer(observed_issue.expires_at_epoch_ns, minimum=1)
        if observed_issue.expires_at_epoch_ns <= observed_issue.issued_at_epoch_ns:
            raise DeliverySqlError("consume SQL custody original interval is empty")
        expires = min(window[3], observed_issue.expires_at_epoch_ns)
        window = clock._validate((window[0], window[1], window[2], expires,
            min(window[4], window[1] + expires - window[0]), window[5], window[6]))
        bound = min(bound, window[4])
        live()
        observed = owners.SuccessorExecutionExecutor.execute(executor,
            pending_decision_digest=pending_digest, packet_digest=packet_digest,
            live_window=window, transport_deadline_ns=bound, work=work)
        live()
        if type(observed) is not owners.SuccessorExecutionObservation:
            raise DeliverySqlError("consume SQL executor returned no actual commit observation")
        for actual, expected in ((observed.pending_decision_digest, pending_digest),
                (observed.packet_digest, packet_digest)):
            evidence.plan._same(actual, expected, work,
                "consume SQL observation differs from the same-call issuer identity")
        _marker_matches(observed.marker_bytes, marker, work)
        live()
        result = _ExecutedSql(observed, window, bound, live)
        live()
        return result
    except Exception:
        # Includes errors after a real commit. Never release an attempt, retry
        # SQL, infer absence, issue completion or expose a plaintext token.
        raise DeliverySqlOutcomeError(pending_digest, packet_digest,
            live_window=window if guarded else None,
            deadline_ns=bound if guarded else None,
            live=live if guarded else None) from None
