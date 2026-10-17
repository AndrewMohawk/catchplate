"""Genuine activation pending admission into protected issuer/executor owners.

The caller independently admits database/role/TLS/catalog provenance, current
pending and predecessor pins, and actual sql-issuer private receiving custody.
Neither a signed launch snapshot nor a reservation ACK establishes action-time
off-host currentness. Actual protected SQL still checks roots, rows and one use.

Only this call's original admission supplies issuer arguments. Only actual
issuer-returned custody IDs reach the executor; its durable attempt is never
cleared after uncertainty. The packet retains the encrypted plan-originals
bundle, not plaintext tokens or AES keys. Other packet controls/effects are not
claimed to be ciphertext. No incoming successful DTO, replacement work/window,
automatic reissue/retry, completion signature or token-release path exists.

A normal return is an unsigned commit observation with the original live guard
for the fixed service's response. It is not signed completion, browser token
delivery, a public session-activation result or independent currentness proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from catchplate import authority_oidc_session_activation_pending_admission as admission
from catchplate import authority_successor_execution_owner as owners


evidence, clock, shape = owners.evidence, owners.clock, owners.authorization.shape
OPERATION = admission.OPERATION


class OidcSessionActivationSqlError(RuntimeError):
    pass


class OidcSessionActivationSqlOutcomeError(OidcSessionActivationSqlError):
    """Actual issuer locators only; never proof of absence or retry authority."""

    def __init__(self, pending_decision_digest, packet_digest):
        shape._digest(pending_decision_digest)
        shape._digest(packet_digest)
        super().__init__("activation SQL outcome is not established; original custody locators retained")
        self.pending_decision_digest = pending_decision_digest
        self.packet_digest = packet_digest


@dataclass(frozen=True, slots=True)
class _ExecutedSql:
    observation: owners.SuccessorExecutionObservation
    live_window: tuple
    deadline_ns: int
    live: object


def _held_configuration(value):
    # Retain immutable owner fields before native readiness callbacks; original
    # admission below first owns all mutable caller graphs and private scope.
    if (type(value) is not tuple or len(value) != 8 or type(value[1]) is not int
            or any(type(value[index]) is not str for index in (0, 2, 3, 4, 5, 6, 7))):
        raise OidcSessionActivationSqlError("activation SQL configuration is not immutable scalars")
    return value


def _marker_matches(original, expected, work):
    if type(original) is not bytes or not 2 <= len(original) <= 4096:
        raise OidcSessionActivationSqlError("activation SQL marker exceeds its original bound")
    actual = owners.authorization.wire._decode_object(original, work=work,
        maximum_bytes=4096, maximum_nodes=64, maximum_depth=2)
    shape._object(actual, frozenset(owners.markers.FIELDS), "activation SQL commit marker")
    owners.authorization.capability._canonical(original, actual,
        evidence.capture._SharedLedger(work), 4096, 64)
    for name in owners.markers.FIELDS:
        if type(actual[name]) is not type(expected[name]):
            raise OidcSessionActivationSqlError("activation SQL marker scalar type differs")
        evidence.plan._same(actual[name], expected[name], work,
            "activation SQL marker differs from genuine original pending admission")


def _execute_on_configuration(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        activation_custody, live_window, transport_deadline_ns, work, issuer, executor):
    """One original pending → issue → IDs-only execute; no successful input carrier."""
    if type(issuer) is not owners.SuccessorExecutionIssuer or type(executor) is not owners.SuccessorExecutionExecutor:
        raise OidcSessionActivationSqlError("activation SQL requires actual issuer and executor owners")
    issuer_configuration = _held_configuration(issuer._configuration)
    executor_configuration = _held_configuration(executor._configuration)
    issuer_pid, executor_pid, attempt_owner = issuer._pid, executor._pid, executor._attempts
    if (type(issuer_pid) is not int or type(executor_pid) is not int
            or type(attempt_owner) is not owners.attempts.SuccessorExecutionAttempts):
        raise OidcSessionActivationSqlError("activation SQL process or durable attempt owner differs")
    admitted = admission._admit_for_sql_on_work(originals=originals, expectations=expectations,
        before_vector_bytes=before_vector_bytes, authorization_bytes=authorization_bytes,
        grant_bytes=grant_bytes, response_originals=response_originals,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes, root_public_key=root_public_key,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        configuration_digest=configuration_digest, expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest,
        expected_database_id=expected_database_id, expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence, expected_pending_head_digest=expected_pending_head_digest,
        expected_fence=expected_fence, activation_custody=activation_custody,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    window, bound = admitted.live_window, admitted.deadline_ns
    shape._literal(admitted.issue_arguments["operation"], OPERATION)
    last_epoch, last_monotonic = window[0], window[2]
    callback = evidence.production._callback

    def live():
        nonlocal last_epoch, last_monotonic
        admitted.live()
        actual_issuer = callback(work, lambda: owners.SuccessorExecutionIssuer._snapshot_configuration(issuer))
        actual_executor = callback(work, lambda: owners.SuccessorExecutionExecutor._snapshot_configuration(executor))
        if (actual_issuer != issuer_configuration or actual_executor != executor_configuration
                or issuer._pid != issuer_pid or executor._pid != executor_pid
                or executor._attempts is not attempt_owner):
            raise OidcSessionActivationSqlError("activation SQL actual owners changed")
        checked = admitted.live()
        now = clock._check_on_work(window, work=work)
        monotonic = callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < checked or now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise OidcSessionActivationSqlError("activation SQL original deadline expired or clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    live()
    # Equal query/catalog pins do not equate the independently admitted DB/TLS
    # identities or substitute for the actual role checks inside either owner.
    for index in (6, 7):
        evidence.plan._same(issuer_configuration[index], executor_configuration[index], work,
            "activation SQL owners differ from the same independent query/catalog pins")
    live()
    try:
        issued = owners.SuccessorExecutionIssuer.issue(issuer, **admitted.issue_arguments,
            live_window=window, work=work, transport_deadline_ns=bound)
    except Exception:
        raise OidcSessionActivationSqlError("activation SQL issuance outcome is not established") from None
    if type(issued) is not owners.SuccessorCustodyObservation:
        raise OidcSessionActivationSqlError("activation SQL issuer returned no actual custody observation")
    shape._digest(issued.pending_decision_digest)
    shape._digest(issued.packet_digest)
    pending_digest, packet_digest = issued.pending_decision_digest, issued.packet_digest
    try:
        evidence.plan._same(pending_digest, admitted.issue_arguments["expected_pending_head_digest"], work,
            "activation SQL custody differs from independently admitted current pending scope")
        shape._integer(issued.issued_at_epoch_ns, minimum=1)
        shape._integer(issued.expires_at_epoch_ns, minimum=1)
        if issued.expires_at_epoch_ns <= issued.issued_at_epoch_ns:
            raise OidcSessionActivationSqlError("activation SQL custody original interval is empty")
        expires = min(window[3], issued.expires_at_epoch_ns)
        window = clock._validate((window[0], window[1], window[2], expires,
            min(window[4], window[1] + expires - window[0]), window[5], window[6]))
        bound = min(bound, window[4])
        live()
        observed = owners.SuccessorExecutionExecutor.execute(executor,
            pending_decision_digest=pending_digest, packet_digest=packet_digest,
            live_window=window, work=work, transport_deadline_ns=bound)
        live()
        if type(observed) is not owners.SuccessorExecutionObservation:
            raise OidcSessionActivationSqlError("activation SQL executor returned no actual commit observation")
        for actual, expected in ((observed.pending_decision_digest, pending_digest),
                (observed.packet_digest, packet_digest)):
            evidence.plan._same(actual, expected, work,
                "activation SQL observation differs from the same-call issuer identity")
        _marker_matches(observed.marker_bytes, admitted.marker_expectation, work)
        live()
        result = _ExecutedSql(observed, window, bound, live)
        live()
        return result
    except Exception:
        # The executor's irreversible attempt is never cleared on failure,
        # including errors after an actual commit. BaseException propagates.
        raise OidcSessionActivationSqlOutcomeError(pending_digest, packet_digest) from None
