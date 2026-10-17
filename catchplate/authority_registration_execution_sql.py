"""Original registration admission into actual protected SQL issuance/execution.

The cold caller independently admits both database owners and their endpoint,
database, role/TLS and catalog provenance. This composition preserves distinct
issuer/executor identities; equal query/catalog pins alone do not establish
database identity. No DSN is inferred from a response or parsed as new authority.
Present-caller and execution-purpose admission remain the future caller's gates;
retained originals alone do not supply that fresh request authority.

Only this invocation's genuine admission supplies issuer inputs. Only custody
locators returned by that actual issuer reach the actual executor, whose own
durable attempt claim precedes SQL. A post-issuance error preserves those two
locators, never a retry permission or a claim that execution did not commit.
Uncertain issuance supplies no invented locator. Cancellation propagates.

Returned execution observations are unsigned normal-commit observations, not
signed completion, credential finalization or session activation. No completion
key, cold service, public route, database opener or automatic retry is supplied.
Original deadlines do not constitute a hard watchdog for locks, disk or SQL.
"""
from __future__ import annotations

import time

from catchplate import authority_registration_execution_sql_admission as admission
from catchplate import authority_successor_execution_owner as owners


evidence, clock, shape = owners.evidence, owners.clock, owners.authorization.shape


class RegistrationExecutionSqlError(RuntimeError):
    pass


class RegistrationExecutionSqlOutcomeError(RegistrationExecutionSqlError):
    """Actual custody locators only; subsequent SQL outcome remains uncertain."""

    def __init__(self, pending_decision_digest, packet_digest):
        shape._digest(pending_decision_digest)
        shape._digest(packet_digest)
        super().__init__("registration SQL outcome is not established; original custody locators retained")
        self.pending_decision_digest = pending_decision_digest
        self.packet_digest = packet_digest


def _held_configuration(value):
    # Capture immutable scalar owners without calling native journal readiness
    # before admission has detached every mutable caller graph. Actual owner
    # methods perform full role/configuration/PID checks afterward.
    if (type(value) is not tuple or len(value) != 8 or type(value[1]) is not int
            or any(type(value[index]) is not str for index in (0, 2, 3, 4, 5, 6, 7))):
        raise RegistrationExecutionSqlError("registration SQL owner configuration is not immutable scalars")
    return value


def _execute_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, reservation_originals,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, deadline_epoch_ns, transport_deadline_ns, work, issuer, executor):
    """Issue and attempt execution once using actual independently admitted owners.

    No incoming admitted-input object, custody observation or packet locator is
    accepted. Original raw10/raw3 and independent pending scope reach the genuine
    admission helper; execution receives only this call's actual issuer result.
    """
    if type(issuer) is not owners.SuccessorExecutionIssuer or type(executor) is not owners.SuccessorExecutionExecutor:
        raise RegistrationExecutionSqlError("registration SQL requires its actual issuer and executor")
    issuer_configuration = _held_configuration(issuer._configuration)
    executor_configuration = _held_configuration(executor._configuration)
    issuer_pid, executor_pid = issuer._pid, executor._pid
    attempt_owner = executor._attempts
    if (type(issuer_pid) is not int or type(executor_pid) is not int
            or type(attempt_owner) is not owners.attempts.SuccessorExecutionAttempts):
        raise RegistrationExecutionSqlError("registration SQL process or attempt owner differs")

    admitted = admission._admit_on_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, originals=originals,
        reservation_originals=reservation_originals,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes, root_public_key=root_public_key,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        deadline_epoch_ns=deadline_epoch_ns, transport_deadline_ns=transport_deadline_ns, work=work)
    window = admitted.live_window
    bound = admitted.deadline_ns
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
            raise RegistrationExecutionSqlError("registration SQL actual owners changed")
        # The executor snapshot checks its actual catalog-bound attempt owner
        # under that owner's lock. This observes readiness, not a fresh or
        # independently current checkpoint; the admitted constructor owns that.
        checked = admitted.live()
        now = clock._check_on_work(window, work=work)
        monotonic = callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < checked or now < last_epoch or monotonic < last_monotonic or monotonic >= bound):
            raise RegistrationExecutionSqlError("registration SQL original deadline expired or its clocks reversed")
        last_epoch, last_monotonic = now, monotonic

    live()
    for index in (6, 7):
        evidence.plan._same(issuer_configuration[index], executor_configuration[index], work,
            "registration SQL owners differ from the same independent query or catalog pin")
    live()
    try:
        issued = owners.SuccessorExecutionIssuer.issue(issuer, **admitted.issue_arguments,
            live_window=window, work=work, transport_deadline_ns=bound)
    except Exception:
        # A late issuance error may follow durable SQL custody. No successful
        # same-call result means there are no validated locators to publish.
        raise RegistrationExecutionSqlError("registration SQL issuance outcome is not established") from None
    if type(issued) is not owners.SuccessorCustodyObservation:
        raise RegistrationExecutionSqlError("registration SQL issuer returned no actual custody observation")
    shape._digest(issued.pending_decision_digest)
    shape._digest(issued.packet_digest)
    pending_digest, packet_digest = issued.pending_decision_digest, issued.packet_digest
    try:
        evidence.plan._same(pending_digest, admitted.issue_arguments["expected_pending_head_digest"], work,
            "registration SQL custody differs from independently admitted pending scope")
        shape._integer(issued.issued_at_epoch_ns, minimum=1)
        shape._integer(issued.expires_at_epoch_ns, minimum=1)
        if issued.expires_at_epoch_ns <= issued.issued_at_epoch_ns:
            raise RegistrationExecutionSqlError("registration SQL custody original interval is empty")
        # Actual reserve/custody expiry can be narrower than the caller/grant
        # bound. Preserve every original opening scalar, never reopen a window.
        expires = min(window[3], issued.expires_at_epoch_ns)
        window = clock._validate((window[0], window[1], window[2], expires,
            window[1] + expires - window[0], window[5], window[6]))
        bound = min(bound, window[4])
        live()
        result = owners.SuccessorExecutionExecutor.execute(executor,
            pending_decision_digest=pending_digest, packet_digest=packet_digest,
            live_window=window, work=work, transport_deadline_ns=bound)
        live()
        if type(result) is not owners.SuccessorExecutionObservation:
            raise RegistrationExecutionSqlError("registration SQL executor returned no actual commit observation")
        for actual, expected in ((result.pending_decision_digest, pending_digest),
                (result.packet_digest, packet_digest)):
            evidence.plan._same(actual, expected, work,
                "registration SQL observation differs from the same-call custody identity")
        live()
        return result
    except Exception:
        # Claims and commits remain durable on late failure. No failure path
        # clears an attempt, issues another packet or retries any SQL operation.
        raise RegistrationExecutionSqlOutcomeError(pending_digest, packet_digest) from None
