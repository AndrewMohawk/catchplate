"""Original finalization admission into actual protected SQL owners.

Independent caller admission must establish each owner's database, role, TLS,
query/catalog and storage provenance. Equal query/catalog pins do not prove
database identity, and the distinct issuer/executor role identities are not
equated here. Present caller and finalization-execution permission remain
separate prerequisites; possession of retained originals is not that authority.

Only this invocation's genuine original admission supplies issuer arguments.
Only custody identities returned by the actual issuer reach the actual
executor, whose irreversible durable attempt precedes database execution.
No incoming packet locator, successful proof object, alternate operation,
replacement work/window, automatic retry or completion key is accepted.

The result is the actual unsigned normal-commit observation, not independently
signed completion, latest-state evidence or OIDC session activation. Ordinary
post-issuance failures retain only actual validated custody locators, without
claiming the attempt or commit did not occur. Cancellation propagates.
"""
from __future__ import annotations

import time

from catchplate import authority_registration_finalization_sql_admission as admission
from catchplate import authority_successor_execution_owner as owners


evidence, clock, shape = owners.evidence, owners.clock, owners.authorization.shape
OPERATION = "webauthn.registration.finalize"


class RegistrationFinalizationSqlError(RuntimeError):
    pass


class RegistrationFinalizationSqlOutcomeError(RegistrationFinalizationSqlError):
    """Actual same-call custody locators, never execution or retry authority."""

    def __init__(self, pending_decision_digest, packet_digest):
        shape._digest(pending_decision_digest)
        shape._digest(packet_digest)
        super().__init__("finalization SQL outcome is not established; original custody locators retained")
        self.pending_decision_digest = pending_decision_digest
        self.packet_digest = packet_digest


def _held_configuration(value):
    # No native readiness callback before genuine admission owns the mutable
    # caller graphs. Actual class methods validate these retained scalars next.
    if (type(value) is not tuple or len(value) != 8 or type(value[1]) is not int
            or any(type(value[index]) is not str for index in (0, 2, 3, 4, 5, 6, 7))):
        raise RegistrationFinalizationSqlError("finalization SQL owner configuration is not immutable scalars")
    return value


def _execute_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, reservation_originals,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, live_window, transport_deadline_ns, work, issuer, executor):
    """Compose one actual issuance/execution under independently admitted scope.

    Originals are exact finalization raw10 and reservation raw3. The caller
    supplies one existing live window/work allowance and an inherited deadline,
    plus independently held CURRENT pending pins and actual database owners.
    No serialized admission result or caller-selected custody ID substitutes.
    """
    if type(issuer) is not owners.SuccessorExecutionIssuer or type(executor) is not owners.SuccessorExecutionExecutor:
        raise RegistrationFinalizationSqlError("finalization SQL requires its actual issuer and executor")
    issuer_configuration = _held_configuration(issuer._configuration)
    executor_configuration = _held_configuration(executor._configuration)
    issuer_pid, executor_pid = issuer._pid, executor._pid
    attempt_owner = executor._attempts
    if (type(issuer_pid) is not int or type(executor_pid) is not int
            or type(attempt_owner) is not owners.attempts.SuccessorExecutionAttempts):
        raise RegistrationFinalizationSqlError("finalization SQL process or attempt owner differs")

    admitted = admission._admit_on_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, originals=originals,
        reservation_originals=reservation_originals,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes, root_public_key=root_public_key,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
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
            raise RegistrationFinalizationSqlError("finalization SQL actual owners changed")
        # The executor snapshot locks/checks its actual catalog-bound journal.
        # Readiness is not an independent checkpoint or action-time witness.
        checked = admitted.live()
        now = clock._check_on_work(window, work=work)
        monotonic = callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < checked or now < last_epoch or monotonic < last_monotonic or monotonic >= bound):
            raise RegistrationFinalizationSqlError("finalization SQL original deadline expired or its clocks reversed")
        last_epoch, last_monotonic = now, monotonic

    live()
    for index in (6, 7):
        evidence.plan._same(issuer_configuration[index], executor_configuration[index], work,
            "finalization SQL owners differ from the same independent query or catalog pin")
    live()
    try:
        issued = owners.SuccessorExecutionIssuer.issue(issuer, **admitted.issue_arguments,
            live_window=window, work=work, transport_deadline_ns=bound)
    except Exception:
        # Issuance may already have committed custody. Without an actual
        # successful return there are no validated locators to manufacture.
        raise RegistrationFinalizationSqlError("finalization SQL issuance outcome is not established") from None
    if type(issued) is not owners.SuccessorCustodyObservation:
        raise RegistrationFinalizationSqlError("finalization SQL issuer returned no actual custody observation")
    shape._digest(issued.pending_decision_digest)
    shape._digest(issued.packet_digest)
    pending_digest, packet_digest = issued.pending_decision_digest, issued.packet_digest
    try:
        evidence.plan._same(pending_digest, admitted.issue_arguments["expected_pending_head_digest"], work,
            "finalization SQL custody differs from independently admitted pending scope")
        shape._integer(issued.issued_at_epoch_ns, minimum=1)
        shape._integer(issued.expires_at_epoch_ns, minimum=1)
        if issued.expires_at_epoch_ns <= issued.issued_at_epoch_ns:
            raise RegistrationFinalizationSqlError("finalization SQL custody original interval is empty")
        # Preserve the original opening samples and clip to actual issuance;
        # a reserve/custody interval may be narrower than caller/grant expiry.
        expires = min(window[3], issued.expires_at_epoch_ns)
        window = clock._validate((window[0], window[1], window[2], expires,
            min(window[4], window[1] + expires - window[0]), window[5], window[6]))
        bound = min(bound, window[4])
        live()
        result = owners.SuccessorExecutionExecutor.execute(executor,
            pending_decision_digest=pending_digest, packet_digest=packet_digest,
            live_window=window, work=work, transport_deadline_ns=bound)
        live()
        if type(result) is not owners.SuccessorExecutionObservation:
            raise RegistrationFinalizationSqlError("finalization SQL executor returned no actual commit observation")
        for actual, expected in ((result.pending_decision_digest, pending_digest),
                (result.packet_digest, packet_digest)):
            evidence.plan._same(actual, expected, work,
                "finalization SQL observation differs from the same-call custody identity")
        live()
        return result
    except Exception:
        # A durable attempt or commit is never cleared on failure. Genuine
        # reconciliation is separate; this method does not issue or execute twice.
        raise RegistrationFinalizationSqlOutcomeError(pending_digest, packet_digest) from None
