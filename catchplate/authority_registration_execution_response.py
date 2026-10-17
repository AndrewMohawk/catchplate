"""Authenticate one original registration execution grant after transport.

The caller retains independently admitted root/configuration/generation/runtime
scope and the exact original authorization and complete planning exchange.
Socket peer checks and a transport return do not authenticate any grant. This
module repeats genuine original verification, never invokes signing and never
requires a private key or an incoming successful verification carrier.

One supplied cumulative work allowance spans the shared planning admission,
request-purpose verification and actual grant/complete-vector replay. The
mandatory inherited monotonic deadline must be the caller's original bound;
verifier-local clock samples cannot renew it. The original authorization,
planning controls and grant must remain live through the final check.

Only the exact original grant bytes are returned. They are not a reservation,
current-root observation, one-use decision, execution acknowledgement or public
receipt. A later reservation must preserve and independently admit the complete
original grant; this helper performs no socket access, retry or durable write.
"""
from __future__ import annotations

import time

from catchplate import authority_registration_execution_exchange as exchange


authorization, grants, evidence, clock = (
    exchange.authorization, exchange.grants, exchange.evidence, exchange.clock)


class RegistrationExecutionResponseError(ValueError):
    pass


def _verify_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_originals, response_originals,
        before_vector_bytes, authorization_bytes, grant_bytes, authorization_enrollment_bytes,
        grant_enrollment_bytes, current_root_enrollment_bytes, root_public_key,
        deadline_epoch_ns, transport_deadline_ns, work):
    """Return unchanged original bytes only after genuine same-call admission.

    Planning request originals are (control, context, inputs); planning response
    originals are (control, plan envelope, inputs, evaluation context). No caller
    expectation graph, authorization digest, returned scope or replacement work
    allowance can stand in for verification of those actual originals.
    """
    evidence.capture._SharedLedger(work)
    original_grant = grants.authorization._original(grant_bytes,
        grants.MAX_GRANT_BYTES, "returned registration execution grant")
    evidence.plan.contract._integer(transport_deadline_ns, minimum=1)
    inherited = transport_deadline_ns
    # Shared admission owns the remaining originals and all caller graphs
    # before native callbacks. The returned grant is also included in that
    # complete aggregate inventory, even though it is not authenticated yet.
    admitted = exchange._admit_on_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, request_originals=request_originals,
        response_originals=response_originals, before_vector_bytes=before_vector_bytes,
        authorization_bytes=authorization_bytes,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes, root_public_key=root_public_key,
        deadline_epoch_ns=deadline_epoch_ns, work=work, transport_deadline_ns=inherited,
        _returned_grant_bytes=original_grant)
    admitted.live()
    authorized = authorization._verify_on_work(authorization_bytes=admitted.authorization,
        authorization_enrollment_bytes=admitted.authorization_enrollment,
        current_root_enrollment_bytes=admitted.current_enrollment,
        grant_enrollment_bytes=admitted.grant_enrollment, root_public_key=admitted.root,
        configuration_digest=admitted.configuration_digest,
        planner_public_key=admitted.configured.pins[1], evidence_public_key=admitted.configured.pins[4],
        deadline_epoch_ns=admitted.deadline_epoch_ns, work=work,
        transport_deadline_ns=admitted.deadline_ns)
    bound = min(inherited, admitted.deadline_ns, authorized.deadline_ns)
    last_epoch, last_monotonic = authorized.last_epoch_ns, authorized.last_monotonic_ns

    def live():
        nonlocal last_epoch, last_monotonic
        # Both actual verification brackets continue; neither can reset the
        # other's signed expiry, elapsed bound or sticky rollback samples.
        exchange_now = admitted.live()
        now = clock._check_on_work(authorized.window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        evidence.plan.contract._integer(monotonic, minimum=1)
        if (now < exchange_now or now < last_epoch or monotonic < last_monotonic
                or monotonic >= bound or now >= authorized.expires_at_epoch_ns):
            raise RegistrationExecutionResponseError("registration grant response expired or its original clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    verified = grants._verify_on_work(grant_bytes=original_grant,
        grant_enrollment_bytes=admitted.grant_enrollment,
        current_root_enrollment_bytes=admitted.current_enrollment, root_public_key=admitted.root,
        operation=authorization.OPERATION, originals=admitted.originals, expectations=admitted.history,
        planner_public_key=admitted.configured.pins[1], operation_public_key=admitted.configured.pins[4],
        before_vector_bytes=admitted.before, expected_authorization_digest=authorized.authorization_digest,
        now_epoch_ns=live(), work=work)
    evidence.plan._same(verified.replayed.request["requestDigest"], authorized.request_digest,
        work, "received grant original plan differs from the authorized request")
    evidence.plan._same(verified.replayed.request["operationId"], authorized.operation_id,
        work, "received grant original plan differs from the authorized operation")
    issued, expires = verified.payload["issuedAtEpochNs"], verified.payload["expiresAtEpochNs"]
    if (issued < authorized.issued_at_epoch_ns
            or expires > min(authorized.expires_at_epoch_ns, admitted.deadline_epoch_ns)):
        raise RegistrationExecutionResponseError("received grant escapes its original authorization interval")
    # Actual grant verification already checked enrolled maximum age/skew and
    # original-plan interval containment at the earlier sample. A nondecreasing
    # final sample before its unchanged expiry preserves those checks across
    # genuine replay and cryptographic work, without reopening verification.
    if live() >= expires:
        raise RegistrationExecutionResponseError("received grant expired during verification")
    return original_grant
