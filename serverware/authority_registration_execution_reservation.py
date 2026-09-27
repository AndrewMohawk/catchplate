"""Original registration authorization and grant into a reserve computation.

The caller supplies independently admitted cold configuration, root/enrollment
originals, computation key and predecessor/fence scope. None is inferred from
a received grant or a successful verification carrier. The live signed
planning exchange supplies the historical replay inputs; the separately
authenticated caller authorization fixes the request and operation identity.

Grant control signatures precede the dedicated request/interval joins. Only
then does the existing generic reserve producer perform its genuine full
grant/plan/vector replay and sign the computation. All phases share the same
supplied work and inherited deadline, and the original planning/authorization
windows remain guarded through return. No key, clock or work fallback exists.

The result contains only actual reserve-request and snapshot original bytes.
It is not a durable reservation, latest-root admission, one-use marker, SQL
execution, commit or completion. This module opens no transport or storage and
does not implement a cold owner, public route, retry or deployment admission.
"""
from __future__ import annotations

import time

from serverware import authority_registration_execution_exchange as exchange
from serverware import authority_successor_execution_preparation as preparation


authorization, grants, evidence, clock = (
    exchange.authorization, exchange.grants, exchange.evidence, exchange.clock)


class RegistrationExecutionReservationError(ValueError):
    pass


def _produce_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_originals, response_originals,
        before_vector_bytes, authorization_bytes, grant_bytes, authorization_enrollment_bytes,
        grant_enrollment_bytes, current_root_enrollment_bytes, root_public_key,
        computation_private_key, predecessor_sequence, predecessor_head_digest, fence,
        deadline_epoch_ns, transport_deadline_ns, work):
    """Return the genuine CurrentRootComputation, not an accepted result token.

    Request originals are (control, context, inputs); response originals are
    (control, plan envelope, inputs, evaluation context). The predecessor and
    fence are independent caller-owned scope, never claims copied from the
    planning response, grant or locally retained record metadata.
    """
    evidence.capture._SharedLedger(work)
    original_grant = grants.authorization._original(grant_bytes,
        grants.MAX_GRANT_BYTES, "registration reservation execution grant")
    signer = computation_private_key
    grants.authorization._private(signer)
    shape = grants.authorization.shape
    shape._integer(predecessor_sequence, grants.authorization.MAX_RECORDS)
    shape._digest(predecessor_head_digest)
    shape._integer(fence, minimum=1)
    shape._integer(deadline_epoch_ns, minimum=1)
    shape._integer(transport_deadline_ns, minimum=1)
    sequence, predecessor, held_fence = predecessor_sequence, predecessor_head_digest, fence
    inherited = transport_deadline_ns
    # The shared gate captures all graphs and immutable originals before
    # native callbacks. Its complete aggregate includes this original grant.
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
    authorization_expiry = min(admitted.deadline_epoch_ns, authorized.expires_at_epoch_ns)
    deadline = min(authorization_expiry, authorized.window[3])
    last_epoch, last_monotonic = authorized.last_epoch_ns, authorized.last_monotonic_ns
    grant_expiry = None

    def live():
        nonlocal last_epoch, last_monotonic
        # Continue both genuine original brackets, including their rollback
        # observations. The generic producer's local bracket cannot renew them.
        exchange_now = admitted.live()
        now = clock._check_on_work(authorized.window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < exchange_now or now < last_epoch or monotonic < last_monotonic
                or monotonic >= bound or now >= deadline
                or grant_expiry is not None and now >= grant_expiry):
            raise RegistrationExecutionReservationError(
                "registration reservation expired or its original clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    # This is actual grant signature/enrollment/scope/freshness admission,
    # never parsing an unverified payload and treating its digest as authority.
    control, _grant_digest = grants._verify_control_on_work(grant_bytes=original_grant,
        grant_enrollment_bytes=admitted.grant_enrollment,
        current_root_enrollment_bytes=admitted.current_enrollment, root_public_key=admitted.root,
        planner_public_key=admitted.configured.pins[1], operation_public_key=admitted.configured.pins[4],
        expected_authorization_digest=authorized.authorization_digest,
        now_epoch_ns=live(), work=work)
    operation, request_digest, operation_id, issued, expires = (
        control["operation"], control["requestDigest"], control["operationId"],
        control["issuedAtEpochNs"], control["expiresAtEpochNs"])
    evidence.plan._same(operation, authorization.OPERATION, work,
        "registration reserve grant differs from the fixed operation")
    evidence.plan._same(request_digest, authorized.request_digest, work,
        "registration reserve grant differs from the authorized request")
    evidence.plan._same(operation_id, authorized.operation_id, work,
        "registration reserve grant differs from the authorized operation identity")
    if issued < authorized.issued_at_epoch_ns or expires > authorization_expiry:
        raise RegistrationExecutionReservationError(
            "registration reserve grant escapes its original authorization interval")
    # Grant shape already requires issued == original plan issue and expiry
    # within the original plan. Preserve those exact instants, never restamp.
    grant_expiry = expires
    deadline = min(deadline, expires)
    bound = min(bound, authorized.window[1] + deadline - authorized.window[0])
    live()
    produced = preparation._produce_reserve_on_work(operation=authorization.OPERATION,
        originals=admitted.originals, expectations=admitted.history,
        planner_public_key=admitted.configured.pins[1], operation_public_key=admitted.configured.pins[4],
        before_vector_bytes=admitted.before, enrollment_bytes=admitted.current_enrollment,
        root_public_key=admitted.root, computation_private_key=signer,
        grant_bytes=original_grant, grant_enrollment_bytes=admitted.grant_enrollment,
        expected_authorization_digest=authorized.authorization_digest,
        predecessor_sequence=sequence, predecessor_head_digest=predecessor, fence=held_fence,
        deadline_epoch_ns=deadline, transport_deadline_ns=bound, work=work)
    # The genuine generic replay joins every authenticated grant plan claim,
    # including the request/operation checked above, before computation signing.
    live()
    return produced
