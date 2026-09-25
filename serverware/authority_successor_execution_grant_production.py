"""Produce one dedicated execution grant from genuine original plan replay.

Independent caller authorization, historical expectations and key/root
provenance are prerequisites, not claims inferred from a plan or its result.
The purpose-enrolled authorizer signs only this invocation's actual replayed
claims. No successful replay carrier or caller-selected signing payload is
accepted. This does not provide a cold owner, user authorization, reservation,
SQL permission, one-use custody, transport or a replacement work allowance.

The original plan issue instant is never changed. One actual dual-clock window
is opened under the enrolled policy and only shortened after genuine replay;
old expired originals cannot acquire a fresh execution interval.
"""
from __future__ import annotations

import time

from serverware import authority_successor_execution_grant as grants
from serverware import authority_successor_execution_grant_signing as signing
from serverware import authority_webauthn_evidence_plan_clock as clock


authorization, replay, evidence = grants.authorization, grants.replay, grants.evidence
shape, capture, plan, keys = grants.shape, grants.capture, grants.plan, grants.keys


class SuccessorExecutionGrantProductionError(ValueError):
    pass


def _produce_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, before_vector_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, authorizer_private_key,
        expected_authorization_digest, deadline_epoch_ns, work, transport_deadline_ns=None):
    """Sign original-plan-derived claims once on the supplied cumulative work.

    ``expected_authorization_digest`` must come from independently admitted
    request authorization. It is mandatory even when a retained plan already
    carries an authorization commitment. Neither that plan nor this producer
    establishes the independent caller-authorization or current-root owner.
    """
    capture._SharedLedger(work)
    held_operation = operation
    held_originals, held_before = replay._originals(held_operation, originals, before_vector_bytes)
    held_grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "successor grant enrollment")
    held_current_enrollment = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    if sum(len(raw) for raw in (*held_originals, held_before,
            held_grant_enrollment, held_current_enrollment)) > replay.MAX_ORIGINAL_BYTES:
        raise SuccessorExecutionGrantProductionError("grant production originals exceed the source aggregate")
    held_root, held_signer = root_public_key, authorizer_private_key
    held_planner, held_operation_key = planner_public_key, operation_public_key
    authorization._public(held_root)
    authorization._private(held_signer)
    authorization._public(held_planner)
    authorization._public(held_operation_key)
    shape._digest(expected_authorization_digest)
    shape._integer(deadline_epoch_ns, minimum=1)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    held_authorization = expected_authorization_digest
    held_deadline, inherited = deadline_epoch_ns, transport_deadline_ns
    # The actual family capture owns all caller graphs (and preserves the
    # exact revocation UTC instant) before any enrollment/key/clock callback.
    owned_expectations = replay._expectations(held_operation, expectations,
        held_planner, held_operation_key, work)

    material = grants._admit_enrollment_on_work(grant_enrollment_bytes=held_grant_enrollment,
        current_root_enrollment_bytes=held_current_enrollment, root_public_key=held_root, work=work)
    policy = material.payload
    policy_pins = (material.enrollment_digest, policy["currentRootEnrollmentDigest"],
        policy["databaseId"], policy["generationDigest"], policy["authorizer"]["measurementDigest"],
        policy["maximumGrantAgeNs"], policy["maximumClockSkewNs"])
    authorizer_key = material.authorizer_public_key
    maximum_age, skew = policy_pins[5:]
    window = clock._open_on_work(deadline_epoch_ns=held_deadline,
        maximum_lifetime_ns=maximum_age, maximum_clock_skew_ns=skew, work=work)
    bound = window[4] if inherited is None else min(window[4], inherited)
    last_epoch, last_monotonic = window[0], window[2]
    original_interval = None

    def live():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise SuccessorExecutionGrantProductionError("grant production original clock window expired or reversed")
        if original_interval is not None:
            evidence._fresh(original_interval, now, maximum_age, skew)
        last_epoch, last_monotonic = now, monotonic
        return now

    live()
    keys._pair_on_work(held_signer, authorizer_key, work)
    authorizer_spki = keys._spki_on_work(authorizer_key, work)
    for other in (held_planner, held_operation_key):
        actual = keys._spki_on_work(other, work)
        work.prepare_comparison(authorizer_spki, actual)
        if authorizer_spki == actual:
            raise SuccessorExecutionGrantProductionError("planner or operation key cannot issue execution grants")
    live()
    replayed = replay._replay_on_work(operation=held_operation, originals=held_originals,
        expectations=owned_expectations, planner_public_key=held_planner,
        operation_public_key=held_operation_key, before_vector_bytes=held_before, work=work)
    issued, original_expires = replayed.original_interval
    expires = min(window[3], original_expires, issued + maximum_age, held_deadline)
    # Shortening retains the ORIGINAL actual clock bracket. Do not reopen a
    # window after expensive replay or replace the signed plan's issue instant.
    window = clock._validate((window[0], window[1], window[2], expires,
        window[1] + expires - window[0], maximum_age, skew))
    bound = min(bound, window[4])
    original_interval = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    live()

    request_digest = authorization.commitment._typed_request_digest(replayed.request, work=work)
    plan._same(request_digest, replayed.request["requestDigest"], work,
        "grant request differs from its genuine typed commitment")
    plan._same(replayed.request["operation"], held_operation, work,
        "grant request differs from the fixed original plan operation")
    operation_size = work.prepare_utf8(held_operation)
    request_size = work.prepare_utf8(request_digest)
    work.charge(hashes=1, input_bytes=len("serverware.policyAuthorityOperation/v2") + 17
        + operation_size + request_size)
    operation_id = authorization.production._callback(work,
        lambda: authorization.commitment.operation_id(held_operation, request_digest))
    plan._same(operation_id, replayed.request["operationId"], work,
        "grant operation identity differs from the actual typed request")
    claims = grants._replay_claims(replayed, work)
    payload = {"schema": grants.GRANT_PAYLOAD_SCHEMA,
        "sourceRevision": grants.authority.SOURCE_REVISION,
        "grantEnrollmentDigest": policy_pins[0], "currentRootEnrollmentDigest": policy_pins[1],
        "databaseId": policy_pins[2], "generationDigest": policy_pins[3],
        "authorizerMeasurementDigest": policy_pins[4],
        "requestAuthorizationDigest": held_authorization, **claims, **original_interval}
    grants._grant_shape(payload)
    # Preserve exact same-call claims independently of native signing and
    # verification callbacks; this is not an accepted successful-proof DTO.
    expected_payload_bytes = authorization.capability._wire(payload,
        capture._SharedLedger(work), grants.MAX_GRANT_BYTES, grants.MAX_NODES)
    live()
    original_grant = signing._sign_grant_on_work(payload=payload,
        private_key=held_signer, public_key=authorizer_key, work=work)
    verified_payload, _digest = grants._verify_control_on_work(grant_bytes=original_grant,
        grant_enrollment_bytes=held_grant_enrollment,
        current_root_enrollment_bytes=held_current_enrollment, root_public_key=held_root,
        planner_public_key=held_planner, operation_public_key=held_operation_key,
        expected_authorization_digest=held_authorization, now_epoch_ns=live(), work=work)
    verified_payload_bytes = authorization.capability._wire(verified_payload,
        capture._SharedLedger(work), grants.MAX_GRANT_BYTES, grants.MAX_NODES)
    work.charge(input_bytes=len(expected_payload_bytes) + len(verified_payload_bytes))
    if expected_payload_bytes != verified_payload_bytes:
        raise SuccessorExecutionGrantProductionError("signed execution grant changed the genuine same-call claims")
    live()
    return original_grant
