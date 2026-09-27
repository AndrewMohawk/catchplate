"""Produce one dedicated execution grant from genuine original plan replay.

Independent caller authorization, historical expectations and key/root
provenance are prerequisites, not claims inferred from a plan or its result.
The purpose-enrolled authorizer signs only this invocation's actual replayed
claims. No successful replay carrier or caller-selected signing payload is
accepted. This does not provide a cold owner, user authorization, reservation,
SQL permission, one-use custody, transport or a replacement work allowance.

The original plan issue instant is never changed. Existing families open one
actual dual-clock window under the enrolled policy; activation must instead
retain its supplied original opening. Windows only narrow after genuine replay;
old expired originals cannot acquire a fresh execution interval.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from serverware import authority_successor_execution_grant as grants
from serverware import authority_successor_execution_grant_signing as signing
from serverware import authority_webauthn_evidence_plan_clock as clock


authorization, replay, evidence = grants.authorization, grants.replay, grants.evidence
shape, capture, plan, keys = grants.shape, grants.capture, grants.plan, grants.keys


class SuccessorExecutionGrantProductionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HeldInputs:
    """Private captured inputs, not a successful replay or authorization token."""

    operation: str
    originals: tuple
    before: bytes
    grant_enrollment: bytes
    current_enrollment: bytes
    root: object
    signer: object
    planner: object
    operation_key: object
    expectations: dict
    deadline: int
    inherited: int | None
    original_bytes: int
    activation_custody: object | None
    live_window: tuple | None


def _produce_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, before_vector_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, authorizer_private_key,
        expected_authorization_digest, deadline_epoch_ns, work, transport_deadline_ns=None,
        activation_custody=None, live_window=None):
    """Sign original-plan-derived claims once on the supplied cumulative work.

    ``expected_authorization_digest`` must come from independently admitted
    request authorization. It is mandatory even when a retained plan already
    carries an authorization commitment. Neither that plan nor this producer
    establishes the independent caller-authorization or current-root owner.
    """
    shape._digest(expected_authorization_digest)
    held = _hold_on_work(operation=operation, originals=originals,
        expectations=expectations, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, before_vector_bytes=before_vector_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, authorizer_private_key=authorizer_private_key,
        deadline_epoch_ns=deadline_epoch_ns, work=work,
        transport_deadline_ns=transport_deadline_ns, activation_custody=activation_custody,
        live_window=live_window)
    return _produce_held_on_work(held, expected_authorization_digest, work=work)


def _hold_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, before_vector_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, authorizer_private_key,
        deadline_epoch_ns, work, transport_deadline_ns=None, activation_custody=None, live_window=None):
    """Capture the caller graph before the dedicated authorization callback."""
    capture._SharedLedger(work)
    held_operation = operation
    held_originals, held_before = replay._originals(held_operation, originals, before_vector_bytes)
    held_grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "successor grant enrollment")
    held_current_enrollment = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    original_bytes = sum(len(raw) for raw in (*held_originals, held_before,
        held_grant_enrollment, held_current_enrollment))
    if original_bytes > replay.MAX_ORIGINAL_BYTES:
        raise SuccessorExecutionGrantProductionError("grant production originals exceed the source aggregate")
    held_root, held_signer = root_public_key, authorizer_private_key
    held_planner, held_operation_key = planner_public_key, operation_public_key
    authorization._public(held_root)
    authorization._private(held_signer)
    authorization._public(held_planner)
    authorization._public(held_operation_key)
    shape._integer(deadline_epoch_ns, minimum=1)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    held_deadline, inherited = deadline_epoch_ns, transport_deadline_ns
    held_custody, held_window = activation_custody, None
    if held_operation == replay.ACTIVATION_OPERATION:
        from serverware import authority_oidc_session_activation_execution_custody as activation_owner

        if type(held_custody) is not activation_owner.OidcSessionActivationExecutionCustody:
            raise SuccessorExecutionGrantProductionError("activation grant production requires actual private custody")
        held_window = clock._validate(live_window)
        shape._integer(inherited, minimum=1)
    elif held_custody is not None:
        raise SuccessorExecutionGrantProductionError("activation custody cannot authorize another grant family")
    # The actual family capture owns all caller graphs (and preserves the
    # exact revocation UTC instant) before any enrollment/key/clock callback.
    owned_expectations = replay._expectations(held_operation, expectations,
        held_planner, held_operation_key, work)
    replay._activation_context_on_work(held_operation, held_custody,
        root_public_key=held_root, current_root_enrollment_bytes=held_current_enrollment, work=work)
    return _HeldInputs(held_operation, held_originals, held_before,
        held_grant_enrollment, held_current_enrollment, held_root, held_signer,
        held_planner, held_operation_key, owned_expectations, held_deadline,
        inherited, original_bytes, held_custody, held_window)


def _produce_held_on_work(held, held_authorization, *, work, request_binding=None):
    """Shared private suffix; a binding is only from the raw-auth composition.

    No externally exposed producer accepts a successful authorization carrier.
    The registration wrapper itself verifies original authorization bytes and
    supplies its same-call observations here on the unchanged work allowance.
    """
    capture._SharedLedger(work)
    if type(held) is not _HeldInputs:
        raise SuccessorExecutionGrantProductionError("grant inputs were not captured by the source producer")
    shape._digest(held_authorization)
    held_operation, held_originals, held_before = held.operation, held.originals, held.before
    held_grant_enrollment, held_current_enrollment = held.grant_enrollment, held.current_enrollment
    held_root, held_signer = held.root, held.signer
    held_planner, held_operation_key = held.planner, held.operation_key
    held_deadline, inherited = held.deadline, held.inherited
    owned_expectations = held.expectations
    activation = held_operation == replay.ACTIVATION_OPERATION
    original_current = None
    if activation:
        from serverware import authority_successor_execution_window as execution_window
        from serverware import oidc_session_activation_delivery as activation_delivery

        original_window = clock._validate(held.live_window)
        shape._integer(inherited, minimum=1)
        _window, original_current = activation_delivery._window(original_window, inherited, work)
        original_current()

    material = grants._admit_enrollment_on_work(grant_enrollment_bytes=held_grant_enrollment,
        current_root_enrollment_bytes=held_current_enrollment, root_public_key=held_root, work=work)
    if original_current is not None:
        original_current()
    policy = material.payload
    policy_pins = (material.enrollment_digest, policy["currentRootEnrollmentDigest"],
        policy["databaseId"], policy["generationDigest"], policy["authorizer"]["measurementDigest"],
        policy["maximumGrantAgeNs"], policy["maximumClockSkewNs"])
    authorizer_key = material.authorizer_public_key
    maximum_age, skew = policy_pins[5:]
    if activation:
        window = execution_window._narrow(original_window, deadline_epoch_ns=held_deadline,
            maximum_lifetime_ns=maximum_age, maximum_clock_skew_ns=skew)
        bound = min(window[4], inherited)
        last_epoch, last_monotonic = window[0], window[2]
        if request_binding is not None:
            binding_window = clock._validate(request_binding.window)
            plan._same(binding_window[:3], original_window[:3], work,
                "activation grant authorization replaced the original clock bracket")
            shape._integer(request_binding.deadline_ns, minimum=1)
            window = execution_window._narrow(window,
                deadline_epoch_ns=min(binding_window[3], request_binding.expires_at_epoch_ns, held_deadline),
                maximum_lifetime_ns=min(window[5], binding_window[5]),
                maximum_clock_skew_ns=min(window[6], binding_window[6]))
            bound = min(bound, window[4], binding_window[4], request_binding.deadline_ns)
            last_epoch = max(last_epoch, request_binding.last_epoch_ns)
            last_monotonic = max(last_monotonic, request_binding.last_monotonic_ns)
            plan._same(held_authorization, request_binding.authorization_digest, work,
                "grant authorization differs from the genuine original authorization")
        maximum_age, skew = window[5:]
    elif request_binding is None:
        window = clock._open_on_work(deadline_epoch_ns=held_deadline,
            maximum_lifetime_ns=maximum_age, maximum_clock_skew_ns=skew, work=work)
        bound = window[4] if inherited is None else min(window[4], inherited)
        last_epoch, last_monotonic = window[0], window[2]
    else:
        # Reuse the verifier's original clock bracket, including its final
        # rollback observations. Neither enrollment replay nor plan replay
        # earns a fresh interval or a replacement cumulative work allowance.
        window = clock._validate(request_binding.window)
        maximum_age, skew = min(maximum_age, window[5]), min(skew, window[6])
        expires = min(window[3], held_deadline, request_binding.expires_at_epoch_ns,
            window[0] + maximum_age)
        window = clock._validate((window[0], window[1], window[2], expires,
            window[1] + expires - window[0], maximum_age, skew))
        bound = min(window[4], request_binding.deadline_ns)
        if inherited is not None:
            bound = min(bound, inherited)
        last_epoch = request_binding.last_epoch_ns
        last_monotonic = request_binding.last_monotonic_ns
        plan._same(held_authorization, request_binding.authorization_digest, work,
            "grant authorization differs from the genuine original authorization")
    original_interval = None

    def live():
        nonlocal last_epoch, last_monotonic
        original_now = None if original_current is None else original_current()
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < last_epoch or monotonic < last_monotonic or monotonic >= bound
                or original_now is not None and now < original_now):
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
        operation_public_key=held_operation_key, before_vector_bytes=held_before, work=work,
        activation_custody=held.activation_custody, live_window=window if activation else None,
        transport_deadline_ns=bound if activation else None)
    issued, original_expires = replayed.original_interval
    if request_binding is not None and issued < request_binding.issued_at_epoch_ns:
        raise SuccessorExecutionGrantProductionError("original plan precedes its request authorization")
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
    if request_binding is not None:
        plan._same(request_digest, request_binding.request_digest, work,
            "actual original plan request differs from its request authorization")
        plan._same(operation_id, request_binding.operation_id, work,
            "actual original plan operation differs from its request authorization")
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
