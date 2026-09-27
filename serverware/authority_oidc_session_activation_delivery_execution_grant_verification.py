"""Original-based live consume-grant verification, not execution admission.

Caller/root/custody admission and the genuine grant signature precede private
decryption. The actual consume originals are then replayed once. No successful
result object, generic grant fallback or renewed clock allowance is accepted.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_delivery_execution_grant as wire
from serverware import authority_oidc_session_activation_delivery_execution_grant_admission as admission
from serverware import authority_successor_execution_window as windows


class DeliveryExecutionGrantVerificationError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedGrant:
    """Ordinary same-call data and guard, never an accepted proof input."""

    payload: dict
    grant_digest: str
    result: object
    valid_until_epoch_ns: int
    window: tuple
    deadline_ns: int
    live: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedFullGrant:
    """Private same-call continuation; never an accepted proof input."""

    verified: _VerifiedGrant
    replayed: object


def _fail(message):
    raise DeliveryExecutionGrantVerificationError(message)


def _verify_on_work(*, grant_bytes, authorization_bytes, authorization_enrollment_bytes,
        current_root_enrollment_bytes, grant_enrollment_bytes, root_public_key,
        configuration_digest, planner_public_key, operation_public_key, originals,
        expectations, before_vector_bytes, receiving_custody, live_window,
        transport_deadline_ns, work):
    """Authenticate the signed grant and replay its exact original consume plan."""
    return _verify_full_on_work(grant_bytes=grant_bytes, authorization_bytes=authorization_bytes,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, root_public_key=root_public_key,
        configuration_digest=configuration_digest, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, originals=originals, expectations=expectations,
        before_vector_bytes=before_vector_bytes, receiving_custody=receiving_custody,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        work=work, required_consumer_role="grant").verified


def _verify_full_on_work(*, grant_bytes, authorization_bytes, authorization_enrollment_bytes,
        current_root_enrollment_bytes, grant_enrollment_bytes, root_public_key,
        configuration_digest, planner_public_key, operation_public_key, originals,
        expectations, before_vector_bytes, receiving_custody, live_window,
        transport_deadline_ns, work, required_consumer_role="grant", extra_originals=()):
    """Replay once for a fixed receiving purpose and retain actual replay facts.

    Extra originals are only the bounded reserve/snapshot/ACK held by the
    reservation continuation. They join the aggregate before admission callbacks.
    Neither successful result type is accepted by an original-input entrypoint.
    """
    try:
        # Immutable grant capture precedes every callback. The common capture
        # also meters this exact extra original before caller hashes or clocks.
        original = wire.authorization._original(grant_bytes, wire.MAX_GRANT_BYTES,
            "consume execution grant")
        if type(extra_originals) is not tuple or len(extra_originals) > 3:
            _fail("consume grant continuation originals are not a bounded tuple")
        extras = tuple(wire.authorization._original(value, wire.MAX_ORIGINAL_BYTES,
            "consume reservation continuation original") for value in extra_originals)
        held = admission._hold_on_work(authorization_bytes=authorization_bytes,
            authorization_enrollment_bytes=authorization_enrollment_bytes,
            current_root_enrollment_bytes=current_root_enrollment_bytes,
            grant_enrollment_bytes=grant_enrollment_bytes, root_public_key=root_public_key,
            configuration_digest=configuration_digest, planner_public_key=planner_public_key,
            operation_public_key=operation_public_key, originals=originals,
            expectations=expectations, before_vector_bytes=before_vector_bytes,
            receiving_custody=receiving_custody, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, work=work,
            required_consumer_role=required_consumer_role, extra_originals=(original, *extras))
        admitted = admission._admit_on_work(held, work)
        admitted.live()
        payload, grant_digest = wire._verify_signature_on_work(original,
            admitted.enrollment.authorizer_public_key, work)
        admitted.live()
        # Static cohort/caller/raw-frame and current original-lifetime joins
        # must hold before the actual custody owner decrypts the bundle.
        admission._check_control_on_work(payload, admitted, work)
        admitted.live()
        replay = admission._replay_on_work(admitted, work)
        replay.live()
        admission._check_claims_on_work(payload, replay, work)
        replay.live()

        signed_expiry = payload["expiresAtEpochNs"]
        if signed_expiry > replay.valid_until_epoch_ns:
            _fail("consume grant expires beyond its genuine original replay ceiling")
        window = windows._narrow(replay.window, deadline_epoch_ns=signed_expiry,
            maximum_lifetime_ns=replay.window[5], maximum_clock_skew_ns=replay.window[6])
        deadline = min(replay.deadline_ns, window[4])
        valid_until = min(signed_expiry, replay.valid_until_epoch_ns, window[3])

        def live():
            first = replay.live()
            observed = windows.clock._check_on_work(window, work=work)
            last = replay.live()
            if (not first[0] <= observed <= last[0] or first[1] > last[1]
                    or last[1] >= deadline or last[0] >= valid_until):
                _fail("consume grant expired or clocks reversed before return")
            return last

        live()
        # Copy the actual token-free business result with the same bounded
        # source copier and cumulative work used by original replay itself.
        result = wire.capture._JSONCapture(wire.capture._SharedLedger(work),
            maximum_bytes=wire.authority.MAX_RESULT_BYTES).visit(replay.replayed.result)
        live()
        verified = _VerifiedGrant(payload, grant_digest, result, valid_until, window, deadline, live)
        live()
        return _VerifiedFullGrant(verified, replay.replayed)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, DeliveryExecutionGrantVerificationError):
            raise
        raise DeliveryExecutionGrantVerificationError("consume execution grant verification failed") from exc
