"""Produce a consume-only grant from genuinely admitted and replayed originals.

No payload, successful replay result or signing callback is accepted. The actual
enrolled key signs only same-call derived claims under the original allowance.
Post-signature verification repeats fixed wire/control/claim joins, not private
proof replay. This module creates no cold service or generic consume authority.
"""
from __future__ import annotations

from catchplate import authority_oidc_session_activation_delivery_execution_grant as contract
from catchplate import authority_oidc_session_activation_delivery_execution_grant_admission as admission


class DeliveryExecutionGrantProductionError(ValueError):
    pass


def _advance(previous, current):
    if (type(current) is not tuple or len(current) != 2
            or any(type(value) is not int or value <= 0 for value in current)
            or (previous is not None and (current[0] < previous[0] or current[1] < previous[1]))):
        raise DeliveryExecutionGrantProductionError("consume grant production clocks reversed or changed shape")
    return current


def _produce_on_work(*, authorization_bytes, authorization_enrollment_bytes,
        current_root_enrollment_bytes, grant_enrollment_bytes, root_public_key,
        configuration_digest, planner_public_key, operation_public_key, originals,
        expectations, before_vector_bytes, receiving_custody, live_window,
        transport_deadline_ns, private_key, work):
    """Return only the original signed grant bytes, without renewed authority."""
    # Hold the exact native signer before shared capture can hash or invoke any
    # callback. The actual public partner comes only from genuine root admission.
    private = private_key
    contract.authorization._private(private)
    held = admission._hold_on_work(authorization_bytes=authorization_bytes,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, root_public_key=root_public_key,
        configuration_digest=configuration_digest, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, originals=originals, expectations=expectations,
        before_vector_bytes=before_vector_bytes, receiving_custody=receiving_custody,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    admitted = admission._admit_on_work(held, work)
    last = _advance(None, admitted.live())
    public = admitted.enrollment.authorizer_public_key
    contract.keys._pair_on_work(private, public, work)
    last = _advance(last, admitted.live())
    actual = admission._replay_on_work(admitted, work)
    last = _advance(last, actual.live())
    # Both mappings come from this same original admission/replay. Neither is
    # an incoming authority object or arbitrary payload selected by a caller.
    work.prepare_copy(admitted.bindings)
    work.prepare_copy(actual.claims)
    work.charge(input_bytes=2, json_nodes=1)
    payload = {**admitted.bindings, **actual.claims,
        "issuedAtEpochNs": actual.claims["originalIssuedAtEpochNs"],
        "expiresAtEpochNs": actual.valid_until_epoch_ns}
    admission._check_control_on_work(payload, admitted, work)
    admission._check_claims_on_work(payload, actual, work)
    last = _advance(last, actual.live())
    original = contract._sign_on_work(payload, private, public, work)
    last = _advance(last, actual.live())
    if admitted.held.original_bytes + len(original) > contract.MAX_ORIGINAL_BYTES:
        raise DeliveryExecutionGrantProductionError("consume grant and held originals exceed the aggregate bound")
    checked, identity = contract._verify_signature_on_work(original, public, work)
    last = _advance(last, actual.live())
    contract.shape._digest(identity)
    contract.plan._same(checked, payload, work, "consume grant signed original differs from actual derivation")
    admission._check_control_on_work(checked, admitted, work)
    admission._check_claims_on_work(checked, actual, work)
    final = _advance(last, actual.live())
    if final[0] >= actual.valid_until_epoch_ns or final[1] >= actual.deadline_ns:
        raise DeliveryExecutionGrantProductionError("consume grant expired during signing or output verification")
    return original
