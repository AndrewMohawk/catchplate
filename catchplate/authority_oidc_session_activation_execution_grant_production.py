"""Issue one activation grant from true post-plan caller and private originals.

No authorization digest, replay result or prepared-plan carrier is accepted in
place of original signatures. Actual receiving custody stays private. The
generic producer repeats full original replay and joins its claims to the
same-call caller authorization before signing the original grant bytes.
"""
from __future__ import annotations

from catchplate import authority_oidc_session_activation_execution_authorization as caller
from catchplate import authority_oidc_session_activation_execution_custody as custody
from catchplate import authority_successor_execution_grant_production as production


OPERATION = caller.OPERATION


class ActivationExecutionGrantProductionError(ValueError):
    pass


def _produce_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, planner_public_key, operation_public_key, authorizer_private_key,
        configuration_digest, activation_custody, live_window, transport_deadline_ns, work):
    """Return only a genuine grant, preserving the original plan's issue time."""
    original = caller.authorization._original(authorization_bytes,
        caller.MAX_AUTHORIZATION_BYTES, "activation execution caller authorization")
    owner, signer = activation_custody, authorizer_private_key
    if type(owner) is not custody.OidcSessionActivationExecutionCustody:
        raise ActivationExecutionGrantProductionError("activation grant requires the actual private receiving owner")
    caller.authorization._private(signer)
    held = caller._capture_on_work(originals=originals, expectations=expectations,
        before_vector_bytes=before_vector_bytes, authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        configuration_digest=configuration_digest, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, extra_originals=(original,))
    # Every caller graph and key reference is held before this process/key
    # configuration check. Receiving purpose cannot be borrowed from reserve.
    configured = custody.OidcSessionActivationExecutionCustody._snapshot_configuration(owner)
    if configured.consumer_role != "grant":
        raise ActivationExecutionGrantProductionError("activation grant requires grant-purpose receiving custody")
    production.replay._activation_context_on_work(OPERATION, owner,
        root_public_key=held.root, current_root_enrollment_bytes=held.current_enrollment, work=work)
    authorized = caller._verify_held_on_work(held, original, work)
    authorized.live()
    inputs = production._hold_on_work(operation=OPERATION, originals=held.originals,
        expectations=held.expectations, planner_public_key=held.planner, operation_public_key=held.operation_key,
        before_vector_bytes=held.before, grant_enrollment_bytes=held.grant_enrollment,
        current_root_enrollment_bytes=held.current_enrollment, root_public_key=held.root,
        authorizer_private_key=signer, deadline_epoch_ns=authorized.window[3], work=work,
        transport_deadline_ns=authorized.deadline_ns, activation_custody=owner, live_window=authorized.window)
    authorized.live()
    result = production._produce_held_on_work(inputs, authorized.authorization_digest,
        work=work, request_binding=authorized)
    authorized.live()
    if custody.OidcSessionActivationExecutionCustody._snapshot_configuration(owner) is not configured:
        raise ActivationExecutionGrantProductionError("activation grant receiving configuration changed")
    # The generic suffix has already verified its real signed output and all
    # replay-derived claims. This final independent caller bound cannot renew it.
    authorized.live()
    return result
