"""Compose original registration request authorization with raw3 grant replay.

The independently pinned root, enrollment originals, planner/evidence keys and
configuration remain caller-admitted prerequisites. The new request-purpose
signature is verified here; an evidence-signing grant, successful verification
carrier or caller-selected authorization digest is never accepted instead.

Only the actual original plan replay supplies the grant claims. Its request
and operation identities must equal the genuinely authenticated authorization
before the dedicated successor authorizer signs anything. Original issue and
expiry bounds are intersected without reopening the verifier's live window or
replacing the caller's cumulative work. All originals, independent historical
expectations and key references are captured before native verification.

The result is only an original signed execution grant. This provides no cold
owner, key provisioning, transport, reserve, current-root admission, SQL
execution, one-use custody or successful execution acknowledgement.
"""
from __future__ import annotations

from serverware import authority_registration_execution_authorization as request_authorization
from serverware import authority_successor_execution_grant_production as production


class RegistrationExecutionGrantProductionError(ValueError):
    pass


def _produce_on_work(*, originals, expectations, planner_public_key,
        evidence_public_key, before_vector_bytes, authorization_bytes,
        authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, authorizer_private_key,
        configuration_digest, deadline_epoch_ns, work, transport_deadline_ns=None):
    """Verify original request authority and sign matching genuine raw3 claims.

    The operation is source fixed. Neither the original request digest nor
    the original authorization digest is supplied as an independent shortcut.
    Every cryptographic and replay phase uses the same ``work`` object.
    """
    production.capture._SharedLedger(work)
    original_authorization = production.authorization._original(authorization_bytes,
        request_authorization.MAX_AUTHORIZATION_BYTES, "registration request authorization")
    original_authorization_enrollment = production.authorization._original(
        authorization_enrollment_bytes, request_authorization.MAX_ENROLLMENT_BYTES,
        "registration request authorization enrollment")
    production.shape._digest(configuration_digest)
    held_configuration = configuration_digest
    held = production._hold_on_work(operation=request_authorization.OPERATION,
        originals=originals, expectations=expectations, planner_public_key=planner_public_key,
        operation_public_key=evidence_public_key, before_vector_bytes=before_vector_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, authorizer_private_key=authorizer_private_key,
        deadline_epoch_ns=deadline_epoch_ns, work=work,
        transport_deadline_ns=transport_deadline_ns)
    if (held.original_bytes + len(original_authorization)
            + len(original_authorization_enrollment) > production.replay.MAX_ORIGINAL_BYTES):
        raise RegistrationExecutionGrantProductionError(
            "registration grant originals exceed the source aggregate")
    # The raw3 verifier later authenticates this exact captured expectation
    # against the actual plan; no returned plan chooses its own configuration.
    production.plan._same(held.expectations["configurationDigest"], held_configuration,
        work, "registration plan configuration differs from independently admitted authorization scope")
    verified = request_authorization._verify_on_work(
        authorization_bytes=original_authorization,
        authorization_enrollment_bytes=original_authorization_enrollment,
        current_root_enrollment_bytes=held.current_enrollment,
        grant_enrollment_bytes=held.grant_enrollment, root_public_key=held.root,
        configuration_digest=held_configuration, planner_public_key=held.planner,
        evidence_public_key=held.operation_key, deadline_epoch_ns=held.deadline,
        work=work, transport_deadline_ns=held.inherited)
    # This private suffix accepts only this same-call result through this raw
    # composition. Its actual replay-derived request/operation joins precede
    # grant signing, and its live guard continues the original verifier window.
    return production._produce_held_on_work(held, verified.authorization_digest,
        work=work, request_binding=verified)
