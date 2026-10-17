"""Sign finalization execution claims only after genuine caller/raw7 admission.

No incoming successful carrier or caller-selected authorization digest is
accepted. The original signed purpose is authenticated before raw7 replay;
the genuine generic producer then replays raw4 plus the complete before-vector
and joins the same request/operation BEFORE signing. Its private adapter only
continues this invocation's original window and cumulative work.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_registration_finalization_plan_admission as admission
from catchplate import authority_successor_execution_grant_production as production


OPERATION = admission.OPERATION


class RegistrationFinalizationGrantProductionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _RequestBinding:
    """Same-call adapter only; neither public producer accepts this object."""

    request_digest: str
    operation_id: str
    authorization_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple
    deadline_ns: int
    last_epoch_ns: int
    last_monotonic_ns: int


def _produce_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, before_vector_bytes, authorization_bytes,
        authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, authorizer_private_key,
        live_window, work, transport_deadline_ns=None):
    """Return only the actual original signed grant for fixed finalization."""
    production.capture._SharedLedger(work)
    if type(originals) is not tuple or len(originals) != 7:
        raise RegistrationFinalizationGrantProductionError("finalization grant requires exact original raw7")
    held = admission.custody.transport._validate_originals(intent_bytes=originals[0],
        relay_bytes=originals[1], envelope_bytes=originals[2], proof_bytes=originals[3],
        inputs_bytes=originals[4], context_bytes=originals[5], historical_expectations_bytes=originals[6])
    raw4, before = production.replay._originals(OPERATION, held[2:6], before_vector_bytes)
    request = production.authorization._original(authorization_bytes,
        admission.caller.MAX_AUTHORIZATION_BYTES, "finalization request authorization")
    caller_enrollment = production.authorization._original(authorization_enrollment_bytes,
        admission.caller.MAX_ENROLLMENT_BYTES, "finalization caller enrollment")
    grant_enrollment = production.authorization._original(grant_enrollment_bytes,
        production.grants.MAX_ENROLLMENT_BYTES, "finalization grant enrollment")
    current_enrollment = production.authorization._original(current_root_enrollment_bytes,
        production.authorization.MAX_ENROLLMENT_BYTES, "finalization current-root enrollment")
    if sum(len(raw) for raw in (*held, before, request, caller_enrollment,
            grant_enrollment, current_enrollment)) > production.replay.MAX_ORIGINAL_BYTES:
        raise RegistrationFinalizationGrantProductionError("finalization grant originals exceed their aggregate bound")
    root, signer = root_public_key, authorizer_private_key
    production.authorization._public(root)
    production.authorization._private(signer)
    # Hold the complete raw12 inventory and actual key references before any
    # signature/clock callback. The shared admission owns configuration graphs.
    admitted = admission._admit_on_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, originals=held,
        authorization_bytes=request, authorization_enrollment_bytes=caller_enrollment,
        grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=current_enrollment,
        root_public_key=root, live_window=live_window, work=work,
        transport_deadline_ns=transport_deadline_ns)
    authorized, configured = admitted.authorized, admitted.configured
    captured = production._hold_on_work(operation=OPERATION, originals=raw4,
        expectations=admitted.expectations, planner_public_key=configured.pins[1],
        operation_public_key=configured.pins[4], before_vector_bytes=before,
        grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=current_enrollment,
        root_public_key=root, authorizer_private_key=signer,
        deadline_epoch_ns=admitted.window[3], work=work, transport_deadline_ns=admitted.deadline_ns)
    last_epoch, last_monotonic = admitted.check()
    binding = _RequestBinding(authorized.request_digest, authorized.operation_id,
        authorized.authorization_digest, authorized.issued_at_epoch_ns, authorized.expires_at_epoch_ns,
        admitted.window, admitted.deadline_ns, last_epoch, last_monotonic)
    # This real suffix checks the dedicated key pair, replays the complete
    # vector and raw4, and compares actual request identities before signing.
    original_grant = production._produce_held_on_work(captured, authorized.authorization_digest,
        work=work, request_binding=binding)
    now, _monotonic = admitted.check()
    actual, _identity = production.grants._verify_control_on_work(grant_bytes=original_grant,
        grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=current_enrollment,
        root_public_key=root, planner_public_key=configured.pins[1], operation_public_key=configured.pins[4],
        expected_authorization_digest=authorized.authorization_digest, now_epoch_ns=now, work=work)
    for name, expected in (("operation", OPERATION), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id), ("databaseId", authorized.database_id),
            ("generationDigest", authorized.generation_digest),
            ("currentRootEnrollmentDigest", authorized.current_root_enrollment_digest),
            ("grantEnrollmentDigest", authorized.grant_enrollment_digest),
            ("retainedRecordDigest", admitted.retained_record_digest)):
        production.plan._same(actual[name], expected, work, "produced finalization grant differs from " + name)
    if (actual["issuedAtEpochNs"] < authorized.issued_at_epoch_ns
            or actual["expiresAtEpochNs"] > admitted.window[3]):
        raise RegistrationFinalizationGrantProductionError("produced finalization grant escapes its original scope")
    final_now, _final_monotonic = admitted.check()
    if final_now >= actual["expiresAtEpochNs"]:
        raise RegistrationFinalizationGrantProductionError("produced finalization grant expired before return")
    return original_grant
