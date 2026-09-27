"""Genuine finalization grant/plan admission into an original reserve request.

Independent cold inputs fix configuration, root and original enrollments,
computation key and predecessor/fence. Actual finalization caller signatures,
custody controls and complete grant/plan/vector replay precede the existing
generic reserve producer. No evidence-admission purpose or successful result
carrier replaces those originals. The generic signer receives original bytes,
not this module's same-call admission facts, and performs its actual replay.

The supplied work/window and inherited epoch/monotonic bounds remain live
through return. Generic internal brackets cannot renew those original limits.
Only the actual CurrentRootComputation original request/snapshot pair returns;
there is no transport, storage, pending/currentness claim, SQL, completion,
credential/session activation, automatic retry or replacement allowance here.
"""
from __future__ import annotations

from serverware import authority_registration_finalization_execution_admission as admission
from serverware import authority_successor_execution_preparation as preparation


authorization, grants, evidence, clock = (
    admission.authorization, admission.grants, admission.evidence, admission.clock)
OPERATION = admission.OPERATION


class RegistrationFinalizationReservationError(ValueError):
    pass


def _produce_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, before_vector_bytes, authorization_bytes,
        grant_bytes, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, computation_private_key,
        predecessor_sequence, predecessor_head_digest, fence, live_window,
        transport_deadline_ns, work):
    """Return actual reserve originals for independently admitted predecessor scope."""
    evidence.capture._SharedLedger(work)
    signer = computation_private_key
    authorization._private(signer)
    shape = authorization.shape
    shape._integer(predecessor_sequence, authorization.MAX_RECORDS)
    shape._digest(predecessor_head_digest)
    shape._integer(fence, minimum=1)
    shape._integer(transport_deadline_ns, minimum=1)
    sequence, predecessor, held_fence = predecessor_sequence, predecessor_head_digest, fence
    inherited = transport_deadline_ns
    window = clock._validate(live_window)
    # All independent immutable scope and key references are held before the
    # actual admission captures graphs and invokes any native callbacks.
    # That gate enforces the aggregate of every original, including the grant.
    admitted = admission._admit_on_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, originals=originals,
        before_vector_bytes=before_vector_bytes, authorization_bytes=authorization_bytes,
        authorization_enrollment_bytes=authorization_enrollment_bytes, grant_bytes=grant_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, live_window=window, work=work,
        transport_deadline_ns=inherited)
    admitted.live()
    # No post-replay caller graph is consulted. The actual original-derived
    # history/key pins stay local, and the generic producer re-verifies the
    # exact grant/raw4/vector before using its real computation signing suffix.
    produced = preparation._produce_reserve_on_work(operation=OPERATION,
        originals=admitted.raw4, expectations=admitted.history,
        planner_public_key=admitted.configured.pins[1],
        operation_public_key=admitted.configured.pins[4],
        before_vector_bytes=admitted.before, enrollment_bytes=admitted.current_enrollment,
        root_public_key=admitted.root, computation_private_key=signer,
        grant_bytes=admitted.grant, grant_enrollment_bytes=admitted.grant_enrollment,
        expected_authorization_digest=admitted.authorized.authorization_digest,
        predecessor_sequence=sequence, predecessor_head_digest=predecessor, fence=held_fence,
        deadline_epoch_ns=admitted.deadline_epoch_ns,
        transport_deadline_ns=min(inherited, admitted.deadline_ns), work=work)
    admitted.live()
    if type(produced) is not preparation.computation.CurrentRootComputation:
        raise RegistrationFinalizationReservationError("finalization reserve did not return actual original computation")
    return produced
