"""Local-only retained finalization prerequisite for separate OIDC activation.

Original ownership and the retained finalization acknowledgment are genuinely
replayed under the actual cold owner. A missing or uncertain acknowledgment
fails locally: this module never calls completion/recovery transport, appends
an outcome, signs, executes SQL, or changes an OIDC session.

Returned exact subject scalars are ordinary data, not activation permission or
a reusable successful-admission token. The future effect owner must invoke the
private same-work inspection again and independently admit current permission,
session/credential state and the real activation transition.
"""
from __future__ import annotations

from serverware import authority_registration_finalization_completion_history as admission
from serverware import control_plane_registration_finalization_completion_subject as completion_subject
from serverware import control_plane_registration_finalization_outcome_records as records


startup, evidence, clock = completion_subject.startup, completion_subject.evidence, completion_subject.clock
custody_client, journal, wire = completion_subject.custody_client, completion_subject.journal, completion_subject.wire
_SUBJECT_FIELDS = frozenset({"localDigest", "userId", "challengeId", "sessionId", "mode",
    "requestDigest", "operationId", "credentialId"})


class RegistrationActivationSubjectError(ValueError):
    pass


def _expected_subject(expected_user_id, expected_session_id):
    user_id, session_id = completion_subject.handoff._expected_subject(
        expected_user_id, expected_session_id)
    if type(session_id) is not str or not session_id:
        raise RegistrationActivationSubjectError("activation inspection requires the authenticated pending session")
    return user_id, session_id


def _inspect_material_on_owner(owner, *, local_digest, expected_user_id, expected_session_id,
        live_window, transport_deadline_ns, work):
    """Replay originals and retain only cold continuity after ACK admission."""
    ledger = evidence.capture._SharedLedger(work)
    digest = journal._digest(local_digest)
    user_id, session_id = _expected_subject(expected_user_id, expected_session_id)
    inspected = completion_subject._inspect_material_on_owner(owner, digest,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    subject, held, reserved, observed, common = (inspected.subject, inspected.originals,
        inspected.reservation_originals, inspected.observed, inspected.common)
    window, bound, current = inspected.window, inspected.deadline_ns, inspected.current
    if type(subject) is not dict or set(subject) != _SUBJECT_FIELDS:
        raise RegistrationActivationSubjectError("activation inspection subject shape differs")
    evidence.plan._same((subject["localDigest"], subject["userId"], subject["sessionId"], subject["mode"]),
        (digest, user_id, session_id, "oidc-session-first-enrollment"), work,
        "activation inspection differs from authenticated current user/session or original OIDC mode")
    current()
    pending = inspected.current_pending
    record = observed.completion_reconciled
    expected_kind = "completion-reconciled"
    if record is None:
        record = observed.completion_outcome
        expected_kind = "completion-outcome"
    if (type(record) is not records.FinalizationOutcomeRecord
            or record.finalization_digest != digest
            or record.source_revision != observed.source_revision
            or record.kind != expected_kind):
        raise RegistrationActivationSubjectError("activation inspection requires an associated retained completion original")
    returned = wire._originals(record.originals, response=True)
    if returned[0] != b"acknowledged":
        raise RegistrationActivationSubjectError("activation inspection cannot recover missing or uncertain completion")
    # The subject inspector already bounded the complete retained inventory,
    # including both completion slots, before cryptographic callbacks. These
    # exact originals are part of that inventory, not a fresh remote response.
    current()
    admission._verify_on_configuration(**common, originals=held,
        reservation_originals=reserved, response_originals=returned,
        expected_pending_sequence=pending[0], expected_pending_head_digest=pending[1],
        expected_fence=pending[2], live_window=window, work=work, transport_deadline_ns=bound)
    current()
    result = evidence.capture._JSONCapture(ledger,
        maximum_bytes=evidence.authority.MAX_REQUEST_BYTES).visit(subject)
    current()
    # The ACK has consumed the historical graphs and originals. This narrow
    # guard retains only actual cold owners/archive lifetime, not the replay
    # inventory or an authority token; the copied scalar subject is ordinary data.
    return result, inspected.continuity


def _inspect_on_owner(owner, *, local_digest, expected_user_id, expected_session_id,
        live_window, transport_deadline_ns, work):
    """Existing same-call effect owners receive only freshly replayed scalars."""
    result, current = _inspect_material_on_owner(owner, local_digest=local_digest,
        expected_user_id=expected_user_id, expected_session_id=expected_session_id,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    current()
    return result


def inspect_retained_registration_activation_subject(local_digest, *, expected_user_id, expected_session_id):
    """Return exact eight-field original ownership data, never permission.

    Expected user/session must come from genuine present authentication. This
    facade does not authenticate a browser cookie or authorize activation.
    """
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    digest = journal._digest(local_digest)
    user_id, session_id = _expected_subject(expected_user_id, expected_session_id)
    work = _ValidationWork(QueryReadValidationLimits())
    callback = evidence.production._callback
    owner, material, binding, window = completion_subject._open_on_work(work)
    custody = owner._custody
    result, current = startup._EnrollmentOwner._inspect_retained_registration_activation_subject(
        owner, local_digest=digest, expected_user_id=user_id, expected_session_id=session_id,
        live_window=window, transport_deadline_ns=window[4], work=work)
    if (owner._material is not material or owner._binding is not binding
            or owner._custody is not custody or callback(work, startup.require_started) is not owner
            or callback(work, completion_subject.custody_startup.require_started) is not custody):
        raise RegistrationActivationSubjectError("activation inspection cold owners changed")
    clock._check_on_work(window, work=work)
    current()
    return result
