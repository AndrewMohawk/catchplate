"""Historical retained ownership for finalization completion, never permission.

The finalization grant's local association is only a locator. The actual cold
owner supplies independently admitted current or archived configuration, original
enrollments, pending scope and completion authorization/packet pins. This path
authenticates the historical finalization, its associated signer/evidence grant
and acknowledged evidence completion, then regenerates the complete finalization
request from THAT signer. A successful incoming subject object cannot skip it.

One present processing window and work allowance span the replay. Historical
expiry remains historical, never a clock or renewed SQL authority. There is no
transport, signing, mutation, public permission or browser-session activation.
Source-version adapters remain separate; signed source labels are never rewritten.
"""
from __future__ import annotations

from serverware import authority_registration_finalization_history_exchange as history
from serverware import authority_registration_finalization_completion_response as completion
from serverware import authority_registration_finalization_reservation_transport as reservation_wire
from serverware import authority_registration_completion_history as evidence_completion
from serverware import authority_registration_history_exchange as evidence_history
from serverware import authority_webauthn_registration_signer_history as signer_history
from serverware import control_plane_registration_finalization_execution as caller
from serverware import control_plane_registration_finalization_records as finalization_records
from serverware import control_plane_registration_finalization_reservation_records as reservation_records
from serverware import control_plane_registration_finalization_outcome_records as outcome_records
from serverware import control_plane_registration_handoff_subject as subjects
from serverware import control_plane_registration_handoff as handoff
from serverware import control_plane_registration_finalization_history as resolved_history


startup, evidence, clock = caller.startup, caller.evidence, caller.clock
custody_client, custody_startup = caller.custody_client, caller.custody_startup
journal, wire = custody_client.journal, completion.transport
# Source-defined byte representations, not an interpreter heap-size assertion.
# Retain the actual sealed cold parent and its known captures separately from
# two regenerated typed-request representations; never substitute a posted size.
_PARENT_REPRESENTATIONS = 8
_REPLAY_HEADROOM_BYTES = 2 * evidence.authority.MAX_REQUEST_BYTES + 2 * 8192
_HISTORY_REPRESENTATIONS = 8
_RESPONSE_REPRESENTATIONS_BYTES = 8 * wire.MAX_RESPONSE_BYTES + 64 * 1024
_HISTORY_METADATA_BYTES = 16 * 1024


class FinalizationCompletionSubjectError(ValueError):
    pass


def _parent_representation_bytes_on_owner(owner, *, work, current):
    """Measure only the original admitted sealed descriptor, under its owner."""
    if type(owner) is not startup._EnrollmentOwner or not callable(current):
        raise FinalizationCompletionSubjectError("parent measurement requires its actual owner and guard")
    callback = evidence.production._callback
    current()
    callback(work, lambda: startup._continuity(owner))
    material, binding, custody = owner._material, owner._binding, owner._custody
    descriptor, identity = owner._bootstrap_fd, owner._bootstrap_identity
    if (type(descriptor) is not int or descriptor < 0
            or type(identity) is not tuple or len(identity) != 11
            or type(identity[6]) is not int or not 2 <= identity[6] <= startup.MAX_BOOTSTRAP_BYTES):
        raise FinalizationCompletionSubjectError("parent descriptor has no bounded admitted original size")
    actual = callback(work, lambda: startup._descriptor_identity(descriptor, private=False))
    if actual != identity:
        raise FinalizationCompletionSubjectError("parent original descriptor changed during measurement")
    callback(work, lambda: startup._continuity(owner))
    current()
    if (owner._material is not material or owner._binding is not binding or owner._custody is not custody
            or owner._bootstrap_fd != descriptor or owner._bootstrap_identity is not identity):
        raise FinalizationCompletionSubjectError("parent original owner changed during measurement")
    return _PARENT_REPRESENTATIONS * identity[6]


def _open_on_work(work):
    """Open current processing from the actual cold owner, never an old time."""
    startup._require_pid()
    callback = evidence.production._callback
    owner = callback(work, startup.require_started)
    if (type(owner) is not startup._EnrollmentOwner
            or not callback(work, lambda: owner.finalization_completion_enabled)
            or not callback(work, lambda: owner.sql_handoff_enabled)
            or callback(work, custody_startup.require_started) is not owner._custody):
        raise FinalizationCompletionSubjectError("finalization completion is not cold-enabled")
    material, binding = owner._material, owner._binding
    endpoint = wire._endpoint(material.finalization.completion_endpoint)
    window = clock._open_on_work(deadline_epoch_ns=binding.attestation_interval[1],
        maximum_lifetime_ns=min(binding.maximum_deadline_ns, int(endpoint[1] * 1_000_000_000),
            evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS),
        maximum_clock_skew_ns=material.issuer_policy["maximumClockSkewNs"], work=work)
    if (owner._material is not material or owner._binding is not binding
            or callback(work, startup.require_started) is not owner
            or callback(work, custody_startup.require_started) is not owner._custody):
        raise FinalizationCompletionSubjectError("finalization completion startup changed")
    clock._check_on_work(window, work=work)
    return owner, material, binding, window


def _scope_on_owner(owner, *, live_window, transport_deadline_ns, work):
    """Preserve the original opening while checking actual current ownership."""
    callback = evidence.production._callback
    if (type(owner) is not startup._EnrollmentOwner
            or not callback(work, lambda: owner.finalization_completion_enabled)
            or not callback(work, lambda: owner.sql_handoff_enabled)):
        raise FinalizationCompletionSubjectError("finalization completion requires enabled cold owners")
    common, _private, window, bound, owner_live = caller._scope(owner,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    material, binding, custody = owner._material, owner._binding, owner._custody
    configured = material.finalization
    endpoint = wire._endpoint(configured.completion_endpoint)
    bound = min(bound, window[1] + int(endpoint[1] * 1_000_000_000))

    def current():
        owner_live()
        if (owner._material is not material or owner._binding is not binding
                or owner._custody is not custody or material.finalization is not configured
                or callback(work, startup.require_started) is not owner
                or callback(work, custody_startup.require_started) is not custody
                or callback(work, lambda: custody_client._snapshot(custody)) is not binding):
            raise FinalizationCompletionSubjectError("finalization completion owners changed")
        clock._check_on_work(window, work=work)
        callback(work, lambda: wire._check_deadline(bound))
        owner_live()

    current()
    return common, endpoint, window, bound, current


def _association_on_work(association, digest, work):
    """Check ordinary records returned only by the actual combined loader."""
    if (type(association) is not tuple or len(association) != 3
            or type(association[0]) is not subjects.records.PreparedRecord
            or type(association[2]) is not tuple or len(association[2]) != 2
            or any(type(record) is not subjects.records.PreparedRecord for record in association[2])):
        raise FinalizationCompletionSubjectError("finalization completion requires its complete retained association")
    final_record, evidence_digest, pair = association
    evidence_digest = journal._digest(evidence_digest)
    evidence_record, signer_record = pair
    if (final_record.digest != digest or evidence_record.digest != evidence_digest
            or (final_record.family, final_record.selector)
                != (finalization_records.FAMILY, finalization_records.OPERATION)
            or (evidence_record.family, evidence_record.selector)
                != (subjects.execution_records.FAMILY, subjects.execution_records.OPERATION)
            or (signer_record.family, signer_record.selector)
                != (subjects.signer_records.FAMILY, subjects.signer_records.OPERATION)
            or final_record.source_revision != evidence.authority.SOURCE_REVISION
            or evidence_record.source_revision != final_record.source_revision
            or signer_record.source_revision != final_record.source_revision
            or len({digest, evidence_digest, signer_record.digest}) != 3):
        raise FinalizationCompletionSubjectError("finalization completion association source or family differs")
    return final_record, evidence_digest, evidence_record, signer_record


def _inspect_material_on_owner(owner, local_digest, *, live_window, transport_deadline_ns, work,
        _additional_original_bytes=0):
    """Return same-call subject and raw originals; no API accepts them as proof."""
    digest = journal._digest(local_digest)
    common, endpoint, window, bound, current = _scope_on_owner(owner,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    material, custody = owner._material, owner._custody
    configured = material.finalization
    window, bound, current, archive_bytes = resolved_history._lifetime_on_owner(owner,
        window=window, bound=bound, work=work, current=current)
    if (type(_additional_original_bytes) is not int
            or not 0 <= _additional_original_bytes < completion.MAX_ORIGINAL_BYTES
            or completion.MAX_ORIGINAL_BYTES != 64 * 1024 * 1024):
        raise FinalizationCompletionSubjectError("additional retained history bytes exceed the fixed allowance")
    parent_reservation = _parent_representation_bytes_on_owner(owner, work=work, current=current)
    # All six enrollment originals come from the already admitted cold owner,
    # before any journal body. They cannot be replaced by historical records.
    evidence_common = dict(common,
        authorization_enrollment_bytes=material.execution.authorization_enrollment_bytes,
        grant_enrollment_bytes=material.execution.grant_enrollment_bytes,
        current_root_enrollment_bytes=material.execution.current_root_enrollment_bytes)
    enrollments = tuple(scope[name] for scope in (common, evidence_common) for name in (
        "authorization_enrollment_bytes", "grant_enrollment_bytes", "current_root_enrollment_bytes"))
    enrollment_limits = (history.caller.MAX_ENROLLMENT_BYTES, history.grants.MAX_ENROLLMENT_BYTES,
        history.authorization.MAX_ENROLLMENT_BYTES, evidence_history.authorization.MAX_ENROLLMENT_BYTES,
        evidence_history.grants.MAX_ENROLLMENT_BYTES, evidence_history.current_root.MAX_ENROLLMENT_BYTES)
    if any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
            for raw, maximum in zip(enrollments, enrollment_limits)):
        raise FinalizationCompletionSubjectError("historical enrollment originals exceed their independent bounds")
    base_reservation = (_additional_original_bytes + parent_reservation
        + 8 * archive_bytes + _REPLAY_HEADROOM_BYTES + 4 * sum(map(len, enrollments))
        + _RESPONSE_REPRESENTATIONS_BYTES + _HISTORY_METADATA_BYTES)
    remaining = completion.MAX_ORIGINAL_BYTES - base_reservation
    # The combined reader charges/reserves three encoded-body footprints plus
    # 16 KiB before body1. Tightening its allowance to 3/8 leaves five additional
    # selected-byte footprints for original replay, capture and canonical work.
    maximum_history = 3 * (remaining // _HISTORY_REPRESENTATIONS)
    if maximum_history <= 16 * 1024:
        raise FinalizationCompletionSubjectError("held originals leave no bounded historical replay capacity")
    current()
    combined = custody_client.ControlPlaneCustodyClient.load_registration_finalization_completion_history(
        custody, digest, maximum_original_bytes=maximum_history, work=work, current=current)
    current()
    if type(combined) is not tuple or len(combined) != 4:
        raise FinalizationCompletionSubjectError("combined finalization history inventory differs")
    association, reserved_record, observed, prior = combined
    final_record, evidence_digest, evidence_record, signer_record = _association_on_work(association, digest, work)
    held = reservation_wire._originals(final_record.originals, response=False)
    evidence_originals = subjects.reservation_wire._originals(evidence_record.originals, response=False)
    signer = subjects.signer_wire._request_originals(signer_record.originals)
    if (type(reserved_record) is not reservation_records.FinalizationReservationRecord
            or reserved_record.finalization_digest != digest
            or reserved_record.source_revision != final_record.source_revision
            or type(observed) is not outcome_records.FinalizationOutcomes
            or observed.finalization_digest != digest or observed.source_revision != final_record.source_revision
            or observed.sql_attempt is None
            or type(prior) is not resolved_history.registration.outcomes.RegistrationOutcomes
            or prior.local_digest != evidence_digest or prior.source_revision != final_record.source_revision
            or prior.reservation is None or prior.sql_attempt is None):
        raise FinalizationCompletionSubjectError("finalization completion lacks its original reservation or SQL claim")
    reserved = reservation_wire._originals(reserved_record.originals, response=True)
    prior_completed = prior.completion_reconciled or prior.completion_outcome
    if prior_completed is None:
        raise FinalizationCompletionSubjectError("finalization completion lacks associated evidence completion")
    evidence_returned = handoff.completion_wire._originals(prior_completed.originals, response=True)
    evidence_reserved = subjects.reservation_wire._originals(prior.reservation.originals, response=True)
    if evidence_returned[0] != b"acknowledged":
        raise FinalizationCompletionSubjectError("uncertain evidence completion cannot establish finalization ownership")
    retained_outcomes = (prior.sql_outcome, prior.completion_outcome, prior.completion_reconciled,
        observed.sql_outcome, observed.completion_outcome, observed.completion_reconciled)
    retained_originals = (*held, *evidence_originals, *signer, *reserved, *evidence_reserved,
        *(raw for record in retained_outcomes if record is not None for raw in record.originals))
    selected_bytes = sum(map(len, retained_originals))
    original_reservation_bytes = base_reservation + _HISTORY_REPRESENTATIONS * selected_bytes
    if original_reservation_bytes > completion.MAX_ORIGINAL_BYTES:
        raise FinalizationCompletionSubjectError("finalization completion retained inventory exceeds its aggregate bound")
    final_snapshot = registration_snapshot = None
    final_scope, registration_scope = configured, material.execution
    if configured.context_directory is not None:
        from serverware import authority_local_registration_context as contexts
        final_scope = contexts._selected_scope(owner, "finalization", digest)
        selected_context = owner._registration_contexts[("finalization", digest, "execute")][1]
        window, bound = contexts._narrow(selected_context, window, bound)
    if material.execution.context_directory is not None:
        from serverware import authority_local_registration_context as contexts
        registration_scope = contexts._selected_scope(owner, "execution", evidence_digest)
        selected_context = owner._registration_contexts[("execution", evidence_digest, "execute")][1]
        window, bound = contexts._narrow(selected_context, window, bound)
    if material.finalization_history is not None:
        common, final_scope, final_snapshot = resolved_history._select_finalization_on_owner(owner, held,
            window=window, bound=bound, work=work, current=current)
    if material.registration_history is not None:
        # This second selection authenticates the registration originals, not
        # the finalization's claims about its earlier evidence association.
        evidence_common, registration_scope, registration_snapshot = (
            resolved_history.registration._select_on_work(material.registration_history, evidence_originals,
                window=window, bound=bound, work=work, current=current))
    enrollments = tuple(scope[name] for scope in (common, evidence_common) for name in (
        "authorization_enrollment_bytes", "grant_enrollment_bytes", "current_root_enrollment_bytes"))
    if any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
            for raw, maximum in zip(enrollments, enrollment_limits)):
        raise FinalizationCompletionSubjectError("selected historical enrollments exceed their original bounds")
    original_bytes = (parent_reservation // _PARENT_REPRESENTATIONS + archive_bytes
        + selected_bytes + sum(map(len, enrollments)))
    if original_bytes + _additional_original_bytes > completion.MAX_ORIGINAL_BYTES:
        raise FinalizationCompletionSubjectError("selected historical original inventory exceeds its ceiling")
    pending = final_scope.current_pending
    packet = final_scope.completion_packet_digest
    authorization_digest = final_scope.completion_authorization_digest
    current()
    exchanged = history._verify_on_configuration(**common, originals=held,
        live_window=window, work=work, transport_deadline_ns=bound)
    evidence.plan._same(exchanged.authorization_digest, authorization_digest, work,
        "finalization completion authorization differs from the independent cold pin")
    current()
    config = {name: evidence_common[name] for name in (
        "payload", "configuration_digest", "generation", "runtime_role_identities")}
    subject, regenerated, inputs = signer_history._verify_finalization_on_configuration(**config,
        request_originals=signer[:8], response_originals=signer[8:],
        sibling_challenge_ids=exchanged.request["arguments"]["sibling_challenge_ids"],
        live_window=window, work=work, transport_deadline_ns=bound)
    evidence.plan._same(regenerated, exchanged.request, work,
        "historical finalization differs from its associated signer's complete request")
    work.charge(input_bytes=len(inputs) + len(exchanged.inputs_bytes))
    if inputs != exchanged.inputs_bytes:
        raise FinalizationCompletionSubjectError("historical finalization inputs differ from the actual signer replay")
    prior_exchange = evidence_history._verify_on_configuration(**evidence_common,
        originals=evidence_originals, live_window=window, work=work, transport_deadline_ns=bound)
    evidence.plan._same((subject["requestDigest"], subject["operationId"]),
        (prior_exchange.request_digest, prior_exchange.operation_id), work,
        "historical evidence exchange differs from the associated signer request")
    current()
    prior_pending = registration_scope.current_pending
    evidence_completion._verify_on_configuration(**evidence_common,
        originals=evidence_originals, reservation_originals=evidence_reserved,
        response_originals=evidence_returned, expected_pending_sequence=prior_pending[0],
        expected_pending_head_digest=prior_pending[1], expected_fence=prior_pending[2],
        live_window=window, work=work, transport_deadline_ns=bound)
    current()
    sequence, head, fence = pending
    candidate = completion.pending._admit_for_completion_on_work(operation=completion.OPERATION,
        originals=exchanged.raw4, expectations=exchanged.expectations,
        planner_public_key=exchanged.planner_public_key, operation_public_key=exchanged.operation_public_key,
        enrollment_bytes=common["current_root_enrollment_bytes"], root_public_key=common["root_public_key"],
        reserve_request_bytes=reserved[0], reserve_receipt_bytes=reserved[2], snapshot_bytes=reserved[1],
        expected_database_id=exchanged.database_id, expected_generation_digest=exchanged.generation_digest,
        expected_pending_sequence=sequence, expected_pending_head_digest=head, expected_fence=fence,
        live_window=window, work=work, transport_deadline_ns=bound)
    completion.completion._verify_grant_on_work(candidate=candidate, grant_raw=held[9],
        grant_enrollment=common["grant_enrollment_bytes"], enrollment=common["current_root_enrollment_bytes"],
        root_public_key=common["root_public_key"], planner_public_key=exchanged.planner_public_key,
        operation_public_key=exchanged.operation_public_key,
        authorization_digest=authorization_digest, work=work)
    resolved_history._authenticated_intervals(final_snapshot,
        (held[0], held[1], held[2], held[9]), work=work, current=current)
    # The signer must genuinely share the independently selected registration
    # configuration/keys/identities and original interval. No assumed finalization
    # cohort or unverified successful signer object supplies those bindings.
    resolved_history._authenticated_intervals(registration_snapshot,
        (evidence_originals[0], evidence_originals[9], signer[0], signer[2], signer[4], signer[8]),
        work=work, current=current)
    current()
    arguments, intent = regenerated["arguments"], regenerated["arguments"]["semantic_intent"]
    result = {"localDigest": digest, "userId": intent["userId"], "challengeId": intent["challengeId"],
        "sessionId": arguments["oidc_session_id"], "mode": intent["authorizationMode"],
        "requestDigest": regenerated["requestDigest"], "operationId": regenerated["operationId"],
        "credentialId": arguments["credential"]["credential_id"]}
    evidence.plan._same((result["userId"], result["challengeId"], result["sessionId"], result["mode"]),
        (subject["userId"], subject["challengeId"], subject["sessionId"], subject["mode"]), work,
        "historical finalization subject differs from its genuine associated signer")
    current()
    return resolved_history._result_on_work(subject=result, originals=held,
        reservation_originals=reserved, observed=observed, common=common, evidence_common=evidence_common,
        endpoint=endpoint, current_pending=pending, completion_packet_digest=packet,
        completion_authorization_digest=authorization_digest, window=window, deadline_ns=bound,
        original_bytes=original_bytes, original_reservation_bytes=original_reservation_bytes,
        continuity=current, work=work, retained_originals=(*retained_originals, *enrollments))


def _inspect_on_owner(owner, local_digest, *, live_window, transport_deadline_ns, work,
        _additional_original_bytes=0):
    """Compatibility projection; new consumers retain explicit historical pins."""
    result = _inspect_material_on_owner(owner, local_digest, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work,
        _additional_original_bytes=_additional_original_bytes)
    return (result.subject, result.originals, result.reservation_originals, result.observed,
        result.common, result.endpoint, result.window, result.deadline_ns, result.current, result.original_bytes)


def inspect_retained_finalization_completion_subject(local_digest):
    """Return genuine eight-field ownership data, not present action permission.

    The credential ID comes from the complete signer-regenerated request, not
    a posted selector. It permits the public pending branch to distinguish the
    exact post-SQL credential from unrelated, replaced or revoked history.
    """
    from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

    digest = journal._digest(local_digest)
    work = _ValidationWork(QueryReadValidationLimits())
    owner, material, binding, window = _open_on_work(work)
    startup._require_pid()
    with startup._LOCK:
        if owner._material is not material or owner._binding is not binding:
            raise FinalizationCompletionSubjectError("finalization completion startup changed before inspection")
        result = _inspect_material_on_owner(owner, digest, live_window=window,
            transport_deadline_ns=window[4], work=work)
        result.current()
    # The same real owner/archive guard remains valid after normal lock exit;
    # there is no closed actor fallback or new processing window here.
    result.current()
    return result.subject
