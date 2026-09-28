"""Historical pre-intent target and possession, never completion authority.

The retained raw5 is ordinary data until both historical caller and planner
signatures join independently admitted cold originals and genuine finalization
ownership. No intent, delivery dates, SQL outcome or live permission is invented.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping
from serverware import authority_registration_finalization_completion_history as completed
from serverware import control_plane_oidc_session_activation_completion_recovery_selection as selection
from serverware import control_plane_oidc_session_activation_planning as planning
from serverware import control_plane_oidc_session_activation_records as records
from serverware import control_plane_registration_activation_subject as subjects
from serverware import control_plane_registration_finalization_completion_subject as finalization
from serverware import control_plane_oidc_session_activation_history as historical


execution, configured = planning.execution, planning.configured
caller, planner, assertion = planning.caller, planning.planner, planning.assertion
authorization, shape, plan = caller.authorization, caller.shape, caller.plan
capture, production, clock = caller.capture, caller.production, caller.clock
MAX_ORIGINAL_BYTES = caller.grants.replay.MAX_ORIGINAL_BYTES
_METADATA_RESERVATION = 16 * 1024


class CompletionRecoveryHistoryError(ValueError):
    pass


def _fail(message):
    raise CompletionRecoveryHistoryError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CompletionRecoveryTarget:
    """Ordinary same-call facts; no API accepts this instead of originals."""

    subject: dict
    activation_authorization_digest: str
    old_token_digest: str
    new_token_digest: str
    credential_record_id: str
    challenge_id: str
    live_window: tuple
    deadline_ns: int
    live: object
    original_bytes: int
    original_reservation_bytes: int
    authority: object


def _inspect_on_owner(owner, *, local_digest, old_token_bytes, live_window,
        transport_deadline_ns, work, current, _additional_original_bytes=0):
    """Re-admit the actual pre-intent target on one unchanged owner allowance.

    Additional bytes only tighten the shared bound. The returned reservation
    includes them and the parent reserve; a later owner must not count either
    twice. It is source-defined representation accounting, not heap authority.
    """
    capture._SharedLedger(work)
    if (type(owner) is not execution.startup._EnrollmentOwner or not callable(current)
            or type(_additional_original_bytes) is not int
            or not 0 <= _additional_original_bytes < MAX_ORIGINAL_BYTES
            or MAX_ORIGINAL_BYTES != 64 * 1024 * 1024):
        _fail("completion recovery requires its actual owner and tightened original allowance")
    parent, binding, custody = owner._material, owner._binding, owner._custody
    if parent is None or binding is None or custody is None:
        _fail("completion recovery has no admitted cold owner")
    digest = finalization.journal._digest(local_digest)
    old = assertion._token(old_token_bytes, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    window, bound, archive_current, _archive_original_bytes = historical._lifetime_on_owner(owner,
        window=window, bound=bound, work=work, current=current)
    cold_original_bytes, cold_capture = historical._capture_reservation_on_owner(owner)
    cold_reservation = cold_capture + 8 * (len(old) + 4 * 32) + _METADATA_RESERVATION
    parent_reservation = finalization._parent_representation_bytes_on_owner(
        owner, work=work, current=current)
    held_reservation = _additional_original_bytes + parent_reservation + cold_reservation
    if held_reservation >= MAX_ORIGINAL_BYTES:
        _fail("completion recovery cold representations exhaust the original bound")
    pid, thread = os.getpid(), threading.get_ident()
    history_current = None
    parent_configuration = parent.configuration_digest
    cold_lanes = parent.activation_planning, parent.activation_execution, parent.activation_history

    def identity():
        if (os.getpid() != pid or threading.get_ident() != thread
                or execution.startup._owner is not owner
                or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or parent.configuration_digest != parent_configuration
                or any(actual is not held for actual, held in zip((parent.activation_planning,
                    parent.activation_execution, parent.activation_history), cold_lanes))):
            _fail("completion recovery original owner or keys changed")

    def ancestor(epoch_floor, monotonic_floor):
        identity()
        observed = current()
        if type(observed) is not int or observed < epoch_floor:
            _fail("completion recovery ancestor lowered the current epoch")
        archive_current()
        if history_current is not None:
            history_current()
        now = current()
        sampled = production._callback(work, time.monotonic_ns)
        if (type(now) is not int or now < observed or type(sampled) is not int
                or sampled < monotonic_floor):
            _fail("completion recovery ancestor clocks reversed")
        identity()
        return now, sampled

    lifetime = bookkeeping._Lifetime(window, bound, work, ancestor)
    lifetime.current()

    # Existing combined finalization loader reserves all selected bodies and
    # replay captures before reading. It already owns the parent reservation.
    inspected = finalization._inspect_material_on_owner(owner, digest, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work,
        _additional_original_bytes=_additional_original_bytes + cold_reservation)
    subject, held, reserved, observed, common = (inspected.subject, inspected.originals,
        inspected.reservation_originals, inspected.observed, inspected.common)
    finalization_original_bytes = inspected.original_bytes
    lifetime.adopt(inspected.window, inspected.deadline_ns)
    history_current = inspected.current
    lifetime.current()
    if (type(subject) is not dict or set(subject) != subjects._SUBJECT_FIELDS
            or subject["localDigest"] != digest or subject["mode"] != "oidc-session-first-enrollment"):
        _fail("completion recovery requires genuine finalization target ownership")
    record, kind = observed.completion_reconciled, "completion-reconciled"
    if record is None:
        record, kind = observed.completion_outcome, "completion-outcome"
    if (type(record) is not subjects.records.FinalizationOutcomeRecord
            or record.finalization_digest != digest or record.kind != kind
            or record.source_revision != observed.source_revision):
        _fail("completion recovery lacks associated finalization completion originals")
    returned = subjects.wire._originals(record.originals, response=True)
    if returned[0] != b"acknowledged":
        _fail("completion recovery cannot infer finalization from an uncertain result")
    if finalization_original_bytes + _additional_original_bytes + cold_original_bytes > MAX_ORIGINAL_BYTES:
        _fail("completion recovery finalization originals exceed the original aggregate")
    pending = inspected.current_pending
    completed._verify_on_configuration(**common, originals=held, reservation_originals=reserved,
        response_originals=returned, expected_pending_sequence=pending[0],
        expected_pending_head_digest=pending[1], expected_fence=pending[2],
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work)
    lifetime.current()
    subject = capture._JSONCapture(capture._SharedLedger(work), maximum_bytes=caller.MAX_AUTHORIZATION_BYTES).visit(subject)
    subject_pin = tuple(sorted(subject.items()))
    # Preserve the actual archive authorization and original clock without
    # accidentally retaining the complete finalization replay result while the
    # next bounded activation preparation is read. No proof token is exported.
    history_current = inspected.continuity
    del inspected, held, reserved, observed, common, record, returned
    lifetime.current()

    # The selector preflights 3*encoded pair + metadata before body1. Tighten
    # its remaining allowance to 3/8, retaining five additional footprints for
    # canonical expectations, vector/request capture and genuine signature work.
    remaining = MAX_ORIGINAL_BYTES - held_reservation
    selected_allowance = 3 * (remaining // 8)
    if selected_allowance <= _METADATA_RESERVATION:
        _fail("completion recovery has no bounded prepared-original capacity")
    selected = selection._select_on_owner(owner, local_digest=digest,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        current=lifetime.base, _additional_original_bytes=MAX_ORIGINAL_BYTES - selected_allowance)
    lifetime.current()
    if (type(selected) is not tuple or len(selected) != 2
            or type(selected[0]) is not records.attempts.ActivationDispatchAttemptRecord
            or type(selected[1]) is not records.ActivationRecord):
        _fail("completion recovery has no exact retained activation claim and preparation")
    claim, prepared = selected
    if (claim.finalization_digest != digest or prepared.finalization_digest != digest
            or prepared.kind != "prepared" or prepared.source_revision != claim.source_revision
            or prepared.source_revision != caller.grants.authority.SOURCE_REVISION):
        _fail("completion recovery prepared association differs from the source cohort")
    raw = records._originals(records.KINDS.index("prepared"), prepared.originals)
    encoded_bound = (records.attempts.MAX_RECORD_BYTES + records._MAX_HEADER_BYTES
        + 8 * len(raw) + sum(map(len, raw)))
    reservation_bytes = held_reservation + 8 * encoded_bound
    original_bytes = cold_original_bytes + sum(map(len, raw))
    if reservation_bytes > MAX_ORIGINAL_BYTES or original_bytes + _additional_original_bytes > MAX_ORIGINAL_BYTES:
        _fail("completion recovery selected originals exceed retained replay capacity")
    # No current planner/key admission precedes this bounded read. Original
    # caller and planner signatures select only an independently cold-admitted
    # historical scope; the actual historical bootstrap is then replayed below.
    selected_scope = historical._prepared_scope_on_owner(owner, originals=raw,
        window=lifetime.window, bound=lifetime.bound, work=work, current=lifetime.base)
    policy, caller_policy = selected_scope.activation_planning, selected_scope.activation_execution
    if (type(policy) is not configured._PlanningMaterial
            or type(caller_policy) is not configured.execution._ActivationExecutionMaterial):
        _fail("completion recovery requires independently selected activation originals")
    bootstrap = authorization._original(policy.planner_bootstrap_bytes, planner.MAX_BYTES,
        "selected historical planner bootstrap")
    enrollment_originals = tuple(authorization._original(value, cap, label) for value, cap, label in (
        (caller_policy.authorization_enrollment_bytes, caller.MAX_ENROLLMENT_BYTES, "historical caller enrollment"),
        (caller_policy.current_root_enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES, "historical state enrollment"),
        (caller_policy.grant_enrollment_bytes, caller.grants.MAX_ENROLLMENT_BYTES, "historical grant enrollment")))
    root, planner_key, operation_key, caller_key = (selected_scope.root_public_key,
        caller_policy.planner_public_key, caller_policy.operation_public_key, caller_policy.caller_public_key)
    configuration_pin = selected_scope.configuration_digest
    selected_scope.live()
    material = planner._verify_historical_on_work(bootstrap_bytes=bootstrap, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if type(material) is not planner._PlannerMaterial:
        _fail("completion recovery lacks genuine historical planner admission")
    for actual, expected, label in (
            (material.configuration_payload, selected_scope.configuration_payload, "configuration"),
            (material.generation, selected_scope.generation, "generation"),
            (material.runtime_role_identities, selected_scope.runtime_role_identities, "runtime cohort")):
        configured._same_configuration(actual, expected, work,
            "completion recovery planner differs from independently selected " + label)
    plan._same(material.configuration_digest, configuration_pin, work, "completion recovery configuration")
    plan._same(material.planner_spki_digest, caller.keys._spki_on_work(planner_key, work), work,
        "completion recovery independently enrolled planner")
    plan._same(caller.keys._spki_on_work(operation_key, work), caller.keys._spki_on_work(root, work), work,
        "completion recovery operation key is the selected root")
    bookkeeping._same_bytes(material.state_enrollment_bytes, enrollment_originals[1], work,
        "completion recovery independent state enrollment")
    enrolled = caller._admit_enrollment_on_work(authorization_enrollment_bytes=enrollment_originals[0],
        current_root_enrollment_bytes=enrollment_originals[1], grant_enrollment_bytes=enrollment_originals[2],
        root_public_key=root, configuration_digest=configuration_pin,
        planner_public_key=planner_key, operation_public_key=operation_key, work=work)
    plan._same(enrolled.enrollment_digest, caller_policy.authorization_enrollment_digest, work,
        "completion recovery actual caller enrollment")
    plan._same(caller.keys._spki_on_work(enrolled.caller_public_key, work),
        caller.keys._spki_on_work(caller_key, work), work, "completion recovery actual caller key")
    plan._same(enrolled.payload["generationDigest"], selected_scope.generation["digest"], work,
        "completion recovery selected caller generation")
    lifetime.narrow(lifetime.window[3], min(material.maximum_plan_age_ns,
        enrolled.payload["maximumAgeNs"]), min(material.maximum_clock_skew_ns,
        enrolled.payload["maximumClockSkewNs"]))
    selected_scope.live()
    expectations = caller.expectations_wire._capture_on_work(
        planning._object(raw[3], caller.expectations_wire.MAX_BYTES, work), work=work)
    arguments = caller.expectations_wire.plan.transition._arguments(expectations["request"]["arguments"], work)
    original_deadline = expectations["scope"]["deadlineEpochNs"]
    shape._integer(original_deadline, minimum=1)
    if original_deadline > material.attestation_interval[1]:
        _fail("completion recovery original scope exceeds its independent historical planner interval")
    expected_scope = {"userId": subject["userId"], "sessionId": subject["sessionId"],
        "credentialId": subject["credentialId"], "credentialRecordId": arguments["credential_record_id"],
        "challengeId": arguments["challenge_id"], "rpId": material.rp_id, "origin": material.origin,
        "authenticationPolicy": material.authn_policy, "trustPolicy": material.trust_policy,
        "configurationDigest": configuration_pin, "plannerIdentity": material.planner_identity,
        "plannerSpkiDigest": material.planner_spki_digest, "maximumPlanAgeNs": material.maximum_plan_age_ns,
        "maximumClockSkewNs": material.maximum_clock_skew_ns, "deadlineEpochNs": original_deadline}
    plan._same(expectations["scope"], expected_scope, work, "independent completion recovery planning scope")
    bookkeeping._same_bytes(raw[4], material.complete_root_vector_bytes, work,
        "completion recovery independent complete before vector")
    for field, expected in (("user_id", subject["userId"]), ("session_id", subject["sessionId"]),
            ("credential_id", subject["credentialId"]), ("delivery_ttl_seconds", material.delivery_ttl_seconds)):
        plan._same(arguments[field], expected, work, "completion recovery exact target " + field)
    if arguments["challenge_id"] == subject["challengeId"]:
        _fail("completion recovery activation challenge cannot be the registration challenge")
    # Candidate dynamic fields become historical facts only through the actual
    # signed typed-request commitment below; static policies came from root.
    authenticated = caller._verify_historical_on_work(authorization_bytes=raw[0],
        authorization_enrollment_bytes=enrollment_originals[0], current_root_enrollment_bytes=enrollment_originals[1],
        grant_enrollment_bytes=enrollment_originals[2], root_public_key=root,
        configuration_digest=configuration_pin, planner_public_key=planner_key, operation_public_key=operation_key,
        originals=raw[1:3], expectations=expectations, before_vector_bytes=raw[4],
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if type(authenticated) is not caller._HistoricalAuthorization:
        _fail("completion recovery requires genuine historical caller admission")
    lifetime.attach(authenticated.live)
    plan_payload, _plan_digest = caller.history._authenticate(raw[1], expectations["request"],
        expected_scope, planner_key, lifetime.base, work)
    if not (material.attestation_interval[0] <= plan_payload["issuedAtEpochNs"]
            < plan_payload["expiresAtEpochNs"] <= material.attestation_interval[1]):
        _fail("completion recovery signed plan escapes its original root planner interval")
    old_digest = assertion._digest(old, work)
    plan._same(old_digest, arguments["old_token_digest"], work, "completion recovery genuine old-token possession")
    del old
    plan._same(claim.authorization_enrollment_digest, enrolled.enrollment_digest, work,
        "completion recovery claim is only the exact enrollment association")
    target_scalars = (authenticated.authorization_digest, old_digest, arguments["new_token_digest"],
        arguments["credential_record_id"], arguments["challenge_id"])
    lifetime.current()
    result = None

    def live():
        identity()
        if (tuple(sorted(subject.items())) != subject_pin
                or result is not None and result.authority is not selected_scope):
            _fail("completion recovery genuine subject changed")
        selected_scope.live()
        lifetime.current()
        return selected_scope.live()

    live()
    result = _CompletionRecoveryTarget(subject, *target_scalars, lifetime.window,
        lifetime.bound, live, original_bytes, reservation_bytes, selected_scope)
    live()
    return result
