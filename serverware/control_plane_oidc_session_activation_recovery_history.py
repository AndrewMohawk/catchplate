"""Fresh local historical target inspection, never recovery permission.

Only the actual cold owner and retained originals enter this composition.
Finalization and its ACK are genuinely replayed; a separately enrolled intent
then authenticates the same target and old-token possession. No private AES,
activation prepared bundle, SQL retry, new intent or token release is involved.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from serverware import authority_oidc_session_activation_release_intent as intent
from serverware import authority_registration_finalization_completion_history as completed
from serverware import control_plane_enrollment_startup as startup
from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as configured
from serverware import control_plane_oidc_session_activation_history as historical
from serverware import control_plane_oidc_session_activation_consume_records as retained
from serverware import control_plane_oidc_session_activation_dispatch_attempt as attempts
from serverware import control_plane_oidc_session_activation_recovery_selection as selection
from serverware import control_plane_registration_activation_subject as subjects
from serverware import control_plane_registration_finalization_completion_subject as finalization


authorization, shape, plan = intent.authorization, intent.shape, intent.plan
capture, production, clock = intent.capture, intent.production, intent.clock
MAX_ORIGINAL_BYTES = intent.contract.authority.MAX_RESULT_BYTES
_METADATA_RESERVATION_BYTES = 16 * 1024
_TARGET_REPRESENTATION_BYTES = (4 * intent.MAX_BYTES + _METADATA_RESERVATION_BYTES
    + 8 * (attempts.MAX_RECORD_BYTES + retained.MAX_CLAIM_BYTES + retained._MAX_HEADER_BYTES + 8))


class OidcSessionActivationRecoveryHistoryError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationRecoveryHistoryError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _RecoveryTarget:
    """Same-call target data, never accepted as authority by another call.

    The authorization digest is only the unique retained association locator;
    this inspector does not authenticate activation execution or its outcome.
    No old-token original is returned or captured by the retained guard.
    """

    subject: dict
    activation_authorization_digest: str
    intent_bytes: bytes
    intent_digest: str
    delivery_scope: dict
    old_token_digest: str
    live_window: tuple
    deadline_ns: int
    live: object
    original_bytes: int
    original_reservation_bytes: int


def _inspect_on_owner(owner, *, local_digest, old_token_bytes, live_window,
        transport_deadline_ns, work, current, _additional_original_bytes=0):
    """Freshly join originals before recovery options or assertion admission.

    The returned reservation includes the caller's additional bytes and actual
    parent once. A later owner must not add those representations a second time.
    """
    capture._SharedLedger(work)
    if type(owner) is not startup._EnrollmentOwner or not callable(current):
        _fail("recovery history requires the actual owner and current guard")
    if (type(_additional_original_bytes) is not int
            or not 0 <= _additional_original_bytes < MAX_ORIGINAL_BYTES):
        _fail("recovery history held capacity can only tighten the original bound")
    material, binding, custody = owner._material, owner._binding, owner._custody
    if material is None or binding is None or custody is None:
        _fail("recovery history has no actual cold configuration")
    current_policy, current_root = material.release_intent, binding.runtime_root_public_key
    archive_material = material.activation_history
    selected_scope = policy = root = enrollment = enrollment_digest = None
    scope_original = public = forbidden = None
    digest = finalization.journal._digest(local_digest)
    # Hold the request-local token before callbacks. It is never part of the
    # returned subject, selected journal originals or lifetime closure.
    old_token = intent.delivery._token(old_token_bytes, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    window, bound, archive_current, _archive_bytes = historical._lifetime_on_owner(owner,
        window=window, bound=bound, work=work, current=current)
    archive_current()
    cold_original_bytes, cold_reservation = historical._capture_reservation_on_owner(owner)
    archive_current()
    held_history_bytes = (_additional_original_bytes + cold_reservation
        + _TARGET_REPRESENTATION_BYTES + 8 * (len(old_token)
            + 32 * (2 + intent.enrollments.MAX_FORBIDDEN_PUBLIC_KEYS)))
    if held_history_bytes >= MAX_ORIGINAL_BYTES:
        _fail("recovery history held originals exhaust finalization capacity")
    pid, thread = os.getpid(), threading.get_ident()
    limits = work.limits
    ceilings = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
    metrics = work.metrics
    last_epoch, last_monotonic = window[0], window[2]
    history_current = None

    def identity():
        if (os.getpid() != pid or threading.get_ident() != thread
                or owner._material is not material or owner._binding is not binding
                or owner._custody is not custody or material.release_intent is not current_policy
                or binding.runtime_root_public_key is not current_root
                or material.activation_history is not archive_material):
            _fail("recovery history actual cold ownership changed")
        if selected_scope is not None and (
                selected_scope.release_intent is not policy or selected_scope.root_public_key is not root
                or policy.enrollment_bytes is not enrollment or policy.enrollment_digest != enrollment_digest
                or policy.expected_scope_bytes is not scope_original
                or policy.caller_public_key is not public or policy.forbidden_public_keys is not forbidden):
            _fail("recovery history selected original intent authority changed")

    def continuity(epoch_floor, monotonic_floor):
        nonlocal last_epoch, last_monotonic, metrics
        shape._integer(epoch_floor, minimum=1)
        shape._integer(monotonic_floor, minimum=1)
        last_epoch = max(last_epoch, epoch_floor)
        last_monotonic = max(last_monotonic, monotonic_floor)
        identity()
        # The supplied original guard is upstream only. It never re-enters
        # this inspector or the child intent guard returned below.
        first = current()
        shape._integer(first, minimum=1)
        archive_current()
        if history_current is not None:
            history_current()
        observed = current()
        shape._integer(observed, minimum=1)
        now = clock._check_on_work(window, work=work)
        mono = production._callback(work, time.monotonic_ns)
        shape._integer(mono, minimum=1)
        if (first < last_epoch or observed < first or now < observed
                or mono < last_monotonic or mono >= bound):
            _fail("recovery history original clocks expired or reversed")
        after = work.metrics
        if (work.limits is not limits
                or ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or after.hash_work < metrics.hash_work or after.input_bytes < metrics.input_bytes
                or after.json_nodes < metrics.json_nodes):
            _fail("recovery history reset its original work allowance")
        metrics = after
        last_epoch, last_monotonic = now, mono
        identity()
        return now, mono

    def base_current():
        return continuity(last_epoch, last_monotonic)[0]

    base_current()
    parent_reservation = finalization._parent_representation_bytes_on_owner(
        owner, work=work, current=base_current)
    held_reservation = held_history_bytes + parent_reservation
    if held_reservation >= MAX_ORIGINAL_BYTES:
        _fail("recovery history cold representations exceed the shared original bound")
    # Complete independently selected finalization replay first. Keep its full
    # result guard through ACK admission; only then release the replay inventory
    # before reading the separately selected intent. No ciphertext is opened.
    inspected = finalization._inspect_material_on_owner(owner, digest, live_window=window,
        transport_deadline_ns=bound, work=work,
        _additional_original_bytes=held_history_bytes)
    subject, held, reserved, observed, common = (inspected.subject, inspected.originals,
        inspected.reservation_originals, inspected.observed, inspected.common)
    selected_bound, original_bytes = inspected.deadline_ns, inspected.original_bytes
    candidate = clock._validate(inspected.window)
    shape._integer(selected_bound, minimum=1)
    if (candidate[:3] != window[:3] or selected_bound > bound
            or any(actual > prior for actual, prior in zip(candidate[3:], window[3:]))):
        _fail("recovery finalization replay widened the original lifetime")
    if original_bytes + held_history_bytes > MAX_ORIGINAL_BYTES:
        _fail("recovery finalization originals exceed the shared aggregate bound")
    window, bound, history_current = candidate, min(selected_bound, candidate[4]), inspected.current
    base_current()
    if type(subject) is not dict or set(subject) != subjects._SUBJECT_FIELDS:
        _fail("recovery finalization target differs from its exact source shape")
    plan._same((subject["localDigest"], subject["mode"]),
        (digest, "oidc-session-first-enrollment"), work,
        "recovery requires the genuinely retained OIDC finalization target")
    record = observed.completion_reconciled
    kind = "completion-reconciled"
    if record is None:
        record, kind = observed.completion_outcome, "completion-outcome"
    if (type(record) is not subjects.records.FinalizationOutcomeRecord
            or record.finalization_digest != digest or record.source_revision != observed.source_revision
            or record.kind != kind):
        _fail("recovery requires the associated original finalization completion")
    returned = subjects.wire._originals(record.originals, response=True)
    if returned[0] != b"acknowledged":
        _fail("recovery target cannot infer finalization success from uncertainty")
    pending = inspected.current_pending
    base_current()
    completed._verify_on_configuration(**common, originals=held,
        reservation_originals=reserved, response_originals=returned,
        expected_pending_sequence=pending[0], expected_pending_head_digest=pending[1],
        expected_fence=pending[2], live_window=window, transport_deadline_ns=bound, work=work)
    base_current()
    subject = capture._JSONCapture(capture._SharedLedger(work),
        maximum_bytes=intent.MAX_BYTES).visit(subject)
    subject_fields = tuple(sorted(subject))
    subject_values = tuple(subject[name] for name in subject_fields)
    # A bound `.current` method retains the full historical result. Replace it
    # only after genuine completion admission and scalar capture, with the cold
    # owner/archive-only guard; deleting aliases alone would not release bodies.
    history_current = inspected.continuity
    del inspected, held, reserved, observed, common, record, returned
    base_current()

    maximum_selected = 3 * ((MAX_ORIGINAL_BYTES - held_reservation) // 8)
    if maximum_selected <= _METADATA_RESERVATION_BYTES:
        _fail("recovery history has no remaining target-original capacity")
    selected = selection._select_on_owner(owner, local_digest=digest, live_window=window,
        transport_deadline_ns=bound, work=work, current=base_current,
        maximum_original_bytes=maximum_selected)
    base_current()
    if selected is None:
        _fail("recovery target has no retained release intent; prior-stage recovery is unavailable")
    if type(selected) is not tuple or len(selected) != 3:
        _fail("recovery selector lost its source-fixed original association")
    _activation_claim, consume_claim, intent_record = selected
    association = finalization.journal._digest(consume_claim.activation_authorization_digest)
    originals = intent_record.originals
    if type(originals) is not tuple or len(originals) != 1:
        _fail("recovery requires the exact retained intent original")
    raw = authorization._original(originals[0], intent.MAX_BYTES, "selected historical release intent")
    # The two claim records contain only the bounded public metadata already
    # reserved above; the selected original body is exactly this raw intent.
    selected_bytes = len(raw)
    original_bytes = cold_original_bytes + selected_bytes
    original_reservation_bytes = held_reservation + 8 * selected_bytes
    if not 0 < original_bytes <= original_reservation_bytes <= MAX_ORIGINAL_BYTES:
        _fail("recovery historical target representations exceed the shared bound")
    # Locators only select one independently admitted archived scope. The
    # resolver repeats original signature/scope/interval checks; no unknown
    # archived cohort silently falls back to the current intent configuration.
    selected_scope = historical._intent_scope_on_owner(owner, intent_bytes=raw,
        window=window, bound=bound, work=work, current=base_current)
    policy, root = selected_scope.release_intent, selected_scope.root_public_key
    if type(policy) is not configured._ReleaseIntentMaterial:
        _fail("recovery history requires independently admitted intent custody")
    enrollment, enrollment_digest = policy.enrollment_bytes, policy.enrollment_digest
    scope_original, public, forbidden = (
        policy.expected_scope_bytes, policy.caller_public_key, policy.forbidden_public_keys)
    authorization._public(root)
    authorization._public(public)
    selected_scope.live()
    scope = configured._scope_on_work(scope_original, work)
    for name, expected in (("configurationDigest", selected_scope.configuration_digest),
            ("generationDigest", selected_scope.generation["digest"])):
        plan._same(scope[name], expected, work, "recovery actual independent intent " + name)
    base_current()
    target = intent._inspect_historical_target_on_work(intent_bytes=raw,
        enrollment_bytes=enrollment, root_public_key=root, forbidden_public_keys=forbidden,
        expected_scope=scope, expected_target={name: subject[name]
            for name in ("userId", "sessionId", "credentialId")},
        expected_caller_public_key=public, expected_enrollment_digest=enrollment_digest,
        old_token_bytes=old_token, live_window=window, transport_deadline_ns=bound,
        work=work, _continuity=continuity)
    del old_token
    if type(target) is not intent._HistoricalIntentTarget:
        _fail("recovery target requires genuine same-call historical target admission")
    selected_scope.live()
    candidate = clock._validate(target.live_window)
    if (candidate[:3] != window[:3] or target.deadline_ns > bound
            or any(actual > prior for actual, prior in zip(candidate[3:], window[3:]))):
        _fail("recovery target replaced the original processing lifetime")
    window, bound = candidate, min(target.deadline_ns, candidate[4])

    result = None
    budget_pin = original_bytes, original_reservation_bytes

    def live():
        if (type(subject) is not dict or set(subject) != set(subject_fields)
                or tuple(subject[name] for name in subject_fields) != subject_values
                or result is not None and (result.original_bytes, result.original_reservation_bytes) != budget_pin):
            _fail("recovery historical subject changed after original admission")
        # Both children use the same ancestor; neither is inserted into that
        # ancestor. The selected scope remains live without a child cycle.
        selected_scope.live()
        target.live()
        return selected_scope.live()

    live()
    result = _RecoveryTarget(subject, association, raw, target.intent_digest,
        target.delivery_scope, target.old_token_digest, window, bound, live,
        original_bytes, original_reservation_bytes)
    live()
    return result
