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
from serverware import control_plane_oidc_session_activation_recovery_selection as selection
from serverware import control_plane_registration_activation_subject as subjects
from serverware import control_plane_registration_finalization_completion_subject as finalization


authorization, shape, plan = intent.authorization, intent.shape, intent.plan
capture, production, clock = intent.capture, intent.production, intent.clock
MAX_ORIGINAL_BYTES = intent.contract.authority.MAX_RESULT_BYTES


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


def _inspect_on_owner(owner, *, local_digest, old_token_bytes, live_window,
        transport_deadline_ns, work, current):
    """Freshly join originals before recovery options or assertion admission."""
    capture._SharedLedger(work)
    if type(owner) is not startup._EnrollmentOwner or not callable(current):
        _fail("recovery history requires the actual owner and current guard")
    material, binding, custody = owner._material, owner._binding, owner._custody
    if material is None or binding is None or custody is None:
        _fail("recovery history has no actual cold configuration")
    policy = material.release_intent
    if type(policy) is not configured._ReleaseIntentMaterial:
        _fail("recovery history requires independently configured intent custody")
    root = binding.runtime_root_public_key
    enrollment, enrollment_digest = policy.enrollment_bytes, policy.enrollment_digest
    scope_original, public, forbidden = (
        policy.expected_scope_bytes, policy.caller_public_key, policy.forbidden_public_keys)
    authorization._public(root)
    authorization._public(public)
    digest = finalization.journal._digest(local_digest)
    # Hold the request-local token before callbacks. It is never part of the
    # returned subject, selected journal originals or lifetime closure.
    old_token = intent.delivery._token(old_token_bytes, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    pid, thread = os.getpid(), threading.get_ident()
    limits = work.limits
    ceilings = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
    metrics = work.metrics
    last_epoch, last_monotonic = window[0], window[2]
    history_current = None

    def identity():
        if (os.getpid() != pid or threading.get_ident() != thread
                or owner._material is not material or owner._binding is not binding
                or owner._custody is not custody or material.release_intent is not policy
                or binding.runtime_root_public_key is not root
                or policy.enrollment_bytes is not enrollment
                or policy.enrollment_digest != enrollment_digest
                or policy.expected_scope_bytes is not scope_original
                or policy.caller_public_key is not public or policy.forbidden_public_keys is not forbidden):
            _fail("recovery history actual cold ownership changed")

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
    # Complete existing finalization replay first. Its temporary retained
    # inventory is discarded before the separately selected intent is read;
    # no activation prepared ciphertext is loaded or opened.
    inspected = finalization._inspect_on_owner(owner, digest, live_window=window,
        transport_deadline_ns=bound, work=work)
    (subject, held, reserved, observed, common, _endpoint, selected_window,
        selected_bound, selected_current, original_bytes) = inspected
    candidate = clock._validate(selected_window)
    shape._integer(selected_bound, minimum=1)
    if (candidate[:3] != window[:3] or selected_bound > bound
            or any(actual > prior for actual, prior in zip(candidate[3:], window[3:]))):
        _fail("recovery finalization replay widened the original lifetime")
    if original_bytes + len(old_token) > MAX_ORIGINAL_BYTES:
        _fail("recovery finalization originals exceed the shared aggregate bound")
    window, bound, history_current = candidate, min(selected_bound, candidate[4]), selected_current
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
    pending = material.finalization.current_pending
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
    del inspected, held, reserved, observed, common, record, returned

    selected = selection._select_on_owner(owner, local_digest=digest, live_window=window,
        transport_deadline_ns=bound, work=work, current=base_current)
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
    scope = configured._scope_on_work(scope_original, work)
    for name, expected in (("configurationDigest", binding.configuration_digest),
            ("generationDigest", material.generation["digest"])):
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
    candidate = clock._validate(target.live_window)
    if (candidate[:3] != window[:3] or target.deadline_ns > bound
            or any(actual > prior for actual, prior in zip(candidate[3:], window[3:]))):
        _fail("recovery target replaced the original processing lifetime")
    window, bound = candidate, min(target.deadline_ns, candidate[4])

    def live():
        if (type(subject) is not dict or set(subject) != set(subject_fields)
                or tuple(subject[name] for name in subject_fields) != subject_values):
            _fail("recovery historical subject changed after original admission")
        # target.live retains continuity, the exact cold resources, genuine
        # finalization guard and narrowed clocks; do not add a child cycle.
        return target.live()

    live()
    return _RecoveryTarget(subject, association, raw, target.intent_digest,
        target.delivery_scope, target.old_token_digest, window, bound, live)
