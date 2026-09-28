"""One fresh-actor intent, or read-only admission of its retained original.

The existing consume-family slot is global to live and recovery callers. A
durable claim without an original cannot be resumed or replaced. This module
does not revive an activation permission, execute SQL, choose a release-store
checkpoint or open a token. Its private continuation stays inside this actor.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_release_intent as intent
from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping
from serverware import control_plane_oidc_session_activation_consume_records as records
from serverware import control_plane_oidc_session_activation_execution as execution
from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as configured
from serverware import control_plane_oidc_session_activation_release_proof_bootstrap as proof_configured
from serverware import control_plane_oidc_session_activation_release_proof_acquisition_bootstrap as setup_configured
from serverware import control_plane_oidc_session_activation_completion_recovery_intent_inputs as inputs_source


plan, production, state = intent.plan, intent.production, intent.authorization
MAX_ORIGINAL_BYTES = bookkeeping.MAX_ORIGINAL_BYTES
FUTURE_REPRESENTATION_BYTES = 8 * 1024 * 1024
INTENT_REPRESENTATION_BYTES = 16 * intent.MAX_BYTES + 64 * 1024
_INTENT_IO_BYTES = FUTURE_REPRESENTATION_BYTES - INTENT_REPRESENTATION_BYTES
_CONSTRUCTION = object()
_KINDS = ("release-intent-claimed", "release-intent", "release-proof-claimed",
    "release-proof-setup", "release-proof")


class CompletionRecoveryIntentError(ValueError):
    pass


def _fail(message):
    raise CompletionRecoveryIntentError(message)


def _additional_original_bytes(owner):
    """Read lengths of already-held public cold originals only, before body1.

    The root carries this exact additive reservation through actor/target and
    controls; it must not add it again at signing or proof receiving. No file,
    private-key export, clock, work allowance or authority is opened here.
    """
    if type(owner) is not execution.startup._EnrollmentOwner:
        _fail("release preparation requires the actual cold owner")
    parent = owner._material
    policy, proof, setup = parent.release_intent, parent.release_proof, parent.release_proof_acquisition
    if (type(policy) is not configured._ReleaseIntentMaterial
            or type(proof) is not proof_configured._ReleaseProofMaterial
            or setup is not None and type(setup) is not setup_configured._ReleaseProofAcquisitionMaterial):
        _fail("release preparation lacks its independent cold configuration")
    originals = (policy.enrollment_bytes, policy.expected_scope_bytes,
        proof.enrollment_bytes, proof.expected_scope_bytes)
    if any(type(raw) is not bytes or not 2 <= len(raw) <= configured.MAX_BYTES for raw in originals):
        _fail("release preparation cold originals exceed their source bounds")
    if setup is not None:
        template = setup.current_activation_planner_bytes
        maximum = (setup_configured.issuer.V1_MAX_BYTES if template is None
            else setup_configured.issuer.V2_MAX_BYTES)
        if type(setup.issuer_policy_bytes) is not bytes or not 2 <= len(setup.issuer_policy_bytes) <= maximum:
            _fail("release preparation original setup policy exceeds its versioned bound")
        originals += (setup.issuer_policy_bytes,)
        if template is not None:
            if (type(template) is not bytes
                    or not 2 <= len(template) <= setup_configured.issuer.bootstrap.release_bootstrap.planner_bootstrap.MAX_BYTES):
                _fail("release preparation current planner exceeds its original bound")
            # Count this separately held original as well as its wrapped copy
            # in the policy. The target carries the total forward only once.
            originals += (template,)
    reserved = (FUTURE_REPRESENTATION_BYTES + 8 * sum(map(len, originals))
        + 8 * execution.startup.MAX_PRIVATE_KEY_BYTES + 8 * 4 * 32)
    if reserved >= MAX_ORIGINAL_BYTES:
        _fail("release preparation cold representations leave no original capacity")
    return reserved


def _persistence(inputs, current, maximum):
    return {"finalization_digest": inputs.finalization_digest,
        "activation_authorization_digest": inputs.activation_authorization_digest,
        "completion_originals": inputs.response_originals,
        "reconciliation_digest": inputs.reconciliation_digest,
        "work": inputs.work, "current": current, "maximum_original_bytes": maximum}


def _record(value, kind, inputs):
    if value is None:
        return None
    if (type(value) is not records.ConsumeRecord or value.kind != kind
            or value.source_revision != state.authority.SOURCE_REVISION
            or value.finalization_digest != inputs.finalization_digest
            or value.activation_authorization_digest != inputs.activation_authorization_digest):
        _fail("release preparation retained record association differs")
    state.shape._digest(value.digest)
    return records._originals(records.KINDS.index(kind), value.originals)


def _read_records(inputs, current):
    current()
    held = execution.custody.ControlPlaneCustodyClient.load_oidc_session_activation_completion_recovery_release_records(
        inputs.actor._owner._custody, **_persistence(inputs, current, _INTENT_IO_BYTES))
    current()
    if type(held) is not tuple or len(held) != len(_KINDS):
        _fail("release preparation requires its exact bounded retained prefix")
    for value, kind in zip(held, _KINDS):
        _record(value, kind, inputs)
    if (held[1] is not None and held[0] is None
            or held[2] is not None and held[1] is None
            or any(value is not None for value in held[3:]) and held[2] is None):
        _fail("release preparation retained prefix lacks its irreversible predecessor")
    inputs_source._match_retained_release_records(inputs, held)
    current()
    return held


def _retained_interval(inputs):
    """Selected archived evidence only; never a fresh signing interval."""
    if type(inputs.retained_only) is not bool:
        _fail("release intent retained mode is not source-exact")
    interval = inputs.retained_authority_interval
    if not inputs.retained_only:
        if interval is not None:
            _fail("current release authority cannot borrow a retained interval")
        return None
    if inputs._purpose != "release-intent-proof":
        _fail("retired release authority permits preparation readmission only")
    if type(interval) is not tuple or len(interval) != 2:
        _fail("retained release authority lacks its independently selected interval")
    for value in interval:
        state.shape._integer(value, minimum=1)
    if interval[0] >= interval[1]:
        _fail("retained release authority interval is empty")
    return interval


def _contain_original_interval(inputs, payload):
    """Called only after genuine signature admission; does not retime evidence."""
    interval = _retained_interval(inputs)
    if interval is not None and not (interval[0] <= payload["issuedAtEpochNs"]
            < payload["expiresAtEpochNs"] <= interval[1]):
        _fail("retained release original exceeds its selected authority interval")


class _IntentContinuation:
    """Actual same-input call identity and original guard, never a public DTO."""

    __slots__ = ("_construction", "inputs", "intent_bytes", "intent_digest", "_interval",
        "_lifetime", "_records", "_key_identity", "_seal")

    def __init__(self, construction, inputs, original, admitted, lifetime, retained, key_identity):
        if construction is not _CONSTRUCTION:
            _fail("release intent continuation is privately constructed")
        self._construction, self.inputs = construction, inputs
        self.intent_bytes, self.intent_digest = original, admitted.intent_digest
        self._interval = admitted.payload["issuedAtEpochNs"], admitted.payload["expiresAtEpochNs"]
        self._lifetime, self._records, self._key_identity = lifetime, retained, key_identity
        self._seal = (inputs, original, self.intent_digest, self._interval, lifetime, retained, key_identity)

    @property
    def window(self):
        return self._lifetime.window

    @property
    def deadline_ns(self):
        return self._lifetime.bound

    def current(self):
        _identity(self)
        epoch = self._lifetime.current()
        _identity(self)
        return epoch


def _identity(value):
    if (type(value) is not _IntentContinuation or value._construction is not _CONSTRUCTION
            or type(value._seal) is not tuple or len(value._seal) != 7
            or any(actual is not expected for actual, expected in zip((value.inputs,
                value.intent_bytes, value.intent_digest, value._interval, value._lifetime,
                value._records, value._key_identity), value._seal))):
        _fail("release intent changed its actual private continuation")
    inputs_source._require_inputs(value.inputs)
    value._key_identity()


def _require_intent(value):
    _identity(value)
    value.current()
    return value


def _intent_on_inputs(inputs):
    """Preparation-only signing or historical re-admission."""
    inputs_source._require_inputs(inputs)
    if inputs._purpose != "release-intent-proof":
        _fail("intent preparation cannot borrow a release-purpose actor")
    return _intent_from_inputs(inputs)


def _readmit_on_inputs(inputs):
    """Existing original only; never sign or publish on a release-purpose call."""
    inputs_source._require_inputs(inputs)
    if inputs._purpose not in ("release", "retained-release"):
        _fail("intent readmission requires its separate fresh release actor")
    return _intent_from_inputs(inputs)


def _intent_from_inputs(inputs):
    inputs_source._require_inputs(inputs)
    if inputs._purpose == "release-intent-proof":
        from serverware import control_plane_oidc_session_activation_completion_recovery_release as owner_call
    elif inputs._purpose in ("release", "retained-release"):
        from serverware import control_plane_oidc_session_activation_completion_recovery_delivery as owner_call
    else:
        _fail("intent continuation has no actual source owner")

    owner_call._require_intent_call(inputs)
    _retained_interval(inputs)
    owner, work, policy = inputs.actor._owner, inputs.work, inputs.intent_policy
    root = inputs.root_public_key
    response_pin = owner._response_pin
    if (type(policy) is not configured._ReleaseIntentMaterial or response_pin is None
            or type(inputs.original_reservation_bytes) is not int
            or not FUTURE_REPRESENTATION_BYTES <= inputs.original_reservation_bytes <= MAX_ORIGINAL_BYTES):
        _fail("release intent lacks its actual cold scope or reserved inventory")

    def owner_identity():
        if inputs.actor._owner is not owner or owner._response_pin != response_pin:
            _fail("release intent original response owner changed")

    # Read-only re-admission needs the selected public originals and actor,
    # never possession of either a current or retired intent signing key.
    key_identity = owner_identity

    def ancestor(epoch, monotonic):
        key_identity()
        inputs.current()
        observed = inputs.continuity(epoch, monotonic)
        inputs.current()
        key_identity()
        return inputs.continuity(*observed)

    lifetime = bookkeeping._Lifetime(inputs.window, inputs.deadline_ns, work, ancestor)
    current = lifetime.current
    current()
    retained = _read_records(inputs, current)
    original = _record(retained[1], "release-intent", inputs)
    if original is None:
        if inputs.retained_only:
            _fail("retired release authority requires its exact retained intent; signing is forbidden")
        if inputs._purpose != "release-intent-proof":
            _fail("release requires an existing intent; it cannot sign or resume preparation")
        if retained[0] is not None:
            _fail("release intent claim is spent without an original; it cannot be resumed")
        if type(inputs.setup_policy) is not setup_configured._ReleaseProofAcquisitionMaterial:
            _fail("new release intent requires the independently configured proof setup")
        private, descriptor, descriptor_identity = owner._intent_key, owner._intent_key_fd, owner._intent_key_identity
        if (private is None or descriptor != configured.CALLER_KEY_FD
                or descriptor != policy.caller_private_key_fd or descriptor_identity is None):
            _fail("new release intent lacks its actual dedicated cold key")

        def signing_identity():
            owner_identity()
            if (owner._material.release_intent is not policy or owner._intent_key is not private
                    or owner._intent_key_fd != descriptor or owner._intent_key_identity is not descriptor_identity
                    or owner._binding.runtime_root_public_key is not root):
                _fail("new release intent original current key or authority changed")

        key_identity = signing_identity
        current()
        claim = execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_completion_recovery_release_intent_attempt(
            owner._custody, **_persistence(inputs, current, _INTENT_IO_BYTES))
        current()
        state.shape._digest(claim)
        # The global durable slot is spent before nonce generation or signing.
        enrolled = intent.enrollments._admit_on_work(enrollment_bytes=policy.enrollment_bytes,
            root_public_key=root, expected_scope=inputs.intent_scope,
            forbidden_public_keys=policy.forbidden_public_keys, work=work)
        current()
        actual_pin = intent.enrollments.keys._spki_on_work(enrolled.caller_public_key, work)
        current()
        plan._same(actual_pin, intent.enrollments.keys._spki_on_work(policy.caller_public_key, work),
            work, "release intent actual dedicated cold public key")
        if actual_pin == response_pin:
            _fail("release intent cannot reuse the actual HTTP signing key")
        current()
        original = intent._produce_on_work(enrollment_bytes=policy.enrollment_bytes,
            root_public_key=root, forbidden_public_keys=policy.forbidden_public_keys,
            expected_scope=inputs.intent_scope, expected_release=inputs.expected_release,
            old_token_bytes=inputs.old_token_bytes, caller_private_key=private,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
            _continuity=lifetime.continuity)
        current()
        published = execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_completion_recovery_release_intent(
            owner._custody, originals=(original,), **_persistence(inputs, current, _INTENT_IO_BYTES))
        current()
        state.shape._digest(published)
    else:
        original = original[0]
    # Existing signed intervals are historical evidence, not renewed time.
    # New proof contact separately requires the exact intent still be live.
    admitted = intent._verify_historical_on_work(intent_bytes=original,
        enrollment_bytes=policy.enrollment_bytes, root_public_key=root,
        forbidden_public_keys=policy.forbidden_public_keys, expected_scope=inputs.intent_scope,
        expected_release=inputs.expected_release, old_token_bytes=inputs.old_token_bytes,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if type(admitted) is not intent._HistoricalIntentEvidence:
        _fail("release intent lacks genuine historical original admission")
    _contain_original_interval(inputs, admitted.payload)
    current()
    lifetime.attach(admitted.live)
    result = _IntentContinuation(_CONSTRUCTION, inputs, original, admitted, lifetime, retained, key_identity)
    return _require_intent(result)


def _live_for_proof(value):
    """A fresh contact may not borrow expired historical intent authority."""
    _require_intent(value)
    inputs, lifetime = value.inputs, value._lifetime
    if inputs.retained_only:
        _fail("retired release authority cannot authorize a new proof contact")
    policy = inputs.intent_policy
    admitted = intent._verify_on_work(intent_bytes=value.intent_bytes,
        enrollment_bytes=policy.enrollment_bytes, root_public_key=inputs.root_public_key,
        forbidden_public_keys=policy.forbidden_public_keys, expected_scope=inputs.intent_scope,
        expected_release=inputs.expected_release, old_token_bytes=inputs.old_token_bytes,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=inputs.work,
        _continuity=lifetime.continuity)
    if type(admitted) is not intent._AdmittedIntent:
        _fail("new release proof contact lacks its actual live intent")
    plan._same(admitted.intent_digest, value.intent_digest, inputs.work, "release proof exact retained intent")
    lifetime.attach(admitted.live)
    lifetime.narrow(value._interval[1], lifetime.window[5], lifetime.window[6])
    return value.current()
