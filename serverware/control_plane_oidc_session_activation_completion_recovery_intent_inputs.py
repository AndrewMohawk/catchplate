"""Original-bound release expectations on one fresh completion recovery actor.

The acknowledged controls and receiving guard come from the actual private
source call. Activation originals are separately reselected and historically
admitted. Encrypted delivery hints remain expectations for later committed
proof, never evidence of private replay or permission to disclose a token.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_oidc_session_activation_release_hints as hints
from serverware import authority_oidc_session_activation_release_intent as intent
from serverware import authority_transition_oidc_session_activation as activation
from serverware import authority_transition_oidc_session_activation_delivery as consumption
from serverware import control_plane_oidc_session_activation_completion_recovery_controls as controls_source
from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as intent_configuration
from serverware import control_plane_oidc_session_activation_release_proof_bootstrap as proof_configuration
from serverware import control_plane_oidc_session_activation_release_proof_acquisition_bootstrap as setup_configuration


actors, execution, state = controls_source.actors, controls_source.execution, controls_source.state
caller, consume, plan = controls_source.caller, controls_source.consume, controls_source.plan
bookkeeping, records = controls_source.bookkeeping, controls_source.activation_records
INPUT_RESERVATION_BYTES = 4 * 1024 * 1024
_METADATA_BYTES = 16 * 1024
_CONSTRUCTION = object()


class CompletionRecoveryIntentInputsError(ValueError):
    pass


def _fail(message):
    raise CompletionRecoveryIntentInputsError(message)


def _scalars(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _fail("release preparation changed a fixed graph")
    result = []
    for name in sorted(fields):
        item = value[name]
        if type(item) is not str or not 1 <= len(item) <= 2048:
            _fail("release preparation changed a bounded scalar")
        result.append((name, item))
    return tuple(result)


def _scope_pin(value, *, proof):
    fields = (proof_configuration.enrollment.SCOPE_FIELDS if proof else intent.enrollments.SCOPE_FIELDS)
    identities = ("producerIdentity", "receiverIdentity") if proof else ("receiverIdentity",)
    if type(value) is not dict or set(value) != fields:
        _fail("release preparation changed its independent scope")
    return (_scalars({name: value[name] for name in fields if name not in identities},
        fields - set(identities)), tuple(_scalars(value[name],
            intent.bootstrap.planner_bootstrap._IDENTITY_FIELDS) for name in identities))


def _release_pin(value):
    if type(value) is not dict or set(value) != intent.RELEASE_FIELDS:
        _fail("release preparation changed its derived release expectation")
    return (_scalars({name: value[name] for name in intent.RELEASE_FIELDS
        if name not in ("deliveryScope", "consumeBinding")},
        intent.RELEASE_FIELDS - {"deliveryScope", "consumeBinding"}),
        _scalars(value["deliveryScope"], intent.delivery._SCOPE_LIMITS),
        _scalars(value["consumeBinding"], intent.contract.CONSUME_BINDING_FIELDS))


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _IntentInputs:
    """Private same-call inputs; no external API accepts this as authority."""

    _construction: object
    _purpose: str
    actor: object
    controls: object
    work: object
    old_token_bytes: bytes
    completion_originals: tuple
    response_originals: tuple
    expected_release_bytes: bytes
    expected_release: dict
    intent_scope_bytes: bytes
    intent_scope: dict
    proof_scope_bytes: bytes
    proof_scope: dict
    intent_policy: object
    proof_policy: object
    setup_policy: object
    planner_original: bytes
    root_public_key: object
    finalization_digest: str
    activation_authorization_digest: str
    original_reservation_bytes: int
    reconciliation_digest: str | None
    retained_only: bool
    retained_authority_interval: tuple | None
    _retained_intent_selection: object
    _lifetime: object
    _live: object
    _bounds: object
    _seal: tuple | None = None

    @property
    def window(self):
        _identity(self)
        return self._lifetime.window

    @property
    def deadline_ns(self):
        _identity(self)
        return self._lifetime.bound

    def current(self):
        _identity(self)
        now = self._live()
        _identity(self)
        return now

    def narrow(self, expiry, age, skew):
        _identity(self)
        for value, minimum in ((expiry, 1), (age, 1), (skew, 0)):
            state.shape._integer(value, minimum=minimum)
        self._lifetime.narrow(expiry, age, skew)
        self.current()

    def continuity(self, epoch, monotonic):
        _identity(self)
        # Only the original ancestor is called here, never a later intent or
        # proof guard which itself calls this continuation.
        result = self._lifetime.continuity(epoch, monotonic)
        _identity(self)
        return result


_SEALED_FIELDS = ("_purpose", "actor", "controls", "work", "old_token_bytes", "completion_originals",
    "response_originals", "expected_release_bytes", "expected_release", "intent_scope_bytes",
    "intent_scope", "proof_scope_bytes", "proof_scope", "intent_policy", "proof_policy",
    "setup_policy", "planner_original", "root_public_key", "finalization_digest",
    "activation_authorization_digest", "original_reservation_bytes", "reconciliation_digest",
    "retained_only", "retained_authority_interval", "_retained_intent_selection", "_lifetime", "_live", "_bounds")


def _identity(value):
    if (type(value) is not _IntentInputs or value._construction is not _CONSTRUCTION
            or type(value._seal) is not tuple or len(value._seal) != 4
            or type(value._seal[0]) is not tuple or len(value._seal[0]) != len(_SEALED_FIELDS)
            or any(getattr(value, name) is not held for name, held in zip(_SEALED_FIELDS, value._seal[0]))
            or _scope_pin(value.intent_scope, proof=False) != value._seal[1]
            or _scope_pin(value.proof_scope, proof=True) != value._seal[2]
            or _release_pin(value.expected_release) != value._seal[3]):
        _fail("release preparation inputs lost their source-owned seals")
    actor = value.actor
    if (type(actor) is not actors._CompletionActorScope or actor._active is not True
            or actor._authorized is not True or actor._completion_recovery_spent is not True
            or type(value._purpose) is not str
            or value._purpose not in ("release-intent-proof", "release", "retained-release")
            or actor._purpose != value._purpose or actor._profile != "consume"
            or actor._work is not value.work or actor._old_token is not value.old_token_bytes
            or value.controls._actor is not actor):
        _fail("release preparation outlived its distinct actual fresh actor")
    value._bounds()
    selection = value._retained_intent_selection
    if type(value.retained_only) is not bool or actor._retained_intent_selection is not selection:
        _fail("release inputs changed their original retained authority selection")
    if selection is not None:
        actors.intent_selection._require_selection(selection,
            owner=actor._owner, target=actor._target, work=value.work)
        if value._purpose not in ("release-intent-proof", "release") or value.retained_only is not selection.retained_only:
            _fail("retained intent selection cannot authorize another purpose or mode")
    if value.retained_only:
        authority = selection.authority
        if (value.retained_authority_interval is not authority.authority_interval
                or value.root_public_key is not authority.root_public_key
                or value.intent_policy is not authority.release_intent
                or value.proof_policy is not authority.release_proof
                or value.planner_original is not authority.activation_planning.planner_bootstrap_bytes
                or value.setup_policy is not None):
            _fail("retained release inputs changed their independently archived authority")
    elif value.retained_authority_interval is not None:
        _fail("current release inputs cannot borrow a retired authority interval")


def _require_inputs(value):
    _identity(value)
    value.current()
    return value


def _match_retained_release_records(inputs, held):
    """Match immutable prefix commitments before any signature or effect."""
    _require_inputs(inputs)
    if inputs._retained_intent_selection is not None:
        actors.intent_selection._match_release_records(inputs._retained_intent_selection, held)


def _admit_on_controls(selected, *, response_originals, receiving_current):
    """Preparation-only expectations on the actual acknowledged continuation."""
    return _admit_for_purpose(selected, response_originals=response_originals,
        receiving_current=receiving_current, purpose="release-intent-proof")


def _admit_for_release_on_controls(selected, *, response_originals, receiving_current):
    """Fresh release actor; only the separate delivery owner supplies provenance."""
    return _admit_for_purpose(selected, response_originals=response_originals,
        receiving_current=receiving_current, purpose="release")


def _admit_for_retained_release_on_controls(selected, *, response_originals, receiving_current):
    """Fresh retained-release actor; no preparation or LIVE authority is reused."""
    return _admit_for_purpose(selected, response_originals=response_originals,
        receiving_current=receiving_current, purpose="retained-release")


def _admit_for_purpose(selected, *, response_originals, receiving_current, purpose):
    # Literal source owners, not a supplied callback, select the one-use
    # provenance handshake. Neither owner can borrow the other's actor purpose.
    if type(purpose) is not str:
        _fail("release inputs require a literal actor purpose")
    if purpose == "release-intent-proof":
        from serverware import control_plane_oidc_session_activation_completion_recovery_release as source
    elif purpose in ("release", "retained-release"):
        from serverware import control_plane_oidc_session_activation_completion_recovery_delivery as source
    else:
        _fail("release inputs require an exact source-selected actor purpose")

    controls_source._require_controls(selected)
    actor = selected._actor
    if (selected.profile != "consume" or type(actor) is not actors._CompletionActorScope
            or actor._purpose != purpose
            or type(actor._future_original_bytes) is not int
            or not INPUT_RESERVATION_BYTES <= actor._future_original_bytes <= selected.original_reservation_bytes
            or selected.original_reservation_bytes > controls_source.MAX_ORIGINAL_BYTES
            or type(response_originals) is not tuple or len(response_originals) != 6
            or response_originals[0] != b"acknowledged"
            or any(type(value) is not bytes for value in response_originals)):
        _fail("release preparation lacks acknowledged, pre-reserved consume controls")
    # One-use provenance check, not a repeated ancestor and not a supplied
    # success callback. The source pins this exact tuple and genuine verifier.
    reconciliation_digest = source._require_inputs_call(selected, response_originals, receiving_current)
    if reconciliation_digest is not None:
        state.shape._digest(reconciliation_digest)
    owner, work, target = actor._owner, actor._work, actor._target
    parent, binding, custody = owner._material, owner._binding, owner._custody
    activation_authority = target.authority
    consume_authority = selected.consume_authority
    consume_selection = actor._consume_recovery_selection
    evidence_authority = activation_authority if consume_authority is None else consume_authority
    current_intent, current_proof, current_setup = (parent.release_intent,
        parent.release_proof, parent.release_proof_acquisition)
    retained_selection = actor._retained_intent_selection
    retained_only = False
    release_authority = None
    if retained_selection is not None:
        actors.intent_selection._require_selection(retained_selection, owner=owner, target=target, work=work)
        if (purpose not in ("release-intent-proof", "release") or selected._retained_intent_selection is not retained_selection
                or retained_selection.consume_selection is not consume_selection):
            _fail("release preparation changed its actual retained-prefix selection")
        retained_only = retained_selection.retained_only
        if retained_only:
            release_authority = retained_selection.authority
    intent_policy = current_intent if release_authority is None else release_authority.release_intent
    proof_policy = current_proof if release_authority is None else release_authority.release_proof
    setup_policy = current_setup if release_authority is None else None
    if (type(intent_policy) is not intent_configuration._ReleaseIntentMaterial
            or type(proof_policy) is not proof_configuration._ReleaseProofMaterial
            or (setup_policy is not None
                and type(setup_policy) is not setup_configuration._ReleaseProofAcquisitionMaterial)
            or parent.activation_planning is None
            or type(parent.consume_execution) is not intent_configuration.consume._ConsumeExecutionMaterial
            or type(activation_authority) is not controls_source.history.historical._SelectedActivationHistory
            or (consume_authority is not None and type(consume_authority)
                is not controls_source.consume_history._SelectedConsumeHistory)
            or selected.authority is not activation_authority):
        _fail("release preparation lacks actual independent parent configuration")
    if purpose == "release" and (consume_authority is None or consume_selection is None
            or consume_selection.authority is not consume_authority):
        _fail("LIVE release requires its independently selected original consume authority")
    policy = activation_authority.activation_execution
    planner_policy = parent.activation_planning if release_authority is None else release_authority.activation_planning
    consume_policy, current_policy = evidence_authority.consume_execution, parent.consume_execution
    release_state_policy = current_policy if release_authority is None else release_authority.consume_execution
    if (type(policy) is not intent_configuration.activation._ActivationExecutionMaterial
            or type(consume_policy) is not intent_configuration.consume._ConsumeExecutionMaterial):
        _fail("release preparation lacks independently selected original execution policies")
    current_root, old = binding.runtime_root_public_key, actor._old_token
    root = current_root if release_authority is None else release_authority.root_public_key
    if type(old) is not bytes or len(old) != intent.delivery.TOKEN_BYTES:
        _fail("release preparation lost original old-token possession")
    state._public(root)
    current_config, current_generation = parent.configuration_digest, parent.generation["digest"]
    config = current_config if release_authority is None else release_authority.configuration_digest
    generation = current_generation if release_authority is None else release_authority.generation["digest"]
    retained_interval = None if release_authority is None else release_authority.authority_interval
    activation_config, activation_root = activation_authority.configuration_digest, activation_authority.root_public_key
    consume_config, consume_root = evidence_authority.configuration_digest, evidence_authority.root_public_key
    authority_interval = activation_authority.authority_interval
    finalization, activation_digest = selected.finalization_digest, target.activation_authorization_digest
    intent_scope_original, proof_scope_original = intent_policy.expected_scope_bytes, proof_policy.expected_scope_bytes
    planner_original = planner_policy.planner_bootstrap_bytes
    enrollments = (policy.authorization_enrollment_bytes,
        policy.current_root_enrollment_bytes, policy.grant_enrollment_bytes)
    state_originals = (consume_policy.current_root_enrollment_bytes, release_state_policy.current_root_enrollment_bytes)
    if retained_only:
        state_originals += (current_policy.current_root_enrollment_bytes,)
    # These are fixed source-selected attributes, not a generic graph walk.
    pins = ((owner, "_material", parent), (owner, "_binding", binding), (owner, "_custody", custody),
        (parent, "release_intent", current_intent), (parent, "release_proof", current_proof),
        (parent, "release_proof_acquisition", current_setup), (parent, "consume_execution", current_policy),
        (parent, "activation_planning", parent.activation_planning), (binding, "runtime_root_public_key", current_root),
        (target, "authority", activation_authority), (selected, "consume_authority", consume_authority),
        (actor, "_consume_recovery_selection", consume_selection),
        (actor, "_retained_intent_selection", retained_selection),
        (selected, "_retained_intent_selection", retained_selection),
        (selected, "root_public_key", evidence_authority.root_public_key),
        (activation_authority, "activation_execution", policy),
        (activation_authority, "root_public_key", activation_root),
        (activation_authority, "configuration_digest", activation_config),
        (activation_authority, "authority_interval", authority_interval),
        (evidence_authority, "consume_execution", consume_policy),
        (evidence_authority, "root_public_key", consume_root),
        (evidence_authority, "configuration_digest", consume_config),
        (consume_policy, "current_root_enrollment_bytes", state_originals[0]),
        (release_state_policy, "current_root_enrollment_bytes", state_originals[1]),
        (current_policy, "current_root_enrollment_bytes", state_originals[-1]),
        (planner_policy, "planner_bootstrap_bytes", planner_original),
        (intent_policy, "expected_scope_bytes", intent_scope_original),
        (proof_policy, "expected_scope_bytes", proof_scope_original),
        *((policy, name, getattr(policy, name)) for name in ("authorization_enrollment_bytes",
            "current_root_enrollment_bytes", "grant_enrollment_bytes", "planner_public_key", "operation_public_key")),
        *((intent_policy, name, getattr(intent_policy, name)) for name in
            ("enrollment_bytes", "enrollment_digest", "caller_public_key", "forbidden_public_keys")),
        *((proof_policy, name, getattr(proof_policy, name)) for name in
            ("enrollment_bytes", "enrollment_digest", "proof_public_key", "forbidden_public_keys", "endpoint")),
        *((setup_policy, name, getattr(setup_policy, name)) for name in
            ("issuer_policy_bytes", "current_activation_planner_bytes") if setup_policy is not None))
    future = actor._future_original_bytes

    def identity():
        if (actor._owner is not owner or actor._target is not target or actor._old_token is not old
                or actor._purpose != purpose or actor._future_original_bytes != future
                or parent.configuration_digest != current_config or parent.generation["digest"] != current_generation
                or any(getattr(held, name) is not original for held, name, original in pins)):
            _fail("release preparation changed its original actor or cold pins")
        if release_authority is not None and (retained_selection.authority is not release_authority
                or release_authority.root_public_key is not root
                or release_authority.release_intent is not intent_policy
                or release_authority.release_proof is not proof_policy
                or release_authority.activation_planning is not planner_policy
                or release_authority.consume_execution is not release_state_policy
                or release_authority.configuration_digest != config
                or release_authority.generation["digest"] != generation
                or release_authority.authority_interval is not retained_interval):
            _fail("release preparation changed its original RI authority")

    def ancestor(epoch, monotonic):
        identity()
        if retained_selection is not None:
            retained_selection.live()
        selected.current()
        received = receiving_current()
        now = selected.current()
        sampled = caller.production._callback(work, time.monotonic_ns)
        if (type(received) is not int or type(now) is not int or type(sampled) is not int
                or received < epoch or now < received or sampled < monotonic):
            _fail("release preparation original clocks reversed")
        identity()
        return now, sampled

    lifetime = bookkeeping._Lifetime(selected.window, selected.deadline_ns, work, ancestor)
    lifetime.current()
    # The actor already reserved this lane before its first history read. Do
    # not add it again to the whole-call reservation carried by the controls.
    # Eight original footprints cover read/decode/canonical/signature capture;
    # all fixed projections are reserved before the second selected body read.
    lane_held = (8 * (len(selected.originals[3]) + len(intent_scope_original)
        + len(proof_scope_original) + sum(map(len, (*enrollments, *state_originals)))
        + records.attempts.MAX_RECORD_BYTES + records._MAX_HEADER_BYTES)
        + 4 * sum(map(len, response_originals)) + 4 * intent.MAX_BYTES + 2 * _METADATA_BYTES)
    allowance = 3 * ((INPUT_RESERVATION_BYTES - lane_held) // 8)
    if allowance <= _METADATA_BYTES:
        _fail("release preparation has no reserved activation re-admission capacity")
    retained = execution.custody.ControlPlaneCustodyClient.load_oidc_session_activation_completion_recovery_target(
        custody, finalization, work=work, current=lifetime.base, maximum_original_bytes=allowance)
    lifetime.current()
    if (type(retained) is not tuple or len(retained) != 2
            or type(retained[0]) is not records.attempts.ActivationDispatchAttemptRecord):
        _fail("release preparation lacks its exact retained activation originals")
    claim, prepared = retained
    raw = controls_source._record(prepared, "prepared", "activation", finalization, activation_digest, work)
    if (claim.finalization_digest != finalization or claim.source_revision != state.authority.SOURCE_REVISION
            or lane_held + 8 * sum(map(len, raw)) > INPUT_RESERVATION_BYTES):
        _fail("release preparation activation association or capacity differs")
    plan._same(claim.authorization_enrollment_digest, policy.authorization_enrollment_digest, work,
        "release preparation actual activation enrollment association")
    original, signed, cipher, expected_original, before = raw
    expected = caller.expectations_wire._capture_on_work(controls_source.history.planning._object(
        expected_original, caller.expectations_wire.MAX_BYTES, work), work=work)
    consumed_expected = consume.expectations_wire._capture_on_work(controls_source.history.planning._object(
        selected.originals[3], consume.expectations_wire.MAX_BYTES, work), work=work)
    for graph, phase, configured in ((expected, "activation", activation_config),
            (consumed_expected, "consume", consume_config)):
        controls_source._target_arguments(graph, target, phase, work)
        plan._same(graph["scope"]["configurationDigest"], configured, work,
            "release preparation original request configuration")
    scope = expected["scope"]
    lifetime.narrow(lifetime.window[3], min(policy.maximum_age_ns, scope["maximumPlanAgeNs"]),
        min(policy.maximum_clock_skew_ns, scope["maximumClockSkewNs"]))
    authenticated = caller._verify_historical_on_work(authorization_bytes=original,
        authorization_enrollment_bytes=enrollments[0], current_root_enrollment_bytes=enrollments[1],
        grant_enrollment_bytes=enrollments[2], root_public_key=activation_root, configuration_digest=activation_config,
        planner_public_key=policy.planner_public_key, operation_public_key=policy.operation_public_key,
        originals=(signed, cipher), expectations=expected, before_vector_bytes=before,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    plan._same(authenticated.authorization_digest, activation_digest, work,
        "release preparation genuinely retained activation caller")
    if not (authority_interval[0] <= authenticated.issued_at_epoch_ns
            < authenticated.expires_at_epoch_ns <= authority_interval[1]):
        _fail("release preparation activation caller escapes its original authority interval")
    lifetime.narrow(lifetime.window[3], authenticated.maximum_age_ns, authenticated.maximum_clock_skew_ns)
    lifetime.attach(authenticated.live)
    # Root rotation is not a state migration: authenticate all selected originals
    # under their independently selected roots, then compare COMPLETE payloads.
    # LIVE keeps these evidence roots distinct from the CURRENT root used for
    # its new client/server originals. Read-only retained RI remains separately
    # selected and must also match the current R2 complete state payload.
    states = []
    state_roots = ((enrollments[1], activation_root),
        (state_originals[0], consume_root), (state_originals[1], root))
    if retained_only:
        state_roots += ((state_originals[2], current_root),)
    for original_state, selected_root in state_roots:
        lifetime.current()
        states.append(state._admit_enrollment_on_work(enrollment_bytes=original_state,
            root_public_key=selected_root, work=work))
        lifetime.current()
    for original_state in states[:-1]:
        plan._same(original_state.payload, states[-1].payload, work,
            "release preparation unchanged complete state enrollment payload")
    for actual, wanted in ((activation_authority.generation["digest"], generation),
            (evidence_authority.generation["digest"], generation),
            (current_generation, generation),
            (states[-1].payload["generationDigest"], generation),
            (states[-1].payload["databaseId"], selected.marker["database_id"])):
        plan._same(actual, wanted, work, "release preparation exact original/current state cohort")
    bookkeeping._same_bytes(selected.enrollment_bytes, state_originals[0], work,
        "release preparation exact consume state enrollment original")
    activated, consumed = expected["request"], consumed_expected["request"]
    activation_arguments = activation._arguments(activated["arguments"], work)
    arguments = consumption._arguments(consumed["arguments"], work)
    for name in ("user_id", "session_id", "credential_id", "credential_record_id", "challenge_id",
            "old_token_digest", "new_token_digest", "assertion_digest"):
        plan._same(arguments[name], activation_arguments[name], work,
            "release preparation same signed activation/consume " + name)
    # Consume signatures, marker and exact raw8 remain protected by selected's
    # genuine historical controls, not by these newly decoded projections.
    plan._same(consumed["requestDigest"], selected.marker["request_digest"], work,
        "release preparation exact signed consume request")
    plan._same(consumed["operationId"], selected.marker["operation_id"], work,
        "release preparation exact signed consume operation")
    packet, effects, envelope, created, expires = hints._decode_on_work(response_originals[4:], work=work)
    plan._same(packet, selected.packet_digest, work, "release preparation independent packet pin")
    delivery_scope = {"deliveryId": arguments["delivery_id"], "userId": arguments["user_id"],
        "sessionId": arguments["session_id"], "credentialId": arguments["credential_id"],
        "credentialRecordId": arguments["credential_record_id"], "challengeId": arguments["challenge_id"],
        "assertionDigest": arguments["assertion_digest"], "oldTokenDigest": arguments["old_token_digest"],
        "newTokenDigest": arguments["new_token_digest"], "createdAt": created, "expiresAt": expires}
    created_epoch, delivery_expiry = intent.bootstrap._scope(delivery_scope, work)
    if delivery_expiry - created_epoch > activation_arguments["delivery_ttl_seconds"] * 1_000_000_000:
        _fail("release preparation descriptor exceeds signed activation delivery lifetime")
    plan._same(intent.delivery._token_digest(old, work, lifetime.current), arguments["old_token_digest"],
        work, "release preparation exact old-token original possession")
    deterministic = intent.registration.core._deterministic_uuid(operation=activation.OPERATION,
        request_digest=activated["requestDigest"], purpose="activation-delivery", work=work)
    plan._same(deterministic, arguments["delivery_id"], work, "release preparation deterministic delivery")
    operation = plan._frame("serverware.policyAuthorityOperation/v2",
        (plan._ascii(activation.OPERATION, work), plan._ascii(activated["requestDigest"], work)), work)
    plan._same(operation, activated["operationId"], work, "release preparation activation operation")
    intent_scope = intent_configuration._scope_on_work(intent_scope_original, work)
    proof_scope = proof_configuration._scope_on_work(proof_scope_original, work)
    for name in proof_configuration._SHARED_FIELDS:
        plan._same(proof_scope[name], intent_scope[name], work, "release preparation independent shared " + name)
    for name, value in (("configurationDigest", config), ("generationDigest", generation),
            ("databaseId", selected.marker["database_id"])):
        plan._same(intent_scope[name], value, work, "release preparation actual cold scope " + name)
    plan._same(intent_scope["generationDigest"], selected.marker["generation_digest"], work,
        "release preparation signed consume generation")
    work.charge(input_bytes=len(response_originals[1]))
    complete_digest = response_originals[1].decode("ascii")
    state.shape._digest(complete_digest)
    after_digest = state.vector._digest_on_work(selected.after_bytes, work=work)
    plan._same(after_digest, selected.marker["after_vector_digest"], work,
        "release preparation exact consume after-vector")
    release = {"activationRequestDigest": activated["requestDigest"],
        "activationOperationId": activated["operationId"], "consumeRequestDigest": consumed["requestDigest"],
        "deliveryEnvelopeDigest": controls_source.history.planning.assertion._digest(envelope, work),
        "deliveryScope": delivery_scope, "consumeBinding": {"packetDigest": packet,
            "pendingDecisionDigest": selected.current_pending[1], "completionRequestDigest": complete_digest,
            "effectsDigest": effects, "afterVectorDigest": after_digest}}
    intent_scope, release = intent._graphs(intent_scope, release)
    release_original = intent.contract._wire(release, work)
    if len(release_original) > intent.MAX_BYTES:
        _fail("release preparation projection exceeds its reserved fixed output")
    lifetime.narrow(delivery_expiry, lifetime.window[5], lifetime.window[6])
    previous_window, previous_bound = lifetime.window, lifetime.bound

    def bounds():
        nonlocal previous_window, previous_bound
        held = caller.clock._validate(lifetime.window)
        bound = lifetime.bound
        if (type(bound) is not int or bound <= 0 or bound > previous_bound or bound > held[4]
                or held[:3] != previous_window[:3]
                or any(actual > maximum for actual, maximum in zip(held[3:], previous_window[3:]))):
            _fail("release preparation restored or widened its narrowed allowance")
        previous_window, previous_bound = held, bound

    def live():
        bounds()
        now = lifetime.current()
        if created_epoch > now + lifetime.window[6] or now >= delivery_expiry:
            _fail("release preparation original delivery is future-created or expired")
        return now

    live()
    result = _IntentInputs(_CONSTRUCTION, purpose, actor, selected, work, old, response_originals[:4],
        response_originals, release_original, release, intent_scope_original, intent_scope,
        proof_scope_original, proof_scope, intent_policy, proof_policy, setup_policy,
        planner_original, root, finalization, activation_digest, selected.original_reservation_bytes,
        reconciliation_digest, retained_only, retained_interval, retained_selection, lifetime, live, bounds)
    object.__setattr__(result, "_seal", (tuple(getattr(result, name) for name in _SEALED_FIELDS),
        _scope_pin(intent_scope, proof=False), _scope_pin(proof_scope, proof=True), _release_pin(release)))
    result.current()
    return result
