"""Fresh-actor proof setup/exchange or genuine read-only historical admission.

The exact intent continuation is required. A new contact consumes the existing
global proof claim, requires configured root setup, and retains each original
reply before admission. An existing claim is never resumed. No release profile,
store checkpoint, token opening, SQL retry or cookie is selected here.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_release_proof as proof
from serverware import authority_oidc_session_activation_release_proof_transport as transport
from serverware import authority_oidc_session_activation_release_proof_input_transport as setup_transport
from serverware import oidc_session_activation_release_proof_bootstrap as worker_bootstrap
from serverware import control_plane_oidc_session_activation_completion_recovery_intent as intent_source


state, plan, bookkeeping = intent_source.state, intent_source.plan, intent_source.bookkeeping
configured, acquisition = intent_source.proof_configured, intent_source.setup_configured
execution, records = intent_source.execution, intent_source.records
_CONSTRUCTION = object()
_FIXED_REPRESENTATIONS = (intent_source.INTENT_REPRESENTATION_BYTES + 256 * 1024
    + 4 * setup_transport.MAX_REQUEST_BYTES + 2 * records.COMPLETION_RECOVERY_METADATA_BYTES
    + 4096 + 8 * (transport.REQUEST_HEADER_BYTES + transport.RESPONSE_HEADER_BYTES
        + setup_transport.REQUEST_HEADER_BYTES + setup_transport.RESPONSE_HEADER_BYTES))
_SMALL_PROOF_MAXIMUM = 6 + proof.MAX_BYTES + proof.enrollments.MAX_BYTES


class CompletionRecoveryProofError(ValueError):
    pass


def _fail(message):
    raise CompletionRecoveryProofError(message)


def _same(actual, expected, work, label):
    bookkeeping._same_bytes(actual, expected, work, "recovery proof " + label)


def _capacity(setup_size, response_size, *, setup_admitted):
    # 16 footprints cover repeated canonical/capture/nested originals and
    # their bounded publication buffers. A retained setup not re-admitted is
    # only DATA, with its read/copy allowance. None is a new work budget.
    if (type(setup_size) is not int or setup_size < 0
            or type(response_size) is not int or response_size < 0
            or type(setup_admitted) is not bool):
        _fail("release proof representation sizes are not exact")
    total = (_FIXED_REPRESENTATIONS + (16 if setup_admitted else 3) * setup_size
        + 16 * response_size)
    if total > intent_source.FUTURE_REPRESENTATION_BYTES:
        _fail("release proof exceeds its original reserved representation lane")
    return total


def _io_capacity(setup_size=0, response_size=0, *, setup_admitted=False):
    # C separately preflights its selected rereads and publication buffers.
    # Subtract our simultaneously held representations before that preflight;
    # a not-yet-admitted reply needs raw/copy space, not decoded proof space.
    _capacity(setup_size, response_size, setup_admitted=setup_admitted)
    held = (_FIXED_REPRESENTATIONS + (16 if setup_admitted else 3) * setup_size
        + 3 * response_size)
    remaining = intent_source.FUTURE_REPRESENTATION_BYTES - held
    if remaining < records.COMPLETION_RECOVERY_METADATA_BYTES:
        _fail("release proof has no remaining publication representation capacity")
    return remaining


class _ProofContinuation:
    """Private source association and full current guard; no release token."""

    __slots__ = ("_construction", "intent", "_lifetime", "_originals", "_seal")

    def __init__(self, construction, selected_intent, lifetime, originals):
        if construction is not _CONSTRUCTION:
            _fail("release proof continuation is privately constructed")
        self._construction, self.intent = construction, selected_intent
        self._lifetime, self._originals = lifetime, originals
        self._seal = (selected_intent, lifetime, originals)

    def current(self):
        _identity(self)
        epoch = self._lifetime.current()
        _identity(self)
        return epoch


def _identity(value):
    if (type(value) is not _ProofContinuation or value._construction is not _CONSTRUCTION
            or type(value._seal) is not tuple or len(value._seal) != 3
            or any(actual is not expected for actual, expected in zip(
                (value.intent, value._lifetime, value._originals), value._seal))):
        _fail("release proof changed its actual private continuation")
    intent_source._require_intent(value.intent)


def _require_proof(value):
    _identity(value)
    value.current()
    return value


def _proof_on_intent(selected_intent):
    """Preparation-only acquisition or historical re-admission."""
    intent_source._require_intent(selected_intent)
    if selected_intent.inputs._purpose != "release-intent-proof":
        _fail("proof preparation cannot borrow a release-purpose actor")
    return _proof_from_intent(selected_intent)


def _readmit_on_intent(selected_intent):
    """Existing original only; never contact setup/proof services or publish."""
    intent_source._require_intent(selected_intent)
    if selected_intent.inputs._purpose not in ("release", "retained-release"):
        _fail("proof readmission requires its separate fresh release actor")
    return _proof_from_intent(selected_intent)


def _proof_from_intent(selected_intent):
    intent_source._require_intent(selected_intent)
    if selected_intent.inputs._purpose == "release-intent-proof":
        from serverware import control_plane_oidc_session_activation_completion_recovery_release as owner_call
    elif selected_intent.inputs._purpose in ("release", "retained-release"):
        from serverware import control_plane_oidc_session_activation_completion_recovery_delivery as owner_call
    else:
        _fail("proof continuation has no actual source owner")

    owner_call._require_proof_call(selected_intent)
    inputs = selected_intent.inputs
    owner, work, policy = inputs.actor._owner, inputs.work, inputs.proof_policy
    root, release, scope = inputs.root_public_key, inputs.expected_release, inputs.proof_scope
    if type(policy) is not configured._ReleaseProofMaterial:
        _fail("release proof lacks its actual independent cold configuration")

    def ancestor(epoch, monotonic):
        intent_source._require_intent(selected_intent)
        observed = selected_intent._lifetime.continuity(epoch, monotonic)
        selected_intent.current()
        return selected_intent._lifetime.continuity(*observed)

    lifetime = bookkeeping._Lifetime(selected_intent.window, selected_intent.deadline_ns, work, ancestor)
    current = lifetime.current
    current()
    retained = selected_intent._records
    setup_originals = intent_source._record(retained[3], "release-proof-setup", inputs)
    returned = intent_source._record(retained[4], "release-proof", inputs)
    setup_size = 0 if setup_originals is None else len(setup_originals[0])
    setup_material = None
    historical = returned is not None
    if not historical and inputs.retained_only:
        _fail("retired release authority requires its exact retained proof; contact is forbidden")
    if not historical and inputs._purpose != "release-intent-proof":
        _fail("release requires an existing proof; it cannot contact or resume preparation")
    if historical:
        returned = transport._originals(returned, response=True)
        _capacity(setup_size, sum(map(len, returned)), setup_admitted=False)
    elif retained[2] is not None:
        _fail("release proof claim is spent without a response; it cannot be resumed")
    # Actual enrolled proof key/scope/separation is required on both paths.
    enrolled = proof.enrollments._admit_on_work(enrollment_bytes=policy.enrollment_bytes,
        root_public_key=root, expected_scope=scope,
        forbidden_public_keys=policy.forbidden_public_keys, work=work)
    current()
    plan._same(enrolled.enrollment_digest, policy.enrollment_digest, work,
        "recovery proof actual cold enrollment")
    signing_pin = proof.enrollments.keys._spki_on_work(enrolled.proof_public_key, work)
    current()
    plan._same(signing_pin, proof.enrollments.keys._spki_on_work(policy.proof_public_key, work),
        work, "recovery proof actual configured signer")
    if owner._response_pin is None or signing_pin == owner._response_pin:
        _fail("recovery proof cannot reuse the actual HTTP signing key")
    current()
    age, skew = enrolled.payload["maximumAgeNs"], enrolled.payload["maximumClockSkewNs"]
    lifetime.narrow(lifetime.window[3], age, skew)
    if not historical:
        setup = inputs.setup_policy
        if type(setup) is not acquisition._ReleaseProofAcquisitionMaterial:
            _fail("new recovery proof requires independently configured root setup")
        # Historical intent is enough for read-only old proof admission, not
        # for a new contact. Never regenerate an expired retained intent.
        intent_source._live_for_proof(selected_intent)
        lifetime.narrow(selected_intent.window[3], selected_intent.window[5],
            selected_intent.window[6])
        lifetime.adopt(lifetime.window, min(lifetime.bound, selected_intent.deadline_ns))
        current()
        setup_policy = acquisition._policy_on_work(setup.issuer_policy_bytes,
            release_intent=inputs.intent_policy, release_proof=policy,
            root_public_key=root, work=work,
            activation_planner_bytes=inputs.planner_original, current=current)
        if setup.current_activation_planner_bytes is not None:
            _same(setup.current_activation_planner_bytes, inputs.planner_original, work,
                "independently current setup planner")
        current()
        interval = setup_policy["issuedAtEpochNs"], setup_policy["expiresAtEpochNs"]
        launch_guard = worker_bootstrap.completion.primitives._launch_guard(interval,
            (lifetime.window[1], lifetime.window[0], lifetime.window[2]), lifetime.base, work)
        lifetime.attach(launch_guard)
        lifetime.narrow(interval[1], age, skew)
        setup_request = setup_transport._originals((setup_transport.PURPOSE,
            inputs.completion_originals[2], inputs.completion_originals[3],
            selected_intent.intent_bytes), response=False)
        # Split the fixed future lane before either socket. The conservative
        # 32x reserves setup captures plus a later independently bounded
        # custody copy, not a promise to accept all per-file source maxima.
        setup_cap = min(worker_bootstrap.MAX_BYTES,
            (intent_source.FUTURE_REPRESENTATION_BYTES - _FIXED_REPRESENTATIONS
                - 16 * _SMALL_PROOF_MAXIMUM) // 32)
        if setup_cap < 2:
            _fail("recovery proof has no bounded setup response capacity")
        _capacity(setup_cap, setup_cap + _SMALL_PROOF_MAXIMUM, setup_admitted=True)
        claim = execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_completion_recovery_release_proof_attempt(
            owner._custody, **intent_source._persistence(inputs, current,
                _io_capacity()))
        current()
        state.shape._digest(claim)
        setup_originals = setup_transport._socket_request_on_work(setup.endpoint,
            originals=setup_request, deadline_ns=lifetime.bound, work=work, current=current,
            maximum_response_bytes=setup_cap)
        current()
        setup_originals = setup_transport._originals(setup_originals, response=True)
        setup_size = len(setup_originals[0])
        if setup_size > setup_cap:
            _fail("recovery proof setup exceeded its original pre-body capacity")
        published = execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_completion_recovery_release_proof_setup(
            owner._custody, originals=setup_originals, **intent_source._persistence(inputs, current,
                _io_capacity(setup_size)))
        current()
        state.shape._digest(published)
        setup_material = worker_bootstrap._verify_on_work(bootstrap_bytes=setup_originals[0],
            root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            work=work, _current=lifetime.base)
        if type(setup_material) is not worker_bootstrap._ProofMaterial:
            _fail("recovery proof setup lacks genuine root-original admission")
        lifetime.attach(setup_material.live)
        lifetime.adopt(setup_material.live_window, setup_material.deadline_ns)
        if setup.current_activation_planner_bytes is None:
            if (setup_material.current_activation_planner_bytes is not None
                    or setup_material.current_activation_planner is not None):
                _fail("legacy proof policy cannot select a versioned current planner")
        else:
            _same(setup_material.current_activation_planner_bytes,
                setup.current_activation_planner_bytes, work, "versioned setup current planner")
            if type(setup_material.current_activation_planner) is not worker_bootstrap.release_bootstrap.planner_bootstrap._PlannerMaterial:
                _fail("versioned proof setup lacks genuine current planner admission")
        cm = setup_material.completion_material
        plan._same(proof.enrollments.keys._spki_on_work(cm.evidence_root_public_key, work),
            proof.enrollments.keys._spki_on_work(inputs.controls.root_public_key, work), work,
            "independently selected original consume evidence root")
        for actual, expected, label in (
                (setup_material.intent_bytes, selected_intent.intent_bytes, "intent"),
                (setup_material.intent_enrollment_bytes, inputs.intent_policy.enrollment_bytes, "intent enrollment"),
                (setup_material.proof_enrollment_bytes, policy.enrollment_bytes, "proof enrollment"),
                (setup_material.completion_request_bytes, inputs.completion_originals[2], "completion request"),
                (setup_material.state_receipt_bytes, inputs.completion_originals[3], "state receipt"),
                (cm.authorization_bytes, inputs.controls.originals[0], "consume authorization"),
                (cm.current_root_enrollment_bytes, inputs.controls.enrollment_bytes, "consume state enrollment")):
            _same(actual, expected, work, "setup exact " + label)
        for actual, expected, label in (
                (setup_material.expected_proof_scope, scope, "proof scope"),
                (setup_material.expected_release, release, "release"),
                (setup_material.caller_id, inputs.intent_scope["callerId"], "caller")):
            plan._same(actual, expected, work, "recovery setup independent " + label)
        current()
        issued = acquisition.issuer._verify_on_work(policy_bytes=setup.issuer_policy_bytes,
            completion_bootstrap_bytes=setup_material.completion_bootstrap_bytes,
            proof_enrollment_bytes=policy.enrollment_bytes,
            intent_enrollment_bytes=inputs.intent_policy.enrollment_bytes,
            root_public_key=root, live_window=lifetime.window, transport_deadline_ns=lifetime.bound,
            work=work, _continuity=lifetime.continuity)
        if type(issued) is not acquisition.issuer._IssuerPolicyMaterial:
            _fail("recovery proof setup lacks its independent original issuer policy")
        lifetime.attach(issued.live)
        if setup.current_activation_planner_bytes is None:
            if issued.current_activation_planner_bytes is not None or issued.current_activation_planner is not None:
                _fail("legacy setup policy changed its original planner profile")
        else:
            _same(issued.current_activation_planner_bytes, setup.current_activation_planner_bytes,
                work, "issuer original current planner")
            _same(issued.current_activation_planner.bootstrap_bytes,
                setup_material.current_activation_planner.bootstrap_bytes, work,
                "genuine issuer and setup current context")
        plan._same(setup_material.launch, issued.proof_launch, work, "recovery proof root launch")
        lifetime.adopt(issued.live_window, issued.deadline_ns)
        if len(setup_material.release_custody_bytes) > setup_size:
            _fail("recovery setup nested custody exceeds the reserved enclosing original")
        proof_cap = len(setup_material.release_custody_bytes) + _SMALL_PROOF_MAXIMUM
        _capacity(setup_size, proof_cap, setup_admitted=True)
        work.prepare_utf8(selected_intent.intent_digest)
        request = transport._originals((transport.PURPOSE,
            selected_intent.intent_digest.encode("ascii"), inputs.old_token_bytes), response=False)
        current()
        returned = transport._socket_request_on_work(policy.endpoint, originals=request,
            deadline_ns=lifetime.bound, work=work, current=current, maximum_response_bytes=proof_cap)
        current()
        returned = transport._originals(returned, response=True)
        _capacity(setup_size, sum(map(len, returned)), setup_admitted=True)
        # Preserve even uncertain/malformed semantic replies as bounded DATA.
        published = execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_completion_recovery_release_proof(
            owner._custody, originals=returned, **intent_source._persistence(inputs, current,
                _io_capacity(setup_size, sum(map(len, returned)), setup_admitted=True)))
        current()
        state.shape._digest(published)
    if returned[0] != b"proved":
        _fail("recovery proof returned no authenticated proof original")
    _same(returned[3], policy.enrollment_bytes, work, "independently enrolled proof signer")
    if setup_material is not None:
        _same(returned[1], setup_material.release_custody_bytes, work, "exact acquired root custody")
    current()
    verify_custody = (proof.bootstrap._verify_historical_on_work if historical
        else proof.bootstrap._verify_on_work)
    custody = verify_custody(custody_bytes=returned[1], root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _current=lifetime.base)
    current()
    _same(custody.planner.bootstrap_bytes, inputs.planner_original, work, "original activation planner")
    for actual, expected, label in (
            (custody.release_intent_digest, selected_intent.intent_digest, "intent"),
            (custody.activation_request_digest, release["activationRequestDigest"], "activation request"),
            (custody.activation_operation_id, release["activationOperationId"], "activation operation"),
            (custody.consume_request_digest, release["consumeRequestDigest"], "consume request"),
            (custody.delivery_envelope_digest, release["deliveryEnvelopeDigest"], "encrypted envelope"),
            (custody.delivery_scope, release["deliveryScope"], "delivery scope"),
            (custody.receiver_identity, scope["receiverIdentity"], "receiver"),
            (custody.planner.configuration_digest, scope["configurationDigest"], "configuration"),
            (custody.planner.generation["digest"], scope["generationDigest"], "generation"),
            (custody.planner.runtime_closure_digest, scope["runtimeClosureDigest"], "runtime closure")):
        plan._same(actual, expected, work, "recovery proof independently joined custody " + label)
    if not historical:
        lifetime.attach(proof.bootstrap.planner_bootstrap._launch_guard(custody.attestation_interval,
            custody.opening_sample, lifetime.base, work))
        lifetime.narrow(custody.attestation_interval[1], custody.planner.maximum_plan_age_ns,
            custody.planner.maximum_clock_skew_ns)
    evidence = {"releaseCustodyDigest": plan._frame(proof.contract.CUSTODY_IDENTITY_DOMAIN,
            (returned[1],), work), "releaseIntentDigest": selected_intent.intent_digest,
        "stateReceiptDigest": plan._frame(state.RECEIPT_IDENTITY_DOMAIN,
            (inputs.completion_originals[3],), work)}
    verify = proof._verify_historical_on_work if historical else proof._verify_on_work
    current()
    admitted = verify(proof_bytes=returned[2], enrollment_bytes=returned[3],
        root_public_key=root, forbidden_public_keys=policy.forbidden_public_keys,
        expected_scope=scope, expected_release=release, expected_evidence=evidence,
        expected_intent_interval=selected_intent._interval, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    expected_type = proof._HistoricalProofEvidence if historical else proof._AdmittedProof
    if type(admitted) is not expected_type:
        _fail("recovery proof lacks genuine original signature admission")
    intent_source._contain_original_interval(inputs, admitted.payload)
    current()
    lifetime.attach(admitted.live)
    if not historical:
        lifetime.narrow(min(admitted.payload["expiresAtEpochNs"],
            admitted.payload["issuedAtEpochNs"] + age), age, skew)
    result = _ProofContinuation(_CONSTRUCTION, selected_intent, lifetime, returned)
    return _require_proof(result)
