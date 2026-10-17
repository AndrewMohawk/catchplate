"""Configured signed-original owners for three genuine successor acquisitions.

Every call holds its read configuration, signer and caller graphs before key,
native or database callbacks. One real live window spans original-input
encoding, acquisition, proof replay and signing. Its deadline is narrowed by
the original evidence expiry and configured plan age without rewriting the
independently admitted evaluation time or invocation deadline. The real read
owner closes all scopes before its result is packaged; genuine offline proof
and semantic replay occurs once inside the signed-plan producer.

Returned originals are ordinary immutable observations, not persistence,
current-root admission, reservation, execution or public-handler authority.
All phases use the original caller work, with no replacement allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_webauthn_transition_planning as planning
from catchplate import authority_webauthn_transition_proof_production as packing
from catchplate import authority_webauthn_transition_plan as plan


evidence, clock = planning.evidence, plan.clock
_IDENTITY_FIELDS = planning._IDENTITY_FIELDS
_READ_OWNERS = {
    planning.registration.OPERATION: planning.RegistrationTransitionPlanner,
    planning.stage.OPERATION: planning.TrustStageTransitionPlanner,
    planning.completion.OPERATION: planning.TrustCompletionTransitionPlanner,
}


class WebAuthnTransitionPlanOwnerError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _ProducedTransitionPlan:
    envelope_bytes: bytes
    proof_bytes: bytes
    inputs_bytes: bytes
    context_bytes: bytes


def _configuration(values):
    """Validate held immutable configuration without key or driver callbacks."""
    if type(values) is not tuple or len(values) != 9:
        raise WebAuthnTransitionPlanOwnerError("transition plan configuration is not exact")
    operation, owner_type, read_config, private, public, identity, spki, digest, age = values
    if type(operation) is not str or owner_type is not _READ_OWNERS.get(operation):
        raise WebAuthnTransitionPlanOwnerError("transition plan read owner is not source fixed")
    planning._configuration(operation, read_config)
    if (not isinstance(private, evidence.Ed25519PrivateKey)
            or not isinstance(public, evidence.keys.Ed25519PublicKey)
            or type(identity) is not tuple or len(identity) != 3):
        raise WebAuthnTransitionPlanOwnerError("transition plan signing pins are not exact")
    for value in (*identity, spki, digest):
        evidence.plan.contract._digest(value)
    evidence.plan.contract._integer(age, planning.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    return values


def _read_owner(configured):
    """Reconstruct only the actual fixed owner from its held validated tuple."""
    operation, owner_type, values = configured[:3]
    common = {"read_dsn": values[0], "connect_timeout_seconds": values[1],
        "database_identity": values[2], "maximum_age_ns": values[-2],
        "maximum_clock_skew_ns": values[-1]}
    identity = dict(zip(_IDENTITY_FIELDS, values[4]))
    if operation == planning.registration.OPERATION:
        return owner_type(**common, evidence_public_key=values[3], expected_signer_identity=identity,
            expected_signer_spki_digest=values[5], expected_rp_id=values[6], expected_origin=values[7])
    if operation == planning.stage.OPERATION:
        return owner_type(**common, verifier_public_key=values[3], verifier_identity=identity,
            expected_candidate_signing_key_id=values[5], development_enabled=values[6],
            require_approval=values[7], require_approver_webauthn=values[8])
    return owner_type(**common, installer_public_key=values[3], expected_installer_identity=identity,
        expected_installer_spki_digest=values[5], installation_target_digest=values[6])


def _evidence_expiry(raw, purpose, work):
    # Decoding a closed original only narrows the live window. Genuine
    # acquisition and the later proof replay still authenticate this original.
    value = evidence._decode_on_work(raw, work)
    if value["purpose"] != purpose:
        raise WebAuthnTransitionPlanOwnerError("transition original has the wrong configured purpose")
    evidence.plan.contract._integer(value["expiresAtEpochNs"], minimum=1)
    return value["expiresAtEpochNs"]


def _live_cap(value):
    if value is not None:
        evidence.plan.contract._integer(value, minimum=1)
    return value


def _open(configured, owned, expires, work, live_deadline_epoch_ns=None):
    evidence.plan.contract._integer(expires, minimum=1)
    cap = _live_cap(live_deadline_epoch_ns)
    deadline = min(owned["deadlineEpochNs"], expires)
    if cap is not None:
        deadline = min(deadline, cap)
    window = clock._open_on_work(deadline_epoch_ns=deadline,
        maximum_lifetime_ns=configured[8], maximum_clock_skew_ns=configured[2][-1], work=work)
    if abs(owned["nowEpochNs"] - window[0]) > configured[2][-1]:
        raise WebAuthnTransitionPlanOwnerError("original evaluation time differs from the live opening sample")
    return window


def _policy(configured, owned):
    operation, _owner_type, values = configured[:3]
    result = {"nowEpochNs": owned["nowEpochNs"], "deadlineEpochNs": owned["deadlineEpochNs"],
        "maximumAgeNs": values[-2], "maximumClockSkewNs": values[-1]}
    identity = dict(zip(_IDENTITY_FIELDS, values[4]))
    if operation == planning.registration.OPERATION:
        result.update({"signerIdentity": identity, "signerSpkiDigest": values[5],
            "rpId": values[6], "origin": values[7]})
    elif operation == planning.stage.OPERATION:
        result.update({"verifierIdentity": identity, "candidateSigningKeyId": values[5],
            "capabilityId": owned["inputs"]["capabilityId"], "developmentEnabled": values[6],
            "requireApproval": values[7], "requireApproverWebauthn": values[8]})
    else:
        result.update({"installerIdentity": identity, "installerSpkiDigest": values[5],
            "installationTargetDigest": values[6], "committedStage": owned["inputs"]["committedStage"]})
    return result


def _finish(configured, owned, acquisition, inputs_bytes, inputs_digest, window, work):
    clock._check_on_work(window, work=work)
    packed = packing._encode_from_acquisition_on_work(acquisition=acquisition,
        inputs_bytes=inputs_bytes, inputs_digest=inputs_digest, request=owned["request"],
        business_before_roots=owned["businessBeforeRoots"],
        authorization_before_roots=owned["authorizationBeforeRoots"],
        counted_before_heads=owned["expectedCountedHeads"], policy=_policy(configured, owned), work=work)
    # Encoding produces ordinary bytes and an owned independent expectation
    # graph, not a proof token. Only the actual plan signer below replays it.
    proof_bytes, proof_expected = packed.proof_bytes, packed.expectations
    expected = {"proofExpectations": proof_expected, "configurationDigest": configured[7],
        "plannerIdentity": dict(zip(_IDENTITY_FIELDS, configured[5])),
        "plannerSpkiDigest": configured[6], "maximumPlanAgeNs": configured[8]}
    context_bytes = plan.context._encode_on_work(expectations=expected, work=work)
    proof_digest = evidence.plan._frame(plan.proof.contract.IDENTITY_DOMAIN, (proof_bytes,), work)
    context_digest = plan.context._digest_on_work(context_bytes, work)
    payload = {"schema": plan.contract.SCHEMA, "sourceRevision": planning.authority.SOURCE_REVISION,
        "operation": configured[0], "configurationDigest": configured[7],
        "plannerIdentity": expected["plannerIdentity"], "plannerSpkiDigest": configured[6],
        "proofDigest": proof_digest, "proofByteCount": len(proof_bytes),
        "inputsDigest": inputs_digest, "inputsByteCount": len(inputs_bytes),
        "contextDigest": context_digest, "contextByteCount": len(context_bytes),
        "issuedAtEpochNs": window[0], "expiresAtEpochNs": window[3]}
    envelope = plan._produce_on_work(payload=payload, proof_bytes=proof_bytes,
        inputs_bytes=inputs_bytes, context_bytes=context_bytes, expectations=expected,
        planner_private_key=configured[3], planner_public_key=configured[4],
        public_key=configured[2][3], live_window=window, work=work)
    clock._check_on_work(window, work=work)
    return _ProducedTransitionPlan(envelope, proof_bytes, inputs_bytes, context_bytes)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class TransitionPlanOwner:
    """An inert, source-fixed reader and separately admitted plan signer."""

    _configured: tuple

    def __init__(self, *, read_planner, planner_private_key, planner_public_key,
            expected_planner_identity, expected_planner_spki_digest, configuration_digest,
            maximum_plan_age_ns):
        operation = next((operation for operation, owner_type in _READ_OWNERS.items()
            if type(read_planner) is owner_type), None)
        if operation is None:
            raise WebAuthnTransitionPlanOwnerError("transition plan requires an actual configured read owner")
        owner_type = _READ_OWNERS[operation]
        read_config = planning._snapshot(read_planner, owner_type, operation)
        evidence._identity(expected_planner_identity)
        values = (operation, owner_type, read_config, planner_private_key, planner_public_key,
            tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS),
            expected_planner_spki_digest, configuration_digest, maximum_plan_age_ns)
        object.__setattr__(self, "_configured", _configuration(values))

    @property
    def operation(self):
        return _configuration(self._configured)[0]

    def _snapshot(self, operation):
        if type(self) is not TransitionPlanOwner:
            raise WebAuthnTransitionPlanOwnerError("transition plan owner type changed")
        configured = _configuration(self._configured)
        if configured[0] != operation:
            raise WebAuthnTransitionPlanOwnerError("transition plan method differs from its configured operation")
        return configured

    def produce_registration(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, now_epoch_ns, deadline_epoch_ns, work,
            live_deadline_epoch_ns=None):
        configured = self._snapshot(planning.registration.OPERATION)
        live_cap = _live_cap(live_deadline_epoch_ns)
        owned = planning._capture(configured[0], request=request,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, inputs={}, work=work)
        original = planning.registration._encoded_original(
            owned["request"]["arguments"]["attestation_envelope_base64url"], evidence.MAX_EVIDENCE_BYTES, work)
        expiry = _evidence_expiry(original, "registration-attestation", work)
        reader = _read_owner(configured)
        window = _open(configured, owned, expiry, work, live_cap)
        inputs_bytes = planning.registration_replay._encode_inputs_on_work(work=work)
        inputs_digest = planning.originals._digest_on_work(inputs_bytes, work)
        clock._check_on_work(window, work=work)
        acquired = planning.RegistrationTransitionPlanner.acquire(reader,
            request=owned["request"], business_before_roots=owned["businessBeforeRoots"],
            authorization_before_roots=owned["authorizationBeforeRoots"],
            expected_counted_heads=owned["expectedCountedHeads"], now_epoch_ns=owned["nowEpochNs"],
            deadline_epoch_ns=owned["deadlineEpochNs"], work=work)
        return _finish(configured, owned, acquired, inputs_bytes, inputs_digest, window, work)

    def produce_stage(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, assertion_evidence, capability_id, candidate_bundle_bytes,
            candidate_verification_context, now_epoch_ns, deadline_epoch_ns, work,
            live_deadline_epoch_ns=None):
        configured = self._snapshot(planning.stage.OPERATION)
        live_cap = _live_cap(live_deadline_epoch_ns)
        original = planning._raw(candidate_bundle_bytes, 1, planning.candidate.bundle_core.MAX_INPUT_BYTES)
        context_fields = planning._hold_candidate(candidate_verification_context)
        owned = planning._capture(configured[0], request=request,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns,
            inputs={"assertion": assertion_evidence, "capabilityId": capability_id}, work=work)
        evidence.plan.contract._object(owned["inputs"]["assertion"],
            planning.stage_replay.assertion.EVIDENCE_FIELDS, "original stage assertion")
        evidence.plan.contract._digest(owned["inputs"]["capabilityId"])
        if planning.registration._now(context_fields[2]) != owned["nowEpochNs"]:
            raise WebAuthnTransitionPlanOwnerError("original candidate time differs from the evaluation instant")
        reader = _read_owner(configured)
        window = _open(configured, owned, owned["inputs"]["assertion"]["expiresAtEpochNs"], work, live_cap)
        held_context = planning.candidate.bundle_core.TrustVerificationContext(*context_fields, _work=work)
        inputs_bytes = planning.stage_replay._encode_inputs_on_work(
            assertion_evidence=owned["inputs"]["assertion"], candidate_bundle_bytes=original,
            candidate_verification_context=held_context, work=work)
        inputs_digest = planning.originals._digest_on_work(inputs_bytes, work)
        clock._check_on_work(window, work=work)
        acquired = planning.TrustStageTransitionPlanner.acquire(reader,
            request=owned["request"], business_before_roots=owned["businessBeforeRoots"],
            authorization_before_roots=owned["authorizationBeforeRoots"],
            expected_counted_heads=owned["expectedCountedHeads"], assertion_evidence=owned["inputs"]["assertion"],
            capability_id=owned["inputs"]["capabilityId"], candidate_bundle_bytes=original,
            candidate_verification_context=held_context, now_epoch_ns=owned["nowEpochNs"],
            deadline_epoch_ns=owned["deadlineEpochNs"], work=work)
        return _finish(configured, owned, acquired, inputs_bytes, inputs_digest, window, work)

    def produce_completion(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, installation_envelope_bytes, installed_bundle_bytes, installed_state_bytes,
            expected_committed_stage, now_epoch_ns, deadline_epoch_ns, work,
            live_deadline_epoch_ns=None):
        configured = self._snapshot(planning.completion.OPERATION)
        live_cap = _live_cap(live_deadline_epoch_ns)
        raw = (planning._raw(installation_envelope_bytes, 2, evidence.MAX_EVIDENCE_BYTES),
            planning._raw(installed_bundle_bytes, 2, planning.completion.bundle_core.MAX_INSTALLATION_BYTES),
            planning._raw(installed_state_bytes, 2, planning.completion.bundle_core.MAX_STATE_BYTES))
        owned = planning._capture(configured[0], request=request,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, inputs={"committedStage": expected_committed_stage}, work=work)
        planning.completion._object(owned["inputs"]["committedStage"], planning.completion._STAGE_FIELDS,
            "independently committed stage")
        expiry = _evidence_expiry(raw[0], "trust-installation", work)
        reader = _read_owner(configured)
        window = _open(configured, owned, expiry, work, live_cap)
        inputs_bytes = planning.completion_replay._encode_inputs_on_work(installation_envelope_bytes=raw[0],
            installed_bundle_bytes=raw[1], installed_state_bytes=raw[2], work=work)
        inputs_digest = planning.originals._digest_on_work(inputs_bytes, work)
        clock._check_on_work(window, work=work)
        acquired = planning.TrustCompletionTransitionPlanner.acquire(reader,
            request=owned["request"], business_before_roots=owned["businessBeforeRoots"],
            authorization_before_roots=owned["authorizationBeforeRoots"],
            expected_counted_heads=owned["expectedCountedHeads"], installation_envelope_bytes=raw[0],
            installed_bundle_bytes=raw[1], installed_state_bytes=raw[2],
            expected_committed_stage=owned["inputs"]["committedStage"], now_epoch_ns=owned["nowEpochNs"],
            deadline_epoch_ns=owned["deadlineEpochNs"], work=work)
        return _finish(configured, owned, acquired, inputs_bytes, inputs_digest, window, work)

    def produce_originals(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, inputs_bytes, now_epoch_ns, deadline_epoch_ns,
            invocation, work, live_deadline_epoch_ns=None):
        """Decode actual family originals, then invoke its genuine fixed producer.

        The enclosing signed-request receiver supplies authenticated invocation
        data. Neither this byte codec nor a prior-success carrier replaces the
        real acquisition and proof replay performed by the family producer.
        """
        if type(self) is not TransitionPlanOwner:
            raise WebAuthnTransitionPlanOwnerError("transition plan owner type changed")
        configured = _configuration(self._configured)
        cap = _live_cap(live_deadline_epoch_ns)
        original = planning._raw(inputs_bytes, 2, planning.originals.wire.MAX_BYTES)
        owned = planning._capture(configured[0], request=request,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, inputs=invocation, work=work)
        operation = configured[0]
        fields = (frozenset() if operation == planning.registration.OPERATION else
            frozenset({"capabilityId"}) if operation == planning.stage.OPERATION else
            frozenset({"committedStage"}))
        evidence.plan.contract._object(owned["inputs"], fields, "authenticated transition invocation")
        # Reconstruct from held configuration before any decoder/native call;
        # subsequent mutation of the original owner's slots cannot retarget it.
        private_owner = TransitionPlanOwner(read_planner=_read_owner(configured),
            planner_private_key=configured[3], planner_public_key=configured[4],
            expected_planner_identity=dict(zip(_IDENTITY_FIELDS, configured[5])),
            expected_planner_spki_digest=configured[6], configuration_digest=configured[7],
            maximum_plan_age_ns=configured[8])
        digest = planning.originals._digest_on_work(original, work)
        common = {"request": owned["request"], "business_before_roots": owned["businessBeforeRoots"],
            "authorization_before_roots": owned["authorizationBeforeRoots"],
            "expected_counted_heads": owned["expectedCountedHeads"], "now_epoch_ns": owned["nowEpochNs"],
            "deadline_epoch_ns": owned["deadlineEpochNs"], "live_deadline_epoch_ns": cap, "work": work}
        if operation == planning.registration.OPERATION:
            decoded = planning.originals._decode_on_work(operation, original, digest, work)
            evidence.plan.contract._object(decoded, frozenset(), "registration original inputs")
            result = TransitionPlanOwner.produce_registration(private_owner, **common)
        elif operation == planning.stage.OPERATION:
            decoded = planning.originals._decode_on_work(operation, original, digest, work)
            instant = planning.stage_replay._inputs_shape(decoded, work)
            context = decoded["candidateVerificationContext"]
            core, wire = planning.candidate.bundle_core, planning.originals.wire
            bundle = wire._unpack_raw(decoded["candidateBundle"], minimum=1,
                maximum=core.MAX_INPUT_BYTES, work=work)
            public_der = wire._unpack_raw(context["publicKeyDer"], minimum=1,
                maximum=core.MAX_PUBLIC_KEY_BYTES, work=work)
            schema = wire._unpack_raw(context["schema"], minimum=1,
                maximum=core.MAX_SCHEMA_BYTES, work=work)
            if planning.registration._now(instant) != owned["nowEpochNs"]:
                raise WebAuthnTransitionPlanOwnerError("original candidate time differs from the evaluation instant")
            evidence.plan._same(core.sha256_prefixed(public_der, _work=work), configured[2][5], work,
                "original candidate DER differs from the configured signing key")
            held_context = core.TrustVerificationContext(public_der, schema, instant, _work=work)
            result = TransitionPlanOwner.produce_stage(private_owner, **common,
                assertion_evidence=decoded["assertionEvidence"], capability_id=owned["inputs"]["capabilityId"],
                candidate_bundle_bytes=bundle, candidate_verification_context=held_context)
        else:
            raw = planning.completion_replay._decode_inputs_on_work(original, digest, work)
            result = TransitionPlanOwner.produce_completion(private_owner, **common,
                installation_envelope_bytes=raw[0], installed_bundle_bytes=raw[1], installed_state_bytes=raw[2],
                expected_committed_stage=owned["inputs"]["committedStage"])
        work.charge(input_bytes=len(original) + len(result.inputs_bytes))
        if original != result.inputs_bytes:
            raise WebAuthnTransitionPlanOwnerError("transition production changed the original input bytes")
        return result
