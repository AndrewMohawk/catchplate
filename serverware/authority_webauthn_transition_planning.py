"""Configured read owners for the three WebAuthn successor transitions.

Each inert owner holds one fixed operation's database and verification policy.
An invocation owns all mutable request/root/original-input graphs before any
native constructor, key or database callback. The actual read scope supplies
its admitted manifest and source trace; the genuine acquisition repeats query,
membership, semantic, capacity and write-root computation on the same work.
Results escape only after normal cursor, transaction and connection exits.
The separate acquire_originals methods additionally retain canonical original
inputs before database acquisition, package the actual raw proof material after
closing the scope, and repeat genuine primary/count/query, semantic/capacity
and indexed-write computation. Unsigned proof bytes do not sign plans or
establish independent historical admission.

Configuration, request/current-root/time, assertion/capability and committed
stage or physical readback provenance remain independent caller obligations.
No caller cursor, SQL, manifest, successful-proof object or replacement budget
is accepted. Ordinary acquisition observations are not signed plans, custody,
execution authority or registry activation, and do not extend legacy v3.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from serverware import authority_index_heads as heads
from serverware import authority_query_reads as reads
from serverware import authority_request_commitment as commitment
from serverware import authority_revocation_planning as planning
from serverware import authority_transition_webauthn_registration as registration
from serverware import authority_transition_webauthn_trust_stage as stage
from serverware import authority_transition_webauthn_completion as completion
from serverware import authority_webauthn_trust_candidate as candidate
from serverware import authority_webauthn_transition_inputs as originals
from serverware import authority_webauthn_registration_replay as registration_replay
from serverware import authority_webauthn_stage_replay as stage_replay
from serverware import authority_webauthn_completion_replay as completion_replay


authority, evidence = registration.authority, registration.evidence
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_CONFIGURATION_LENGTHS = {registration.OPERATION: 10, stage.OPERATION: 11, completion.OPERATION: 9}


class WebAuthnTransitionPlanningError(ValueError):
    pass


def _identity(value):
    evidence._identity(value)
    return tuple(value[name] for name in _IDENTITY_FIELDS)


def _configuration(operation, values):
    """Validate immutable source configuration without key/driver callbacks."""
    if (operation not in _CONFIGURATION_LENGTHS or type(values) is not tuple
            or len(values) != _CONFIGURATION_LENGTHS[operation]):
        raise WebAuthnTransitionPlanningError("WebAuthn transition configuration is not exact")
    planning._validate_read_scope_configuration(values[:3])
    dsn, timeout, database, key, identity = values[:5]
    planning.reader._bounded_text(dsn, 65536)
    if "\n" in dsn or "\r" in dsn or timeout < 2:
        raise WebAuthnTransitionPlanningError("WebAuthn transition connection settings are invalid")
    planning.reader._bounded_text(database[0], 63)
    for value in database[1:4]:
        planning.reader._bounded_text(value, 4096)
    if (not isinstance(key, evidence.keys.Ed25519PublicKey)
            or type(identity) is not tuple or len(identity) != 3):
        raise WebAuthnTransitionPlanningError("WebAuthn transition signer pins are not exact")
    for digest in identity:
        evidence.plan.contract._digest(digest)
    evidence.plan.contract._digest(values[5])
    if operation == registration.OPERATION:
        planning.reader._bounded_text(values[6], 4096)
        planning.reader._bounded_text(values[7], 8192)
    elif operation == stage.OPERATION:
        if any(type(value) is not bool for value in values[6:9]):
            raise WebAuthnTransitionPlanningError("trust stage policies are not exact booleans")
    else:
        evidence.plan.contract._digest(values[6])
    registration._integer(values[-2], "maximum age", 1, authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    registration._integer(values[-1], "clock skew", 0, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    return values


def _snapshot(owner, owner_type, operation):
    if type(owner) is not owner_type:
        raise WebAuthnTransitionPlanningError("WebAuthn transition owner type changed")
    return _configuration(operation, owner._configured)


def _capture(operation, *, request, business_before_roots, authorization_before_roots,
        expected_counted_heads, now_epoch_ns, deadline_epoch_ns, inputs, work):
    evidence.capture._SharedLedger(work)
    if (type(request) is not dict or type(expected_counted_heads) is not tuple
            or not 1 <= len(expected_counted_heads) <= heads.MAX_HEADS
            or operation == completion.OPERATION and len(expected_counted_heads) != 3):
        raise WebAuthnTransitionPlanningError("WebAuthn transition invocation is not source bounded")
    owned = reads._CopyBudget(work).copy({"request": request,
        "businessBeforeRoots": business_before_roots, "authorizationBeforeRoots": authorization_before_roots,
        "expectedCountedHeads": expected_counted_heads, "nowEpochNs": now_epoch_ns,
        "deadlineEpochNs": deadline_epoch_ns, "inputs": inputs})
    actual = owned["request"]
    if (actual.get("operation") != operation
            or actual.get("handler") != authority.operation_spec(operation)["handler"]):
        raise WebAuthnTransitionPlanningError("WebAuthn transition request differs from its configured operation")
    if operation == registration.OPERATION:
        registration._arguments(actual.get("arguments"), work)
    elif operation == stage.OPERATION:
        stage._arguments(actual.get("arguments"), work)
    else:
        completion._object(actual.get("arguments"), completion._ARGUMENT_FIELDS, "completion arguments")
    digest = commitment._typed_request_digest(actual, work=work)
    if commitment._request_different(digest, actual.get("requestDigest"), work=work):
        raise WebAuthnTransitionPlanningError("WebAuthn transition request digest changed")
    work.prepare_utf8(operation)
    work.prepare_utf8(digest)
    work.charge(hashes=1)
    if commitment._request_different(commitment.operation_id(operation, digest), actual.get("operationId"), work=work):
        raise WebAuthnTransitionPlanningError("WebAuthn transition operation ID changed")
    for name in ("nowEpochNs", "deadlineEpochNs"):
        registration._integer(owned[name], name, 1)
    if owned["nowEpochNs"] >= owned["deadlineEpochNs"]:
        raise WebAuthnTransitionPlanningError("WebAuthn transition invocation has expired")
    return owned


def _raw(value, minimum, maximum):
    if type(value) is not bytes or not minimum <= len(value) <= maximum:
        raise WebAuthnTransitionPlanningError("WebAuthn transition requires bounded immutable originals")
    return value


def _hold_candidate(context):
    if type(context) is not candidate.bundle_core.TrustVerificationContext:
        raise WebAuthnTransitionPlanningError("trust stage requires the actual candidate verification context")
    # The exact frozen core instance can be rebound by its owner. Hold only
    # validated immutable members before any invocation/native callback.
    der, schema, verified_at = context.public_key_der, context.schema_bytes, context.verified_at
    _raw(der, 1, candidate.bundle_core.MAX_PUBLIC_KEY_BYTES)
    _raw(schema, 1, candidate.bundle_core.MAX_SCHEMA_BYTES)
    if type(verified_at) is not datetime or verified_at.tzinfo is not timezone.utc:
        raise WebAuthnTransitionPlanningError("candidate verification time is not exact UTC")
    return der, schema, verified_at


def _retain_proof(acquisition, inputs_bytes, inputs_digest, configured, owned, operation, work):
    """Keep the actual owner's held policy; never adopt it from proof bytes."""
    from serverware import authority_webauthn_transition_proof_production as production

    policy = {"nowEpochNs": owned["nowEpochNs"], "deadlineEpochNs": owned["deadlineEpochNs"],
        "maximumAgeNs": configured[-2], "maximumClockSkewNs": configured[-1]}
    identity = dict(zip(_IDENTITY_FIELDS, configured[4]))
    if operation == registration.OPERATION:
        policy.update({"signerIdentity": identity, "signerSpkiDigest": configured[5],
            "rpId": configured[6], "origin": configured[7]})
    elif operation == stage.OPERATION:
        policy.update({"verifierIdentity": identity, "capabilityId": owned["inputs"]["capabilityId"],
            "candidateSigningKeyId": configured[5], "developmentEnabled": configured[6],
            "requireApproval": configured[7], "requireApproverWebauthn": configured[8]})
    elif operation == completion.OPERATION:
        policy.update({"installerIdentity": identity, "installerSpkiDigest": configured[5],
            "installationTargetDigest": configured[6], "committedStage": owned["inputs"]["committedStage"]})
    else:
        raise WebAuthnTransitionPlanningError("proof retention operation is not source fixed")
    return production._package_from_acquisition_on_work(acquisition=acquisition,
        inputs_bytes=inputs_bytes, inputs_digest=inputs_digest, request=owned["request"],
        business_before_roots=owned["businessBeforeRoots"],
        authorization_before_roots=owned["authorizationBeforeRoots"],
        counted_before_heads=owned["expectedCountedHeads"], policy=policy, public_key=configured[3], work=work)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class RegistrationTransitionPlanner:
    _configured: tuple

    def __init__(self, *, read_dsn, connect_timeout_seconds, database_identity,
            evidence_public_key, expected_signer_identity, expected_signer_spki_digest,
            expected_rp_id, expected_origin, maximum_age_ns, maximum_clock_skew_ns):
        configured = _configuration(registration.OPERATION,
            (read_dsn, connect_timeout_seconds, database_identity, evidence_public_key,
                _identity(expected_signer_identity), expected_signer_spki_digest,
                expected_rp_id, expected_origin, maximum_age_ns, maximum_clock_skew_ns))
        object.__setattr__(self, "_configured", configured)

    def acquire(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, now_epoch_ns, deadline_epoch_ns, work):
        return self._acquire(request=request, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, expected_counted_heads=expected_counted_heads,
            now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns, work=work, retain_originals=False)

    def acquire_originals(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, now_epoch_ns, deadline_epoch_ns, work):
        """Acquire actual proofs, then retain inputs and repeat real semantics."""
        return self._acquire(request=request, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, expected_counted_heads=expected_counted_heads,
            now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns, work=work, retain_originals=True)

    def _acquire(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, now_epoch_ns, deadline_epoch_ns, work, retain_originals):
        configured = _snapshot(self, RegistrationTransitionPlanner, registration.OPERATION)
        owned = _capture(registration.OPERATION, request=request,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, inputs={}, work=work)
        if retain_originals:
            inputs_bytes = registration_replay._encode_inputs_on_work(work=work)
            inputs_digest = originals._digest_on_work(inputs_bytes, work)
        evidence.keys._public_binding(configured[3], configured[5], work)
        from serverware import authority_planner as planner

        with planning._read_scope(configured[:3], operation=registration.OPERATION, work=work) as (cursor, manifest, trace):
            result = planner._acquire_registration_transition_on_work(cursor,
                request=owned["request"], manifest=manifest,
                business_before_roots=owned["businessBeforeRoots"],
                authorization_before_roots=owned["authorizationBeforeRoots"],
                expected_counted_heads=owned["expectedCountedHeads"],
                evidence_public_key=configured[3], expected_signer_identity=dict(zip(_IDENTITY_FIELDS, configured[4])),
                expected_signer_spki_digest=configured[5], expected_rp_id=configured[6], expected_origin=configured[7],
                now_epoch_ns=owned["nowEpochNs"], deadline_epoch_ns=owned["deadlineEpochNs"],
                maximum_age_ns=configured[8], maximum_clock_skew_ns=configured[9], query_work=work, trace=trace)
        if not retain_originals:
            return result
        return _retain_proof(result, inputs_bytes, inputs_digest, configured, owned, registration.OPERATION, work)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class TrustStageTransitionPlanner:
    _configured: tuple

    def __init__(self, *, read_dsn, connect_timeout_seconds, database_identity,
            verifier_public_key, verifier_identity, expected_candidate_signing_key_id,
            development_enabled, require_approval, require_approver_webauthn,
            maximum_age_ns, maximum_clock_skew_ns):
        configured = _configuration(stage.OPERATION,
            (read_dsn, connect_timeout_seconds, database_identity, verifier_public_key,
                _identity(verifier_identity), expected_candidate_signing_key_id,
                development_enabled, require_approval, require_approver_webauthn,
                maximum_age_ns, maximum_clock_skew_ns))
        object.__setattr__(self, "_configured", configured)

    def acquire(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, assertion_evidence, capability_id, candidate_bundle_bytes,
            candidate_verification_context, now_epoch_ns, deadline_epoch_ns, work):
        return self._acquire(request=request, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, expected_counted_heads=expected_counted_heads,
            assertion_evidence=assertion_evidence, capability_id=capability_id,
            candidate_bundle_bytes=candidate_bundle_bytes, candidate_verification_context=candidate_verification_context,
            now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns, work=work, retain_originals=False)

    def acquire_originals(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, assertion_evidence, capability_id, candidate_bundle_bytes,
            candidate_verification_context, now_epoch_ns, deadline_epoch_ns, work):
        """Retain candidate/assertion originals, acquire and repeat stage effects."""
        return self._acquire(request=request, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, expected_counted_heads=expected_counted_heads,
            assertion_evidence=assertion_evidence, capability_id=capability_id,
            candidate_bundle_bytes=candidate_bundle_bytes, candidate_verification_context=candidate_verification_context,
            now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns, work=work, retain_originals=True)

    def _acquire(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, assertion_evidence, capability_id, candidate_bundle_bytes,
            candidate_verification_context, now_epoch_ns, deadline_epoch_ns, work, retain_originals):
        configured = _snapshot(self, TrustStageTransitionPlanner, stage.OPERATION)
        original = _raw(candidate_bundle_bytes, 1, candidate.bundle_core.MAX_INPUT_BYTES)
        context_fields = _hold_candidate(candidate_verification_context)
        owned = _capture(stage.OPERATION, request=request,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns,
            inputs={"assertion": assertion_evidence, "capabilityId": capability_id}, work=work)
        if type(owned["inputs"]["assertion"]) is not dict:
            raise WebAuthnTransitionPlanningError("trust stage assertion is not an exact object")
        evidence.plan.contract._digest(owned["inputs"]["capabilityId"])
        if registration._now(context_fields[2]) != owned["nowEpochNs"]:
            raise WebAuthnTransitionPlanningError("candidate time differs from the admitted invocation time")
        observed_key = candidate.bundle_core.sha256_prefixed(context_fields[0], _work=work)
        stage._same(observed_key, configured[5], work,
            "candidate DER differs from the configured signing-key pin")
        # Reconstruction uses only held immutable members after every caller
        # graph is owned; the actual acquisition repeats signature admission.
        held_context = candidate.bundle_core.TrustVerificationContext(*context_fields, _work=work)
        if retain_originals:
            inputs_bytes = stage_replay._encode_inputs_on_work(assertion_evidence=owned["inputs"]["assertion"],
                candidate_bundle_bytes=original, candidate_verification_context=held_context, work=work)
            inputs_digest = originals._digest_on_work(inputs_bytes, work)
        from serverware import authority_planner as planner

        with planning._read_scope(configured[:3], operation=stage.OPERATION, work=work) as (cursor, manifest, trace):
            result = planner._acquire_trust_stage_transition_on_work(cursor,
                request=owned["request"], manifest=manifest,
                business_before_roots=owned["businessBeforeRoots"],
                authorization_before_roots=owned["authorizationBeforeRoots"],
                expected_counted_heads=owned["expectedCountedHeads"],
                assertion_evidence=owned["inputs"]["assertion"],
                verifier_identity=dict(zip(_IDENTITY_FIELDS, configured[4])), verifier_public_key=configured[3],
                capability_id=owned["inputs"]["capabilityId"], candidate_bundle_bytes=original,
                candidate_verification_context=held_context, expected_candidate_signing_key_id=configured[5],
                development_enabled=configured[6], require_approval=configured[7], require_approver_webauthn=configured[8],
                now_epoch_ns=owned["nowEpochNs"], deadline_epoch_ns=owned["deadlineEpochNs"],
                maximum_age_ns=configured[9], maximum_clock_skew_ns=configured[10], query_work=work, trace=trace)
        if not retain_originals:
            return result
        return _retain_proof(result, inputs_bytes, inputs_digest, configured, owned, stage.OPERATION, work)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class TrustCompletionTransitionPlanner:
    _configured: tuple

    def __init__(self, *, read_dsn, connect_timeout_seconds, database_identity,
            installer_public_key, expected_installer_identity, expected_installer_spki_digest,
            installation_target_digest, maximum_age_ns, maximum_clock_skew_ns):
        configured = _configuration(completion.OPERATION,
            (read_dsn, connect_timeout_seconds, database_identity, installer_public_key,
                _identity(expected_installer_identity), expected_installer_spki_digest,
                installation_target_digest, maximum_age_ns, maximum_clock_skew_ns))
        object.__setattr__(self, "_configured", configured)

    def acquire(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, installation_envelope_bytes, installed_bundle_bytes, installed_state_bytes,
            expected_committed_stage, now_epoch_ns, deadline_epoch_ns, work):
        return self._acquire(request=request, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, expected_counted_heads=expected_counted_heads,
            installation_envelope_bytes=installation_envelope_bytes, installed_bundle_bytes=installed_bundle_bytes,
            installed_state_bytes=installed_state_bytes, expected_committed_stage=expected_committed_stage,
            now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns, work=work, retain_originals=False)

    def acquire_originals(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, installation_envelope_bytes, installed_bundle_bytes, installed_state_bytes,
            expected_committed_stage, now_epoch_ns, deadline_epoch_ns, work):
        """Retain installed originals without enrolling committed-stage history."""
        return self._acquire(request=request, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, expected_counted_heads=expected_counted_heads,
            installation_envelope_bytes=installation_envelope_bytes, installed_bundle_bytes=installed_bundle_bytes,
            installed_state_bytes=installed_state_bytes, expected_committed_stage=expected_committed_stage,
            now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns, work=work, retain_originals=True)

    def _acquire(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, installation_envelope_bytes, installed_bundle_bytes, installed_state_bytes,
            expected_committed_stage, now_epoch_ns, deadline_epoch_ns, work, retain_originals):
        configured = _snapshot(self, TrustCompletionTransitionPlanner, completion.OPERATION)
        raw3 = (_raw(installation_envelope_bytes, 2, evidence.MAX_EVIDENCE_BYTES),
            _raw(installed_bundle_bytes, 2, completion.bundle_core.MAX_INSTALLATION_BYTES),
            _raw(installed_state_bytes, 2, completion.bundle_core.MAX_STATE_BYTES))
        owned = _capture(completion.OPERATION, request=request,
            business_before_roots=business_before_roots, authorization_before_roots=authorization_before_roots,
            expected_counted_heads=expected_counted_heads, now_epoch_ns=now_epoch_ns,
            deadline_epoch_ns=deadline_epoch_ns, inputs={"committedStage": expected_committed_stage}, work=work)
        completion._object(owned["inputs"]["committedStage"], completion._STAGE_FIELDS, "committed stage")
        if retain_originals:
            inputs_bytes = completion_replay._encode_inputs_on_work(installation_envelope_bytes=raw3[0],
                installed_bundle_bytes=raw3[1], installed_state_bytes=raw3[2], work=work)
            inputs_digest = originals._digest_on_work(inputs_bytes, work)
        evidence.keys._public_binding(configured[3], configured[5], work)
        from serverware import authority_planner as planner

        with planning._read_scope(configured[:3], operation=completion.OPERATION, work=work) as (cursor, manifest, trace):
            result = planner._acquire_trust_completion_transition_on_work(cursor,
                request=owned["request"], manifest=manifest,
                business_before_roots=owned["businessBeforeRoots"],
                authorization_before_roots=owned["authorizationBeforeRoots"],
                expected_counted_heads=owned["expectedCountedHeads"],
                installation_envelope_bytes=raw3[0], installed_bundle_bytes=raw3[1],
                installed_state_bytes=raw3[2], installation_target_digest=configured[6],
                expected_committed_stage=owned["inputs"]["committedStage"], installer_public_key=configured[3],
                expected_installer_identity=dict(zip(_IDENTITY_FIELDS, configured[4])),
                expected_installer_spki_digest=configured[5], now_epoch_ns=owned["nowEpochNs"],
                deadline_epoch_ns=owned["deadlineEpochNs"], maximum_age_ns=configured[7],
                maximum_clock_skew_ns=configured[8], query_work=work, trace=trace)
        if not retain_originals:
            return result
        return _retain_proof(result, inputs_bytes, inputs_digest, configured, owned, completion.OPERATION, work)
