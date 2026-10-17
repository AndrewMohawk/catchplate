"""Genuine historical semantic replay of retained admission inputs.

An independently admitted historical input commitment, typed request, selected
rows/database cutoff and signer policy are prerequisites, not authority this
module manufactures. Decoding retained roots or committed-stage descriptors
does not authenticate their provenance. The exact input commitment must come
from the historical admission boundary, not be copied from untrusted storage.

Replay reconstructs original ceremony/installation inputs and invokes the real
purpose kernel, including actual attestation/semantic/signature verification.
It then compares complete effects and both business work totals. This is not
selected-row proof replay, current-root admission, durable storage, signing or
execution. It neither extends v3 nor reuses the revocation-only v4 protocol.
No registry entry, SQL, clock sample or fresh work allowance is introduced.
"""
from __future__ import annotations

from catchplate import authority_webauthn_evidence_computation as computation


registration, installation, wire = computation.registration, computation.installation, computation.wire
evidence, authority, core = computation.evidence, computation.authority, computation.core
_TRANSITION_FIELDS = frozenset({"mutations", "result", "kernelWorkUnits", "workUnits"})


class WebAuthnEvidenceReplayError(ValueError):
    pass


# Preserve the existing observation type reference without wrapping a genuine
# computation result in a new successful-proof carrier.
_EvidenceReplayObservation = computation._EvidenceComputationObservation


def _replay_on_work(*, operation, request, selected_rows, database_now, inputs_bytes,
        expected_inputs_digest, expected_transition, public_key, expected_identity,
        expected_spki_digest, maximum_age_ns, maximum_clock_skew_ns,
        rp_id, origin, installation_target_digest, work):
    evidence.capture._SharedLedger(work)
    if type(operation) is not str or operation not in (registration.OPERATION, installation.OPERATION):
        raise WebAuthnEvidenceReplayError("evidence replay operation is not source fixed")
    spec = authority.operation_spec(operation)
    if (type(selected_rows) is not tuple or len(selected_rows) > spec["maximumBusinessQueryRows"]
            or any(type(row) is not dict for row in selected_rows)
            or not isinstance(public_key, evidence.keys.Ed25519PublicKey)):
        raise WebAuthnEvidenceReplayError("evidence replay requires exact rows and an independently pinned key")
    # Retain immutable originals/time and own every mutable expectation before
    # decoder reconstruction, native attestation or public-key callbacks.
    wire._raw(inputs_bytes, 2, wire.MAX_BYTES)
    cutoff_us = wire._to_epoch_us(database_now)
    registration.registration._now(database_now)
    work.prepare_copy(selected_rows)
    owned = wire._capture({"request": request, "selected": list(selected_rows),
        "expectedInputsDigest": expected_inputs_digest, "expectedTransition": expected_transition,
        "identity": expected_identity, "spkiDigest": expected_spki_digest,
        "maximumAgeNs": maximum_age_ns, "maximumClockSkewNs": maximum_clock_skew_ns,
        "rpId": rp_id, "origin": origin, "installationTargetDigest": installation_target_digest}, work)
    shape = evidence.plan.contract
    shape._digest(owned["expectedInputsDigest"])
    shape._digest(owned["spkiDigest"])
    evidence._identity(owned["identity"])
    shape._integer(owned["maximumAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(owned["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if operation == registration.OPERATION:
        shape._text(owned["rpId"], 4096)
        shape._text(owned["origin"], 8192)
        if owned["installationTargetDigest"] is not None:
            raise WebAuthnEvidenceReplayError("registration replay cannot use an installation target")
    else:
        shape._digest(owned["installationTargetDigest"])
        if owned["rpId"] is not None or owned["origin"] is not None:
            raise WebAuthnEvidenceReplayError("installation replay cannot use a registration RP")
    expected = owned["expectedTransition"]
    shape._object(expected, _TRANSITION_FIELDS, "expected historical evidence transition")
    shape._array(expected["mutations"], spec["maximumBusinessMutations"], "expected evidence mutations")
    shape._integer(expected["kernelWorkUnits"], spec["maximumBusinessWorkUnits"], minimum=1)
    shape._integer(expected["workUnits"], spec["maximumWorkUnits"], minimum=1)
    # Construction holds independently admitted purpose policy; it is not a
    # successful verification. The fixed configured method always invokes the
    # same original-input computation used by live acquisition on this work.
    from catchplate import authority_webauthn_evidence_kernel as configured_kernel
    from catchplate import authority_transition_registry as registry

    program = registry.successor_program(operation)
    kernel = program.kernel_factory(public_key=public_key,
        expected_identity=owned["identity"], expected_spki_digest=owned["spkiDigest"],
        maximum_age_ns=owned["maximumAgeNs"], maximum_clock_skew_ns=owned["maximumClockSkewNs"],
        rp_id=owned["rpId"], origin=owned["origin"], installation_target_digest=owned["installationTargetDigest"])
    work.prepare_copy(owned["selected"])
    try:
        evaluated = configured_kernel.EvidenceAdmissionKernel.transition_on_work(kernel,
            request=owned["request"], selected_rows=tuple(owned["selected"]),
            database_now=wire._from_epoch_us(cutoff_us), inputs_bytes=inputs_bytes,
            expected_inputs_digest=owned["expectedInputsDigest"], work=work)
    except computation.WebAuthnEvidenceComputationError as exc:
        raise WebAuthnEvidenceReplayError(str(exc)) from exc
    work.prepare_copy(evaluated.kernel.mutations)
    evidence.plan._same({"mutations": list(evaluated.kernel.mutations), "result": evaluated.kernel.result,
        "kernelWorkUnits": evaluated.kernel.work_units, "workUnits": evaluated.work_units}, expected, work,
        "genuine evidence replay differs from the complete historical transition")
    return evaluated


def _replay_registration_on_work(*, request, selected_rows, database_now, inputs_bytes,
        expected_inputs_digest, expected_transition, public_key, expected_identity,
        expected_spki_digest, maximum_age_ns, maximum_clock_skew_ns, rp_id, origin, work):
    return _replay_on_work(operation=registration.OPERATION, request=request,
        selected_rows=selected_rows, database_now=database_now, inputs_bytes=inputs_bytes,
        expected_inputs_digest=expected_inputs_digest, expected_transition=expected_transition,
        public_key=public_key, expected_identity=expected_identity, expected_spki_digest=expected_spki_digest,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns,
        rp_id=rp_id, origin=origin, installation_target_digest=None, work=work)


def _replay_installation_on_work(*, request, selected_rows, database_now, inputs_bytes,
        expected_inputs_digest, expected_transition, public_key, expected_identity,
        expected_spki_digest, maximum_age_ns, maximum_clock_skew_ns, installation_target_digest, work):
    return _replay_on_work(operation=installation.OPERATION, request=request,
        selected_rows=selected_rows, database_now=database_now, inputs_bytes=inputs_bytes,
        expected_inputs_digest=expected_inputs_digest, expected_transition=expected_transition,
        public_key=public_key, expected_identity=expected_identity, expected_spki_digest=expected_spki_digest,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns,
        rp_id=None, origin=None, installation_target_digest=installation_target_digest, work=work)
