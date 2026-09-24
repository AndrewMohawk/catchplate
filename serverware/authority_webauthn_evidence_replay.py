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

from dataclasses import dataclass

from serverware import authority_audit_capacity as capacity
from serverware import authority_request_commitment as commitment
from serverware import authority_transition_webauthn_registration_admission as registration
from serverware import authority_transition_webauthn_installation_admission as installation
from serverware import authority_webauthn_registration_inputs as registration_inputs
from serverware import authority_webauthn_installation_inputs as installation_inputs
from serverware import authority_webauthn_evidence_input_wire as wire


evidence, authority, core = registration.evidence, registration.authority, registration.core
_TRANSITION_FIELDS = frozenset({"mutations", "result", "kernelWorkUnits", "workUnits"})


class WebAuthnEvidenceReplayError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _EvidenceReplayObservation:
    """Actual replay observations, not proof, custody or execution authority."""

    kernel: core.KernelTransition
    queries: tuple
    work_units: int
    inputs_digest: str


def _replay_on_work(*, operation, request, selected_rows, database_now, inputs_bytes,
        expected_inputs_digest, expected_transition, public_key, expected_identity,
        expected_spki_digest, maximum_age_ns, maximum_clock_skew_ns,
        rp_id, origin, installation_target_digest, work):
    evidence.capture._SharedLedger(work)
    if type(operation) is not str or operation not in (registration.OPERATION, installation.OPERATION):
        raise WebAuthnEvidenceReplayError("evidence replay operation is not source fixed")
    adapter = registration if operation == registration.OPERATION else installation
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
    actual = owned["request"]
    if type(actual) is not dict or actual.get("operation") != operation or actual.get("handler") != adapter.HANDLER:
        raise WebAuthnEvidenceReplayError("evidence replay request differs from the fixed operation")
    adapter._arguments(actual.get("arguments"), work)
    digest = commitment._typed_request_digest(actual, work=work)
    if commitment._request_different(digest, actual.get("requestDigest"), work=work):
        raise WebAuthnEvidenceReplayError("evidence replay typed request commitment changed")
    work.prepare_utf8(operation)
    work.prepare_utf8(digest)
    work.charge(hashes=1)
    if commitment._request_different(commitment.operation_id(operation, digest), actual.get("operationId"), work=work):
        raise WebAuthnEvidenceReplayError("evidence replay operation commitment changed")
    inputs_digest = wire._digest_on_work(inputs_bytes, work)
    evidence.plan._same(inputs_digest, owned["expectedInputsDigest"], work,
        "evidence originals differ from the independent historical input commitment")
    evidence.keys._public_binding(public_key, owned["spkiDigest"], work)
    queries = adapter._query_recipe_on_work(arguments=actual["arguments"], work=work)
    work.prepare_copy(owned["selected"])
    context = core.KernelContext(operation, actual["arguments"], tuple(owned["selected"]),
        wire._from_epoch_us(cutoff_us), digest)
    if operation == registration.OPERATION:
        originals = registration_inputs._decode_on_work(inputs_bytes, work=work)
        evidence.plan._same((originals["verification_context"].rp_id, originals["verification_context"].origin),
            (owned["rpId"], owned["origin"]), work,
            "retained registration RP/origin differs from independent configuration")
        kernel = registration._kernel_transition_on_work(context, **originals,
            public_key=public_key, expected_signer_identity=owned["identity"],
            expected_signer_spki_digest=owned["spkiDigest"], maximum_age_ns=owned["maximumAgeNs"],
            maximum_clock_skew_ns=owned["maximumClockSkewNs"], work=work)
    else:
        originals = installation_inputs._decode_on_work(inputs_bytes, work=work)
        kernel = installation._kernel_transition_on_work(context, **originals,
            installation_target_digest=owned["installationTargetDigest"], installer_public_key=public_key,
            expected_installer_identity=owned["identity"], expected_installer_spki_digest=owned["spkiDigest"],
            maximum_age_ns=owned["maximumAgeNs"], maximum_clock_skew_ns=owned["maximumClockSkewNs"], work=work)
    total_work = capacity.transition_work_units(operation=operation,
        query_work_units=sum(query.work_units for query in queries),
        kernel_work_units=kernel.work_units, mutations=kernel.mutations)
    work.prepare_copy(kernel.mutations)
    evidence.plan._same({"mutations": list(kernel.mutations), "result": kernel.result,
        "kernelWorkUnits": kernel.work_units, "workUnits": total_work}, expected, work,
        "genuine evidence replay differs from the complete historical transition")
    return _EvidenceReplayObservation(kernel, queries, total_work, inputs_digest)


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
