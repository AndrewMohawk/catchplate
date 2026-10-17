"""Genuine shared computation from original evidence-admission inputs.

Live acquisition and historical replay use this same original-input worker.
The caller independently admits request authority, primary-row proofs/current
roots, original-input commitment and purpose-specific signer policy. Neither
decoded ceremony roots/committed-stage data nor the returned observations
supply that authority. No successful proof or expected-transition DTO is an
input to this computation.

Every variable graph is owned before native/key callbacks. Real request/input
commitments, public SPKI binding, original decoding, attestation/installation
semantics and original evidence signature verification run on the supplied
work. Actual query and kernel work units are derived from those computations.
There is no SQL, registry change, clock sample, signer or replacement allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_request_commitment as commitment
from catchplate import authority_transition_webauthn_registration_admission as registration
from catchplate import authority_transition_webauthn_installation_admission as installation
from catchplate import authority_webauthn_registration_inputs as registration_inputs
from catchplate import authority_webauthn_installation_inputs as installation_inputs
from catchplate import authority_webauthn_evidence_input_wire as wire


evidence, authority, core = registration.evidence, registration.authority, registration.core


class WebAuthnEvidenceComputationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _EvidenceComputationObservation:
    """Actual computation observations, not proof, custody or execution authority."""

    kernel: core.KernelTransition
    queries: tuple
    work_units: int
    inputs_digest: str


def _compute_on_work(*, operation, request, selected_rows, database_now, inputs_bytes,
        expected_inputs_digest, public_key, expected_identity, expected_spki_digest,
        maximum_age_ns, maximum_clock_skew_ns, rp_id, origin, installation_target_digest, work):
    evidence.capture._SharedLedger(work)
    if type(operation) is not str or operation not in (registration.OPERATION, installation.OPERATION):
        raise WebAuthnEvidenceComputationError("evidence computation operation is not source fixed")
    adapter = registration if operation == registration.OPERATION else installation
    spec = authority.operation_spec(operation)
    if (type(selected_rows) is not tuple or len(selected_rows) > spec["maximumBusinessQueryRows"]
            or any(type(row) is not dict for row in selected_rows)
            or not isinstance(public_key, evidence.keys.Ed25519PublicKey)):
        raise WebAuthnEvidenceComputationError("evidence computation requires exact rows and an independently pinned key")
    wire._raw(inputs_bytes, 2, wire.MAX_BYTES)
    cutoff_us = wire._to_epoch_us(database_now)
    registration.registration._now(database_now)
    work.prepare_copy(selected_rows)
    owned = wire._capture({"request": request, "selected": list(selected_rows),
        "expectedInputsDigest": expected_inputs_digest,
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
            raise WebAuthnEvidenceComputationError("registration computation cannot use an installation target")
    else:
        shape._digest(owned["installationTargetDigest"])
        if owned["rpId"] is not None or owned["origin"] is not None:
            raise WebAuthnEvidenceComputationError("installation computation cannot use a registration RP")
    actual = owned["request"]
    if type(actual) is not dict or actual.get("operation") != operation or actual.get("handler") != adapter.HANDLER:
        raise WebAuthnEvidenceComputationError("evidence computation request differs from the fixed operation")
    adapter._arguments(actual.get("arguments"), work)
    digest = commitment._typed_request_digest(actual, work=work)
    if commitment._request_different(digest, actual.get("requestDigest"), work=work):
        raise WebAuthnEvidenceComputationError("evidence computation typed request commitment changed")
    work.prepare_utf8(operation)
    work.prepare_utf8(digest)
    work.charge(hashes=1)
    if commitment._request_different(commitment.operation_id(operation, digest), actual.get("operationId"), work=work):
        raise WebAuthnEvidenceComputationError("evidence computation operation commitment changed")
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
    return _EvidenceComputationObservation(kernel, queries, total_work, inputs_digest)
