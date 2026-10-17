"""Authenticate original live registration source exchange for fixed signers.

The actual owner supplies root-admitted configuration, active generation and
runtime identities. Their consistency mapper does not establish that external
provenance. This composition authenticates both original controls using the
independently configured verifier/planner keys before decoding returned source
bytes, then runs genuine primary/query/cutoff replay on the same work.

Only the original live request interval is admitted. Expired controls cannot
become historical signing authority or acquire a renewed lifetime. Returned
owned context, source observations and local timings are ordinary same-call
data, never an accepted proof token, enrollment grant or evidence signature.
No caller selectors, roots, timing or policy overrides, SQL, transport, private
signer, fallback key or replacement allowance are accepted.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_revocation_configuration as measured
from catchplate import authority_webauthn_evidence_custody_configuration as configuration
from catchplate import authority_webauthn_registration_source_request as request_wire
from catchplate import authority_webauthn_registration_source_response as response_wire
from catchplate import authority_webauthn_registration_source_wire as source_wire


evidence, authority = request_wire.evidence, request_wire.authority


class WebAuthnRegistrationSourceAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _AdmittedSourceExchange:
    """Locally owned outputs of this invocation, not transferable authority."""

    context: dict
    observations: source_wire._RegistrationSourceObservations
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple
    maximum_control_age_ns: int
    maximum_clock_skew_ns: int


def _verify_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, request_control_bytes, request_context_bytes,
        response_control_bytes, source_bytes, work):
    """Authenticate raw four and replay source proofs before returning data."""
    ledger = evidence.capture._SharedLedger(work)
    request_originals = request_wire._raw2(request_control_bytes, request_context_bytes)
    response_originals = response_wire._raw2(response_control_bytes, source_bytes)
    digest = configuration_digest
    evidence.plan.contract._digest(digest)
    if type(payload) is not dict or type(generation) is not dict:
        raise WebAuthnRegistrationSourceAdmissionError("source exchange configuration is not exact data")
    measured.capability.shape._bounded_object(generation, 24, "source exchange launch context")
    # Own every mutable input graph before the genuine mapper can perform its
    # first commitment, key or native callback. Original byte references and
    # the configuration digest are immutable and already bounded/held above.
    owned_payload = measured._ConfigurationCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(generation)
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    configured = configuration._capture_on_work(purpose="registration", payload=owned_payload,
        configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    pins, verifier_key = configured.pins, configured.verifier_public_key
    sequence, generation_digest = configured.generation_sequence, configured.generation_digest
    maximum_age, skew = configured.maximum_control_age_ns, pins[9]

    request = request_wire._verify_on_work(control_bytes=request_originals[0],
        context_bytes=request_originals[1], pins=pins, generation_sequence=sequence,
        generation_digest=generation_digest, verifier_public_key=verifier_key,
        maximum_control_age_ns=maximum_age, work=work)
    context, window = request.context, request.window
    issued, expires = request.issued_at_epoch_ns, request.expires_at_epoch_ns
    request_timing = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    response = response_wire._verify_on_work(control_bytes=response_originals[0],
        request_control_bytes=request_originals[0], source_bytes=response_originals[1],
        pins=pins, generation_sequence=sequence, generation_digest=generation_digest,
        verifier_public_key=verifier_key, request_issued_at_epoch_ns=issued,
        request_expires_at_epoch_ns=expires, request_window=window,
        maximum_control_age_ns=maximum_age, work=work)
    response_timing = {"issuedAtEpochNs": response.issued_at_epoch_ns,
        "expiresAtEpochNs": response.expires_at_epoch_ns}
    # The planner signature binds this exact request control and the complete
    # source bytes before any returned roots, rows or cutoff are decoded.
    observations = source_wire._verify_on_work(source_bytes=response_originals[1],
        request_context=context, request_issued_at_epoch_ns=issued,
        request_expires_at_epoch_ns=expires, maximum_clock_skew_ns=skew, work=work)
    response_wire._fresh_response(response_timing, request_timing, window=window,
        maximum_age_ns=maximum_age, maximum_clock_skew_ns=skew, work=work)
    # The last native clock callback must not retarget the authenticated
    # request graph subsequently consumed by the same-call signer.
    evidence.capability._canonical(request_originals[1], context, ledger,
        request_wire.MAX_CONTEXT_BYTES, request_wire.MAX_CONTEXT_NODES)
    return _AdmittedSourceExchange(context, observations, issued, expires, window,
        maximum_age, skew)
