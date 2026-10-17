"""Reconstruct registration finalization from original signer bytes, then plan.

Only the actual measured verifier supplies configuration, generation and the
original runtime receipt. Its genuine signer consumer derives the complete
typed request; no caller credential, semantic intent or proof-success carrier
is accepted. Sibling IDs are bounded lookup hints, never population authority.
The actual transition planner must still prove complete credential history and
siblings and the unconsumed v2 business evidence row. Retained evidence custody
alone is not that row, and this composition does not create it.

The result is prepared transition raw7, not execution or a custody write. No
public route, current-root reservation, capability or SQL permission is added.
The caller must journal originals before any separately authorized forwarding.
One existing work allowance and original local receipt/deadline span this call.
"""
from __future__ import annotations

from catchplate import authority_webauthn_registration_custody_caller as framing
from catchplate import authority_webauthn_registration_signer_response as verifying
from catchplate import authority_webauthn_transition_service as transition
from catchplate import authority_webauthn_evidence_plan_clock as clock


evidence, authority = verifying.evidence, verifying.authority


class RegistrationFinalizationPreparationError(ValueError):
    pass


def _prepare_on_work(process, *, request_originals, response_originals,
        sibling_challenge_ids, deadline_epoch_ns, work, transport_deadline_ns=None):
    """Replay originals and prepare real raw7 under the actual verifier owner."""
    return _prepare_core(process, request_originals=request_originals,
        response_originals=response_originals, sibling_challenge_ids=sibling_challenge_ids,
        deadline_epoch_ns=deadline_epoch_ns, work=work,
        transport_deadline_ns=transport_deadline_ns, execution=False)


def _prepare_core(process, *, request_originals, response_originals,
        sibling_challenge_ids, deadline_epoch_ns, work, transport_deadline_ns, execution):
    from catchplate import authority_service as service
    import time

    ledger = evidence.capture._SharedLedger(work)
    if type(execution) is not bool:
        raise RegistrationFinalizationPreparationError("finalization preparation profile is not fixed")
    request_raw = verifying.wire._request_originals(request_originals)
    response_raw = verifying.wire._response_originals(response_originals)
    # Raw byte tuples cannot pass through the JSON-only shallow-copy meter.
    work.charge(input_bytes=sum(len(raw) for raw in request_raw)
        + sum(len(raw) for raw in response_raw))
    framing._request_originals(request_raw + response_raw)
    deadline = framing._epoch_deadline(deadline_epoch_ns)
    inherited = transport_deadline_ns
    if inherited is not None:
        evidence.plan.contract._integer(inherited, minimum=1)
    if (type(sibling_challenge_ids) is not list
            or len(sibling_challenge_ids) > verifying.production.registration.MAX_SIBLINGS
            or any(type(value) is not str or not 1 <= len(value) <= 4096
                for value in sibling_challenge_ids)):
        raise RegistrationFinalizationPreparationError("registration sibling hints exceed the source bound")
    siblings = evidence.capture._JSONCapture(ledger,
        maximum_bytes=authority.MAX_REQUEST_BYTES).visit(sibling_challenge_ids)
    if (type(process) is not service.AuthorityProcess or process.role_name != "verifier"
            or process.process_mode != service.PROCESS_MODES["verifier"]
            or type(process.configuration) is not service.MeasuredConfiguration):
        raise RegistrationFinalizationPreparationError("registration finalization requires the actual verifier")
    measured = process.configuration
    digest = measured.digest
    evidence.plan.contract._digest(digest)
    receipt = measured.attestation_evidence
    interval = framing._receipt_interval(receipt)

    # Every caller graph/byte reference and the original receipt are held
    # before the real launch, key and clock callbacks. No transport or policy
    # identity is selected from returned signer data.
    payload, captured_digest, generation, _dsn, _key, runtime = transition._measured_context_on_work(
        process, role="verifier", signing=False, read_descriptor=None, work=work)
    generation = transition._generation_on_work(generation, work)
    evidence.plan._same(captured_digest, digest, work,
        "registration finalization configuration changed")
    window = clock._open_on_work(deadline_epoch_ns=min(deadline, interval[1]),
        maximum_lifetime_ns=authority.VERIFIER_RESPONSE_MAX_AGE_NS,
        maximum_clock_skew_ns=authority.VERIFIER_MAX_CLOCK_SKEW_NS, work=work)
    bound = window[4] if inherited is None else min(window[4], inherited)
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        if (process.configuration is not measured or measured.digest != digest
                or process.role_name != "verifier"
                or process.process_mode != service.PROCESS_MODES["verifier"]
                or measured.attestation_evidence is not receipt
                or framing._receipt_interval(receipt) != interval):
            raise RegistrationFinalizationPreparationError("registration finalization owner changed")
        transition._require_generation_on_work("verifier", generation, work)
        evidence.plan._same(measured.runtime_role_identities, runtime, work,
            "registration finalization runtime cohort changed")
        now = clock._check_on_work(window, work=work)
        if not interval[0] <= now < interval[1]:
            raise RegistrationFinalizationPreparationError("registration finalization receipt expired")
        if execution:
            monotonic = evidence.production._callback(work, time.monotonic_ns)
            evidence.plan.contract._integer(monotonic, minimum=1)
            if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
                raise RegistrationFinalizationPreparationError("finalization execution preparation clocks reversed or expired")
            last_epoch, last_monotonic = now, monotonic
        if (process.configuration is not measured or measured.digest != digest
                or measured.attestation_evidence is not receipt
                or framing._receipt_interval(receipt) != interval):
            raise RegistrationFinalizationPreparationError("registration finalization changed during callbacks")
        evidence.production._callback(work, lambda: framing._check_deadline(bound))

    current()
    request, inputs = verifying._verify_finalization_on_configuration(payload=payload,
        configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, request_originals=request_raw,
        response_originals=response_raw, sibling_challenge_ids=siblings, work=work)
    current()
    # Evaluation time is the genuine opening sample, not a new post-replay
    # window and not the attestation's historical verification instant.
    if execution:
        from catchplate import authority_webauthn_transition_preparation as preparation

        result = preparation._prepare_finalization_execution_on_work(process,
            request=request, inputs_bytes=inputs, now_epoch_ns=window[0],
            deadline_epoch_ns=window[3], invocation={}, live_window=window,
            work=work, transport_deadline_ns=bound)
    else:
        result = service.AuthorityProcess._prepare_webauthn_transition_custody(process,
            operation=verifying.production.registration.OPERATION, request=request,
            inputs_bytes=inputs, now_epoch_ns=window[0], deadline_epoch_ns=window[3],
            invocation={}, work=work, transport_deadline_ns=bound)
    current()
    return result
