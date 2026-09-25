"""Configured verifier-side replay of original evidence-admission plans.

This owner has no database endpoint or private signing key. Its immutable pins
come from independently admitted configuration; construction authenticates
neither that provenance nor caller-supplied history. Every invocation compares
all historical expectations with its held purpose policy and genuinely replays
the three original byte strings on the caller's remaining work allowance.

Returned observations are not a capability, current-root assertion, committed
custody receipt or successful-verification token for another consumer. No clock
is sampled and no stored context or signed-plan field enrolls expectations.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_webauthn_evidence_plan_admission as admission
from serverware import authority_webauthn_evidence_plan_retention as retention


class WebAuthnEvidencePlanVerifierError(ValueError):
    pass


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class EvidencePlanVerifier:
    """Hold one independently configured purpose's public verification pins."""

    _pins: tuple

    def __init__(self, *, pins):
        object.__setattr__(self, "_pins", admission._validate_pins(pins))

    def verify(self, *, envelope_bytes, inputs_bytes, evaluation_context_bytes,
            expectations, work):
        """Authenticate originals against independent history, not stored claims.

        Own pins, raw-byte references and the full expectation graph before
        native key or decoding callbacks. The shared admission helper performs
        the same configured joins as writer custody, but opens no store or
        transaction. The genuine retained verifier repeats all signature,
        semantic, primary-proof and resulting-root checks on this same work.
        """
        if type(self) is not EvidencePlanVerifier:
            raise WebAuthnEvidencePlanVerifierError("evidence plan verifier owner type changed")
        pins = admission._validate_pins(self._pins)
        originals = (envelope_bytes, inputs_bytes, evaluation_context_bytes)
        for raw, maximum in zip(originals, (retention.plan.contract.MAX_BYTES,
                retention.plan.inputs_wire.MAX_BYTES, retention.context_wire.MAX_BYTES)):
            if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
                raise WebAuthnEvidencePlanVerifierError("evidence plan handoff requires bounded original bytes")
        owned = admission._capture_expectations_on_work(pins, expectations, work)
        return retention._verify_record_on_work(envelope_bytes=originals[0],
            inputs_bytes=originals[1], evaluation_context_bytes=originals[2],
            expectations=owned, planner_public_key=pins[1],
            evidence_public_key=pins[4], work=work)
