"""Configured raw-original verification of three successor transition plans.

This inert owner has only independently admitted public-key and policy pins.
Every invocation owns its independent expectations before native callbacks,
then runs the actual signed-plan verifier and genuine proof/semantic replay.
A received context never supplies expectation authority. No current clock,
database, private key, new allowance or successful-proof input is accepted.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_webauthn_transition_plan_admission as admission


plan = admission.plan


class WebAuthnTransitionPlanVerifierError(ValueError):
    pass


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class TransitionPlanVerifier:
    _pins: tuple

    def __init__(self, *, pins):
        object.__setattr__(self, "_pins", admission._validate_pins(pins))

    def verify(self, *, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
            expectations, work):
        """Verify raw4 against independently admitted request/root/history pins."""
        if type(self) is not TransitionPlanVerifier:
            raise WebAuthnTransitionPlanVerifierError("transition plan verifier owner type changed")
        pins = admission._validate_pins(self._pins)
        originals = (envelope_bytes, proof_bytes, inputs_bytes, context_bytes)
        maxima = (plan.contract.MAX_BYTES, plan.proof.contract.MAX_BYTES,
            plan.proof.wire.MAX_BYTES, plan.context.MAX_BYTES)
        for raw, maximum in zip(originals, maxima):
            if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
                raise WebAuthnTransitionPlanVerifierError("transition plan handoff requires bounded original bytes")
        owned = admission._capture_expectations_on_work(pins, expectations, work)
        return plan._verify_on_work(envelope_bytes=originals[0], proof_bytes=originals[1],
            inputs_bytes=originals[2], context_bytes=originals[3], expectations=owned,
            planner_public_key=pins[1], public_key=pins[4], work=work)
