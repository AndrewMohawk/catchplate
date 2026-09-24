"""Private measured-writer composition of original detached commitments.

The service supplies one held configuration seven-tuple and configuration,
generation and writer-age pins from its preceding genuine mapper over the same
held full measured payload. Those are fixed internal preconditions, not claims
established by constructing an owner or passing an ordinary dictionary here.
The extra full-payload capture below owns aliases before callbacks; it is not a
second measured-configuration admission or an accepted proof token.

Original controls and all three bodies are mandatory on every call. Actual
current clocks, both role signatures, detached commitments and measured
historical policy precede the existing atomic owner path, whose two genuine
replays and database/registry admission remain unchanged. No transport, public
purpose, durable control custody, replay journal or signed ACK is introduced.
Post-commit failures retain the owner's existing uncertainty boundary.
"""
from __future__ import annotations

import time

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration_capture
from serverware import authority_revocation_persistence as persistence
from serverware import authority_revocation_writer_action as action
from serverware import authority_revocation_writer_commitment as commitment


def _validate_originals(*, intent_bytes, relay_bytes, envelope_bytes,
        evaluation_context_bytes, historical_expectations_bytes):
    """Fixed immutable references; this does not decode or authenticate them."""
    commitment._raw(intent_bytes, commitment.MAX_CONTROL_BYTES)
    commitment._raw(relay_bytes, commitment.MAX_CONTROL_BYTES)
    commitment._body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)


def _persist_commitments_on_configuration(configuration, *, intent_bytes,
        relay_bytes, envelope_bytes, evaluation_context_bytes,
        historical_expectations_bytes, owned_payload, configuration_digest,
        generation_sequence, generation_digest, maximum_age_ns, work):
    """Authenticate originals and persist using the same fixed owner tuple.

    The caller is the fixed private service adapter, not a configurable action
    or clock provider. Its mapper has already bound these configuration and
    generation pins to the admitted launch and genuine role keys. Direct
    component calls supply ordinary inputs and establish no such admission.
    Current age is the measured writer role's age, not the historical verifier
    plan-age cap. The source skew cannot be widened by either signed control.

    Capture the full payload again on the existing work before clocks or key
    callbacks (0H/1L/1N). The receiver owns its fourteen-field history itself;
    no separate speculative history capture or proof-result input is used.
    Actual policy comparison uses this same captured payload without replacing
    any authenticated historical value. The fixed atomic suffix preserves its
    existing ID comparison, external capture, admission and two replay costs.
    """
    persistence._validate_configuration(configuration)
    ledger = commitment.capture._SharedLedger(work)
    _validate_originals(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
        historical_expectations_bytes=historical_expectations_bytes)
    commitment._pins(configuration_digest, generation_sequence, generation_digest)
    commitment.plan.contract._integer(maximum_age_ns, minimum=1)
    if type(owned_payload) is not dict:
        raise ValueError("revocation writer composition requires an exact full configuration object")
    payload = configuration_capture._ConfigurationCapture(
        ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(owned_payload)
    planner_key, verifier_key = configuration[2:4]
    now_monotonic_ns = commitment.production._callback(work, time.monotonic_ns)
    now_epoch_ns = commitment.production._callback(work, time.time_ns)
    received = commitment._verify_commitments_on_work(intent_bytes=intent_bytes,
        relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
        evaluation_context_bytes=evaluation_context_bytes,
        historical_expectations_bytes=historical_expectations_bytes,
        planner_public_key=planner_key, verifier_public_key=verifier_key,
        expected_configuration_digest=configuration_digest,
        expected_generation_sequence=generation_sequence,
        expected_generation_digest=generation_digest,
        now_epoch_ns=now_epoch_ns, now_monotonic_ns=now_monotonic_ns,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=authority.VERIFIER_MAX_CLOCK_SKEW_NS,
        work=work)
    action._assert_policy_on_work(payload, received.expectations, work)
    return persistence._persist_and_reserve_on_configuration(configuration,
        **received.arguments, work=work, **received.expectations)
