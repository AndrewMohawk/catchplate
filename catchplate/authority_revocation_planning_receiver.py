"""Configured authenticated planning on the genuine read-only owner.

Root-signed configuration, the active generation, the descriptor-loaded
planner signer/read DSN and verifier request/root provenance remain real
service prerequisites. This fixed worker owns data and checks its measured
bindings; constructing an owner or authenticated carrier grants none of that
admission. No successful carrier is accepted as an external argument.

All five original bodies are mandatory. Actual verifier authentication and
a fresh historical-time check precede the genuine planner's lazy database/
registry boundary. Only original plan/context bytes survive its normal return
and another current-time check. No writer, persistence, retry or new work is used.
Full-payload capture and existing workers retain their real H/B/N charges;
fixed scalar pin scaffolding and native driver/clock internals are excluded.
"""
from __future__ import annotations

import time

from catchplate import authority_contract as authority
from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_revocation_planner_configuration as planner_configuration
from catchplate import authority_revocation_planning as planning
from catchplate import authority_revocation_planning_request as request
from catchplate import authority_revocation_planning_transport as transport


class RevocationPlanningReceiverError(ValueError):
    pass


def _validate_originals(*, control_bytes, request_bytes, evidence_bytes,
        context_bytes, root_inventory_bytes):
    """Admit immutable references and all lengths before external callbacks."""
    originals = (control_bytes, request_bytes, evidence_bytes, context_bytes, root_inventory_bytes)
    if any(type(raw) is not bytes for raw in originals):
        raise RevocationPlanningReceiverError("planning receiver requires five exact original byte strings")
    transport._validate_request_lengths(tuple(len(raw) for raw in originals))


def _capture_payload(payload, configuration_digest, generation, work):
    """Own the full graph and hold role/scope scalars before mapper callbacks."""
    owned, launch = configuration._capture_configuration_on_work(payload=payload,
        configuration_digest=configuration_digest, generation=generation, work=work)
    roles = owned["roles"]
    if type(roles) is not dict:
        raise RevocationPlanningReceiverError("planning receiver roles are not an exact object")
    ages = []
    for name in ("verifier", "planner"):
        role = roles[name]
        if type(role) is not dict:
            raise RevocationPlanningReceiverError("planning receiver role is not an exact object")
        request.plan.contract._literal(role["processMode"], "policy-authority-" + name)
        request.plan.contract._integer(role["maximumInternalAgeNs"], minimum=1)
        ages.append(role["maximumInternalAgeNs"])
    request._require_enabled_operation(roles["planner"], work)
    scope = (configuration_digest, launch["sequence"], launch["digest"])
    request.commitment._pins(*scope)
    return owned, launch, scope, min(ages)


def _produce_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities,
        control_bytes, request_bytes, evidence_bytes, context_bytes,
        root_inventory_bytes, read_dsn, planner_private_key, work):
    """Authenticate originals, run the real planner, then recheck freshness.

    The mapper genuinely binds the held full configuration to the supplied
    active launch snapshot and pairs the actual planner signer. Its fixed
    owner tuple supplies both authentication keys and the read configuration;
    callback-driven owner replacement is denied before the real owner method
    takes its synchronous snapshot. Its actual lazy registry gate is retained.

    Historical context stays unchanged. A fixed local nine-scalar copy pins
    those authenticated values before planner callbacks, so the post-return
    clock checks cannot use a mutated carrier or response-supplied cutoff.
    The native read/crypto calls are not preempted by a wall-clock timeout;
    expiry after they return denies publication of their original output.
    """
    try:
        request.capture._SharedLedger(work)
        _validate_originals(control_bytes=control_bytes, request_bytes=request_bytes,
            evidence_bytes=evidence_bytes, context_bytes=context_bytes,
            root_inventory_bytes=root_inventory_bytes)
        owned_payload, launch, scope, role_age = _capture_payload(payload, configuration_digest, generation, work)
        owner = planner_configuration._planner_from_configuration_on_work(
            payload=owned_payload, configuration_digest=scope[0], generation=launch,
            runtime_role_identities=runtime_role_identities,
            read_dsn=read_dsn, planner_private_key=planner_private_key, work=work)
        fixed = owner._snapshot_configuration()
        maximum_age = min(role_age, fixed[8])
        now_monotonic = configuration.production._callback(work, time.monotonic_ns)
        now_epoch = configuration.production._callback(work, time.time_ns)
        received = request._verify_request_on_work(control_bytes=control_bytes,
            request_bytes=request_bytes, evidence_bytes=evidence_bytes,
            context_bytes=context_bytes, root_inventory_bytes=root_inventory_bytes,
            verifier_public_key=fixed[5], planner_public_key=fixed[4],
            expected_configuration_digest=scope[0], expected_generation_sequence=scope[1],
            expected_generation_digest=scope[2], now_epoch_ns=now_epoch,
            now_monotonic_ns=now_monotonic, maximum_age_ns=maximum_age,
            maximum_clock_skew_ns=fixed[9], work=work)
        historical_context = {name: received.context[name] for name in planning._CALL_CONTEXT}
        before_monotonic = configuration.production._callback(work, time.monotonic_ns)
        before_epoch = configuration.production._callback(work, time.time_ns)
        request._require_current_context(historical_context, now_epoch_ns=before_epoch,
            now_monotonic_ns=before_monotonic, maximum_age_ns=maximum_age,
            maximum_clock_skew_ns=fixed[9])
        # Shape-only exact owner snapshot; no external callback may interpose
        # between this identity check and the real method's own fixed capture.
        if owner._snapshot_configuration() is not fixed:
            raise RevocationPlanningReceiverError("planning receiver owner changed during authentication")
        produced = owner.produce_observed(request=received.request, evidence=received.evidence,
            context=received.context, root_inventory=received.root_inventory, work=work)
        envelope_bytes, evaluation_context_bytes = produced.envelope_bytes, produced.evaluation_context_bytes
        if type(envelope_bytes) is not bytes or type(evaluation_context_bytes) is not bytes:
            raise RevocationPlanningReceiverError("planning receiver lost the original immutable response")
        transport._validate_response_lengths((len(envelope_bytes), len(evaluation_context_bytes)))
        after_monotonic = configuration.production._callback(work, time.monotonic_ns)
        after_epoch = configuration.production._callback(work, time.time_ns)
        request._require_current_context(historical_context, now_epoch_ns=after_epoch,
            now_monotonic_ns=after_monotonic, maximum_age_ns=maximum_age,
            maximum_clock_skew_ns=fixed[9])
        return envelope_bytes, evaluation_context_bytes
    except request.commitment._FAILURES as exc:
        if isinstance(exc, RevocationPlanningReceiverError):
            raise
        raise RevocationPlanningReceiverError("configured planning request failed") from exc
