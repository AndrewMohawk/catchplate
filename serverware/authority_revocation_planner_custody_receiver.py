"""Fixed planner ingress for separate relay and custody-forwarding phases.

The actual service supplies root-admitted measured configuration, its active
generation and, only for relay preparation, its descriptor-held signer. This
inert module owns and checks those inputs; it does not manufacture admission
or accept an authenticated observation as a substitute for original bytes.

Relay preparation authenticates the verifier intent and returns only a fresh
original planner relay. It never sends to the writer. Forwarding accepts all
five caller-held originals, genuinely derives ACK expectations and sends them
through the existing configured writer client. It never creates a relay or
retries. An ACK is a pinned custody statement, not current execution authority;
a late or failed response may follow commit and never implies rollback.

All configuration/launch ownership, signatures, replay and canonical work are
charged on the same existing allowance. No DSN, database facade, new allowance,
public dispatcher or registry bypass is introduced here.
"""
from __future__ import annotations

from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_planning_request as request
from serverware import authority_revocation_planner_custody_transport as transport
from serverware import authority_revocation_writer_client as client
from serverware import authority_revocation_writer_producers as producers


class RevocationPlannerCustodyReceiverError(ValueError):
    pass


def _capture_configuration(*, payload, configuration_digest, generation, runtime_role_identities, work):
    """Own full configuration, launch bindings and the separate runtime cohort."""
    owned, launch = configuration._capture_configuration_on_work(
        payload=payload, configuration_digest=configuration_digest,
        generation=generation, work=work)
    runtime = configuration._capture_runtime_role_identities_on_work(
        runtime_role_identities=runtime_role_identities, owned_payload=owned,
        configuration_digest=configuration_digest, launch=launch, work=work)
    roles = owned["roles"]
    if type(roles) is not dict or type(roles["planner"]) is not dict:
        raise RevocationPlannerCustodyReceiverError("planner custody role is not an exact object")
    configuration.capability.shape._literal(
        roles["planner"]["processMode"], "policy-authority-planner")
    request._require_enabled_operation(roles["planner"], work)
    return owned, launch, runtime


def _produce_relay_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, raw4, planner_private_key, work):
    """Prepare a separately returned relay; no forward or custody action.

    Exact immutable originals and all local/aggregate lengths are checked
    before callbacks. The real producer repeats configuration/key admission,
    authenticates original intent/body bindings, pairs the actual signer and
    checks held authenticated clocks after signing before returning bytes.
    """
    try:
        configuration.capability.capture._SharedLedger(work)
        if (type(raw4) is not tuple or len(raw4) != 4
                or any(type(raw) is not bytes for raw in raw4)):
            raise RevocationPlannerCustodyReceiverError("planner relay requires four original byte strings")
        transport._validate_relay_lengths(tuple(len(raw) for raw in raw4))
        owned, launch, runtime = _capture_configuration(payload=payload,
            configuration_digest=configuration_digest, generation=generation,
            runtime_role_identities=runtime_role_identities, work=work)
        relay_bytes = producers._produce_relay_on_configuration(
            payload=owned, configuration_digest=configuration_digest, generation=launch,
            runtime_role_identities=runtime,
            intent_bytes=raw4[0], envelope_bytes=raw4[1], evaluation_context_bytes=raw4[2],
            historical_expectations_bytes=raw4[3], planner_private_key=planner_private_key, work=work)
        if type(relay_bytes) is not bytes or not 2 <= len(relay_bytes) <= transport.MAX_RELAY_BYTES:
            raise RevocationPlannerCustodyReceiverError("planner relay is not bounded original bytes")
        return relay_bytes
    except producers._FAILURES as exc:
        if isinstance(exc, RevocationPlannerCustodyReceiverError):
            raise
        raise RevocationPlannerCustodyReceiverError("configured planner relay preparation failed") from exc


def _forward_on_configuration(*, payload, configuration_digest, generation, runtime_role_identities, raw5, work):
    """Forward only retained originals and return their genuinely verified ACK.

    The actual client authenticates both controls, performs genuine retained
    replay, holds independent ACK fields and freshly checks the authenticated
    clocks immediately before its writer socket. ACK verification is custody
    evidence only; it is not a fresh execution or successful delivery token.
    No mutable service method or caller-supplied success object is involved.
    """
    try:
        configuration.capability.capture._SharedLedger(work)
        if (type(raw5) is not tuple or len(raw5) != 5
                or any(type(raw) is not bytes for raw in raw5)):
            raise RevocationPlannerCustodyReceiverError("planner forwarding requires five original byte strings")
        transport._validate_forward_lengths(tuple(len(raw) for raw in raw5))
        owned, launch, runtime = _capture_configuration(payload=payload,
            configuration_digest=configuration_digest, generation=generation,
            runtime_role_identities=runtime_role_identities, work=work)
        acknowledgment_bytes = client._send_on_configuration(
            payload=owned, configuration_digest=configuration_digest, generation=launch,
            runtime_role_identities=runtime,
            intent_bytes=raw5[0], relay_bytes=raw5[1], envelope_bytes=raw5[2],
            evaluation_context_bytes=raw5[3], historical_expectations_bytes=raw5[4], work=work)
        if (type(acknowledgment_bytes) is not bytes
                or not 2 <= len(acknowledgment_bytes) <= transport.MAX_ACK_BYTES):
            raise RevocationPlannerCustodyReceiverError("planner forwarding lost bounded original ACK bytes")
        return acknowledgment_bytes
    except producers._FAILURES as exc:
        if isinstance(exc, RevocationPlannerCustodyReceiverError):
            raise
        raise RevocationPlannerCustodyReceiverError("configured planner custody forwarding failed") from exc
