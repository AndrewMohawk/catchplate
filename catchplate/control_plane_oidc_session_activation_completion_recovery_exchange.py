"""Completion-only exchange and genuine public historical response admission.

Only the actual fresh actor's sealed historical controls enter this module.
The root orchestrator must publish its terminal attempt before the one socket
call, then retain the returned opaque originals before signature admission.
Neither an unsigned packet hint nor an old uncertain outcome supplies authority.
Private packet/AES/commit replay remains in the independently configured worker.
"""
from __future__ import annotations

import time

from catchplate import authority_current_root_authorization as state
from catchplate import authority_current_root_completion as observations
from catchplate import authority_current_root_delivery_records as acknowledgments
from catchplate import authority_oidc_session_activation_completion_dispatch_transport as activation_wire
from catchplate import authority_oidc_session_activation_delivery_completion_release_transport as consume_wire
from catchplate import authority_oidc_session_activation_consume_input_production as bookkeeping
from catchplate import authority_oidc_session_activation_release_hints as hints
from catchplate import authority_registration_completion_response as neutral
from catchplate import control_plane_oidc_session_activation_completion_recovery_controls as controls_source


plan, production, clock = state.plan, state.production, bookkeeping.clock
MAX_ORIGINAL_BYTES = bookkeeping.MAX_ORIGINAL_BYTES


class CompletionRecoveryExchangeError(ValueError):
    pass


class CompletionRecoveryUncertainError(CompletionRecoveryExchangeError):
    """No authenticated acknowledgment or automatic retry permission."""


def _profile(profile):
    if type(profile) is str and profile == "activation":
        return activation_wire
    if type(profile) is str and profile == "consume":
        return consume_wire
    raise CompletionRecoveryExchangeError("completion recovery profile is not source fixed")


def _exchange_reservation(profile):
    """Reserve known wire/capture representations before historical body reads.

    This is an additive byte-accounting reserve, not a Python heap/RSS bound
    or additional work allowance. The controls loader already includes this
    root-supplied reserve in its final held total; do not add it again later.
    Journal claim/response publication has its own separate pre-reservation.
    """
    wire = _profile(profile)
    return (4 * wire.MAX_REQUEST_BYTES + 16 * wire.MAX_RESPONSE_BYTES
        + 8 * state.MAX_ENROLLMENT_BYTES + 8 * observations.MAX_OBSERVATION_BYTES
        + 4 * state.vector.MAX_BYTES + 16 * 1024 + 4096
        + 4 * wire.REQUEST_HEADER_BYTES + 3 * wire.RESPONSE_HEADER_BYTES)


def _held(controls):
    controls_source._require_controls(controls)
    wire = _profile(controls.profile)
    work = controls.work
    state.capture._SharedLedger(work)
    authority = controls.authority
    if wire is not activation_wire and controls.consume_authority is not None:
        authority = controls.consume_authority
    policy = (authority.activation_execution if wire is activation_wire
        else authority.consume_execution)
    recovery = authority.completion_recovery
    configured = recovery.activation if wire is activation_wire else recovery.consume
    if (controls.root_public_key is not authority.root_public_key
            or controls.enrollment_bytes is not policy.current_root_enrollment_bytes):
        raise CompletionRecoveryExchangeError("completion receiving changed its selected historical keys")
    for name in ("packet_digest", "authorization_digest", "current_pending"):
        plan._same(getattr(controls, name), getattr(configured, name), work,
            "completion receiving independent historical " + name)
    # The endpoint intentionally remains current. The archived caller/state
    # keys and independent completion pins are not replaced by current keys.
    controls.current()
    reserved = controls.original_reservation_bytes
    if (type(reserved) is not int or not _exchange_reservation(controls.profile)
            <= reserved <= MAX_ORIGINAL_BYTES):
        raise CompletionRecoveryExchangeError("completion recovery held representations exceed their bound")
    return wire, work


def _same_bytes(actual, expected, work, label):
    if type(actual) is not bytes or type(expected) is not bytes:
        raise CompletionRecoveryExchangeError("completion recovery requires immutable originals")
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        raise CompletionRecoveryExchangeError("completion recovery " + label + " differs")


def _exchange_on_controls(controls):
    """One claimed source-selected exchange, returning only opaque originals.

    The exact root-owned attempt consumes its socket latch before contact.
    The existing fixed transport guards native socket operations, checks peer,
    EOF and all response lengths, and owns a single normal close. A close or
    guard failure yields no returned response and never another socket.
    """
    from catchplate import control_plane_oidc_session_activation_completion_recovery as owner

    wire, work = _held(controls)
    controls.current()
    selected = wire._originals((wire.PURPOSE, controls.originals[0]), response=False)
    endpoint = wire._endpoint(controls.endpoint)
    # No caller-created successful controls or bare actor can bypass the
    # durable claim. This actual source method validates and spends the latch.
    owner._require_claimed(controls)
    controls.current()
    response = wire._socket_request_on_work(endpoint, originals=selected,
        deadline_ns=controls.deadline_ns, work=work, current=controls.current)
    controls.current()
    return wire._originals(response, response=True)


def _verify_on_controls(controls, *, response_originals):
    """Return a live historical-receiving guard only after genuine admission.

    The root calls this on newly published raw4/raw6 or exact stored separate
    reconciliation data reselected under a fresh actor. Reuse still performs
    every genuine admission below and never contacts the worker again.
    An uncertain selector raises; it never becomes a
    false negative SQL/current-session result. No token, permission carrier,
    unsigned packet or private AES custody is accepted or returned.
    """
    wire, work = _held(controls)
    controls.current()
    returned = wire._originals(response_originals, response=True)
    window = clock._validate(controls.window)
    bound = controls.deadline_ns
    state.shape._integer(bound, minimum=1)
    if bound > window[4]:
        raise CompletionRecoveryExchangeError("completion recovery widened its original deadline")

    def ancestor(epoch, monotonic):
        controls_source._require_controls(controls)
        observed = controls.current()
        sampled = production._callback(work, time.monotonic_ns)
        if (type(observed) is not int or type(sampled) is not int
                or observed < epoch or sampled < monotonic):
            raise CompletionRecoveryExchangeError("completion receiving original clocks reversed")
        return observed, sampled

    lifetime = bookkeeping._Lifetime(window, bound, work, ancestor)
    complete = material = None

    def current():
        epoch = lifetime.current()
        if complete is not None and complete["issuedAtEpochNs"] > (
                epoch + min(lifetime.window[6], material.payload["maxClockSkewNs"])):
            raise CompletionRecoveryExchangeError("completion historical statement is future-issued")
        return epoch

    current()
    if returned[0] == b"uncertain":
        raise CompletionRecoveryUncertainError("completion recovery acknowledgment is unavailable")
    # Existing acknowledged originals are immutable history, including the
    # partial consume case where old raw4 survived but its hints did not.
    prior_complete = controls.prior_completion
    if prior_complete is not None:
        prior_complete = activation_wire._originals(prior_complete, response=True)
        if prior_complete[0] == b"acknowledged":
            for actual, expected in zip(returned[:4], prior_complete):
                _same_bytes(actual, expected, work, "retained acknowledged completion")
    prior = controls.prior_response
    if prior is not None:
        prior = wire._originals(prior, response=True)
        if prior[0] == b"acknowledged":
            for actual, expected in zip(returned, prior):
                _same_bytes(actual, expected, work, "retained acknowledged response")
    sequence, head, fence = controls.current_pending
    marker = controls.marker
    for actual, expected in ((marker["pending_sequence"], sequence),
            (marker["pending_decision_digest"], head), (marker["fence"], fence)):
        plan._same(actual, expected, work, "completion recovery independent pending scope")
    # These are bounded, pure original signature/canonical admission calls.
    # The controls guard retains the independently selected archive/root. A
    # newly issued completion/ACK is not forced into the old execution interval;
    # its own genuine enrollment, marker and current processing checks apply.
    # They charge this ledger directly; guards bracket them, not an unmetered
    # wrapper or a generic interception of lower native operations.
    current()
    try:
        material, complete, complete_digest = state._verify_historical_request_on_work(
            request_bytes=returned[2], enrollment_bytes=controls.enrollment_bytes,
            root_public_key=controls.root_public_key, work=work)
    finally:
        current()
    lifetime.narrow(lifetime.window[3], material.payload["maxControlAgeNs"],
        material.payload["maxClockSkewNs"])
    current()
    try:
        acknowledged = acknowledgments._verify_ack_on_work(request_bytes=returned[2],
            receipt_bytes=returned[3], enrollment_bytes=controls.enrollment_bytes,
            root_public_key=controls.root_public_key, expected_pending_sequence=sequence,
            expected_pending_head_digest=head, work=work)
    finally:
        current()
    plan._same(acknowledged.request_payload, complete, work,
        "completion recovery independently verified request readback")
    plan._same(acknowledged.request_digest, complete_digest, work,
        "completion recovery independently verified request identity")
    work.prepare_utf8(complete_digest)
    _same_bytes(returned[1], complete_digest.encode("ascii"), work, "returned complete identity")
    plan._same(complete["action"], "complete", work, "completion recovery fixed action")
    for field, column in neutral._REQUEST_MARKER_JOINS:
        plan._same(complete[field], marker[column], work,
            "completion recovery genuine historical marker " + field)
    current()
    try:
        bookkeeping._observation(complete, marker, controls.after_bytes, work)
    finally:
        current()
    if wire is consume_wire:
        current()
        try:
            packet_digest, _effects, _envelope, _created, _expires = hints._decode_on_work(
                returned[4:], work=work)
        finally:
            current()
        # A mismatch rejects. Equality cannot turn these unsigned hints into
        # packet, private replay, token-release or current-session authority.
        plan._same(packet_digest, controls.packet_digest, work,
            "completion recovery unsigned hint versus independent packet pin")
    current()
    # Root retains this child separately through append and normal actor/trust
    # cleanup. It must never feed it back into controls.current/its ancestors.
    return current
