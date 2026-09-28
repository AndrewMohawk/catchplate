"""One fresh actor, one completion-only claim, separately retained originals.

This coordinator never resumes a spent activation permission, invokes SQL,
opens a token or replaces an uncertain original outcome. A successful return
means only that historical signed completion controls have been admitted and
retained separately, followed by normal actor cleanup.
"""
from __future__ import annotations

from serverware import control_plane_oidc_session_activation_completion_recovery_actor as actors
from serverware import control_plane_oidc_session_activation_completion_recovery_controls as controls
from serverware import control_plane_oidc_session_activation_completion_recovery_exchange as exchange
from serverware import control_plane_oidc_session_activation_completion_recovery_records as records


execution = actors.execution
_ACTIVE = None
_CONFIGURATION_DOMAIN = "serverware.controlPlaneOidcSessionActivationCompletionRecoveryConfiguration/v1"
_CONFIGURATION_RESERVATION = 16 * 1024


class _CompletionAttempt:
    """Private call association and irreversible network latch, not evidence."""

    __slots__ = ("controls", "claim_digest", "exchange_spent", "closed")

    def __init__(self, selected):
        controls._require_controls(selected)
        self.controls = selected
        self.claim_digest = None
        self.exchange_spent = False
        self.closed = False


def _require_claimed(selected):
    """The fixed exchange calls this immediately before its sole socket."""
    active = _ACTIVE
    controls._require_controls(selected)
    if (type(active) is not _CompletionAttempt or active.closed is not False
            or active.controls is not selected or active.exchange_spent is not False
            or type(active.claim_digest) is not str):
        execution._fail("completion recovery is not its unspent durably claimed call")
    execution.shape._digest(active.claim_digest)
    selected.current()
    active.exchange_spent = True
    selected.current()


def _configuration_digest(scope):
    """Bind every actual cold pin, not a candidate reply or generic config ID."""
    scope.current()
    configured = scope._configuration
    endpoint = configured.endpoint
    pending = configured.current_pending
    values = (scope._profile, endpoint[0], str(endpoint[1]), str(endpoint[2]), str(endpoint[3]),
        configured.packet_digest, configured.authorization_digest,
        str(pending[0]), pending[1], str(pending[2]))
    for value in values:
        scope._work.prepare_utf8(value)
    frames = tuple(value.encode("ascii") for value in values)
    identity = execution.plan._frame(_CONFIGURATION_DOMAIN, frames, scope._work)
    scope.current()
    return identity


def _retained_response(selected, existing, pins):
    """Read-only reuse of DATA; actual signature admission still follows."""
    if type(existing) is not records.CompletionRecoveryRecords:
        execution._fail("completion recovery retained slot shape differs")
    claim, response = existing.claim, existing.response
    if (type(claim) is not records.CompletionRecoveryRecord or claim.kind != "claimed"
            or type(response) is not records.CompletionRecoveryRecord or response.kind != "response"):
        execution._fail("completion recovery spent slot has no retained response")
    for record in (claim, response):
        for name, value in pins.items():
            execution.plan._same(getattr(record, name), value, selected.work,
                "completion recovery retained original " + name)
        execution.plan._same(record.source_revision, records.authority.SOURCE_REVISION,
            selected.work, "completion recovery retained source cohort")
    execution.plan._same(claim.slot_digest, response.slot_digest, selected.work,
        "completion recovery retained slot association")
    execution.plan._same(claim.predecessor_completion_digest, response.predecessor_completion_digest,
        selected.work, "completion recovery unchanged predecessor outcome")
    selected.current()
    return response.originals


def _recover_on_owner(owner, *, profile, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current):
    """Literal owner facade entry; no caller-supplied controls or results."""
    global _ACTIVE

    if _ACTIVE is not None:
        execution._fail("completion recovery cannot overlap another attempt")
    index = records._phase(profile)
    claim_capacity = records.MAX_CLAIM_IO_BYTES + records.METADATA_RESERVATION_BYTES
    response_capacity = (records.MAX_CLAIM_BYTES + 3 * records.MAX_RESPONSE_BYTES[index]
        + records.METADATA_RESERVATION_BYTES)
    reload_capacity = (3 * (records.MAX_CLAIM_BYTES + records.MAX_RESPONSE_BYTES[index])
        + records.METADATA_RESERVATION_BYTES)
    additional = (exchange._exchange_reservation(profile) + claim_capacity
        + response_capacity + reload_capacity + _CONFIGURATION_RESERVATION)
    active, scope, receiving_current = None, None, None
    try:
        with actors._authorize_on_owner(owner, profile=profile, request=request,
                recovery_bytes=recovery_bytes, live_window=live_window,
                transport_deadline_ns=transport_deadline_ns, work=work, current=current) as scope:
            scope.current()
            if (scope._authorized is not True or scope._completion_recovery_spent is not False
                    or scope._completion_receiving_current is not None):
                execution._fail("completion recovery requires a fresh unspent actor")
            scope._completion_recovery_spent = True
            configuration_digest = _configuration_digest(scope)
            selected = controls._admit_on_actor(scope, _additional_original_bytes=additional)
            controls._require_controls(selected)
            if selected._actor is not scope or selected.work is not work:
                execution._fail("completion recovery changed its original actor or work")
            active = _CompletionAttempt(selected)
            _ACTIVE = active
            pins = {"finalization_digest": selected.finalization_digest, "phase": profile,
                "authorization_digest": selected.authorization_digest,
                "packet_digest": selected.packet_digest,
                "recovery_configuration_digest": configuration_digest}
            selected.current()
            existing = execution.custody.ControlPlaneCustodyClient.load_oidc_session_activation_completion_recovery_records(
                owner._custody, selected.finalization_digest, phase=profile,
                work=work, current=selected.current, maximum_original_bytes=reload_capacity)
            selected.current()
            if existing is not None:
                # A new actor may re-admit an already stored response, never
                # resend a spent claim, including an absent/uncertain response.
                response = _retained_response(selected, existing, pins)
            else:
                # The journal precharges bounded native I/O on this original
                # work, using headroom reserved before historical body1.
                claim = execution.custody.ControlPlaneCustodyClient.claim_oidc_session_activation_completion_recovery_attempt(
                    owner._custody, **pins, work=work, current=selected.current,
                    maximum_original_bytes=claim_capacity)
                selected.current()
                execution.shape._digest(claim)
                active.claim_digest = claim
                response = exchange._exchange_on_controls(selected)
                selected.current()
                if active.exchange_spent is not True:
                    execution._fail("completion recovery did not consume its sole exchange")
                # Preserve raw4/raw6 before even the status or hint branch.
                # This immutable record is DATA, never an admission shortcut.
                retained = execution.custody.ControlPlaneCustodyClient.append_oidc_session_activation_completion_recovery_response(
                    owner._custody, **pins, originals=response, work=work,
                    current=selected.current, maximum_original_bytes=response_capacity)
                selected.current()
                execution.shape._digest(retained)
            selected.current()
            receiving_current = exchange._verify_on_controls(selected, response_originals=response)
            if not callable(receiving_current):
                execution._fail("completion recovery lacks its genuine receiving guard")
            receiving_current()
            # This child is not attached to actor.current(), which is its own
            # ancestor. The actor checks it separately through trust cleanup.
            scope._completion_receiving_current = receiving_current
            selected.current()
            receiving_current()
        if scope._normal_exit is not True:
            execution._fail("completion recovery did not finish normal actor cleanup")
        # Deliberately return no permission/result object or private originals.
        # The HTTP owner projects only the completed historical fact.
    finally:
        if active is not None:
            active.closed = True
            active.claim_digest = None
        if _ACTIVE is active:
            _ACTIVE = None
