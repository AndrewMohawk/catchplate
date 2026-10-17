"""Fresh, distinct recovery permission through retained intent and proof.

This stage never executes SQL, repeats completion, selects a private release
checkpoint, opens a token or changes a cookie. Its immutable originals can only
feed a later independently configured release continuation.
"""
from __future__ import annotations

from catchplate import control_plane_oidc_session_activation_completion_recovery as completion
from catchplate import control_plane_oidc_session_activation_completion_recovery_intent_inputs as inputs
from catchplate import control_plane_oidc_session_activation_completion_recovery_intent as intent
from catchplate import control_plane_oidc_session_activation_completion_recovery_proof as proof


actors, controls, exchange, records = completion.actors, completion.controls, completion.exchange, completion.records
execution = completion.execution
_ACTIVE = None
_RECONCILIATION_IO_BYTES = 1024 * 1024


class _IntentProofAttempt:
    """Actual source call association; durable custody owns irreversible slots."""

    __slots__ = ("actor", "controls", "response", "receiving_current",
        "reconciliation_digest", "inputs", "intent", "inputs_spent", "intent_spent",
        "proof_spent", "closed")

    def __init__(self, actor, selected):
        self.actor, self.controls = actor, selected
        self.response = self.receiving_current = self.reconciliation_digest = None
        self.inputs = self.intent = None
        self.inputs_spent = self.intent_spent = self.proof_spent = False
        self.closed = False


def _active():
    active = _ACTIVE
    if (type(active) is not _IntentProofAttempt or active.closed is not False
            or completion._ACTIVE is not None
            or active.actor._purpose != "release-intent-proof"
            or active.controls._actor is not active.actor):
        execution._fail("completion release preparation is not its actual active call")
    controls._require_controls(active.controls)
    return active


def _require_inputs_call(selected, response_originals, receiving_current):
    """Pin the actual response reader/verifier, never a supplied success guard."""
    active = _active()
    if (active.controls is not selected or active.response is not response_originals
            or active.receiving_current is not receiving_current
            or active.inputs_spent is not False):
        execution._fail("completion release inputs changed their actual receiving call")
    active.inputs_spent = True
    receiving_current()
    return active.reconciliation_digest


def _require_intent_call(selected):
    active = _active()
    if (active.inputs_spent is not True or active.inputs is not selected
            or active.intent_spent is not False):
        execution._fail("completion release intent is not its sole original input call")
    active.intent_spent = True
    selected.current()


def _require_proof_call(selected):
    active = _active()
    if (active.intent_spent is not True or active.intent is not selected
            or active.proof_spent is not False):
        execution._fail("completion release proof is not its sole original intent call")
    active.proof_spent = True
    selected.current()


def _prepare_on_owner(owner, *, request, recovery_bytes, live_window,
        transport_deadline_ns, work, current):
    """One purpose-bound actor; only original-admitted, durable preparation."""
    global _ACTIVE

    if _ACTIVE is not None or completion._ACTIVE is not None:
        execution._fail("completion release preparation cannot overlap another call")
    # Reserve the complete future inventory before the actor's FIRST selected
    # target body. The target carries it forward, so controls adds zero again.
    future = (inputs.INPUT_RESERVATION_BYTES + intent._additional_original_bytes(owner)
        + exchange._exchange_reservation("consume") + _RECONCILIATION_IO_BYTES
        + completion._CONFIGURATION_RESERVATION)
    if type(future) is not int or not 0 < future < controls.MAX_ORIGINAL_BYTES:
        execution._fail("completion release preparation exceeds its original capacity")
    active, scope = None, None
    try:
        with actors._authorize_on_owner(owner, profile="consume", request=request,
                recovery_bytes=recovery_bytes, live_window=live_window,
                transport_deadline_ns=transport_deadline_ns, work=work, current=current,
                _purpose="release-intent-proof", _additional_original_bytes=future) as scope:
            scope.current()
            if (scope._purpose != "release-intent-proof" or scope._authorized is not True
                    or scope._completion_recovery_spent is not False
                    or scope._completion_receiving_current is not None):
                execution._fail("completion release preparation requires its fresh distinct actor")
            scope._completion_recovery_spent = True
            selected = controls._admit_on_actor(scope, _additional_original_bytes=0)
            if selected._actor is not scope or selected.work is not work:
                execution._fail("completion release preparation changed its original actor or work")
            active = _IntentProofAttempt(scope, selected)
            _ACTIVE = active
            configuration_digest = completion._configuration_digest(scope, selected=selected)
            pins = {"finalization_digest": selected.finalization_digest, "phase": "consume",
                "authorization_digest": selected.authorization_digest,
                "packet_digest": selected.packet_digest,
                "recovery_configuration_digest": configuration_digest}
            selected.current()
            retained = execution.custody.ControlPlaneCustodyClient.load_oidc_session_activation_completion_recovery_records(
                owner._custody, selected.finalization_digest, phase="consume", work=work,
                current=selected.current, maximum_original_bytes=_RECONCILIATION_IO_BYTES)
            selected.current()
            if retained is not None:
                response = completion._retained_response(selected, retained, pins)
                active.reconciliation_digest = retained.response.digest
            else:
                # Original acknowledged raw4 plus exact retained hints is also
                # eligible. Absence/uncertainty is NOT permission to exchange.
                response = selected.prior_response
            if type(response) is not tuple or len(response) != 6 or response[0] != b"acknowledged":
                execution._fail("completion release preparation has no acknowledged retained raw6")
            receiving_current = exchange._verify_on_controls(selected, response_originals=response)
            receiving_current()
            active.response, active.receiving_current = response, receiving_current
            scope._completion_receiving_current = receiving_current
            selected_inputs = inputs._admit_on_controls(selected,
                response_originals=response, receiving_current=receiving_current)
            inputs._require_inputs(selected_inputs)
            if selected_inputs.controls is not selected or selected_inputs.work is not work:
                execution._fail("completion release input admission changed the actual source call")
            active.inputs = selected_inputs
            selected_intent = intent._intent_on_inputs(selected_inputs)
            intent._require_intent(selected_intent)
            if selected_intent.inputs is not selected_inputs:
                execution._fail("completion release intent changed its actual input continuation")
            active.intent = selected_intent
            selected_proof = proof._proof_on_intent(selected_intent)
            proof._require_proof(selected_proof)
            if selected_proof.intent is not selected_intent or active.proof_spent is not True:
                execution._fail("completion release proof did not enter its sole original call")
            selected_proof.current()
            # Never attach a receiving child to actor.current(): that actor
            # is its own ancestor. Keep this terminal guard through cleanup.
            scope._completion_receiving_current = selected_proof.current
            scope._completion_receiving_current()
        if scope._normal_exit is not True:
            execution._fail("completion release preparation lacks normal actor cleanup")
        # No permission, token or successful private-original carrier escapes.
    finally:
        if active is not None:
            active.closed = True
            active.response = active.receiving_current = active.inputs = active.intent = None
        if _ACTIVE is active:
            _ACTIVE = None
