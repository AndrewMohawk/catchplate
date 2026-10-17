"""Original completed-activation provenance for a distinct delivery consume.

Actual historical custody replays the original activation once, and the real
completion receiver verifies signed complete/state originals against that replay.
Only then are its typed subject/rotation and original delivery INSERT joined to
the consume request and supplied current-row data. The latter is not proved
current here: the separate consumption transition must verify its current proofs.

No previous success, raw pending ACK, claimed digest or consumed flag is proof.
This prerequisite neither executes a consume nor releases/decrypts a token or
establishes fresh public permission, current state or committed consumption.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from catchplate import authority_oidc_session_activation_completion_response as response
from catchplate import authority_transition_oidc_session_activation_delivery as consumption


assertion, registration, core = consumption.assertion, consumption.registration, consumption.core
admission, evidence, plan = response.admission, response.evidence, response.admission.plan
OPERATION = consumption.OPERATION
ACTIVATION_OPERATION = response.OPERATION
SCHEMA = "catchplate.oidcSessionActivationDeliveryProvenance/v1"
IDENTITY_DOMAIN = "catchplate.oidcSessionActivationDeliveryProvenanceIdentity/v1"
MAX_ORIGINAL_BYTES = response.MAX_ORIGINAL_BYTES
MAX_CONTEXT_BYTES = assertion.MAX_CONTEXT_BYTES


class OidcSessionActivationDeliveryProvenanceError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedProvenance:
    """Same-call diagnostic identities/current guard; never an admitted input."""

    activation_request_digest: str
    activation_plan_digest: str
    completion_request_digest: str
    state_receipt_digest: str
    delivery_id: str
    delivery_scope_digest: str
    delivery_row_digest: str
    delivery_envelope_digest: str
    provenance_digest: str
    live: Callable[[], int]


def _fail(message):
    raise OidcSessionActivationDeliveryProvenanceError(message)


def _capture_on_work(*, consume_request, current_delivery_row,
        response_originals, plan_originals, reserve_request_bytes, reserve_receipt_bytes,
        snapshot_bytes, enrollment_bytes, authorization_bytes, authorization_enrollment_bytes,
        grant_bytes, grant_enrollment_bytes, expectations, planner_public_key,
        operation_public_key, root_public_key, configuration_digest,
        expected_authorization_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        historical_custody, live_window, transport_deadline_ns, work):
    """Return owned original kwargs, not authority or a successful proof carrier.

    A composing caller must own its OTHER external graphs before calling this
    helper: actual typed-expectation commitment hashing is part of capture.
    No clock allowance is opened and no signature/custody result is accepted.
    """
    ledger = evidence.capture._SharedLedger(work)
    registration._closed(consume_request, plan.contract.shape.TYPED_REQUEST_FIELDS,
        "delivery consumption typed request")
    registration._closed(current_delivery_row, admission._DELIVERY_FIELDS,
        "delivery provenance supplied current row")
    # Own these external graphs before the existing response capture hashes
    # its separate expectation graph. Original frames are exact immutable bytes.
    owned = assertion._Capture(ledger, maximum_bytes=MAX_CONTEXT_BYTES).visit({
        "request": consume_request, "delivery": current_delivery_row})
    returned = response.transport._originals(response_originals, response=True)
    held, total = response._capture_on_work(plan_originals=plan_originals,
        reserve_request_bytes=reserve_request_bytes, reserve_receipt_bytes=reserve_receipt_bytes,
        snapshot_bytes=snapshot_bytes, enrollment_bytes=enrollment_bytes,
        authorization_bytes=authorization_bytes, authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_bytes=grant_bytes, grant_enrollment_bytes=grant_enrollment_bytes,
        expectations=expectations, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, root_public_key=root_public_key,
        configuration_digest=configuration_digest, expected_authorization_digest=expected_authorization_digest,
        expected_database_id=expected_database_id, expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence, expected_pending_head_digest=expected_pending_head_digest,
        expected_fence=expected_fence, historical_custody=historical_custody,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    size, _nodes = work.measure(owned)
    expected_size, _nodes = work.measure(held["expectations"])
    if total + sum(map(len, returned)) + size + expected_size > MAX_ORIGINAL_BYTES:
        _fail("activation delivery provenance exceeds its original aggregate bound")
    return {**held, "response_originals": returned, "consume_request": owned["request"],
        "current_delivery_row": owned["delivery"]}


def _verify_on_work(*, consume_request, current_delivery_row,
        response_originals, plan_originals, reserve_request_bytes, reserve_receipt_bytes,
        snapshot_bytes, enrollment_bytes, authorization_bytes, authorization_enrollment_bytes,
        grant_bytes, grant_enrollment_bytes, expectations, planner_public_key,
        operation_public_key, root_public_key, configuration_digest,
        expected_authorization_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        historical_custody, live_window, transport_deadline_ns, work, _current=None):
    """Genuinely authenticate original completion and join this consume once."""
    held = _capture_on_work(consume_request=consume_request, current_delivery_row=current_delivery_row,
        response_originals=response_originals, plan_originals=plan_originals,
        reserve_request_bytes=reserve_request_bytes, reserve_receipt_bytes=reserve_receipt_bytes,
        snapshot_bytes=snapshot_bytes, enrollment_bytes=enrollment_bytes,
        authorization_bytes=authorization_bytes, authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_bytes=grant_bytes, grant_enrollment_bytes=grant_enrollment_bytes,
        expectations=expectations, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, root_public_key=root_public_key,
        configuration_digest=configuration_digest, expected_authorization_digest=expected_authorization_digest,
        expected_database_id=expected_database_id, expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence, expected_pending_head_digest=expected_pending_head_digest,
        expected_fence=expected_fence, historical_custody=historical_custody,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    current_request = held.pop("consume_request")
    current_row = held.pop("current_delivery_row")
    _window, current = admission.delivery._window(held["live_window"], held["transport_deadline_ns"], work)
    current = admission.delivery._join_current(current, _current, work)
    actual = None

    def live():
        first = current()
        if actual is not None:
            checked = actual.live()
            finished = current()
            if checked < first or finished < checked:
                _fail("activation delivery provenance clock reversed across original completion")
            return finished
        return first

    live()
    if current_request["operation"] != OPERATION:
        _fail("activation delivery provenance requires the distinct consume operation")
    consume_digest = plan.commitment._typed_request_digest(current_request, work=work)
    registration._same(current_request["requestDigest"], consume_digest, work,
        "delivery consume typed request commitment")
    consume_id = evidence.plan._frame("catchplate.policyAuthorityOperation/v2",
        (evidence.plan._ascii(OPERATION, work), evidence.plan._ascii(consume_digest, work)), work)
    registration._same(current_request["operationId"], consume_id, work,
        "delivery consume typed operation identity")
    values = consumption._arguments(current_request["arguments"], work)
    live()
    # The diagnostic suffix shares the existing actual verifier algorithm and
    # performs its historical replay ONCE. It accepts only the original inputs.
    actual = response._verify_delivery_on_work(expected_consume_request=current_request,
        **held, work=work, _current=_current)
    if type(actual) is not response._VerifiedDeliveryCompletion:
        _fail("delivery provenance requires the actual original completion verifier")
    live()
    activation_request = held["expectations"]["request"]
    if activation_request["operation"] != ACTIVATION_OPERATION:
        _fail("delivery provenance activation family differs")
    original_values = activation_request["arguments"]
    for field in ("user_id", "session_id", "credential_id", "credential_record_id", "challenge_id",
            "old_token_digest", "new_token_digest", "assertion_digest"):
        registration._same(values[field], original_values[field], work,
            "consume differs from completed activation " + field)
    identity = core._deterministic_uuid(operation=ACTIVATION_OPERATION,
        request_digest=activation_request["requestDigest"], purpose=plan.transition.DELIVERY_PURPOSE, work=work)
    registration._same((values["delivery_id"], actual.delivery_id), (identity, identity), work,
        "consume delivery differs from original deterministic insertion")
    # Only hashes of the original replayed INSERT escaped the verifier. Match
    # every current-row column (including exact retained ciphertext/times) to
    # that authentic row, not just its ID or a received scalar digest. Current
    # membership, status/lifetime and old-token possession are separately proved
    # by the original consumption transition; this supplied row is not authority.
    observed = admission._delivery_identity_on_work(current_row, activation_request, work)
    expected = (actual.delivery_id, actual.delivery_scope_digest,
        actual.delivery_row_digest, actual.delivery_envelope_digest)
    registration._same(observed, expected, work,
        "consume current delivery differs from the authentic completed insertion")
    live()
    completed = actual.completion
    diagnostics = {"schema": SCHEMA, "sourceRevision": registration.authority.SOURCE_REVISION,
        "consumeRequestDigest": consume_digest, "consumeOperationId": consume_id,
        "activationRequestDigest": activation_request["requestDigest"],
        "activationPlanDigest": actual.activation_plan_digest,
        "activationConfigurationDigest": held["configuration_digest"],
        "activationAuthorizationDigest": held["expected_authorization_digest"],
        "activationJournalDigest": held["expectations"]["journalDigest"],
        "completionRequestDigest": completed.completion_request_digest,
        "stateReceiptDigest": completed.state_receipt_digest, "deliveryId": actual.delivery_id,
        "deliveryScopeDigest": actual.delivery_scope_digest, "deliveryRowDigest": actual.delivery_row_digest,
        "deliveryEnvelopeDigest": actual.delivery_envelope_digest}
    digest = evidence.plan._frame(IDENTITY_DOMAIN, (registration._wire(diagnostics, work),), work)
    live()
    result = _VerifiedProvenance(activation_request["requestDigest"], actual.activation_plan_digest,
        completed.completion_request_digest, completed.state_receipt_digest, actual.delivery_id,
        actual.delivery_scope_digest, actual.delivery_row_digest, actual.delivery_envelope_digest, digest, live)
    live()
    return result
