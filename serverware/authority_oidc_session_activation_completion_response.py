"""Private receiving completion verification with genuine historical custody.

Actual original caller/grant/encrypted plan and reserve/ACK admission derive
the expected marker. Actual completion/state signatures and the signed inner
observation must match it. No ID, alleged candidate or previous success is
accepted as proof. AES remains inside the separately admitted private owner.

The fixed private client holds all independent inputs before one socket call
and performs this real verification on the same current allowance. It neither
replays SQL nor signs, stores, retries, releases tokens or admits public
permission. Historical acknowledgments are not action-time current state.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_completion_admission as admission
from serverware import authority_oidc_session_activation_completion_transport as transport
from serverware import authority_oidc_session_activation_history_custody as custody
from serverware import authority_registration_completion_response as shared


authorization, pending, grants = shared.authorization, shared.pending, shared.grants
evidence, records = shared.evidence, shared.records
OPERATION = admission.OPERATION
MAX_ORIGINAL_BYTES = admission.MAX_ORIGINAL_BYTES


class OidcSessionActivationCompletionResponseError(ValueError):
    pass


class OidcSessionActivationCompletionUncertainError(OidcSessionActivationCompletionResponseError):
    """Closed uncertainty: no authenticated completion, identity or retry grant."""


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedCompletionResponse:
    """Original authenticated observations, never an accepted input proof."""

    completion_request_bytes: bytes
    state_receipt_bytes: bytes
    completion_request_digest: str
    state_receipt_digest: str


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedDeliveryCompletion:
    """Authentic same-call delivery identities, never a verifier input."""

    completion: _VerifiedCompletionResponse
    activation_plan_digest: str
    delivery_id: str
    delivery_scope_digest: str
    delivery_row_digest: str
    delivery_envelope_digest: str
    live: object


def _capture_on_work(*, plan_originals, reserve_request_bytes, reserve_receipt_bytes,
        snapshot_bytes, enrollment_bytes, authorization_bytes, authorization_enrollment_bytes,
        grant_bytes, grant_enrollment_bytes, expectations, planner_public_key, operation_public_key,
        root_public_key, configuration_digest, expected_authorization_digest, expected_database_id,
        expected_generation_digest, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, historical_custody, live_window, transport_deadline_ns, work):
    """Own only original data before callbacks; no semantic-success carrier."""
    evidence.capture._SharedLedger(work)
    owner = historical_custody
    if type(owner) is not custody.OidcSessionActivationHistoryCustody:
        raise OidcSessionActivationCompletionResponseError(
            "activation completion receiver requires actual historical custody")
    held = pending._originals(OPERATION, plan_originals, enrollment_bytes,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes)
    originals, enrollment, reserve, receipt, snapshot = held
    caller_raw = authorization._original(authorization_bytes,
        admission.caller.MAX_AUTHORIZATION_BYTES, "activation response caller")
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        admission.caller.MAX_ENROLLMENT_BYTES, "activation response caller enrollment")
    grant = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES, "activation response grant")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "activation response grant enrollment")
    total = sum(len(raw) for raw in (*originals, *held[1:], caller_raw,
        caller_enrollment, grant, grant_enrollment))
    if total > MAX_ORIGINAL_BYTES:
        raise OidcSessionActivationCompletionResponseError(
            "activation completion receiver originals exceed the aggregate bound")
    root, planner, operation_key = root_public_key, planner_public_key, operation_public_key
    for key in (root, planner, operation_key):
        authorization._public(key)
    config, authorization_digest = configuration_digest, expected_authorization_digest
    authorization.shape._digest(config)
    authorization.shape._digest(authorization_digest)
    authorization.shape._integer(transport_deadline_ns, minimum=1)
    scope = pending._scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    expected = pending.replay._expectations(OPERATION, expectations, planner, operation_key, work)
    evidence.plan._same(expected["scope"]["configurationDigest"], config, work,
        "activation response independent configuration")
    return {"plan_originals": originals, "reserve_request_bytes": reserve,
        "reserve_receipt_bytes": receipt, "snapshot_bytes": snapshot, "enrollment_bytes": enrollment,
        "authorization_bytes": caller_raw, "authorization_enrollment_bytes": caller_enrollment,
        "grant_bytes": grant, "grant_enrollment_bytes": grant_enrollment, "expectations": expected,
        "planner_public_key": planner, "operation_public_key": operation_key, "root_public_key": root,
        "configuration_digest": config, "expected_authorization_digest": authorization_digest,
        "expected_database_id": scope[0], "expected_generation_digest": scope[1],
        "expected_pending_sequence": scope[2], "expected_pending_head_digest": scope[3],
        "expected_fence": scope[4], "historical_custody": owner, "live_window": scope[5],
        "transport_deadline_ns": min(scope[5][4], scope[6])}, total


def _start_on_work(held, work, *, expected_consume_request=None, _current=None):
    """Fixed suffix over this call's owned inputs, never caller-supplied success."""
    owner = held["historical_custody"]
    if expected_consume_request is None:
        custody.OidcSessionActivationHistoryCustody.require_completion_on_work(owner, work=work)
    else:
        custody.OidcSessionActivationHistoryCustody.bind_consume_request_on_work(owner,
            expected_consume_request=expected_consume_request, work=work)
    custody.OidcSessionActivationHistoryCustody.bind_context_on_work(owner,
        root_public_key=held["root_public_key"], current_root_enrollment_bytes=held["enrollment_bytes"],
        work=work)
    window, bound = custody.OidcSessionActivationHistoryCustody.processing_bounds_on_work(owner,
        live_window=held["live_window"], transport_deadline_ns=held["transport_deadline_ns"],
        work=work, _current=_current)
    held["live_window"], held["transport_deadline_ns"] = window, bound
    owner_live = custody.OidcSessionActivationHistoryCustody.check_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work, _current=_current)
    _window, processing = admission.delivery._window(window, bound, work)
    processing = admission.delivery._join_current(processing, _current, work)

    def current():
        first = processing()
        checked = owner_live()
        finished = processing()
        if checked < first or finished < checked:
            raise OidcSessionActivationCompletionResponseError(
                "activation completion receiving clock reversed across custody")
        return finished

    current()
    return current


def _verify_originals_on_work(*, response_originals, plan_originals,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes,
        enrollment_bytes, authorization_bytes, authorization_enrollment_bytes,
        grant_bytes, grant_enrollment_bytes, expectations, planner_public_key,
        operation_public_key, root_public_key, configuration_digest,
        expected_authorization_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        historical_custody, live_window, transport_deadline_ns, work, include_delivery,
        expected_consume_request=None, _current=None):
    """Authenticate returned originals against actual historical pending replay."""
    returned = transport._originals(response_originals, response=True)
    if include_delivery:
        consume = custody.history.assertion._Capture(evidence.capture._SharedLedger(work),
            maximum_bytes=custody.bootstrap.MAX_CONSUME_REQUEST_BYTES).visit(expected_consume_request)
        if type(consume) is not dict:
            raise OidcSessionActivationCompletionResponseError(
                "delivery provenance requires its independently supplied consume request")
    else:
        if expected_consume_request is not None:
            raise OidcSessionActivationCompletionResponseError(
                "completion receiving cannot accept a consume purpose")
        consume = None
    held, total = _capture_on_work(plan_originals=plan_originals,
        reserve_request_bytes=reserve_request_bytes, reserve_receipt_bytes=reserve_receipt_bytes,
        snapshot_bytes=snapshot_bytes, enrollment_bytes=enrollment_bytes,
        authorization_bytes=authorization_bytes, authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_bytes=grant_bytes, grant_enrollment_bytes=grant_enrollment_bytes, expectations=expectations,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        root_public_key=root_public_key, configuration_digest=configuration_digest,
        expected_authorization_digest=expected_authorization_digest, expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest, expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        historical_custody=historical_custody, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    consume_size = work.measure(consume)[0] if include_delivery else 0
    if total + sum(map(len, returned)) + consume_size > MAX_ORIGINAL_BYTES:
        raise OidcSessionActivationCompletionResponseError(
            "activation completion returned originals exceed the aggregate bound")
    if returned[0] == b"uncertain":
        raise OidcSessionActivationCompletionUncertainError("activation completion is not established")
    work.charge(input_bytes=len(returned[1]))
    returned_identity = returned[1].decode("ascii")
    current = _start_on_work(held, work, expected_consume_request=consume, _current=_current)
    admitted = None

    def live():
        first = current()
        if admitted is not None:
            checked = admitted.live()
            finished = current()
            if checked < first or finished < checked:
                raise OidcSessionActivationCompletionResponseError(
                    "activation completion receiving clock reversed across replay")
            return finished
        return first

    live()
    admit = admission._admit_for_delivery_on_work if include_delivery else admission._admit_on_work
    actual_admission = admit(originals=held["plan_originals"],
        expectations=held["expectations"], planner_public_key=held["planner_public_key"],
        operation_public_key=held["operation_public_key"], enrollment_bytes=held["enrollment_bytes"],
        root_public_key=held["root_public_key"], reserve_request_bytes=held["reserve_request_bytes"],
        reserve_receipt_bytes=held["reserve_receipt_bytes"], snapshot_bytes=held["snapshot_bytes"],
        expected_database_id=held["expected_database_id"], expected_generation_digest=held["expected_generation_digest"],
        expected_pending_sequence=held["expected_pending_sequence"],
        expected_pending_head_digest=held["expected_pending_head_digest"], expected_fence=held["expected_fence"],
        authorization_bytes=held["authorization_bytes"],
        authorization_enrollment_bytes=held["authorization_enrollment_bytes"],
        grant_bytes=held["grant_bytes"], grant_enrollment_bytes=held["grant_enrollment_bytes"],
        configuration_digest=held["configuration_digest"], historical_custody=held["historical_custody"],
        live_window=held["live_window"], transport_deadline_ns=held["transport_deadline_ns"],
        work=work, _current=_current)
    if include_delivery:
        if type(actual_admission) is not admission._AdmittedDeliveryCompletion:
            raise OidcSessionActivationCompletionResponseError(
                "activation receiver requires actual original delivery admission")
        admitted = actual_admission.admission
    else:
        admitted = actual_admission
    if type(admitted) is not admission._AdmittedCompletion:
        raise OidcSessionActivationCompletionResponseError("activation receiver requires actual original admission")
    live()
    evidence.plan._same(admitted.authorization_digest, held["expected_authorization_digest"], work,
        "activation response independent caller authorization")
    acknowledged = records._verify_ack_on_work(request_bytes=returned[2], receipt_bytes=returned[3],
        enrollment_bytes=held["enrollment_bytes"], root_public_key=held["root_public_key"],
        expected_pending_sequence=held["expected_pending_sequence"],
        expected_pending_head_digest=held["expected_pending_head_digest"], work=work)
    live()
    evidence.plan._same(returned_identity, acknowledged.request_digest, work,
        "activation completion response ID differs from its original signed request")
    request, candidate = acknowledged.request_payload, admitted.candidate
    evidence.plan._same(request["action"], "complete", work, "activation completion response action")
    # These operation-neutral joins consume only this call's actual activation
    # candidate. No registration admission or successful external DTO is used.
    for field, column in shared._REQUEST_MARKER_JOINS:
        evidence.plan._same(request[field], candidate.marker[column], work,
            "activation completion control differs from genuine marker " + field)
    live()
    shared._observation_on_work(request, candidate, work)
    live()
    result = _VerifiedCompletionResponse(returned[2], returned[3],
        acknowledged.request_digest, acknowledged.receipt_digest)
    live()
    if include_delivery:
        result = _VerifiedDeliveryCompletion(result, actual_admission.activation_plan_digest,
            actual_admission.delivery_id, actual_admission.delivery_scope_digest,
            actual_admission.delivery_row_digest, actual_admission.delivery_envelope_digest, live)
        live()
    return result


def _verify_on_work(*, response_originals, plan_originals,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes,
        enrollment_bytes, authorization_bytes, authorization_enrollment_bytes,
        grant_bytes, grant_enrollment_bytes, expectations, planner_public_key,
        operation_public_key, root_public_key, configuration_digest,
        expected_authorization_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        historical_custody, live_window, transport_deadline_ns, work):
    """Preserved original-only completion verification and four-field result."""
    return _verify_originals_on_work(response_originals=response_originals, plan_originals=plan_originals,
        reserve_request_bytes=reserve_request_bytes, reserve_receipt_bytes=reserve_receipt_bytes,
        snapshot_bytes=snapshot_bytes, enrollment_bytes=enrollment_bytes, authorization_bytes=authorization_bytes,
        authorization_enrollment_bytes=authorization_enrollment_bytes, grant_bytes=grant_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, expectations=expectations,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        root_public_key=root_public_key, configuration_digest=configuration_digest,
        expected_authorization_digest=expected_authorization_digest, expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest, expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        historical_custody=historical_custody, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, include_delivery=False)


def _verify_delivery_on_work(*, expected_consume_request, response_originals, plan_originals,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes,
        enrollment_bytes, authorization_bytes, authorization_enrollment_bytes,
        grant_bytes, grant_enrollment_bytes, expectations, planner_public_key,
        operation_public_key, root_public_key, configuration_digest,
        expected_authorization_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        historical_custody, live_window, transport_deadline_ns, work, _current=None):
    """Original-only suffix: verify completion and expose authentic delivery IDs."""
    return _verify_originals_on_work(response_originals=response_originals, plan_originals=plan_originals,
        reserve_request_bytes=reserve_request_bytes, reserve_receipt_bytes=reserve_receipt_bytes,
        snapshot_bytes=snapshot_bytes, enrollment_bytes=enrollment_bytes, authorization_bytes=authorization_bytes,
        authorization_enrollment_bytes=authorization_enrollment_bytes, grant_bytes=grant_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, expectations=expectations,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        root_public_key=root_public_key, configuration_digest=configuration_digest,
        expected_authorization_digest=expected_authorization_digest, expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest, expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        historical_custody=historical_custody, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, include_delivery=True,
        expected_consume_request=expected_consume_request, _current=_current)


def _request_on_work(endpoint, *, packet_digest, plan_originals,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes,
        enrollment_bytes, authorization_bytes, authorization_enrollment_bytes,
        grant_bytes, grant_enrollment_bytes, expectations, planner_public_key,
        operation_public_key, root_public_key, configuration_digest,
        expected_authorization_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        historical_custody, live_window, transport_deadline_ns, work):
    """One fixed private exchange followed by genuine receiving verification.

    Packet identity selects the request only: raw4 has no packet ID, so this
    function makes no returned packet-identity or latest-head claim.
    """
    configured = transport._endpoint(endpoint)
    authorization.shape._digest(packet_digest)
    selected_packet = packet_digest
    held, total = _capture_on_work(plan_originals=plan_originals,
        reserve_request_bytes=reserve_request_bytes, reserve_receipt_bytes=reserve_receipt_bytes,
        snapshot_bytes=snapshot_bytes, enrollment_bytes=enrollment_bytes,
        authorization_bytes=authorization_bytes, authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_bytes=grant_bytes, grant_enrollment_bytes=grant_enrollment_bytes, expectations=expectations,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        root_public_key=root_public_key, configuration_digest=configuration_digest,
        expected_authorization_digest=expected_authorization_digest, expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest, expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        historical_custody=historical_custody, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    # Reserve the entire fixed response ceiling before connecting or receiving
    # any bodies, not merely after an oversized exchange has been allocated.
    if total + transport.MAX_RESPONSE_BYTES > MAX_ORIGINAL_BYTES:
        raise OidcSessionActivationCompletionResponseError(
            "activation completion cannot reserve its bounded original response")
    work.prepare_utf8(selected_packet)
    request = (transport.PURPOSE, selected_packet.encode("ascii"))
    current = _start_on_work(held, work)
    current()
    returned = transport._socket_request(configured, originals=request,
        deadline_ns=held["transport_deadline_ns"])
    current()
    # Only original inputs are forwarded; the actual private full replay runs
    # once here after transport, not in a supplied-success shortcut.
    result = _verify_on_work(response_originals=returned, **held, work=work)
    current()
    return result
