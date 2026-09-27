"""Private receiving completion verification with genuine historical custody.

Actual original caller/grant/encrypted plan and reserve/ACK admission derive
the expected marker. Actual completion/state signatures and the signed inner
observation must match it. No ID, alleged candidate or previous success is
accepted as proof. AES remains inside the separately admitted private owner.

The fixed private client holds all independent inputs before one socket call
and performs this real verification on the same current allowance. It neither
replays SQL nor signs, stores, retries, releases tokens or admits public
permission. Historical acknowledgments are not action-time current state.
Only a separately admitted private completion-purpose process can use this
client; generic application callers cannot borrow its custody or private keys.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_delivery_completion_admission as admission
from serverware import authority_oidc_session_activation_delivery_completion_transport as transport
from serverware import authority_oidc_session_activation_delivery_completion_custody as custody
from serverware import authority_registration_completion_response as shared


authorization, pending, grants = admission.authorization, admission.pending, admission.grants
evidence, records = shared.evidence, shared.records
OPERATION = admission.OPERATION
MAX_ORIGINAL_BYTES = admission.MAX_ORIGINAL_BYTES


class OidcSessionActivationDeliveryCompletionResponseError(ValueError):
    pass


class OidcSessionActivationDeliveryCompletionUncertainError(OidcSessionActivationDeliveryCompletionResponseError):
    """Closed uncertainty: no authenticated completion, identity or retry grant."""


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedCompletionResponse:
    """Original authenticated observations, never an accepted input proof."""

    completion_request_bytes: bytes
    state_receipt_bytes: bytes
    completion_request_digest: str
    state_receipt_digest: str


def _capture_on_work(*, plan_originals, reserve_request_bytes, reserve_receipt_bytes,
        snapshot_bytes, enrollment_bytes, authorization_bytes, authorization_enrollment_bytes,
        grant_bytes, grant_enrollment_bytes, expectations, planner_public_key, operation_public_key,
        root_public_key, configuration_digest, expected_authorization_digest, expected_database_id,
        expected_generation_digest, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, historical_custody, live_window, transport_deadline_ns, response_byte_count, work):
    """Own only original data before callbacks; no semantic-success carrier."""
    evidence.capture._SharedLedger(work)
    owner = historical_custody
    if type(owner) is not custody.OidcSessionActivationDeliveryCompletionCustody:
        raise OidcSessionActivationDeliveryCompletionResponseError(
            "consume completion receiver requires actual historical custody")
    if type(plan_originals) is not tuple or len(plan_originals) != 2:
        raise OidcSessionActivationDeliveryCompletionResponseError(
            "consume receiving requires exact plan/ciphertext raw2")
    originals = tuple(authorization._original(raw, maximum, "consume response plan original")
        for raw, maximum in zip(plan_originals, grants.FRAME_MAXIMA))
    enrollment = authorization._original(enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES,
        "consume response state enrollment")
    reserve = authorization._original(reserve_request_bytes, admission.records.MAX_REQUEST_BYTES,
        "consume response reserve original")
    receipt = authorization._original(reserve_receipt_bytes, admission.records.MAX_RECEIPT_BYTES,
        "consume response reserve ACK")
    snapshot = authorization._original(snapshot_bytes, admission.computation.MAX_SNAPSHOT_BYTES,
        "consume response computation snapshot")
    authorization.shape._integer(response_byte_count, MAX_ORIGINAL_BYTES)
    caller_raw = authorization._original(authorization_bytes,
        admission.caller.MAX_AUTHORIZATION_BYTES, "consume response caller")
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        admission.caller.MAX_ENROLLMENT_BYTES, "consume response caller enrollment")
    grant = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES, "consume response grant")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        admission.enrollments.MAX_ENROLLMENT_BYTES, "consume response grant enrollment")
    total = sum(len(raw) for raw in (*originals, enrollment, reserve, receipt, snapshot,
        caller_raw, caller_enrollment, grant, grant_enrollment))
    if total + response_byte_count > MAX_ORIGINAL_BYTES:
        raise OidcSessionActivationDeliveryCompletionResponseError(
            "consume completion receiver originals exceed the aggregate bound")
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
    expected = admission.expectations_wire._capture_on_work(expectations, work=work)
    evidence.plan._same(expected["scope"]["configurationDigest"], config, work,
        "consume response independent configuration")
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


def _start_on_work(held, work):
    """Fixed suffix over this call's owned inputs, never caller-supplied success."""
    owner = held["historical_custody"]
    custody.OidcSessionActivationDeliveryCompletionCustody.require_completion_on_work(owner, work=work)
    custody.OidcSessionActivationDeliveryCompletionCustody.bind_context_on_work(owner,
        root_public_key=held["root_public_key"], current_root_enrollment_bytes=held["enrollment_bytes"],
        work=work)
    window, bound = custody.OidcSessionActivationDeliveryCompletionCustody.processing_bounds_on_work(owner,
        live_window=held["live_window"], transport_deadline_ns=held["transport_deadline_ns"], work=work)
    held["live_window"], held["transport_deadline_ns"] = window, bound
    owner_live = custody.OidcSessionActivationDeliveryCompletionCustody.check_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    _window, processing = admission.delivery._window(window, bound, work)

    def current():
        first = processing()
        checked = owner_live()
        finished = processing()
        if checked < first or finished < checked:
            raise OidcSessionActivationDeliveryCompletionResponseError(
                "consume completion receiving clock reversed across custody")
        return finished

    current()
    return current


def _verify_on_work(*, response_originals, plan_originals,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes,
        enrollment_bytes, authorization_bytes, authorization_enrollment_bytes,
        grant_bytes, grant_enrollment_bytes, expectations, planner_public_key,
        operation_public_key, root_public_key, configuration_digest,
        expected_authorization_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        historical_custody, live_window, transport_deadline_ns, work):
    """Authenticate returned originals against actual historical pending replay."""
    returned = transport._originals(response_originals, response=True)
    held, _total = _capture_on_work(plan_originals=plan_originals,
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
        transport_deadline_ns=transport_deadline_ns, response_byte_count=sum(map(len, returned)), work=work)
    if returned[0] == b"uncertain":
        raise OidcSessionActivationDeliveryCompletionUncertainError("consume completion is not established")
    work.charge(input_bytes=len(returned[1]))
    returned_identity = returned[1].decode("ascii")
    current = _start_on_work(held, work)
    admitted = None

    def live():
        first = current()
        if admitted is not None:
            checked = admitted.live()
            finished = current()
            if checked < first or finished < checked:
                raise OidcSessionActivationDeliveryCompletionResponseError(
                    "consume completion receiving clock reversed across replay")
            return finished
        return first

    live()
    admitted = admission._admit_on_work(originals=held["plan_originals"],
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
        live_window=held["live_window"], transport_deadline_ns=held["transport_deadline_ns"], work=work)
    if type(admitted) is not admission._AdmittedCompletion:
        raise OidcSessionActivationDeliveryCompletionResponseError("consume receiver requires actual original admission")
    live()
    evidence.plan._same(admitted.authorization_digest, held["expected_authorization_digest"], work,
        "consume response independent caller authorization")
    acknowledged = records._verify_ack_on_work(request_bytes=returned[2], receipt_bytes=returned[3],
        enrollment_bytes=held["enrollment_bytes"], root_public_key=held["root_public_key"],
        expected_pending_sequence=held["expected_pending_sequence"],
        expected_pending_head_digest=held["expected_pending_head_digest"], work=work)
    live()
    evidence.plan._same(returned_identity, acknowledged.request_digest, work,
        "consume completion response ID differs from its original signed request")
    request, candidate = acknowledged.request_payload, admitted.candidate
    evidence.plan._same(request["action"], "complete", work, "consume completion response action")
    # These operation-neutral joins consume only this call's actual consume
    # candidate. No registration admission or successful external DTO is used.
    for field, column in shared._REQUEST_MARKER_JOINS:
        evidence.plan._same(request[field], candidate.marker[column], work,
            "consume completion control differs from genuine marker " + field)
    live()
    shared._observation_on_work(request, candidate, work)
    live()
    result = _VerifiedCompletionResponse(returned[2], returned[3],
        acknowledged.request_digest, acknowledged.receipt_digest)
    live()
    return result


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
    held, _total = _capture_on_work(plan_originals=plan_originals,
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
        transport_deadline_ns=transport_deadline_ns,
        response_byte_count=transport.MAX_RESPONSE_BYTES, work=work)
    # Capture reserves the entire fixed response ceiling before callbacks,
    # connection or receiving any bodies, not after allocating the exchange.
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
