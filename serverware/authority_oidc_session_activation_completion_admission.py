"""Historical activation originals into non-executable pending-completion facts.

The exact historical custody owner authenticates its independent cold scope
and genuinely replays the original caller/grant/encrypted plan. This adapter
authenticates the original reserve and ACK against independently supplied
database/generation/pending/fence pins, then reconstructs the exact snapshot,
complete vectors, marker and effects identity from that same replay.

Original execution intervals are algebraic constraints, never current clocks
or renewed permission. Actual current processing retains the supplied work,
window and inherited deadline. No successful candidate is accepted, and no
selected rows, mutations or executable result escape this fixed entrypoint.
Generic activation completion remains rejected; this is not a reader, signer,
state publisher, SQL executor, token release or cross-source history resolver.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_current_root_execution_admission as pending
from serverware import authority_oidc_session_activation_history_exchange as exchange
from serverware import authority_successor_execution_admission as successor
from serverware import authority_successor_execution_recovery_packet as recovery
from serverware import oidc_session_activation_delivery as delivery


authorization, computation, vector = pending.authorization, pending.computation, pending.vector
evidence, clock = pending.evidence, pending.clock
caller, grants, plan = exchange.caller, exchange.grants, exchange.plan
OPERATION = exchange.OPERATION
MAX_ORIGINAL_BYTES = pending.replay.MAX_ORIGINAL_BYTES


class OidcSessionActivationCompletionAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AdmittedCompletion:
    """Same-invocation private suffix; never an admitted input or effects DTO."""

    candidate: pending._PendingCompletion
    effects_digest: str
    authorization_digest: str
    live: object


def _admit_on_work(*, originals, expectations, planner_public_key,
        operation_public_key, enrollment_bytes, root_public_key, reserve_request_bytes,
        reserve_receipt_bytes, snapshot_bytes, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        authorization_bytes, authorization_enrollment_bytes, grant_bytes,
        grant_enrollment_bytes, configuration_digest, historical_custody,
        live_window, transport_deadline_ns, work):
    """Authenticate all originals once; return pending scope plus effects ID only."""
    # Lazy import avoids a bootstrap/owner/completion composition import cycle.
    from serverware import authority_oidc_session_activation_history_custody as custody

    evidence.capture._SharedLedger(work)
    owner = historical_custody
    if type(owner) is not custody.OidcSessionActivationHistoryCustody:
        raise OidcSessionActivationCompletionAdmissionError(
            "activation completion requires the actual historical custody owner")
    held = pending._originals(OPERATION, originals, enrollment_bytes,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes)
    raw2, enrollment, reserve, receipt_raw, snapshot_raw = held
    caller_raw = authorization._original(authorization_bytes,
        caller.MAX_AUTHORIZATION_BYTES, "activation completion caller")
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        caller.MAX_ENROLLMENT_BYTES, "activation completion caller enrollment")
    grant_raw = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES,
        "activation completion grant")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "activation completion grant enrollment")
    if sum(len(raw) for raw in (*raw2, *held[1:], caller_raw, caller_enrollment,
            grant_raw, grant_enrollment)) > MAX_ORIGINAL_BYTES:
        raise OidcSessionActivationCompletionAdmissionError(
            "activation completion originals exceed the aggregate byte bound")
    root, planner, operation_key, config = (root_public_key, planner_public_key,
        operation_public_key, configuration_digest)
    for key in (root, planner, operation_key):
        authorization._public(key)
    authorization.shape._digest(config)
    authorization.shape._integer(transport_deadline_ns, minimum=1)
    scope = pending._scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    window, inherited = scope[5:]
    bound = min(window[4], inherited)
    # Detach the sole external JSON graph before any native key/clock callback.
    expected = pending.replay._expectations(OPERATION, expectations, planner, operation_key, work)
    plan._same(expected["scope"]["configurationDigest"], config, work,
        "activation completion independent configuration")
    _window, processing = delivery._window(window, bound, work)
    verified = None

    def live():
        first = processing()
        if verified is not None:
            joined = verified.live()
            finished = processing()
            if joined < first or finished < joined:
                raise OidcSessionActivationCompletionAdmissionError(
                    "activation completion processing reversed across original replay")
            return finished
        return first

    live()
    custody.OidcSessionActivationHistoryCustody.bind_context_on_work(owner,
        root_public_key=root, current_root_enrollment_bytes=enrollment, work=work)
    live()
    material, request, request_digest = authorization._verify_historical_request_on_work(
        request_bytes=reserve, enrollment_bytes=enrollment, root_public_key=root, work=work)
    if request["action"] != "reserve":
        raise OidcSessionActivationCompletionAdmissionError(
            "activation completion requires the original reserve")
    live()
    receipt = authorization._verify_receipt_on_work(receipt_bytes=receipt_raw,
        enrollment_bytes=enrollment, root_public_key=root, work=work)
    receipt_digest = authorization._receipt_digest_on_work(receipt_raw, work)
    pending._pending(material, request, request_digest, receipt, receipt_digest, scope, work)
    plan._same(request["operation"], OPERATION, work,
        "activation completion reserve operation")
    before = vector._encode_on_work(request["beforeVector"], work=work)
    live()
    # The owner independently joins this signed-reserve vector to its original
    # root-pinned complete vector; the ACK never chooses current pending scope.
    verified = custody.OidcSessionActivationHistoryCustody.verify_exchange_on_work(owner,
        originals=raw2, expectations=expected, before_vector_bytes=before,
        authorization_bytes=caller_raw, grant_bytes=grant_raw,
        authorization_enrollment_bytes=caller_enrollment, grant_enrollment_bytes=grant_enrollment,
        current_root_enrollment_bytes=enrollment, root_public_key=root,
        planner_public_key=planner, operation_public_key=operation_key,
        configuration_digest=config, live_window=window, transport_deadline_ns=bound, work=work)
    if (type(verified) is not exchange._HistoricalExchange
            or type(verified.replayed) is not exchange.history._HistoricalReplayedPlan):
        raise OidcSessionActivationCompletionAdmissionError(
            "activation completion requires genuine same-call historical exchange")
    live()
    replayed = verified.replayed
    for actual, wanted in ((verified.database_id, scope[0]),
            (verified.generation_digest, scope[1]), (replayed.operation, OPERATION),
            (request["capabilityDigest"], verified.grant_digest)):
        plan._same(actual, wanted, work, "activation completion independent original scope")
    for field in ("operation", "requestDigest", "operationId"):
        plan._same(request[field], replayed.request[field], work,
            "activation completion reserve differs from actual typed request")
    if (request["issuedAtEpochNs"] != replayed.original_interval[0]
            or request["expiresAtEpochNs"] > replayed.original_interval[1]):
        raise OidcSessionActivationCompletionAdmissionError(
            "activation completion reserve retimed or renewed its original plan")
    expected_snapshot = computation._snapshot(replayed, material, verified.grant_digest, work)
    expected_snapshot_raw = computation._snapshot_wire(expected_snapshot, work)
    work.charge(input_bytes=len(expected_snapshot_raw) + len(snapshot_raw))
    if expected_snapshot_raw != snapshot_raw:
        raise OidcSessionActivationCompletionAdmissionError(
            "activation completion snapshot differs from genuine historical replay")
    snapshot_digest = computation._snapshot_digest_on_work(snapshot_raw, work=work)
    plan._same(snapshot_digest, request["snapshotDigest"], work,
        "activation completion reserve snapshot identity")
    after = vector._encode_on_work(request["afterVector"], work=work)
    work.charge(input_bytes=len(before) + len(replayed.before_vector_bytes)
        + len(after) + len(replayed.after_vector_bytes))
    if before != replayed.before_vector_bytes or after != replayed.after_vector_bytes:
        raise OidcSessionActivationCompletionAdmissionError(
            "activation completion vectors differ from actual historical effects")
    for field, actual in (("beforeVectorDigest", replayed.before_vector_digest),
            ("afterVectorDigest", replayed.after_vector_digest)):
        plan._same(receipt[field], actual, work,
            "activation completion ACK differs from actual complete vectors")
    live()
    # This immutable original was authenticated in the actual exchange above.
    # Decode its original interval/claims, not another incoming success object;
    # do not repeat the expensive private plan replay or invent a live clock.
    grant = grants._read(grant_raw, enrollment=False, work=work)["payload"]
    plan._same(grant["currentRootEnrollmentDigest"], expected_snapshot["enrollmentDigest"], work,
        "activation completion grant enrollment differs from genuine computation")
    for field in successor._SNAPSHOT_JOINS:
        plan._same(grant[field], expected_snapshot[field], work,
            "activation completion grant differs from genuine computation " + field)
    if (request["issuedAtEpochNs"] != grant["issuedAtEpochNs"]
            or request["expiresAtEpochNs"] > grant["expiresAtEpochNs"]):
        raise OidcSessionActivationCompletionAdmissionError(
            "activation completion reserve extends original caller/grant authority")
    marker = pending._marker(material, request, request_digest, receipt, receipt_digest,
        expected_snapshot, work)
    live()
    effects_digest = recovery._effects_digest_on_work(selected_rows=replayed.selected_rows,
        mutations=replayed.mutations, result=replayed.result, work_units=replayed.work_units, work=work)
    live()
    candidate = pending._PendingCompletion(OPERATION, marker, replayed.after_vector_bytes,
        reserve, receipt_raw, snapshot_raw,
        (request["issuedAtEpochNs"], request["expiresAtEpochNs"]))
    result = _AdmittedCompletion(candidate, effects_digest, verified.authorization_digest, live)
    live()
    return result
