"""Original-only committed-consumption facts, never plaintext-release authority.

One genuine consume completion admission is joined to a normally closed real
commit read and the original signed completion/state ACK. Independently held
release targets must match both the authenticated effects and full activation
provenance. The current processing allowance never renews historical originals.
No signing key, release AES key, SQL write, outcome store or retry is accepted.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_current_root_completion as common
from serverware import authority_oidc_session_activation_delivery_completion_admission as admission
from serverware import authority_oidc_session_activation_delivery_completion_custody as custody
from serverware import authority_oidc_session_activation_delivery_recovery_packet as packets
from serverware import authority_oidc_session_activation_release_committed_inputs as inputs
from serverware import authority_oidc_session_activation_release_committed_target as target
from serverware import authority_registration_completion_response as shared
from serverware import authority_successor_execution_window as processing_window


authorization, evidence, reader = common.authorization, common.evidence, common.reader
delivery, vector, records = admission.delivery, common.vector, shared.records
OPERATION = admission.OPERATION


class OidcSessionActivationReleaseCommittedError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CommittedOriginals:
    """Private same-call facts/current guard; no API accepts this as proof."""

    consume_binding: dict
    release_binding: dict
    completion_request_bytes: bytes
    state_receipt_bytes: bytes
    state_receipt_digest: str
    live: object


def _fail(message):
    raise OidcSessionActivationReleaseCommittedError(message)


def _verify_on_work(*, packet_bytes, completion_request_bytes, state_receipt_bytes,
        expected_consume_binding, expected_release, expectations, planner_public_key,
        operation_public_key, root_public_key, authorization_bytes,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        configuration_digest, expected_authorization_digest, expected_database_id,
        expected_generation_digest, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, historical_custody, commit_reader, live_window, transport_deadline_ns, work):
    """Derive committed facts from original bytes and independent actual owners."""
    held = inputs._capture_on_work(packet_bytes=packet_bytes,
        completion_request_bytes=completion_request_bytes, state_receipt_bytes=state_receipt_bytes,
        expected_consume_binding=expected_consume_binding, expected_release=expected_release,
        expectations=expectations, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, root_public_key=root_public_key,
        authorization_bytes=authorization_bytes, authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, current_root_enrollment_bytes=current_root_enrollment_bytes,
        configuration_digest=configuration_digest, expected_authorization_digest=expected_authorization_digest,
        expected_database_id=expected_database_id, expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence, expected_pending_head_digest=expected_pending_head_digest,
        expected_fence=expected_fence, historical_custody=historical_custody,
        commit_reader=commit_reader, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    owner_type = custody.OidcSessionActivationDeliveryCompletionCustody
    owner, configured = held.historical_custody, held.reader_configuration
    owner_configuration = owner_type._snapshot_configuration(owner)
    window, bound = held.live_window, held.transport_deadline_ns
    _window, initial_processing = delivery._window(window, bound, work)
    processing_guards = [initial_processing]
    owner_live = admitted = None
    last_epoch = window[0]

    def current():
        nonlocal last_epoch

        def identities():
            if owner_type._snapshot_configuration(owner) is not owner_configuration:
                _fail("committed-consumption custody configuration changed")
            if reader.CurrentRootCommitReader._snapshot_configuration(held.commit_reader) is not configured:
                _fail("committed-consumption reader configuration changed")

        def sample(guard):
            nonlocal last_epoch
            epoch = guard()
            authorization.shape._integer(epoch, minimum=1)
            if epoch < last_epoch:
                _fail("committed-consumption current clocks reversed across a guarded stage")
            last_epoch = epoch

        identities()
        for guard in processing_guards:
            sample(guard)
        if owner_live is not None:
            sample(owner_live)
        if admitted is not None:
            sample(admitted.live)
        # Preserve the first guard and every narrower guard's sticky history.
        for guard in processing_guards:
            sample(guard)
        identities()
        return last_epoch

    current()
    owner_type.require_completion_on_work(owner, work=work)
    current()
    owner_type.bind_context_on_work(owner, root_public_key=held.root_public_key,
        current_root_enrollment_bytes=held.current_root_enrollment_bytes, work=work)
    current()
    window, bound = owner_type.processing_bounds_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    _window, custody_processing = delivery._window(window, bound, work)
    processing_guards.append(custody_processing)
    current()
    owner_live = owner_type.check_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()

    retained = packets._decode_on_work(held.packet_bytes,
        expected_packet_digest=held.expected_consume_binding["packetDigest"],
        expected_pending_decision_digest=held.expected_pending_head_digest, work=work)
    current()
    for actual, independent, label in (
            (retained.enrollment_bytes, held.current_root_enrollment_bytes, "current-root enrollment"),
            (retained.grant_enrollment_bytes, held.grant_enrollment_bytes, "grant enrollment"),
            (retained.authorization_enrollment_bytes, held.authorization_enrollment_bytes, "caller enrollment"),
            (retained.authorization_bytes, held.authorization_bytes, "caller authorization")):
        work.charge(input_bytes=len(actual) + len(independent))
        if actual != independent:
            _fail("committed-consumption retained " + label + " differs from its independent original")
    current()
    enrollment = authorization._admit_enrollment_on_work(
        enrollment_bytes=held.current_root_enrollment_bytes, root_public_key=held.root_public_key, work=work)
    current()
    policy = enrollment.payload
    for actual, expected in ((policy["databaseId"], held.expected_database_id),
            (policy["generationDigest"], held.expected_generation_digest)):
        evidence.plan._same(actual, expected, work, "committed-consumption independent state scope")
    window = processing_window._narrow(window, deadline_epoch_ns=window[3],
        maximum_lifetime_ns=policy["maxControlAgeNs"], maximum_clock_skew_ns=policy["maxClockSkewNs"])
    bound = min(bound, window[4])
    _window, enrolled_processing = delivery._window(window, bound, work)
    processing_guards.append(enrolled_processing)
    current()

    # This is the sole genuine historical plan/provenance/effects replay. All
    # later comparisons consume only this call's actual admitted originals.
    admitted = admission._admit_on_work(originals=retained.originals, expectations=held.expectations,
        planner_public_key=held.planner_public_key, operation_public_key=held.operation_public_key,
        enrollment_bytes=held.current_root_enrollment_bytes, root_public_key=held.root_public_key,
        reserve_request_bytes=retained.reserve_request_bytes, reserve_receipt_bytes=retained.reserve_receipt_bytes,
        snapshot_bytes=retained.snapshot_bytes, expected_database_id=held.expected_database_id,
        expected_generation_digest=held.expected_generation_digest,
        expected_pending_sequence=held.expected_pending_sequence,
        expected_pending_head_digest=held.expected_pending_head_digest, expected_fence=held.expected_fence,
        authorization_bytes=held.authorization_bytes, authorization_enrollment_bytes=held.authorization_enrollment_bytes,
        grant_bytes=retained.grant_bytes, grant_enrollment_bytes=held.grant_enrollment_bytes,
        configuration_digest=held.configuration_digest, historical_custody=owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    if type(admitted) is not admission._AdmittedCompletion:
        _fail("committed-consumption requires its genuine same-call completion admission")
    current()
    evidence.plan._same(admitted.authorization_digest, held.expected_authorization_digest, work,
        "committed-consumption independently expected caller authorization")
    candidate = admitted.candidate
    common._match_custody_on_work(payload=retained.payload, candidate=candidate,
        actual_effects_digest=admitted.effects_digest, operation=OPERATION,
        authorization_digest=held.expected_authorization_digest, work=work)
    current()

    # Fixed physical read-only observation returns only after normal close.
    # A supplied marker, reader override or signed result cannot replace it.
    marker, after_bytes = reader._read_on_configuration(configured,
        pending_decision_digest=held.expected_pending_head_digest,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()
    evidence.plan._same(marker, candidate.marker, work,
        "committed-consumption immutable marker differs from genuine original replay")
    work.charge(input_bytes=len(after_bytes) + len(candidate.after_vector_bytes))
    if after_bytes != candidate.after_vector_bytes:
        _fail("committed-consumption complete after roots differ from genuine original replay")
    after_digest = vector._digest_on_work(after_bytes, work=work)
    evidence.plan._same(after_digest, marker["after_vector_digest"], work,
        "committed-consumption complete after roots differ from immutable marker")
    current()

    acknowledged = records._verify_ack_on_work(request_bytes=held.completion_request_bytes,
        receipt_bytes=held.state_receipt_bytes, enrollment_bytes=held.current_root_enrollment_bytes,
        root_public_key=held.root_public_key, expected_pending_sequence=held.expected_pending_sequence,
        expected_pending_head_digest=held.expected_pending_head_digest, work=work)
    current()
    request = acknowledged.request_payload
    evidence.plan._same(request["action"], "complete", work, "committed-consumption completion action")
    for field, column in shared._REQUEST_MARKER_JOINS:
        evidence.plan._same(request[field], candidate.marker[column], work,
            "committed-consumption signed completion differs from genuine marker " + field)
    current()
    shared._observation_on_work(request, candidate, work)
    current()

    consume_binding = {
        "packetDigest": evidence.plan._frame(packets.IDENTITY_DOMAIN, (held.packet_bytes,), work),
        "pendingDecisionDigest": candidate.marker["pending_decision_digest"],
        "completionRequestDigest": acknowledged.request_digest,
        "effectsDigest": admitted.effects_digest,
        "afterVectorDigest": after_digest,
    }
    evidence.plan._same(consume_binding, held.expected_consume_binding, work,
        "committed-consumption derived identities differ from independent pins")
    evidence.plan._same(consume_binding, held.expected_release["consumeBinding"], work,
        "committed-consumption identities differ from independent release scope")
    current()
    release_binding = target._match_on_work(packet_payload=retained.payload,
        expectations=held.expectations, expected_release=held.expected_release, work=work)
    current()
    scope_digest = target._scope_digest_on_work(release_binding["deliveryScope"], work)
    for actual, expected, label in (
            (admitted.activation_request_digest, release_binding["activationRequestDigest"], "activation request"),
            (admitted.activation_delivery_id, release_binding["deliveryScope"]["deliveryId"], "delivery identity"),
            (admitted.activation_delivery_scope_digest, scope_digest, "delivery scope"),
            (admitted.activation_delivery_envelope_digest, release_binding["deliveryEnvelopeDigest"], "delivery ciphertext")):
        evidence.plan._same(actual, expected, work,
            "committed-consumption genuine predecessor provenance differs from release " + label)
    current()
    result = _CommittedOriginals(consume_binding, release_binding, held.completion_request_bytes,
        held.state_receipt_bytes, acknowledged.receipt_digest, current)
    current()
    return result
