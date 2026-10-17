"""Bounded sealed-header candidate from original maintenance stream admission.

Raw effect bodies are not aggregated here. Their exact same-call descriptors
are in the completed stream header, while this small custody packet retains
the original signed controls/raw3 and full before/after vector bytes. Only the
actual protected issuer may seal it after its tentative step writes succeed.

The public preparation path accepts originals, never a supplied prepared
stream, packet, mutation or proof verdict. It calls genuine pending/grant/raw
page admission once. This module opens no clock/SQL and gives its freely
constructible output no authority. Failure leaves tentative steps unsealed.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_challenge_execution_admission as admission
from catchplate import authority_successor_execution_packet as framing


SCHEMA = "catchplate.policyAuthorityChallengeMaintenanceExecutionPacket/v1"
IDENTITY_DOMAIN = "catchplate.policyAuthorityChallengeMaintenanceExecutionPacketIdentity/v1"
MAX_BYTES = 8 * 1024 * 1024
MAX_NODES = 65536
MAX_DEPTH = 8
FIELDS = frozenset({"schema", "sourceRevision", "operation", "authorizationDigest",
    "grantDigest", "pendingDecisionDigest", "issuedAtEpochNs", "expiresAtEpochNs",
    "streamHeader", "streamDigest", "beforeVector", "afterVector", "result", "marker", "originals"})
ORIGINAL_FIELDS = frozenset({"currentRootEnrollment", "grantEnrollment", "grant",
    "reserveRequest", "reserveReceipt", "computationSnapshot", "plan"})
CONTROL_MAXIMA = (
    ("currentRootEnrollment", admission.authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", admission.grants.MAX_ENROLLMENT_BYTES),
    ("grant", admission.grants.MAX_GRANT_BYTES),
    ("reserveRequest", admission.authorization.MAX_BYTES),
    ("reserveReceipt", admission.pending.MAX_RECEIPT_BYTES),
    ("computationSnapshot", admission.pending.computation.MAX_SNAPSHOT_BYTES),
)


class ChallengeExecutionPacketError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PreparedPacket:
    """Same-call bytes only; the executor accepts protected identifiers only."""

    packet_bytes: bytes
    packet_digest: str
    pending_decision_digest: str
    stream_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int


def _require(value):
    if not value:
        raise ChallengeExecutionPacketError("maintenance custody packet differs from its genuine stream")


def _encode(derived, expected_authorization_digest, work):
    """Private suffix reached only after this invocation's real admission."""
    _require(type(derived) is admission._PreparedMaintenanceStream)
    evidence, vector = admission.plan.evidence, admission.vector
    evidence.plan.contract._digest(expected_authorization_digest)
    originals = {name: framing._raw_frame(raw, maximum, work)
        for (name, maximum), raw in zip(CONTROL_MAXIMA, derived.controls, strict=True)}
    originals["plan"] = [framing._raw_frame(raw, maximum, work)
        for raw, maximum in zip(derived.originals, admission.grants.FRAME_MAXIMA, strict=True)]
    admission.plan._object(originals, ORIGINAL_FIELDS)
    owned = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=16384).visit({"result": derived.result, "marker": derived.marker})
    admission.plan._object(owned["marker"], frozenset(admission.authorization.authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS))
    for name, expected in (("pending_decision_digest", derived.pending_decision_digest),
            ("capability_digest", derived.grant_digest), ("operation", admission.OPERATION)):
        admission.plan._same(owned["marker"][name], expected, work)
    issued, expires = derived.original_interval
    packet = {"schema": SCHEMA, "sourceRevision": admission.authorization.authority.SOURCE_REVISION,
        "operation": admission.OPERATION, "authorizationDigest": expected_authorization_digest,
        "grantDigest": derived.grant_digest, "pendingDecisionDigest": derived.pending_decision_digest,
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires,
        "streamHeader": framing._raw_frame(derived.stream_header_bytes, admission.streams.MAX_HEADER_BYTES, work),
        "streamDigest": derived.stream_digest,
        "beforeVector": framing._raw_frame(derived.before_vector_bytes, vector.MAX_BYTES, work),
        "afterVector": framing._raw_frame(derived.after_vector_bytes, vector.MAX_BYTES, work),
        "result": owned["result"], "marker": owned["marker"], "originals": originals}
    admission.plan._object(packet, FIELDS)
    encoded = vector.encoding._bounded_wire(packet, vector.capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES)
    identity = evidence.plan._frame(IDENTITY_DOMAIN, (encoded,), work)
    return _PreparedPacket(encoded, identity, derived.pending_decision_digest,
        derived.stream_digest, issued, expires)


def _prepare_on_work(*, originals, expectations, planner_public_key,
        enrollment_bytes, root_public_key, reserve_request_bytes, reserve_receipt_bytes,
        snapshot_bytes, grant_bytes, grant_enrollment_bytes, expected_authorization_digest,
        expected_database_id, expected_generation_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence, live_window,
        read_original, check, retain_effect, work):
    """Only original-byte entrypoint; no supplied stream/packet acceptance."""
    derived = admission._prepare_on_work(originals=originals, expectations=expectations,
        planner_public_key=planner_public_key, enrollment_bytes=enrollment_bytes,
        root_public_key=root_public_key, reserve_request_bytes=reserve_request_bytes,
        reserve_receipt_bytes=reserve_receipt_bytes, snapshot_bytes=snapshot_bytes,
        grant_bytes=grant_bytes, grant_enrollment_bytes=grant_enrollment_bytes,
        expected_authorization_digest=expected_authorization_digest,
        expected_database_id=expected_database_id, expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, read_original=read_original, check=check,
        retain_effect=retain_effect, work=work)
    encoded = _encode(derived, expected_authorization_digest, work)
    # Serializing retained originals cannot renew the operation after proof
    # completion. The actual issuer must also check before its protected seal.
    window = admission.grants.clock._validate(live_window)
    now = admission.grants.clock._check_on_work(window, work=work)
    monotonic = admission.plan.evidence.production._callback(work,
        admission.grants.clock.time.monotonic_ns)
    _require(type(monotonic) is int and derived.last_epoch_ns <= now < encoded.expires_at_epoch_ns
        and derived.last_monotonic_ns <= monotonic < min(window[4], derived.original_deadline_ns))
    return encoded
