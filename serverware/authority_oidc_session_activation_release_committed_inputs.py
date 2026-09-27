"""Owned original inputs for private committed-consumption verification.

Joint structural ownership precedes typed commitment hashes and native owner
callbacks. These are ordinary held inputs, not packet, commit, completion or
release admission. No packet is decoded and no I/O or clock is opened here.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_current_root_commit_reader as reader
from serverware import authority_current_root_delivery_records as records
from serverware import authority_oidc_session_activation_delivery_completion_admission as admission
from serverware import authority_oidc_session_activation_delivery_completion_custody as custody
from serverware import authority_oidc_session_activation_delivery_recovery_packet as packet
from serverware import authority_oidc_session_activation_release_intent as intent


authorization, pending = admission.authorization, admission.pending
expectations_wire, caller, enrollments = admission.expectations_wire, admission.caller, admission.enrollments
shape, plan, capture = authorization.shape, authorization.plan, authorization.capture
MAX_ORIGINAL_BYTES = admission.MAX_ORIGINAL_BYTES
MAX_GRAPH_BYTES = expectations_wire.MAX_BYTES + 2 * intent.contract.MAX_BYTES
MAX_GRAPH_NODES = expectations_wire.MAX_NODES + 2 * intent.contract.MAX_NODES + 8
MAX_GRAPH_DEPTH = 14


class ReleaseCommittedInputsError(ValueError):
    pass


def _fail(message):
    raise ReleaseCommittedInputsError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Inputs:
    """Detached input data only; never accepted as an admission proof."""

    packet_bytes: bytes
    completion_request_bytes: bytes
    state_receipt_bytes: bytes
    expected_consume_binding: dict
    expected_release: dict
    expectations: dict
    planner_public_key: object
    operation_public_key: object
    root_public_key: object
    authorization_bytes: bytes
    authorization_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    current_root_enrollment_bytes: bytes
    configuration_digest: str
    expected_authorization_digest: str
    expected_database_id: str
    expected_generation_digest: str
    expected_pending_sequence: int
    expected_pending_head_digest: str
    expected_fence: int
    historical_custody: object
    commit_reader: object
    live_window: tuple
    transport_deadline_ns: int
    reader_configuration: tuple


class _Graphs(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_GRAPH_DEPTH or self.nodes >= MAX_GRAPH_NODES:
            _fail("committed release inputs exceed their joint graph bounds")
        owned = super().visit(value, depth, ancestors)
        if self.nodes > MAX_GRAPH_NODES:
            _fail("committed release inputs exceed their joint node bound")
        return owned


def _graphs(expectations, release, binding, work):
    # Stage one performs only exact JSON structural copies/charges on the
    # original work object. This source-fixed wrapper holds every mutable
    # graph together before stage two can hash a typed request or call a key,
    # process owner or reader. No new ledger allowance or callback is created.
    expectations_wire._shape(expectations)
    shape._object(release, intent.RELEASE_FIELDS, "independent committed release target")
    shape._object(binding, intent.contract.CONSUME_BINDING_FIELDS,
        "independent committed consumption identities")
    owned = _Graphs(capture._SharedLedger(work), maximum_bytes=MAX_GRAPH_BYTES).visit({
        "expectations": expectations, "release": release, "binding": binding})
    return owned["expectations"], owned["release"], owned["binding"]


def _capture_on_work(*, packet_bytes, completion_request_bytes, state_receipt_bytes,
        expected_consume_binding, expected_release, expectations, planner_public_key,
        operation_public_key, root_public_key, authorization_bytes,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        configuration_digest, expected_authorization_digest, expected_database_id,
        expected_generation_digest, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, historical_custody, commit_reader, live_window,
        transport_deadline_ns, work):
    """Own exact original data and actual handles, without admitting a commit."""
    capture._SharedLedger(work)
    owner, observer = historical_custody, commit_reader
    if type(owner) is not custody.OidcSessionActivationDeliveryCompletionCustody:
        _fail("committed release requires the actual dedicated completion custodian")
    if type(observer) is not reader.CurrentRootCommitReader:
        _fail("committed release requires the actual fixed commit reader")
    planner, operation_key, root = planner_public_key, operation_public_key, root_public_key
    for key in (planner, operation_key, root):
        authorization._public(key)
    originals = tuple(authorization._original(raw, maximum, label) for raw, maximum, label in (
        (packet_bytes, packet.MAX_BYTES, "committed consume packet"),
        (completion_request_bytes, records.MAX_REQUEST_BYTES, "consume completion request"),
        (state_receipt_bytes, records.MAX_RECEIPT_BYTES, "consume completion state ACK"),
        (authorization_bytes, caller.MAX_AUTHORIZATION_BYTES, "independent consume caller"),
        (authorization_enrollment_bytes, caller.MAX_ENROLLMENT_BYTES, "independent consume caller enrollment"),
        (grant_enrollment_bytes, enrollments.MAX_ENROLLMENT_BYTES, "independent consume grant enrollment"),
        (current_root_enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES, "independent current-root enrollment")))
    total = sum(map(len, originals))
    if total > MAX_ORIGINAL_BYTES:
        _fail("committed release original request inventory exceeds 64 MiB")
    config, caller_digest = configuration_digest, expected_authorization_digest
    shape._digest(config)
    shape._digest(caller_digest)
    shape._integer(transport_deadline_ns, minimum=1)
    scope = pending._scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    bound = min(scope[5][4], scope[6])
    work.charge(input_bytes=total)
    expected_graph, release_graph, binding_graph = _graphs(
        expectations, expected_release, expected_consume_binding, work)
    # All external mutable graphs and immutable originals/key/owner references
    # are now held. Later captures and native snapshots cannot observe a
    # callback-mutated caller graph that escaped this ownership phase.
    expected = expectations_wire._capture_on_work(expected_graph, work=work)
    release = intent.contract._capture(release_graph, work)
    binding = intent.contract._capture(binding_graph, work)
    shape._object(release, intent.RELEASE_FIELDS, "independent committed release target")
    shape._object(binding, intent.contract.CONSUME_BINDING_FIELDS,
        "independent committed consumption identities")
    for value in binding.values():
        shape._digest(value)
    for name in intent.RELEASE_FIELDS - {"deliveryScope", "consumeBinding"}:
        shape._digest(release[name])
    shape._object(release["consumeBinding"], intent.contract.CONSUME_BINDING_FIELDS,
        "release target consumption identities")
    for value in release["consumeBinding"].values():
        shape._digest(value)
    # This is original scope grammar only: no current clock, AEAD opening or
    # claim that any expected target is the historically committed row.
    intent.bootstrap._scope(release["deliveryScope"], work)
    plan._same(release["consumeBinding"], binding, work,
        "release target differs from independent consumption identities")
    plan._same(release["consumeRequestDigest"], expected["request"]["requestDigest"], work,
        "release target differs from the independently captured consume request")
    plan._same(expected["scope"]["configurationDigest"], config, work,
        "committed release independent configuration")
    configured = reader.CurrentRootCommitReader._snapshot_configuration(observer)
    return _Inputs(packet_bytes=originals[0], completion_request_bytes=originals[1],
        state_receipt_bytes=originals[2], expected_consume_binding=binding,
        expected_release=release, expectations=expected, planner_public_key=planner,
        operation_public_key=operation_key, root_public_key=root,
        authorization_bytes=originals[3], authorization_enrollment_bytes=originals[4],
        grant_enrollment_bytes=originals[5], current_root_enrollment_bytes=originals[6],
        configuration_digest=config, expected_authorization_digest=caller_digest,
        expected_database_id=scope[0], expected_generation_digest=scope[1],
        expected_pending_sequence=scope[2], expected_pending_head_digest=scope[3],
        expected_fence=scope[4], historical_custody=owner, commit_reader=observer,
        live_window=scope[5], transport_deadline_ns=bound, reader_configuration=configured)
