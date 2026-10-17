"""Bounded original-retaining custody decoding, not execution authority.

An independently expected framed packet identity is checked before parsing.
The closed source packet and raw-frame identities are then decoded on the
caller's existing work. This authenticates byte identity, not signatures,
plan semantics, currentness, commit, enrollment or permission to execute.
Historical completion must genuinely verify the retained original controls
and plan, with independently admitted keys, scope and history, in that call.

The effects fingerprint joins stored data to genuine same-call replay without
exporting executable replay outputs from historical completion. Neither the
fingerprint nor the returned ordinary data is an accepted authority token.
There is no clock, SQL, I/O, signing, expiry renewal or replacement allowance.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from catchplate import authority_contract as authority
from catchplate import authority_current_root_authorization as authorization
from catchplate import authority_current_root_plan_replay as replay
from catchplate import authority_current_root_vector as vector
from catchplate import authority_successor_execution_packet as packet


SCHEMA = packet.SCHEMA
IDENTITY_DOMAIN = packet.IDENTITY_DOMAIN
MAX_BYTES, MAX_NODES, MAX_DEPTH = packet.MAX_BYTES, packet.MAX_NODES, packet.MAX_DEPTH
EFFECTS_IDENTITY_DOMAIN = "catchplate.policyAuthoritySuccessorCustodyEffects/v1"
_FRAME_FIELDS = frozenset({"base64Url", "bytesDigest", "byteCount"})
_SELECTED_FIELDS = frozenset({"table", "key", "keyDigest", "present", "row", "contractSelector"})
_MUTATION_FIELDS = frozenset({"templateId", "operation", "table", "key", "keyDigest", "expectedRow", "row"})
_EFFECTS_FIELDS = frozenset({"selectedRows", "mutations", "result", "workUnits"})
_MARKER_DIGESTS = ("pending_decision_digest", "enrollment_digest", "generation_digest",
    "pending_request_digest", "predecessor_head_digest", "request_digest", "operation_id",
    "capability_digest", "snapshot_digest", "before_vector_digest", "after_vector_digest", "result_digest")


class SuccessorExecutionRecoveryPacketError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _RecoveryPacket:
    """Detached ordinary packet data and true originals, not admission proof."""

    payload: dict
    originals: tuple[bytes, ...]
    enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    grant_bytes: bytes
    reserve_request_bytes: bytes
    reserve_receipt_bytes: bytes
    snapshot_bytes: bytes


class _Capture(vector.capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise SuccessorExecutionRecoveryPacketError("custody effects exceed their structure bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            raise SuccessorExecutionRecoveryPacketError("custody effects exceed their node bound")
        return result


def _bound(value, maximum, nodes, work):
    size, count = work.measure(value)
    if size > maximum or count > nodes:
        raise SuccessorExecutionRecoveryPacketError("custody component exceeds its source bound")


def _same(actual, expected, work, label):
    vector.framing._same(actual, expected, work, label)


def _effect_shape(selected, mutations, work_units, *, spec=None):
    maximum_rows = authority.MAX_PLAN_QUERY_ROWS if spec is None else spec["maximumQueryRows"]
    maximum_mutations = authority.MAX_PLAN_MUTATIONS if spec is None else spec["maximumMutations"]
    maximum_work = authority.MAX_PLAN_WORK_UNITS if spec is None else spec["maximumWorkUnits"]
    if (type(selected) is not list or len(selected) > maximum_rows
            or type(mutations) is not list or len(mutations) > maximum_mutations):
        raise SuccessorExecutionRecoveryPacketError("custody effects exceed their fixed source inventory")
    authorization.shape._integer(work_units, maximum_work, minimum=1)
    for item in selected:
        vector._closed(item, _SELECTED_FIELDS, "custody selected row")
        table = item["table"]
        if (type(table) is not str or table not in vector.primary.PRIMARY_KEY_COLUMNS
                or spec is not None and table not in (
                    *spec["businessReads"], *spec["businessWrites"], *spec["authorizationReads"])
                or type(item["present"]) is not bool
                or item["row"] is not None and type(item["row"]) is not dict
                or item["present"] != (item["row"] is not None)
                or item["contractSelector"] is not None and type(item["contractSelector"]) is not str):
            raise SuccessorExecutionRecoveryPacketError("custody selected row has an invalid source shape")
        vector._closed(item["key"], frozenset(vector.primary.PRIMARY_KEY_COLUMNS[table]),
            "custody selected key")
        authorization.shape._digest(item["keyDigest"])
    for item in mutations:
        vector._closed(item, _MUTATION_FIELDS, "custody mutation")
        table, mutation = item["table"], item["operation"]
        authorization.shape._digest(item["templateId"])
        authorization.shape._digest(item["keyDigest"])
        if (type(table) is not str or table not in vector.primary.PRIMARY_KEY_COLUMNS
                or type(mutation) is not str or mutation not in ("INSERT", "UPDATE", "DELETE")
                or item["expectedRow"] is not None and type(item["expectedRow"]) is not dict
                or item["row"] is not None and type(item["row"]) is not dict):
            raise SuccessorExecutionRecoveryPacketError("custody mutation has an invalid source shape")
        vector._closed(item["key"], frozenset(vector.primary.PRIMARY_KEY_COLUMNS[table]),
            "custody mutation key")
        if spec is not None:
            template = next((value for value in spec["mutationTemplates"]
                if value["templateId"] == item["templateId"]), None)
            if (table not in spec["businessWrites"] or template is None
                    or template["table"] != table or template["mutation"] != mutation):
                raise SuccessorExecutionRecoveryPacketError("custody mutation is not a source operation template")


def _effects_digest_on_work(*, selected_rows, mutations, result, work_units, work):
    """Fingerprint exact effects; tuple/list inputs share one canonical array.

    All caller graphs are detached before native encoding/hash work. No caller
    effect graph is interpreted as genuinely replayed or allowed to execute.
    """
    ledger = vector.capture._SharedLedger(work)
    if (type(selected_rows) not in (tuple, list) or len(selected_rows) > authority.MAX_PLAN_QUERY_ROWS
            or type(mutations) not in (tuple, list) or len(mutations) > authority.MAX_PLAN_MUTATIONS):
        raise SuccessorExecutionRecoveryPacketError("custody effects are not bounded exact arrays")
    held_work_units = work_units
    authorization.shape._integer(held_work_units, authority.MAX_PLAN_WORK_UNITS, minimum=1)
    work.prepare_copy(selected_rows)
    work.prepare_copy(mutations)
    owned = _Capture(ledger, maximum_bytes=MAX_BYTES).visit({"selectedRows": list(selected_rows),
        "mutations": list(mutations), "result": result, "workUnits": held_work_units})
    vector._closed(owned, _EFFECTS_FIELDS, "custody effects")
    _effect_shape(owned["selectedRows"], owned["mutations"], owned["workUnits"])
    _bound(owned["selectedRows"], authority.MAX_PLAN_SELECTED_BYTES, MAX_NODES, work)
    _bound(owned["mutations"], authority.MAX_RESULT_BYTES, MAX_NODES, work)
    _bound(owned["result"], authority.MAX_RESULT_BYTES, MAX_NODES, work)
    encoded = vector.encoding._bounded_wire(owned, ledger,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES)
    return vector.framing._frame(EFFECTS_IDENTITY_DOMAIN, (encoded,), work)


def _plan_maxima(operation):
    # Storage decoding names the real source family; it grants no historical
    # replay or completion authority for the activation ciphertext originals.
    return replay._frame_maxima(operation)


def _frame_shape(frame, maximum):
    vector._closed(frame, _FRAME_FIELDS, "custody original frame")
    authorization.shape._digest(frame["bytesDigest"])
    authorization.transport._transport_shape(frame["base64Url"], frame["byteCount"], maximum)


def _decode_frame(frame, maximum, work):
    raw = authorization.transport._decode(frame["base64Url"], frame["byteCount"], maximum, work)
    work.charge(hashes=1, input_bytes=len(raw))
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    _same(actual, frame["bytesDigest"], work, "custody original raw identity differs")
    return raw


def _packet_shape(payload, expected_pending, work):
    vector._closed(payload, packet.PACKET_FIELDS, "retained custody packet")
    authorization.shape._literal(payload["schema"], SCHEMA)
    authorization.shape._literal(payload["sourceRevision"], authority.SOURCE_REVISION)
    operation = payload["operation"]
    authorization.delta._source(operation)
    spec = authority.operation_spec(operation)
    for name in ("authorizationDigest", "requestDigest", "operationId"):
        authorization.shape._digest(payload[name])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        authorization.shape._integer(payload[name], minimum=1)
    if payload["expiresAtEpochNs"] <= payload["issuedAtEpochNs"]:
        raise SuccessorExecutionRecoveryPacketError("custody original interval is empty")
    _effect_shape(payload["selectedRows"], payload["mutations"], payload["workUnits"], spec=spec)
    _bound(payload["selectedRows"], authority.MAX_PLAN_SELECTED_BYTES, MAX_NODES, work)
    _bound(payload["mutations"], authority.MAX_RESULT_BYTES, MAX_NODES, work)
    _bound(payload["result"], authority.MAX_RESULT_BYTES, MAX_NODES, work)
    for name in ("beforeVector", "afterVector"):
        vector._shape(payload[name])
        _bound(payload[name], vector.MAX_BYTES, vector.MAX_NODES, work)
    marker = payload["marker"]
    vector._closed(marker, frozenset(authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS), "custody commit marker")
    authorization.shape._literal(marker["source_revision"], authority.SOURCE_REVISION)
    authorization._token(marker["database_id"])
    for name in _MARKER_DIGESTS:
        authorization.shape._digest(marker[name])
    authorization.shape._integer(marker["pending_sequence"], authorization.MAX_RECORDS - 1, minimum=1)
    authorization.shape._integer(marker["predecessor_sequence"], authorization.MAX_RECORDS - 2)
    authorization.shape._integer(marker["fence"], minimum=1)
    if marker["pending_sequence"] != marker["predecessor_sequence"] + 1:
        raise SuccessorExecutionRecoveryPacketError("custody marker predecessor is not adjacent")
    for actual, expected in ((marker["pending_decision_digest"], expected_pending),
            (marker["operation"], operation), (marker["request_digest"], payload["requestDigest"]),
            (marker["operation_id"], payload["operationId"])):
        _same(actual, expected, work, "custody marker differs from its independently held packet scope")
    _bound(marker, 4096, 64, work)
    inventory = payload["originals"]
    vector._closed(inventory, packet.ORIGINAL_FIELDS, "custody original inventory")
    maxima = _plan_maxima(operation)
    plans = inventory["plan"]
    if type(plans) is not list or len(plans) != len(maxima):
        raise SuccessorExecutionRecoveryPacketError("custody original plan count differs from its fixed family")
    # Bound every original and their aggregate BEFORE allocating any decoded
    # body. The six controls retain the producer's actual source byte ceilings.
    total = 0
    for name, maximum in packet._CONTROL_MAXIMA:
        _frame_shape(inventory[name], maximum)
        total += inventory[name]["byteCount"]
    for frame, maximum in zip(plans, maxima):
        _frame_shape(frame, maximum)
        total += frame["byteCount"]
    if total > MAX_BYTES:
        raise SuccessorExecutionRecoveryPacketError("custody originals exceed their aggregate source bound")
    return maxima


def _decode_on_work(packet_bytes, *, expected_packet_digest, expected_pending_decision_digest, work):
    """Decode independently pinned originals, never substitute for their replay."""
    ledger = vector.capture._SharedLedger(work)
    original = authorization._original(packet_bytes, MAX_BYTES, "retained successor custody packet")
    held_digest, held_pending = expected_packet_digest, expected_pending_decision_digest
    authorization.shape._digest(held_digest)
    authorization.shape._digest(held_pending)
    # The original and both independent scalar pins are exact immutable values
    # before hashing/parsing. No packet-provided identity enrolls itself here.
    actual_digest = vector.framing._frame(IDENTITY_DOMAIN, (original,), work)
    _same(actual_digest, held_digest, work, "retained custody packet differs from its independent identity")
    payload = vector.wire._decode_object(original, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    authorization.capability._canonical(original, payload, ledger, MAX_BYTES, MAX_NODES)
    maxima = _packet_shape(payload, held_pending, work)
    inventory = payload["originals"]
    controls = tuple(_decode_frame(inventory[name], maximum, work)
        for name, maximum in packet._CONTROL_MAXIMA)
    originals = tuple(_decode_frame(frame, maximum, work)
        for frame, maximum in zip(inventory["plan"], maxima))
    # These true originals remain opaque here. The completion consumer must
    # authenticate all original signatures/proofs and compare actual effects,
    # vectors, marker, authorization and original interval in its same call.
    return _RecoveryPacket(payload, originals, *controls)
