"""Dedicated trusted-host-local cold admission for the current-root state owner.

The independently provisioned root authenticates the original enrollment and
the exact latest checkpoint before this service opens its journal. A recovered
journal never enrolls its own expected head. The closed launch also pins both
the kernel listener and its distinct filesystem socket identity.

These are explicit root assertions, not native runtime measurement, hardware
attestation or external rollback-witness proof. The signed lifetime is never
renewed by startup or a request. The provisioner must separately establish
checkpoint currentness and runtime provenance; possessing an old valid prefix
or a matching digest does not establish either. No key, checkpoint, descriptor,
path, journal, listener or new work allowance is synthesized here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature

from serverware import authority_current_root_authorization as authorization
from serverware import authority_webauthn_evidence_plan_clock as clock


authority, shape, capture, wire = (
    authorization.authority, authorization.shape, authorization.capture, authorization.wire)
capability, plan, production, keys = (
    authorization.capability, authorization.plan, authorization.production, authorization.keys)
ROLE = PROCESS_MODE = "policy-authority-current-root-state"
SERVICE_UID = SERVICE_GID = 65516
RESERVE_PEER_UID = RESERVE_PEER_GID = 65514
COMPLETE_PEER_UID = COMPLETE_PEER_GID = 65515
FINALIZATION_RESERVE_PEER_UID = FINALIZATION_RESERVE_PEER_GID = 65510
FINALIZATION_COMPLETE_PEER_UID = FINALIZATION_COMPLETE_PEER_GID = 65508
ACTIVATION_PLANNER_PEER_UID = ACTIVATION_PLANNER_PEER_GID = 65507
ACTIVATION_RESERVE_PEER_UID = ACTIVATION_RESERVE_PEER_GID = 65505
ACTIVATION_COMPLETE_PEER_UID = ACTIVATION_COMPLETE_PEER_GID = 65503
DELIVERY_PLANNER_PEER_UID = DELIVERY_PLANNER_PEER_GID = 65501
DELIVERY_RESERVE_PEER_UID = DELIVERY_RESERVE_PEER_GID = 65499
DELIVERY_COMPLETE_PEER_UID = DELIVERY_COMPLETE_PEER_GID = 65497
REVOCATION_HEAD_PEER_UID = REVOCATION_HEAD_PEER_GID = 65520
REVOCATION_RESERVE_PEER_UID = REVOCATION_RESERVE_PEER_GID = 65521
REVOCATION_COMPLETE_PEER_UID = REVOCATION_COMPLETE_PEER_GID = 65522
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD = 198, 199, 200, 201, 202
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD)
LISTENER_PATH = "/run/serverware/current-root/state.sock"
MAX_BYTES = 256 * 1024
MAX_NODES, MAX_DEPTH = 256, 4
MAX_RECEIPT_AGE_NS = 300 * 1_000_000_000
SCHEMA = "serverware.signedCurrentRootStateBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.currentRootStateBootstrap/v1"
LAUNCH_SCHEMA = "serverware.currentRootStateLaunch/v1"
SCHEMA_V2 = "serverware.signedCurrentRootStateBootstrap/v2"
PAYLOAD_SCHEMA_V2 = "serverware.currentRootStateBootstrap/v2"
LAUNCH_SCHEMA_V2 = "serverware.currentRootStateLaunch/v2"
SCHEMA_V3 = "serverware.signedCurrentRootStateBootstrap/v3"
PAYLOAD_SCHEMA_V3 = "serverware.currentRootStateBootstrap/v3"
LAUNCH_SCHEMA_V3 = "serverware.currentRootStateLaunch/v3"
SCHEMA_V4 = "serverware.signedCurrentRootStateBootstrap/v4"
PAYLOAD_SCHEMA_V4 = "serverware.currentRootStateBootstrap/v4"
LAUNCH_SCHEMA_V4 = "serverware.currentRootStateLaunch/v4"
SCHEMA_V5 = "serverware.signedCurrentRootStateBootstrap/v5"
PAYLOAD_SCHEMA_V5 = "serverware.currentRootStateBootstrap/v5"
LAUNCH_SCHEMA_V5 = "serverware.currentRootStateLaunch/v5"
SCHEMA_V6 = "serverware.signedCurrentRootStateBootstrap/v6"
PAYLOAD_SCHEMA_V6 = "serverware.currentRootStateBootstrap/v6"
LAUNCH_SCHEMA_V6 = "serverware.currentRootStateLaunch/v6"
SCHEMA_V7 = "serverware.signedCurrentRootStateBootstrap/v7"
PAYLOAD_SCHEMA_V7 = "serverware.currentRootStateBootstrap/v7"
LAUNCH_SCHEMA_V7 = "serverware.currentRootStateLaunch/v7"
SCHEMA_V8 = "serverware.signedCurrentRootStateBootstrap/v8"
PAYLOAD_SCHEMA_V8 = "serverware.currentRootStateBootstrap/v8"
LAUNCH_SCHEMA_V8 = "serverware.currentRootStateLaunch/v8"
SCHEMA_V9 = "serverware.signedCurrentRootStateBootstrap/v9"
PAYLOAD_SCHEMA_V9 = "serverware.currentRootStateBootstrap/v9"
LAUNCH_SCHEMA_V9 = "serverware.currentRootStateLaunch/v9"
SCHEMA_V10 = "serverware.signedCurrentRootStateBootstrap/v10"
PAYLOAD_SCHEMA_V10 = "serverware.currentRootStateBootstrap/v10"
LAUNCH_SCHEMA_V10 = "serverware.currentRootStateLaunch/v10"
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "enrollmentBase64Url",
    "enrollmentBytesDigest", "enrollmentByteCount", "enrollmentDigest", "databaseId",
    "generationDigest", "stateSigningSpkiDigest", "stateMeasurementDigest", "runtimeClosureDigest",
    "checkpoint", "issuedAtEpochNs", "expiresAtEpochNs", "trustMode", "hardwareBacked",
    "nativeStageZero", "hsmBackedKeys", "teeVerified", "externalWitnessVerified", "launch"})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid",
    "reservePeerUid", "reservePeerGid", "completePeerUid", "completePeerGid",
    "rootPublicKeyFd", "bootstrapFd", "listenerFd", "signingKeyFd", "journalDirectoryFd",
    "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds", "journalDirectoryDevice",
    "journalDirectoryInode", "journalMaximumRecords", "listenerSocketDevice", "listenerSocketInode",
    "listenerPathDevice", "listenerPathInode"})
_LAUNCH_FIELDS_V2 = _LAUNCH_FIELDS | frozenset({"finalizationReservePeerUid", "finalizationReservePeerGid"})
_LAUNCH_FIELDS_V3 = _LAUNCH_FIELDS_V2 | frozenset({"finalizationCompletePeerUid", "finalizationCompletePeerGid"})
_LAUNCH_FIELDS_V4 = _LAUNCH_FIELDS_V3 | frozenset({"activationPlannerPeerUid", "activationPlannerPeerGid"})
_LAUNCH_FIELDS_V5 = _LAUNCH_FIELDS_V4 | frozenset({"activationReservePeerUid", "activationReservePeerGid"})
_LAUNCH_FIELDS_V6 = _LAUNCH_FIELDS_V5 | frozenset({"activationCompletePeerUid", "activationCompletePeerGid"})
_LAUNCH_FIELDS_V7 = _LAUNCH_FIELDS_V6 | frozenset({"deliveryPlannerPeerUid", "deliveryPlannerPeerGid"})
_LAUNCH_FIELDS_V8 = _LAUNCH_FIELDS_V7 | frozenset({"deliveryReservePeerUid", "deliveryReservePeerGid"})
_LAUNCH_FIELDS_V9 = _LAUNCH_FIELDS_V8 | frozenset({"deliveryCompletePeerUid", "deliveryCompletePeerGid"})
_LAUNCH_FIELDS_V10 = _LAUNCH_FIELDS_V9 | frozenset({"revocationHeadPeerUid", "revocationHeadPeerGid",
    "revocationReservePeerUid", "revocationReservePeerGid", "revocationCompletePeerUid",
    "revocationCompletePeerGid"})
_ENVELOPE_PAYLOADS = {SCHEMA: PAYLOAD_SCHEMA, SCHEMA_V2: PAYLOAD_SCHEMA_V2,
    SCHEMA_V3: PAYLOAD_SCHEMA_V3, SCHEMA_V4: PAYLOAD_SCHEMA_V4, SCHEMA_V5: PAYLOAD_SCHEMA_V5,
    SCHEMA_V6: PAYLOAD_SCHEMA_V6, SCHEMA_V7: PAYLOAD_SCHEMA_V7, SCHEMA_V8: PAYLOAD_SCHEMA_V8,
    SCHEMA_V9: PAYLOAD_SCHEMA_V9, SCHEMA_V10: PAYLOAD_SCHEMA_V10}
_PAYLOAD_LAUNCHES = {PAYLOAD_SCHEMA: LAUNCH_SCHEMA, PAYLOAD_SCHEMA_V2: LAUNCH_SCHEMA_V2,
    PAYLOAD_SCHEMA_V3: LAUNCH_SCHEMA_V3, PAYLOAD_SCHEMA_V4: LAUNCH_SCHEMA_V4,
    PAYLOAD_SCHEMA_V5: LAUNCH_SCHEMA_V5, PAYLOAD_SCHEMA_V6: LAUNCH_SCHEMA_V6,
    PAYLOAD_SCHEMA_V7: LAUNCH_SCHEMA_V7, PAYLOAD_SCHEMA_V8: LAUNCH_SCHEMA_V8,
    PAYLOAD_SCHEMA_V9: LAUNCH_SCHEMA_V9, PAYLOAD_SCHEMA_V10: LAUNCH_SCHEMA_V10}
_LAUNCH_PROFILES = {LAUNCH_SCHEMA: _LAUNCH_FIELDS, LAUNCH_SCHEMA_V2: _LAUNCH_FIELDS_V2,
    LAUNCH_SCHEMA_V3: _LAUNCH_FIELDS_V3, LAUNCH_SCHEMA_V4: _LAUNCH_FIELDS_V4,
    LAUNCH_SCHEMA_V5: _LAUNCH_FIELDS_V5, LAUNCH_SCHEMA_V6: _LAUNCH_FIELDS_V6,
    LAUNCH_SCHEMA_V7: _LAUNCH_FIELDS_V7, LAUNCH_SCHEMA_V8: _LAUNCH_FIELDS_V8,
    LAUNCH_SCHEMA_V9: _LAUNCH_FIELDS_V9, LAUNCH_SCHEMA_V10: _LAUNCH_FIELDS_V10}


class CurrentRootStateBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _StateMaterial:
    """Owned same-call data, never an accepted proof token or latest-head API."""

    enrollment_bytes: bytes
    state_public_key: object
    enrollment_digest: str
    checkpoint: tuple[int, str]
    attestation_interval: tuple[int, int]
    launch: dict


def _launch_shape(value, work):
    if type(value) is not dict or type(value.get("schema")) is not str:
        raise CurrentRootStateBootstrapError("current-root launch schema is not source fixed")
    schema = value["schema"]
    if schema not in _LAUNCH_PROFILES:
        raise CurrentRootStateBootstrapError("current-root launch schema is unsupported")
    shape._object(value, _LAUNCH_PROFILES[schema], "current-root state launch")
    shape._literal(value["processMode"], PROCESS_MODE)
    shape._literal(value["listenerPath"], LISTENER_PATH)
    fixed = (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
        ("reservePeerUid", RESERVE_PEER_UID), ("reservePeerGid", RESERVE_PEER_GID),
        ("completePeerUid", COMPLETE_PEER_UID), ("completePeerGid", COMPLETE_PEER_GID),
        ("rootPublicKeyFd", ROOT_FD), ("bootstrapFd", BOOTSTRAP_FD),
        ("listenerFd", LISTENER_FD), ("signingKeyFd", KEY_FD), ("journalDirectoryFd", JOURNAL_FD))
    if schema in (LAUNCH_SCHEMA_V2, LAUNCH_SCHEMA_V3, LAUNCH_SCHEMA_V4, LAUNCH_SCHEMA_V5,
            LAUNCH_SCHEMA_V6, LAUNCH_SCHEMA_V7, LAUNCH_SCHEMA_V8, LAUNCH_SCHEMA_V9, LAUNCH_SCHEMA_V10):
        fixed += (("finalizationReservePeerUid", FINALIZATION_RESERVE_PEER_UID),
            ("finalizationReservePeerGid", FINALIZATION_RESERVE_PEER_GID))
    if schema in (LAUNCH_SCHEMA_V3, LAUNCH_SCHEMA_V4, LAUNCH_SCHEMA_V5, LAUNCH_SCHEMA_V6,
            LAUNCH_SCHEMA_V7, LAUNCH_SCHEMA_V8, LAUNCH_SCHEMA_V9, LAUNCH_SCHEMA_V10):
        fixed += (("finalizationCompletePeerUid", FINALIZATION_COMPLETE_PEER_UID),
            ("finalizationCompletePeerGid", FINALIZATION_COMPLETE_PEER_GID))
    if schema in (LAUNCH_SCHEMA_V4, LAUNCH_SCHEMA_V5, LAUNCH_SCHEMA_V6,
            LAUNCH_SCHEMA_V7, LAUNCH_SCHEMA_V8, LAUNCH_SCHEMA_V9, LAUNCH_SCHEMA_V10):
        fixed += (("activationPlannerPeerUid", ACTIVATION_PLANNER_PEER_UID),
            ("activationPlannerPeerGid", ACTIVATION_PLANNER_PEER_GID))
    if schema in (LAUNCH_SCHEMA_V5, LAUNCH_SCHEMA_V6, LAUNCH_SCHEMA_V7, LAUNCH_SCHEMA_V8, LAUNCH_SCHEMA_V9, LAUNCH_SCHEMA_V10):
        fixed += (("activationReservePeerUid", ACTIVATION_RESERVE_PEER_UID),
            ("activationReservePeerGid", ACTIVATION_RESERVE_PEER_GID))
    if schema in (LAUNCH_SCHEMA_V6, LAUNCH_SCHEMA_V7, LAUNCH_SCHEMA_V8, LAUNCH_SCHEMA_V9, LAUNCH_SCHEMA_V10):
        fixed += (("activationCompletePeerUid", ACTIVATION_COMPLETE_PEER_UID),
            ("activationCompletePeerGid", ACTIVATION_COMPLETE_PEER_GID))
    if schema in (LAUNCH_SCHEMA_V7, LAUNCH_SCHEMA_V8, LAUNCH_SCHEMA_V9, LAUNCH_SCHEMA_V10):
        fixed += (("deliveryPlannerPeerUid", DELIVERY_PLANNER_PEER_UID),
            ("deliveryPlannerPeerGid", DELIVERY_PLANNER_PEER_GID))
    if schema in (LAUNCH_SCHEMA_V8, LAUNCH_SCHEMA_V9, LAUNCH_SCHEMA_V10):
        fixed += (("deliveryReservePeerUid", DELIVERY_RESERVE_PEER_UID),
            ("deliveryReservePeerGid", DELIVERY_RESERVE_PEER_GID))
    if schema in (LAUNCH_SCHEMA_V9, LAUNCH_SCHEMA_V10):
        fixed += (("deliveryCompletePeerUid", DELIVERY_COMPLETE_PEER_UID),
            ("deliveryCompletePeerGid", DELIVERY_COMPLETE_PEER_GID))
    if schema == LAUNCH_SCHEMA_V10:
        fixed += (("revocationHeadPeerUid", REVOCATION_HEAD_PEER_UID),
            ("revocationHeadPeerGid", REVOCATION_HEAD_PEER_GID),
            ("revocationReservePeerUid", REVOCATION_RESERVE_PEER_UID),
            ("revocationReservePeerGid", REVOCATION_RESERVE_PEER_GID),
            ("revocationCompletePeerUid", REVOCATION_COMPLETE_PEER_UID),
            ("revocationCompletePeerGid", REVOCATION_COMPLETE_PEER_GID))
    for name, expected in fixed:
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            raise CurrentRootStateBootstrapError("current-root fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "current-root inherited descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work,
        "current-root inherited descriptor inventory differs")
    # Integer seconds keep the signed canonical JSON contract exact.
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("journalDirectoryDevice", "listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("journalDirectoryInode", "listenerSocketInode", "listenerPathInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], authorization.MAX_RECORDS, minimum=2)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "current-root state bootstrap payload")
    schema = payload["schema"]
    if type(schema) is not str or schema not in _PAYLOAD_LAUNCHES:
        raise CurrentRootStateBootstrapError("current-root payload schema is unsupported")
    for name, expected in (("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("enrollmentBytesDigest", "enrollmentDigest", "generationDigest",
            "stateSigningSpkiDigest", "stateMeasurementDigest", "runtimeClosureDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    authorization.transport._transport_shape(payload["enrollmentBase64Url"],
        payload["enrollmentByteCount"], authorization.MAX_ENROLLMENT_BYTES)
    checkpoint = payload["checkpoint"]
    shape._object(checkpoint, frozenset({"sequence", "headDigest"}), "independent state checkpoint")
    shape._integer(checkpoint["sequence"], authorization.MAX_RECORDS)
    shape._digest(checkpoint["headDigest"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[name], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        raise CurrentRootStateBootstrapError("current-root launch lifetime exceeds its source bound")
    if any(payload[name] is not False for name in ("hardwareBacked", "nativeStageZero",
            "hsmBackedKeys", "teeVerified", "externalWitnessVerified")):
        raise CurrentRootStateBootstrapError("current-root launch is not the explicit trusted-host-local assurance")
    _launch_shape(payload["launch"], work)
    shape._literal(payload["launch"]["schema"], _PAYLOAD_LAUNCHES[schema])


def _fresh(interval, work, opening=None):
    """Check the unchanged signed interval against actual bracketed clocks."""
    capture._SharedLedger(work)
    if type(interval) is not tuple or len(interval) != 2:
        raise CurrentRootStateBootstrapError("current-root launch interval is not an exact pair")
    issued, expires = interval
    shape._integer(issued, minimum=1)
    shape._integer(expires, minimum=1)
    if not 0 < expires - issued <= MAX_RECEIPT_AGE_NS:
        raise CurrentRootStateBootstrapError("current-root launch interval exceeds its bound")
    sample = clock._sample_on_work(work)
    before, epoch, after = sample
    if not issued <= epoch < expires:
        raise CurrentRootStateBootstrapError("current-root original bootstrap is future-issued or expired")
    if opening is not None:
        if type(opening) is not tuple or len(opening) != 3:
            raise CurrentRootStateBootstrapError("current-root original clock bracket is invalid")
        old_before, old_epoch, old_after = opening
        for value in opening:
            shape._integer(value, minimum=1)
        if (old_after < old_before or not issued <= old_epoch < expires
                or before < old_after or epoch < old_epoch
                or after >= old_before + expires - old_epoch
                or not old_epoch + before - old_after <= epoch <= old_epoch + after - old_before):
            raise CurrentRootStateBootstrapError("current-root original clock bracket or expiry changed")
    return sample


def _canonical(raw, value, work):
    capability._canonical(raw, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _material(payload, root_key, work):
    _payload_shape(payload, work)
    raw = authorization.transport._decode(payload["enrollmentBase64Url"],
        payload["enrollmentByteCount"], authorization.MAX_ENROLLMENT_BYTES, work)
    work.charge(hashes=1, input_bytes=len(raw))
    plan._same("sha256:" + hashlib.sha256(raw).hexdigest(), payload["enrollmentBytesDigest"], work,
        "current-root original enrollment byte identity differs")
    enrolled = authorization._admit_enrollment_on_work(enrollment_bytes=raw,
        root_public_key=root_key, work=work)
    policy = enrolled.payload
    for actual, expected in ((payload["enrollmentDigest"], enrolled.enrollment_digest),
            (payload["databaseId"], policy["databaseId"]),
            (payload["generationDigest"], policy["generationDigest"]),
            (payload["stateSigningSpkiDigest"], policy["state"]["spkiDigest"]),
            (payload["stateMeasurementDigest"], policy["state"]["measurementDigest"]),
            (payload["launch"]["journalMaximumRecords"], policy["maxRecords"])):
        plan._same(actual, expected, work, "current-root bootstrap differs from genuine enrollment")
    sequence, head = payload["checkpoint"]["sequence"], payload["checkpoint"]["headDigest"]
    if sequence > policy["maxRecords"]:
        raise CurrentRootStateBootstrapError("current-root checkpoint exceeds its enrolled journal capacity")
    if sequence == 0:
        plan._same(head, enrolled.enrollment_digest, work, "current-root independent genesis head differs")
    return _StateMaterial(raw, enrolled.state_public_key, enrolled.enrollment_digest,
        (sequence, head), (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]), payload["launch"])


def _admit_on_work(*, bootstrap_bytes, root_public_key, work):
    """Authenticate exact root originals before selecting any launch resources."""
    try:
        ledger = capture._SharedLedger(work)
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "current-root bootstrap")
        root_key = root_public_key
        authorization._public(root_key)
        envelope = wire._decode_object(original, work=work, maximum_bytes=MAX_BYTES,
            maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
        shape._object(envelope, _ENVELOPE_FIELDS, "current-root state root envelope")
        schema = envelope["schema"]
        if type(schema) is not str or schema not in _ENVELOPE_PAYLOADS:
            raise CurrentRootStateBootstrapError("current-root envelope schema is unsupported")
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            raise CurrentRootStateBootstrapError("current-root bootstrap payload is not an exact object")
        _canonical(original, envelope, work)
        payload = envelope["payload"]
        shape._literal(payload.get("schema"), _ENVELOPE_PAYLOADS[schema])
        payload_bytes = capability._wire(payload, ledger, MAX_BYTES, MAX_NODES)
        capability._signature(root_key, envelope["signatureBase64Url"], schema, payload_bytes, ledger)
        _canonical(original, envelope, work)
        _payload_shape(payload, work)
        interval = (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
        opening = _fresh(interval, work)
        material = _material(payload, root_key, work)
        _fresh(interval, work, opening=opening)
        _canonical(original, envelope, work)
        return material
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, CurrentRootStateBootstrapError):
            raise
        raise CurrentRootStateBootstrapError("current-root state bootstrap admission failed") from exc


def _sign(payload, private_key, public_key, work):
    """Sign the closed payload's source-fixed domain, never an override."""
    authorization._private(private_key)
    authorization._public(public_key)
    keys._pair_on_work(private_key, public_key, work)
    _payload_shape(payload, work)
    schema = {value: key for key, value in _ENVELOPE_PAYLOADS.items()}[payload["schema"]]
    envelope = {"schema": schema, "payload": payload, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(payload)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        raise CurrentRootStateBootstrapError("current-root bootstrap signature output exceeds its bound")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(schema) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise CurrentRootStateBootstrapError("current-root bootstrap cannot reserve signature work")
    unsigned = plan.core.canonical_bytes(payload)
    if len(unsigned) != unsigned_size:
        raise CurrentRootStateBootstrapError("current-root bootstrap payload changed after measurement")
    message = plan._ascii(plan._frame(schema, (unsigned,), work), work)
    signature = production._sign_and_verify(private_key, public_key, message, work)
    if work.measure(payload) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(payload) != unsigned:
        raise CurrentRootStateBootstrapError("current-root bootstrap changed during root signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    envelope["signatureBase64Url"] = encoded
    result = plan.core.canonical_bytes(envelope)
    if len(result) != envelope_size:
        raise CurrentRootStateBootstrapError("current-root bootstrap output changed after reservation")
    return result


def _produce_on_work(*, enrollment_bytes, checkpoint_sequence, checkpoint_head_digest,
        runtime_closure_digest, issued_at_epoch_ns, expires_at_epoch_ns, launch,
        root_private_key, root_public_key, work):
    """Provisioner-only signing of independently established original cold scope.

    There is deliberately no journal path/reader or current-state lookup here.
    The actual root provisioner must supply the independently current exact
    checkpoint and measured-runtime provenance; this does not manufacture them.
    """
    ledger = capture._SharedLedger(work)
    raw = authorization._original(enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES,
        "current-root bootstrap enrollment")
    private_key, public_key = root_private_key, root_public_key
    authorization._private(private_key)
    authorization._public(public_key)
    shape._integer(checkpoint_sequence, authorization.MAX_RECORDS)
    shape._digest(checkpoint_head_digest)
    shape._digest(runtime_closure_digest)
    shape._integer(issued_at_epoch_ns, minimum=1)
    shape._integer(expires_at_epoch_ns, minimum=1)
    sequence, head, closure, issued, expires = (checkpoint_sequence, checkpoint_head_digest,
        runtime_closure_digest, issued_at_epoch_ns, expires_at_epoch_ns)
    owned_launch = capture._JSONCapture(ledger, maximum_bytes=8192).visit(launch)
    _launch_shape(owned_launch, work)
    opening = _fresh((issued, expires), work)
    enrolled = authorization._admit_enrollment_on_work(enrollment_bytes=raw,
        root_public_key=public_key, work=work)
    policy = enrolled.payload
    work.charge(hashes=1, input_bytes=len(raw))
    raw_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    payload_schema = {value: key for key, value in _PAYLOAD_LAUNCHES.items()}[owned_launch["schema"]]
    payload = {"schema": payload_schema, "sourceRevision": authority.SOURCE_REVISION, "role": ROLE,
        "enrollmentBase64Url": authorization.transport._encode(raw, work),
        "enrollmentBytesDigest": raw_digest, "enrollmentByteCount": len(raw),
        "enrollmentDigest": enrolled.enrollment_digest, "databaseId": policy["databaseId"],
        "generationDigest": policy["generationDigest"], "stateSigningSpkiDigest": policy["state"]["spkiDigest"],
        "stateMeasurementDigest": policy["state"]["measurementDigest"], "runtimeClosureDigest": closure,
        "checkpoint": {"sequence": sequence, "headDigest": head},
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires, "trustMode": "trusted-host-local",
        "hardwareBacked": False, "nativeStageZero": False, "hsmBackedKeys": False,
        "teeVerified": False, "externalWitnessVerified": False, "launch": owned_launch}
    _material(payload, public_key, work)
    _fresh((issued, expires), work, opening=opening)
    original = _sign(payload, private_key, public_key, work)
    _fresh((issued, expires), work, opening=opening)
    return original
