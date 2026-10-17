"""Root-original cold resource admission for private release or recovery.

The two source-fixed profiles do not substitute for intent, proof, outcome or
old-token admission. Originals are reauthenticated under one supplied current
allowance; this module opens no key, directory, listener or token.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature

from catchplate import authority_successor_execution_window as processing
from catchplate import oidc_session_activation_release_custody_bootstrap as custody
from catchplate import oidc_session_activation_release_retained_authority as retained
from catchplate import oidc_session_activation_release_outcome_authorization as storage
from catchplate import oidc_session_activation_release_proof as proof
from catchplate import oidc_session_activation_release_recovery_authorization as recovery


authority, authorization, capability = custody.authority, custody.authorization, custody.capability
capture, plan, shape = custody.capture, custody.plan, custody.shape
clock, production, delivery = custody.clock, custody.production, custody.delivery
planner_bootstrap, registration = custody.planner_bootstrap, custody.registration
keys, codec = planner_bootstrap.keys, planner_bootstrap.codec
ROLE = PROCESS_MODE = custody.PROCESS_MODE
SERVICE_UID, SERVICE_GID = custody.SERVICE_UID, custody.SERVICE_GID
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, DELIVERY_KEY_FD, OUTCOME_DIR_FD, LISTENER_FD = range(198, 203)
INHERITED_DESCRIPTORS = tuple(range(198, 203))
LISTENER_PATH = "/run/catchplate/oidc-session-activation-token-release/release.sock"
LIVE_PROFILE, RECOVERY_PROFILE = "live-release", "recovery"
PURPOSE = "launch-oidc-session-activation-token-release"
SCHEMA = "catchplate.signedOidcSessionActivationReleaseBootstrap/v1"
PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationReleaseBootstrap/v1"
V2_SCHEMA = "catchplate.signedOidcSessionActivationReleaseBootstrap/v2"
V2_PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationReleaseBootstrap/v2"
V3_SCHEMA = "catchplate.signedOidcSessionActivationReleaseBootstrap/v3"
V3_PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationReleaseBootstrap/v3"
LAUNCH_SCHEMA = "catchplate.oidcSessionActivationReleaseLaunch/v1"
MAX_BYTES = MAX_BOOTSTRAP_BYTES = 16 * 1024 * 1024
MAX_ORIGINAL_BYTES = authority.MAX_RESULT_BYTES
MAX_NODES, MAX_DEPTH = 1024, 8
MAX_RECEIPT_AGE_NS = planner_bootstrap.MAX_RECEIPT_AGE_NS
_FALSE_FIELDS = custody._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest"})
_ORIGINAL_LIMITS = (("releaseCustody", custody.MAX_BYTES),
    ("storageAuthorization", storage.MAX_BYTES), ("recoveryAuthorization", recovery.MAX_BYTES))
_FD_FIELDS = (("rootPublicKeyFd", ROOT_FD), ("bootstrapFd", BOOTSTRAP_FD),
    ("deliveryKeyFd", DELIVERY_KEY_FD), ("outcomeDirectoryFd", OUTCOME_DIR_FD),
    ("listenerFd", LISTENER_FD))
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid",
    *(name for name, _ in _FD_FIELDS), "inheritedFileDescriptors",
    "outcomeDirectoryDevice", "outcomeDirectoryInode", "outcomeDirectoryUid",
    "outcomeDirectoryGid", "outcomeDirectoryMode", "listenerPath", "peerUid", "peerGid",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode",
    "requestTimeoutSeconds"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "role", "profile",
    "configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest",
    "receiverIdentity", "callerId", "producerId", "producerIdentity", "stateReceiptDigest",
    "expectedRelease", "releaseCustodyDigest", "deliveryKeyDigest", "storageScope", "recoveryScope",
    *(name for name, _ in _ORIGINAL_LIMITS), "issuedAtEpochNs", "expiresAtEpochNs",
    "trustMode", "launch", *_FALSE_FIELDS})


class OidcSessionActivationReleaseBootstrapError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseBootstrapError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReleaseMaterial:
    bootstrap_bytes: bytes
    profile: str
    custody_bytes: bytes
    storage_authorization_bytes: bytes
    recovery_authorization_bytes: bytes | None
    storage_scope: dict
    recovery_scope: dict | None
    expected_release: dict
    producer_id: str
    producer_identity: dict
    caller_id: str
    state_receipt_digest: str
    receiver_identity: dict
    delivery_key_digest: str
    custody_material: custody._ReleaseCustodyMaterial
    configuration_digest: str
    database_id: str
    generation_digest: str
    runtime_closure_digest: str
    launch: dict
    attestation_interval: tuple
    opening_sample: tuple
    live_window: tuple
    deadline_ns: int
    live: object


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("release bootstrap exceeds its fixed shape bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("release bootstrap exceeds its fixed node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _decode(original, work):
    return _capture(capability.wire._decode_object(original, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH), work)


def _construction_on_work(work):
    """Start the sole real bracket before resource intake or root/key I/O."""
    capture._SharedLedger(work)
    before, epoch, after = clock._sample_on_work(work)
    age, skew = authority.VERIFIER_RESPONSE_MAX_AGE_NS, authority.VERIFIER_MAX_CLOCK_SKEW_NS
    window = clock._validate((epoch, before, after, epoch + age, before + age, age, skew))
    return window, window[4]


def _fresh(interval, work, opening=None):
    return custody._fresh(interval, work, opening=opening)


def _launch_guard(interval, opening, inherited, work):
    previous, last_epoch = opening, opening[1]

    def live():
        nonlocal previous, last_epoch
        first = inherited()
        sample = _fresh(interval, work, opening=opening)
        last = inherited()
        if (first < last_epoch or sample[0] < previous[2]
                or sample[1] < first or last < sample[1]):
            _fail("release launch freshness and processing clocks reversed")
        previous, last_epoch = sample, last
        return last

    return live


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "private release cold launch")
    for name, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("outcomeDirectoryUid", SERVICE_UID), ("outcomeDirectoryGid", SERVICE_GID),
            ("outcomeDirectoryMode", 0o700), ("peerUid", PEER_UID), ("peerGid", PEER_GID), *_FD_FIELDS):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            _fail("release launch identity, mode or descriptor is not source fixed")
    shape._array(value["inheritedFileDescriptors"], len(INHERITED_DESCRIPTORS), "release descriptors")
    for descriptor in value["inheritedFileDescriptors"]:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(value["inheritedFileDescriptors"], list(INHERITED_DESCRIPTORS), work,
        "release exact inherited descriptor inventory")
    for name in ("outcomeDirectoryDevice", "listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("outcomeDirectoryInode", "listenerSocketInode", "listenerPathInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)


def _release_shape(value, work):
    shape._object(value, proof.RELEASE_FIELDS, "release launch independent target")
    for name in proof.RELEASE_FIELDS - {"deliveryScope", "consumeBinding"}:
        shape._digest(value[name])
    custody._scope(value["deliveryScope"], work)
    shape._object(value["consumeBinding"], proof.CONSUME_BINDING_FIELDS,
        "release launch independent committed-consumption binding")
    for name in proof.CONSUME_BINDING_FIELDS:
        shape._digest(value["consumeBinding"][name])


def _payload_shape(payload, work):
    historical = type(payload) is dict and payload.get("schema") in (V2_PAYLOAD_SCHEMA, V3_PAYLOAD_SCHEMA)
    selected_schema = payload["schema"] if historical else PAYLOAD_SCHEMA
    shape._object(payload, _PAYLOAD_FIELDS | {"evidenceCustodyDigest"} if historical else _PAYLOAD_FIELDS,
        "release bootstrap payload")
    for name, expected in (("schema", selected_schema), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("role", ROLE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    if type(payload["profile"]) is not str or payload["profile"] not in (LIVE_PROFILE, RECOVERY_PROFILE):
        _fail("release launch profile is not one of the two fixed root purposes")
    if historical:
        shape._digest(payload["evidenceCustodyDigest"])
        selected_profile = RECOVERY_PROFILE if selected_schema == V3_PAYLOAD_SCHEMA else LIVE_PROFILE
        if payload["profile"] != selected_profile:
            _fail("current historical-delivery bootstrap has a different explicit purpose")
    for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "stateReceiptDigest", "releaseCustodyDigest", "deliveryKeyDigest"):
        shape._digest(payload[name])
    for name in ("databaseId", "callerId", "producerId"):
        authorization._token(payload[name])
    for name in ("receiverIdentity", "producerIdentity"):
        shape.validate_identity_shape(payload[name])
    _release_shape(payload["expectedRelease"], work)
    storage._scope_shape(payload["storageScope"], work)
    if payload["profile"] == LIVE_PROFILE:
        if payload["recoveryScope"] is not None or payload["recoveryAuthorization"] is not None:
            _fail("live release cannot carry recovery authority")
        if payload["storageScope"]["checkpoint"] != {"recordCount": 0, "outcomeDigest": None}:
            _fail("live cold release requires the independently authorized empty checkpoint")
    else:
        recovery._scope_shape(payload["recoveryScope"], work)
        shape._object(payload["recoveryScope"], recovery.V2_SCOPE_FIELDS if selected_schema == V3_PAYLOAD_SCHEMA
            else recovery.SCOPE_FIELDS, "release independently selected recovery profile")
        checkpoint = payload["storageScope"]["checkpoint"]
        if checkpoint["recordCount"] != 1:
            _fail("cold recovery requires the independently authorized retained checkpoint")
        plan._same(checkpoint["outcomeDigest"], payload["recoveryScope"]["outcomeDigest"], work,
            "release recovery and storage exact outcome")
    for name, maximum in _ORIGINAL_LIMITS:
        value = payload[name]
        if name == "recoveryAuthorization" and payload["profile"] == LIVE_PROFILE:
            continue
        shape._object(value, _ORIGINAL_FIELDS, "release launch original " + name)
        shape._integer(value["byteCount"], maximum, minimum=2)
        authorization.transport._transport_shape(value["base64Url"], value["byteCount"], maximum)
        shape._digest(value["bytesDigest"])
    authorization._interval(payload, MAX_RECEIPT_AGE_NS)
    _created, delivery_expiry = custody._scope(payload["expectedRelease"]["deliveryScope"], work)
    if payload["expiresAtEpochNs"] > delivery_expiry:
        _fail("release launch extends the original delivery expiry")
    if any(payload[name] is not False for name in _FALSE_FIELDS):
        _fail("release cold launch claims unsupported hardware or witness assurance")
    _launch_shape(payload["launch"], work)


def _originals(payload, original, current, work):
    total = len(original) + sum(payload[name]["byteCount"] for name, _ in _ORIGINAL_LIMITS
        if payload[name] is not None)
    if total > MAX_ORIGINAL_BYTES:
        _fail("release cold original inventory exceeds its aggregate bound")
    result = []
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        if record is None:
            result.append(None)
            continue
        current()
        raw = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
        work.charge(hashes=1, input_bytes=len(raw))
        digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
        current()
        plan._same(digest, record["bytesDigest"], work, "release cold original " + name)
        result.append(raw)
    return tuple(result), total


def _contains(outer, inner):
    if outer[0] < inner[0] or outer[1] > inner[1]:
        _fail("release launch interval exceeds an independently authenticated fresh original")


def _material(payload, original, root, window, bound, opening, current, work, _continuity=None):
    (custody_bytes, storage_bytes, recovery_bytes), total = _originals(payload, original, current, work)
    current_recovery = payload["schema"] == V3_PAYLOAD_SCHEMA
    verifier = custody._verify_on_work if payload["profile"] == LIVE_PROFILE or current_recovery else custody._verify_historical_on_work
    admitted = verifier(custody_bytes=custody_bytes, root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work,
        _current=current if _continuity is not None else None)
    current()
    historical = payload["schema"] in (V2_PAYLOAD_SCHEMA, V3_PAYLOAD_SCHEMA)
    if historical != (admitted.intent_root_public_key is not None):
        _fail("release bootstrap and current custody historical profiles differ")
    evidence_root = retained.root_for(admitted, root)
    current_planner = retained.planner_for(admitted)
    if total + len(admitted.planner.bootstrap_bytes) > MAX_ORIGINAL_BYTES:
        _fail("release cold nested original inventory exceeds its aggregate bound")
    custody_digest = plan._frame(proof.CUSTODY_IDENTITY_DOMAIN, (custody_bytes,), work)
    evidence_digest = plan._frame(proof.CUSTODY_IDENTITY_DOMAIN, (retained.custody_for(admitted),), work)
    if historical:
        plan._same(evidence_digest, payload["evidenceCustodyDigest"], work,
            "release bootstrap exact retired evidence custody")
    for actual, expected in ((custody_digest, payload["releaseCustodyDigest"]),
            (admitted.receiver_identity, payload["receiverIdentity"]),
            (admitted.delivery_key_digest, payload["deliveryKeyDigest"]),
            (admitted.planner.configuration_digest, payload["configurationDigest"]),
            (admitted.planner.generation["digest"], payload["generationDigest"]),
            (admitted.planner.runtime_closure_digest, payload["runtimeClosureDigest"]),
            (admitted.activation_request_digest, payload["expectedRelease"]["activationRequestDigest"]),
            (admitted.activation_operation_id, payload["expectedRelease"]["activationOperationId"]),
            (admitted.consume_request_digest, payload["expectedRelease"]["consumeRequestDigest"]),
            (admitted.delivery_envelope_digest, payload["expectedRelease"]["deliveryEnvelopeDigest"]),
            (admitted.delivery_scope, payload["expectedRelease"]["deliveryScope"])):
        plan._same(actual, expected, work, "release launch genuine custody and independent target")
    state = authorization._admit_enrollment_on_work(enrollment_bytes=admitted.planner.state_enrollment_bytes,
        root_public_key=evidence_root, work=work)
    current()
    for actual, expected in ((state.enrollment_digest, admitted.planner.state_enrollment_digest),
            (state.payload["databaseId"], payload["databaseId"]),
            (state.payload["generationDigest"], payload["generationDigest"])):
        plan._same(actual, expected, work, "release launch original state enrollment")
    slot = payload["storageScope"]
    for name in storage.SCOPE_FIELDS - {"directory", "checkpoint", "deliveryId"}:
        expected = evidence_digest if name == "releaseCustodyDigest" else payload[name]
        plan._same(slot[name], expected, work, "release launch independent storage " + name)
    plan._same(slot["deliveryId"], admitted.delivery_scope["deliveryId"], work, "release launch exact slot")
    directory = {name: payload["launch"]["outcomeDirectory" + name[0].upper() + name[1:]]
        for name in storage.DIRECTORY_FIELDS}
    plan._same(slot["directory"], directory, work, "release launch actual directory pins")
    stored = storage._verify_on_work(authorization_bytes=storage_bytes, root_public_key=root,
        expected_scope=slot, live_window=window, transport_deadline_ns=bound, work=work,
        _continuity=_continuity)
    current()
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    _contains(interval, (stored.payload["issuedAtEpochNs"], stored.payload["expiresAtEpochNs"]))
    recovered = None
    if payload["profile"] == LIVE_PROFILE:
        _contains(interval, admitted.attestation_interval)
    else:
        recovery_scope = payload["recoveryScope"]
        if current_recovery:
            _contains(interval, admitted.attestation_interval)
        recovery_fields = recovery.V2_SCOPE_FIELDS if current_recovery else recovery.SCOPE_FIELDS
        for name in recovery_fields - {"directory", "deliveryId", "outcomeDigest"}:
            expected = (custody_digest if name == "currentReleaseCustodyDigest" else
                evidence_digest if name == "releaseCustodyDigest" else payload[name])
            plan._same(recovery_scope[name], expected, work, "release launch independent recovery " + name)
        plan._same(recovery_scope["directory"], directory, work, "release recovery directory pins")
        plan._same(recovery_scope["deliveryId"], slot["deliveryId"], work, "release recovery exact slot")
        recovered = recovery._verify_on_work(authorization_bytes=recovery_bytes, root_public_key=root,
            expected_scope=recovery_scope, live_window=window, transport_deadline_ns=bound, work=work,
            _continuity=_continuity)
        current()
        _contains(interval, (recovered.payload["issuedAtEpochNs"], recovered.payload["expiresAtEpochNs"]))
    _created, delivery_expiry = custody._scope(admitted.delivery_scope, work)
    narrowed = processing._narrow(window, deadline_epoch_ns=min(interval[1], delivery_expiry),
        maximum_lifetime_ns=min(current_planner.maximum_plan_age_ns,
            payload["launch"]["requestTimeoutSeconds"] * 1_000_000_000),
        maximum_clock_skew_ns=current_planner.maximum_clock_skew_ns)
    deadline = min(bound, narrowed[4])
    checked, _bind = storage._processing(narrowed, deadline, work, _continuity)
    last_epoch = current()

    def live():
        nonlocal last_epoch
        # Preserve every previously observed epoch across distinct original
        # guards; no later native callback may hide a backward clock step.
        checks = (current, stored.live) if recovered is None else (current, stored.live, recovered.live)
        for check in (*checks, checked):
            observed = check()
            if observed < last_epoch:
                _fail("release launch original guards observed a reversed clock")
            last_epoch = observed
        if last_epoch >= delivery_expiry:
            _fail("release launch original delivery is expired")
        return last_epoch

    live()
    return _ReleaseMaterial(original, payload["profile"], custody_bytes, storage_bytes, recovery_bytes,
        slot, payload["recoveryScope"], payload["expectedRelease"], payload["producerId"],
        payload["producerIdentity"], payload["callerId"], payload["stateReceiptDigest"],
        payload["receiverIdentity"], payload["deliveryKeyDigest"], admitted,
        payload["configurationDigest"], payload["databaseId"], payload["generationDigest"],
        payload["runtimeClosureDigest"], payload["launch"], interval, opening, narrowed, deadline, live)


def _verify_on_work(*, bootstrap_bytes, root_public_key, live_window, transport_deadline_ns, work,
        _continuity=None):
    """Admit root originals, never a prior material carrier or inferred slot."""
    capture._SharedLedger(work)
    original = authorization._original(bootstrap_bytes, MAX_BYTES, "release cold bootstrap")
    root = root_public_key
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    current, bind_interval = storage._processing(window, bound, work, _continuity)
    current()
    envelope = _decode(original, work)
    shape._object(envelope, _ENVELOPE_FIELDS, "signed release cold bootstrap")
    if envelope["schema"] not in (SCHEMA, V2_SCHEMA, V3_SCHEMA):
        _fail("unsupported release cold schema")
    shape._base64url(envelope["signatureBase64Url"], signature=True)
    _payload_shape(envelope["payload"], work)
    shape._literal(envelope["payload"]["schema"],
        V3_PAYLOAD_SCHEMA if envelope["schema"] == V3_SCHEMA else
        V2_PAYLOAD_SCHEMA if envelope["schema"] == V2_SCHEMA else PAYLOAD_SCHEMA)
    _canonical(original, envelope, work)
    unsigned = _wire(envelope["payload"], work)
    current()
    try:
        capability._signature(root, envelope["signatureBase64Url"], envelope["schema"],
            unsigned, capture._SharedLedger(work))
    except InvalidSignature as exc:
        raise OidcSessionActivationReleaseBootstrapError("release cold root signature is invalid") from exc
    current()
    payload = envelope["payload"]
    opening = window[1], window[0], window[2]
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    live = _launch_guard(interval, opening, bind_interval(*interval), work)
    live()
    material = _material(payload, original, root, window, bound, opening, live, work, _continuity)
    _canonical(original, envelope, work)
    material.live()
    return material


def _produce_on_work(*, payload, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    """Sign a closed root-selected launch after genuine nested admission."""
    capture._SharedLedger(work)
    private, root = root_private_key, root_public_key
    owned = _capture(payload, work)
    authorization._private(private)
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    current, bind_interval = storage._processing(window, bound, work, _continuity)
    current()
    _payload_shape(owned, work)
    opening = window[1], window[0], window[2]
    interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
    live = _launch_guard(interval, opening, bind_interval(*interval), work)
    unsigned = _wire(owned, work)
    admitted = _material(owned, unsigned, root, window, bound, opening, live, work, _continuity)
    keys._pair_on_work(private, root, work)
    admitted.live()
    schema = V3_SCHEMA if owned["schema"] == V3_PAYLOAD_SCHEMA else V2_SCHEMA if owned["schema"] == V2_PAYLOAD_SCHEMA else SCHEMA
    envelope = {"schema": schema, "payload": owned, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(envelope)
    payload_size, payload_nodes = work.measure(owned)
    if size > MAX_BYTES or nodes > MAX_NODES:
        _fail("release cold signed output exceeds its fixed bound")
    work.charge(input_bytes=size + 2 * payload_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=nodes + payload_nodes)
    message = plan._ascii(plan._frame(schema, (unsigned,), work), work)
    admitted.live()
    signature = production._sign_and_verify(private, root, message, work)
    admitted.live()
    if codec._encode(owned) != unsigned:
        _fail("release cold payload changed during signing")
    envelope["signatureBase64Url"] = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(envelope["signatureBase64Url"], signature=True)
    result = codec._encode(envelope)
    if len(result) != size:
        _fail("release cold signed output changed after reservation")
    checked = _decode(result, work)
    plan._same(checked, envelope, work, "release cold canonical signed readback")
    _canonical(result, checked, work)
    admitted.live()
    return result
