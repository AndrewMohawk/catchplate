"""Fresh root-original launch of one private committed-release proof worker.

The nested completion bootstrap admits public originals and read-only custody
pins, not completion resources. No completion signer, journal or state writer
is delivered. The actual proof producer still authenticates committed originals.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import authority_current_root_delivery_records as records
from serverware import oidc_session_activation_delivery_completion_bootstrap as completion
from serverware import oidc_session_activation_release_custody_bootstrap as release_bootstrap
from serverware import oidc_session_activation_release_intent as intent
from serverware import oidc_session_activation_release_intent_enrollment as intent_enrollments
from serverware import oidc_session_activation_release_proof as proof_contract
from serverware import oidc_session_activation_release_proof_enrollment as proof_enrollments


authorization, shape, plan = completion.authorization, completion.shape, completion.plan
capture, production, clock = completion.capture, completion.production, completion.clock
capability, codec, authority = completion.capability, completion.codec, completion.authority
processing, delivery = completion.processing_window, release_bootstrap.delivery
ROLE = "oidc-session-activation-release-proof"
PROCESS_MODE = completion.PROCESS_MODE
SERVICE_UID = SERVICE_GID = 65497
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, EXECUTION_BUNDLE_KEY_FD, HISTORICAL_BUNDLE_KEY_FD, DELIVERY_KEY_FD = range(198, 205)
INHERITED_DESCRIPTORS = tuple(range(198, 205))
LISTENER_PATH = "/run/serverware/oidc-session-activation-token-release/proof.sock"
LISTENER_NAME = "serverware-oidc-session-activation-release-proof"
SCHEMA = "serverware.signedOidcSessionActivationReleaseProofBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseProofBootstrap/v1"
LAUNCH_SCHEMA = "serverware.oidcSessionActivationReleaseProofLaunch/v1"
PURPOSE = "launch-oidc-session-activation-release-proof"
MAX_BYTES = MAX_BOOTSTRAP_BYTES = 48 * 1024 * 1024
MAX_ORIGINAL_BYTES = 64 * 1024 * 1024
MAX_NODES, MAX_DEPTH = 2048, 10
TLS_PATHS, TLS_LIMITS = completion.TLS_PATHS, completion.TLS_LIMITS
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest"})
_ORIGINAL_LIMITS = (("completionBootstrap", completion.MAX_BYTES),
    ("proofEnrollment", proof_enrollments.MAX_BYTES),
    ("releaseCustody", release_bootstrap.MAX_BYTES), ("intent", intent.MAX_BYTES),
    ("intentEnrollment", intent_enrollments.MAX_BYTES),
    ("completionRequest", records.MAX_REQUEST_BYTES), ("stateReceipt", records.MAX_RECEIPT_BYTES))
_FD_FIELDS = (("rootPublicKeyFd", ROOT_FD), ("bootstrapFd", BOOTSTRAP_FD),
    ("listenerFd", LISTENER_FD), ("signingKeyFd", KEY_FD),
    ("executionBundleKeyFd", EXECUTION_BUNDLE_KEY_FD),
    ("historicalBundleKeyFd", HISTORICAL_BUNDLE_KEY_FD), ("deliveryKeyFd", DELIVERY_KEY_FD))
_LAUNCH_FIELDS = frozenset({"schema", "role", "processMode", "serviceUid", "serviceGid",
    "peerUid", "peerGid", *(name for name, _ in _FD_FIELDS), "inheritedFileDescriptors",
    "listenerPath", "requestTimeoutSeconds", "listenerSocketDevice", "listenerSocketInode",
    "listenerPathDevice", "listenerPathInode"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "role", "trustMode",
    *(name for name, _ in _ORIGINAL_LIMITS), "proofScope", "expectedRelease", "callerId",
    "issuedAtEpochNs", "expiresAtEpochNs", "launch"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class ReleaseProofBootstrapError(ValueError):
    pass


def _fail(message):
    raise ReleaseProofBootstrapError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ProofMaterial:
    bootstrap_bytes: bytes
    completion_bootstrap_bytes: bytes
    completion_material: completion._CompletionMaterial
    proof_enrollment_bytes: bytes
    proof_public_key: object
    proof_spki_digest: str
    expected_proof_scope: dict
    release_custody_bytes: bytes
    intent_bytes: bytes
    intent_enrollment_bytes: bytes
    completion_request_bytes: bytes
    state_receipt_bytes: bytes
    expected_release: dict
    expected_consume_binding: dict
    caller_id: str
    launch: dict
    attestation_interval: tuple
    opening_sample: tuple
    live_window: tuple
    deadline_ns: int
    live: object


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("release proof bootstrap exceeds its structure bound")
        return super().visit(value, depth, ancestors)


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _decode(original, work):
    return _capture(capability.wire._decode_object(original, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH), work)


_construction_on_work, _fresh = completion._construction_on_work, completion._fresh


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "release proof launch")
    for name, expected in (("schema", LAUNCH_SCHEMA), ("role", ROLE),
            ("processMode", PROCESS_MODE), ("listenerPath", LISTENER_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), *_FD_FIELDS):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            _fail("release proof launch identity or descriptor differs")
    shape._array(value["inheritedFileDescriptors"], len(INHERITED_DESCRIPTORS), "proof descriptors")
    for descriptor in value["inheritedFileDescriptors"]:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(value["inheritedFileDescriptors"], list(INHERITED_DESCRIPTORS), work, "proof exact FDs")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[name], minimum=0)
    for name in ("listenerSocketInode", "listenerPathInode"):
        shape._integer(value[name], minimum=1)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "release proof bootstrap")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("role", ROLE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "proof root original")
        shape._integer(record["byteCount"], maximum, minimum=2)
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._digest(record["bytesDigest"])
    proof_enrollments._scope_shape(payload["proofScope"])
    authorization._token(payload["callerId"])
    expected = payload["expectedRelease"]
    shape._object(expected, proof_contract.RELEASE_FIELDS, "proof independent release")
    for name in ("activationRequestDigest", "activationOperationId", "consumeRequestDigest", "deliveryEnvelopeDigest"):
        shape._digest(expected[name])
    release_bootstrap._scope(expected["deliveryScope"], work)
    shape._object(expected["consumeBinding"], intent.CONSUME_BINDING_FIELDS, "proof independent consume binding")
    for value in expected["consumeBinding"].values():
        shape._digest(value)
    authorization._interval(payload, completion.MAX_RECEIPT_AGE_NS)
    _launch_shape(payload["launch"], work)


def _unique_keys(values, work):
    result, seen = [], []
    for key in values:
        authorization._public(key)
        digest = authorization.keys._spki_on_work(key, work)
        work.prepare_scan(seen)
        if digest not in seen:
            seen.append(digest)
            result.append(key)
    return tuple(result)


def _material(payload, original, root, window, bound, work, inherited, *, _current=None):
    # Bound the complete nested byte inventory before any base64 allocation.
    if len(original) + sum(payload[name]["byteCount"] for name, _ in _ORIGINAL_LIMITS) > MAX_ORIGINAL_BYTES:
        _fail("proof bootstrap and nested originals exceed 64 MiB")
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    opening = window[1], window[0], window[2]
    _fresh(interval, work, opening=opening)
    guards = [completion.primitives._launch_guard(interval, opening, inherited, work)]
    last_epoch = window[0]

    def live():
        nonlocal last_epoch
        for guarded in (inherited, *guards, inherited):
            epoch = guarded()
            shape._integer(epoch, minimum=1)
            if epoch < last_epoch:
                _fail("proof cold processing reversed across original guards")
            last_epoch = epoch
        return last_epoch

    def narrow(expiry, age, skew):
        nonlocal window, bound
        window = processing._narrow(window, deadline_epoch_ns=expiry,
            maximum_lifetime_ns=age, maximum_clock_skew_ns=skew)
        bound = min(bound, window[4])
        _window, guarded = delivery._window(window, bound, work)
        guards.append(guarded)
        live()

    live()
    raw = tuple(completion.grammar._original(payload[name], maximum, work, live)
        for name, maximum in _ORIGINAL_LIMITS)
    cm = completion._verify_on_work(bootstrap_bytes=raw[0], root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work, _current=_current)
    if type(cm) is not completion._CompletionMaterial:
        _fail("proof cold admission requires genuine completion originals")
    for material in (cm, cm.custody_material, cm.custody_material.history):
        guards.append(completion.primitives._launch_guard(material.attestation_interval,
            material.opening_sample, inherited, work))
    live()
    rm = release_bootstrap._verify_on_work(custody_bytes=raw[2], root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work, _current=_current)
    guards.append(release_bootstrap.planner_bootstrap._launch_guard(rm.attestation_interval,
        rm.opening_sample, inherited, work))
    live()
    nested = (cm.custody_bytes, cm.planner_bootstrap_bytes, cm.planner_history_custody_bytes,
        cm.receiving_history_custody_bytes, cm.authorization_bytes, cm.current_root_enrollment_bytes,
        cm.grant_enrollment_bytes, cm.authorization_enrollment_bytes, rm.planner.bootstrap_bytes)
    if len(original) + sum(map(len, (*raw, *nested))) > MAX_ORIGINAL_BYTES:
        _fail("proof complete retained originals exceed 64 MiB")
    for actual in (cm.attestation_interval, rm.attestation_interval,
            cm.custody_material.attestation_interval, cm.custody_material.history.attestation_interval):
        if not actual[0] <= interval[0] < interval[1] <= actual[1]:
            _fail("proof launch escapes genuinely admitted current authority")
    scope, expected = payload["proofScope"], payload["expectedRelease"]
    for actual, wanted in ((scope["configurationDigest"], cm.configuration_digest),
            (scope["databaseId"], cm.database_id), (scope["generationDigest"], cm.generation_digest),
            (scope["runtimeClosureDigest"], cm.runtime_closure_digest),
            (scope["producerIdentity"], cm.receiver_identity), (scope["receiverIdentity"], rm.receiver_identity),
            (rm.planner.configuration_digest, cm.configuration_digest),
            (rm.planner.generation["digest"], cm.generation_digest),
            (rm.planner.runtime_closure_digest, cm.runtime_closure_digest),
            (expected["activationRequestDigest"], rm.activation_request_digest),
            (expected["activationOperationId"], rm.activation_operation_id),
            (expected["consumeRequestDigest"], rm.consume_request_digest),
            (expected["consumeRequestDigest"], cm.expectations["request"]["requestDigest"]),
            (expected["deliveryEnvelopeDigest"], rm.delivery_envelope_digest),
            (expected["deliveryScope"], rm.delivery_scope),
            (expected["consumeBinding"]["packetDigest"], cm.packet_digest)):
        plan._same(actual, wanted, work, "proof independent root cohort/target")
    completion.receiving._same_bytes(rm.planner.state_enrollment_bytes,
        cm.current_root_enrollment_bytes, work, "proof original state enrollment differs")
    state = authorization._admit_enrollment_on_work(enrollment_bytes=cm.current_root_enrollment_bytes,
        root_public_key=root, work=work)
    live()
    base = _unique_keys((rm.planner.planner_public_key, state.computation_public_key,
        state.completion_public_key, state.state_public_key), work)
    intent_scope = {name: scope[name] for name in ("configurationDigest", "databaseId",
        "generationDigest", "runtimeClosureDigest", "receiverIdentity")}
    intent_scope["callerId"] = payload["callerId"]
    enrolled_intent = intent_enrollments._admit_on_work(enrollment_bytes=raw[4], root_public_key=root,
        expected_scope=intent_scope, forbidden_public_keys=base, work=work)
    live()
    envelope = intent._read(raw[3], work)
    intent._signature(envelope, enrolled_intent.caller_public_key, work)
    live()
    for name, wanted in {**intent_scope, **expected,
            "enrollmentDigest": enrolled_intent.enrollment_digest,
            "callerMeasurementDigest": enrolled_intent.payload["callerKey"]["measurementDigest"]}.items():
        plan._same(envelope["payload"][name], wanted, work, "proof original intent target")
    plan._same(intent._digest(raw[3], work), rm.release_intent_digest, work, "proof root-pinned intent")
    intent_interval = envelope["payload"]["issuedAtEpochNs"], envelope["payload"]["expiresAtEpochNs"]
    if not intent_interval[0] <= interval[0] < interval[1] <= intent_interval[1]:
        _fail("proof launch escapes its exact original intent")
    caller = completion.caller._admit_enrollment_on_work(
        authorization_enrollment_bytes=cm.authorization_enrollment_bytes,
        current_root_enrollment_bytes=cm.current_root_enrollment_bytes,
        grant_enrollment_bytes=cm.grant_enrollment_bytes, root_public_key=root,
        configuration_digest=cm.configuration_digest, planner_public_key=cm.planner_public_key,
        operation_public_key=cm.operation_public_key, work=work)
    grant = completion.grants._admit_enrollment_on_work(grant_enrollment_bytes=cm.grant_enrollment_bytes,
        current_root_enrollment_bytes=cm.current_root_enrollment_bytes, root_public_key=root, work=work)
    live()
    forbidden = _unique_keys((*base, enrolled_intent.caller_public_key, cm.planner_public_key,
        cm.operation_public_key, caller.caller_public_key, grant.authorizer_public_key,
        cm.custody_material.history.planner.planner_public_key), work)
    enrolled = proof_enrollments._admit_on_work(enrollment_bytes=raw[1], root_public_key=root,
        expected_scope=scope, forbidden_public_keys=forbidden, work=work)
    live()
    proof_pin = enrolled.payload["proofKey"]["spkiDigest"]
    completion._configured_keys(cm.configuration_payload, proof_pin, proof_pin, work)
    policy = cm.custody_material.planner.payload
    _created, delivery_expiry = release_bootstrap._scope(expected["deliveryScope"], work)
    narrow(min(interval[1], delivery_expiry),
        min(policy["maximumPlanAgeNs"], enrolled.payload["maximumAgeNs"],
            enrolled_intent.payload["maximumAgeNs"]),
        min(policy["maximumClockSkewNs"], enrolled.payload["maximumClockSkewNs"],
            enrolled_intent.payload["maximumClockSkewNs"]))
    if payload["launch"]["requestTimeoutSeconds"] * 1_000_000_000 > window[5]:
        _fail("proof socket timeout exceeds its original processing lifetime")
    result = _ProofMaterial(original, raw[0], cm, raw[1], enrolled.proof_public_key, proof_pin,
        scope, raw[2], raw[3], raw[4], raw[5], raw[6], expected, expected["consumeBinding"],
        payload["callerId"], payload["launch"], interval, opening, window, bound, live)
    live()
    return result


def _verify_on_work(*, bootstrap_bytes, root_public_key, live_window, transport_deadline_ns, work,
        _current=None):
    root = root_public_key
    authorization._public(root)
    original = authorization._original(bootstrap_bytes, MAX_BYTES, "release proof bootstrap")
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    _window, inherited = delivery._window(window, bound, work)
    inherited = delivery._join_current(inherited, _current, work)
    inherited()
    try:
        envelope = _decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed release proof bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        _canonical(original, envelope, work)
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA,
            _wire(envelope["payload"], work), capture._SharedLedger(work))
        inherited()
        _payload_shape(envelope["payload"], work)
        material = _material(envelope["payload"], original, root, window, bound, work, inherited,
            _current=_current)
        _canonical(original, envelope, work)
        material.live()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, ReleaseProofBootstrapError):
            raise
        raise ReleaseProofBootstrapError("release proof cold admission failed") from exc


def _produce_on_work(*, payload, root_private_key, root_public_key, live_window, transport_deadline_ns, work,
        _current=None):
    private, root = root_private_key, root_public_key
    authorization._private(private)
    authorization._public(root)
    owned = _capture(payload, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    _window, inherited = delivery._window(window, bound, work)
    inherited = delivery._join_current(inherited, _current, work)
    inherited()
    _payload_shape(owned, work)
    unsigned = _wire(owned, work)
    envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    # Reserve the full fixed-signature envelope, including its wrapper, in the
    # complete original inventory before opening nested originals.
    reserved_original = _wire(envelope, work)
    material = _material(owned, reserved_original, root, window, bound, work, inherited,
        _current=_current)
    authorization.keys._pair_on_work(private, root, work)
    size, nodes = work.measure(envelope)
    payload_size, payload_nodes = work.measure(owned)
    if size > MAX_BYTES or nodes > MAX_NODES:
        _fail("signed proof bootstrap exceeds output bounds")
    work.charge(input_bytes=size + 2 * payload_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=nodes + payload_nodes)
    message = plan._ascii(plan._frame(SCHEMA, (unsigned,), work), work)
    material.live()
    signature = production._sign_and_verify(private, root, message, work)
    material.live()
    if codec._encode(owned) != unsigned:
        _fail("proof bootstrap payload changed during signing")
    envelope["signatureBase64Url"] = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    original = codec._encode(envelope)
    if len(original) != size:
        _fail("proof bootstrap output changed after preallocation")
    _canonical(original, envelope, work)
    material.live()
    return original
