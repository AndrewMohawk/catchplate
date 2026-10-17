"""Independent original admission for the dedicated activation reserver.

The root must independently establish the receiving identity, enrolled
computation key, state predecessor and separate durable journal checkpoint.
Authenticating these claims neither measures a runtime nor makes a static
predecessor current. The state owner still compares and publishes atomically.
No successful material object, caller-selected endpoint or regenerated clock
can replace the original role, custody, planner and enrollment statements.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature

from catchplate import authority_oidc_session_activation_execution_authorization as caller
from catchplate import oidc_session_activation_execution_custody_bootstrap as receiving


planner_bootstrap = receiving.planner_bootstrap
authority, configuration = planner_bootstrap.authority, planner_bootstrap.configuration
codec, signing = planner_bootstrap.codec, planner_bootstrap.signing
capability, capture, plan, keys = (planner_bootstrap.capability, planner_bootstrap.capture,
    planner_bootstrap.plan, planner_bootstrap.keys)
authorization, grants, shape, clock = caller.authorization, caller.grants, caller.shape, caller.clock
production = configuration.production
ROLE = PROCESS_MODE = receiving.CONSUMERS["reserve"][0]
OPERATION = "oidc.session.activate"
SERVICE_UID = SERVICE_GID = 65505
PEER_UID = PEER_GID = 65532
STATE_SERVICE_UID = STATE_SERVICE_GID = 65516
STATE_LISTENER_UID = STATE_LISTENER_GID = 0
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD, BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD, JOURNAL_FD = range(198, 206)
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD,
    BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD, JOURNAL_FD)
LISTENER_PATH = "/run/catchplate/oidc-session-activation-execution/reserver.sock"
LISTENER_NAME = "catchplate-oidc-session-activation-execution-reserver"
JOURNAL_PATH = "/var/lib/catchplate/oidc-session-activation-execution-reservations"
STATE_SOCKET_PATH = "/run/catchplate/current-root/state.sock"
MAX_BYTES = MAX_ROLE_BYTES = 4 * 1024 * 1024
MAX_CUSTODY_BYTES = receiving.MAX_BYTES
MAX_RECEIPT_AGE_NS = planner_bootstrap.MAX_RECEIPT_AGE_NS
SCHEMA = "catchplate.signedOidcSessionActivationExecutionReserverBootstrap/v1"
PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationExecutionReserverBootstrap/v1"
LAUNCH_SCHEMA = "catchplate.oidcSessionActivationExecutionReserverLaunch/v1"
_FALSE_FIELDS = receiving._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_CUSTODY_FIELDS = frozenset({"byteCount", "bytesDigest"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest", "identityDigest"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "operation", "receivingCustody",
    "receiverIdentity", "configurationDigest", "generationDigest", "runtimeClosureDigest", "databaseId",
    "currentRootEnrollment", "grantEnrollment", "authorizationEnrollment", "computationSpkiDigest",
    "computationMeasurementDigest", "statePredecessor", "reservationCheckpoint", "stateEndpoint",
    "issuedAtEpochNs", "expiresAtEpochNs", "trustMode", "launch", *_FALSE_FIELDS})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
    "rootPublicKeyFd", "bootstrapFd", "listenerFd", "custodyFd", "bundleKeyFd", "deliveryKeyFd",
    "signingKeyFd", "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode",
    "journalDirectoryFd", "journalDirectoryPath", "journalDirectoryDevice", "journalDirectoryInode",
    "journalMaximumRecords"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "serviceUid", "serviceGid",
    "listenerUid", "listenerGid"})


class OidcSessionActivationExecutionReserverBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReserverMaterial:
    """Owned same-call facts, never a public admission token."""

    bootstrap_bytes: bytes
    custody_bytes: bytes
    custody_material: receiving._CustodyMaterial
    receiver_identity: dict
    configuration_payload: dict
    generation: dict
    runtime_role_identities: dict
    configuration_digest: str
    runtime_closure_digest: str
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    planner_public_key: object
    operation_public_key: object
    computation_public_key: object
    computation_spki_digest: str
    computation_measurement_digest: str
    database_id: str
    generation_digest: str
    enrollment_digest: str
    maximum_authorization_age_ns: int
    maximum_authorization_clock_skew_ns: int
    state_predecessor: tuple
    reservation_checkpoint: tuple
    state_endpoint: tuple
    attestation_interval: tuple
    opening_sample: tuple
    launch: dict


def _fail(message):
    raise OidcSessionActivationExecutionReserverBootstrapError(message)


def _state_endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "activation reservation state endpoint")
    shape._literal(value["socketPath"], STATE_SOCKET_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for field, expected in (("serviceUid", STATE_SERVICE_UID), ("serviceGid", STATE_SERVICE_GID),
            ("listenerUid", STATE_LISTENER_UID), ("listenerGid", STATE_LISTENER_GID)):
        shape._integer(value[field], 2**32 - 2)
        if value[field] != expected:
            _fail("activation reservation state endpoint identity is not fixed")
    return (value["socketPath"], value["requestTimeoutSeconds"], STATE_SERVICE_UID,
        STATE_SERVICE_GID, STATE_LISTENER_UID, STATE_LISTENER_GID)


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "activation execution reserver launch")
    for field, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH), ("journalDirectoryPath", JOURNAL_PATH)):
        shape._literal(value[field], expected)
    for field, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD),
            ("bootstrapFd", BOOTSTRAP_FD), ("listenerFd", LISTENER_FD), ("custodyFd", CUSTODY_FD),
            ("bundleKeyFd", BUNDLE_KEY_FD), ("deliveryKeyFd", DELIVERY_KEY_FD), ("signingKeyFd", KEY_FD),
            ("journalDirectoryFd", JOURNAL_FD)):
        shape._integer(value[field], 2**32 - 2, minimum=1)
        if value[field] != expected:
            _fail("activation reserver fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "activation reserver descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work, "activation reserver exact descriptor inventory")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for field in ("listenerSocketDevice", "listenerPathDevice", "journalDirectoryDevice"):
        shape._integer(value[field], 2**64 - 1)
    for field in ("listenerSocketInode", "listenerPathInode", "journalDirectoryInode"):
        shape._integer(value[field], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], authorization.MAX_RECORDS, minimum=2)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "activation execution reserver payload")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("operation", OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(payload[field], expected)
    shape.validate_identity_shape(payload["receiverIdentity"])
    for field in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "computationSpkiDigest", "computationMeasurementDigest"):
        shape._digest(payload[field])
    authorization._token(payload["databaseId"])
    custody = payload["receivingCustody"]
    shape._object(custody, _CUSTODY_FIELDS, "activation external receiving original")
    shape._integer(custody["byteCount"], MAX_CUSTODY_BYTES, minimum=2)
    shape._digest(custody["bytesDigest"])
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "activation reserver enrollment original")
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._integer(record["byteCount"], maximum, minimum=2)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    predecessor, checkpoint = payload["statePredecessor"], payload["reservationCheckpoint"]
    shape._object(predecessor, frozenset({"sequence", "headDigest", "nextFence"}),
        "independent activation state predecessor")
    shape._object(checkpoint, frozenset({"sequence", "headDigest"}),
        "independent activation reservation checkpoint")
    for selected in (predecessor, checkpoint):
        shape._integer(selected["sequence"], authorization.MAX_RECORDS)
        shape._digest(selected["headDigest"])
    shape._integer(predecessor["nextFence"], minimum=1)
    if predecessor["sequence"] == 0 and predecessor["nextFence"] != 1:
        _fail("activation reservation genesis predecessor requires fence one")
    _state_endpoint(payload["stateEndpoint"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[field], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        _fail("activation reserver lifetime exceeds its original launch ceiling")
    if any(payload[field] is not False for field in _FALSE_FIELDS):
        _fail("activation reserver claims unsupported hardware or witness assurance")
    _launch_shape(payload["launch"], work)


def _fresh(interval, work, opening=None):
    return planner_bootstrap._fresh(interval, work, opening=opening)


def _digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())


def _originals(payload, work, current):
    originals = []
    for name, maximum in _ORIGINAL_LIMITS:
        current()
        record = payload[name]
        raw = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
        plan._same(_digest(raw, work), record["bytesDigest"], work, "activation enrollment original digest")
        current()
        originals.append(raw)
    return tuple(originals)


def _key_scope(configured, root_spki, planner_spki, caller_spki, grant_spki, computation_spki, work):
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "activation configured roles")
    forbidden = [root_spki, planner_spki, caller_spki, grant_spki]
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        for field in ("serviceUid", "serviceGid"):
            shape._integer(role[field], 2**32 - 2)
            if role[field] == SERVICE_UID:
                _fail("activation reserver identity is shared with a configured role")
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            forbidden.append(role["signingSpkiDigest"])
    for policy_module, slots in ((planner_bootstrap.evidence_policy, ("registration", "installation")),
            (planner_bootstrap.transition_policy, ("registration", "stage", "completion"))):
        value = configured.get(policy_module.FIELD)
        if value is not None:
            policy, _public_keys = policy_module._validate_policy_on_work(value,
                webauthn=configured["webauthn"], work=work)
            forbidden.extend(policy[name]["signingSpkiDigest"] for name in slots if policy[name] is not None)
    value = configured.get(planner_bootstrap.enrollment_policy.FIELD)
    if value is not None:
        policy, _public_key = planner_bootstrap.enrollment_policy._validate_policy_on_work(
            value, payload=configured, work=work)
        forbidden.append(policy["signingSpkiDigest"])
    work.prepare_scan(forbidden)
    for pin in forbidden:
        shape._digest(pin)
        work.prepare_comparison(computation_spki, pin)
        if computation_spki == pin:
            _fail("activation computation key is shared with another configured purpose")


def _admit_payload(payload, custody_bytes, root, window, deadline, work, current):
    record = payload["receivingCustody"]
    if len(custody_bytes) != record["byteCount"]:
        _fail("activation receiving original byte count differs from the role launch")
    if len(custody_bytes) + sum(payload[name]["byteCount"] for name, _ in _ORIGINAL_LIMITS) + MAX_BYTES > authority.MAX_RESULT_BYTES:
        _fail("activation reserver original inventory exceeds its aggregate ceiling")
    current()
    plan._same(_digest(custody_bytes, work), record["bytesDigest"], work, "activation receiving original digest")
    custody = receiving._verify_on_work(custody_bytes=custody_bytes, root_public_key=root,
        expected_consumer_role="reserve", work=work, live_window=window, transport_deadline_ns=deadline)
    current()
    admitted = custody.planner
    for actual, expected in ((payload["receiverIdentity"], custody.receiver_identity),
            (payload["configurationDigest"], admitted.configuration_digest),
            (payload["generationDigest"], admitted.generation["digest"]),
            (payload["runtimeClosureDigest"], admitted.runtime_closure_digest)):
        plan._same(actual, expected, work, "activation reserver differs from genuine receiving scope")
    if not custody.attestation_interval[0] <= payload["issuedAtEpochNs"] < payload["expiresAtEpochNs"] <= custody.attestation_interval[1]:
        _fail("activation reserver interval escapes its original receiving interval")

    def live():
        current()
        _fresh(custody.attestation_interval, work, opening=custody.opening_sample)
        _fresh(admitted.attestation_interval, work, opening=admitted.opening_sample)
        return current()

    live()
    current_raw, grant_raw, caller_raw = _originals(payload, work, live)
    work.charge(input_bytes=len(current_raw) + len(admitted.state_enrollment_bytes))
    if current_raw != admitted.state_enrollment_bytes:
        _fail("activation reserver state enrollment differs from its original planner scope")
    enrolled = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=admitted.configuration_digest,
        planner_public_key=admitted.planner_public_key, operation_public_key=root, work=work)
    live()
    current_material = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
        root_public_key=root, work=work)
    live()
    grant = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root, work=work)
    live()
    policy, caller_policy = current_material.payload, enrolled.payload
    computation = policy["computation"]
    for actual, expected in ((payload["currentRootEnrollment"]["identityDigest"], admitted.state_enrollment_digest),
            (payload["currentRootEnrollment"]["identityDigest"], current_material.enrollment_digest),
            (payload["currentRootEnrollment"]["identityDigest"], caller_policy["currentRootEnrollmentDigest"]),
            (payload["grantEnrollment"]["identityDigest"], grant.enrollment_digest),
            (payload["authorizationEnrollment"]["identityDigest"], enrolled.enrollment_digest),
            (payload["databaseId"], caller_policy["databaseId"]),
            (payload["generationDigest"], caller_policy["generationDigest"]),
            (payload["computationSpkiDigest"], computation["spkiDigest"]),
            (payload["computationMeasurementDigest"], computation["measurementDigest"]),
            (payload["receiverIdentity"]["measurementDigest"], computation["measurementDigest"]),
            (payload["launch"]["journalMaximumRecords"], policy["maxRecords"])):
        plan._same(actual, expected, work, "activation reserver differs from genuine purpose enrollment")
    # Genuine current-root enrollment separates computation from state and
    # completion. Also exclude the actual root, caller, grant and other purposes.
    _key_scope(admitted.configuration_payload, keys._spki_on_work(root, work), admitted.planner_spki_digest,
        caller_policy["callerKey"]["spkiDigest"], grant.payload["authorizer"]["spkiDigest"],
        computation["spkiDigest"], work)
    predecessor, checkpoint = payload["statePredecessor"], payload["reservationCheckpoint"]
    for selected in (predecessor, checkpoint):
        if selected["sequence"] > policy["maxRecords"]:
            _fail("activation independent checkpoint exceeds enrolled capacity")
        if selected["sequence"] == 0:
            plan._same(selected["headDigest"], current_material.enrollment_digest, work,
                "activation independent genesis head differs")
    live()
    return custody, current_raw, grant_raw, caller_raw, enrolled, current_material, live


def _verify_on_work(*, bootstrap_bytes, custody_bytes, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Authenticate originals before selecting keys, journal, listener or peer."""
    try:
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "activation reserver bootstrap")
        custody_original = authorization._original(custody_bytes, MAX_CUSTODY_BYTES, "activation receiving custody")
        root = root_public_key
        authorization._public(root)
        window = None if live_window is None else clock._validate(live_window)
        deadline = transport_deadline_ns
        inherited = planner_bootstrap._processing(window, deadline, work)
        inherited()
        envelope = codec._decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed activation reserver bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("activation reserver payload is not an exact object")
        codec._canonical(original, envelope, work)
        payload = envelope["payload"]
        unsigned = configuration._configuration_wire(payload, capture._SharedLedger(work))
        inherited()
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned, capture._SharedLedger(work))
        inherited()
        codec._canonical(original, envelope, work)
        _payload_shape(payload, work)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        custody, current_raw, grant_raw, caller_raw, enrolled, current_material, live = _admit_payload(
            payload, custody_original, root, window, deadline, work, current)
        admitted = custody.planner
        predecessor, checkpoint = payload["statePredecessor"], payload["reservationCheckpoint"]
        material = _ReserverMaterial(original, custody_original, custody, payload["receiverIdentity"],
            admitted.configuration_payload, admitted.generation, admitted.runtime_role_identities,
            admitted.configuration_digest, admitted.runtime_closure_digest, current_raw, grant_raw, caller_raw,
            admitted.planner_public_key, root, current_material.computation_public_key,
            payload["computationSpkiDigest"], payload["computationMeasurementDigest"], payload["databaseId"],
            payload["generationDigest"], current_material.enrollment_digest, enrolled.payload["maximumAgeNs"],
            enrolled.payload["maximumClockSkewNs"],
            (predecessor["sequence"], predecessor["headDigest"], predecessor["nextFence"]),
            (checkpoint["sequence"], checkpoint["headDigest"]), _state_endpoint(payload["stateEndpoint"]),
            interval, opening, payload["launch"])
        codec._canonical(original, envelope, work)
        live()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationExecutionReserverBootstrapError):
            raise
        raise OidcSessionActivationExecutionReserverBootstrapError("activation reserver bootstrap admission failed") from exc


def _produce_on_work(*, payload, custody_bytes, root_private_key, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Sign independently established original launch claims, never create them."""
    try:
        custody_original = authorization._original(custody_bytes, MAX_CUSTODY_BYTES, "activation receiving custody")
        private, root = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(root)
        owned = configuration._ConfigurationCapture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(payload)
        window = None if live_window is None else clock._validate(live_window)
        deadline = transport_deadline_ns
        inherited = planner_bootstrap._processing(window, deadline, work)
        inherited()
        _payload_shape(owned, work)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        *_facts, live = _admit_payload(owned, custody_original, root, window, deadline, work, current)
        unsigned = configuration._configuration_wire(owned, capture._SharedLedger(work))
        live()
        original = signing._sign(owned, SCHEMA, MAX_BYTES, private, root, work)
        codec._canonical(unsigned, owned, work)
        live()
        return original
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationExecutionReserverBootstrapError):
            raise
        raise OidcSessionActivationExecutionReserverBootstrapError("activation reserver bootstrap production failed") from exc
