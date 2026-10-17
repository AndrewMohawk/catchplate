"""Independent root-original launch for the consume-only reservation purpose.

The four detached originals, enrolled computation key, independent state
predecessor and separate local journal checkpoint are genuinely admitted.
These host-local root assertions do not provision a cold process or make a
static predecessor current. No incoming material or sampled head is authority.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from catchplate import oidc_session_activation_delivery_execution_authorizer_bootstrap as primitives
from catchplate import oidc_session_activation_delivery_execution_custody_bootstrap as receiving


authority, configuration, codec, signing = (
    primitives.authority, primitives.configuration, primitives.codec, primitives.signing)
capability, capture, plan, keys = primitives.capability, primitives.capture, primitives.plan, primitives.keys
authorization, caller, grants = primitives.authorization, primitives.caller, primitives.grants
shape, clock, production, shared = primitives.shape, primitives.clock, primitives.production, primitives.shared
ROLE = PROCESS_MODE = receiving.RESERVE_PROCESS_MODE
OPERATION = caller.OPERATION
SERVICE_UID = SERVICE_GID = 65499
PEER_UID = PEER_GID = 65532
STATE_SERVICE_UID = STATE_SERVICE_GID = 65516
STATE_LISTENER_UID = STATE_LISTENER_GID = 0
(ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD, PLANNER_BOOTSTRAP_FD,
    PLANNER_HISTORY_CUSTODY_FD, RECEIVING_HISTORY_CUSTODY_FD, EXECUTION_BUNDLE_KEY_FD,
    HISTORICAL_BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD, JOURNAL_FD) = range(198, 210)
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD,
    PLANNER_BOOTSTRAP_FD, PLANNER_HISTORY_CUSTODY_FD, RECEIVING_HISTORY_CUSTODY_FD,
    EXECUTION_BUNDLE_KEY_FD, HISTORICAL_BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD, JOURNAL_FD)
LISTENER_PATH = "/run/catchplate/oidc-session-activation-delivery-execution/reserver.sock"
LISTENER_NAME = "catchplate-oidc-session-activation-delivery-execution-reserver"
JOURNAL_PATH = "/var/lib/catchplate/oidc-session-activation-delivery-execution-reservations"
STATE_SOCKET_PATH = "/run/catchplate/current-root/state.sock"
MAX_BYTES = MAX_ROLE_BYTES = 4 * 1024 * 1024
MAX_CUSTODY_BYTES = primitives.MAX_CUSTODY_BYTES
MAX_PLANNER_BOOTSTRAP_BYTES = primitives.MAX_PLANNER_BOOTSTRAP_BYTES
MAX_PLANNER_HISTORY_CUSTODY_BYTES = primitives.MAX_PLANNER_HISTORY_CUSTODY_BYTES
MAX_RECEIVING_HISTORY_CUSTODY_BYTES = primitives.MAX_RECEIVING_HISTORY_CUSTODY_BYTES
MAX_RECEIPT_AGE_NS = primitives.MAX_RECEIPT_AGE_NS
SCHEMA = "catchplate.signedOidcSessionActivationDeliveryExecutionReserverBootstrap/v1"
PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationDeliveryExecutionReserverBootstrap/v1"
LAUNCH_SCHEMA = "catchplate.oidcSessionActivationDeliveryExecutionReserverLaunch/v1"
_FALSE_FIELDS = receiving._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_DETACHED_FIELDS = primitives._DETACHED_FIELDS
_DETACHED_LIMITS = primitives._DETACHED_LIMITS
_ORIGINAL_FIELDS = primitives._ORIGINAL_FIELDS
_ORIGINAL_LIMITS = primitives._ORIGINAL_LIMITS
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "operation",
    "receivingCustody", "plannerBootstrap", "plannerHistoryCustody", "receivingHistoryCustody",
    "receiverIdentity", "configurationDigest", "generationDigest", "runtimeClosureDigest", "databaseId",
    "currentRootEnrollment", "grantEnrollment", "authorizationEnrollment", "computationSpkiDigest",
    "computationMeasurementDigest", "statePredecessor", "reservationCheckpoint", "stateEndpoint",
    "issuedAtEpochNs", "expiresAtEpochNs", "trustMode", "launch", *_FALSE_FIELDS})
_FD_FIELDS = (("rootPublicKeyFd", ROOT_FD), ("bootstrapFd", BOOTSTRAP_FD),
    ("listenerFd", LISTENER_FD), ("custodyFd", CUSTODY_FD),
    ("plannerBootstrapFd", PLANNER_BOOTSTRAP_FD),
    ("plannerHistoryCustodyFd", PLANNER_HISTORY_CUSTODY_FD),
    ("receivingHistoryCustodyFd", RECEIVING_HISTORY_CUSTODY_FD),
    ("executionBundleKeyFd", EXECUTION_BUNDLE_KEY_FD),
    ("historicalBundleKeyFd", HISTORICAL_BUNDLE_KEY_FD),
    ("deliveryKeyFd", DELIVERY_KEY_FD), ("signingKeyFd", KEY_FD), ("journalDirectoryFd", JOURNAL_FD))
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
    *(name for name, _ in _FD_FIELDS), "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode",
    "journalDirectoryPath", "journalDirectoryDevice", "journalDirectoryInode", "journalMaximumRecords"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "serviceUid", "serviceGid",
    "listenerUid", "listenerGid"})
# These fixed helpers capture bytes or check a current allowance only. No
# authorizer role verifier, grant key admission or successful material is reused.
_construction_on_work = primitives._construction_on_work
_processing = primitives._processing
_fresh = primitives._fresh
_digest = primitives._digest
_detached = primitives._detached
_originals = primitives._originals


class OidcSessionActivationDeliveryExecutionReserverBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReserverMaterial:
    """Owned same-call facts; no verifier accepts this in place of originals."""

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
    planner_bootstrap_bytes: bytes
    planner_history_custody_bytes: bytes
    receiving_history_custody_bytes: bytes


def _fail(message):
    raise OidcSessionActivationDeliveryExecutionReserverBootstrapError(message)


def _state_endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "consume reservation state endpoint")
    shape._literal(value["socketPath"], STATE_SOCKET_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for field, expected in (("serviceUid", STATE_SERVICE_UID), ("serviceGid", STATE_SERVICE_GID),
            ("listenerUid", STATE_LISTENER_UID), ("listenerGid", STATE_LISTENER_GID)):
        shape._integer(value[field], 2**32 - 2)
        if value[field] != expected:
            _fail("consume reservation state endpoint identity is not fixed")
    return (value["socketPath"], value["requestTimeoutSeconds"], STATE_SERVICE_UID,
        STATE_SERVICE_GID, STATE_LISTENER_UID, STATE_LISTENER_GID)


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "consume reserver launch")
    for field, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH), ("journalDirectoryPath", JOURNAL_PATH)):
        shape._literal(value[field], expected)
    for field, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), *_FD_FIELDS):
        shape._integer(value[field], 2**32 - 2, minimum=1)
        if value[field] != expected:
            _fail("consume reserver fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "consume reserver descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work, "consume reserver descriptor inventory")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for field in ("listenerSocketDevice", "listenerPathDevice", "journalDirectoryDevice"):
        shape._integer(value[field], 2**64 - 1)
    for field in ("listenerSocketInode", "listenerPathInode", "journalDirectoryInode"):
        shape._integer(value[field], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], authorization.MAX_RECORDS, minimum=2)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "consume reserver payload")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("operation", OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(payload[field], expected)
    shape.validate_identity_shape(payload["receiverIdentity"])
    for field in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "computationSpkiDigest", "computationMeasurementDigest"):
        shape._digest(payload[field])
    authorization._token(payload["databaseId"])
    for name, maximum in _DETACHED_LIMITS:
        record = payload[name]
        shape._object(record, _DETACHED_FIELDS, "consume reserver detached original")
        shape._integer(record["byteCount"], maximum, minimum=2)
        shape._digest(record["bytesDigest"])
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "consume reserver enrollment original")
        shape._integer(record["byteCount"], maximum, minimum=2)
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    predecessor, checkpoint = payload["statePredecessor"], payload["reservationCheckpoint"]
    shape._object(predecessor, frozenset({"sequence", "headDigest", "nextFence"}),
        "independent consume state predecessor")
    shape._object(checkpoint, frozenset({"sequence", "headDigest"}),
        "independent consume local reservation checkpoint")
    for selected in (predecessor, checkpoint):
        shape._integer(selected["sequence"], authorization.MAX_RECORDS)
        shape._digest(selected["headDigest"])
    shape._integer(predecessor["nextFence"], minimum=1)
    if predecessor["sequence"] == 0 and predecessor["nextFence"] != 1:
        _fail("consume genesis predecessor requires fence one")
    _state_endpoint(payload["stateEndpoint"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[field], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        _fail("consume reserver interval exceeds its fixed launch ceiling")
    if any(payload[field] is not False for field in _FALSE_FIELDS):
        _fail("consume reserver claims unsupported hardware or witness assurance")
    _launch_shape(payload["launch"], work)


def _key_scope(configured, forbidden, computation_spki, work):
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "consume configured roles")
    forbidden = list(forbidden)
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        for field in ("serviceUid", "serviceGid"):
            shape._integer(role[field], 2**32 - 2)
            if role[field] == SERVICE_UID:
                _fail("consume reserver identity is shared with a configured role")
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            forbidden.append(role["signingSpkiDigest"])
    for policy_module, slots in ((shared.evidence_policy, ("registration", "installation")),
            (shared.transition_policy, ("registration", "stage", "completion"))):
        value = configured.get(policy_module.FIELD)
        if value is not None:
            policy, _public_keys = policy_module._validate_policy_on_work(value,
                webauthn=configured["webauthn"], work=work)
            forbidden.extend(policy[name]["signingSpkiDigest"] for name in slots if policy[name] is not None)
    value = configured.get(shared.enrollment_policy.FIELD)
    if value is not None:
        policy, _public_key = shared.enrollment_policy._validate_policy_on_work(value, payload=configured, work=work)
        forbidden.append(policy["signingSpkiDigest"])
    work.prepare_scan(forbidden)
    for pin in forbidden:
        shape._digest(pin)
        work.prepare_comparison(computation_spki, pin)
        if computation_spki == pin:
            _fail("consume computation key is shared with another admitted purpose")


def _admit_payload(payload, originals, root, window, bound, work, current):
    if MAX_BYTES + sum(len(raw) for raw in originals) + sum(
            payload[name]["byteCount"] for name, _ in _ORIGINAL_LIMITS) > authority.MAX_RESULT_BYTES:
        _fail("consume reserver original inventory exceeds its aggregate ceiling")
    for (name, _maximum), original in zip(_DETACHED_LIMITS, originals):
        current()
        record = payload[name]
        if len(original) != record["byteCount"]:
            _fail("consume reserver detached original byte count differs")
        plan._same(_digest(original, work), record["bytesDigest"], work, "consume reserver detached original digest")
        current()
    custody_raw, planner_raw, planning_raw, receiving_raw = originals
    custody = receiving._verify_reserve_on_work(custody_bytes=custody_raw, planner_bootstrap_bytes=planner_raw,
        planner_history_custody_bytes=planning_raw, receiving_history_custody_bytes=receiving_raw,
        root_public_key=root, work=work, live_window=window, transport_deadline_ns=bound)
    current()
    for field, expected in (("consumerRole", receiving.RESERVE_CONSUMER_ROLE),
            ("processMode", PROCESS_MODE), ("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID)):
        plan._same(custody.payload[field], expected, work, "consume reserver receiving purpose differs")
    admitted, configured = custody.planner, custody.planner.payload
    live = current
    for material in (custody, admitted, admitted.history_material, custody.history):
        if not material.attestation_interval[0] <= payload["issuedAtEpochNs"] < payload["expiresAtEpochNs"] <= material.attestation_interval[1]:
            _fail("consume reserver interval escapes an original current nested launch")
        live = shared._launch_guard(material.attestation_interval, material.opening_sample, live, work)
    live()
    for actual, expected in ((payload["receiverIdentity"], custody.receiver_identity),
            (payload["configurationDigest"], configured["configurationDigest"]),
            (payload["generationDigest"], configured["generation"]["digest"]),
            (payload["runtimeClosureDigest"], configured["runtimeClosureDigest"]),
            (payload["databaseId"], configured["databaseId"])):
        plan._same(actual, expected, work, "consume reserver differs from genuine receiving scope")
    current_raw, grant_raw, caller_raw = _originals(payload, work, live)
    work.charge(input_bytes=len(current_raw) + len(admitted.state_enrollment_bytes))
    if current_raw != admitted.state_enrollment_bytes:
        _fail("consume reserver state enrollment differs from its original planner scope")
    enrolled = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=payload["configurationDigest"],
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
        plan._same(actual, expected, work, "consume reserver differs from genuine purpose enrollment")
    # Genuine current-root admission separates computation, completion and
    # state keys. Also exclude root, both planners, caller, grant and config keys.
    forbidden = (keys._spki_on_work(root, work), keys._spki_on_work(admitted.planner_public_key, work),
        keys._spki_on_work(custody.history.historical_root_public_key, work),
        custody.history.planner.planner_spki_digest, caller_policy["callerKey"]["spkiDigest"],
        grant.payload["authorizer"]["spkiDigest"])
    _key_scope(configured["configurationPayload"], forbidden, computation["spkiDigest"], work)
    for selected in (payload["statePredecessor"], payload["reservationCheckpoint"]):
        if selected["sequence"] > policy["maxRecords"]:
            _fail("consume independent checkpoint exceeds enrolled capacity")
        if selected["sequence"] == 0:
            plan._same(selected["headDigest"], current_material.enrollment_digest, work,
                "consume independent genesis head differs")
    live()
    return custody, current_raw, grant_raw, caller_raw, enrolled, current_material, live


def _verify_on_work(*, bootstrap_bytes, custody_bytes, planner_bootstrap_bytes,
        planner_history_custody_bytes, receiving_history_custody_bytes, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Admit genuine reserve originals before selecting private resources."""
    try:
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "consume reserver bootstrap")
        originals = _detached(custody_bytes, planner_bootstrap_bytes,
            planner_history_custody_bytes, receiving_history_custody_bytes)
        receiving._intake_reservation((16 * 1024, len(original), *map(len, originals)))
        root = root_public_key
        authorization._public(root)
        window, bound, inherited = _processing(live_window, transport_deadline_ns, work)
        inherited()
        envelope = codec._decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed consume reserver bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("consume reserver payload is not an exact object")
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
        current = shared._launch_guard(interval, opening, inherited, work)
        custody, current_raw, grant_raw, caller_raw, enrolled, current_material, live = _admit_payload(
            payload, originals, root, window, bound, work, current)
        admitted, configured = custody.planner, custody.planner.payload
        predecessor, checkpoint = payload["statePredecessor"], payload["reservationCheckpoint"]
        material = _ReserverMaterial(bootstrap_bytes=original, custody_bytes=originals[0],
            custody_material=custody, receiver_identity=payload["receiverIdentity"],
            configuration_payload=configured["configurationPayload"], generation=configured["generation"],
            runtime_role_identities=configured["runtimeRoleIdentities"],
            configuration_digest=payload["configurationDigest"], runtime_closure_digest=payload["runtimeClosureDigest"],
            current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
            authorization_enrollment_bytes=caller_raw, planner_public_key=admitted.planner_public_key,
            operation_public_key=root, computation_public_key=current_material.computation_public_key,
            computation_spki_digest=payload["computationSpkiDigest"],
            computation_measurement_digest=payload["computationMeasurementDigest"], database_id=payload["databaseId"],
            generation_digest=payload["generationDigest"], enrollment_digest=current_material.enrollment_digest,
            maximum_authorization_age_ns=enrolled.payload["maximumAgeNs"],
            maximum_authorization_clock_skew_ns=enrolled.payload["maximumClockSkewNs"],
            state_predecessor=(predecessor["sequence"], predecessor["headDigest"], predecessor["nextFence"]),
            reservation_checkpoint=(checkpoint["sequence"], checkpoint["headDigest"]),
            state_endpoint=_state_endpoint(payload["stateEndpoint"]), attestation_interval=interval,
            opening_sample=opening, launch=payload["launch"], planner_bootstrap_bytes=originals[1],
            planner_history_custody_bytes=originals[2], receiving_history_custody_bytes=originals[3])
        codec._canonical(original, envelope, work)
        live()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationDeliveryExecutionReserverBootstrapError):
            raise
        raise OidcSessionActivationDeliveryExecutionReserverBootstrapError("consume reserver bootstrap admission failed") from exc


def _produce_on_work(*, payload, custody_bytes, planner_bootstrap_bytes, planner_history_custody_bytes,
        receiving_history_custody_bytes, root_private_key, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Sign an independently established reserve launch after real admission."""
    try:
        originals = _detached(custody_bytes, planner_bootstrap_bytes,
            planner_history_custody_bytes, receiving_history_custody_bytes)
        private, root = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(root)
        owned = configuration._ConfigurationCapture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(payload)
        window, bound, inherited = _processing(live_window, transport_deadline_ns, work)
        inherited()
        _payload_shape(owned, work)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = shared._launch_guard(interval, opening, inherited, work)
        *_facts, live = _admit_payload(owned, originals, root, window, bound, work, current)
        unsigned = configuration._configuration_wire(owned, capture._SharedLedger(work))
        live()
        original = signing._sign(owned, SCHEMA, MAX_BYTES, private, root, work)
        codec._canonical(unsigned, owned, work)
        live()
        checked = codec._decode(original, work)
        shape._object(checked, _ENVELOPE_FIELDS, "signed consume reserver output")
        shape._literal(checked["schema"], SCHEMA)
        shape._base64url(checked["signatureBase64Url"], signature=True)
        _payload_shape(checked["payload"], work)
        plan._same(checked["payload"], owned, work, "consume reserver output payload changed")
        codec._canonical(original, checked, work)
        live()
        return original
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationDeliveryExecutionReserverBootstrapError):
            raise
        raise OidcSessionActivationDeliveryExecutionReserverBootstrapError("consume reserver bootstrap production failed") from exc
