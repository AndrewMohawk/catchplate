"""Root-original cold launch for dedicated consume completion and recovery.

Fresh role/custody originals authorize current processing. The old consume
planner and planning-history originals remain history. No resource, key,
database, completion or release is created by this verifier.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import authority_oidc_session_activation_delivery_execution_authorization as caller
from serverware import authority_oidc_session_activation_delivery_execution_enrollment as grants
from serverware import authority_oidc_session_activation_delivery_execution_history as history
from serverware import authority_successor_execution_window as processing_window
from serverware import oidc_session_activation_completion_bootstrap as grammar
from serverware import oidc_session_activation_delivery_completion_custody_bootstrap as receiving


primitives = receiving.shared
planner_bootstrap = receiving.planner_bootstrap
authority, configuration = primitives.authority, primitives.configuration
codec, capability, capture, plan = primitives.codec, primitives.capability, primitives.capture, primitives.plan
authorization, shape, clock = caller.authorization, caller.shape, caller.clock
production = configuration.production
expectations_wire = caller.expectations_wire
ROLE = PROCESS_MODE = receiving.PROCESS_MODE
OPERATION = caller.OPERATION
SERVICE_UID = SERVICE_GID = PEER_UID = PEER_GID = 65497
DISPATCH_PEER_UID = DISPATCH_PEER_GID = 65532
STATE_SERVICE_UID = STATE_SERVICE_GID = 65516
STATE_LISTENER_UID = STATE_LISTENER_GID = 0
(ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD,
    EXECUTION_BUNDLE_KEY_FD, HISTORICAL_BUNDLE_KEY_FD, DELIVERY_KEY_FD) = range(198, 206)
INHERITED_DESCRIPTORS = tuple(range(198, 206))
LISTENER_PATH = "/run/serverware/oidc-session-activation-delivery-execution/completion.sock"
LISTENER_NAME = "serverware-oidc-session-activation-delivery-completion"
JOURNAL_PATH = "/var/lib/serverware/oidc-session-activation-delivery-completions"
STATE_SOCKET_PATH = "/run/serverware/current-root/state.sock"
TLS_PATHS = {
    "ca": "/run/serverware/oidc-session-activation-delivery-completion-tls/ca.pem",
    "custodyCertificate": "/run/serverware/oidc-session-activation-delivery-completion-tls/custody.crt",
    "custodyKey": "/run/serverware/oidc-session-activation-delivery-completion-tls/custody.key",
    "commitCertificate": "/run/serverware/oidc-session-activation-delivery-completion-tls/commit.crt",
    "commitKey": "/run/serverware/oidc-session-activation-delivery-completion-tls/commit.key",
}
TLS_LIMITS = {name: (16 * 1024 if name in ("custodyKey", "commitKey") else 64 * 1024)
    for name in TLS_PATHS}
MIN_TLS_BYTES = 2
MAX_BYTES = MAX_BOOTSTRAP_BYTES = 32 * 1024 * 1024
MAX_ORIGINAL_BYTES = authority.MAX_RESULT_BYTES
MAX_NODES, MAX_DEPTH = expectations_wire.MAX_NODES + 8192, 16
MAX_RECEIPT_AGE_NS = primitives.MAX_RECEIPT_AGE_NS
SCHEMA = "serverware.signedOidcSessionActivationDeliveryCompletionBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationDeliveryCompletionBootstrap/v1"
LAUNCH_SCHEMA = "serverware.oidcSessionActivationDeliveryCompletionLaunch/v1"
DISPATCH_LAUNCH_SCHEMA = "serverware.oidcSessionActivationDeliveryCompletionLaunch/v2"
_FALSE_FIELDS = receiving._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_CUSTODY_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest"})
_ORIGINAL_FIELDS = _CUSTODY_FIELDS | frozenset({"identityDigest"})
_CUSTODY_LIMITS = (("receivingCustody", receiving.MAX_BYTES),
    ("plannerBootstrap", planner_bootstrap.MAX_BYTES),
    ("plannerHistoryCustody", receiving.history_bootstrap.MAX_BYTES),
    ("receivingHistoryCustody", receiving.history_bootstrap.MAX_BYTES))
_ORIGINAL_LIMITS = (("currentRootEnrollment", authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES),
    ("authorization", caller.MAX_AUTHORIZATION_BYTES))
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "operation",
    *(name for name, _ in _CUSTODY_LIMITS), "receiverIdentity", "configurationDigest",
    "generationDigest", "runtimeClosureDigest", "databaseId", "currentRootEnrollment",
    "grantEnrollment", "authorizationEnrollment", "authorization", "completionSpkiDigest",
    "completionMeasurementDigest", "currentPending", "completionCheckpoint", "stateEndpoint",
    "packetDigest", "authorizationDigest", "replayExpectations", "databaseEndpoint", "sqlRoles",
    "queryManifestDigest", "structureManifestDigest", "tlsFiles", "issuedAtEpochNs",
    "expiresAtEpochNs", "trustMode", "launch", *_FALSE_FIELDS})
_FD_FIELDS = (("rootPublicKeyFd", ROOT_FD), ("bootstrapFd", BOOTSTRAP_FD),
    ("listenerFd", LISTENER_FD), ("signingKeyFd", KEY_FD), ("journalDirectoryFd", JOURNAL_FD),
    ("executionBundleKeyFd", EXECUTION_BUNDLE_KEY_FD),
    ("historicalBundleKeyFd", HISTORICAL_BUNDLE_KEY_FD), ("deliveryKeyFd", DELIVERY_KEY_FD))
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
    *(name for name, _ in _FD_FIELDS), "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode",
    "journalDirectoryPath", "journalDirectoryDevice", "journalDirectoryInode", "journalMaximumRecords"})


class DeliveryCompletionBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CompletionMaterial:
    bootstrap_bytes: bytes
    custody_bytes: bytes
    planner_bootstrap_bytes: bytes
    planner_history_custody_bytes: bytes
    receiving_history_custody_bytes: bytes
    custody_material: receiving._CustodyMaterial
    receiver_identity: dict
    configuration_payload: dict
    generation: dict
    runtime_role_identities: dict
    configuration_digest: str
    runtime_closure_digest: str
    authorization_bytes: bytes
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    planner_public_key: object
    operation_public_key: object
    completion_public_key: object
    completion_spki_digest: str
    completion_measurement_digest: str
    database_id: str
    generation_digest: str
    enrollment_digest: str
    maximum_authorization_age_ns: int
    maximum_authorization_clock_skew_ns: int
    current_pending: tuple
    completion_checkpoint: tuple
    state_endpoint: tuple
    packet_digest: str
    authorization_digest: str
    expectations: dict
    custody_configuration: tuple
    commit_configuration: tuple
    tls_files: dict
    attestation_interval: tuple
    opening_sample: tuple
    launch: dict


def _fail(message):
    raise DeliveryCompletionBootstrapError(message)


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("consume completion bootstrap exceeds its fixed shape bound")
        return super().visit(value, depth, ancestors)


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(raw, value, work):
    return capability._canonical(raw, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _decode(raw, work):
    return _capture(capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH), work)


def _construction_on_work(work):
    capture._SharedLedger(work)
    before, epoch, after = clock._sample_on_work(work)
    age, skew = authority.VERIFIER_RESPONSE_MAX_AGE_NS, authority.VERIFIER_MAX_CLOCK_SKEW_NS
    window = clock._validate((epoch, before, after, epoch + age, before + age, age, skew))
    return window, window[4]


def _processing(live_window, transport_deadline_ns, work):
    window = _construction_on_work(work)[0] if live_window is None else clock._validate(live_window)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    bound = window[4] if transport_deadline_ns is None else min(window[4], transport_deadline_ns)
    return window, bound, primitives._processing(window, bound, work)


def _fresh(interval, work, opening=None):
    return receiving._fresh(interval, work, opening=opening)


def _database_configurations(payload, work):
    endpoint, roles = payload["databaseEndpoint"], payload["sqlRoles"]
    grammar._database_shape(endpoint)
    shape._object(roles, frozenset({"custody", "commit"}), "consume completion read roles")
    result = []
    for name, role in (("custody", authority.SUCCESSOR_RECOVERY_ROLE), ("commit", authority.COMPLETION_READER_ROLE)):
        selected = roles[name]
        shape._object(selected, grammar._SQL_ROLE_FIELDS, "consume completion read TLS identity")
        shape._integer(selected["connectTimeoutSeconds"], 300, minimum=2)
        for field in ("clientDn", "clientSerial", "issuerDn"):
            value = selected[field]
            if (type(value) is not str or not 1 <= len(value) <= 4096 or "\x00" in value
                    or work.prepare_utf8(value) > 4096):
                _fail("consume completion read TLS identity exceeds its bound")
        dsn = ("host=" + endpoint["host"] + " hostaddr=" + endpoint["hostaddr"]
            + " port=" + str(endpoint["port"]) + " dbname=" + endpoint["databaseName"]
            + " user=" + role + " sslmode=verify-full sslrootcert=" + TLS_PATHS["ca"]
            + " sslcert=" + TLS_PATHS[name + "Certificate"] + " sslkey=" + TLS_PATHS[name + "Key"]
            + " passfile=/dev/null gssencmode=disable")
        result.append((dsn, selected["connectTimeoutSeconds"], role, selected["clientDn"],
            selected["clientSerial"], selected["issuerDn"], payload["queryManifestDigest"],
            payload["structureManifestDigest"]))
    return tuple(result)


def _state_endpoint(value):
    shape._object(value, grammar._ENDPOINT_FIELDS, "consume completion state endpoint")
    shape._literal(value["socketPath"], STATE_SOCKET_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name, expected in (("serviceUid", STATE_SERVICE_UID), ("serviceGid", STATE_SERVICE_GID),
            ("listenerUid", STATE_LISTENER_UID), ("listenerGid", STATE_LISTENER_GID)):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != expected:
            _fail("consume completion state endpoint is not source fixed")
    return value["socketPath"], value["requestTimeoutSeconds"], STATE_LISTENER_UID, STATE_LISTENER_GID


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "consume completion launch")
    if type(value["schema"]) is not str or value["schema"] not in (LAUNCH_SCHEMA, DISPATCH_LAUNCH_SCHEMA):
        _fail("consume completion launch profile differs")
    peer = (PEER_UID, PEER_GID) if value["schema"] == LAUNCH_SCHEMA else (DISPATCH_PEER_UID, DISPATCH_PEER_GID)
    for name, expected in (("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH), ("journalDirectoryPath", JOURNAL_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", peer[0]), ("peerGid", peer[1]), *_FD_FIELDS):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            _fail("consume completion launch scalar differs")
    shape._array(value["inheritedFileDescriptors"], len(INHERITED_DESCRIPTORS), "consume completion descriptors")
    for descriptor in value["inheritedFileDescriptors"]:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(value["inheritedFileDescriptors"], list(INHERITED_DESCRIPTORS), work, "consume completion exact FDs")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerSocketDevice", "listenerPathDevice", "journalDirectoryDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("listenerSocketInode", "listenerPathInode", "journalDirectoryInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], authorization.MAX_RECORDS, minimum=2)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "consume completion bootstrap payload")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("operation", OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    shape.validate_identity_shape(payload["receiverIdentity"])
    for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest", "completionSpkiDigest",
            "completionMeasurementDigest", "packetDigest", "authorizationDigest", "queryManifestDigest",
            "structureManifestDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    for inventory, fields in ((_CUSTODY_LIMITS, _CUSTODY_FIELDS), (_ORIGINAL_LIMITS, _ORIGINAL_FIELDS)):
        for name, maximum in inventory:
            record = payload[name]
            shape._object(record, fields, "consume completion authority original")
            authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
            shape._integer(record["byteCount"], maximum, minimum=2)
            shape._digest(record["bytesDigest"])
            if fields is _ORIGINAL_FIELDS:
                shape._digest(record["identityDigest"])
    if sum(payload[name]["byteCount"] for name, _ in (*_CUSTODY_LIMITS, *_ORIGINAL_LIMITS)) > MAX_ORIGINAL_BYTES:
        _fail("consume completion embedded originals exceed aggregate bound")
    expectations_wire._shape(payload["replayExpectations"])
    pending, checkpoint = payload["currentPending"], payload["completionCheckpoint"]
    shape._object(pending, frozenset({"sequence", "headDigest", "fence"}), "independent consume pending")
    shape._integer(pending["sequence"], authorization.MAX_RECORDS, minimum=1)
    shape._digest(pending["headDigest"])
    shape._integer(pending["fence"], minimum=1)
    shape._object(checkpoint, frozenset({"sequence", "headDigest"}), "consume completion checkpoint")
    shape._integer(checkpoint["sequence"], authorization.MAX_RECORDS)
    shape._digest(checkpoint["headDigest"])
    _state_endpoint(payload["stateEndpoint"])
    _database_configurations(payload, work)
    shape._object(payload["tlsFiles"], frozenset(TLS_PATHS), "consume completion TLS pins")
    for name, maximum in TLS_LIMITS.items():
        record = payload["tlsFiles"][name]
        shape._object(record, frozenset({"byteCount", "bytesDigest"}), "consume completion TLS original")
        shape._integer(record["byteCount"], maximum, minimum=MIN_TLS_BYTES)
        shape._digest(record["bytesDigest"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[name], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        _fail("consume completion launch exceeds fixed lifetime")
    if any(payload[name] is not False for name in _FALSE_FIELDS):
        _fail("consume completion claims unsupported hardware or witness assurance")
    _launch_shape(payload["launch"], work)


def _configured_keys(configured, caller_pin, completion_pin, work):
    roles, forbidden = configured["roles"], []
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "consume completion configured roles")
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        for field in ("serviceUid", "serviceGid"):
            shape._integer(role[field], 2**32 - 2)
            if role[field] == SERVICE_UID:
                _fail("consume completion shares a configured generic role")
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            forbidden.append(role["signingSpkiDigest"])
    for module, slots in ((primitives.evidence_policy, ("registration", "installation")),
            (primitives.transition_policy, ("registration", "stage", "completion"))):
        value = configured.get(module.FIELD)
        if value is not None:
            policy, _keys = module._validate_policy_on_work(value, webauthn=configured["webauthn"], work=work)
            forbidden.extend(policy[name]["signingSpkiDigest"] for name in slots if policy[name] is not None)
    value = configured.get(primitives.enrollment_policy.FIELD)
    if value is not None:
        policy, _key = primitives.enrollment_policy._validate_policy_on_work(value, payload=configured, work=work)
        forbidden.append(policy["signingSpkiDigest"])
    work.prepare_scan(forbidden)
    for pin in forbidden:
        shape._digest(pin)
        for actual in (caller_pin, completion_pin):
            work.prepare_comparison(actual, pin)
            if actual == pin:
                _fail("consume completion/caller key shares another configured purpose")


def _material(payload, original, root, window, bound, opening, work, current):
    raw4 = tuple(grammar._original(payload[name], maximum, work, current) for name, maximum in _CUSTODY_LIMITS)
    custody = receiving._verify_on_work(custody_bytes=raw4[0], planner_bootstrap_bytes=raw4[1],
        planner_history_custody_bytes=raw4[2], receiving_history_custody_bytes=raw4[3],
        root_public_key=root, live_window=window, transport_deadline_ns=bound, work=work)
    admitted, configured = custody.planner, custody.planner.payload
    for actual, expected in ((payload["receiverIdentity"], custody.receiver_identity),
            (payload["configurationDigest"], configured["configurationDigest"]),
            (payload["generationDigest"], configured["generation"]["digest"]),
            (payload["runtimeClosureDigest"], configured["runtimeClosureDigest"]),
            (payload["queryManifestDigest"], configured["configurationPayload"]["queryManifestDigest"])):
        plan._same(actual, expected, work, "consume completion genuine custody cohort")
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if not custody.attestation_interval[0] <= interval[0] < interval[1] <= custody.attestation_interval[1]:
        _fail("consume completion launch escapes its fresh custody interval")
    narrowed = processing_window._narrow(window, deadline_epoch_ns=interval[1],
        maximum_lifetime_ns=configured["maximumPlanAgeNs"], maximum_clock_skew_ns=configured["maximumClockSkewNs"])
    processing = primitives._processing(narrowed, min(bound, narrowed[4]), work)

    def live():
        first = current()
        _fresh(custody.attestation_interval, work, opening=custody.opening_sample)
        _fresh(custody.history.attestation_interval, work, opening=custody.history.opening_sample)
        now = processing()
        if not first <= now <= current():
            _fail("consume completion current processing reversed")
        return now

    live()
    current_raw, grant_raw, caller_raw, intent_raw = tuple(grammar._original(payload[name], maximum, work, live)
        for name, maximum in _ORIGINAL_LIMITS)
    if sum(map(len, (original, *raw4, current_raw, grant_raw, caller_raw, intent_raw))) > MAX_ORIGINAL_BYTES:
        _fail("consume completion original inventory exceeds aggregate bound")
    receiving._same_bytes(current_raw, admitted.state_enrollment_bytes, work,
        "consume completion state enrollment differs from original planner")
    enrolled = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw, root_public_key=root,
        configuration_digest=payload["configurationDigest"], planner_public_key=admitted.planner_public_key,
        operation_public_key=root, work=work)
    live()
    state = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw, root_public_key=root, work=work)
    grant = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root, work=work)
    live()
    policy, caller_policy = state.payload, enrolled.payload
    completion = policy["completion"]
    for actual, expected in ((payload["currentRootEnrollment"]["identityDigest"], state.enrollment_digest),
            (state.enrollment_digest, admitted.state_enrollment_digest),
            (payload["grantEnrollment"]["identityDigest"], grant.enrollment_digest),
            (payload["authorizationEnrollment"]["identityDigest"], enrolled.enrollment_digest),
            (payload["databaseId"], caller_policy["databaseId"]),
            (payload["generationDigest"], caller_policy["generationDigest"]),
            (payload["completionSpkiDigest"], completion["spkiDigest"]),
            (payload["completionMeasurementDigest"], completion["measurementDigest"]),
            (payload["receiverIdentity"]["measurementDigest"], completion["measurementDigest"]),
            (payload["launch"]["journalMaximumRecords"], policy["maxRecords"])):
        plan._same(actual, expected, work, "consume completion original enrollment binding")
    caller_pin = caller_policy["callerKey"]["spkiDigest"]
    _configured_keys(configured["configurationPayload"], caller_pin, completion["spkiDigest"], work)
    for pin in (caller.keys._spki_on_work(root, work), configured["planner"]["spkiDigest"],
            custody.history.planner.planner_spki_digest, caller_pin, grant.payload["authorizer"]["spkiDigest"],
            policy["computation"]["spkiDigest"], policy["state"]["spkiDigest"]):
        work.prepare_comparison(completion["spkiDigest"], pin)
        if completion["spkiDigest"] == pin:
            _fail("consume completion signer shares another admitted purpose")
    expected = expectations_wire._capture_on_work(payload["replayExpectations"], work=work)
    history._scope(expected, narrowed, work)
    plan._same(expected["request"], configured["consumeRequest"], work, "completion root-held consume request")
    for name, wanted in (("configurationDigest", payload["configurationDigest"]),
            ("plannerSpkiDigest", configured["planner"]["spkiDigest"]),
            ("plannerIdentity", configured["planner"]["identity"]),
            ("authenticationPolicy", configured["authenticationPolicy"]), ("trustPolicy", configured["trustPolicy"]),
            ("maximumPlanAgeNs", configured["maximumPlanAgeNs"]),
            ("maximumClockSkewNs", configured["maximumClockSkewNs"])):
        plan._same(expected["scope"][name], wanted, work, "consume completion independently admitted original policy")
    # Genuine historical caller signature/scope only, not a claim of private
    # plan/effects admission: the actual worker still repeats the full exchange.
    envelope = caller._read(intent_raw, enrollment=False, work=work)
    caller.primitives._signature(envelope, enrolled.caller_public_key, caller.MAX_AUTHORIZATION_BYTES, work)
    actual = envelope["payload"]
    for name in caller._SCOPE_FIELDS:
        plan._same(actual[name], caller_policy[name], work, "consume completion original caller scope")
    for name, wanted in (("authorizationEnrollmentDigest", enrolled.enrollment_digest),
            ("callerMeasurementDigest", caller_policy["callerKey"]["measurementDigest"]),
            ("requestDigest", expected["request"]["requestDigest"]),
            ("operationId", expected["request"]["operationId"]), ("journalDigest", expected["journalDigest"]),
            ("beforeVectorDigest", admitted.complete_root_vector_digest)):
        plan._same(actual[name], wanted, work, "consume completion root-held caller original")
    authorization._interval(actual, caller_policy["maximumAgeNs"])
    issued, expires = actual["issuedAtEpochNs"], actual["expiresAtEpochNs"]
    if (issued > live() + caller_policy["maximumClockSkewNs"]
            or not admitted.attestation_interval[0] <= issued < expires <= admitted.attestation_interval[1]
            or expires > expected["scope"]["deadlineEpochNs"]):
        _fail("consume completion caller original exceeds its original scope")
    digest = plan._frame(caller.REQUEST_IDENTITY_DOMAIN, (intent_raw,), work)
    for wanted in (payload["authorization"]["identityDigest"], payload["authorizationDigest"]):
        plan._same(digest, wanted, work, "consume completion caller identity")
    caller.primitives._unchanged(intent_raw, envelope, caller.MAX_AUTHORIZATION_BYTES, work)
    pending, checkpoint = payload["currentPending"], payload["completionCheckpoint"]
    if (pending["sequence"] >= policy["maxRecords"] or pending["fence"] > pending["sequence"]
            or checkpoint["sequence"] > policy["maxRecords"]):
        _fail("consume completion pending/checkpoint exceeds enrolled scope")
    if checkpoint["sequence"] == 0:
        plan._same(checkpoint["headDigest"], state.enrollment_digest, work, "consume completion journal genesis")
    custody_config, commit_config = _database_configurations(payload, work)
    material = _CompletionMaterial(bootstrap_bytes=original, custody_bytes=raw4[0],
        planner_bootstrap_bytes=raw4[1], planner_history_custody_bytes=raw4[2],
        receiving_history_custody_bytes=raw4[3], custody_material=custody,
        receiver_identity=payload["receiverIdentity"], configuration_payload=configured["configurationPayload"],
        generation=configured["generation"], runtime_role_identities=configured["runtimeRoleIdentities"],
        configuration_digest=payload["configurationDigest"], runtime_closure_digest=payload["runtimeClosureDigest"],
        authorization_bytes=intent_raw, current_root_enrollment_bytes=current_raw,
        grant_enrollment_bytes=grant_raw, authorization_enrollment_bytes=caller_raw,
        planner_public_key=admitted.planner_public_key, operation_public_key=root,
        completion_public_key=state.completion_public_key, completion_spki_digest=completion["spkiDigest"],
        completion_measurement_digest=completion["measurementDigest"], database_id=payload["databaseId"],
        generation_digest=payload["generationDigest"], enrollment_digest=state.enrollment_digest,
        maximum_authorization_age_ns=caller_policy["maximumAgeNs"],
        maximum_authorization_clock_skew_ns=caller_policy["maximumClockSkewNs"],
        current_pending=(pending["sequence"], pending["headDigest"], pending["fence"]),
        completion_checkpoint=(checkpoint["sequence"], checkpoint["headDigest"]),
        state_endpoint=_state_endpoint(payload["stateEndpoint"]), packet_digest=payload["packetDigest"],
        authorization_digest=payload["authorizationDigest"], expectations=expected,
        custody_configuration=custody_config, commit_configuration=commit_config, tls_files=payload["tlsFiles"],
        attestation_interval=interval, opening_sample=opening, launch=payload["launch"])
    live()
    return material, live


def _verify_on_work(*, bootstrap_bytes, root_public_key, work, live_window=None, transport_deadline_ns=None):
    try:
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "consume completion bootstrap")
        root = root_public_key
        authorization._public(root)
        window, bound, inherited = _processing(live_window, transport_deadline_ns, work)
        inherited()
        envelope = _decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed consume completion bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        _canonical(original, envelope, work)
        unsigned = _wire(envelope["payload"], work)
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned, capture._SharedLedger(work))
        inherited()
        _payload_shape(envelope["payload"], work)
        interval = envelope["payload"]["issuedAtEpochNs"], envelope["payload"]["expiresAtEpochNs"]
        opening = window[1], window[0], window[2]
        _fresh(interval, work, opening=opening)
        current = primitives._launch_guard(interval, opening, inherited, work)
        material, live = _material(envelope["payload"], original, root, window, bound, opening, work, current)
        _canonical(original, envelope, work)
        live()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, DeliveryCompletionBootstrapError):
            raise
        raise DeliveryCompletionBootstrapError("consume completion bootstrap admission failed") from exc


def _produce_on_work(*, payload, root_private_key, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    try:
        private, root = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(root)
        owned = _capture(payload, work)
        window, bound, inherited = _processing(live_window, transport_deadline_ns, work)
        inherited()
        _payload_shape(owned, work)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = window[1], window[0], window[2]
        _fresh(interval, work, opening=opening)
        current = primitives._launch_guard(interval, opening, inherited, work)
        unsigned = _wire(owned, work)
        _material_value, live = _material(owned, unsigned, root, window, bound, opening, work, current)
        primitives.keys._pair_on_work(private, root, work)
        envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
        size, nodes = work.measure(envelope)
        payload_size, payload_nodes = work.measure(owned)
        if size > MAX_BYTES or nodes > MAX_NODES:
            _fail("consume completion signed output exceeds its fixed bound")
        work.charge(input_bytes=size + 2 * payload_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=nodes + payload_nodes)
        message = plan._ascii(plan._frame(SCHEMA, (unsigned,), work), work)
        live()
        signature = production._sign_and_verify(private, root, message, work)
        live()
        if codec._encode(owned) != unsigned:
            _fail("consume completion payload changed during signing")
        envelope["signatureBase64Url"] = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        original = codec._encode(envelope)
        if len(original) != size:
            _fail("consume completion signed output changed after sizing")
        checked = _decode(original, work)
        plan._same(checked, envelope, work, "consume completion signed output readback")
        _canonical(original, checked, work)
        live()
        return original
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, DeliveryCompletionBootstrapError):
            raise
        raise DeliveryCompletionBootstrapError("consume completion bootstrap production failed") from exc
