"""Independent root-original launch admission for activation completion.

Fresh completion custody and the dedicated launch are separate signatures.
The embedded original planner is admitted as history, never a current launch.
Packet, caller, pending, reader and journal pins are independently root held;
neither SQL observations nor retained acknowledgments select these expectations.
No descriptor, TLS file, key, journal, network or database is opened here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature

from serverware import authority_oidc_session_activation_execution_authorization as caller
from serverware import authority_oidc_session_activation_execution_expectations as expectations_wire
from serverware import authority_oidc_session_activation_execution_history as history
from serverware import authority_successor_execution_window as processing_window
from serverware import oidc_session_activation_history_custody_bootstrap as receiving
# This shares only closed scalar grammar, not another purpose's admission.
from serverware.registration_execution_sql_bootstrap import _database_shape


planner_bootstrap = receiving.planner_bootstrap
authority, configuration = planner_bootstrap.authority, planner_bootstrap.configuration
codec = planner_bootstrap.codec
capability, capture, plan = planner_bootstrap.capability, planner_bootstrap.capture, planner_bootstrap.plan
authorization, grants, shape, clock = caller.authorization, caller.grants, caller.shape, caller.clock
production = configuration.production
ROLE = PROCESS_MODE = receiving.PROCESS_MODE
OPERATION = "oidc.session.activate"
SERVICE_UID = SERVICE_GID = 65503
PEER_UID = PEER_GID = 65532
STATE_SERVICE_UID = STATE_SERVICE_GID = 65516
STATE_LISTENER_UID = STATE_LISTENER_GID = 0
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD, BUNDLE_KEY_FD, DELIVERY_KEY_FD = range(198, 205)
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD,
    JOURNAL_FD, BUNDLE_KEY_FD, DELIVERY_KEY_FD)
LISTENER_PATH = "/run/serverware/oidc-session-activation/completion.sock"
LISTENER_NAME = "serverware-oidc-session-activation-completion"
JOURNAL_PATH = "/var/lib/serverware/oidc-session-activation-completions"
STATE_SOCKET_PATH = "/run/serverware/current-root/state.sock"
TLS_PATHS = {
    "ca": "/run/serverware/oidc-session-activation-completion-tls/ca.pem",
    "custodyCertificate": "/run/serverware/oidc-session-activation-completion-tls/custody.crt",
    "custodyKey": "/run/serverware/oidc-session-activation-completion-tls/custody.key",
    "commitCertificate": "/run/serverware/oidc-session-activation-completion-tls/commit.crt",
    "commitKey": "/run/serverware/oidc-session-activation-completion-tls/commit.key",
}
TLS_LIMITS = {name: (16 * 1024 if name in ("custodyKey", "commitKey") else 64 * 1024)
    for name in TLS_PATHS}
MIN_TLS_BYTES = 2
MAX_BYTES = 16 * 1024 * 1024
MAX_CUSTODY_BYTES = receiving.MAX_BYTES
MAX_NODES = expectations_wire.MAX_NODES + 4096
MAX_DEPTH = 16
MAX_RECEIPT_AGE_NS = planner_bootstrap.MAX_RECEIPT_AGE_NS
SCHEMA = "serverware.signedOidcSessionActivationCompletionBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationCompletionBootstrap/v1"
LAUNCH_SCHEMA = "serverware.oidcSessionActivationCompletionLaunch/v1"
_FALSE_FIELDS = receiving._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest", "identityDigest"})
_CUSTODY_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES),
    ("authorization", caller.MAX_AUTHORIZATION_BYTES))
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "operation", "historicalCustody",
    "receiverIdentity", "configurationDigest", "generationDigest", "runtimeClosureDigest", "databaseId",
    "currentRootEnrollment", "grantEnrollment", "authorizationEnrollment", "authorization",
    "completionSpkiDigest", "completionMeasurementDigest", "currentPending", "completionCheckpoint",
    "stateEndpoint", "packetDigest", "authorizationDigest", "replayExpectations", "databaseEndpoint",
    "sqlRoles", "queryManifestDigest", "structureManifestDigest", "tlsFiles", "issuedAtEpochNs",
    "expiresAtEpochNs", "trustMode", "launch", *_FALSE_FIELDS})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
    "rootPublicKeyFd", "bootstrapFd", "listenerFd", "signingKeyFd", "journalDirectoryFd",
    "bundleKeyFd", "deliveryKeyFd", "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode",
    "journalDirectoryPath", "journalDirectoryDevice", "journalDirectoryInode", "journalMaximumRecords"})
_SQL_ROLE_FIELDS = frozenset({"connectTimeoutSeconds", "clientDn", "clientSerial", "issuerDn"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "serviceUid", "serviceGid",
    "listenerUid", "listenerGid"})


class OidcSessionActivationCompletionBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CompletionMaterial:
    """Owned same-call facts; never an accepted completion capability."""

    bootstrap_bytes: bytes
    custody_bytes: bytes
    custody_material: receiving._HistoryCustodyMaterial
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
    raise OidcSessionActivationCompletionBootstrapError(message)


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("activation completion bootstrap exceeds its fixed shape bound")
        return super().visit(value, depth, ancestors)


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(raw, value, work):
    return capability._canonical(raw, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _decode(raw, work):
    # The outer embeds up to 8MiB of genuine history custody. Never run this
    # through the older 4MiB bootstrap decoder or an uncharged JSON decoder.
    value = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    return _capture(value, work)


def _fresh(interval, work, opening=None):
    """Fresh role/custody intervals only; never the old planner interval."""
    return receiving._fresh(interval, work, opening=opening)


def _processing(live_window, deadline, work):
    if deadline is not None:
        shape._integer(deadline, minimum=1)
    if live_window is None:
        # One actual sample precedes original parsing/signature callbacks.
        # Later narrowing retains these samples rather than opening a window.
        before, epoch, after = clock._sample_on_work(work)
        maximum = authority.VERIFIER_RESPONSE_MAX_AGE_NS
        until = epoch + maximum
        window = clock._validate((epoch, before, after, until,
            before + until - epoch, maximum, 0))
    else:
        window = clock._validate(live_window)
    bound = window[4] if deadline is None else min(window[4], deadline)
    return window, bound, planner_bootstrap._processing(window, bound, work)


def _database_configurations(payload, work):
    endpoint, roles = payload["databaseEndpoint"], payload["sqlRoles"]
    _database_shape(endpoint)
    shape._object(roles, frozenset({"custody", "commit"}), "activation completion fixed read roles")
    result = []
    for name, role in (("custody", authority.SUCCESSOR_RECOVERY_ROLE),
            ("commit", authority.COMPLETION_READER_ROLE)):
        selected = roles[name]
        shape._object(selected, _SQL_ROLE_FIELDS, "activation completion read TLS identity")
        shape._integer(selected["connectTimeoutSeconds"], 300, minimum=2)
        for field in ("clientDn", "clientSerial", "issuerDn"):
            text = selected[field]
            if (type(text) is not str or not 1 <= len(text) <= 4096 or "\x00" in text
                    or work.prepare_utf8(text) > 4096):
                _fail("activation completion SQL TLS identity exceeds its exact bound")
        dsn = ("host=" + endpoint["host"] + " hostaddr=" + endpoint["hostaddr"]
            + " port=" + str(endpoint["port"]) + " dbname=" + endpoint["databaseName"]
            + " user=" + role + " sslmode=verify-full sslrootcert=" + TLS_PATHS["ca"]
            + " sslcert=" + TLS_PATHS[name + "Certificate"]
            + " sslkey=" + TLS_PATHS[name + "Key"]
            + " passfile=/dev/null gssencmode=disable")
        result.append((dsn, selected["connectTimeoutSeconds"], role, selected["clientDn"],
            selected["clientSerial"], selected["issuerDn"], payload["queryManifestDigest"],
            payload["structureManifestDigest"]))
    return tuple(result)


def _state_endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "activation completion fixed state endpoint")
    shape._literal(value["socketPath"], STATE_SOCKET_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name, expected in (("serviceUid", STATE_SERVICE_UID), ("serviceGid", STATE_SERVICE_GID),
            ("listenerUid", STATE_LISTENER_UID), ("listenerGid", STATE_LISTENER_GID)):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != expected:
            _fail("activation completion state endpoint identity is not source fixed")
    return value["socketPath"], value["requestTimeoutSeconds"], STATE_LISTENER_UID, STATE_LISTENER_GID


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "activation completion launch")
    for name, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH), ("journalDirectoryPath", JOURNAL_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD),
            ("bootstrapFd", BOOTSTRAP_FD), ("listenerFd", LISTENER_FD), ("signingKeyFd", KEY_FD),
            ("journalDirectoryFd", JOURNAL_FD), ("bundleKeyFd", BUNDLE_KEY_FD),
            ("deliveryKeyFd", DELIVERY_KEY_FD)):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            _fail("activation completion fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "activation completion descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work, "activation completion exact descriptors")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerSocketDevice", "listenerPathDevice", "journalDirectoryDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("listenerSocketInode", "listenerPathInode", "journalDirectoryInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], authorization.MAX_RECORDS, minimum=2)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "activation completion bootstrap payload")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("operation", OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    shape.validate_identity_shape(payload["receiverIdentity"])
    for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest", "completionSpkiDigest",
            "completionMeasurementDigest", "packetDigest", "authorizationDigest", "queryManifestDigest",
            "structureManifestDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    record = payload["historicalCustody"]
    shape._object(record, _CUSTODY_FIELDS, "activation historical custody original")
    authorization.transport._transport_shape(record["base64Url"], record["byteCount"], MAX_CUSTODY_BYTES)
    shape._integer(record["byteCount"], MAX_CUSTODY_BYTES, minimum=2)
    shape._digest(record["bytesDigest"])
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "activation completion authority original")
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._integer(record["byteCount"], maximum, minimum=2)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    expectations_wire._shape(payload["replayExpectations"])
    pending, checkpoint = payload["currentPending"], payload["completionCheckpoint"]
    shape._object(pending, frozenset({"sequence", "headDigest", "fence"}), "independent completion pending")
    shape._integer(pending["sequence"], authorization.MAX_RECORDS, minimum=1)
    shape._digest(pending["headDigest"])
    shape._integer(pending["fence"], minimum=1)
    shape._object(checkpoint, frozenset({"sequence", "headDigest"}), "independent completion checkpoint")
    shape._integer(checkpoint["sequence"], authorization.MAX_RECORDS)
    shape._digest(checkpoint["headDigest"])
    _state_endpoint(payload["stateEndpoint"])
    _database_configurations(payload, work)
    shape._object(payload["tlsFiles"], frozenset(TLS_PATHS), "activation completion TLS original pins")
    for name, maximum in TLS_LIMITS.items():
        record = payload["tlsFiles"][name]
        shape._object(record, frozenset({"byteCount", "bytesDigest"}), "activation completion TLS file pin")
        shape._integer(record["byteCount"], maximum, minimum=MIN_TLS_BYTES)
        shape._digest(record["bytesDigest"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[name], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        _fail("activation completion launch exceeds its fixed lifetime")
    if any(payload[name] is not False for name in _FALSE_FIELDS):
        _fail("activation completion claims unsupported hardware or witness assurance")
    _launch_shape(payload["launch"], work)


def _original(record, maximum, work, current):
    current()
    raw = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
    work.charge(hashes=1, input_bytes=len(raw))
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())
    current()
    plan._same(digest, record["bytesDigest"], work, "activation completion original bytes differ")
    return raw


def _configured_keys(configured, caller_pin, completion_pin, work):
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "activation completion configured roles")
    forbidden = []
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        for field in ("serviceUid", "serviceGid"):
            shape._integer(role[field], 2**32 - 2)
            if role[field] == SERVICE_UID:
                _fail("activation completion process shares a configured generic role")
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            forbidden.append(role["signingSpkiDigest"])
    for module, slots in ((planner_bootstrap.evidence_policy, ("registration", "installation")),
            (planner_bootstrap.transition_policy, ("registration", "stage", "completion"))):
        value = configured.get(module.FIELD)
        if value is not None:
            policy, _keys = module._validate_policy_on_work(value,
                webauthn=configured["webauthn"], work=work)
            forbidden.extend(policy[name]["signingSpkiDigest"] for name in slots if policy[name] is not None)
    value = configured.get(planner_bootstrap.enrollment_policy.FIELD)
    if value is not None:
        policy, _key = planner_bootstrap.enrollment_policy._validate_policy_on_work(
            value, payload=configured, work=work)
        forbidden.append(policy["signingSpkiDigest"])
    work.prepare_scan(forbidden)
    for pin in forbidden:
        shape._digest(pin)
        for actual in (caller_pin, completion_pin):
            work.prepare_comparison(actual, pin)
            if actual == pin:
                _fail("activation completion/caller signing key shares another configured purpose")


def _caller_original(raw, record, enrolled, expected, admitted, payload, work, current):
    """Authenticate the original signature/scope, not absent encrypted effects."""
    current()
    envelope = caller._read(raw, enrollment=False, work=work)
    caller.primitives._signature(envelope, enrolled.caller_public_key, caller.MAX_AUTHORIZATION_BYTES, work)
    actual, policy = envelope["payload"], enrolled.payload
    for name in caller._SCOPE_FIELDS:
        plan._same(actual[name], policy[name], work, "activation completion original caller scope")
    for name, wanted in (("authorizationEnrollmentDigest", enrolled.enrollment_digest),
            ("callerMeasurementDigest", policy["callerKey"]["measurementDigest"]),
            ("requestDigest", expected["request"]["requestDigest"]),
            ("operationId", expected["request"]["operationId"]),
            ("journalDigest", expected["journalDigest"]),
            ("beforeVectorDigest", admitted.complete_root_vector_digest)):
        plan._same(actual[name], wanted, work, "activation completion caller original binding")
    authorization._interval(actual, policy["maximumAgeNs"])
    issued, expires = actual["issuedAtEpochNs"], actual["expiresAtEpochNs"]
    if (issued > current() + policy["maximumClockSkewNs"]
            or not admitted.attestation_interval[0] <= issued < expires <= admitted.attestation_interval[1]
            or expires > expected["scope"]["deadlineEpochNs"]):
        _fail("historical caller original exceeds original scope or is future-issued")
    digest = plan._frame(caller.REQUEST_IDENTITY_DOMAIN, (raw,), work)
    for wanted in (record["identityDigest"], payload["authorizationDigest"]):
        plan._same(digest, wanted, work, "independent completion authorization identity")
    caller.primitives._unchanged(raw, envelope, caller.MAX_AUTHORIZATION_BYTES, work)
    current()


def _material(payload, original, root, window, deadline, opening, work, current):
    custody_raw = _original(payload["historicalCustody"], MAX_CUSTODY_BYTES, work, current)
    custody = receiving._verify_on_work(custody_bytes=custody_raw, root_public_key=root,
        live_window=window, transport_deadline_ns=deadline, work=work)
    current()
    admitted = custody.planner
    for actual, wanted in ((payload["receiverIdentity"], custody.receiver_identity),
            (payload["configurationDigest"], admitted.configuration_digest),
            (payload["generationDigest"], admitted.generation["digest"]),
            (payload["runtimeClosureDigest"], admitted.runtime_closure_digest),
            (payload["queryManifestDigest"], admitted.configuration_payload["queryManifestDigest"])):
        plan._same(actual, wanted, work, "activation completion differs from genuine historical custody")
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if not custody.attestation_interval[0] <= interval[0] < interval[1] <= custody.attestation_interval[1]:
        _fail("activation completion launch escapes fresh historical custody interval")
    narrowed = processing_window._narrow(window, deadline_epoch_ns=interval[1],
        maximum_lifetime_ns=admitted.maximum_plan_age_ns,
        maximum_clock_skew_ns=admitted.maximum_clock_skew_ns)
    processing = planner_bootstrap._processing(narrowed, min(deadline, narrowed[4]), work)

    def live():
        current()
        _fresh(custody.attestation_interval, work, opening=custody.opening_sample)
        now = processing()
        if current() < now:
            _fail("activation completion processing reversed across historical custody")
        return now

    live()
    current_raw, grant_raw, caller_raw, intent_raw = tuple(_original(payload[name], maximum, work, live)
        for name, maximum in _ORIGINAL_LIMITS)
    if sum(map(len, (original, custody_raw, admitted.bootstrap_bytes, current_raw,
            grant_raw, caller_raw, intent_raw))) > authority.MAX_RESULT_BYTES:
        _fail("activation completion original inventory exceeds its aggregate ceiling")
    work.charge(input_bytes=len(current_raw) + len(admitted.state_enrollment_bytes))
    if current_raw != admitted.state_enrollment_bytes:
        _fail("activation completion state enrollment differs from genuine historical planner")
    enrolled = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=admitted.configuration_digest,
        planner_public_key=admitted.planner_public_key, operation_public_key=root, work=work)
    live()
    state = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw, root_public_key=root, work=work)
    live()
    grant = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root, work=work)
    live()
    policy, enrolled_policy = state.payload, enrolled.payload
    completion = policy["completion"]
    for actual, wanted in ((payload["currentRootEnrollment"]["identityDigest"], state.enrollment_digest),
            (state.enrollment_digest, admitted.state_enrollment_digest),
            (payload["grantEnrollment"]["identityDigest"], grant.enrollment_digest),
            (payload["authorizationEnrollment"]["identityDigest"], enrolled.enrollment_digest),
            (payload["databaseId"], enrolled_policy["databaseId"]),
            (payload["generationDigest"], enrolled_policy["generationDigest"]),
            (payload["completionSpkiDigest"], completion["spkiDigest"]),
            (payload["completionMeasurementDigest"], completion["measurementDigest"]),
            (payload["receiverIdentity"]["measurementDigest"], completion["measurementDigest"]),
            (payload["launch"]["journalMaximumRecords"], policy["maxRecords"])):
        plan._same(actual, wanted, work, "activation completion differs from genuine enrollment")
    caller_pin = enrolled_policy["callerKey"]["spkiDigest"]
    _configured_keys(admitted.configuration_payload, caller_pin, completion["spkiDigest"], work)
    for pin in (caller.keys._spki_on_work(root, work), admitted.planner_spki_digest, caller_pin,
            grant.payload["authorizer"]["spkiDigest"], policy["computation"]["spkiDigest"], policy["state"]["spkiDigest"]):
        work.prepare_comparison(completion["spkiDigest"], pin)
        if completion["spkiDigest"] == pin:
            _fail("activation completion key shares another admitted purpose")
    expected = expectations_wire._capture_on_work(payload["replayExpectations"], work=work)
    history._expectations(expected["request"], expected["scope"], narrowed, work)
    for name, wanted in (("configurationDigest", admitted.configuration_digest),
            ("plannerSpkiDigest", admitted.planner_spki_digest), ("plannerIdentity", admitted.planner_identity),
            ("rpId", admitted.rp_id), ("origin", admitted.origin),
            ("authenticationPolicy", admitted.authn_policy), ("trustPolicy", admitted.trust_policy),
            ("maximumPlanAgeNs", admitted.maximum_plan_age_ns),
            ("maximumClockSkewNs", admitted.maximum_clock_skew_ns)):
        plan._same(expected["scope"][name], wanted, work, "activation completion independently admitted original policy")
    _caller_original(intent_raw, payload["authorization"], enrolled, expected, admitted, payload, work, live)
    pending, checkpoint = payload["currentPending"], payload["completionCheckpoint"]
    if pending["sequence"] >= policy["maxRecords"] or checkpoint["sequence"] > policy["maxRecords"]:
        _fail("activation completion pending/checkpoint exceeds enrolled capacity")
    if checkpoint["sequence"] == 0:
        plan._same(checkpoint["headDigest"], state.enrollment_digest, work,
            "activation completion independent journal genesis")
    custody_config, commit_config = _database_configurations(payload, work)
    material = _CompletionMaterial(bootstrap_bytes=original, custody_bytes=custody_raw,
        custody_material=custody, receiver_identity=payload["receiverIdentity"],
        configuration_payload=admitted.configuration_payload, generation=admitted.generation,
        runtime_role_identities=admitted.runtime_role_identities, configuration_digest=admitted.configuration_digest,
        runtime_closure_digest=admitted.runtime_closure_digest, authorization_bytes=intent_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        authorization_enrollment_bytes=caller_raw, planner_public_key=admitted.planner_public_key,
        operation_public_key=root, completion_public_key=state.completion_public_key,
        completion_spki_digest=completion["spkiDigest"], completion_measurement_digest=completion["measurementDigest"],
        database_id=payload["databaseId"], generation_digest=payload["generationDigest"],
        enrollment_digest=state.enrollment_digest, maximum_authorization_age_ns=enrolled_policy["maximumAgeNs"],
        maximum_authorization_clock_skew_ns=enrolled_policy["maximumClockSkewNs"],
        current_pending=(pending["sequence"], pending["headDigest"], pending["fence"]),
        completion_checkpoint=(checkpoint["sequence"], checkpoint["headDigest"]),
        state_endpoint=_state_endpoint(payload["stateEndpoint"]), packet_digest=payload["packetDigest"],
        authorization_digest=payload["authorizationDigest"], expectations=expected,
        custody_configuration=custody_config, commit_configuration=commit_config, tls_files=payload["tlsFiles"],
        attestation_interval=interval, opening_sample=opening, launch=payload["launch"])
    live()
    return material, live


def _verify_on_work(*, bootstrap_bytes, root_public_key, work, live_window=None, transport_deadline_ns=None):
    """Authenticate all original purpose/configuration before cold resource use."""
    try:
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "activation completion bootstrap")
        root = root_public_key
        authorization._public(root)
        window, deadline, inherited = _processing(live_window, transport_deadline_ns, work)
        inherited()
        envelope = _decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed activation completion bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("activation completion payload is not an exact object")
        _canonical(original, envelope, work)
        payload = envelope["payload"]
        unsigned = _wire(payload, work)
        inherited()
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned, capture._SharedLedger(work))
        inherited()
        _canonical(original, envelope, work)
        _payload_shape(payload, work)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = (window[1], window[0], window[2])
        _fresh(interval, work, opening=opening)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        material, live = _material(payload, original, root, window, deadline, opening, work, current)
        _canonical(original, envelope, work)
        live()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationCompletionBootstrapError):
            raise
        raise OidcSessionActivationCompletionBootstrapError("activation completion bootstrap admission failed") from exc


def _produce_on_work(*, payload, root_private_key, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Sign independent claims, never infer packet/pending scope from a response."""
    try:
        private, root = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(root)
        owned = _capture(payload, work)
        window, deadline, inherited = _processing(live_window, transport_deadline_ns, work)
        inherited()
        _payload_shape(owned, work)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = (window[1], window[0], window[2])
        _fresh(interval, work, opening=opening)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        unsigned = _wire(owned, work)
        # Admit every held original before signing; the measured envelope is
        # separately bounded and charged below on this same work allowance.
        _material_value, live = _material(owned, unsigned, root, window, deadline, opening, work, current)
        planner_bootstrap.keys._pair_on_work(private, root, work)
        live()
        envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
        envelope_size, envelope_nodes = work.measure(envelope)
        payload_size, payload_nodes = work.measure(owned)
        if envelope_size > MAX_BYTES or envelope_nodes > MAX_NODES:
            _fail("activation completion signed output exceeds its fixed bound")
        work.charge(input_bytes=envelope_size + 2 * payload_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=envelope_nodes + payload_nodes)
        message = plan._ascii(plan._frame(SCHEMA, (unsigned,), work), work)
        live()
        signature = production._sign_and_verify(private, root, message, work)
        live()
        if codec._encode(owned) != unsigned:
            _fail("activation completion payload changed while signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = codec._encode(envelope)
        if len(result) != envelope_size:
            _fail("activation completion signed output changed after reservation")
        _canonical(result, envelope, work)
        live()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationCompletionBootstrapError):
            raise
        raise OidcSessionActivationCompletionBootstrapError("activation completion bootstrap production failed") from exc
