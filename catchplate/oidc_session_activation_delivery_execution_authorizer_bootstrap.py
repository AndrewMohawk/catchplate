"""Root-original cold launch for the dedicated consume-grant authorizer.

The four detached originals and three embedded enrollments are authenticated
on one supplied ledger and original current clock allowance. No received
material substitutes for an original, and no key, descriptor, request
permission, grant, reservation, SQL operation or token release is created.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature

from catchplate import authority_oidc_session_activation_delivery_execution_authorization as caller
from catchplate import authority_oidc_session_activation_delivery_execution_enrollment as grants
from catchplate import oidc_session_activation_delivery_execution_custody_bootstrap as receiving


planner_bootstrap, history_bootstrap, shared = (
    receiving.planner_bootstrap, receiving.history_bootstrap, receiving.shared)
authority, configuration = shared.authority, shared.configuration
codec, signing = shared.codec, shared.signing
capability, capture, plan, keys = shared.capability, shared.capture, shared.plan, shared.keys
authorization, shape, clock = caller.authorization, caller.shape, caller.clock
production = configuration.production
ROLE = PROCESS_MODE = receiving.PROCESS_MODE
OPERATION = caller.OPERATION
SERVICE_UID = SERVICE_GID = 65500
PEER_UID = PEER_GID = 65532
(ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD, PLANNER_BOOTSTRAP_FD,
    PLANNER_HISTORY_CUSTODY_FD, RECEIVING_HISTORY_CUSTODY_FD, EXECUTION_BUNDLE_KEY_FD,
    HISTORICAL_BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD) = range(198, 209)
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD,
    PLANNER_BOOTSTRAP_FD, PLANNER_HISTORY_CUSTODY_FD, RECEIVING_HISTORY_CUSTODY_FD,
    EXECUTION_BUNDLE_KEY_FD, HISTORICAL_BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD)
LISTENER_PATH = "/run/catchplate/oidc-session-activation-delivery-execution/authorizer.sock"
LISTENER_NAME = "catchplate-oidc-session-activation-delivery-execution-authorizer"
MAX_BYTES = MAX_ROLE_BYTES = 4 * 1024 * 1024
MAX_CUSTODY_BYTES = receiving.MAX_BYTES
MAX_PLANNER_BOOTSTRAP_BYTES = planner_bootstrap.MAX_BYTES
MAX_PLANNER_HISTORY_CUSTODY_BYTES = history_bootstrap.MAX_BYTES
MAX_RECEIVING_HISTORY_CUSTODY_BYTES = history_bootstrap.MAX_BYTES
MAX_RECEIPT_AGE_NS = shared.MAX_RECEIPT_AGE_NS
SCHEMA = "catchplate.signedOidcSessionActivationDeliveryExecutionAuthorizerBootstrap/v1"
PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationDeliveryExecutionAuthorizerBootstrap/v1"
LAUNCH_SCHEMA = "catchplate.oidcSessionActivationDeliveryExecutionAuthorizerLaunch/v1"
_FALSE_FIELDS = receiving._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_DETACHED_FIELDS = frozenset({"byteCount", "bytesDigest"})
_DETACHED_LIMITS = (("receivingCustody", MAX_CUSTODY_BYTES),
    ("plannerBootstrap", MAX_PLANNER_BOOTSTRAP_BYTES),
    ("plannerHistoryCustody", MAX_PLANNER_HISTORY_CUSTODY_BYTES),
    ("receivingHistoryCustody", MAX_RECEIVING_HISTORY_CUSTODY_BYTES))
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest", "identityDigest"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "operation",
    "receivingCustody", "plannerBootstrap", "plannerHistoryCustody", "receivingHistoryCustody",
    "receiverIdentity", "configurationDigest", "generationDigest", "runtimeClosureDigest", "databaseId",
    "currentRootEnrollment", "grantEnrollment", "authorizationEnrollment", "authorizerSpkiDigest",
    "authorizerMeasurementDigest", "issuedAtEpochNs", "expiresAtEpochNs", "trustMode", "launch",
    *_FALSE_FIELDS})
_FD_FIELDS = (("rootPublicKeyFd", ROOT_FD), ("bootstrapFd", BOOTSTRAP_FD),
    ("listenerFd", LISTENER_FD), ("custodyFd", CUSTODY_FD),
    ("plannerBootstrapFd", PLANNER_BOOTSTRAP_FD),
    ("plannerHistoryCustodyFd", PLANNER_HISTORY_CUSTODY_FD),
    ("receivingHistoryCustodyFd", RECEIVING_HISTORY_CUSTODY_FD),
    ("executionBundleKeyFd", EXECUTION_BUNDLE_KEY_FD),
    ("historicalBundleKeyFd", HISTORICAL_BUNDLE_KEY_FD),
    ("deliveryKeyFd", DELIVERY_KEY_FD), ("signingKeyFd", KEY_FD))
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
    *(name for name, _ in _FD_FIELDS), "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode"})


class OidcSessionActivationDeliveryExecutionAuthorizerBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AuthorizerMaterial:
    """Owned same-call facts, never an accepted successful-authority input."""

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
    authorizer_public_key: object
    authorizer_spki_digest: str
    authorizer_measurement_digest: str
    database_id: str
    generation_digest: str
    maximum_authorization_age_ns: int
    maximum_authorization_clock_skew_ns: int
    attestation_interval: tuple
    opening_sample: tuple
    launch: dict
    planner_bootstrap_bytes: bytes
    planner_history_custody_bytes: bytes
    receiving_history_custody_bytes: bytes


def _fail(message):
    raise OidcSessionActivationDeliveryExecutionAuthorizerBootstrapError(message)


def _construction_on_work(work):
    """One actual source-max opening; never used to replace a supplied window."""
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
    return window, bound, shared._processing(window, bound, work)


def _fresh(interval, work, opening=None):
    return shared._fresh(interval, work, opening=opening)


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "consume authorizer launch")
    for field, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH)):
        shape._literal(value[field], expected)
    for field, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), *_FD_FIELDS):
        shape._integer(value[field], 2**32 - 2, minimum=1)
        if value[field] != expected:
            _fail("consume authorizer fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "consume authorizer descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work, "consume authorizer descriptor inventory")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for field in ("listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[field], 2**64 - 1)
    for field in ("listenerSocketInode", "listenerPathInode"):
        shape._integer(value[field], 2**64 - 1, minimum=1)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "consume authorizer payload")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("operation", OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(payload[field], expected)
    shape.validate_identity_shape(payload["receiverIdentity"])
    for field in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "authorizerSpkiDigest", "authorizerMeasurementDigest"):
        shape._digest(payload[field])
    authorization._token(payload["databaseId"])
    for name, maximum in _DETACHED_LIMITS:
        record = payload[name]
        shape._object(record, _DETACHED_FIELDS, "consume authorizer detached original")
        shape._integer(record["byteCount"], maximum, minimum=2)
        shape._digest(record["bytesDigest"])
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "consume authorizer enrollment original")
        shape._integer(record["byteCount"], maximum, minimum=2)
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[field], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        _fail("consume authorizer interval exceeds its fixed launch ceiling")
    if any(payload[field] is not False for field in _FALSE_FIELDS):
        _fail("consume authorizer claims unsupported hardware or witness assurance")
    _launch_shape(payload["launch"], work)


def _detached(custody, planner, planning_history, receiving_history):
    return tuple(authorization._original(raw, maximum, name)
        for raw, (name, maximum) in zip((custody, planner, planning_history, receiving_history), _DETACHED_LIMITS))


def _digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())


def _originals(payload, work, live):
    originals = []
    for name, maximum in _ORIGINAL_LIMITS:
        live()
        record = payload[name]
        original = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
        plan._same(_digest(original, work), record["bytesDigest"], work, "consume enrollment original digest")
        live()
        originals.append(original)
    return tuple(originals)


def _key_scope(configured, consume_planner_spki, historical_planner_spki, caller_spki, authorizer_spki, work):
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "consume configured roles")
    forbidden = [consume_planner_spki, historical_planner_spki, caller_spki]
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        for field in ("serviceUid", "serviceGid"):
            shape._integer(role[field], 2**32 - 2)
            if role[field] == SERVICE_UID:
                _fail("consume authorizer identity is shared with a configured role")
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
        work.prepare_comparison(authorizer_spki, pin)
        if authorizer_spki == pin:
            _fail("consume authorizer signing key is shared with another admitted purpose")


def _admit_payload(payload, originals, root, window, bound, work, current):
    if MAX_BYTES + sum(len(raw) for raw in originals) + sum(
            payload[name]["byteCount"] for name, _ in _ORIGINAL_LIMITS) > authority.MAX_RESULT_BYTES:
        _fail("consume authorizer original inventory exceeds its aggregate ceiling")
    for (name, _maximum), original in zip(_DETACHED_LIMITS, originals):
        current()
        record = payload[name]
        if len(original) != record["byteCount"]:
            _fail("consume authorizer detached original byte count differs")
        plan._same(_digest(original, work), record["bytesDigest"], work, "consume authorizer detached original digest")
        current()
    custody_raw, planner_raw, planning_raw, receiving_raw = originals
    custody = receiving._verify_on_work(custody_bytes=custody_raw, planner_bootstrap_bytes=planner_raw,
        planner_history_custody_bytes=planning_raw, receiving_history_custody_bytes=receiving_raw,
        root_public_key=root, work=work, live_window=window, transport_deadline_ns=bound)
    current()
    admitted = custody.planner
    configured = admitted.payload
    live = current
    # Only these fresh launch intervals constrain processing. The nested
    # historical activation planner's expired interval is never made current.
    for material in (custody, admitted, admitted.history_material, custody.history):
        if not material.attestation_interval[0] <= payload["issuedAtEpochNs"] < payload["expiresAtEpochNs"] <= material.attestation_interval[1]:
            _fail("consume authorizer interval escapes an original current nested launch")
        live = shared._launch_guard(material.attestation_interval, material.opening_sample, live, work)
    live()
    for actual, expected in ((payload["receiverIdentity"], custody.receiver_identity),
            (payload["configurationDigest"], configured["configurationDigest"]),
            (payload["generationDigest"], configured["generation"]["digest"]),
            (payload["runtimeClosureDigest"], configured["runtimeClosureDigest"]),
            (payload["databaseId"], configured["databaseId"])):
        plan._same(actual, expected, work, "consume role differs from genuine receiving scope")
    current_raw, grant_raw, caller_raw = _originals(payload, work, live)
    work.charge(input_bytes=len(current_raw) + len(admitted.state_enrollment_bytes))
    if current_raw != admitted.state_enrollment_bytes:
        _fail("consume authorizer state enrollment differs from its original planner scope")
    enrolled = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=payload["configurationDigest"],
        planner_public_key=admitted.planner_public_key, operation_public_key=root, work=work)
    live()
    grant = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root, work=work)
    live()
    caller_payload, authorizer = enrolled.payload, grant.payload["authorizer"]
    if authorizer["spkiDigest"] == keys._spki_on_work(custody.history.historical_root_public_key, work):
        _fail("consume authorizer key reuses the independently admitted historical root")
    for actual, expected in ((payload["currentRootEnrollment"]["identityDigest"], admitted.state_enrollment_digest),
            (payload["currentRootEnrollment"]["identityDigest"], caller_payload["currentRootEnrollmentDigest"]),
            (payload["grantEnrollment"]["identityDigest"], grant.enrollment_digest),
            (payload["authorizationEnrollment"]["identityDigest"], enrolled.enrollment_digest),
            (payload["databaseId"], caller_payload["databaseId"]),
            (payload["generationDigest"], caller_payload["generationDigest"]),
            (payload["authorizerSpkiDigest"], authorizer["spkiDigest"]),
            (payload["authorizerMeasurementDigest"], authorizer["measurementDigest"]),
            (payload["receiverIdentity"]["measurementDigest"], authorizer["measurementDigest"])):
        plan._same(actual, expected, work, "consume role differs from genuine purpose enrollment")
    _key_scope(configured["configurationPayload"], keys._spki_on_work(admitted.planner_public_key, work),
        custody.history.planner.planner_spki_digest, caller_payload["callerKey"]["spkiDigest"],
        authorizer["spkiDigest"], work)
    live()
    return custody, current_raw, grant_raw, caller_raw, enrolled, grant, live


def _verify_on_work(*, bootstrap_bytes, custody_bytes, planner_bootstrap_bytes,
        planner_history_custody_bytes, receiving_history_custody_bytes, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Admit the actual role and detached originals, not a received material."""
    try:
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "consume authorizer bootstrap")
        originals = _detached(custody_bytes, planner_bootstrap_bytes,
            planner_history_custody_bytes, receiving_history_custody_bytes)
        receiving._intake_reservation((16 * 1024, len(original), *map(len, originals)))
        root = root_public_key
        authorization._public(root)
        window, bound, inherited = _processing(live_window, transport_deadline_ns, work)
        inherited()
        envelope = codec._decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed consume authorizer bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("consume authorizer payload is not an exact object")
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
        custody, current_raw, grant_raw, caller_raw, enrolled, grant, live = _admit_payload(
            payload, originals, root, window, bound, work, current)
        admitted = custody.planner
        configured = admitted.payload
        material = _AuthorizerMaterial(bootstrap_bytes=original, custody_bytes=originals[0],
            custody_material=custody, receiver_identity=payload["receiverIdentity"],
            configuration_payload=configured["configurationPayload"], generation=configured["generation"],
            runtime_role_identities=configured["runtimeRoleIdentities"],
            configuration_digest=payload["configurationDigest"], runtime_closure_digest=payload["runtimeClosureDigest"],
            current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
            authorization_enrollment_bytes=caller_raw, planner_public_key=admitted.planner_public_key,
            operation_public_key=root, authorizer_public_key=grant.authorizer_public_key,
            authorizer_spki_digest=payload["authorizerSpkiDigest"],
            authorizer_measurement_digest=payload["authorizerMeasurementDigest"], database_id=payload["databaseId"],
            generation_digest=payload["generationDigest"], maximum_authorization_age_ns=enrolled.payload["maximumAgeNs"],
            maximum_authorization_clock_skew_ns=enrolled.payload["maximumClockSkewNs"],
            attestation_interval=interval, opening_sample=opening, launch=payload["launch"],
            planner_bootstrap_bytes=originals[1], planner_history_custody_bytes=originals[2],
            receiving_history_custody_bytes=originals[3])
        codec._canonical(original, envelope, work)
        live()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationDeliveryExecutionAuthorizerBootstrapError):
            raise
        raise OidcSessionActivationDeliveryExecutionAuthorizerBootstrapError("consume authorizer bootstrap admission failed") from exc


def _produce_on_work(*, payload, custody_bytes, planner_bootstrap_bytes, planner_history_custody_bytes,
        receiving_history_custody_bytes, root_private_key, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Sign independently established launch claims after original admission."""
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
        shape._object(checked, _ENVELOPE_FIELDS, "signed consume authorizer output")
        shape._literal(checked["schema"], SCHEMA)
        shape._base64url(checked["signatureBase64Url"], signature=True)
        _payload_shape(checked["payload"], work)
        plan._same(checked["payload"], owned, work, "consume authorizer output payload changed")
        codec._canonical(original, checked, work)
        live()
        return original
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationDeliveryExecutionAuthorizerBootstrapError):
            raise
        raise OidcSessionActivationDeliveryExecutionAuthorizerBootstrapError("consume authorizer bootstrap production failed") from exc
