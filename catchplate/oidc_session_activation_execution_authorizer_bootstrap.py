"""Independent cold launch for the actual activation execution grant signer.

The role launch, separate receiving original and embedded planner original are
genuinely root-authenticated on the caller's work and unchanged clock bounds.
No material object substitutes for originals, and no key, FD, process, request
permission, grant, reservation or SQL operation is created by this module.
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
ROLE = PROCESS_MODE = receiving.CONSUMERS["grant"][0]
OPERATION = "oidc.session.activate"
SERVICE_UID = SERVICE_GID = 65506
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD, BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD = range(198, 205)
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD,
    BUNDLE_KEY_FD, DELIVERY_KEY_FD, KEY_FD)
LISTENER_PATH = "/run/catchplate/oidc-session-activation-execution/authorizer.sock"
LISTENER_NAME = "catchplate-oidc-session-activation-execution-authorizer"
MAX_BYTES = MAX_ROLE_BYTES = 4 * 1024 * 1024
MAX_CUSTODY_BYTES = receiving.MAX_BYTES
MAX_RECEIPT_AGE_NS = planner_bootstrap.MAX_RECEIPT_AGE_NS
SCHEMA = "catchplate.signedOidcSessionActivationExecutionAuthorizerBootstrap/v1"
PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationExecutionAuthorizerBootstrap/v1"
LAUNCH_SCHEMA = "catchplate.oidcSessionActivationExecutionAuthorizerLaunch/v1"
_FALSE_FIELDS = receiving._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_CUSTODY_FIELDS = frozenset({"byteCount", "bytesDigest"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest", "identityDigest"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "operation", "receivingCustody",
    "receiverIdentity", "configurationDigest", "generationDigest", "runtimeClosureDigest", "databaseId",
    "currentRootEnrollment", "grantEnrollment", "authorizationEnrollment", "authorizerSpkiDigest",
    "authorizerMeasurementDigest", "issuedAtEpochNs", "expiresAtEpochNs", "trustMode", "launch",
    *_FALSE_FIELDS})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
    "rootPublicKeyFd", "bootstrapFd", "listenerFd", "custodyFd", "bundleKeyFd", "deliveryKeyFd",
    "signingKeyFd", "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode"})


class OidcSessionActivationExecutionAuthorizerBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AuthorizerMaterial:
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


def _fail(message):
    raise OidcSessionActivationExecutionAuthorizerBootstrapError(message)


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "activation execution authorizer launch")
    for field, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH)):
        shape._literal(value[field], expected)
    for field, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD),
            ("bootstrapFd", BOOTSTRAP_FD), ("listenerFd", LISTENER_FD), ("custodyFd", CUSTODY_FD),
            ("bundleKeyFd", BUNDLE_KEY_FD), ("deliveryKeyFd", DELIVERY_KEY_FD), ("signingKeyFd", KEY_FD)):
        shape._integer(value[field], 2**32 - 2, minimum=1)
        if value[field] != expected:
            _fail("activation authorizer fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "activation authorizer descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work, "activation authorizer exact descriptor inventory")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for field in ("listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[field], 2**64 - 1)
    for field in ("listenerSocketInode", "listenerPathInode"):
        shape._integer(value[field], 2**64 - 1, minimum=1)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "activation execution authorizer payload")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("operation", OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(payload[field], expected)
    shape.validate_identity_shape(payload["receiverIdentity"])
    for field in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "authorizerSpkiDigest", "authorizerMeasurementDigest"):
        shape._digest(payload[field])
    authorization._token(payload["databaseId"])
    custody = payload["receivingCustody"]
    shape._object(custody, _CUSTODY_FIELDS, "activation external receiving original")
    shape._integer(custody["byteCount"], MAX_CUSTODY_BYTES, minimum=2)
    shape._digest(custody["bytesDigest"])
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "activation authorizer enrollment original")
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._integer(record["byteCount"], maximum, minimum=2)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[field], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        _fail("activation authorizer lifetime exceeds its original launch ceiling")
    if any(payload[field] is not False for field in _FALSE_FIELDS):
        _fail("activation authorizer claims unsupported hardware or witness assurance")
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
        original = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
        plan._same(_digest(original, work), record["bytesDigest"], work, "activation enrollment original digest")
        current()
        originals.append(original)
    return tuple(originals)


def _key_scope(configured, planner_spki, caller_spki, authorizer_spki, work):
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "activation configured roles")
    forbidden = [planner_spki, caller_spki]
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        for field in ("serviceUid", "serviceGid"):
            shape._integer(role[field], 2**32 - 2)
            if role[field] == SERVICE_UID:
                _fail("activation authorizer identity is shared with a configured role")
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
        work.prepare_comparison(authorizer_spki, pin)
        if authorizer_spki == pin:
            _fail("activation authorizer signing key is shared with another configured purpose")


def _admit_payload(payload, custody_bytes, root, window, deadline, work, current):
    record = payload["receivingCustody"]
    if len(custody_bytes) != record["byteCount"]:
        _fail("activation receiving original byte count differs from the role launch")
    if len(custody_bytes) + sum(payload[name]["byteCount"] for name, _ in _ORIGINAL_LIMITS) + MAX_BYTES > authority.MAX_RESULT_BYTES:
        _fail("activation authorizer original inventory exceeds its aggregate ceiling")
    current()
    plan._same(_digest(custody_bytes, work), record["bytesDigest"], work, "activation receiving original digest")
    current()
    custody = receiving._verify_on_work(custody_bytes=custody_bytes, root_public_key=root,
        expected_consumer_role="grant", work=work, live_window=window, transport_deadline_ns=deadline)
    current()
    admitted = custody.planner
    for actual, expected in ((payload["receiverIdentity"], custody.receiver_identity),
            (payload["configurationDigest"], admitted.configuration_digest),
            (payload["generationDigest"], admitted.generation["digest"]),
            (payload["runtimeClosureDigest"], admitted.runtime_closure_digest)):
        plan._same(actual, expected, work, "activation role differs from genuine receiving scope")
    if not custody.attestation_interval[0] <= payload["issuedAtEpochNs"] < payload["expiresAtEpochNs"] <= custody.attestation_interval[1]:
        _fail("activation role interval escapes the original receiving interval")

    def live():
        current()
        _fresh(custody.attestation_interval, work, opening=custody.opening_sample)
        _fresh(admitted.attestation_interval, work, opening=admitted.opening_sample)
        return current()

    live()
    current_raw, grant_raw, caller_raw = _originals(payload, work, live)
    work.charge(input_bytes=len(current_raw) + len(admitted.state_enrollment_bytes))
    if current_raw != admitted.state_enrollment_bytes:
        _fail("activation authorizer state enrollment differs from its original planner scope")
    caller_material = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=admitted.configuration_digest,
        planner_public_key=admitted.planner_public_key, operation_public_key=root, work=work)
    live()
    grant = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root, work=work)
    live()
    enrolled, authorizer = caller_material.payload, grant.payload["authorizer"]
    for actual, expected in ((payload["currentRootEnrollment"]["identityDigest"], admitted.state_enrollment_digest),
            (payload["currentRootEnrollment"]["identityDigest"], enrolled["currentRootEnrollmentDigest"]),
            (payload["grantEnrollment"]["identityDigest"], grant.enrollment_digest),
            (payload["authorizationEnrollment"]["identityDigest"], caller_material.enrollment_digest),
            (payload["databaseId"], enrolled["databaseId"]),
            (payload["generationDigest"], enrolled["generationDigest"]),
            (payload["authorizerSpkiDigest"], authorizer["spkiDigest"]),
            (payload["authorizerMeasurementDigest"], authorizer["measurementDigest"]),
            (payload["receiverIdentity"]["measurementDigest"], authorizer["measurementDigest"])):
        plan._same(actual, expected, work, "activation role differs from genuine purpose enrollment")
    _key_scope(admitted.configuration_payload, admitted.planner_spki_digest,
        enrolled["callerKey"]["spkiDigest"], authorizer["spkiDigest"], work)
    live()
    return custody, current_raw, grant_raw, caller_raw, caller_material, grant, live


def _verify_on_work(*, bootstrap_bytes, custody_bytes, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Authenticate original role, receiving, planner and enrollment authority."""
    try:
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "activation authorizer bootstrap")
        custody_original = authorization._original(custody_bytes, MAX_CUSTODY_BYTES, "activation receiving custody")
        root = root_public_key
        authorization._public(root)
        window = None if live_window is None else clock._validate(live_window)
        deadline = transport_deadline_ns
        inherited = planner_bootstrap._processing(window, deadline, work)
        inherited()
        envelope = codec._decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed activation authorizer bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("activation authorizer payload is not an exact object")
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
        custody, current_raw, grant_raw, caller_raw, enrolled, grant, live = _admit_payload(
            payload, custody_original, root, window, deadline, work, current)
        admitted = custody.planner
        material = _AuthorizerMaterial(original, custody_original, custody, payload["receiverIdentity"],
            admitted.configuration_payload, admitted.generation, admitted.runtime_role_identities,
            admitted.configuration_digest, admitted.runtime_closure_digest, current_raw, grant_raw, caller_raw,
            admitted.planner_public_key, root, grant.authorizer_public_key, payload["authorizerSpkiDigest"],
            payload["authorizerMeasurementDigest"], payload["databaseId"], payload["generationDigest"],
            enrolled.payload["maximumAgeNs"], enrolled.payload["maximumClockSkewNs"], interval, opening, payload["launch"])
        codec._canonical(original, envelope, work)
        live()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationExecutionAuthorizerBootstrapError):
            raise
        raise OidcSessionActivationExecutionAuthorizerBootstrapError("activation authorizer bootstrap admission failed") from exc


def _produce_on_work(*, payload, custody_bytes, root_private_key, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Sign an independently established role launch, never synthesize authority."""
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
        if isinstance(exc, OidcSessionActivationExecutionAuthorizerBootstrapError):
            raise
        raise OidcSessionActivationExecutionAuthorizerBootstrapError("activation authorizer bootstrap production failed") from exc
