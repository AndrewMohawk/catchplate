"""Root-authenticated cold scope for the fixed finalization grant authorizer.

The root provisioner independently admits configuration, generation, runtime
provenance, purpose enrollments and actual listener identities. This verifier
authenticates their original bytes and genuine existing configuration mapper;
matching claims do not manufacture those external prerequisites. The signed
assurance is explicitly trusted-host-local, never hardware or witness proof.

Only the separately provisioned successor-grant authorizer private key belongs
in this service. Returned material is ordinary same-call data, not an accepted
admission token. No private key, descriptor, listener, directory, clock override,
request authorization, reserve, replay store, one-use decision or new work
allowance is created. The original launch interval is never renewed.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import control_plane_enrollment_bootstrap as codec
from serverware import current_root_state_bootstrap as state_bootstrap
from serverware import registration_evidence_signer_bootstrap as signing
from serverware import authority_registration_finalization_authorization as caller
from serverware import authority_webauthn_transition_custody_configuration as custody_configuration
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_evidence_policy as evidence_policy
from serverware.authority_local_limits import LOCAL_SESSION_MAX_NS


authority, configuration = codec.authority, codec.configuration
capability, capture, plan = codec.capability, codec.capture, codec.plan
authorization, grants, shape = caller.authorization, caller.grants, caller.shape
ROLE = PROCESS_MODE = "registration-finalization-authorizer"
SERVICE_UID = SERVICE_GID = 65511
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD = 198, 199, 200, 201
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD)
LISTENER_PATH = "/run/serverware/registration-finalization-authorizer.sock"
MAX_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_AGE_NS = LOCAL_SESSION_MAX_NS
SCHEMA = "serverware.signedRegistrationFinalizationAuthorizerBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.registrationFinalizationAuthorizerBootstrap/v1"
LAUNCH_SCHEMA = "serverware.registrationFinalizationAuthorizerLaunch/v1"
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest", "identityDigest"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
_FALSE_FIELDS = ("hardwareBacked", "nativeStageZero", "hsmBackedKeys", "teeVerified",
    "externalWitnessVerified")
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "configurationPayload",
    "configurationDigest", "generation", "runtimeRoleIdentities", "currentRootEnrollment",
    "grantEnrollment", "authorizationEnrollment", "databaseId", "generationDigest",
    "authorizerSpkiDigest", "authorizerMeasurementDigest", "runtimeClosureDigest",
    "issuedAtEpochNs", "expiresAtEpochNs", "trustMode", "launch", *_FALSE_FIELDS})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid",
    "peerGid", "rootPublicKeyFd", "bootstrapFd", "listenerFd", "signingKeyFd",
    "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds", "listenerSocketDevice",
    "listenerSocketInode", "listenerPathDevice", "listenerPathInode"})


class RegistrationFinalizationAuthorizerBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AuthorizerMaterial:
    configuration_payload: dict
    generation: dict
    runtime_role_identities: dict
    configuration_digest: str
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    planner_public_key: object
    evidence_public_key: object
    authorizer_public_key: object
    authorizer_spki_digest: str
    authorizer_measurement_digest: str
    database_id: str
    generation_digest: str
    attestation_interval: tuple
    opening_sample: tuple
    launch: dict


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "registration finalization authorizer launch")
    for name, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD),
            ("bootstrapFd", BOOTSTRAP_FD), ("listenerFd", LISTENER_FD), ("signingKeyFd", KEY_FD)):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            raise RegistrationFinalizationAuthorizerBootstrapError("authorizer fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "authorizer inherited descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work,
        "authorizer inherited descriptor inventory differs")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("listenerSocketInode", "listenerPathInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "registration finalization authorizer bootstrap")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("configurationDigest", "generationDigest", "authorizerSpkiDigest",
            "authorizerMeasurementDigest", "runtimeClosureDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    shape._object(payload["generation"], frozenset(configuration._GENERATION_FIELDS),
        "authorizer generation")
    if type(payload["configurationPayload"]) is not dict or type(payload["runtimeRoleIdentities"]) is not dict:
        raise RegistrationFinalizationAuthorizerBootstrapError("authorizer configuration and runtime are not exact data")
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "authorizer enrollment original")
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[name], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        raise RegistrationFinalizationAuthorizerBootstrapError("authorizer launch lifetime exceeds its source bound")
    if any(payload[name] is not False for name in _FALSE_FIELDS):
        raise RegistrationFinalizationAuthorizerBootstrapError("authorizer bootstrap is not trusted-host-local assurance")
    _launch_shape(payload["launch"], work)


def _fresh(interval, work, opening=None):
    """Reuse the actual bounded epoch/monotonic bracket, never a new deadline."""
    try:
        return state_bootstrap._fresh(interval, work, opening=opening)
    except (TypeError, ValueError, OverflowError) as exc:
        raise RegistrationFinalizationAuthorizerBootstrapError("authorizer original launch interval is not live") from exc


def _originals(payload, work):
    originals = []
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        raw = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
        work.charge(hashes=1, input_bytes=len(raw))
        plan._same("sha256:" + hashlib.sha256(raw).hexdigest(), record["bytesDigest"], work,
            "authorizer enrollment original bytes differ from their root pin")
        originals.append(raw)
    return tuple(originals)


def _material(payload, root_key, opening, work):
    configured, generation, runtime = (payload["configurationPayload"],
        payload["generation"], payload["runtimeRoleIdentities"])
    digest = payload["configurationDigest"]
    # The actual finalization mapper admits the configuration commitment,
    # generation/runtime cohort and explicit transition policy. No evidence-
    # admission key or enabled-purpose fallback can select this signer.
    mapped = custody_configuration._capture_on_work(operation=caller.OPERATION, payload=configured,
        configuration_digest=digest, generation=generation, runtime_role_identities=runtime, work=work)
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "authorizer configured roles")
    forbidden = []
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        shape._integer(role["serviceUid"], 2**32 - 2)
        shape._integer(role["serviceGid"], 2**32 - 2)
        if role["serviceUid"] == SERVICE_UID or role["serviceGid"] == SERVICE_GID:
            raise RegistrationFinalizationAuthorizerBootstrapError("authorizer identity is shared with a configured role")
        shape._digest(role["responseSigningSpkiDigest"])
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            shape._digest(role["signingSpkiDigest"])
            forbidden.append(role["signingSpkiDigest"])
    planner, evidence_key = mapped.pins[1], mapped.pins[4]
    current_raw, grant_raw, caller_raw = _originals(payload, work)
    caller_material = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root_key, configuration_digest=digest,
        planner_public_key=planner, evidence_public_key=evidence_key, work=work)
    grant = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root_key, work=work)
    enrolled = caller_material.payload
    authorizer = grant.payload["authorizer"]
    for actual, expected in ((payload["currentRootEnrollment"]["identityDigest"], enrolled["currentRootEnrollmentDigest"]),
            (payload["grantEnrollment"]["identityDigest"], grant.enrollment_digest),
            (payload["authorizationEnrollment"]["identityDigest"], caller_material.enrollment_digest),
            (payload["databaseId"], enrolled["databaseId"]),
            (payload["generationDigest"], enrolled["generationDigest"]),
            (payload["generationDigest"], mapped.generation_digest),
            (payload["authorizerSpkiDigest"], authorizer["spkiDigest"]),
            (payload["authorizerMeasurementDigest"], authorizer["measurementDigest"])):
        plan._same(actual, expected, work, "authorizer bootstrap differs from genuine configuration or enrollment")
    # The grant enrollment already excludes current-root authority keys. The
    # root-admitted complete configuration additionally excludes generic role
    # response/signing keys from this purpose-only service key.
    forbidden.append(enrolled["callerKey"]["spkiDigest"])
    issuer_policy = configured.get(enrollment_policy.FIELD)
    if issuer_policy is not None:
        issuer, _issuer_key = enrollment_policy._validate_policy_on_work(
            issuer_policy, payload=configured, work=work)
        forbidden.append(issuer["signingSpkiDigest"])
    evidence_purposes = configured.get(evidence_policy.FIELD)
    if evidence_purposes is not None:
        evidence_policy_value, _evidence_keys = evidence_policy._validate_policy_on_work(
            evidence_purposes, webauthn=configured["webauthn"], work=work)
        for slot in ("registration", "installation"):
            selected = evidence_policy_value[slot]
            if selected is not None:
                forbidden.append(selected["signingSpkiDigest"])
    transitions = configured.get(enrollment_policy.transition_policy.FIELD)
    if transitions is not None:
        for slot in ("registration", "stage", "completion"):
            selected = transitions[slot]
            if selected is not None:
                forbidden.append(selected["signingSpkiDigest"])
    work.prepare_scan(forbidden)
    for pin in forbidden:
        work.prepare_comparison(authorizer["spkiDigest"], pin)
        if authorizer["spkiDigest"] == pin:
            raise RegistrationFinalizationAuthorizerBootstrapError("authorizer key is shared with another configured purpose")
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    return _AuthorizerMaterial(configured, generation, runtime, digest, current_raw, grant_raw,
        caller_raw, planner, evidence_key, grant.authorizer_public_key, authorizer["spkiDigest"],
        authorizer["measurementDigest"], enrolled["databaseId"], mapped.generation_digest,
        interval, opening, payload["launch"])


def _verify_on_work(*, bootstrap_bytes, root_public_key, work):
    """Authenticate original root scope before any cold resource selection."""
    try:
        ledger = capture._SharedLedger(work)
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "authorizer bootstrap")
        root = root_public_key
        authorization._public(root)
        envelope = codec._decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "authorizer signed bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            raise RegistrationFinalizationAuthorizerBootstrapError("authorizer payload is not an exact object")
        codec._canonical(original, envelope, work)
        payload = envelope["payload"]
        unsigned = configuration._configuration_wire(payload, ledger)
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned, ledger)
        codec._canonical(original, envelope, work)
        _payload_shape(payload, work)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        material = _material(payload, root, opening, work)
        _fresh(interval, work, opening=opening)
        codec._canonical(original, envelope, work)
        return material
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, RegistrationFinalizationAuthorizerBootstrapError):
            raise
        raise RegistrationFinalizationAuthorizerBootstrapError("authorizer bootstrap admission failed") from exc


def _produce_on_work(*, payload, root_private_key, root_public_key, work):
    """Sign independently established original launch claims, not their provenance."""
    try:
        ledger = capture._SharedLedger(work)
        private, public = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(public)
        owned = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit(payload)
        _payload_shape(owned, work)
        unsigned = configuration._configuration_wire(owned, ledger)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        _material(owned, public, opening, work)
        codec._canonical(unsigned, owned, work)
        _fresh(interval, work, opening=opening)
        original = signing._sign(owned, SCHEMA, MAX_BYTES, private, public, work)
        codec._canonical(unsigned, owned, work)
        _fresh(interval, work, opening=opening)
        return original
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, RegistrationFinalizationAuthorizerBootstrapError):
            raise
        raise RegistrationFinalizationAuthorizerBootstrapError("authorizer bootstrap production failed") from exc
