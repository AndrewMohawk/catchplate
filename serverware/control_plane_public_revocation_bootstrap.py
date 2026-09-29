"""Public passkey-revocation scope admitted only inside signed cold v23.

Original root/current/grant/caller enrollments and actual measured role keys
remain independent. This module grants no present HTTP request permission.
The existing authority sockets are taken from the authenticated configuration,
not this scope or a browser. Only the current-root socket has a fixed additional
pin. A nullable disabled scope still reserves the dedicated caller descriptor.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_public_revocation_caller_authorization as caller
from serverware import authority_public_webauthn_revocation as aggregate
from serverware import authority_revocation_verifier as verifier


SCHEMA = "serverware.controlPlanePublicWebAuthnRevocation/v1"
CALLER_KEY_FD = 208
STATE_SOCKET_PATH = "/run/serverware/current-root/state.sock"
FIELDS = frozenset({"schema", "callerPrivateKeyFd", "currentRootEnrollment", "grantEnrollment",
    "authorizationEnrollment", "stateEndpoint", "mutationPolicy"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "serviceUid", "serviceGid",
    "listenerUid", "listenerGid"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", caller.authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", caller.grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
shape, plan, capture = caller.shape, caller.plan, caller.capture


class PublicRevocationBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PublicRevocationMaterial:
    caller_private_key_fd: int
    caller_public_key: object
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    state_endpoint: tuple
    mutation_policy: dict


def _endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "public revocation current-root endpoint")
    shape._literal(value["socketPath"], STATE_SOCKET_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name, expected in (("serviceUid", 65516), ("serviceGid", 65516),
            ("listenerUid", 0), ("listenerGid", 0)):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != expected:
            raise PublicRevocationBootstrapError("public revocation state endpoint is not source fixed")
    return value["socketPath"], value["requestTimeoutSeconds"], 0, 0


def _shape(value):
    if value is None:
        return
    shape._object(value, FIELDS, "public revocation cold scope")
    shape._literal(value["schema"], SCHEMA)
    shape._integer(value["callerPrivateKeyFd"], 1023, minimum=32)
    if value["callerPrivateKeyFd"] != CALLER_KEY_FD:
        raise PublicRevocationBootstrapError("public revocation caller descriptor is not source fixed")
    for name, maximum in _ORIGINAL_LIMITS:
        original = value[name]
        shape._object(original, _ORIGINAL_FIELDS, "public revocation enrollment original")
        caller.authorization.transport._transport_shape(original["base64Url"], original["byteCount"], maximum)
    _endpoint(value["stateEndpoint"])
    aggregate.policy_shape(value["mutationPolicy"])


def _admit_on_work(*, public_revocation, configuration_payload, configuration_digest,
        generation, runtime_role_identities, runtime_root_public_key, work):
    """Join the three exact enrollments to the actual admitted role keys."""
    ledger = capture._SharedLedger(work)
    _shape(public_revocation)
    if public_revocation is None:
        return None
    root = runtime_root_public_key
    caller.authorization._public(root)
    captured = verifier.configuration._ConfigurationCapture(ledger,
        maximum_bytes=caller.grants.authority.MAX_REQUEST_BYTES).visit({"scope": public_revocation,
        "configuration": configuration_payload, "generation": generation, "runtime": runtime_role_identities})
    owned = captured["scope"]
    configured = verifier._verifier_from_configuration_on_work(payload=captured["configuration"],
        configuration_digest=configuration_digest, generation=captured["generation"],
        runtime_role_identities=captured["runtime"], work=work)
    pins = verifier.RevocationPlanVerifier._snapshot_configuration(configured)
    current_raw, grant_raw, authorization_raw = tuple(caller.authorization.transport._decode(
        owned[name]["base64Url"], owned[name]["byteCount"], maximum, work)
        for name, maximum in _ORIGINAL_LIMITS)
    enrolled = caller._admit_enrollment_on_work(authorization_enrollment_bytes=authorization_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=configuration_digest,
        planner_public_key=pins[0], evidence_public_key=pins[1], work=work)
    current = caller.authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
        root_public_key=root, work=work)
    grant = caller.grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        root_public_key=root, current_root_enrollment_bytes=current_raw, work=work)
    # An original signed by an otherwise valid independent producer is not
    # permission to substitute it for these actual cold authority processes.
    roles, runtime = captured["configuration"]["roles"], captured["runtime"]
    for authority_name, role_name in (("computation", "verifier"), ("completion", "executor")):
        role = roles[role_name]
        for field, expected in (("spkiDigest", role["responseSigningSpkiDigest"]),
                ("measurementDigest", runtime["roles"][role_name]["measurementDigest"])):
            plan._same(current.payload[authority_name][field], expected, work,
                "public revocation current-root role differs from the actual measured authority")
    for field, expected in (("spkiDigest", roles["issuer"]["responseSigningSpkiDigest"]),
            ("measurementDigest", runtime["roles"]["issuer"]["measurementDigest"])):
        plan._same(grant.payload["authorizer"][field], expected, work,
            "public revocation authorizer differs from the actual measured issuer")
    plan._same(enrolled.payload["generationDigest"], pins[9], work,
        "public revocation enrollment differs from the actual generation")
    plan._same(enrolled.payload["mutationPolicy"], owned["mutationPolicy"], work,
        "public revocation policy differs from its independent caller enrollment")
    forbidden = tuple(roles[name]["responseSigningSpkiDigest"] for name in verifier.configuration._ROLE_NAMES)
    for digest in forbidden:
        shape._digest(digest)
        work.prepare_comparison(enrolled.payload["callerKey"]["spkiDigest"], digest)
        if enrolled.payload["callerKey"]["spkiDigest"] == digest:
            raise PublicRevocationBootstrapError("public revocation caller key reuses an authority role")
    return _PublicRevocationMaterial(CALLER_KEY_FD, enrolled.caller_public_key,
        current_raw, grant_raw, authorization_raw, _endpoint(owned["stateEndpoint"]), owned["mutationPolicy"])
