"""Closed opt-in caller-key scope for the v3 control-plane cold bootstrap.

The parent authenticates the complete original v3 envelope under its already
admitted runtime root. This module additionally authenticates all three actual
enrollment originals and joins their caller/configuration/generation/key scope.
It does not deliver descriptors, read private keys, authenticate an actor,
issue permission or open a transport. Returned material is owned data only.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_registration_execution_authorization as caller
from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_evidence_policy as evidence_policy


SCHEMA = "serverware.controlPlaneRegistrationExecution/v1"
CALLER_KEY_FD = 203
AUTHORIZER_SOCKET_PATH = "/run/serverware/registration-execution/authorizer.sock"
_FIELDS = frozenset({"schema", "executionCallerPrivateKeyFd", "currentRootEnrollment",
    "grantEnrollment", "authorizationEnrollment", "authorizerEndpoint"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", caller.authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", caller.grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
shape, capture, plan = caller.shape, caller.capture, caller.plan


class RegistrationExecutionBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ExecutionMaterial:
    caller_private_key_fd: int
    caller_public_key: object
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    authorizer_endpoint: tuple


def _endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "registration execution authorizer endpoint")
    shape._literal(value["socketPath"], AUTHORIZER_SOCKET_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerUid", "listenerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            raise RegistrationExecutionBootstrapError("authorizer listener must retain the fixed root peer identity")
    # This pins the system manager's listen() identity, not the accepting child.
    return value["socketPath"], value["requestTimeoutSeconds"], 0, 0


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane registration execution scope")
    shape._literal(value["schema"], SCHEMA)
    shape._integer(value["executionCallerPrivateKeyFd"], 1023, minimum=32)
    if value["executionCallerPrivateKeyFd"] != CALLER_KEY_FD:
        raise RegistrationExecutionBootstrapError("registration execution caller key FD is not source fixed")
    for name, maximum in _ORIGINAL_LIMITS:
        original = value[name]
        shape._object(original, _ORIGINAL_FIELDS, "registration execution enrollment original")
        caller.authorization.transport._transport_shape(
            original["base64Url"], original["byteCount"], maximum)
    _endpoint(value["authorizerEndpoint"])


def _admit_on_work(*, registration_execution, configuration_payload,
        configuration_digest, generation, runtime_role_identities,
        runtime_root_public_key, issuer_public_key, work):
    """Authenticate actual original enrollments on the parent's existing work."""
    try:
        ledger = capture._SharedLedger(work)
        _shape(registration_execution)
        if registration_execution is None:
            return None
        root, issuer, digest = runtime_root_public_key, issuer_public_key, configuration_digest
        caller.authorization._public(root)
        caller.authorization._public(issuer)
        shape._digest(digest)
        shape._bounded_object(generation, 24, "execution caller launch context")
        # Own all mutable graphs before any genuine key/hash callback.
        owned = configuration._ConfigurationCapture(ledger,
            maximum_bytes=caller.grants.authority.MAX_REQUEST_BYTES).visit({
                "execution": registration_execution, "configuration": configuration_payload,
                "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
                "runtime": runtime_role_identities})
        value, configured = owned["execution"], owned["configuration"]
        _shape(value)
        mapped = enrollment_policy._capture_on_work(payload=configured,
            configuration_digest=digest, generation=owned["generation"],
            runtime_role_identities=owned["runtime"], work=work)
        plan._same(caller.keys._spki_on_work(issuer, work), mapped.policy["signingSpkiDigest"],
            work, "execution caller bootstrap differs from the actual enrollment issuer key")
        purposes, evidence_keys = evidence_policy._validate_policy_on_work(
            configured.get(evidence_policy.FIELD), webauthn=configured["webauthn"], work=work)
        if purposes["registration"] is None:
            raise RegistrationExecutionBootstrapError("registration evidence purpose is disabled")
        roles = configured["roles"]
        shape._object(roles, frozenset(configuration._ROLE_NAMES), "execution caller configured roles")
        planner = configuration._key(roles["planner"]["signingPublicKeyBase64Url"], work,
            expected_spki=roles["planner"]["signingSpkiDigest"])
        originals = tuple(caller.authorization.transport._decode(
            value[name]["base64Url"], value[name]["byteCount"], maximum, work)
            for name, maximum in _ORIGINAL_LIMITS)
        current_raw, grant_raw, authorization_raw = originals
        admitted = caller._admit_enrollment_on_work(authorization_enrollment_bytes=authorization_raw,
            current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
            root_public_key=root, configuration_digest=digest, planner_public_key=planner,
            evidence_public_key=evidence_keys["registration"], work=work)
        plan._same(admitted.payload["generationDigest"], mapped.generation_digest, work,
            "execution caller enrollment generation differs from actual configuration")
        caller_pin = admitted.payload["callerKey"]["spkiDigest"]
        forbidden = [mapped.policy["signingSpkiDigest"]]
        for name in configuration._ROLE_NAMES:
            role = roles[name]
            shape._digest(role["responseSigningSpkiDigest"])
            forbidden.append(role["responseSigningSpkiDigest"])
            if name in ("verifier", "planner"):
                shape._digest(role["signingSpkiDigest"])
                forbidden.append(role["signingSpkiDigest"])
        for name in ("registration", "installation"):
            if purposes[name] is not None:
                forbidden.append(purposes[name]["signingSpkiDigest"])
        transitions = configured.get(enrollment_policy.transition_policy.FIELD)
        if transitions is not None:
            for name in ("registration", "stage", "completion"):
                if transitions[name] is not None:
                    forbidden.append(transitions[name]["signingSpkiDigest"])
        work.prepare_scan(forbidden)
        for pin in forbidden:
            work.prepare_comparison(caller_pin, pin)
            if caller_pin == pin:
                raise RegistrationExecutionBootstrapError("execution caller key reuses another configured purpose")
        return _ExecutionMaterial(CALLER_KEY_FD, admitted.caller_public_key, current_raw,
            grant_raw, authorization_raw, _endpoint(value["authorizerEndpoint"]))
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RegistrationExecutionBootstrapError):
            raise
        raise RegistrationExecutionBootstrapError("registration execution caller bootstrap admission failed") from exc
