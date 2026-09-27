"""Explicit finalization-only caller scope inside root-signed parent v4.

The parent admits the complete original envelope and configuration. This
module then admits the three original enrollments for the dedicated finalization
purpose, its configured transition key and a separate caller public key. No
evidence-execution enrollment, key, endpoint or permission is substituted.
Returned material is private owned data, not present-caller authorization.
No key generation, descriptor access, transport or replacement work occurs here.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_registration_finalization_authorization as caller
from serverware import authority_revocation_configuration as configuration
from serverware import authority_revocation_writer_acknowledgment as keys
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_transition_custody_configuration as transition


SCHEMA = "serverware.controlPlaneRegistrationFinalization/v1"
CALLER_KEY_FD = 204
AUTHORIZER_SOCKET_PATH = "/run/serverware/registration-finalization-authorizer.sock"
_FIELDS = frozenset({"schema", "finalizationCallerPrivateKeyFd", "currentRootEnrollment",
    "grantEnrollment", "authorizationEnrollment", "authorizerEndpoint"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", caller.authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", caller.grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
shape, capture, plan = caller.shape, caller.capture, caller.plan


class RegistrationFinalizationBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _FinalizationMaterial:
    caller_private_key_fd: int
    caller_public_key: object
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    authorizer_endpoint: tuple


def _endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "registration finalization authorizer endpoint")
    shape._literal(value["socketPath"], AUTHORIZER_SOCKET_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerUid", "listenerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            raise RegistrationFinalizationBootstrapError("finalization listener must retain the fixed root peer")
    # The peer identifies the socket activator, not the later signing process.
    return value["socketPath"], value["requestTimeoutSeconds"], 0, 0


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane registration finalization scope")
    shape._literal(value["schema"], SCHEMA)
    shape._integer(value["finalizationCallerPrivateKeyFd"], 1023, minimum=32)
    if value["finalizationCallerPrivateKeyFd"] != CALLER_KEY_FD:
        raise RegistrationFinalizationBootstrapError("finalization caller key FD is not source fixed")
    for name, maximum in _ORIGINAL_LIMITS:
        original = value[name]
        shape._object(original, _ORIGINAL_FIELDS, "registration finalization enrollment original")
        caller.authorization.transport._transport_shape(
            original["base64Url"], original["byteCount"], maximum)
    _endpoint(value["authorizerEndpoint"])


def _admit_on_work(*, registration_finalization, configuration_payload,
        configuration_digest, generation, runtime_role_identities,
        runtime_root_public_key, issuer_public_key, execution_caller_public_key, work):
    """Authenticate finalization originals using only the parent's existing work."""
    try:
        ledger = capture._SharedLedger(work)
        _shape(registration_finalization)
        if registration_finalization is None:
            return None
        root, issuer, prior, digest = (runtime_root_public_key, issuer_public_key,
            execution_caller_public_key, configuration_digest)
        caller.authorization._public(root)
        caller.authorization._public(issuer)
        if prior is not None:
            caller.authorization._public(prior)
        shape._digest(digest)
        shape._bounded_object(generation, 24, "finalization caller launch context")
        # Detach every mutable graph before key/hash/native callbacks.
        owned = configuration._ConfigurationCapture(ledger,
            maximum_bytes=caller.grants.authority.MAX_REQUEST_BYTES).visit({
                "finalization": registration_finalization, "configuration": configuration_payload,
                "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
                "runtime": runtime_role_identities})
        value, configured = owned["finalization"], owned["configuration"]
        _shape(value)
        mapped = enrollment_policy._capture_on_work(payload=configured,
            configuration_digest=digest, generation=owned["generation"],
            runtime_role_identities=owned["runtime"], work=work)
        plan._same(keys._spki_on_work(issuer, work), mapped.policy["signingSpkiDigest"],
            work, "finalization caller differs from the actual enrollment issuer")
        configured_transition = transition._capture_on_work(operation=caller.OPERATION,
            payload=configured, configuration_digest=digest, generation=owned["generation"],
            runtime_role_identities=owned["runtime"], work=work)
        current_raw, grant_raw, authorization_raw = tuple(caller.authorization.transport._decode(
            value[name]["base64Url"], value[name]["byteCount"], maximum, work)
            for name, maximum in _ORIGINAL_LIMITS)
        admitted = caller._admit_enrollment_on_work(authorization_enrollment_bytes=authorization_raw,
            current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
            root_public_key=root, configuration_digest=digest,
            planner_public_key=configured_transition.pins[1],
            evidence_public_key=configured_transition.pins[4], work=work)
        plan._same(admitted.payload["generationDigest"], mapped.generation_digest, work,
            "finalization caller enrollment differs from the actual configured generation")
        caller_pin = admitted.payload["callerKey"]["spkiDigest"]
        forbidden = [mapped.policy["signingSpkiDigest"]]
        if prior is not None:
            forbidden.append(keys._spki_on_work(prior, work))
        roles = configured["roles"]
        shape._object(roles, frozenset(configuration._ROLE_NAMES), "finalization caller configured roles")
        for name in configuration._ROLE_NAMES:
            role = roles[name]
            shape._digest(role["responseSigningSpkiDigest"])
            forbidden.append(role["responseSigningSpkiDigest"])
            if name in ("verifier", "planner"):
                shape._digest(role["signingSpkiDigest"])
                forbidden.append(role["signingSpkiDigest"])
        for field, names in ((enrollment_policy.evidence_policy.FIELD, ("registration", "installation")),
                (enrollment_policy.transition_policy.FIELD, ("registration", "stage", "completion"))):
            purposes = configured.get(field)
            if purposes is not None:
                for name in names:
                    if purposes[name] is not None:
                        shape._digest(purposes[name]["signingSpkiDigest"])
                        forbidden.append(purposes[name]["signingSpkiDigest"])
        work.prepare_scan(forbidden)
        for pin in forbidden:
            work.prepare_comparison(caller_pin, pin)
            if caller_pin == pin:
                raise RegistrationFinalizationBootstrapError("finalization caller key reuses another configured purpose")
        return _FinalizationMaterial(CALLER_KEY_FD, admitted.caller_public_key,
            current_raw, grant_raw, authorization_raw, _endpoint(value["authorizerEndpoint"]))
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RegistrationFinalizationBootstrapError):
            raise
        raise RegistrationFinalizationBootstrapError("registration finalization caller bootstrap admission failed") from exc
