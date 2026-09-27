"""Dedicated caller delegation and original registration-execution requests.

This purpose is NOT the existing enrollment grant for evidence signing. The
independent root must enroll a separate caller key and approve its identity,
configuration and audience. An actual authenticated application must issue the
request from genuine original signer replay; this verifier cannot prove that
the caller authenticated a human or protected its key.

All verification consumes original signatures on the caller's cumulative work.
Returned material is ordinary same-call data, never an input capability. The
grant producer must still join the actual plan's request identities BEFORE
signing. No cold process, transport, replay store, reservation, SQL permission,
public route, key provisioning or replacement work allowance is supplied here.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from serverware import authority_successor_execution_grant as grants
from serverware import authority_webauthn_evidence_plan_clock as clock


authorization, capture, plan, shape = (
    grants.authorization, grants.capture, grants.plan, grants.shape)
keys, production = grants.keys, authorization.production
OPERATION = "webauthn.registration.evidence.admit"
PURPOSE = "authorize-registration-evidence-execution"
ENROLLMENT_SCHEMA = "serverware.signedPolicyAuthorityRegistrationExecutionAuthorizationEnrollment/v1"
ENROLLMENT_PAYLOAD_SCHEMA = "serverware.policyAuthorityRegistrationExecutionAuthorizationEnrollment/v1"
ENROLLMENT_IDENTITY_DOMAIN = "serverware.policyAuthorityRegistrationExecutionAuthorizationEnrollmentIdentity/v1"
REQUEST_SCHEMA = "serverware.signedPolicyAuthorityRegistrationExecutionAuthorization/v1"
REQUEST_PAYLOAD_SCHEMA = "serverware.policyAuthorityRegistrationExecutionAuthorization/v1"
REQUEST_IDENTITY_DOMAIN = "serverware.policyAuthorityRegistrationExecutionAuthorizationIdentity/v1"
MAX_ENROLLMENT_BYTES = 16 * 1024
MAX_AUTHORIZATION_BYTES = MAX_BYTES = 64 * 1024
MAX_NODES, MAX_DEPTH = 4096, 6
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_COMMON = frozenset({"schema", "sourceRevision", "purpose", "operation",
    "configurationDigest", "databaseId", "generationDigest", "currentRootEnrollmentDigest",
    "grantEnrollmentDigest", "callerId", "audienceSpkiDigest"})
ENROLLMENT_FIELDS = _COMMON | frozenset({"callerKey", "maximumAgeNs", "maximumClockSkewNs"})
REQUEST_FIELDS = _COMMON | frozenset({"authorizationEnrollmentDigest", "callerMeasurementDigest",
    "requestDigest", "operationId", "authorizationId", "issuedAtEpochNs", "expiresAtEpochNs"})
_KEY_FIELDS = frozenset({"publicKeyPem", "spkiDigest", "measurementDigest"})
_SCOPE_FIELDS = ("configurationDigest", "databaseId", "generationDigest",
    "currentRootEnrollmentDigest", "grantEnrollmentDigest", "callerId", "audienceSpkiDigest")


class RegistrationExecutionAuthorizationError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Enrollment:
    payload: dict
    enrollment_digest: str
    caller_public_key: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedAuthorization:
    request_digest: str
    operation_id: str
    authorization_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple
    deadline_ns: int
    last_epoch_ns: int
    last_monotonic_ns: int


def _common(payload, schema):
    shape._literal(payload["schema"], schema)
    shape._literal(payload["sourceRevision"], grants.authority.SOURCE_REVISION)
    shape._literal(payload["purpose"], PURPOSE)
    shape._literal(payload["operation"], OPERATION)
    for name in ("configurationDigest", "generationDigest", "currentRootEnrollmentDigest",
            "grantEnrollmentDigest", "audienceSpkiDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    authorization._token(payload["callerId"])


def _enrollment_shape(payload):
    shape._object(payload, ENROLLMENT_FIELDS, "registration execution caller enrollment")
    _common(payload, ENROLLMENT_PAYLOAD_SCHEMA)
    shape._object(payload["callerKey"], _KEY_FIELDS, "registration execution caller key")
    record = payload["callerKey"]
    pem = record["publicKeyPem"]
    if (type(pem) is not str or not 1 <= len(pem) <= authorization.MAX_PEM_BYTES
            or not pem.isascii() or "\x00" in pem):
        raise RegistrationExecutionAuthorizationError("caller public key is not bounded ASCII PEM")
    shape._digest(record["spkiDigest"])
    shape._digest(record["measurementDigest"])
    shape._integer(payload["maximumAgeNs"], grants.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(payload["maximumClockSkewNs"], grants.authority.VERIFIER_MAX_CLOCK_SKEW_NS)


def _request_shape(payload):
    shape._object(payload, REQUEST_FIELDS, "registration execution authorization")
    _common(payload, REQUEST_PAYLOAD_SCHEMA)
    for name in ("authorizationEnrollmentDigest", "callerMeasurementDigest", "requestDigest", "operationId"):
        shape._digest(payload[name])
    identifier = payload["authorizationId"]
    shape._text(identifier, 43, minimum=43)
    shape._base64url(identifier)
    # Exact canonical raw32 encoding; its all-zero spelling is source fixed.
    if identifier == "A" * 43:
        raise RegistrationExecutionAuthorizationError("request authorization identity is zero")
    authorization._interval(payload, grants.authority.VERIFIER_RESPONSE_MAX_AGE_NS)


def _selection(enrollment):
    if type(enrollment) is not bool:
        raise RegistrationExecutionAuthorizationError("authorization purpose is not source fixed")
    return ((ENROLLMENT_SCHEMA, MAX_ENROLLMENT_BYTES, _enrollment_shape) if enrollment
        else (REQUEST_SCHEMA, MAX_AUTHORIZATION_BYTES, _request_shape))


def _unchanged(raw, envelope, maximum, work):
    authorization.capability._canonical(raw, envelope,
        capture._SharedLedger(work), maximum, MAX_NODES)


def _read(raw, *, enrollment, work):
    schema, maximum, validate = _selection(enrollment)
    authorization._original(raw, maximum, "registration execution original")
    decoded = grants.wire._decode_object(raw, work=work, maximum_bytes=maximum,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    shape._object(decoded, _ENVELOPE_FIELDS, "registration execution signed envelope")
    shape._literal(decoded["schema"], schema)
    shape._base64url(decoded["signatureBase64Url"], signature=True)
    validate(decoded["payload"])
    owned = grants._Capture(capture._SharedLedger(work), maximum_bytes=maximum).visit(decoded)
    _unchanged(raw, owned, maximum, work)
    return owned


def _signature(envelope, public_key, maximum, work):
    authorization._public(public_key)
    ledger = capture._SharedLedger(work)
    payload = authorization.capability._wire(envelope["payload"], ledger, maximum, MAX_NODES)
    authorization.capability._signature(public_key, envelope["signatureBase64Url"],
        envelope["schema"], payload, ledger)


def _base(*, current_root_enrollment_bytes, grant_enrollment_bytes,
        root_public_key, planner_public_key, evidence_public_key, work):
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    grant_raw = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "successor grant enrollment")
    held_keys = root_public_key, planner_public_key, evidence_public_key
    for key in held_keys:
        authorization._public(key)
    # Existing genuine admission establishes each original independently on
    # this same work. No stored successful enrollment is accepted as input.
    current = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
        root_public_key=held_keys[0], work=work)
    grant = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=held_keys[0], work=work)
    forbidden = (held_keys[0], current.computation_public_key, current.completion_public_key,
        current.state_public_key, grant.authorizer_public_key, held_keys[1], held_keys[2])
    return current, grant, forbidden


def _separate(caller_key, forbidden, work):
    caller_spki = keys._spki_on_work(caller_key, work)
    for other in forbidden:
        other_spki = keys._spki_on_work(other, work)
        work.prepare_comparison(caller_spki, other_spki)
        if caller_spki == other_spki:
            raise RegistrationExecutionAuthorizationError("caller key reuses an authority or plan/evidence key")
    return caller_spki


def _admit_enrollment_on_work(*, authorization_enrollment_bytes, current_root_enrollment_bytes,
        grant_enrollment_bytes, root_public_key, configuration_digest,
        planner_public_key, evidence_public_key, work):
    raw = authorization._original(authorization_enrollment_bytes,
        MAX_ENROLLMENT_BYTES, "registration execution caller enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    grant_raw = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "successor grant enrollment")
    config = configuration_digest
    shape._digest(config)
    root, planner, evidence = root_public_key, planner_public_key, evidence_public_key
    envelope = _read(raw, enrollment=True, work=work)
    _signature(envelope, root, MAX_ENROLLMENT_BYTES, work)
    current, grant, forbidden = _base(current_root_enrollment_bytes=current_raw,
        grant_enrollment_bytes=grant_raw, root_public_key=root,
        planner_public_key=planner, evidence_public_key=evidence, work=work)
    payload = envelope["payload"]
    for name, expected in (("configurationDigest", config),
            ("databaseId", current.payload["databaseId"]),
            ("generationDigest", current.payload["generationDigest"]),
            ("currentRootEnrollmentDigest", current.enrollment_digest),
            ("grantEnrollmentDigest", grant.enrollment_digest),
            ("audienceSpkiDigest", grant.payload["authorizer"]["spkiDigest"])):
        plan._same(payload[name], expected, work, "registration execution enrollment " + name)
    caller = authorization._role_key(payload["callerKey"], work)
    _separate(caller, forbidden, work)
    _unchanged(raw, envelope, MAX_ENROLLMENT_BYTES, work)
    identity = plan._frame(ENROLLMENT_IDENTITY_DOMAIN, (raw,), work)
    return _Enrollment(payload, identity, caller)


def _produce_enrollment_on_work(*, current_root_enrollment_bytes, grant_enrollment_bytes,
        root_private_key, root_public_key, configuration_digest, caller_public_key,
        caller_measurement_digest, caller_id, planner_public_key, evidence_public_key,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Root delegates one purpose; supplied identity/config provenance is external."""
    root_private, root, caller = root_private_key, root_public_key, caller_public_key
    config, measurement, identity = configuration_digest, caller_measurement_digest, caller_id
    age, skew = maximum_age_ns, maximum_clock_skew_ns
    authorization._private(root_private)
    authorization._public(caller)
    shape._digest(config)
    shape._digest(measurement)
    authorization._token(identity)
    shape._integer(age, grants.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(skew, grants.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    current, grant, forbidden = _base(current_root_enrollment_bytes=current_root_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, root_public_key=root,
        planner_public_key=planner_public_key, evidence_public_key=evidence_public_key, work=work)
    spki = _separate(caller, forbidden, work)
    work.charge(input_bytes=authorization.MAX_PEM_BYTES)
    pem = production._callback(work, lambda: caller.public_bytes(
        authorization.Encoding.PEM, authorization.PublicFormat.SubjectPublicKeyInfo))
    if type(pem) is not bytes or not 1 <= len(pem) <= authorization.MAX_PEM_BYTES or not pem.isascii():
        raise RegistrationExecutionAuthorizationError("caller key did not export bounded canonical PEM")
    work.charge(input_bytes=len(pem))
    payload = {"schema": ENROLLMENT_PAYLOAD_SCHEMA, "sourceRevision": grants.authority.SOURCE_REVISION,
        "purpose": PURPOSE, "operation": OPERATION, "configurationDigest": config,
        "databaseId": current.payload["databaseId"], "generationDigest": current.payload["generationDigest"],
        "currentRootEnrollmentDigest": current.enrollment_digest, "grantEnrollmentDigest": grant.enrollment_digest,
        "callerId": identity, "callerKey": {"publicKeyPem": pem.decode("ascii"),
            "spkiDigest": spki, "measurementDigest": measurement},
        "audienceSpkiDigest": grant.payload["authorizer"]["spkiDigest"],
        "maximumAgeNs": age, "maximumClockSkewNs": skew}
    _enrollment_shape(payload)
    authorization._role_key(payload["callerKey"], work)
    from serverware import authority_registration_execution_signing as signing
    return signing._sign(payload=payload, private_key=root_private, public_key=root,
        enrollment=True, work=work)


def _sign_request_on_work(*, payload, private_key, public_key, work):
    """Fixed private suffix; the actual original-replay producer owns admission."""
    from serverware import authority_registration_execution_signing as signing
    return signing._sign(payload=payload, private_key=private_key, public_key=public_key,
        enrollment=False, work=work)


def _verify_on_work(*, authorization_bytes, authorization_enrollment_bytes,
        current_root_enrollment_bytes, grant_enrollment_bytes, root_public_key,
        configuration_digest, planner_public_key, evidence_public_key,
        deadline_epoch_ns, work, transport_deadline_ns=None):
    """Verify a NEW caller purpose; a grant/plan digest is never substituted."""
    capture._SharedLedger(work)
    original = authorization._original(authorization_bytes, MAX_AUTHORIZATION_BYTES,
        "registration execution request authorization")
    shape._integer(deadline_epoch_ns, minimum=1)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    deadline, inherited = deadline_epoch_ns, transport_deadline_ns
    # Retain independent immutable originals/pins before any native callbacks.
    enrollment_raw = authorization._original(authorization_enrollment_bytes,
        MAX_ENROLLMENT_BYTES, "registration execution caller enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    grant_raw = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "successor grant enrollment")
    root, planner, evidence, config = root_public_key, planner_public_key, evidence_public_key, configuration_digest
    envelope = _read(original, enrollment=False, work=work)
    material = _admit_enrollment_on_work(authorization_enrollment_bytes=enrollment_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=config,
        planner_public_key=planner, evidence_public_key=evidence, work=work)
    policy = material.payload
    _signature(envelope, material.caller_public_key, MAX_AUTHORIZATION_BYTES, work)
    payload = envelope["payload"]
    for name in _SCOPE_FIELDS:
        plan._same(payload[name], policy[name], work, "registration execution request " + name)
    plan._same(payload["authorizationEnrollmentDigest"], material.enrollment_digest, work,
        "registration execution request caller enrollment")
    plan._same(payload["callerMeasurementDigest"], policy["callerKey"]["measurementDigest"], work,
        "registration execution request caller measurement")
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    maximum_age, skew = policy["maximumAgeNs"], policy["maximumClockSkewNs"]
    authorization._interval(payload, maximum_age)
    window = clock._open_on_work(deadline_epoch_ns=min(deadline, expires),
        maximum_lifetime_ns=maximum_age, maximum_clock_skew_ns=skew, work=work)
    bound = window[4] if inherited is None else min(window[4], inherited)
    last_epoch, last_monotonic = window[0], window[2]

    def live():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < last_epoch or monotonic < last_monotonic or monotonic >= bound
                or issued > now + skew or now - issued > maximum_age or now >= expires):
            raise RegistrationExecutionAuthorizationError("request authorization expired or its original clocks reversed")
        last_epoch, last_monotonic = now, monotonic

    live()
    operation_id = plan._frame("serverware.policyAuthorityOperation/v2",
        (OPERATION.encode("ascii"), payload["requestDigest"].encode("ascii")), work)
    plan._same(payload["operationId"], operation_id, work,
        "registration execution request actual operation identity")
    identity = plan._frame(REQUEST_IDENTITY_DOMAIN, (original,), work)
    _unchanged(original, envelope, MAX_AUTHORIZATION_BYTES, work)
    live()
    return _VerifiedAuthorization(payload["requestDigest"], operation_id, identity,
        issued, expires, window, bound, last_epoch, last_monotonic)
