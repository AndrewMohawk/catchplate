"""Verify a distinct original caller delegation for registration finalization.

Evidence-admission authorizations and enrollment-signing grants have different
schemas, purposes and signature domains and cannot enter this path. The root
must independently enroll this caller for finalization. The root enrollment
producer and fixed request-signing suffix do not provision keys, authenticate
the present actor or supply a cold owner.

Only parameter-pure original signature, root-enrollment and key-separation
primitives are shared with the evidence-execution verifier. Its fixed purpose
is never changed. The caller's existing processing window/work are retained;
original expiry and inherited deadlines only narrow them.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from catchplate import authority_registration_execution_authorization as primitives


grants, authorization, capture, plan, shape, clock = (
    primitives.grants, primitives.authorization, primitives.capture,
    primitives.plan, primitives.shape, primitives.clock)
keys, production = primitives.keys, primitives.production
OPERATION = "webauthn.registration.finalize"
PURPOSE = "authorize-registration-finalization"
ENROLLMENT_SCHEMA = "catchplate.signedPolicyAuthorityRegistrationFinalizationAuthorizationEnrollment/v1"
ENROLLMENT_PAYLOAD_SCHEMA = "catchplate.policyAuthorityRegistrationFinalizationAuthorizationEnrollment/v1"
ENROLLMENT_IDENTITY_DOMAIN = "catchplate.policyAuthorityRegistrationFinalizationAuthorizationEnrollmentIdentity/v1"
REQUEST_SCHEMA = "catchplate.signedPolicyAuthorityRegistrationFinalizationAuthorization/v1"
REQUEST_PAYLOAD_SCHEMA = "catchplate.policyAuthorityRegistrationFinalizationAuthorization/v1"
REQUEST_IDENTITY_DOMAIN = "catchplate.policyAuthorityRegistrationFinalizationAuthorizationIdentity/v1"
MAX_ENROLLMENT_BYTES = 16 * 1024
MAX_AUTHORIZATION_BYTES = 64 * 1024
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


class RegistrationFinalizationAuthorizationError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Enrollment:
    payload: dict
    enrollment_digest: str
    caller_public_key: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedAuthorization:
    """Private same-call facts; never accepted instead of original authority."""

    request_digest: str
    operation_id: str
    authorization_digest: str
    database_id: str
    generation_digest: str
    current_root_enrollment_digest: str
    grant_enrollment_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    maximum_age_ns: int
    maximum_clock_skew_ns: int
    last_epoch_ns: int
    last_monotonic_ns: int


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalAuthorization:
    """Original facts, not a live authorization or a reusable proof input."""

    request_digest: str
    operation_id: str
    authorization_digest: str
    database_id: str
    generation_digest: str
    current_root_enrollment_digest: str
    grant_enrollment_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    maximum_age_ns: int
    maximum_clock_skew_ns: int
    last_epoch_ns: int
    last_monotonic_ns: int


def _shape(payload, *, enrollment):
    shape._object(payload, ENROLLMENT_FIELDS if enrollment else REQUEST_FIELDS,
        "registration finalization authority")
    shape._literal(payload["schema"], ENROLLMENT_PAYLOAD_SCHEMA if enrollment else REQUEST_PAYLOAD_SCHEMA)
    shape._literal(payload["sourceRevision"], grants.authority.SOURCE_REVISION)
    shape._literal(payload["purpose"], PURPOSE)
    shape._literal(payload["operation"], OPERATION)
    for name in ("configurationDigest", "generationDigest", "currentRootEnrollmentDigest",
            "grantEnrollmentDigest", "audienceSpkiDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    authorization._token(payload["callerId"])
    if enrollment:
        record = payload["callerKey"]
        shape._object(record, _KEY_FIELDS, "finalization caller key")
        pem = record["publicKeyPem"]
        if (type(pem) is not str or not 1 <= len(pem) <= authorization.MAX_PEM_BYTES
                or not pem.isascii() or "\x00" in pem):
            raise RegistrationFinalizationAuthorizationError("finalization caller public key is not bounded PEM")
        shape._digest(record["spkiDigest"])
        shape._digest(record["measurementDigest"])
        shape._integer(payload["maximumAgeNs"], grants.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
        shape._integer(payload["maximumClockSkewNs"], grants.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    else:
        for name in ("authorizationEnrollmentDigest", "callerMeasurementDigest", "requestDigest", "operationId"):
            shape._digest(payload[name])
        shape._text(payload["authorizationId"], 43, minimum=43)
        shape._base64url(payload["authorizationId"])
        if payload["authorizationId"] == "A" * 43:
            raise RegistrationFinalizationAuthorizationError("finalization authorization identity is zero")
        authorization._interval(payload, grants.authority.VERIFIER_RESPONSE_MAX_AGE_NS)


def _read(raw, *, enrollment, work):
    maximum = MAX_ENROLLMENT_BYTES if enrollment else MAX_AUTHORIZATION_BYTES
    authorization._original(raw, maximum, "registration finalization authority original")
    decoded = grants.wire._decode_object(raw, work=work, maximum_bytes=maximum,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    shape._object(decoded, _ENVELOPE_FIELDS, "signed finalization authority")
    shape._literal(decoded["schema"], ENROLLMENT_SCHEMA if enrollment else REQUEST_SCHEMA)
    shape._base64url(decoded["signatureBase64Url"], signature=True)
    _shape(decoded["payload"], enrollment=enrollment)
    owned = grants._Capture(capture._SharedLedger(work), maximum_bytes=maximum).visit(decoded)
    primitives._unchanged(raw, owned, maximum, work)
    return owned


def _admit_enrollment_on_work(*, authorization_enrollment_bytes, current_root_enrollment_bytes,
        grant_enrollment_bytes, root_public_key, configuration_digest,
        planner_public_key, evidence_public_key, work):
    """Authenticate the original finalization delegation without a live request."""
    capture._SharedLedger(work)
    raw = authorization._original(authorization_enrollment_bytes, MAX_ENROLLMENT_BYTES,
        "finalization caller enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "finalization current-root enrollment")
    grant_raw = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "finalization grant enrollment")
    config, root, planner, evidence_key = (configuration_digest, root_public_key,
        planner_public_key, evidence_public_key)
    shape._digest(config)
    enrolled = _read(raw, enrollment=True, work=work)
    primitives._signature(enrolled, root, MAX_ENROLLMENT_BYTES, work)
    current, grant, forbidden = primitives._base(current_root_enrollment_bytes=current_raw,
        grant_enrollment_bytes=grant_raw, root_public_key=root,
        planner_public_key=planner, evidence_public_key=evidence_key, work=work)
    policy = enrolled["payload"]
    for name, expected in (("configurationDigest", config),
            ("databaseId", current.payload["databaseId"]), ("generationDigest", current.payload["generationDigest"]),
            ("currentRootEnrollmentDigest", current.enrollment_digest),
            ("grantEnrollmentDigest", grant.enrollment_digest),
            ("audienceSpkiDigest", grant.payload["authorizer"]["spkiDigest"])):
        plan._same(policy[name], expected, work, "finalization caller enrollment " + name)
    caller = authorization._role_key(policy["callerKey"], work)
    primitives._separate(caller, forbidden, work)
    primitives._unchanged(raw, enrolled, MAX_ENROLLMENT_BYTES, work)
    identity = plan._frame(ENROLLMENT_IDENTITY_DOMAIN, (raw,), work)
    return _Enrollment(policy, identity, caller)


def _produce_enrollment_on_work(*, current_root_enrollment_bytes, grant_enrollment_bytes,
        root_private_key, root_public_key, configuration_digest, caller_public_key,
        caller_measurement_digest, caller_id, planner_public_key, evidence_public_key,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Root delegates finalization only; identity and policy admission is external."""
    capture._SharedLedger(work)
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
    current, grant, forbidden = primitives._base(current_root_enrollment_bytes=current_root_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, root_public_key=root,
        planner_public_key=planner_public_key, evidence_public_key=evidence_public_key, work=work)
    spki = primitives._separate(caller, forbidden, work)
    work.charge(input_bytes=authorization.MAX_PEM_BYTES)
    pem = production._callback(work, lambda: caller.public_bytes(
        authorization.Encoding.PEM, authorization.PublicFormat.SubjectPublicKeyInfo))
    if type(pem) is not bytes or not 1 <= len(pem) <= authorization.MAX_PEM_BYTES or not pem.isascii():
        raise RegistrationFinalizationAuthorizationError("finalization caller key did not export bounded PEM")
    work.charge(input_bytes=len(pem))
    payload = {"schema": ENROLLMENT_PAYLOAD_SCHEMA, "sourceRevision": grants.authority.SOURCE_REVISION,
        "purpose": PURPOSE, "operation": OPERATION, "configurationDigest": config,
        "databaseId": current.payload["databaseId"], "generationDigest": current.payload["generationDigest"],
        "currentRootEnrollmentDigest": current.enrollment_digest, "grantEnrollmentDigest": grant.enrollment_digest,
        "callerId": identity, "callerKey": {"publicKeyPem": pem.decode("ascii"),
            "spkiDigest": spki, "measurementDigest": measurement},
        "audienceSpkiDigest": grant.payload["authorizer"]["spkiDigest"],
        "maximumAgeNs": age, "maximumClockSkewNs": skew}
    _shape(payload, enrollment=True)
    authorization._role_key(payload["callerKey"], work)
    from catchplate import authority_registration_finalization_signing as signing
    original = signing._sign(payload=payload, private_key=root_private, public_key=root,
        enrollment=True, work=work)
    _admit_enrollment_on_work(authorization_enrollment_bytes=original,
        current_root_enrollment_bytes=current_root_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, root_public_key=root,
        configuration_digest=config, planner_public_key=planner_public_key,
        evidence_public_key=evidence_public_key, work=work)
    return original


def _sign_request_on_work(*, payload, private_key, public_key, work):
    """Fixed private suffix; only the genuine original-replay issuer owns admission."""
    from catchplate import authority_registration_finalization_signing as signing
    return signing._sign(payload=payload, private_key=private_key, public_key=public_key,
        enrollment=False, work=work)


def _verify_on_work(*, authorization_bytes, authorization_enrollment_bytes,
        current_root_enrollment_bytes, grant_enrollment_bytes, root_public_key,
        configuration_digest, planner_public_key, evidence_public_key,
        live_window, work, transport_deadline_ns=None):
    """Authenticate the original finalization purpose on the supplied window."""
    capture._SharedLedger(work)
    original = authorization._original(authorization_bytes, MAX_AUTHORIZATION_BYTES,
        "registration finalization request authorization")
    enrollment_raw = authorization._original(authorization_enrollment_bytes,
        MAX_ENROLLMENT_BYTES, "registration finalization caller enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "finalization current-root enrollment")
    grant_raw = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "finalization grant enrollment")
    config, root, planner, evidence_key = (configuration_digest, root_public_key,
        planner_public_key, evidence_public_key)
    shape._digest(config)
    for key in (root, planner, evidence_key):
        authorization._public(key)
    window = clock._validate(live_window)
    inherited = transport_deadline_ns
    if inherited is not None:
        shape._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    envelope = _read(original, enrollment=False, work=work)
    payload = envelope["payload"]
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    maximum_age = skew = None
    last_epoch, last_monotonic = window[0], window[2]

    def live():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = primitives.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < last_epoch or monotonic < last_monotonic or monotonic >= bound
                or now >= expires or maximum_age is not None
                    and (issued > now + skew or now - issued > maximum_age)):
            raise RegistrationFinalizationAuthorizationError("finalization authorization expired or clocks reversed")
        last_epoch, last_monotonic = now, monotonic

    live()
    material = _admit_enrollment_on_work(authorization_enrollment_bytes=enrollment_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=config,
        planner_public_key=planner, evidence_public_key=evidence_key, work=work)
    policy, caller = material.payload, material.caller_public_key
    maximum_age, skew = policy["maximumAgeNs"], policy["maximumClockSkewNs"]
    authorization._interval(payload, maximum_age)
    live()
    primitives._signature(envelope, caller, MAX_AUTHORIZATION_BYTES, work)
    for name in _SCOPE_FIELDS:
        plan._same(payload[name], policy[name], work, "finalization request " + name)
    plan._same(payload["authorizationEnrollmentDigest"], material.enrollment_digest, work,
        "finalization request caller enrollment")
    plan._same(payload["callerMeasurementDigest"], policy["callerKey"]["measurementDigest"], work,
        "finalization request caller measurement")
    operation_id = plan._frame("catchplate.policyAuthorityOperation/v2",
        (OPERATION.encode("ascii"), payload["requestDigest"].encode("ascii")), work)
    plan._same(payload["operationId"], operation_id, work, "finalization request actual operation identity")
    identity = plan._frame(REQUEST_IDENTITY_DOMAIN, (original,), work)
    primitives._unchanged(original, envelope, MAX_AUTHORIZATION_BYTES, work)
    live()
    return _VerifiedAuthorization(payload["requestDigest"], operation_id, identity,
        policy["databaseId"], policy["generationDigest"], policy["currentRootEnrollmentDigest"],
        policy["grantEnrollmentDigest"], issued, expires, maximum_age, skew, last_epoch, last_monotonic)


def _verify_historical_on_work(*, authorization_bytes, authorization_enrollment_bytes,
        current_root_enrollment_bytes, grant_enrollment_bytes, root_public_key,
        configuration_digest, planner_public_key, evidence_public_key,
        live_window, work, transport_deadline_ns=None):
    """Authenticate original finalization scope without reviving its expiry.

    The legacy key parameter spelling denotes the independently configured
    finalization transition key here, never an evidence-admission fallback.
    The supplied current processing window is retained, not opened or returned.
    """
    capture._SharedLedger(work)
    original = authorization._original(authorization_bytes, MAX_AUTHORIZATION_BYTES,
        "historical finalization request authorization")
    enrollment_raw = authorization._original(authorization_enrollment_bytes,
        MAX_ENROLLMENT_BYTES, "historical finalization caller enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "historical finalization current-root enrollment")
    grant_raw = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "historical finalization grant enrollment")
    config, root, planner, operation_key = (configuration_digest, root_public_key,
        planner_public_key, evidence_public_key)
    shape._digest(config)
    for key in (root, planner, operation_key):
        authorization._public(key)
    window = clock._validate(live_window)
    inherited = transport_deadline_ns
    if inherited is not None:
        shape._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise RegistrationFinalizationAuthorizationError("historical finalization processing expired or clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    current()
    envelope = _read(original, enrollment=False, work=work)
    material = _admit_enrollment_on_work(authorization_enrollment_bytes=enrollment_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=config,
        planner_public_key=planner, evidence_public_key=operation_key, work=work)
    current()
    policy = material.payload
    primitives._signature(envelope, material.caller_public_key, MAX_AUTHORIZATION_BYTES, work)
    payload = envelope["payload"]
    for name in _SCOPE_FIELDS:
        plan._same(payload[name], policy[name], work, "historical finalization request " + name)
    plan._same(payload["authorizationEnrollmentDigest"], material.enrollment_digest, work,
        "historical finalization request caller enrollment")
    plan._same(payload["callerMeasurementDigest"], policy["callerKey"]["measurementDigest"], work,
        "historical finalization request caller measurement")
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    maximum_age, skew = policy["maximumAgeNs"], policy["maximumClockSkewNs"]
    authorization._interval(payload, maximum_age)
    operation_id = plan._frame("catchplate.policyAuthorityOperation/v2",
        (OPERATION.encode("ascii"), payload["requestDigest"].encode("ascii")), work)
    plan._same(payload["operationId"], operation_id, work,
        "historical finalization request actual operation identity")
    identity = plan._frame(REQUEST_IDENTITY_DOMAIN, (original,), work)
    primitives._unchanged(original, envelope, MAX_AUTHORIZATION_BYTES, work)
    if issued > current() + skew:
        raise RegistrationFinalizationAuthorizationError("historical finalization authorization is future-issued")
    return _HistoricalAuthorization(payload["requestDigest"], operation_id, identity,
        policy["databaseId"], policy["generationDigest"], policy["currentRootEnrollmentDigest"],
        policy["grantEnrollmentDigest"], issued, expires, maximum_age, skew, last_epoch, last_monotonic)
