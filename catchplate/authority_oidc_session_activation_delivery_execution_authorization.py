"""Fixed live post-plan caller controls for protected delivery consumption.

Present permission and caller-key custody are independent obligations. The
known consume plan's real signature is checked before signing an exact raw2
identity; ciphertext framing is not private replay. No AES, execution grant,
historical mode, public permission or successful-result input is provided.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import secrets
import time

from catchplate import authority_current_root_vector as vector
from catchplate import authority_oidc_session_activation_delivery_execution_bundle as bundle
from catchplate import authority_oidc_session_activation_delivery_execution_enrollment as enrollments
from catchplate import authority_oidc_session_activation_delivery_execution_expectations as expectations_wire
from catchplate import authority_oidc_session_activation_delivery_plan as consume
from catchplate import authority_registration_execution_authorization as primitives
from catchplate import authority_successor_execution_window as window_policy
from catchplate.authority_query_read_work import QueryReadWorkError


authorization, capture, plan, shape = (primitives.authorization, primitives.capture,
    primitives.plan, primitives.shape)
keys, production, clock = primitives.keys, primitives.production, primitives.clock
contract, evidence, registration = consume.contract, consume.evidence, consume.registration
OPERATION = contract.OPERATION
PURPOSE = "authorize-oidc-session-activation-delivery-consume"
ENROLLMENT_SCHEMA = "catchplate.signedOidcSessionActivationDeliveryExecutionAuthorizationEnrollment/v1"
ENROLLMENT_PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationDeliveryExecutionAuthorizationEnrollment/v1"
ENROLLMENT_IDENTITY_DOMAIN = "catchplate.oidcSessionActivationDeliveryExecutionAuthorizationEnrollmentIdentity/v1"
REQUEST_SCHEMA = "catchplate.signedOidcSessionActivationDeliveryExecutionAuthorization/v1"
REQUEST_PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationDeliveryExecutionAuthorization/v1"
REQUEST_IDENTITY_DOMAIN = "catchplate.oidcSessionActivationDeliveryExecutionAuthorizationIdentity/v1"
MAX_ENROLLMENT_BYTES = 16 * 1024
MAX_AUTHORIZATION_BYTES = MAX_BYTES = 64 * 1024
MAX_ORIGINAL_BYTES = contract.MAX_ORIGINAL_BYTES
MAX_NODES, MAX_DEPTH = 4096, 6
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_SCOPE_FIELDS = ("configurationDigest", "databaseId", "generationDigest",
    "currentRootEnrollmentDigest", "grantEnrollmentDigest", "callerId", "audienceSpkiDigest",
    "plannerSpkiDigest", "operationSpkiDigest")
_COMMON = frozenset({"schema", "sourceRevision", "purpose", "operation", *_SCOPE_FIELDS})
ENROLLMENT_FIELDS = _COMMON | frozenset({"callerKey", "maximumAgeNs", "maximumClockSkewNs"})
_FACT_FIELDS = ("requestDigest", "operationId", "planDigest", "retainedRecordDigest",
    "journalDigest", "beforeVectorDigest")
REQUEST_FIELDS = _COMMON | frozenset({"authorizationEnrollmentDigest", "callerMeasurementDigest",
    "authorizationId", "issuedAtEpochNs", "expiresAtEpochNs", *_FACT_FIELDS})
_KEY_FIELDS = frozenset({"publicKeyPem", "spkiDigest", "measurementDigest"})


class DeliveryExecutionAuthorizationError(ValueError):
    pass


def _fail(message):
    raise DeliveryExecutionAuthorizationError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Enrollment:
    payload: dict
    enrollment_digest: str
    caller_public_key: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Inputs:
    originals: tuple
    before: bytes
    caller_enrollment: bytes
    current_enrollment: bytes
    grant_enrollment: bytes
    root: object
    planner: object
    operation_key: object
    configuration_digest: str
    expectations: dict
    window: tuple
    deadline_ns: int


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedAuthorization:
    """Same-call facts/current guard, not an accepted permission carrier."""
    request_digest: str
    operation_id: str
    authorization_digest: str
    plan_digest: str
    retained_record_digest: str
    journal_digest: str
    before_vector_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int
    window: tuple
    deadline_ns: int
    last_epoch_ns: int
    last_monotonic_ns: int
    live: object


def _shape(payload, *, enrollment):
    shape._object(payload, ENROLLMENT_FIELDS if enrollment else REQUEST_FIELDS,
        "consume execution caller authority")
    shape._literal(payload["schema"], ENROLLMENT_PAYLOAD_SCHEMA if enrollment else REQUEST_PAYLOAD_SCHEMA)
    shape._literal(payload["sourceRevision"], contract.authority.SOURCE_REVISION)
    shape._literal(payload["purpose"], PURPOSE)
    shape._literal(payload["operation"], OPERATION)
    for name in _SCOPE_FIELDS:
        (authorization._token if name in ("databaseId", "callerId") else shape._digest)(payload[name])
    if enrollment:
        record = payload["callerKey"]
        shape._object(record, _KEY_FIELDS, "consume execution caller key")
        pem = record["publicKeyPem"]
        if type(pem) is not str or not 1 <= len(pem) <= authorization.MAX_PEM_BYTES or not pem.isascii() or "\x00" in pem:
            _fail("consume caller key is not bounded original PEM")
        shape._digest(record["spkiDigest"])
        shape._digest(record["measurementDigest"])
        shape._integer(payload["maximumAgeNs"], contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
        shape._integer(payload["maximumClockSkewNs"], contract.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    else:
        for name in (*_FACT_FIELDS, "authorizationEnrollmentDigest", "callerMeasurementDigest"):
            shape._digest(payload[name])
        shape._text(payload["authorizationId"], 43, minimum=43)
        shape._base64url(payload["authorizationId"])
        if payload["authorizationId"] == "A" * 43:
            _fail("consume authorization identity is zero")
        authorization._interval(payload, contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS)


def _read(raw, *, enrollment, work):
    if type(enrollment) is not bool:
        _fail("consume authority wire purpose is not fixed")
    maximum, schema = ((MAX_ENROLLMENT_BYTES, ENROLLMENT_SCHEMA) if enrollment
        else (MAX_AUTHORIZATION_BYTES, REQUEST_SCHEMA))
    authorization._original(raw, maximum, "consume caller authority original")
    decoded = enrollments.wire._decode_object(raw, work=work, maximum_bytes=maximum,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    shape._object(decoded, _ENVELOPE_FIELDS, "signed consume caller authority")
    shape._literal(decoded["schema"], schema)
    shape._base64url(decoded["signatureBase64Url"], signature=True)
    _shape(decoded["payload"], enrollment=enrollment)
    owned = enrollments._Capture(capture._SharedLedger(work), maximum_bytes=maximum).visit(decoded)
    primitives._unchanged(raw, owned, maximum, work)
    return owned


def _sign(payload, *, private_key, public_key, enrollment, work):
    """Only these two fixed consume caller domains, never a generic signer."""
    if type(enrollment) is not bool:
        _fail("consume signing purpose is not fixed")
    schema = ENROLLMENT_SCHEMA if enrollment else REQUEST_SCHEMA
    maximum = MAX_ENROLLMENT_BYTES if enrollment else MAX_AUTHORIZATION_BYTES
    private, public = private_key, public_key
    authorization._private(private)
    authorization._public(public)
    owned = enrollments._Capture(capture._SharedLedger(work), maximum_bytes=maximum).visit(payload)
    _shape(owned, enrollment=enrollment)
    keys._pair_on_work(private, public, work)
    envelope = {"schema": schema, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > maximum or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("consume signature exceeds its output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(schema) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("consume signing cannot reserve its complete output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("consume caller authority changed after measurement")
    message = plan._ascii(plan._frame(schema, (unsigned,), work), work)
    signature = production._sign_and_verify(private, public, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("consume caller authority changed while signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    original = plan.core.canonical_bytes({"schema": schema, "payload": owned, "signatureBase64Url": encoded})
    if len(original) != envelope_size:
        _fail("consume signed output changed after reservation")
    return original


def _base(*, current_root_enrollment_bytes, grant_enrollment_bytes,
        root_public_key, planner_public_key, operation_public_key, work):
    """Genuine current-root and consume-only grant enrollment admission."""
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "consume current-root enrollment")
    grant_raw = authorization._original(grant_enrollment_bytes,
        enrollments.MAX_ENROLLMENT_BYTES, "consume grant enrollment")
    root, planner, operation_key = root_public_key, planner_public_key, operation_public_key
    for key in (root, planner, operation_key):
        authorization._public(key)
    current = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
        root_public_key=root, work=work)
    grant = enrollments._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root, work=work)
    forbidden = (root, current.computation_public_key, current.completion_public_key,
        current.state_public_key, grant.authorizer_public_key, planner, operation_key)
    return current, grant, forbidden


def _admit_enrollment_on_work(*, authorization_enrollment_bytes, current_root_enrollment_bytes,
        grant_enrollment_bytes, root_public_key, configuration_digest,
        planner_public_key, operation_public_key, work):
    capture._SharedLedger(work)
    raw = authorization._original(authorization_enrollment_bytes, MAX_ENROLLMENT_BYTES, "consume caller enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    grant_raw = authorization._original(grant_enrollment_bytes, enrollments.MAX_ENROLLMENT_BYTES, "consume grant enrollment")
    config, root, planner, operation_key = configuration_digest, root_public_key, planner_public_key, operation_public_key
    shape._digest(config)
    enrolled = _read(raw, enrollment=True, work=work)
    primitives._signature(enrolled, root, MAX_ENROLLMENT_BYTES, work)
    current, grant, forbidden = _base(current_root_enrollment_bytes=current_raw,
        grant_enrollment_bytes=grant_raw, root_public_key=root,
        planner_public_key=planner, operation_public_key=operation_key, work=work)
    policy = enrolled["payload"]
    for name, expected in (("configurationDigest", config), ("databaseId", current.payload["databaseId"]),
            ("generationDigest", current.payload["generationDigest"]),
            ("currentRootEnrollmentDigest", current.enrollment_digest), ("grantEnrollmentDigest", grant.enrollment_digest),
            ("audienceSpkiDigest", grant.payload["authorizer"]["spkiDigest"]),
            ("plannerSpkiDigest", keys._spki_on_work(planner, work)),
            ("operationSpkiDigest", keys._spki_on_work(operation_key, work))):
        plan._same(policy[name], expected, work, "consume caller enrollment " + name)
    plan._same(policy["operationSpkiDigest"], keys._spki_on_work(root, work), work, "consume operation root")
    caller = authorization._role_key(policy["callerKey"], work)
    primitives._separate(caller, forbidden, work)
    primitives._unchanged(raw, enrolled, MAX_ENROLLMENT_BYTES, work)
    return _Enrollment(policy, plan._frame(ENROLLMENT_IDENTITY_DOMAIN, (raw,), work), caller)


def _produce_enrollment_on_work(*, current_root_enrollment_bytes, grant_enrollment_bytes,
        root_private_key, root_public_key, configuration_digest, caller_public_key,
        caller_measurement_digest, caller_id, planner_public_key, operation_public_key,
        maximum_age_ns, maximum_clock_skew_ns, work):
    current_raw = authorization._original(current_root_enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    grant_raw = authorization._original(grant_enrollment_bytes, enrollments.MAX_ENROLLMENT_BYTES, "consume grant enrollment")
    private, root, caller, planner, operation_key = root_private_key, root_public_key, caller_public_key, planner_public_key, operation_public_key
    config, measurement, identity, age, skew = configuration_digest, caller_measurement_digest, caller_id, maximum_age_ns, maximum_clock_skew_ns
    authorization._private(private)
    authorization._public(caller)
    shape._digest(config)
    shape._digest(measurement)
    authorization._token(identity)
    shape._integer(age, contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(skew, contract.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    capture._SharedLedger(work)
    current, grant, forbidden = _base(current_root_enrollment_bytes=current_raw,
        grant_enrollment_bytes=grant_raw, root_public_key=root, planner_public_key=planner,
        operation_public_key=operation_key, work=work)
    spki = primitives._separate(caller, forbidden, work)
    work.charge(input_bytes=authorization.MAX_PEM_BYTES)
    pem = production._callback(work, lambda: caller.public_bytes(authorization.Encoding.PEM, authorization.PublicFormat.SubjectPublicKeyInfo))
    if type(pem) is not bytes or not 1 <= len(pem) <= authorization.MAX_PEM_BYTES or not pem.isascii():
        _fail("consume caller public key is not bounded original PEM")
    work.charge(input_bytes=len(pem))
    payload = {"schema": ENROLLMENT_PAYLOAD_SCHEMA, "sourceRevision": contract.authority.SOURCE_REVISION,
        "purpose": PURPOSE, "operation": OPERATION, "configurationDigest": config,
        "databaseId": current.payload["databaseId"], "generationDigest": current.payload["generationDigest"],
        "currentRootEnrollmentDigest": current.enrollment_digest, "grantEnrollmentDigest": grant.enrollment_digest,
        "callerId": identity, "callerKey": {"publicKeyPem": pem.decode("ascii"), "spkiDigest": spki, "measurementDigest": measurement},
        "audienceSpkiDigest": grant.payload["authorizer"]["spkiDigest"],
        "plannerSpkiDigest": keys._spki_on_work(planner, work), "operationSpkiDigest": keys._spki_on_work(operation_key, work),
        "maximumAgeNs": age, "maximumClockSkewNs": skew}
    plan._same(payload["operationSpkiDigest"], keys._spki_on_work(root, work), work, "consume operation root")
    original = _sign(payload, private_key=private, public_key=root, enrollment=True, work=work)
    _admit_enrollment_on_work(authorization_enrollment_bytes=original, current_root_enrollment_bytes=current_raw,
        grant_enrollment_bytes=grant_raw, root_public_key=root, configuration_digest=config,
        planner_public_key=planner, operation_public_key=operation_key, work=work)
    return original


def _scope(owned, window, work):
    """Scope association/lifetime only, not policy or possession verification."""
    expected, request = owned["scope"], owned["request"]
    for name in ("configurationDigest", "plannerSpkiDigest"):
        registration._digest(expected[name])
    evidence._identity(expected["plannerIdentity"])
    for name, maximum in (("deliveryId", 128), ("userId", 1024), ("sessionId", 128),
            ("credentialId", 1366), ("credentialRecordId", 1024), ("challengeId", 1024)):
        registration._text(expected[name], name, maximum, work)
    registration._integer(expected["maximumPlanAgeNs"], "consume plan age", 1,
        contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    registration._integer(expected["maximumClockSkewNs"], "consume plan skew", 0,
        contract.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    registration._integer(expected["deadlineEpochNs"], "consume original deadline", 1)
    if (window[5] > expected["maximumPlanAgeNs"] or window[6] > expected["maximumClockSkewNs"]
            or window[3] > expected["deadlineEpochNs"]):
        _fail("consume caller processing exceeds independent policy or original deadline")
    arguments = consume.transition._arguments(request["arguments"], work)
    for field, name in (("delivery_id", "deliveryId"), ("user_id", "userId"), ("session_id", "sessionId"),
            ("credential_id", "credentialId"), ("credential_record_id", "credentialRecordId"), ("challenge_id", "challengeId")):
        registration._same(arguments[field], expected[name], work, "consume caller subject " + name)


def _capture_on_work(*, originals, expectations, before_vector_bytes, authorization_enrollment_bytes,
        current_root_enrollment_bytes, grant_enrollment_bytes, root_public_key, configuration_digest,
        planner_public_key, operation_public_key, live_window, transport_deadline_ns, work, extra_originals=()):
    capture._SharedLedger(work)
    if type(originals) is not tuple or len(originals) != 2:
        _fail("consume caller controls require exact immutable plan/ciphertext raw2")
    signed = authorization._original(originals[0], contract.MAX_BYTES, "signed consume plan")
    encrypted = bundle._bounded_frame(originals[1])
    before = authorization._original(before_vector_bytes, vector.MAX_BYTES, "consume complete before-vector")
    caller = authorization._original(authorization_enrollment_bytes, MAX_ENROLLMENT_BYTES, "consume caller enrollment")
    current = authorization._original(current_root_enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    grant = authorization._original(grant_enrollment_bytes, enrollments.MAX_ENROLLMENT_BYTES, "consume grant enrollment")
    if (type(extra_originals) is not tuple or len(extra_originals) > 1
            or any(type(raw) is not bytes or not 2 <= len(raw) <= MAX_AUTHORIZATION_BYTES for raw in extra_originals)):
        _fail("consume authorization extra original is not bounded")
    held = (signed, encrypted)
    total = sum(len(raw) for raw in (*held, before, caller, current, grant, *extra_originals))
    if total > MAX_ORIGINAL_BYTES:
        _fail("consume caller authority originals exceed the aggregate bound")
    root, planner, operation_key, config = root_public_key, planner_public_key, operation_public_key, configuration_digest
    for key in (root, planner, operation_key):
        authorization._public(key)
    shape._digest(config)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    work.charge(input_bytes=total)
    # All other originals/scalars/keys are held before capture hashes any graph.
    owned = expectations_wire._capture_on_work(expectations, work=work)
    _scope(owned, window, work)
    plan._same(owned["scope"]["configurationDigest"], config, work, "consume caller configuration")
    return _Inputs(held, before, caller, current, grant, root, planner, operation_key, config, owned, window, bound)


def _enrollment(held, work):
    return _admit_enrollment_on_work(authorization_enrollment_bytes=held.caller_enrollment,
        current_root_enrollment_bytes=held.current_enrollment, grant_enrollment_bytes=held.grant_enrollment,
        root_public_key=held.root, configuration_digest=held.configuration_digest,
        planner_public_key=held.planner, operation_public_key=held.operation_key, work=work)


def _clock(held, work, continuity=None):
    last_epoch, last_monotonic = held.window[0], held.window[2]
    if continuity is not None and not callable(continuity):
        _fail("consume caller restrictive continuity is not callable")

    def continue_owner(selected):
        nonlocal last_epoch, last_monotonic
        if continuity is None:
            return
        limits, before = work.limits, work.metrics
        ceilings = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
        observed = continuity(last_epoch, last_monotonic)
        capture._SharedLedger(work)
        after = work.metrics
        if (work.limits is not limits
                or ceilings != (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                or after.hash_work < before.hash_work or after.input_bytes < before.input_bytes
                or after.json_nodes < before.json_nodes):
            _fail("consume caller continuity reset its original work")
        if (type(observed) is not tuple or len(observed) != 2
                or any(type(value) is not int or value < 1 for value in observed)
                or observed[0] < last_epoch or observed[1] < last_monotonic):
            _fail("consume caller continuity lowered its retained clock floors")
        if observed[0] >= selected[3] or observed[1] >= min(held.deadline_ns, selected[4]):
            _fail("consume caller continuity exceeded its narrowed deadline")
        last_epoch, last_monotonic = observed

    def current(window=None):
        nonlocal last_epoch, last_monotonic
        selected = held.window if window is None else clock._validate(window)
        if (selected[:3] != held.window[:3] or selected[3] > held.window[3]
                or selected[4] > held.window[4] or selected[5] > held.window[5] or selected[6] > held.window[6]):
            _fail("consume caller replaced or widened its original processing bracket")
        continue_owner(selected)
        now = clock._check_on_work(selected, work=work)
        mono = production._callback(work, time.monotonic_ns)
        shape._integer(mono, minimum=1)
        if now < last_epoch or mono < last_monotonic or mono >= held.deadline_ns:
            _fail("consume caller processing expired or clocks reversed")
        last_epoch, last_monotonic = now, mono
        continue_owner(selected)
        return last_epoch, last_monotonic

    return current


def _facts(held, current, work):
    """Authenticate real known-plan controls; never claim ciphertext replay."""
    current()
    request, scope = held.expectations["request"], held.expectations["scope"]
    envelope = contract._decode_on_work(held.originals[0], envelope=True, work=work)
    payload = envelope["payload"]
    for name in ("requestDigest", "operationId"):
        registration._same(payload[name], request[name], work, "consume known plan " + name)
    for name in ("configurationDigest", "plannerIdentity", "plannerSpkiDigest"):
        registration._same(payload[name], scope[name], work, "consume known plan " + name)
    unsigned = contract._encode_on_work(payload, work=work)
    evidence.keys._public_binding(held.planner, scope["plannerSpkiDigest"], work)
    evidence.capability._signature(held.planner, envelope["signatureBase64Url"],
        contract.SIGNATURE_DOMAIN, unsigned, evidence.capture._SharedLedger(work))
    now, _mono = current()
    evidence._fresh(payload, now, scope["maximumPlanAgeNs"], scope["maximumClockSkewNs"])
    if payload["expiresAtEpochNs"] > scope["deadlineEpochNs"] or now >= scope["deadlineEpochNs"]:
        _fail("consume known plan exceeds its independent original interval")
    facts = {name: request[name] for name in ("requestDigest", "operationId")}
    facts.update({"planDigest": plan._frame(contract.IDENTITY_DOMAIN, (held.originals[0],), work),
        "retainedRecordDigest": plan._frame(bundle.RECORD_IDENTITY_DOMAIN, held.originals, work),
        "journalDigest": held.expectations["journalDigest"],
        "beforeVectorDigest": vector._digest_on_work(held.before, work=work)})
    if current()[0] >= payload["expiresAtEpochNs"]:
        _fail("consume known plan expired while binding originals")
    return payload, facts


def _verify_held_on_work(held, original, work, *, current=None):
    """Private same-call suffix; it still verifies every original signature."""
    if type(held) is not _Inputs:
        _fail("consume caller inputs were not captured by the fixed path")
    authorization._original(original, MAX_AUTHORIZATION_BYTES, "consume caller authorization")
    current = _clock(held, work) if current is None else current
    current()
    enrolled = _enrollment(held, work)
    envelope = _read(original, enrollment=False, work=work)
    payload, policy = envelope["payload"], enrolled.payload
    primitives._signature(envelope, enrolled.caller_public_key, MAX_AUTHORIZATION_BYTES, work)
    for name in _SCOPE_FIELDS:
        plan._same(payload[name], policy[name], work, "consume caller request " + name)
    plan._same(payload["authorizationEnrollmentDigest"], enrolled.enrollment_digest, work, "consume caller enrollment")
    plan._same(payload["callerMeasurementDigest"], policy["callerKey"]["measurementDigest"], work, "consume caller measurement")
    authorization._interval(payload, policy["maximumAgeNs"])

    def live(window=None):
        now, mono = current(window)
        evidence._fresh(payload, now, policy["maximumAgeNs"], policy["maximumClockSkewNs"])
        return now, mono

    live()
    actual_plan, facts = _facts(held, live, work)
    for name in _FACT_FIELDS:
        plan._same(payload[name], facts[name], work, "consume caller exact original " + name)
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if not actual_plan["issuedAtEpochNs"] <= issued < expires <= actual_plan["expiresAtEpochNs"]:
        _fail("consume post-plan authorization escapes the original plan interval")
    window = window_policy._narrow(held.window, deadline_epoch_ns=min(expires, actual_plan["expiresAtEpochNs"]),
        maximum_lifetime_ns=policy["maximumAgeNs"], maximum_clock_skew_ns=policy["maximumClockSkewNs"])
    bound = min(held.deadline_ns, window[4])

    def checked():
        now, mono = live(window)
        if mono >= bound or now >= actual_plan["expiresAtEpochNs"]:
            _fail("consume caller or original plan expired")
        return now, mono

    identity = plan._frame(REQUEST_IDENTITY_DOMAIN, (original,), work)
    primitives._unchanged(original, envelope, MAX_AUTHORIZATION_BYTES, work)
    now, mono = checked()
    return _VerifiedAuthorization(facts["requestDigest"], facts["operationId"], identity,
        facts["planDigest"], facts["retainedRecordDigest"], facts["journalDigest"], facts["beforeVectorDigest"],
        issued, expires, window, bound, now, mono, checked)


def _verify_on_work(*, authorization_bytes, authorization_enrollment_bytes, current_root_enrollment_bytes,
        grant_enrollment_bytes, root_public_key, configuration_digest, planner_public_key, operation_public_key,
        originals, expectations, before_vector_bytes, live_window, transport_deadline_ns, work):
    original = authorization._original(authorization_bytes, MAX_AUTHORIZATION_BYTES, "consume caller authorization")
    held = _capture_on_work(originals=originals, expectations=expectations, before_vector_bytes=before_vector_bytes,
        authorization_enrollment_bytes=authorization_enrollment_bytes, current_root_enrollment_bytes=current_root_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, root_public_key=root_public_key, configuration_digest=configuration_digest,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work, extra_originals=(original,))
    return _verify_held_on_work(held, original, work)


def _produce_on_work(*, authorization_enrollment_bytes, current_root_enrollment_bytes, grant_enrollment_bytes,
        root_public_key, configuration_digest, planner_public_key, operation_public_key, caller_private_key,
        originals, expectations, before_vector_bytes, live_window, transport_deadline_ns, work, _continuity=None):
    """Sign a fresh nonce only after genuine live known-plan authentication.

    Independently admitted present permission is a caller obligation. This
    producer never backdates issue time, reopens time or opens the ciphertext.
    """
    signer = caller_private_key
    authorization._private(signer)
    held = _capture_on_work(originals=originals, expectations=expectations, before_vector_bytes=before_vector_bytes,
        authorization_enrollment_bytes=authorization_enrollment_bytes, current_root_enrollment_bytes=current_root_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, root_public_key=root_public_key, configuration_digest=configuration_digest,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    current = _clock(held, work, _continuity)
    current()
    enrolled = _enrollment(held, work)
    keys._pair_on_work(signer, enrolled.caller_public_key, work)
    actual_plan, facts = _facts(held, current, work)
    work.charge(input_bytes=32 + 44 + 43)
    nonce = production._callback(work, lambda: secrets.token_bytes(32))
    if type(nonce) is not bytes or len(nonce) != 32 or nonce == bytes(32):
        _fail("consume authorization nonce generation failed")
    nonce_text = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
    issued, _mono = current()
    policy = enrolled.payload
    expires = min(held.window[3], actual_plan["expiresAtEpochNs"], issued + policy["maximumAgeNs"])
    if not actual_plan["issuedAtEpochNs"] <= issued < expires:
        _fail("consume original plan has no current post-plan authorization interval")
    payload = {"schema": REQUEST_PAYLOAD_SCHEMA, "sourceRevision": contract.authority.SOURCE_REVISION,
        "purpose": PURPOSE, "operation": OPERATION, **{name: policy[name] for name in _SCOPE_FIELDS},
        "authorizationEnrollmentDigest": enrolled.enrollment_digest,
        "callerMeasurementDigest": policy["callerKey"]["measurementDigest"], **facts,
        "authorizationId": nonce_text, "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    original = _sign(payload, private_key=signer, public_key=enrolled.caller_public_key, enrollment=False, work=work)
    if sum(len(raw) for raw in (*held.originals, held.before, held.caller_enrollment,
            held.current_enrollment, held.grant_enrollment, original)) > MAX_ORIGINAL_BYTES:
        _fail("consume signed controls exceed the aggregate original bound")
    current()
    _verify_held_on_work(held, original, work, current=current).live()
    return original
