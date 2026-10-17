"""Maintenance-only predecision grants from actual original proof replay.

This family has a distinct root-signed authorizer enrollment, accepting exactly
webauthn.challenge.maintain. Existing broad successor delegations cannot enroll
it. Root/current-root provenance, independently admitted caller authorization,
historical planner pins and the original live window are supplied prerequisites.
No successful replay observation, signing payload or replacement window is an
input to the grant producer or full verifier. Both replay the genuine raw pages.

The grant precedes reservation. It cannot name its dependent pending receipt or
authorize SQL by itself. Protected reservation, one-use custody, execution and
completion remain separate owners. Partial/source-only integration is not live
authority. No key generation, I/O, routing, new work allowance or clock opening
occurs here; even the control-only verifier requires the retained live window.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib

from catchplate import authority_challenge_current_root as current_root
from catchplate import authority_successor_execution_grant as mechanics
from catchplate import authority_webauthn_evidence_plan_clock as clock
from catchplate.authority_query_read_work import QueryReadWorkError


authorization, shape, capture = mechanics.authorization, mechanics.shape, mechanics.capture
wire, framing, keys = mechanics.wire, mechanics.plan, mechanics.keys
plan = current_root.plan
OPERATION = "webauthn.challenge.maintain"
ENROLLMENT_SCHEMA = "catchplate.signedPolicyAuthorityChallengeMaintenanceExecutionGrantEnrollment/v1"
ENROLLMENT_PAYLOAD_SCHEMA = "catchplate.policyAuthorityChallengeMaintenanceExecutionGrantEnrollment/v1"
ENROLLMENT_IDENTITY_DOMAIN = "catchplate.policyAuthorityChallengeMaintenanceExecutionGrantEnrollmentIdentity/v1"
GRANT_SCHEMA = "catchplate.signedPolicyAuthorityChallengeMaintenanceExecutionGrant/v1"
GRANT_PAYLOAD_SCHEMA = "catchplate.policyAuthorityChallengeMaintenanceExecutionGrant/v1"
GRANT_IDENTITY_DOMAIN = "catchplate.policyAuthorityChallengeMaintenanceExecutionGrantIdentity/v1"
RESULT_DOMAIN = "catchplate.policyAuthorityControlledWriterResult/v2"
MAX_ENROLLMENT_BYTES, MAX_GRANT_BYTES = 16 * 1024, 64 * 1024
MAX_NODES, MAX_DEPTH = 4096, 6
FRAME_MAXIMA = (plan.MAX_PARENT_BYTES, plan.requests.MAX_REQUEST_BYTES, plan.manifests.MAX_MANIFEST_BYTES)
ENROLLMENT_FIELDS = frozenset({"schema", "sourceRevision", "currentRootEnrollmentDigest",
    "databaseId", "generationDigest", "operations", "authorizer", "maximumGrantAgeNs", "maximumClockSkewNs"})
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "grantEnrollmentDigest", "currentRootEnrollmentDigest",
    "databaseId", "generationDigest", "authorizerMeasurementDigest", "operation", "requestDigest", "operationId",
    "configurationDigest", "requestAuthorizationDigest", "planDigest", "manifestDigest", "beforeVectorDigest",
    "afterVectorDigest", "resultDigest", "originalFrames", "issuedAtEpochNs", "expiresAtEpochNs"})
_DIGEST_FIELDS = ("grantEnrollmentDigest", "currentRootEnrollmentDigest", "generationDigest",
    "authorizerMeasurementDigest", "requestDigest", "operationId", "configurationDigest",
    "requestAuthorizationDigest", "planDigest", "manifestDigest", "beforeVectorDigest", "afterVectorDigest", "resultDigest")
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_KEY_FIELDS = frozenset({"publicKeyPem", "spkiDigest", "measurementDigest"})
_FRAME_FIELDS = frozenset({"position", "bytesDigest", "byteCount"})


class ChallengeExecutionGrantError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class _Enrollment:
    payload: dict
    digest: str
    authorizer: object


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedGrant:
    """Same-call observations, never a reusable authorization input."""

    grant_digest: str
    payload: dict
    replayed: current_root.MaintenanceVectorObservation


def _require(value):
    if not value:
        raise ChallengeExecutionGrantError("maintenance execution grant differs from its original authority")


def _enrollment_shape(value):
    shape._object(value, ENROLLMENT_FIELDS, "maintenance grant enrollment")
    shape._literal(value["schema"], ENROLLMENT_PAYLOAD_SCHEMA)
    shape._literal(value["sourceRevision"], authorization.authority.SOURCE_REVISION)
    for name in ("currentRootEnrollmentDigest", "generationDigest"):
        shape._digest(value[name])
    authorization._token(value["databaseId"])
    operations = value["operations"]
    _require(type(operations) is list and len(operations) == 1
        and type(operations[0]) is str and operations[0] == OPERATION)
    key = value["authorizer"]
    shape._object(key, _KEY_FIELDS, "maintenance authorizer")
    for name in ("spkiDigest", "measurementDigest"):
        shape._digest(key[name])
    pem = key["publicKeyPem"]
    _require(type(pem) is str and 1 <= len(pem) <= authorization.MAX_PEM_BYTES
        and pem.isascii() and "\x00" not in pem)
    shape._integer(value["maximumGrantAgeNs"], authorization.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(value["maximumClockSkewNs"], authorization.authority.VERIFIER_MAX_CLOCK_SKEW_NS)


def _grant_shape(value):
    shape._object(value, GRANT_FIELDS, "maintenance execution grant")
    shape._literal(value["schema"], GRANT_PAYLOAD_SCHEMA)
    shape._literal(value["sourceRevision"], authorization.authority.SOURCE_REVISION)
    shape._literal(value["operation"], OPERATION)
    authorization._token(value["databaseId"])
    for name in _DIGEST_FIELDS:
        shape._digest(value[name])
    authorization._interval(value, authorization.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
    frames = value["originalFrames"]
    _require(type(frames) is list and len(frames) == 3)
    for ordinal, (frame, maximum) in enumerate(zip(frames, FRAME_MAXIMA, strict=True)):
        shape._object(frame, _FRAME_FIELDS, "maintenance grant original frame")
        shape._integer(frame["position"], 2)
        _require(frame["position"] == ordinal)
        shape._digest(frame["bytesDigest"])
        shape._integer(frame["byteCount"], maximum, minimum=2)


def _selection(enrollment):
    _require(type(enrollment) is bool)
    return ((ENROLLMENT_SCHEMA, MAX_ENROLLMENT_BYTES, _enrollment_shape) if enrollment
        else (GRANT_SCHEMA, MAX_GRANT_BYTES, _grant_shape))


def _read(raw, *, enrollment, work):
    schema, maximum, validate = _selection(enrollment)
    original = authorization._original(raw, maximum, "maintenance grant control")
    decoded = wire._decode_object(original, work=work, maximum_bytes=maximum,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    shape._object(decoded, _ENVELOPE_FIELDS, "maintenance signed control")
    shape._literal(decoded["schema"], schema)
    shape._base64url(decoded["signatureBase64Url"], signature=True)
    validate(decoded["payload"])
    owned = mechanics._Capture(capture._SharedLedger(work), maximum_bytes=maximum).visit(decoded)
    mechanics._unchanged(original, owned, maximum, work)
    return owned


def _sign(payload, *, private_key, public_key, enrollment, work):
    """Private suffix with only these two source-fixed signing purposes."""
    schema, maximum, validate = _selection(enrollment)
    authorization._private(private_key)
    authorization._public(public_key)
    owned = mechanics._Capture(capture._SharedLedger(work), maximum_bytes=maximum).visit(payload)
    validate(owned)
    keys._pair_on_work(private_key, public_key, work)
    placeholder = {"schema": schema, "payload": owned, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(placeholder)
    _require(max(size, envelope_size) <= maximum and max(nodes, envelope_nodes) <= MAX_NODES)
    work.charge(input_bytes=4 * size + envelope_size + authorization.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * nodes + envelope_nodes)
    frame_bytes = 2 * len(schema) + 9 + size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + size
            or work.limits.max_json_nodes - work.json_nodes < 4 + nodes):
        raise QueryReadWorkError("maintenance signing cannot reserve its complete original output")
    unsigned = framing.core.canonical_bytes(owned)
    _require(len(unsigned) == size)
    message = framing._ascii(framing._frame(schema, (unsigned,), work), work)
    signature = authorization.production._sign_and_verify(private_key, public_key, message, work)
    _require(work.measure(owned) == (size, nodes) and framing.core.canonical_bytes(owned) == unsigned)
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    result = framing.core.canonical_bytes({"schema": schema, "payload": owned, "signatureBase64Url": encoded})
    _require(len(result) == envelope_size)
    return result


def _separate(authorizer, others, work):
    identity = keys._spki_on_work(authorizer, work)
    for other in others:
        actual = keys._spki_on_work(other, work)
        work.prepare_comparison(identity, actual)
        _require(identity != actual)


def _admit_enrollment(*, grant_enrollment_bytes, current_root_enrollment_bytes, root_public_key, work):
    original = authorization._original(grant_enrollment_bytes, MAX_ENROLLMENT_BYTES, "maintenance grant enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    authorization._public(root_public_key)
    envelope = _read(original, enrollment=True, work=work)
    mechanics._signature(envelope, root_public_key, MAX_ENROLLMENT_BYTES, work)
    current = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
        root_public_key=root_public_key, work=work)
    payload = envelope["payload"]
    for name, expected in (("currentRootEnrollmentDigest", current.enrollment_digest),
            ("databaseId", current.payload["databaseId"]), ("generationDigest", current.payload["generationDigest"])):
        plan._same(payload[name], expected, work)
    authorizer = authorization._role_key(payload["authorizer"], work)
    _separate(authorizer, (root_public_key, current.computation_public_key,
        current.completion_public_key, current.state_public_key), work)
    mechanics._unchanged(original, envelope, MAX_ENROLLMENT_BYTES, work)
    return _Enrollment(payload, framing._frame(ENROLLMENT_IDENTITY_DOMAIN, (original,), work), authorizer)


def produce_enrollment(*, current_root_enrollment_bytes, root_private_key, root_public_key,
        authorizer_public_key, authorizer_measurement_digest, maximum_grant_age_ns, maximum_clock_skew_ns, work):
    """Explicit cold root delegation, deriving scope from the actual enrollment."""
    original = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    authorization._private(root_private_key)
    authorization._public(root_public_key)
    authorization._public(authorizer_public_key)
    shape._digest(authorizer_measurement_digest)
    shape._integer(maximum_grant_age_ns, authorization.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(maximum_clock_skew_ns, authorization.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    current = authorization._admit_enrollment_on_work(enrollment_bytes=original,
        root_public_key=root_public_key, work=work)
    scope = current.enrollment_digest, current.payload["databaseId"], current.payload["generationDigest"]
    _separate(authorizer_public_key, (root_public_key, current.computation_public_key,
        current.completion_public_key, current.state_public_key), work)
    spki = keys._spki_on_work(authorizer_public_key, work)
    work.charge(input_bytes=authorization.MAX_PEM_BYTES)
    exported = authorization.production._callback(work, lambda: authorizer_public_key.public_bytes(
        authorization.Encoding.PEM, authorization.PublicFormat.SubjectPublicKeyInfo))
    _require(type(exported) is bytes and 1 <= len(exported) <= authorization.MAX_PEM_BYTES and exported.isascii())
    work.charge(input_bytes=len(exported))
    payload = {"schema": ENROLLMENT_PAYLOAD_SCHEMA, "sourceRevision": authorization.authority.SOURCE_REVISION,
        "currentRootEnrollmentDigest": scope[0], "databaseId": scope[1], "generationDigest": scope[2],
        "operations": [OPERATION], "authorizer": {"publicKeyPem": exported.decode("ascii"),
            "spkiDigest": spki, "measurementDigest": authorizer_measurement_digest},
        "maximumGrantAgeNs": maximum_grant_age_ns, "maximumClockSkewNs": maximum_clock_skew_ns}
    _enrollment_shape(payload)
    authorization._role_key(payload["authorizer"], work)
    return _sign(payload, private_key=root_private_key, public_key=root_public_key, enrollment=True, work=work)


class _Live:
    """Original dual-clock bracket across parent and actual child-stage work."""

    def __init__(self, window, deadline_ns=None):
        self.window = clock._validate(window)
        self.original_deadline = self.window[4] if deadline_ns is None else deadline_ns
        shape._integer(self.original_deadline, minimum=1)
        self.deadline = min(self.original_deadline, self.window[4])
        self.last_epoch, self.last_monotonic = self.window[0], self.window[2]
        self.interval = self.policy = None

    def bind(self, payload, enrolled):
        self.policy = (enrolled["maximumGrantAgeNs"], enrolled["maximumClockSkewNs"])
        authorization._interval(payload, self.policy[0])
        self.interval = (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
        _require(self.window[5] <= self.policy[0] and self.window[6] <= self.policy[1])
        # The receiver may have opened its actual execution bracket later, or
        # clipped it earlier. Neither observation changes signed issue/expiry.
        # sample() checks both original freshness and the held execution limits.

    def sample(self, work):
        now = clock._check_on_work(self.window, work=work)
        monotonic = authorization.production._callback(work, clock.time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        _require(now >= self.last_epoch and self.last_monotonic <= monotonic < self.deadline)
        if self.interval is not None:
            plan.evidence._fresh({"issuedAtEpochNs": self.interval[0], "expiresAtEpochNs": self.interval[1]},
                now, *self.policy)
        self.last_epoch, self.last_monotonic = now, monotonic
        return now


def _pins(material):
    policy = material.payload
    return {"grantEnrollmentDigest": material.digest,
        "currentRootEnrollmentDigest": policy["currentRootEnrollmentDigest"],
        "databaseId": policy["databaseId"], "generationDigest": policy["generationDigest"],
        "authorizerMeasurementDigest": policy["authorizer"]["measurementDigest"]}


def _operation_identity(payload, work):
    size = work.prepare_utf8(payload["requestDigest"])
    work.prepare_utf8(OPERATION)
    work.charge(hashes=1, input_bytes=len("catchplate.policyAuthorityOperation/v2") + 17 + len(OPERATION) + size)
    identity = authorization.production._callback(work,
        lambda: authorization.commitment.operation_id(OPERATION, payload["requestDigest"]))
    plan._same(payload["operationId"], identity, work)


def _verify_control_on_work(*, grant_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, planner_public_key, expected_authorization_digest, live_window, work):
    """Signatures, scope and current liveness only: explicitly NOT proof replay."""
    capture._SharedLedger(work)
    raw = authorization._original(grant_bytes, MAX_GRANT_BYTES, "maintenance grant")
    enrollment_raw = authorization._original(grant_enrollment_bytes, MAX_ENROLLMENT_BYTES, "maintenance enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    authorization._public(root_public_key)
    authorization._public(planner_public_key)
    shape._digest(expected_authorization_digest)
    live = _Live(live_window)
    live.sample(work)
    material = _admit_enrollment(grant_enrollment_bytes=enrollment_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root_public_key, work=work)
    pins = _pins(material)
    _separate(material.authorizer, (planner_public_key,), work)
    envelope = _read(raw, enrollment=False, work=work)
    mechanics._signature(envelope, material.authorizer, MAX_GRANT_BYTES, work)
    payload = envelope["payload"]
    for name, expected in pins.items():
        plan._same(payload[name], expected, work)
    plan._same(payload["requestAuthorizationDigest"], expected_authorization_digest, work)
    live.bind(payload, material.payload)
    live.sample(work)
    _operation_identity(payload, work)
    mechanics._unchanged(raw, envelope, MAX_GRANT_BYTES, work)
    digest = framing._frame(GRANT_IDENTITY_DOMAIN, (raw,), work)
    live.sample(work)
    return payload, digest


def _hold(originals, expectations, before_vector_bytes, planner_public_key, live_window, work):
    capture._SharedLedger(work)
    _require(type(originals) is tuple and len(originals) == 3)
    for original, maximum in zip(originals, FRAME_MAXIMA, strict=True):
        authorization._original(original, maximum, "maintenance plan original")
    before = authorization._original(before_vector_bytes, current_root.vector.MAX_BYTES, "complete before vector")
    authorization._public(planner_public_key)
    expected = plan._expectations(expectations, work)
    shape._literal(expected["context"]["operation"], OPERATION)
    plan._request(originals[1], expected["context"], work)
    live = _Live(live_window, expected["context"]["originalDeadlineNs"])
    return originals, expected, before, live


def _replay(originals, expected, before, planner, read_original, check, live, work):
    _require(callable(read_original) and callable(check))

    def checked(stage):
        _require(type(stage) is current_root.compound._Stage)
        stage.check()
        live.sample(stage.work)
        _require(check(stage) is None)
        stage.check()
        live.sample(stage.work)

    live.sample(work)
    observed = current_root.replay_to_complete_vector(envelope_bytes=originals[0],
        request_bytes=originals[1], manifest_bytes=originals[2], expectations=expected,
        planner_public_key=planner, before_vector_bytes=before, read_original=read_original,
        check=checked, work=work)
    _require(type(observed) is current_root.MaintenanceVectorObservation)
    live.sample(work)
    return observed


def _claims(observed, originals, expected, work):
    """Private suffix reached only after this invocation's genuine replay."""
    frames = []
    for position, raw in enumerate(originals):
        work.charge(hashes=1, input_bytes=len(raw))
        frames.append({"position": position, "bytesDigest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "byteCount": len(raw)})
    context = expected["context"]
    result_raw = work.wire(observed.result)
    return {"operation": OPERATION,
        **{name: context[name] for name in ("requestDigest", "operationId", "configurationDigest")},
        "planDigest": observed.plan_digest, "manifestDigest": observed.manifest_digest,
        "beforeVectorDigest": observed.before_vector_digest, "afterVectorDigest": observed.after_vector_digest,
        "resultDigest": framing._frame(RESULT_DOMAIN, (result_raw,), work), "originalFrames": frames,
        "issuedAtEpochNs": observed.original_interval[0], "expiresAtEpochNs": observed.original_interval[1]}


def produce_grant(*, originals, expectations, planner_public_key, before_vector_bytes,
        grant_enrollment_bytes, current_root_enrollment_bytes, root_public_key, authorizer_private_key,
        expected_authorization_digest, live_window, read_original, check, work):
    """Sign only this call's full raw replay, with unchanged original issue/expiry."""
    enrollment_raw = authorization._original(grant_enrollment_bytes, MAX_ENROLLMENT_BYTES, "maintenance enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    authorization._public(root_public_key)
    authorization._private(authorizer_private_key)
    shape._digest(expected_authorization_digest)
    originals, expected, before, live = _hold(originals, expectations, before_vector_bytes,
        planner_public_key, live_window, work)
    live.sample(work)
    material = _admit_enrollment(grant_enrollment_bytes=enrollment_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root_public_key, work=work)
    pins = _pins(material)
    keys._pair_on_work(authorizer_private_key, material.authorizer, work)
    _separate(material.authorizer, (planner_public_key,), work)
    observed = _replay(originals, expected, before, planner_public_key, read_original, check, live, work)
    claims = _claims(observed, originals, expected, work)
    payload = {"schema": GRANT_PAYLOAD_SCHEMA, "sourceRevision": authorization.authority.SOURCE_REVISION,
        **pins, "requestAuthorizationDigest": expected_authorization_digest, **claims}
    _grant_shape(payload)
    _operation_identity(payload, work)
    live.bind(payload, material.payload)
    live.sample(work)
    owned_bytes = authorization.capability._wire(payload, capture._SharedLedger(work), MAX_GRANT_BYTES, MAX_NODES)
    raw = _sign(payload, private_key=authorizer_private_key, public_key=material.authorizer,
        enrollment=False, work=work)
    live.sample(work)
    verified, _digest = _verify_control_on_work(grant_bytes=raw, grant_enrollment_bytes=enrollment_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root_public_key,
        planner_public_key=planner_public_key, expected_authorization_digest=expected_authorization_digest,
        live_window=live.window, work=work)
    actual = authorization.capability._wire(verified, capture._SharedLedger(work), MAX_GRANT_BYTES, MAX_NODES)
    work.charge(input_bytes=len(owned_bytes) + len(actual))
    _require(actual == owned_bytes)
    live.sample(work)
    return raw


def verify_grant(*, grant_bytes, originals, expectations, planner_public_key, before_vector_bytes,
        grant_enrollment_bytes, current_root_enrollment_bytes, root_public_key,
        expected_authorization_digest, live_window, read_original, check, work):
    """Verify independent control AND independently replay the actual raw pages."""
    raw = authorization._original(grant_bytes, MAX_GRANT_BYTES, "maintenance grant")
    enrollment_raw = authorization._original(grant_enrollment_bytes, MAX_ENROLLMENT_BYTES, "maintenance enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    authorization._public(root_public_key)
    shape._digest(expected_authorization_digest)
    originals, expected, before, live = _hold(originals, expectations, before_vector_bytes,
        planner_public_key, live_window, work)
    live.sample(work)
    payload, digest = _verify_control_on_work(grant_bytes=raw, grant_enrollment_bytes=enrollment_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root_public_key,
        planner_public_key=planner_public_key, expected_authorization_digest=expected_authorization_digest,
        live_window=live.window, work=work)
    # The inner control verifier already admitted the enrolled policy. Preserve
    # its original grant expiry across proof replay, even if the transport's
    # original window happens to end later. Never sample a historical scalar.
    live.bind(payload, {"maximumGrantAgeNs": live.window[5], "maximumClockSkewNs": live.window[6]})
    observed = _replay(originals, expected, before, planner_public_key, read_original, check, live, work)
    for name, actual in _claims(observed, originals, expected, work).items():
        plan._same(payload[name], actual, work)
    live.sample(work)
    return VerifiedGrant(digest, payload, observed)
