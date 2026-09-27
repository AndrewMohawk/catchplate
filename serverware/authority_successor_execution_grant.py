"""Original pre-decision execution grants under a separate root enrollment.

The dedicated authorizer key is not a computation, completion, state, planner
or operation-evidence key. Its genuine original signature authorizes a request
scope; plan replay only establishes the separately admitted plan semantics.
The caller must independently admit the expected request authorization digest,
plan keys/history and evaluation instant. None is adopted from returned data.

A grant precedes the reserve: its framed ORIGINAL signed-byte identity becomes
the reserve's capabilityDigest. It cannot commit the dependent pending receipt
or computation snapshot without creating a cycle. Revocation's original
signed capability ID and snapshot remain separate commitments.

Separate trusted producers construct root delegations and grants from genuine
originals; this verifier offers no signing API accepting a scope DTO. The
existing revocation database issuer has no independent all-operation authorizer key.
A trusted caller-authorization/signing owner, cold enrollment, key provisioning,
durable reservation and executor admission remain separate prerequisites.
Existing families retain their supplied-instant behavior. Activation full
verification requires actual private custody and the supplied original live
window, sampling current clocks before and after grant-control verification.
There is no SQL, new work allowance, retry or execution here.
The separate historical control entrypoint authenticates original commitments
for completion without claiming that an expired grant is executable again.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_plan_replay as replay
from serverware import authority_webauthn_evidence as evidence


authority, shape, capture, wire = (
    authorization.authority, authorization.shape, authorization.capture, authorization.wire)
plan, keys = authorization.plan, authorization.keys
ENROLLMENT_SCHEMA = "serverware.signedPolicyAuthoritySuccessorExecutionGrantEnrollment/v1"
ENROLLMENT_PAYLOAD_SCHEMA = "serverware.policyAuthoritySuccessorExecutionGrantEnrollment/v1"
ENROLLMENT_IDENTITY_DOMAIN = "serverware.policyAuthoritySuccessorExecutionGrantEnrollmentIdentity/v1"
GRANT_SCHEMA = "serverware.signedPolicyAuthoritySuccessorExecutionGrant/v1"
GRANT_PAYLOAD_SCHEMA = "serverware.policyAuthoritySuccessorExecutionGrant/v1"
GRANT_IDENTITY_DOMAIN = "serverware.policyAuthoritySuccessorExecutionGrantIdentity/v1"
MAX_GRANT_BYTES = 64 * 1024
MAX_ENROLLMENT_BYTES = 16 * 1024
MAX_NODES, MAX_DEPTH = 4096, 6
# Root delegation covers exactly implemented replay, not every source planner.
OPERATIONS = tuple(sorted(replay.OPERATIONS))
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_KEY_FIELDS = frozenset({"publicKeyPem", "spkiDigest", "measurementDigest"})
ENROLLMENT_FIELDS = frozenset({"schema", "sourceRevision", "currentRootEnrollmentDigest",
    "databaseId", "generationDigest", "operations", "authorizer",
    "maximumGrantAgeNs", "maximumClockSkewNs"})
GRANT_FIELDS = frozenset({"schema", "sourceRevision", "grantEnrollmentDigest",
    "currentRootEnrollmentDigest", "databaseId", "generationDigest", "authorizerMeasurementDigest",
    "operation", "requestDigest", "operationId", "requestAuthorizationDigest", "retainedRecordDigest",
    "planDigest", "beforeVectorDigest", "afterVectorDigest", "resultDigest", "originalFrames",
    "originalIssuedAtEpochNs", "originalExpiresAtEpochNs", "issuedAtEpochNs", "expiresAtEpochNs",
    "signedSnapshotDigest", "signedCapabilityId"})
_GRANT_DIGESTS = ("grantEnrollmentDigest", "currentRootEnrollmentDigest", "generationDigest",
    "authorizerMeasurementDigest", "requestDigest", "operationId", "requestAuthorizationDigest",
    "retainedRecordDigest", "planDigest", "beforeVectorDigest", "afterVectorDigest", "resultDigest")
_FRAME_FIELDS = frozenset({"position", "bytesDigest", "byteCount"})


class SuccessorExecutionGrantError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Enrollment:
    payload: dict
    enrollment_digest: str
    authorizer_public_key: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedGrant:
    """Ordinary same-call output; no public verifier accepts this as input."""

    grant_digest: str
    payload: dict
    replayed: object


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            raise SuccessorExecutionGrantError("successor grant structure exceeds its source bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            raise SuccessorExecutionGrantError("successor grant node bound exceeded")
        return result


def _enrollment_shape(payload):
    shape._object(payload, ENROLLMENT_FIELDS, "successor grant enrollment")
    shape._literal(payload["schema"], ENROLLMENT_PAYLOAD_SCHEMA)
    shape._literal(payload["sourceRevision"], authority.SOURCE_REVISION)
    for name in ("currentRootEnrollmentDigest", "generationDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    operations = payload["operations"]
    if (type(operations) is not list or len(operations) != len(OPERATIONS)
            or any(type(value) is not str for value in operations) or tuple(operations) != OPERATIONS):
        raise SuccessorExecutionGrantError("grant enrollment does not name the exact supported replay operations")
    record = payload["authorizer"]
    shape._object(record, _KEY_FIELDS, "successor grant authorizer")
    for name in ("spkiDigest", "measurementDigest"):
        shape._digest(record[name])
    pem = record["publicKeyPem"]
    if (type(pem) is not str or not 1 <= len(pem) <= authorization.MAX_PEM_BYTES
            or not pem.isascii() or "\x00" in pem):
        raise SuccessorExecutionGrantError("grant authorizer PEM is not bounded original ASCII")
    shape._integer(payload["maximumGrantAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(payload["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)


def _grant_shape(payload):
    shape._object(payload, GRANT_FIELDS, "successor execution grant")
    shape._literal(payload["schema"], GRANT_PAYLOAD_SCHEMA)
    shape._literal(payload["sourceRevision"], authority.SOURCE_REVISION)
    operation = payload["operation"]
    replay.delta._source(operation)
    for name in _GRANT_DIGESTS:
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    for name in ("originalIssuedAtEpochNs", "originalExpiresAtEpochNs", "issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[name], minimum=1)
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if (issued != payload["originalIssuedAtEpochNs"] or expires <= issued
            or expires > payload["originalExpiresAtEpochNs"]):
        raise SuccessorExecutionGrantError("grant renews or escapes its original plan interval")
    revocation = operation == replay.REVOCATION_OPERATION
    for name in ("signedSnapshotDigest", "signedCapabilityId"):
        if revocation:
            shape._digest(payload[name])
        elif payload[name] is not None:
            raise SuccessorExecutionGrantError("grant invents another family's signed capability or snapshot")
    maxima = replay._frame_maxima(operation)
    count = len(maxima)
    frames = payload["originalFrames"]
    if type(frames) is not list or len(frames) != count:
        raise SuccessorExecutionGrantError("grant original inventory differs from its source family")
    total = 0
    for position, frame in enumerate(frames):
        shape._object(frame, _FRAME_FIELDS, "grant original frame")
        shape._integer(frame["position"], count - 1)
        if frame["position"] != position:
            raise SuccessorExecutionGrantError("grant original frame order changed")
        shape._digest(frame["bytesDigest"])
        shape._integer(frame["byteCount"], maxima[position], minimum=2)
        total += frame["byteCount"]
    if total > authority.MAX_RESULT_BYTES:
        raise SuccessorExecutionGrantError("grant original inventory exceeds the source aggregate")


def _read(original, *, enrollment, work):
    maximum, schema = ((MAX_ENROLLMENT_BYTES, ENROLLMENT_SCHEMA) if enrollment
        else (MAX_GRANT_BYTES, GRANT_SCHEMA))
    authorization._original(original, maximum, "successor grant control")
    decoded = wire._decode_object(original, work=work, maximum_bytes=maximum,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    shape._object(decoded, _ENVELOPE_FIELDS, "successor grant signed envelope")
    shape._literal(decoded["schema"], schema)
    shape._base64url(decoded["signatureBase64Url"], signature=True)
    (_enrollment_shape if enrollment else _grant_shape)(decoded["payload"])
    owned = _Capture(capture._SharedLedger(work), maximum_bytes=maximum).visit(decoded)
    _unchanged(original, owned, maximum, work)
    return owned


def _unchanged(original, envelope, maximum, work):
    authorization.capability._canonical(original, envelope,
        capture._SharedLedger(work), maximum, MAX_NODES)


def _signature(envelope, public_key, maximum, work):
    authorization._public(public_key)
    ledger = capture._SharedLedger(work)
    payload_bytes = authorization.capability._wire(envelope["payload"], ledger, maximum, MAX_NODES)
    authorization.capability._signature(public_key, envelope["signatureBase64Url"],
        envelope["schema"], payload_bytes, ledger)


def _admit_enrollment_on_work(*, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, work):
    """Admit original root-signed authorizer delegation, not caller config data."""
    capture._SharedLedger(work)
    grant_raw = authorization._original(grant_enrollment_bytes, MAX_ENROLLMENT_BYTES, "grant enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    root_key = root_public_key
    authorization._public(root_key)
    envelope = _read(grant_raw, enrollment=True, work=work)
    _signature(envelope, root_key, MAX_ENROLLMENT_BYTES, work)
    current = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
        root_public_key=root_key, work=work)
    payload = envelope["payload"]
    for name, expected in (("currentRootEnrollmentDigest", current.enrollment_digest),
            ("databaseId", current.payload["databaseId"]), ("generationDigest", current.payload["generationDigest"])):
        plan._same(payload[name], expected, work, "grant enrollment " + name)
    authorizer = authorization._role_key(payload["authorizer"], work)
    authorizer_spki = keys._spki_on_work(authorizer, work)
    for other in (root_key, current.computation_public_key, current.completion_public_key, current.state_public_key):
        actual = keys._spki_on_work(other, work)
        work.prepare_comparison(authorizer_spki, actual)
        if authorizer_spki == actual:
            raise SuccessorExecutionGrantError("grant authorizer key is not independent of root/state producers")
    _unchanged(grant_raw, envelope, MAX_ENROLLMENT_BYTES, work)
    digest = plan._frame(ENROLLMENT_IDENTITY_DOMAIN, (grant_raw,), work)
    return _Enrollment(payload, digest, authorizer)


def _verify_control(*, grant_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, planner_public_key, operation_public_key,
        expected_authorization_digest, now_epoch_ns, historical, work):
    """Authenticate original control/scope/time, without claiming plan replay.

    A combined owner must compare every plan claim to its own genuine same-call
    original replay. The independent expected authorization digest must never
    be copied from this grant or from a planner's returned context.
    """
    capture._SharedLedger(work)
    if type(historical) is not bool or historical and now_epoch_ns is not None:
        raise SuccessorExecutionGrantError("grant admission purpose is not source-selected")
    raw = authorization._original(grant_bytes, MAX_GRANT_BYTES, "execution grant")
    enrollment_raw = authorization._original(grant_enrollment_bytes, MAX_ENROLLMENT_BYTES, "grant enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    root_key, planner_key, operation_key = root_public_key, planner_public_key, operation_public_key
    for key in (root_key, planner_key, operation_key):
        authorization._public(key)
    shape._digest(expected_authorization_digest)
    if not historical:
        shape._integer(now_epoch_ns, minimum=1)
    expected_scope, now = expected_authorization_digest, now_epoch_ns
    envelope = _read(raw, enrollment=False, work=work)
    material = _admit_enrollment_on_work(grant_enrollment_bytes=enrollment_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root_key, work=work)
    policy = material.payload
    # Keep signed policy scalars independent of later native key callbacks.
    policy_pins = (material.enrollment_digest, policy["currentRootEnrollmentDigest"],
        policy["databaseId"], policy["generationDigest"], policy["authorizer"]["measurementDigest"],
        policy["maximumGrantAgeNs"], policy["maximumClockSkewNs"])
    authorizer_spki = keys._spki_on_work(material.authorizer_public_key, work)
    for other in (planner_key, operation_key):
        actual = keys._spki_on_work(other, work)
        work.prepare_comparison(authorizer_spki, actual)
        if authorizer_spki == actual:
            raise SuccessorExecutionGrantError("planner or operation signature cannot substitute for grant authorization")
    _signature(envelope, material.authorizer_public_key, MAX_GRANT_BYTES, work)
    payload = envelope["payload"]
    for name, expected in (("grantEnrollmentDigest", policy_pins[0]),
            ("currentRootEnrollmentDigest", policy_pins[1]),
            ("databaseId", policy_pins[2]), ("generationDigest", policy_pins[3]),
            ("authorizerMeasurementDigest", policy_pins[4]),
            ("requestAuthorizationDigest", expected_scope)):
        plan._same(payload[name], expected, work, "execution grant " + name)
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if expires - issued > policy_pins[5]:
        raise SuccessorExecutionGrantError("execution grant original interval exceeds its enrolled age")
    if not historical and (issued > now + policy_pins[6]
            or now - issued > policy_pins[5] or now >= expires):
        raise SuccessorExecutionGrantError("execution grant is not live within its original enrolled interval")
    operation_size = work.prepare_utf8(payload["operation"])
    request_size = work.prepare_utf8(payload["requestDigest"])
    work.charge(hashes=1, input_bytes=len("serverware.policyAuthorityOperation/v2") + 17
        + operation_size + request_size)
    identity = authorization.production._callback(work, lambda: authorization.commitment.operation_id(
        payload["operation"], payload["requestDigest"]))
    plan._same(payload["operationId"], identity, work, "execution grant actual operation identity")
    _unchanged(raw, envelope, MAX_GRANT_BYTES, work)
    return payload, plan._frame(GRANT_IDENTITY_DOMAIN, (raw,), work)


def _verify_control_on_work(*, grant_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, planner_public_key, operation_public_key,
        expected_authorization_digest, now_epoch_ns, work):
    """Original signatures/scope plus actual supplied-instant grant freshness."""
    return _verify_control(grant_bytes=grant_bytes, grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes, root_public_key=root_public_key,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        expected_authorization_digest=expected_authorization_digest, now_epoch_ns=now_epoch_ns,
        historical=False, work=work)


def _verify_historical_control_on_work(*, grant_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key, operation_public_key,
        expected_authorization_digest, work):
    """Original grant commitments for completion, with no live authority claim.

    Original issue/expiry and enrolled maximum age remain checked. No supplied
    or self-declared historical instant is substituted for a real current clock.
    This cannot authorize SQL, revive a grant or release a pending fence.
    """
    return _verify_control(grant_bytes=grant_bytes, grant_enrollment_bytes=grant_enrollment_bytes,
        current_root_enrollment_bytes=current_root_enrollment_bytes, root_public_key=root_public_key,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        expected_authorization_digest=expected_authorization_digest, now_epoch_ns=None,
        historical=True, work=work)


def _replay_claims(replayed, work):
    frames = []
    for position, original in enumerate(replayed.originals):
        work.charge(hashes=1, input_bytes=len(original))
        frames.append({"position": position, "bytesDigest": "sha256:" + hashlib.sha256(original).hexdigest(),
            "byteCount": len(original)})
    result_digest = evidence.plan._json_digest("serverware.policyAuthorityControlledWriterResult/v2",
        replayed.result, evidence.capture._SharedLedger(work))
    return {"operation": replayed.operation, "requestDigest": replayed.request["requestDigest"],
        "operationId": replayed.request["operationId"], "retainedRecordDigest": replayed.retained_record_digest,
        "planDigest": replayed.plan_digest, "beforeVectorDigest": replayed.before_vector_digest,
        "afterVectorDigest": replayed.after_vector_digest, "resultDigest": result_digest,
        "originalFrames": frames, "originalIssuedAtEpochNs": replayed.original_interval[0],
        "originalExpiresAtEpochNs": replayed.original_interval[1],
        "signedSnapshotDigest": replayed.signed_snapshot_digest, "signedCapabilityId": replayed.signed_capability_id}


def _verify_on_work(*, grant_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, operation, originals, expectations, planner_public_key, operation_public_key,
        before_vector_bytes, expected_authorization_digest, now_epoch_ns, work,
        activation_custody=None, live_window=None, transport_deadline_ns=None):
    """Verify original grant and genuine original plan once on the same work.

    Activation retains a real supplied window and inherited bound: its live
    control checks use actual current samples, never the supplied historical
    now scalar. Other families keep their existing supplied-instant behavior.
    """
    capture._SharedLedger(work)
    raw = authorization._original(grant_bytes, MAX_GRANT_BYTES, "execution grant")
    enrollment_raw = authorization._original(grant_enrollment_bytes, MAX_ENROLLMENT_BYTES, "grant enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    original_operation = operation
    held_originals, held_before = replay._originals(original_operation, originals, before_vector_bytes)
    if sum(map(len, (*held_originals, held_before, raw, enrollment_raw, current_raw))) > authority.MAX_RESULT_BYTES:
        raise SuccessorExecutionGrantError("execution grant originals exceed the existing aggregate bound")
    root_key, planner_key, operation_key = root_public_key, planner_public_key, operation_public_key
    authorization._public(root_key)
    shape._digest(expected_authorization_digest)
    shape._integer(now_epoch_ns, minimum=1)
    expected_scope, now = expected_authorization_digest, now_epoch_ns
    held_custody, window, current = activation_custody, None, None
    if original_operation == replay.ACTIVATION_OPERATION:
        from serverware import authority_oidc_session_activation_execution_custody as activation_owner
        from serverware import oidc_session_activation_delivery as activation_delivery

        if type(held_custody) is not activation_owner.OidcSessionActivationExecutionCustody:
            raise SuccessorExecutionGrantError("activation grant verification requires actual private custody")
        shape._integer(transport_deadline_ns, minimum=1)
        window, current = activation_delivery._window(live_window, transport_deadline_ns, work)
    elif held_custody is not None:
        raise SuccessorExecutionGrantError("activation custody cannot verify another grant family")
    owned = replay._expectations(original_operation, expectations, planner_key, operation_key, work)
    if current is not None:
        current()
    replay._activation_context_on_work(original_operation, held_custody,
        root_public_key=root_key, current_root_enrollment_bytes=current_raw, work=work)
    if current is not None:
        current()
    replayed = replay._replay_on_work(operation=original_operation, originals=held_originals,
        expectations=owned, planner_public_key=planner_key, operation_public_key=operation_key,
        before_vector_bytes=held_before, work=work, activation_custody=held_custody,
        live_window=window, transport_deadline_ns=transport_deadline_ns)
    expected = _replay_claims(replayed, work)
    if current is not None:
        now = current()
    payload, digest = _verify_control_on_work(grant_bytes=raw, grant_enrollment_bytes=enrollment_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root_key,
        planner_public_key=planner_key, operation_public_key=operation_key,
        expected_authorization_digest=expected_scope, now_epoch_ns=now, work=work)
    if current is not None and current() >= payload["expiresAtEpochNs"]:
        raise SuccessorExecutionGrantError("activation grant expired during original control verification")
    for name, value in expected.items():
        plan._same(payload[name], value, work, "execution grant genuine replay " + name)
    result = _VerifiedGrant(digest, payload, replayed)
    if current is not None and current() >= payload["expiresAtEpochNs"]:
        raise SuccessorExecutionGrantError("activation grant expired before verified return")
    return result
