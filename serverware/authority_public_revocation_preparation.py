"""Actual measured public-revocation preparation and original-only replay.

The serving verifier authenticates the independent cold caller before reading
an assertion or contacting a planner. A fresh purpose-specific current-root
observation binds the complete database vector. The same actual verifier signs
the raw prepared inventory, including the original historical context; later
roles do not invent expectations from unauthenticated returned metadata.

This stage performs no reservation, SQL write, approval consumption or retry.
All subsequent effects must replay these originals and separately admit the
execution grant/current-root reservation. Returned Python facts are not inputs
accepted as successful authority by another public method.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets
import time

from serverware import authority_public_revocation_request as request_wire
from serverware import authority_public_revocation_caller_authorization as caller
from serverware import authority_public_webauthn_revocation as aggregate
from serverware import authority_revocation_verifier as configured
from serverware import authority_current_root_revocation_head as head_wire
from serverware import authority_current_root_vector as vector
from serverware import authority_current_root_plan_replay as replay
from serverware import authority_current_root_transport as state_wire
from serverware import authority_webauthn_evidence_plan_clock as clock


HISTORY_SCHEMA = "serverware.signedPublicWebAuthnRevocationPreparation/v1"
HISTORY_PAYLOAD_SCHEMA = "serverware.publicWebAuthnRevocationPreparation/v1"
MAX_HISTORY_BYTES = 16 * 1024
_HISTORY_FIELDS = frozenset({"schema", "sourceRevision", "configurationDigest", "generationDigest",
    "requestAuthorizationDigest", "requestOriginalDigest", "originalDigests",
    "issuedAtEpochNs", "expiresAtEpochNs"})
_HISTORY_ENVELOPE = frozenset({"schema", "payload", "signatureBase64Url"})
_STATE_ENDPOINT = ("/run/serverware/current-root/state.sock", 30, 0, 0)
_IDENTITY_NAMES = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _OriginalReplay:
    authorization: object
    request: dict
    expectations: dict
    head: dict
    replayed: object
    planner: object
    verifier: object


def _originals(values, *, prepared=False):
    from serverware import control_plane_public_revocation_records as framing
    index = framing._profile("prepared" if prepared else "request")
    if type(values) is not tuple or any(type(raw) is not bytes for raw in values):
        raise aggregate.PublicRevocationError("public revocation requires its exact original byte tuple")
    framing._lengths(index, tuple(len(raw) for raw in values))
    return values


def _actual_configuration(process, work):
    from serverware import authority_service as service
    from serverware import authority_launch_guard as launch
    if (type(process) is not service.AuthorityProcess or process.role_name != "verifier"
            or process.process_mode != service.PROCESS_MODES["verifier"]
            or type(process.configuration) is not service.MeasuredConfiguration):
        raise aggregate.PublicRevocationError("public revocation requires the actual measured verifier")
    observation = process.configuration
    caller.production._callback(work, lambda: launch.require_active("verifier"))
    generation = caller.production._callback(work, lambda: dict(launch.generation()))
    owner = configured._verifier_from_configuration_on_work(payload=observation.payload,
        configuration_digest=observation.digest, generation=generation,
        runtime_role_identities=observation.runtime_role_identities, work=work)
    pins = configured.RevocationPlanVerifier._snapshot_configuration(owner)
    return observation, generation, pins


def _current(window, bound, work):
    now = clock._check_on_work(window, work=work)
    instant = caller.production._callback(work, time.monotonic_ns)
    caller.shape._integer(instant, minimum=1)
    if instant >= bound:
        raise aggregate.PublicRevocationError("public revocation original processing deadline expired")
    return now, instant


def _hashes(originals, work):
    from serverware import authority_revocation_retention as retention
    return [retention._bytes_digest(raw, work) for raw in originals]


def _history_shape(value):
    caller.shape._object(value, _HISTORY_ENVELOPE, "public revocation preparation original")
    caller.shape._literal(value["schema"], HISTORY_SCHEMA)
    caller.shape._base64url(value["signatureBase64Url"], signature=True)
    payload = value["payload"]
    caller.shape._object(payload, _HISTORY_FIELDS, "public revocation preparation payload")
    caller.shape._literal(payload["schema"], HISTORY_PAYLOAD_SCHEMA)
    caller.shape._literal(payload["sourceRevision"], request_wire.authority.SOURCE_REVISION)
    for name in ("configurationDigest", "generationDigest", "requestAuthorizationDigest", "requestOriginalDigest"):
        caller.shape._digest(payload[name])
    hashes = payload["originalDigests"]
    if type(hashes) is not list or len(hashes) != 5:
        raise aggregate.PublicRevocationError("public revocation preparation inventory is not raw five")
    for item in hashes:
        caller.shape._digest(item)
    caller.authorization._interval(payload, aggregate.MAX_AGE_NS)


def _sign_history(process, raw5, authorization, configuration_digest, generation_digest, window, work):
    now, _mono = _current(window, window[4], work)
    payload = {"schema": HISTORY_PAYLOAD_SCHEMA, "sourceRevision": request_wire.authority.SOURCE_REVISION,
        "configurationDigest": configuration_digest, "generationDigest": generation_digest,
        "requestAuthorizationDigest": authorization.authorization_digest,
        "requestOriginalDigest": authorization.request_original_digest,
        "originalDigests": _hashes(raw5, work), "issuedAtEpochNs": now,
        "expiresAtEpochNs": min(window[3], authorization.expires_at_epoch_ns)}
    envelope = {"schema": HISTORY_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
    _history_shape(envelope)
    message = caller.plan._frame(HISTORY_SCHEMA,
        (caller.authorization.capability._wire(payload, caller.capture._SharedLedger(work),
            MAX_HISTORY_BYTES, 256),), work).encode("ascii")
    signature = caller.production._callback(work, lambda: process.signing_key.sign(message))
    if type(signature) is not bytes or len(signature) != 64:
        raise aggregate.PublicRevocationError("public revocation preparation signature is not Ed25519")
    work.charge(input_bytes=64 + 88 + 86)
    envelope["signatureBase64Url"] = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return caller.authorization.capability._wire(envelope, caller.capture._SharedLedger(work),
        MAX_HISTORY_BYTES, 256)


def _join_request(originals, *, configuration_digest, root, planner, verifier, window, bound, work,
        historical=False):
    current_raw, grant_raw, enrollment_raw, authorization_raw, original = _originals(originals)
    verify = caller._verify_historical_on_work if historical else caller._verify_on_work
    admitted = verify(authorization_bytes=authorization_raw, authorization_enrollment_bytes=enrollment_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=configuration_digest,
        planner_public_key=planner, evidence_public_key=verifier,
        live_window=window, transport_deadline_ns=bound, work=work)
    body = request_wire.decode(original, work=work)
    caller.plan._same(request_wire.original_digest(original, work=work), admitted.request_original_digest,
        work, "public revocation complete HTTP-purpose original differs from its caller signature")
    caller.plan._same((body["request"]["requestDigest"], body["request"]["operationId"]),
        (admitted.request_digest, admitted.operation_id), work,
        "public revocation caller signature names another semantic request")
    enrollment = caller._admit_enrollment_on_work(authorization_enrollment_bytes=enrollment_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=configuration_digest,
        planner_public_key=planner, evidence_public_key=verifier, work=work)
    caller.plan._same(body["policy"], enrollment.payload["mutationPolicy"], work,
        "public revocation policy differs from independent root enrollment")
    return admitted, body


def prepare_on_process(process, *, originals, live_window, transport_deadline_ns, work):
    """Actual verifier -> full vector/head -> optional assertion -> real plan."""
    from serverware import authority_service as service
    from serverware import authority_launch_guard as launch
    from serverware import authority_current_root_reader as roots

    originals = _originals(originals)
    window = clock._validate(live_window)
    bound = min(window[4], transport_deadline_ns)
    observation, generation, pins = _actual_configuration(process, work)
    signer = process.signing_key
    caller.keys._pair_on_work(signer, pins[1], work)
    admitted, body = _join_request(originals, configuration_digest=observation.digest,
        root=observation.root_key, planner=pins[0], verifier=pins[1], window=window, bound=bound, work=work)
    expires = min(window[3], admitted.expires_at_epoch_ns)
    window = clock._validate((*window[:3], expires,
        min(window[4], window[1] + expires - window[0]), window[5], window[6]))
    bound = min(bound, window[4])
    last_epoch, last_mono = window[0], window[2]

    def current():
        nonlocal last_epoch, last_mono
        if (process.configuration is not observation or process.signing_key is not signer
                or process.role_name != "verifier"):
            raise aggregate.PublicRevocationError("public revocation measured owner changed")
        caller.production._callback(work, lambda: launch.require_active("verifier"))
        actual = caller.production._callback(work, lambda: dict(launch.generation()))
        caller.plan._same(actual, generation, work, "public revocation active generation changed")
        now, mono = _current(window, bound, work)
        if now < last_epoch or mono < last_mono:
            raise aggregate.PublicRevocationError("public revocation clocks reversed")
        last_epoch, last_mono = now, mono
        return now

    current()
    role = observation.payload["roles"]["verifier"]
    timeout = role["databaseConnectTimeoutSeconds"]
    if type(timeout) not in (int, float) or not 2 <= timeout <= 300:
        raise aggregate.PublicRevocationError("public revocation verifier database timeout is not bounded")
    dsn = caller.production._callback(work, lambda: service._read_dsn_descriptor(
        "SERVERWARE_POLICY_AUTHORITY_VERIFIER_READ_POSTGRES_DSN"))
    reader = roots.CurrentRootReader(dsn=dsn, connect_timeout_seconds=int(timeout),
        database_role=role["databaseRole"], tls_client_dn=role["tlsClientDn"],
        tls_client_serial=role["tlsClientSerial"], tls_issuer_dn=role["tlsIssuerDn"],
        query_manifest_digest=observation.payload["queryManifestDigest"])
    before = reader.read(work=work)
    current()
    before_digest = vector.framing._frame(vector.IDENTITY_DOMAIN, (before,), work)
    query_context = caller.plan._frame("serverware.publicWebAuthnRevocationHeadContext/v1",
        (admitted.authorization_digest.encode("ascii"), admitted.request_original_digest.encode("ascii")), work)
    work.charge(input_bytes=32 + 43)
    nonce = caller.production._callback(work, lambda: secrets.token_bytes(32))
    if type(nonce) is not bytes or len(nonce) != 32 or nonce == bytes(32):
        raise aggregate.PublicRevocationError("public revocation current-root challenge is invalid")
    query = head_wire._encode_query_on_work(enrollment_digest=admitted.current_root_enrollment_digest,
        context_digest=query_context, expected_vector_digest=before_digest,
        challenge=base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="), work=work)
    observed = state_wire._revocation_head_on_work(_STATE_ENDPOINT,
        query_bytes=query, deadline_ns=bound, work=work, current=current)
    head = head_wire._verify_on_work(observation_bytes=observed, query_bytes=query,
        enrollment_bytes=originals[0], root_public_key=observation.root_key,
        now_epoch_ns=current(), work=work)
    if head["pendingRequestDigest"] is not None or head["pendingDecisionDigest"] is not None:
        raise aggregate.PublicRevocationError("public revocation cannot replace unresolved current-root work")
    capability = caller.plan._frame("serverware.publicWebAuthnRevocationCapability/v1",
        (admitted.authorization_digest.encode("ascii"),), work)
    transaction = caller.plan._frame("serverware.policyAuthorityPlannerTransaction/v1",
        tuple(value.encode("ascii") for value in (admitted.operation_id, admitted.request_digest, capability)), work)
    assertion = None
    if body["assertion"] is not None:
        assertion, _receipt, _digest = service.AuthorityProcess._build_v9_webauthn_evidence(process,
            operation=aggregate.OPERATION, operation_id=admitted.operation_id,
            request_digest=admitted.request_digest, capability_id=capability,
            authorization_reference=body["assertion"], deadline_epoch_ns=expires,
            arguments=body["request"]["arguments"])
        current()
    started = current()
    aggregate_value = {"schema": aggregate.SCHEMA, "operation": aggregate.OPERATION,
        "operationId": admitted.operation_id, "requestDigest": admitted.request_digest,
        "capabilityId": capability, "actor": body["actor"], "policy": body["policy"],
        "payloadDigest": body["payloadDigest"], "approval": body["approval"], "assertion": assertion,
        "verifierIdentity": dict(zip(_IDENTITY_NAMES, pins[3])), "verifiedAtEpochNs": started,
        "expiresAtEpochNs": expires, "signatureBase64Url": "A" * 86}
    signed = aggregate._sign_on_verified_process(process, aggregate_value, work=work)
    now, mono = _current(window, bound, work)
    context = {"expectedCapabilityId": capability, "expectedPlannerTransactionId": transaction,
        "expectedFence": head["fence"] + 1, "reservedAtEpochNs": started,
        "deadlineEpochNs": expires, "deadlineMonotonicNs": bound,
        "nowEpochNs": now, "nowMonotonicNs": mono, "expectedApproverPolicyDigest": None}
    plan_raw, context_raw = service.AuthorityProcess._request_revocation_observed_plan(process,
        request=body["request"], evidence=signed, context=context, work=work)
    current()
    raw5 = (plan_raw, context_raw, before, query, observed)
    history = _sign_history(process, raw5, admitted, observation.digest, pins[9], window, work)
    result = _originals((*raw5, history), prepared=True)
    current()
    # Genuine replay also joins the independently observed COMPLETE vector,
    # not merely the operation-specific subset acquired by the planner path.
    verify_prepared(payload=observation.payload, configuration_digest=observation.digest,
        generation=generation, runtime_role_identities=observation.runtime_role_identities,
        root_public_key=observation.root_key, originals=originals, prepared=result,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()
    return result


def verify_prepared(*, payload, configuration_digest, generation, runtime_role_identities,
        root_public_key, originals, prepared, live_window, transport_deadline_ns, work, historical=False):
    """Replay exact signed originals; no caller-supplied success object accepted."""
    originals, prepared = _originals(originals), _originals(prepared, prepared=True)
    window = clock._validate(live_window)
    bound = min(window[4], transport_deadline_ns)
    owner = configured._verifier_from_configuration_on_work(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    pins = configured.RevocationPlanVerifier._snapshot_configuration(owner)
    admitted, body = _join_request(originals, configuration_digest=configuration_digest,
        root=root_public_key, planner=pins[0], verifier=pins[1], window=window, bound=bound,
        work=work, historical=historical)
    history = caller.authorization.wire._decode_object(prepared[5], work=work,
        maximum_bytes=MAX_HISTORY_BYTES, maximum_nodes=256, maximum_depth=4)
    _history_shape(history)
    caller.authorization._verify_signature(history, HISTORY_SCHEMA, pins[1], MAX_HISTORY_BYTES, work)
    caller.primitives._unchanged(prepared[5], history, MAX_HISTORY_BYTES, work)
    facts = history["payload"]
    for actual, expected in ((facts["configurationDigest"], configuration_digest),
            (facts["generationDigest"], pins[9]), (facts["requestAuthorizationDigest"], admitted.authorization_digest),
            (facts["requestOriginalDigest"], admitted.request_original_digest),
            (facts["originalDigests"], _hashes(prepared[:5], work))):
        caller.plan._same(actual, expected, work, "public revocation preparation original scope changed")
    now, _mono = _current(window, bound, work)
    if not admitted.issued_at_epoch_ns <= facts["issuedAtEpochNs"] < facts["expiresAtEpochNs"] <= admitted.expires_at_epoch_ns:
        raise aggregate.PublicRevocationError("public revocation preparation escapes its original caller interval")
    if facts["issuedAtEpochNs"] > now or not historical and now >= facts["expiresAtEpochNs"]:
        raise aggregate.PublicRevocationError("public revocation preparation is future or expired")
    if historical:
        head, _head_enrollment = head_wire._verify_historical_with_enrollment_on_work(observation_bytes=prepared[4],
            query_bytes=prepared[3], enrollment_bytes=originals[0], root_public_key=root_public_key,
            live_window=window, transport_deadline_ns=bound, work=work)
    else:
        head = head_wire._verify_on_work(observation_bytes=prepared[4], query_bytes=prepared[3],
            enrollment_bytes=originals[0], root_public_key=root_public_key, now_epoch_ns=now, work=work)
    # Historical helper returns its actual authenticated payload, not a state lease.
    query = head_wire._decode_query_on_work(prepared[3], work=work)
    expected_context = caller.plan._frame("serverware.publicWebAuthnRevocationHeadContext/v1",
        (admitted.authorization_digest.encode("ascii"), admitted.request_original_digest.encode("ascii")), work)
    caller.plan._same(query["contextDigest"], expected_context, work, "public revocation head names another caller")
    caller.plan._same(query["expectedVectorDigest"], vector.framing._frame(vector.IDENTITY_DOMAIN,
        (prepared[2],), work), work, "public revocation complete vector differs from the actual state observation")
    if head["pendingRequestDigest"] is not None or head["pendingDecisionDigest"] is not None:
        raise aggregate.PublicRevocationError("public revocation preparation begins with unresolved state")
    retention = configured.handoff.retention
    context = caller.authorization.wire._decode_object(prepared[1], work=work,
        maximum_bytes=retention.MAX_CONTEXT_BYTES, maximum_nodes=retention.MAX_CONTEXT_NODES,
        maximum_depth=retention.MAX_CONTEXT_DEPTH)
    caller.shape._object(context, retention._CONTEXT_FIELDS, "public revocation historical context")
    caller.shape._literal(context["schema"], retention.CONTEXT_SCHEMA)
    caller.shape._literal(context["sourceRevision"], request_wire.authority.SOURCE_REVISION)
    capability = caller.plan._frame("serverware.publicWebAuthnRevocationCapability/v1",
        (admitted.authorization_digest.encode("ascii"),), work)
    transaction = caller.plan._frame("serverware.policyAuthorityPlannerTransaction/v1",
        tuple(value.encode("ascii") for value in (admitted.operation_id, admitted.request_digest, capability)), work)
    for field, expected in (("expectedPlannerIdentity", dict(zip(_IDENTITY_NAMES, pins[2]))),
            ("expectedVerifierIdentity", dict(zip(_IDENTITY_NAMES, pins[3]))),
            ("maximumAssertionAgeNs", pins[4]), ("maximumPlanAgeNs", pins[5]),
            ("maximumClockSkewNs", pins[6]), ("expectedCapabilityId", capability),
            ("expectedPlannerTransactionId", transaction), ("expectedFence", head["fence"] + 1),
            ("expectedApproverPolicyDigest", None)):
        caller.plan._same(context[field], expected, work, "public revocation independent context " + field)
    if not (admitted.issued_at_epoch_ns <= context["reservedAtEpochNs"] <= facts["issuedAtEpochNs"]
            < context["deadlineEpochNs"] <= admitted.expires_at_epoch_ns):
        raise aggregate.PublicRevocationError("public revocation retained plan interval escapes its caller")
    cutoff = context["databaseCutoffUs"]
    if type(cutoff) is not int or not -(2**63) <= cutoff < 2**63:
        raise aggregate.PublicRevocationError("public revocation cutoff is not an exact signed int64")
    expected = {argument: context[name] for name, argument in retention._CONTEXT_PAIRS}
    expected.update(expected_request=body["request"], database_now=_EPOCH + timedelta(microseconds=cutoff))
    observed = replay._replay_on_work(operation=aggregate.OPERATION, originals=prepared[:2],
        expectations=expected, planner_public_key=pins[0], operation_public_key=pins[1],
        before_vector_bytes=prepared[2], work=work)
    _current(window, bound, work)
    return _OriginalReplay(admitted, body["request"], expected, head, observed, pins[0], pins[1])
