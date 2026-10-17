"""Independent current root policy for unchanged-outcome recovery issuance.

Historical custody and enrollments are original evidence, never renewed live
release authority. Resource pins and the exact outcome come from this separate
root signature, not request fields, returned grants or directory observations.
No private key delivery, token, filesystem, service or retry authority is here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from catchplate import oidc_session_activation_release_client_authorization as client
from catchplate import authority_oidc_session_activation_release_intent as intents
from catchplate import authority_oidc_session_activation_release_proof as proofs
from catchplate import oidc_session_activation_release_proof_bootstrap as proof_bootstrap
from catchplate import oidc_session_activation_release_retained_authority as retained
from catchplate import authority_oidc_session_activation_consume_input_production as lifetime_source
from catchplate.authority_query_read_work import QueryReadWorkError


server, custody = client.server, client.server.custody
authorization, shape, plan = client.authorization, client.shape, client.plan
capture, production, clock = client.capture, client.production, client.clock
processing, authority, capability, keys = client.processing, client.authority, client.capability, client.keys
_Lifetime = lifetime_source._Lifetime
PURPOSE = "issue-oidc-session-activation-release-recovery-grants"
SCHEMA = "catchplate.signedOidcSessionActivationReleaseRecoveryIssuerPolicy/v1"
PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationReleaseRecoveryIssuerPolicy/v1"
V2_SCHEMA = "catchplate.signedOidcSessionActivationReleaseRecoveryIssuerPolicy/v2"
V2_PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationReleaseRecoveryIssuerPolicy/v2"
SIGNATURE_DOMAIN = SCHEMA
IDENTITY_DOMAIN = "catchplate.oidcSessionActivationReleaseRecoveryIssuerPolicyIdentity/v1"
PROFILE = server.RECOVERY_PROFILE
MAX_BYTES = 64 * 1024
MAX_CUSTODY_BYTES = custody.MAX_BYTES
MAX_PROOF_ENROLLMENT_BYTES = proofs.enrollments.MAX_BYTES
MAX_INTENT_ENROLLMENT_BYTES = intents.enrollments.MAX_BYTES
MAX_ORIGINAL_BYTES = authority.MAX_RESULT_BYTES
MAX_NODES, MAX_DEPTH = 1024, 6
MAX_RECEIPT_AGE_NS = server.MAX_RECEIPT_AGE_NS
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "trustMode",
    "proofEnrollmentDigest", "intentEnrollmentDigest", "proofScope", "callerId",
    "expectedRelease", "expectedEvidence", "expectedOutcomeDigest", "clientId",
    "clientIdentity", "endpoint", "releaseLaunch", "issuedAtEpochNs", "expiresAtEpochNs"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class OidcSessionActivationReleaseRecoveryIssuerPolicyError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseRecoveryIssuerPolicyError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _IssuerPolicyMaterial:
    """Owned same-call data; no verifier or producer accepts this as input."""

    policy_bytes: bytes
    release_custody_bytes: bytes
    proof_enrollment_bytes: bytes
    intent_enrollment_bytes: bytes
    policy_digest: str
    payload: dict
    custody_material: custody._ReleaseCustodyMaterial
    proof_public_key: object
    intent_public_key: object
    forbidden_public_keys: tuple
    client_id: str
    client_identity: dict
    endpoint: tuple
    release_launch: dict
    live_window: tuple
    deadline_ns: int
    live: object


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("recovery issuer policy exceeds its fixed structure bound")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("recovery issuer policy exceeds its fixed node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _payload_shape(payload, work):
    bridged = type(payload) is dict and payload.get("schema") == V2_PAYLOAD_SCHEMA
    shape._object(payload, PAYLOAD_FIELDS | {"currentReleaseCustodyDigest"} if bridged else PAYLOAD_FIELDS,
        "independent recovery issuer policy")
    if bridged:
        shape._digest(payload["currentReleaseCustodyDigest"])
    for name, expected in (("schema", V2_PAYLOAD_SCHEMA if bridged else PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("proofEnrollmentDigest", "intentEnrollmentDigest", "expectedOutcomeDigest"):
        shape._digest(payload[name])
    proofs.enrollments._scope_shape(payload["proofScope"])
    authorization._token(payload["callerId"])
    server._release_shape(payload["expectedRelease"], work)
    shape._object(payload["expectedEvidence"], proofs.EVIDENCE_FIELDS,
        "independent recovery evidence identities")
    for value in payload["expectedEvidence"].values():
        shape._digest(value)
    authorization._token(payload["clientId"])
    shape.validate_identity_shape(payload["clientIdentity"])
    endpoint = client._endpoint(payload["endpoint"], work)
    launch = payload["releaseLaunch"]
    server._launch_shape(launch, work)
    if (endpoint[0] != launch["listenerPath"]
            or endpoint[1] > launch["requestTimeoutSeconds"]
            or (launch["peerUid"], launch["peerGid"]) != (client.CLIENT_UID, client.CLIENT_GID)):
        _fail("recovery issuer endpoint exceeds the independently pinned release launch")
    authorization._interval(payload, MAX_RECEIPT_AGE_NS)
    _created, delivery_expiry = custody._scope(payload["expectedRelease"]["deliveryScope"], work)
    if payload["expiresAtEpochNs"] > delivery_expiry:
        _fail("fresh recovery policy extends the original delivery expiry")


def _read(original, work):
    raw = authorization._original(original, MAX_BYTES, "recovery issuer policy")
    decoded = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(decoded, work)
    shape._object(owned, _ENVELOPE_FIELDS, "signed recovery issuer policy")
    if owned["schema"] not in (SCHEMA, V2_SCHEMA):
        _fail("unsupported recovery issuer policy profile")
    shape._base64url(owned["signatureBase64Url"], signature=True)
    _payload_shape(owned["payload"], work)
    shape._literal(owned["schema"], V2_SCHEMA if owned["payload"]["schema"] == V2_PAYLOAD_SCHEMA else SCHEMA)
    _canonical(raw, owned, work)
    return owned


def _digest_on_work(original, work):
    raw = authorization._original(original, MAX_BYTES, "recovery issuer policy")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _custody_digest_on_work(original, work):
    raw = authorization._original(original, MAX_CUSTODY_BYTES, "historical release custody")
    return plan._frame(proofs.contract.CUSTODY_IDENTITY_DOMAIN, (raw,), work)


def _proof_enrollment_digest_on_work(original, work):
    raw = authorization._original(original, MAX_PROOF_ENROLLMENT_BYTES, "independent proof enrollment")
    return plan._frame(proofs.enrollments.IDENTITY_DOMAIN, (raw,), work)


def _intent_enrollment_digest_on_work(original, work):
    raw = authorization._original(original, MAX_INTENT_ENROLLMENT_BYTES, "independent intent enrollment")
    return plan._frame(intents.enrollments.IDENTITY_DOMAIN, (raw,), work)


def _originals(release_custody_bytes, proof_enrollment_bytes, intent_enrollment_bytes):
    return (authorization._original(release_custody_bytes, MAX_CUSTODY_BYTES, "historical release custody"),
        authorization._original(proof_enrollment_bytes, MAX_PROOF_ENROLLMENT_BYTES, "independent proof enrollment"),
        authorization._original(intent_enrollment_bytes, MAX_INTENT_ENROLLMENT_BYTES, "independent intent enrollment"))


def _inventory(policy_bytes, originals, work):
    # Reserve the source-bounded decoded planner/state originals before their
    # nested admission allocates them. The actual inventory is checked again.
    total = policy_bytes + sum(map(len, originals))
    if total + custody.planner_bootstrap.MAX_BYTES + authorization.MAX_ENROLLMENT_BYTES > MAX_ORIGINAL_BYTES:
        _fail("recovery issuer original inventory exceeds 64 MiB")
    work.charge(input_bytes=total)


def _signature(envelope, root, work):
    unsigned = _wire(envelope["payload"], work)
    try:
        capability._signature(root, envelope["signatureBase64Url"], envelope["schema"],
            unsigned, capture._SharedLedger(work))
    except InvalidSignature as exc:
        raise OidcSessionActivationReleaseRecoveryIssuerPolicyError(
            "recovery issuer policy root signature is invalid") from exc


def _admit(payload, originals, root, lifetime, work):
    custody_raw, proof_raw, intent_raw = originals
    current = lifetime.current
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    lifetime.narrow(expires, lifetime.window[5], lifetime.window[6])

    def policy_live():
        # Upstream base only: never recurse through attached child guards.
        now = lifetime.base()
        if issued > now + lifetime.window[6] or now >= expires:
            _fail("recovery issuer original policy is future-issued or expired")
        return now

    lifetime.attach(policy_live)
    current()
    bridged = payload["schema"] == V2_PAYLOAD_SCHEMA
    for actual, expected, label in (
            (_custody_digest_on_work(custody_raw, work), payload["currentReleaseCustodyDigest"] if bridged
                else payload["expectedEvidence"]["releaseCustodyDigest"], "custody"),
            (_proof_enrollment_digest_on_work(proof_raw, work), payload["proofEnrollmentDigest"], "proof enrollment"),
            (_intent_enrollment_digest_on_work(intent_raw, work), payload["intentEnrollmentDigest"], "intent enrollment")):
        plan._same(actual, expected, work, "recovery issuer independent exact " + label)
        current()
    verify_custody = custody._verify_on_work if bridged else custody._verify_historical_on_work
    material = verify_custody(custody_bytes=custody_raw, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _current=lifetime.base)
    if type(material) is not custody._ReleaseCustodyMaterial:
        _fail("recovery issuer requires actual historical custody-original admission")
    current()
    if bridged != (material.intent_root_public_key is not None):
        _fail("recovery policy and custody original profiles differ")
    evidence_root = retained.root_for(material, root)
    current_planner = retained.planner_for(material)
    retained.require_originals(material, intent_raw, proof_raw, work)
    if bridged:
        plan._same(_custody_digest_on_work(retained.custody_for(material), work),
            payload["expectedEvidence"]["releaseCustodyDigest"], work, "recovery exact RI evidence custody")
        plan._same(material.proof_scope, payload["proofScope"], work, "recovery independently pinned RI proof scope")
        lifetime.attach(custody.planner_bootstrap._launch_guard(material.attestation_interval,
            material.opening_sample, lifetime.base, work))
        lifetime.narrow(material.attestation_interval[1], current_planner.maximum_plan_age_ns,
            current_planner.maximum_clock_skew_ns)
    nested = material.planner.bootstrap_bytes, material.planner.state_enrollment_bytes
    if MAX_BYTES + sum(map(len, (*originals, *nested))) > MAX_ORIGINAL_BYTES:
        _fail("recovery issuer decoded original inventory exceeds 64 MiB")
    work.charge(input_bytes=sum(map(len, nested)))
    state = authorization._admit_enrollment_on_work(enrollment_bytes=nested[1],
        root_public_key=evidence_root, work=work)
    current()
    scope, release, evidence = payload["proofScope"], payload["expectedRelease"], payload["expectedEvidence"]
    for actual, expected, label in (
            (material.planner.configuration_digest, scope["configurationDigest"], "configuration"),
            (material.planner.generation["digest"], scope["generationDigest"], "generation"),
            (material.planner.runtime_closure_digest, scope["runtimeClosureDigest"], "runtime closure"),
            (material.receiver_identity, scope["receiverIdentity"], "receiver"),
            (state.enrollment_digest, material.planner.state_enrollment_digest, "state original"),
            (state.payload["databaseId"], scope["databaseId"], "database"),
            (state.payload["generationDigest"], scope["generationDigest"], "state generation"),
            (material.activation_request_digest, release["activationRequestDigest"], "activation request"),
            (material.activation_operation_id, release["activationOperationId"], "activation operation"),
            (material.consume_request_digest, release["consumeRequestDigest"], "consume request"),
            (material.delivery_envelope_digest, release["deliveryEnvelopeDigest"], "delivery envelope"),
            (material.delivery_scope, release["deliveryScope"], "delivery scope"),
            (material.release_intent_digest, evidence["releaseIntentDigest"], "intent original")):
        plan._same(actual, expected, work, "recovery issuer genuine historical " + label)
        current()
    forbidden = proof_bootstrap._unique_keys((material.planner.planner_public_key,
        state.computation_public_key, state.completion_public_key, state.state_public_key), work)
    intent_scope = {name: scope[name] for name in intents.SCOPE_FIELDS if name != "callerId"}
    intent_scope["callerId"] = payload["callerId"]
    intent_enrolled = intents.enrollments._admit_on_work(enrollment_bytes=intent_raw,
        root_public_key=evidence_root, expected_scope=intent_scope, forbidden_public_keys=forbidden, work=work)
    current()
    proof_enrolled = proofs.enrollments._admit_on_work(enrollment_bytes=proof_raw,
        root_public_key=evidence_root, expected_scope=scope,
        forbidden_public_keys=(*forbidden, intent_enrolled.caller_public_key), work=work)
    current()
    plan._same(intent_enrolled.enrollment_digest, payload["intentEnrollmentDigest"], work,
        "recovery issuer genuinely admitted intent enrollment")
    plan._same(proof_enrolled.enrollment_digest, payload["proofEnrollmentDigest"], work,
        "recovery issuer genuinely admitted proof enrollment")
    endpoint = client._endpoint(payload["endpoint"], work)
    _created, delivery_expiry = custody._scope(release["deliveryScope"], work)
    lifetime.narrow(min(expires, delivery_expiry),
        min(current_planner.maximum_plan_age_ns, intent_enrolled.payload["maximumAgeNs"],
            proof_enrolled.payload["maximumAgeNs"], endpoint[1] * 1_000_000_000),
        min(current_planner.maximum_clock_skew_ns, intent_enrolled.payload["maximumClockSkewNs"],
            proof_enrolled.payload["maximumClockSkewNs"]))
    current()
    return material, proof_enrolled.proof_public_key, intent_enrolled.caller_public_key, forbidden, endpoint


def _verify_on_work(*, policy_bytes, release_custody_bytes, proof_enrollment_bytes,
        intent_enrollment_bytes, root_public_key, live_window, transport_deadline_ns,
        work, _continuity=None):
    capture._SharedLedger(work)
    raw = authorization._original(policy_bytes, MAX_BYTES, "independent recovery issuer policy")
    originals = _originals(release_custody_bytes, proof_enrollment_bytes, intent_enrollment_bytes)
    root = root_public_key
    authorization._public(root)
    _inventory(len(raw), originals, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(window[4], transport_deadline_ns), work, _continuity)
    current = lifetime.current
    current()
    envelope = _read(raw, work)
    current()
    _signature(envelope, root, work)
    current()
    payload = envelope["payload"]
    material, proof_key, intent_key, forbidden, endpoint = _admit(payload, originals, root, lifetime, work)
    current()
    _canonical(raw, envelope, work)
    identity = _digest_on_work(raw, work)
    owned = _capture(payload, work)
    client_identity, launch = _capture(owned["clientIdentity"], work), _capture(owned["releaseLaunch"], work)
    current()
    return _IssuerPolicyMaterial(raw, *originals, identity, owned, material, proof_key, intent_key,
        forbidden, owned["clientId"], client_identity, endpoint, launch,
        lifetime.window, lifetime.bound, current)


def _produce_on_work(*, payload, release_custody_bytes, proof_enrollment_bytes,
        intent_enrollment_bytes, root_private_key, root_public_key, live_window,
        transport_deadline_ns, work, _continuity=None):
    """Sign this separate purpose only after genuine independent admission."""
    capture._SharedLedger(work)
    originals = _originals(release_custody_bytes, proof_enrollment_bytes, intent_enrollment_bytes)
    private, root = root_private_key, root_public_key
    authorization._private(private)
    authorization._public(root)
    owned = _capture(payload, work)
    _inventory(MAX_BYTES, originals, work)
    _payload_shape(owned, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(window[4], transport_deadline_ns), work, _continuity)
    current = lifetime.current
    current()
    _admit(owned, originals, root, lifetime, work)
    current()
    keys._pair_on_work(private, root, work)
    current()
    schema = V2_SCHEMA if owned["schema"] == V2_PAYLOAD_SCHEMA else SCHEMA
    envelope = {"schema": schema, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("recovery issuer policy signature exceeds its reserved output bound")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(schema) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("recovery issuer policy cannot reserve its signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("recovery issuer policy changed after measurement")
    message = plan._ascii(plan._frame(schema, (unsigned,), work), work)
    current()
    signature = production._sign_and_verify(private, root, message, work)
    current()
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("recovery issuer policy changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    original = plan.core.canonical_bytes({"schema": schema, "payload": owned, "signatureBase64Url": encoded})
    if len(original) != envelope_size:
        _fail("recovery issuer policy output differs from its preallocation reservation")
    current()
    readback = _read(original, work)
    _signature(readback, root, work)
    plan._same(readback["payload"], owned, work, "recovery issuer exact signed policy readback")
    current()
    return original
