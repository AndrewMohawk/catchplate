"""Independent root policy for post-intent private proof-worker setup.

This admits exact completion and signer originals, not a posted release target.
It neither acquires a packet nor proves committed private replay or provisioning.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from serverware import authority_oidc_session_activation_consume_input_production as lifetime_source
from serverware import oidc_session_activation_release_proof_bootstrap as bootstrap
from serverware.authority_query_read_work import QueryReadWorkError


completion = bootstrap.completion
proof_enrollments, intent_enrollments = bootstrap.proof_enrollments, bootstrap.intent_enrollments
authorization, shape, plan = bootstrap.authorization, bootstrap.shape, bootstrap.plan
capture, production, clock = bootstrap.capture, bootstrap.production, bootstrap.clock
capability, authority, processing = bootstrap.capability, bootstrap.authority, bootstrap.processing
keys = proof_enrollments.keys
_Lifetime = lifetime_source._Lifetime
PURPOSE = "issue-oidc-session-activation-release-proof-inputs"
SCHEMA = "serverware.signedOidcSessionActivationReleaseProofInputIssuerPolicy/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseProofInputIssuerPolicy/v1"
SIGNATURE_DOMAIN = SCHEMA
IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseProofInputIssuerPolicyIdentity/v1"
COMPLETION_BOOTSTRAP_IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseProofInputCompletionBootstrapIdentity/v1"
MAX_BYTES = 64 * 1024
MAX_COMPLETION_BOOTSTRAP_BYTES = completion.MAX_BYTES
MAX_ORIGINAL_BYTES = bootstrap.MAX_ORIGINAL_BYTES
MAX_RECEIPT_AGE_NS = completion.MAX_RECEIPT_AGE_NS
MAX_NODES, MAX_DEPTH = 512, 6
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "trustMode",
    "completionBootstrapDigest", "proofEnrollmentDigest", "intentEnrollmentDigest",
    "proofScope", "callerId", "proofLaunch", "issuedAtEpochNs", "expiresAtEpochNs"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class ReleaseProofInputIssuerPolicyError(ValueError):
    pass


def _fail(message):
    raise ReleaseProofInputIssuerPolicyError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _IssuerPolicyMaterial:
    policy_bytes: bytes
    completion_bootstrap_bytes: bytes
    proof_enrollment_bytes: bytes
    intent_enrollment_bytes: bytes
    policy_digest: str
    payload: dict
    completion_material: object
    proof_scope: dict
    caller_id: str
    proof_launch: dict
    proof_public_key: object
    intent_public_key: object
    forbidden_public_keys: tuple
    live_window: tuple
    deadline_ns: int
    live: object


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("proof input policy exceeds its fixed structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("proof input policy exceeds its node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _payload_shape(payload, work):
    shape._object(payload, PAYLOAD_FIELDS, "proof input issuer policy")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("completionBootstrapDigest", "proofEnrollmentDigest", "intentEnrollmentDigest"):
        shape._digest(payload[name])
    proof_enrollments._scope_shape(payload["proofScope"])
    authorization._token(payload["callerId"])
    bootstrap._launch_shape(payload["proofLaunch"], work)
    authorization._interval(payload, MAX_RECEIPT_AGE_NS)


def _read(original, work):
    raw = authorization._original(original, MAX_BYTES, "proof input issuer policy")
    decoded = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    envelope = _capture(decoded, work)
    shape._object(envelope, _ENVELOPE_FIELDS, "signed proof input policy")
    shape._literal(envelope["schema"], SCHEMA)
    shape._base64url(envelope["signatureBase64Url"], signature=True)
    _payload_shape(envelope["payload"], work)
    _canonical(raw, envelope, work)
    return envelope


def _signature(envelope, root, work):
    capability._signature(root, envelope["signatureBase64Url"], SIGNATURE_DOMAIN,
        _wire(envelope["payload"], work), capture._SharedLedger(work))


def _digest_on_work(original, work):
    raw = authorization._original(original, MAX_BYTES, "proof input issuer policy")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _completion_bootstrap_digest_on_work(original, work):
    raw = authorization._original(original, MAX_COMPLETION_BOOTSTRAP_BYTES, "proof input completion bootstrap")
    return plan._frame(COMPLETION_BOOTSTRAP_IDENTITY_DOMAIN, (raw,), work)


def _proof_enrollment_digest_on_work(original, work):
    raw = authorization._original(original, proof_enrollments.MAX_BYTES, "proof input proof enrollment")
    return plan._frame(proof_enrollments.IDENTITY_DOMAIN, (raw,), work)


def _intent_enrollment_digest_on_work(original, work):
    raw = authorization._original(original, intent_enrollments.MAX_BYTES, "proof input intent enrollment")
    return plan._frame(intent_enrollments.IDENTITY_DOMAIN, (raw,), work)


def _originals(completed, proof, intent, work, policy_size):
    values = (authorization._original(completed, completion.MAX_BYTES, "proof input completion bootstrap"),
        authorization._original(proof, proof_enrollments.MAX_BYTES, "proof input proof enrollment"),
        authorization._original(intent, intent_enrollments.MAX_BYTES, "proof input intent enrollment"))
    total = policy_size + sum(map(len, values))
    if total > MAX_ORIGINAL_BYTES:
        _fail("proof input policy original inventory exceeds 64 MiB")
    work.charge(input_bytes=total)
    return values


def _join(payload, originals, root, lifetime, work):
    current = lifetime.current
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    lifetime.narrow(interval[1], lifetime.window[5], lifetime.window[6])
    lifetime.attach(completion.primitives._launch_guard(interval,
        (lifetime.window[1], lifetime.window[0], lifetime.window[2]), lifetime.base, work))
    for raw, digest, field in zip(originals,
            (_completion_bootstrap_digest_on_work, _proof_enrollment_digest_on_work, _intent_enrollment_digest_on_work),
            ("completionBootstrapDigest", "proofEnrollmentDigest", "intentEnrollmentDigest")):
        plan._same(digest(raw, work), payload[field], work, "proof input exact independent " + field)
        current()
    cm = completion._verify_on_work(bootstrap_bytes=originals[0], root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _current=lifetime.base)
    if type(cm) is not completion._CompletionMaterial:
        _fail("proof input policy requires actual completion-original admission")
    for material in (cm, cm.custody_material, cm.custody_material.history):
        if not material.attestation_interval[0] <= interval[0] < interval[1] <= material.attestation_interval[1]:
            _fail("proof input policy escapes independently admitted completion authority")
        lifetime.attach(completion.primitives._launch_guard(material.attestation_interval,
            material.opening_sample, lifetime.base, work))
    scope = payload["proofScope"]
    for name, expected in (("configurationDigest", cm.configuration_digest), ("databaseId", cm.database_id),
            ("generationDigest", cm.generation_digest), ("runtimeClosureDigest", cm.runtime_closure_digest),
            ("producerIdentity", cm.receiver_identity)):
        plan._same(scope[name], expected, work, "proof input independent cohort " + name)
    state = authorization._admit_enrollment_on_work(enrollment_bytes=cm.current_root_enrollment_bytes,
        root_public_key=root, work=work)
    current()
    caller = completion.caller._admit_enrollment_on_work(
        authorization_enrollment_bytes=cm.authorization_enrollment_bytes,
        current_root_enrollment_bytes=cm.current_root_enrollment_bytes,
        grant_enrollment_bytes=cm.grant_enrollment_bytes, root_public_key=root,
        configuration_digest=cm.configuration_digest, planner_public_key=cm.planner_public_key,
        operation_public_key=cm.operation_public_key, work=work)
    current()
    grant = completion.grants._admit_enrollment_on_work(grant_enrollment_bytes=cm.grant_enrollment_bytes,
        current_root_enrollment_bytes=cm.current_root_enrollment_bytes, root_public_key=root, work=work)
    current()
    forbidden = bootstrap._unique_keys((cm.planner_public_key, cm.operation_public_key,
        state.computation_public_key, state.completion_public_key, state.state_public_key,
        caller.caller_public_key, grant.authorizer_public_key,
        cm.custody_material.history.planner.planner_public_key), work)
    intent_scope = {name: scope[name] for name in intent_enrollments.SCOPE_FIELDS if name != "callerId"}
    intent_scope["callerId"] = payload["callerId"]
    intent = intent_enrollments._admit_on_work(enrollment_bytes=originals[2], root_public_key=root,
        expected_scope=intent_scope, forbidden_public_keys=forbidden, work=work)
    current()
    proof = proof_enrollments._admit_on_work(enrollment_bytes=originals[1], root_public_key=root,
        expected_scope=scope, forbidden_public_keys=bootstrap._unique_keys(
            (*forbidden, intent.caller_public_key), work), work=work)
    current()
    plan._same(intent.enrollment_digest, payload["intentEnrollmentDigest"], work, "proof input actual intent enrollment")
    plan._same(proof.enrollment_digest, payload["proofEnrollmentDigest"], work, "proof input actual proof enrollment")
    completion._configured_keys(cm.configuration_payload, intent.payload["callerKey"]["spkiDigest"],
        proof.payload["proofKey"]["spkiDigest"], work)
    current()
    ages = (intent.payload["maximumAgeNs"], proof.payload["maximumAgeNs"],
        payload["proofLaunch"]["requestTimeoutSeconds"] * 1_000_000_000)
    lifetime.narrow(interval[1], min(ages), min(intent.payload["maximumClockSkewNs"],
        proof.payload["maximumClockSkewNs"]))
    nested = (cm.custody_bytes, cm.planner_bootstrap_bytes, cm.planner_history_custody_bytes,
        cm.receiving_history_custody_bytes, cm.authorization_bytes, cm.current_root_enrollment_bytes,
        cm.grant_enrollment_bytes, cm.authorization_enrollment_bytes)
    if MAX_BYTES + sum(map(len, (*originals, *nested))) > MAX_ORIGINAL_BYTES:
        _fail("proof input decoded original inventory exceeds 64 MiB")
    current()
    return cm, proof.proof_public_key, intent.caller_public_key, forbidden


def _verify_on_work(*, policy_bytes, completion_bootstrap_bytes, proof_enrollment_bytes,
        intent_enrollment_bytes, root_public_key, live_window, transport_deadline_ns, work,
        _continuity=None):
    capture._SharedLedger(work)
    root = root_public_key
    authorization._public(root)
    raw = authorization._original(policy_bytes, MAX_BYTES, "proof input issuer policy")
    originals = _originals(completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes, work, len(raw))
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(transport_deadline_ns, window[4]), work, _continuity)
    lifetime.current()
    envelope = _read(raw, work)
    lifetime.current()
    _signature(envelope, root, work)
    lifetime.current()
    payload = envelope["payload"]
    cm, proof, intent, forbidden = _join(payload, originals, root, lifetime, work)
    _canonical(raw, envelope, work)
    identity = _digest_on_work(raw, work)
    owned = _capture(payload, work)
    scope, launch = _capture(owned["proofScope"], work), _capture(owned["proofLaunch"], work)
    lifetime.current()
    return _IssuerPolicyMaterial(raw, *originals, identity, owned, cm,
        scope, owned["callerId"], launch,
        proof, intent, forbidden, lifetime.window, lifetime.bound, lifetime.current)


def _produce_on_work(*, payload, completion_bootstrap_bytes, proof_enrollment_bytes,
        intent_enrollment_bytes, root_private_key, root_public_key, live_window,
        transport_deadline_ns, work, _continuity=None):
    """Root-only publication of independent policy, not public payload signing."""
    capture._SharedLedger(work)
    private, root = root_private_key, root_public_key
    owned = _capture(payload, work)
    originals = _originals(completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes, work, MAX_BYTES)
    authorization._private(private)
    authorization._public(root)
    _payload_shape(owned, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(transport_deadline_ns, window[4]), work, _continuity)
    lifetime.current()
    _join(owned, originals, root, lifetime, work)
    live = lifetime.current
    keys._pair_on_work(private, root, work)
    live()
    envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("proof input policy signature exceeds its fixed output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SIGNATURE_DOMAIN) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("proof input policy cannot reserve its signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("proof input policy changed after measurement")
    message = plan._ascii(plan._frame(SIGNATURE_DOMAIN, (unsigned,), work), work)
    live()
    signature = production._sign_and_verify(private, root, message, work)
    live()
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("proof input policy changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    raw = plan.core.canonical_bytes({"schema": SCHEMA, "payload": owned, "signatureBase64Url": encoded})
    if len(raw) != envelope_size:
        _fail("proof input policy output differs from its reservation")
    readback = _read(raw, work)
    live()
    _signature(readback, root, work)
    live()
    plan._same(readback["payload"], owned, work, "proof input signed policy readback")
    live()
    return raw
