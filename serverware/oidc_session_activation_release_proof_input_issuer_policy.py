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
from serverware.authority_local_limits import LOCAL_SESSION_MAX_NS


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
V2_SCHEMA = "serverware.signedOidcSessionActivationReleaseProofInputIssuerPolicy/v2"
V2_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseProofInputIssuerPolicy/v2"
V3_SCHEMA = "serverware.signedOidcSessionActivationReleaseProofInputIssuerPolicy/v3"
V3_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseProofInputIssuerPolicy/v3"
SIGNATURE_DOMAIN = SCHEMA
IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseProofInputIssuerPolicyIdentity/v1"
COMPLETION_BOOTSTRAP_IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseProofInputCompletionBootstrapIdentity/v1"
V1_MAX_BYTES = 64 * 1024
V2_MAX_BYTES = 6 * 1024 * 1024
V3_MAX_BYTES = V2_MAX_BYTES
MAX_BYTES = V2_MAX_BYTES
MAX_COMPLETION_BOOTSTRAP_BYTES = completion.MAX_BYTES
MAX_ORIGINAL_BYTES = bootstrap.MAX_ORIGINAL_BYTES
MAX_RECEIPT_AGE_NS = completion.MAX_RECEIPT_AGE_NS
MAX_NODES, MAX_DEPTH = 512, 6
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "trustMode",
    "completionBootstrapDigest", "proofEnrollmentDigest", "intentEnrollmentDigest",
    "proofScope", "callerId", "proofLaunch", "issuedAtEpochNs", "expiresAtEpochNs"})
V2_PAYLOAD_FIELDS = PAYLOAD_FIELDS | {"currentActivationPlanner"}
V3_PAYLOAD_FIELDS = (PAYLOAD_FIELDS - {"completionBootstrapDigest"}) | {"activationIssuancePolicy"}
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
    current_activation_planner_bytes: bytes | None
    current_activation_planner: object | None


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
    v2 = type(payload) is dict and payload.get("schema") == V2_PAYLOAD_SCHEMA
    v3 = type(payload) is dict and payload.get("schema") == V3_PAYLOAD_SCHEMA
    shape._object(payload, V3_PAYLOAD_FIELDS if v3 else V2_PAYLOAD_FIELDS if v2 else PAYLOAD_FIELDS, "proof input issuer policy")
    for name, expected in (("schema", V3_PAYLOAD_SCHEMA if v3 else V2_PAYLOAD_SCHEMA if v2 else PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in (("proofEnrollmentDigest", "intentEnrollmentDigest") if v3 else
            ("completionBootstrapDigest", "proofEnrollmentDigest", "intentEnrollmentDigest")):
        shape._digest(payload[name])
    proof_enrollments._scope_shape(payload["proofScope"])
    authorization._token(payload["callerId"])
    bootstrap._launch_shape(payload["proofLaunch"], work)
    authorization._interval(payload, LOCAL_SESSION_MAX_NS if v3 else MAX_RECEIPT_AGE_NS)
    if v2:
        original = payload["currentActivationPlanner"]
        maximum = bootstrap.release_bootstrap.planner_bootstrap.MAX_BYTES
        shape._object(original, bootstrap._ORIGINAL_FIELDS, "proof input current activation planner")
        shape._integer(original["byteCount"], maximum, minimum=2)
        authorization.transport._transport_shape(original["base64Url"], original["byteCount"], maximum)
        shape._digest(original["bytesDigest"])
    if v3:
        from serverware import oidc_session_activation_request_issuance_policy as resources
        original = payload["activationIssuancePolicy"]
        shape._object(original, bootstrap._ORIGINAL_FIELDS, "proof static activation issuance policy")
        shape._integer(original["byteCount"], resources.MAX_BYTES, minimum=2)
        authorization.transport._transport_shape(original["base64Url"], original["byteCount"], resources.MAX_BYTES)
        shape._digest(original["bytesDigest"])


def _read(original, work):
    raw = authorization._original(original, MAX_BYTES, "proof input issuer policy")
    decoded = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    envelope = _capture(decoded, work)
    shape._object(envelope, _ENVELOPE_FIELDS, "signed proof input policy")
    shape._base64url(envelope["signatureBase64Url"], signature=True)
    _payload_shape(envelope["payload"], work)
    v2 = envelope["payload"]["schema"] == V2_PAYLOAD_SCHEMA
    v3 = envelope["payload"]["schema"] == V3_PAYLOAD_SCHEMA
    shape._literal(envelope["schema"], V3_SCHEMA if v3 else V2_SCHEMA if v2 else SCHEMA)
    if len(raw) > (V3_MAX_BYTES if v3 else V2_MAX_BYTES if v2 else V1_MAX_BYTES):
        _fail("proof input policy exceeds its exact version bound")
    _canonical(raw, envelope, work)
    return envelope


def _signature(envelope, root, work):
    capability._signature(root, envelope["signatureBase64Url"], envelope["schema"],
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
    if _cold_reservation_bytes(policy_size, *(len(raw) for raw in values)) > MAX_ORIGINAL_BYTES:
        _fail("proof input policy original inventory exceeds 64 MiB")
    work.charge(input_bytes=total)
    return values


def _cold_reservation_bytes(policy_size, completion_size, proof_size, intent_size):
    """Extra original/canonical graphs for an actual repeated policy admission."""
    sizes = policy_size, completion_size, proof_size, intent_size
    maxima = MAX_BYTES, completion.MAX_BYTES, proof_enrollments.MAX_BYTES, intent_enrollments.MAX_BYTES
    if any(type(size) is not int or not 2 <= size <= maximum for size, maximum in zip(sizes, maxima)):
        _fail("proof input cold reservation requires exact bounded original lengths")
    return 8 * sum(sizes) + 128 * 1024


def _current_planner_bytes(payload, work, current):
    """Extract the versioned original only; this supplies no authority."""
    _payload_shape(payload, work)
    if payload["schema"] in (PAYLOAD_SCHEMA, V3_PAYLOAD_SCHEMA):
        return None
    return completion.grammar._original(payload["currentActivationPlanner"],
        bootstrap.release_bootstrap.planner_bootstrap.MAX_BYTES, work, current)


def _join(payload, originals, root, lifetime, work):
    current = lifetime.current
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    lifetime.narrow(interval[1], lifetime.window[5], lifetime.window[6])
    lifetime.attach(completion.primitives._launch_guard(interval,
        (lifetime.window[1], lifetime.window[0], lifetime.window[2]), lifetime.base, work))
    resource_material = None
    if payload["schema"] == V3_PAYLOAD_SCHEMA:
        from serverware import oidc_session_activation_release_proof_resources as resources
        resource_material = resources._admit_on_work(payload=payload,
            proof_enrollment_bytes=originals[1], intent_enrollment_bytes=originals[2], root_public_key=root,
            live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
            _continuity=lifetime.continuity)
        lifetime.attach(resource_material.live)
    joins = zip(originals,
            (_completion_bootstrap_digest_on_work, _proof_enrollment_digest_on_work, _intent_enrollment_digest_on_work),
            ("completionBootstrapDigest", "proofEnrollmentDigest", "intentEnrollmentDigest"))
    for raw, digest, field in joins:
        if resource_material is not None and field == "completionBootstrapDigest":
            # No future completion is selected by the cold resource policy.
            # The actual late original is authenticated immediately below.
            continue
        plan._same(digest(raw, work), payload[field], work, "proof input exact independent " + field)
        current()
    cm = completion._verify_on_work(bootstrap_bytes=originals[0], root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _current=lifetime.base)
    if type(cm) is not completion._CompletionMaterial:
        _fail("proof input policy requires actual completion-original admission")
    for material in (cm, cm.custody_material, cm.custody_material.history):
        if resource_material is None and not material.attestation_interval[0] <= interval[0] < interval[1] <= material.attestation_interval[1]:
            _fail("proof input policy escapes independently admitted completion authority")
        if resource_material is not None:
            lifetime.narrow(material.attestation_interval[1], lifetime.window[5], lifetime.window[6])
        lifetime.attach(completion.primitives._launch_guard(material.attestation_interval,
            material.opening_sample, lifetime.base, work))
    if resource_material is not None:
        resources._late_on_work(resource_material, cm, root_public_key=root, lifetime=lifetime, work=work)
        lifetime.attach(cm.custody_material.live)
    current_original = _current_planner_bytes(payload, work, current)
    current_planner = None
    if current_original is not None:
        current_planner = bootstrap._current_activation_on_work(current_original,
            completion_material=cm, root_public_key=root, live_window=lifetime.window,
            transport_deadline_ns=lifetime.bound, work=work, _current=lifetime.base)
        lifetime.narrow(interval[1], current_planner.maximum_plan_age_ns,
            current_planner.maximum_clock_skew_ns)
        lifetime.attach(cm.custody_material.live)
        current()
    evidence_root = root if current_planner is None else cm.evidence_root_public_key
    configuration = cm.configuration_payload if current_planner is None else current_planner.configuration_payload
    scope = payload["proofScope"]
    for name, expected in (("configurationDigest", cm.configuration_digest if current_planner is None else current_planner.configuration_digest),
            ("databaseId", cm.database_id),
            ("generationDigest", cm.generation_digest if current_planner is None else current_planner.generation["digest"]),
            ("runtimeClosureDigest", cm.runtime_closure_digest if current_planner is None else current_planner.runtime_closure_digest),
            ("producerIdentity", cm.receiver_identity)):
        plan._same(scope[name], expected, work, "proof input independent cohort " + name)
    state = authorization._admit_enrollment_on_work(enrollment_bytes=cm.current_root_enrollment_bytes,
        root_public_key=evidence_root, work=work)
    current()
    caller = completion.caller._admit_enrollment_on_work(
        authorization_enrollment_bytes=cm.authorization_enrollment_bytes,
        current_root_enrollment_bytes=cm.current_root_enrollment_bytes,
        grant_enrollment_bytes=cm.grant_enrollment_bytes, root_public_key=evidence_root,
        configuration_digest=cm.configuration_digest, planner_public_key=cm.planner_public_key,
        operation_public_key=cm.operation_public_key, work=work)
    current()
    grant = completion.grants._admit_enrollment_on_work(grant_enrollment_bytes=cm.grant_enrollment_bytes,
        current_root_enrollment_bytes=cm.current_root_enrollment_bytes, root_public_key=evidence_root, work=work)
    current()
    forbidden = bootstrap._unique_keys((cm.planner_public_key, cm.operation_public_key,
        state.computation_public_key, state.completion_public_key, state.state_public_key,
        caller.caller_public_key, grant.authorizer_public_key,
        cm.custody_material.history.planner.planner_public_key), work)
    if current_planner is not None:
        forbidden = bootstrap._unique_keys((*forbidden, root, evidence_root,
            cm.custody_material.history.historical_root_public_key,
            current_planner.planner_public_key), work)
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
    completion._configured_keys(configuration, intent.payload["callerKey"]["spkiDigest"],
        proof.payload["proofKey"]["spkiDigest"], work)
    current()
    ages = (intent.payload["maximumAgeNs"], proof.payload["maximumAgeNs"],
        payload["proofLaunch"]["requestTimeoutSeconds"] * 1_000_000_000)
    lifetime.narrow(interval[1], min(ages), min(intent.payload["maximumClockSkewNs"],
        proof.payload["maximumClockSkewNs"]))
    nested = (cm.custody_bytes, cm.planner_bootstrap_bytes, cm.planner_history_custody_bytes,
        cm.receiving_history_custody_bytes, cm.authorization_bytes, cm.current_root_enrollment_bytes,
        cm.grant_enrollment_bytes, cm.authorization_enrollment_bytes)
    if MAX_BYTES + sum(map(len, (*originals, *nested))) + (0 if current_original is None else len(current_original)) > MAX_ORIGINAL_BYTES:
        _fail("proof input decoded original inventory exceeds 64 MiB")
    current()
    return cm, proof.proof_public_key, intent.caller_public_key, forbidden, current_original, current_planner


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
    cm, proof, intent, forbidden, current_original, current_planner = _join(payload, originals, root, lifetime, work)
    _canonical(raw, envelope, work)
    identity = _digest_on_work(raw, work)
    owned = _capture(payload, work)
    scope, launch = _capture(owned["proofScope"], work), _capture(owned["proofLaunch"], work)
    lifetime.current()
    return _IssuerPolicyMaterial(raw, *originals, identity, owned, cm,
        scope, owned["callerId"], launch,
        proof, intent, forbidden, lifetime.window, lifetime.bound, lifetime.current,
        current_original, current_planner)


def _produce_on_work(*, payload, completion_bootstrap_bytes, proof_enrollment_bytes,
        intent_enrollment_bytes, root_private_key, root_public_key, live_window,
        transport_deadline_ns, work, _continuity=None):
    """Root-only publication of independent policy, not public payload signing."""
    capture._SharedLedger(work)
    private, root = root_private_key, root_public_key
    owned = _capture(payload, work)
    authorization._private(private)
    authorization._public(root)
    _payload_shape(owned, work)
    v2 = owned["schema"] == V2_PAYLOAD_SCHEMA
    v3 = owned["schema"] == V3_PAYLOAD_SCHEMA
    maximum = V3_MAX_BYTES if v3 else V2_MAX_BYTES if v2 else V1_MAX_BYTES
    schema = V3_SCHEMA if v3 else V2_SCHEMA if v2 else SCHEMA
    policy_size, _policy_nodes = work.measure(owned)
    if policy_size > maximum:
        _fail("proof input policy payload exceeds its version bound")
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(transport_deadline_ns, window[4]), work, _continuity)
    lifetime.current()
    if v3:
        from serverware import oidc_session_activation_release_proof_resources as resources
        if completion_bootstrap_bytes is not None:
            _fail("static proof resource publication cannot select a future completion")
        static = resources._admit_on_work(payload=owned, proof_enrollment_bytes=proof_enrollment_bytes,
            intent_enrollment_bytes=intent_enrollment_bytes, root_public_key=root,
            live_window=window, transport_deadline_ns=lifetime.bound, work=work,
            _continuity=lifetime.continuity)
        lifetime.attach(static.live)
    else:
        originals = _originals(completion_bootstrap_bytes, proof_enrollment_bytes,
            intent_enrollment_bytes, work, min(maximum, policy_size + 256))
        _join(owned, originals, root, lifetime, work)
    live = lifetime.current
    keys._pair_on_work(private, root, work)
    live()
    envelope = {"schema": schema, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > maximum or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("proof input policy signature exceeds its fixed output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(schema) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("proof input policy cannot reserve its signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("proof input policy changed after measurement")
    message = plan._ascii(plan._frame(schema, (unsigned,), work), work)
    live()
    signature = production._sign_and_verify(private, root, message, work)
    live()
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("proof input policy changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    raw = plan.core.canonical_bytes({"schema": schema, "payload": owned, "signatureBase64Url": encoded})
    if len(raw) != envelope_size:
        _fail("proof input policy output differs from its reservation")
    readback = _read(raw, work)
    live()
    _signature(readback, root, work)
    live()
    plan._same(readback["payload"], owned, work, "proof input signed policy readback")
    live()
    return raw
