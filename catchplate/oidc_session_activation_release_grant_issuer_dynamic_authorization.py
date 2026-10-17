"""Independent cold authority for exact fresh-proof grant-issuer delivery.

Only original bytes enter admission. The derived outputs retain the existing
grant policy/bootstrap schemas and six-FD worker contract. Resource pins are
authorization, not observations, and no private key bytes are read here.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from catchplate import authority_oidc_session_activation_release_grant_input_delivery_transport as transport
from catchplate import oidc_session_activation_release_grant_issuer_bootstrap as bootstrap
from catchplate import oidc_session_activation_release_proof_input_delivery_admission as admission


issuer = admission.issuer
policy = bootstrap.issuer
authorization, shape, plan = issuer.authorization, issuer.shape, issuer.plan
capture, production, clock = issuer.capture, issuer.production, issuer.clock
capability, authority, keys = issuer.capability, issuer.authority, issuer.keys
processing = issuer.processing
_Lifetime = issuer._Lifetime
SCHEMA = "catchplate.signedOidcSessionActivationReleaseGrantIssuerDynamicAuthorization/v1"
PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationReleaseGrantIssuerDynamicAuthorization/v1"
PURPOSE = "stage-oidc-session-activation-release-grant-issuer"
IDENTITY_DOMAIN = "catchplate.oidcSessionActivationReleaseGrantIssuerDynamicAuthorizationIdentity/v1"
INTAKE_PATH = "/run/catchplate/oidc-session-activation-token-release/grant-issuer-bootstrap.sock"
INTAKE_PEER_UID = INTAKE_PEER_GID = 65494
MAX_BYTES = 64 * 1024
MAX_POLICY_BYTES = issuer.MAX_BYTES
MAX_COMPLETION_BOOTSTRAP_BYTES = issuer.MAX_COMPLETION_BOOTSTRAP_BYTES
MAX_PROOF_ENROLLMENT_BYTES = issuer.proof_enrollments.MAX_BYTES
MAX_INTENT_ENROLLMENT_BYTES = issuer.intent_enrollments.MAX_BYTES
MAX_PROOF_BOOTSTRAP_BYTES = policy.MAX_PROOF_BOOTSTRAP_BYTES
MAX_KEY_BYTES = bootstrap.MAX_KEY_BYTES
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES
MAX_NODES, MAX_DEPTH = 512, 8
_OUTPUT_RESERVATION = 4 * (policy.MAX_BYTES + bootstrap.MAX_BYTES)
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "trustMode",
    "proofInputIssuerPolicyDigest", "clientId", "clientIdentity", "endpoint", "releaseLaunch",
    "issuerLaunch", "rootSigningKey", "intake", "issuedAtEpochNs", "expiresAtEpochNs"})
_INTAKE_FIELDS = frozenset({"path", "peerUid", "peerGid", "requestTimeoutSeconds",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class ReleaseGrantIssuerDynamicAuthorizationError(ValueError):
    pass


def _fail(message):
    raise ReleaseGrantIssuerDynamicAuthorizationError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AuthorizationMaterial:
    authorization_bytes: bytes
    proof_input_issuer_policy_bytes: bytes
    completion_bootstrap_bytes: bytes
    proof_enrollment_bytes: bytes
    intent_enrollment_bytes: bytes
    input_policy_material: issuer._IssuerPolicyMaterial
    payload: dict
    issuer_launch: dict
    root_signing_key_byte_count: int
    root_signing_key_digest: str
    live_window: tuple
    deadline_ns: int
    live: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AdmittedMaterial:
    authorization_material: _AuthorizationMaterial
    proof_bootstrap_bytes: bytes
    proof_material: object
    bootstrap_identity: bytes
    live_window: tuple
    deadline_ns: int
    live: object


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("dynamic grant issuer authorization exceeds its structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("dynamic grant issuer authorization exceeds its node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "dynamic grant issuer authorization")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    shape._digest(payload["proofInputIssuerPolicyDigest"])
    authorization._token(payload["clientId"])
    shape.validate_identity_shape(payload["clientIdentity"])
    endpoint = policy.client._endpoint(payload["endpoint"], work)
    policy.server._launch_shape(payload["releaseLaunch"], work)
    release = payload["releaseLaunch"]
    if (endpoint[0] != release["listenerPath"] or endpoint[1] > release["requestTimeoutSeconds"]
            or (release["peerUid"], release["peerGid"]) != (policy.client.CLIENT_UID, policy.client.CLIENT_GID)):
        _fail("dynamic grant client endpoint exceeds its independently pinned release launch")
    launch = payload["issuerLaunch"]
    bootstrap._launch_shape(launch, work)
    shape._literal(launch["schema"], bootstrap.DELIVERY_LAUNCH_SCHEMA)
    key = payload["rootSigningKey"]
    shape._object(key, frozenset({"byteCount", "bytesDigest"}), "dynamic grant issuer signer")
    shape._integer(key["byteCount"], MAX_KEY_BYTES, minimum=2)
    shape._digest(key["bytesDigest"])
    intake = payload["intake"]
    shape._object(intake, _INTAKE_FIELDS, "dynamic grant issuer intake")
    shape._literal(intake["path"], INTAKE_PATH)
    for name, expected in (("peerUid", INTAKE_PEER_UID), ("peerGid", INTAKE_PEER_GID)):
        shape._integer(intake[name], 2**32 - 2, minimum=1)
        if intake[name] != expected:
            _fail("dynamic grant issuer intake peer is not source fixed")
    shape._integer(intake["requestTimeoutSeconds"], 30, minimum=1)
    if intake["requestTimeoutSeconds"] > launch["requestTimeoutSeconds"]:
        _fail("dynamic grant intake timeout exceeds the original issuer allowance")
    for name in ("listenerSocketDevice", "listenerPathDevice"):
        shape._integer(intake[name], 2**64 - 1)
    for name in ("listenerSocketInode", "listenerPathInode"):
        shape._integer(intake[name], 2**64 - 1, minimum=1)
    authorization._interval(payload, min(policy.MAX_RECEIPT_AGE_NS, bootstrap.MAX_RECEIPT_AGE_NS))


def _read(original, work):
    raw = authorization._original(original, MAX_BYTES, "dynamic grant issuer authorization")
    decoded = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(decoded, work)
    shape._object(owned, _ENVELOPE_FIELDS, "signed dynamic grant issuer authorization")
    shape._literal(owned["schema"], SCHEMA)
    shape._base64url(owned["signatureBase64Url"], signature=True)
    _payload_shape(owned["payload"], work)
    _canonical(raw, owned, work)
    return owned


def _digest_on_work(original, work):
    raw = authorization._original(original, MAX_BYTES, "dynamic grant issuer authorization")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _inputs(authorization_bytes, proof_input_issuer_policy_bytes, completion_bootstrap_bytes,
        proof_enrollment_bytes, intent_enrollment_bytes):
    return tuple(authorization._original(raw, maximum, label) for raw, maximum, label in (
        (authorization_bytes, MAX_BYTES, "dynamic grant issuer authorization"),
        (proof_input_issuer_policy_bytes, MAX_POLICY_BYTES, "independent proof input policy"),
        (completion_bootstrap_bytes, MAX_COMPLETION_BOOTSTRAP_BYTES, "independent completion bootstrap"),
        (proof_enrollment_bytes, MAX_PROOF_ENROLLMENT_BYTES, "independent proof enrollment"),
        (intent_enrollment_bytes, MAX_INTENT_ENROLLMENT_BYTES, "independent intent enrollment")))


def _maximum(value):
    maximum = MAX_ORIGINAL_BYTES if value is None else value
    if type(maximum) is not int or not 2 <= maximum <= MAX_ORIGINAL_BYTES:
        _fail("dynamic grant issuer inventory capacity may only tighten 64 MiB")
    return maximum


def _reserve(originals, proof, maximum, work):
    # Bound nested decoded originals and complete output/readback copies before
    # either original admission allocates; owner-held resources are additional.
    required = (8 * len(originals[2]) + 16 * len(proof) + 8 * len(originals[1])
        + 4 * sum(len(raw) for index, raw in enumerate(originals) if index not in (1, 2))
        + _OUTPUT_RESERVATION + MAX_KEY_BYTES)
    if required > maximum:
        _fail("dynamic grant issuer originals and output reservation exceed retained capacity")
    work.charge(input_bytes=sum(map(len, originals)) + len(proof))


def _signature(envelope, root, work):
    try:
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA,
            _wire(envelope["payload"], work), capture._SharedLedger(work))
    except InvalidSignature as exc:
        raise ReleaseGrantIssuerDynamicAuthorizationError("dynamic grant issuer root signature is invalid") from exc


def _verify_on_work(*, authorization_bytes, proof_input_issuer_policy_bytes,
        completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes,
        root_public_key, live_window, transport_deadline_ns, work, _continuity=None,
        maximum_original_bytes=None):
    root = root_public_key
    originals = _inputs(authorization_bytes, proof_input_issuer_policy_bytes,
        completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes)
    maximum = _maximum(maximum_original_bytes)
    capture._SharedLedger(work)
    _reserve(originals, b"", maximum, work)
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(window[4], transport_deadline_ns), work, _continuity)
    current = lifetime.current
    current()
    envelope = _read(originals[0], work)
    current()
    _signature(envelope, root, work)
    current()
    payload = envelope["payload"]
    issued, expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    lifetime.narrow(expires, lifetime.window[5], lifetime.window[6])

    def signed_current():
        epoch = lifetime.base()
        if issued > epoch + lifetime.window[6] or epoch >= expires:
            _fail("dynamic grant issuer authorization interval is not live")
        return epoch

    lifetime.attach(signed_current)
    actual = issuer._verify_on_work(policy_bytes=originals[1], completion_bootstrap_bytes=originals[2],
        proof_enrollment_bytes=originals[3], intent_enrollment_bytes=originals[4], root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if type(actual) is not issuer._IssuerPolicyMaterial:
        _fail("dynamic grant issuer requires genuine independent proof input policy")
    lifetime.attach(actual.live)
    lifetime.adopt(actual.live_window, actual.deadline_ns)
    plan._same(actual.policy_digest, payload["proofInputIssuerPolicyDigest"], work,
        "dynamic grant issuer independently pinned proof input policy")
    if not actual.payload["issuedAtEpochNs"] <= issued < expires <= actual.payload["expiresAtEpochNs"]:
        _fail("dynamic grant issuer authority escapes its independent proof input policy")
    timeout = min(payload["intake"]["requestTimeoutSeconds"], payload["issuerLaunch"]["requestTimeoutSeconds"],
        payload["issuerLaunch"]["deliveryEndpoint"]["timeoutSeconds"], payload["endpoint"]["timeoutSeconds"])
    lifetime.narrow(expires, min(lifetime.window[5], timeout * 1_000_000_000), lifetime.window[6])
    _canonical(originals[0], envelope, work)
    owned, launch = _capture(payload, work), _capture(payload["issuerLaunch"], work)
    current()
    return _AuthorizationMaterial(*originals, actual, owned, launch,
        owned["rootSigningKey"]["byteCount"], owned["rootSigningKey"]["bytesDigest"],
        lifetime.window, lifetime.bound, current)


def _admit_on_work(*, authorization_bytes, proof_input_issuer_policy_bytes,
        completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes,
        proof_bootstrap_bytes, root_public_key, live_window, transport_deadline_ns, work,
        _continuity=None, maximum_original_bytes=None):
    root = root_public_key
    originals = _inputs(authorization_bytes, proof_input_issuer_policy_bytes,
        completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes)
    proof = authorization._original(proof_bootstrap_bytes, MAX_PROOF_BOOTSTRAP_BYTES, "fresh proof bootstrap")
    maximum = _maximum(maximum_original_bytes)
    capture._SharedLedger(work)
    _reserve(originals, proof, maximum, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(window[4], transport_deadline_ns), work, _continuity)
    current = lifetime.current
    current()
    static = _verify_on_work(authorization_bytes=originals[0], proof_input_issuer_policy_bytes=originals[1],
        completion_bootstrap_bytes=originals[2], proof_enrollment_bytes=originals[3],
        intent_enrollment_bytes=originals[4], root_public_key=root, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity,
        maximum_original_bytes=maximum)
    lifetime.attach(static.live)
    lifetime.adopt(static.live_window, static.deadline_ns)
    checked = admission._verify_on_work(proof_bootstrap_bytes=proof, issuer_policy_bytes=originals[1],
        completion_bootstrap_bytes=originals[2], proof_enrollment_bytes=originals[3],
        intent_enrollment_bytes=originals[4], root_public_key=root, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    if type(checked) is not admission._DeliveryMaterial:
        _fail("dynamic grant issuer requires genuine exact proof-original admission")
    lifetime.attach(checked.live)
    lifetime.adopt(checked.live_window, checked.deadline_ns)
    interval = (max(static.payload["issuedAtEpochNs"], checked.proof_material.attestation_interval[0]),
        min(static.payload["expiresAtEpochNs"], checked.proof_material.attestation_interval[1]))
    if interval[0] >= interval[1]:
        _fail("dynamic grant issuer and actual proof intervals do not overlap")
    lifetime.narrow(interval[1], lifetime.window[5], lifetime.window[6])
    identity = transport._bootstrap_identity_on_work(proof, deadline_ns=lifetime.bound,
        work=work, current=current)
    current()
    return _AdmittedMaterial(static, proof, checked.proof_material, identity,
        lifetime.window, lifetime.bound, current)


def _produce_on_work(*, authorization_bytes, proof_input_issuer_policy_bytes,
        completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes,
        proof_bootstrap_bytes, root_private_key, root_public_key, live_window,
        transport_deadline_ns, work, _continuity=None, maximum_original_bytes=None):
    private, root = root_private_key, root_public_key
    originals = _inputs(authorization_bytes, proof_input_issuer_policy_bytes,
        completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes)
    proof = authorization._original(proof_bootstrap_bytes, MAX_PROOF_BOOTSTRAP_BYTES, "fresh proof bootstrap")
    maximum = _maximum(maximum_original_bytes)
    authorization._private(private)
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(window[4], transport_deadline_ns), work, _continuity)
    current = lifetime.current
    current()
    admitted = _admit_on_work(authorization_bytes=originals[0], proof_input_issuer_policy_bytes=originals[1],
        completion_bootstrap_bytes=originals[2], proof_enrollment_bytes=originals[3],
        intent_enrollment_bytes=originals[4], proof_bootstrap_bytes=proof, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity, maximum_original_bytes=maximum)
    lifetime.attach(admitted.live)
    lifetime.adopt(admitted.live_window, admitted.deadline_ns)
    current()
    keys._pair_on_work(private, root, work)
    current()
    static = admitted.authorization_material
    payload = static.payload
    issued = max(payload["issuedAtEpochNs"], admitted.proof_material.attestation_interval[0])
    expires = min(payload["expiresAtEpochNs"], admitted.proof_material.attestation_interval[1])
    proof_digest = policy._proof_bootstrap_digest_on_work(proof, work)
    current()
    policy_payload = {"schema": policy.PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": policy.PURPOSE, "trustMode": "trusted-host-local", "proofBootstrapDigest": proof_digest,
        "clientId": payload["clientId"], "clientIdentity": _capture(payload["clientIdentity"], work),
        "endpoint": _capture(payload["endpoint"], work), "releaseLaunch": _capture(payload["releaseLaunch"], work),
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires}
    _reserve(originals, proof, maximum, work)
    policy_original = policy._produce_on_work(payload=policy_payload, proof_bootstrap_bytes=proof,
        root_private_key=private, root_public_key=root, live_window=lifetime.window,
        transport_deadline_ns=lifetime.bound, work=work, _continuity=lifetime.continuity)
    current()
    policy_digest = policy._digest_on_work(policy_original, work)
    current()
    launch_payload = {"schema": bootstrap.PAYLOAD_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "purpose": bootstrap.PURPOSE, "role": bootstrap.ROLE, "trustMode": "trusted-host-local",
        "issuerPolicyDigest": policy_digest, "proofBootstrapDigest": proof_digest,
        "rootSigningKey": _capture(payload["rootSigningKey"], work), "issuedAtEpochNs": issued,
        "expiresAtEpochNs": expires, "launch": _capture(static.issuer_launch, work)}
    launch_original = bootstrap._produce_on_work(payload=launch_payload, issuer_policy_bytes=policy_original,
        proof_bootstrap_bytes=proof, root_private_key=private, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    current()
    if len(policy_original) > policy.MAX_BYTES or len(launch_original) > bootstrap.MAX_BYTES:
        _fail("dynamic grant issuer outputs exceed their reserved source bounds")
    return policy_original, launch_original
