"""Root-original eight-FD launch for the one-shot proof-input issuer.

Independent policy, completion and enrollment originals remain separate sealed
inputs. Closed launch v1 stages to the proof worker; explicit v2 also requires
the separate grant issuer. This module admits no private key bytes and observes
or creates no resources.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import authority_oidc_session_activation_release_proof_input_transport as transport
from serverware import authority_oidc_session_activation_release_proof_input_delivery_transport as staging
from serverware import authority_oidc_session_activation_release_grant_input_delivery_transport as grant_staging
from serverware import oidc_session_activation_release_proof_input_issuer_policy as issuer
from serverware.authority_query_read_work import QueryReadWorkError


authorization, shape, plan = issuer.authorization, issuer.shape, issuer.plan
capture, production, clock = issuer.capture, issuer.production, issuer.clock
processing, authority, capability, keys = issuer.processing, issuer.authority, issuer.capability, issuer.keys
_Lifetime = issuer._Lifetime
ROLE = PROCESS_MODE = "oidc-session-activation-release-proof-input-issuer"
SERVICE_UID = SERVICE_GID = 65494
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, POLICY_FD, COMPLETION_BOOTSTRAP_FD, PROOF_ENROLLMENT_FD, INTENT_ENROLLMENT_FD, KEY_FD = range(198, 206)
INHERITED_DESCRIPTORS = tuple(range(198, 206))
LISTENER_PATH = transport.LISTENER_PATH
LISTENER_NAME = "serverware-oidc-session-activation-release-proof-input-issuer"
DELIVERY_SOCKET_PATH = staging.LISTENER_PATH
PURPOSE = "launch-oidc-session-activation-release-proof-input-issuer"
SCHEMA = "serverware.signedOidcSessionActivationReleaseProofInputIssuerBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseProofInputIssuerBootstrap/v1"
LAUNCH_SCHEMA = "serverware.oidcSessionActivationReleaseProofInputIssuerLaunch/v1"
LAUNCH_V2_SCHEMA = "serverware.oidcSessionActivationReleaseProofInputIssuerLaunch/v2"
IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseProofInputIssuerBootstrapIdentity/v1"
MAX_BYTES = MAX_BOOTSTRAP_BYTES = 16 * 1024
MAX_POLICY_BYTES = issuer.MAX_BYTES
MAX_COMPLETION_BOOTSTRAP_BYTES = issuer.MAX_COMPLETION_BOOTSTRAP_BYTES
MAX_PROOF_ENROLLMENT_BYTES = issuer.proof_enrollments.MAX_BYTES
MAX_INTENT_ENROLLMENT_BYTES = issuer.intent_enrollments.MAX_BYTES
MAX_KEY_BYTES = 16 * 1024
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES
MAX_NODES, MAX_DEPTH = 256, 6
MAX_RECEIPT_AGE_NS = issuer.MAX_RECEIPT_AGE_NS
_FD_FIELDS = (("rootPublicKeyFd", ROOT_FD), ("bootstrapFd", BOOTSTRAP_FD),
    ("listenerFd", LISTENER_FD), ("issuerPolicyFd", POLICY_FD),
    ("completionBootstrapFd", COMPLETION_BOOTSTRAP_FD), ("proofEnrollmentFd", PROOF_ENROLLMENT_FD),
    ("intentEnrollmentFd", INTENT_ENROLLMENT_FD), ("rootSigningKeyFd", KEY_FD))
_LAUNCH_FIELDS = frozenset({"schema", "role", "processMode", "serviceUid", "serviceGid",
    "peerUid", "peerGid", *(name for name, _ in _FD_FIELDS), "inheritedFileDescriptors",
    "listenerPath", "requestTimeoutSeconds", "listenerSocketDevice", "listenerSocketInode",
    "listenerPathDevice", "listenerPathInode", "deliveryEndpoint"})
_LAUNCH_V2_FIELDS = _LAUNCH_FIELDS | {"grantDeliveryEndpoint"}
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "role", "trustMode",
    "issuerPolicyDigest", "completionBootstrapDigest", "proofEnrollmentDigest", "intentEnrollmentDigest",
    "rootSigningKey", "issuedAtEpochNs", "expiresAtEpochNs", "launch"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class ReleaseProofInputIssuerBootstrapError(ValueError):
    pass


def _fail(message):
    raise ReleaseProofInputIssuerBootstrapError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _IssuerMaterial:
    bootstrap_bytes: bytes
    issuer_policy_bytes: bytes
    completion_bootstrap_bytes: bytes
    proof_enrollment_bytes: bytes
    intent_enrollment_bytes: bytes
    policy_material: issuer._IssuerPolicyMaterial
    launch: dict
    root_signing_key_byte_count: int
    root_signing_key_digest: str
    attestation_interval: tuple
    opening_sample: tuple
    live_window: tuple
    deadline_ns: int
    live: object
    delivery_endpoint: tuple
    grant_delivery_endpoint: tuple | None = None


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("proof input issuer bootstrap exceeds its structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("proof input issuer bootstrap exceeds its node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _construction_on_work(work):
    """The cold owner creates this sole bracket before public-file/key I/O."""
    capture._SharedLedger(work)
    before, epoch, after = clock._sample_on_work(work)
    age, skew = authority.VERIFIER_RESPONSE_MAX_AGE_NS, authority.VERIFIER_MAX_CLOCK_SKEW_NS
    window = clock._validate((epoch, before, after, epoch + age, before + age, age, skew))
    return window, window[4]


def _delivery_endpoint(value):
    shape._object(value, frozenset({"path", "timeoutSeconds", "peerUid", "peerGid"}),
        "proof input issuer fixed staging endpoint")
    shape._literal(value["path"], DELIVERY_SOCKET_PATH)
    shape._integer(value["timeoutSeconds"], 30, minimum=1)
    for name in ("peerUid", "peerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            _fail("proof input issuer staging requires the actual root peer")
    return value["path"], value["timeoutSeconds"], value["peerUid"], value["peerGid"]


def _grant_delivery_endpoint(value):
    shape._object(value, frozenset({"path", "timeoutSeconds", "peerUid", "peerGid"}),
        "proof input issuer fixed grant staging endpoint")
    shape._literal(value["path"], grant_staging.LISTENER_PATH)
    shape._integer(value["timeoutSeconds"], 30, minimum=1)
    for name in ("peerUid", "peerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            _fail("proof input issuer grant staging requires the actual root peer")
    return value["path"], value["timeoutSeconds"], value["peerUid"], value["peerGid"]


def _launch_shape(value, work):
    v2 = type(value) is dict and value.get("schema") == LAUNCH_V2_SCHEMA
    shape._object(value, _LAUNCH_V2_FIELDS if v2 else _LAUNCH_FIELDS, "proof input issuer launch")
    for name, expected in (("schema", LAUNCH_V2_SCHEMA if v2 else LAUNCH_SCHEMA), ("role", ROLE),
            ("processMode", PROCESS_MODE), ("listenerPath", LISTENER_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), *_FD_FIELDS):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            _fail("proof input issuer identity or descriptor is not source fixed")
    shape._array(value["inheritedFileDescriptors"], len(INHERITED_DESCRIPTORS), "proof input issuer descriptors")
    for descriptor in value["inheritedFileDescriptors"]:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(value["inheritedFileDescriptors"], list(INHERITED_DESCRIPTORS), work,
        "proof input issuer exact descriptor inventory")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("listenerSocketInode", "listenerPathInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)
    endpoint = _delivery_endpoint(value["deliveryEndpoint"])
    if endpoint[1] > value["requestTimeoutSeconds"]:
        _fail("proof input issuer staging timeout exceeds its original launch timeout")
    if v2 and _grant_delivery_endpoint(value["grantDeliveryEndpoint"])[1] > value["requestTimeoutSeconds"]:
        _fail("proof input issuer grant staging timeout exceeds its original launch timeout")


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "proof input issuer bootstrap")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("role", ROLE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("issuerPolicyDigest", "completionBootstrapDigest", "proofEnrollmentDigest", "intentEnrollmentDigest"):
        shape._digest(payload[name])
    key = payload["rootSigningKey"]
    shape._object(key, frozenset({"byteCount", "bytesDigest"}), "proof input issuer signer original")
    shape._integer(key["byteCount"], MAX_KEY_BYTES, minimum=2)
    shape._digest(key["bytesDigest"])
    authorization._interval(payload, MAX_RECEIPT_AGE_NS)
    _launch_shape(payload["launch"], work)


def _read(original, work):
    raw = authorization._original(original, MAX_BYTES, "proof input issuer bootstrap")
    value = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(value, work)
    shape._object(owned, _ENVELOPE_FIELDS, "signed proof input issuer bootstrap")
    shape._literal(owned["schema"], SCHEMA)
    shape._base64url(owned["signatureBase64Url"], signature=True)
    _payload_shape(owned["payload"], work)
    _canonical(raw, owned, work)
    return owned


def _digest_on_work(original, work):
    raw = authorization._original(original, MAX_BYTES, "proof input issuer bootstrap")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _originals(policy, completion, proof, intent):
    return tuple(authorization._original(raw, maximum, label) for raw, maximum, label in (
        (policy, MAX_POLICY_BYTES, "proof input issuer policy"),
        (completion, MAX_COMPLETION_BOOTSTRAP_BYTES, "proof input issuer completion bootstrap"),
        (proof, MAX_PROOF_ENROLLMENT_BYTES, "proof input issuer proof enrollment"),
        (intent, MAX_INTENT_ENROLLMENT_BYTES, "proof input issuer intent enrollment")))


def _inventory(size, originals, work):
    total = size + sum(map(len, originals)) + MAX_KEY_BYTES
    if total + 3 * len(originals[1]) > MAX_ORIGINAL_BYTES:
        _fail("proof input issuer originals and decoded reservation exceed 64 MiB")
    work.charge(input_bytes=total)


def _signature(envelope, root, work):
    unsigned = _wire(envelope["payload"], work)
    try:
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA,
            unsigned, capture._SharedLedger(work))
    except InvalidSignature as exc:
        raise ReleaseProofInputIssuerBootstrapError("proof input issuer root signature is invalid") from exc


def _material(payload, original, originals, root, lifetime, work):
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    opening = lifetime.window[1], lifetime.window[0], lifetime.window[2]
    lifetime.narrow(interval[1], lifetime.window[5], lifetime.window[6])

    def launch_live():
        epoch = lifetime.base()
        if interval[0] > epoch + lifetime.window[6] or epoch >= interval[1]:
            _fail("proof input issuer signed launch interval is not live")
        return epoch

    lifetime.attach(launch_live)
    current = lifetime.current
    for raw, name, digest in ((originals[0], "issuerPolicyDigest", issuer._digest_on_work),
            (originals[1], "completionBootstrapDigest", issuer._completion_bootstrap_digest_on_work),
            (originals[2], "proofEnrollmentDigest", issuer._proof_enrollment_digest_on_work),
            (originals[3], "intentEnrollmentDigest", issuer._intent_enrollment_digest_on_work)):
        current()
        plan._same(digest(raw, work), payload[name], work, "proof input issuer exact " + name)
        current()
    policy = issuer._verify_on_work(policy_bytes=originals[0], completion_bootstrap_bytes=originals[1],
        proof_enrollment_bytes=originals[2], intent_enrollment_bytes=originals[3], root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("proof input issuer requires genuine independent policy-original admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    if not policy.payload["issuedAtEpochNs"] <= interval[0] < interval[1] <= policy.payload["expiresAtEpochNs"]:
        _fail("proof input issuer launch escapes its independently signed policy")
    plan._same(policy.policy_digest, payload["issuerPolicyDigest"], work,
        "proof input issuer actual policy identity")
    cm = policy.completion_material
    nested = (cm.custody_bytes, cm.planner_bootstrap_bytes, cm.planner_history_custody_bytes,
        cm.receiving_history_custody_bytes, cm.authorization_bytes, cm.current_root_enrollment_bytes,
        cm.grant_enrollment_bytes, cm.authorization_enrollment_bytes,
        cm.custody_material.history.planner.bootstrap_bytes)
    if MAX_BYTES + MAX_KEY_BYTES + sum(map(len, (*originals, *nested))) > MAX_ORIGINAL_BYTES:
        _fail("proof input issuer actual decoded originals exceed 64 MiB")
    endpoint = _delivery_endpoint(payload["launch"]["deliveryEndpoint"])
    timeout = min(payload["launch"]["requestTimeoutSeconds"], endpoint[1])
    grant_endpoint = None
    if payload["launch"]["schema"] == LAUNCH_V2_SCHEMA:
        grant_endpoint = _grant_delivery_endpoint(payload["launch"]["grantDeliveryEndpoint"])
        timeout = min(timeout, grant_endpoint[1])
    lifetime.narrow(interval[1], min(lifetime.window[5], timeout * 1_000_000_000), lifetime.window[6])
    launch = _capture(payload["launch"], work)
    current()
    return _IssuerMaterial(original, *originals, policy, launch,
        payload["rootSigningKey"]["byteCount"], payload["rootSigningKey"]["bytesDigest"],
        interval, opening, lifetime.window, lifetime.bound, current, endpoint, grant_endpoint)


def _verify_on_work(*, bootstrap_bytes, issuer_policy_bytes, completion_bootstrap_bytes,
        proof_enrollment_bytes, intent_enrollment_bytes, root_public_key, live_window,
        transport_deadline_ns, work, _continuity=None):
    capture._SharedLedger(work)
    root = root_public_key
    original = authorization._original(bootstrap_bytes, MAX_BYTES, "proof input issuer bootstrap")
    originals = _originals(issuer_policy_bytes, completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes)
    _inventory(len(original), originals, work)
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(transport_deadline_ns, window[4]), work, _continuity)
    lifetime.current()
    envelope = _read(original, work)
    lifetime.current()
    _signature(envelope, root, work)
    lifetime.current()
    material = _material(envelope["payload"], original, originals, root, lifetime, work)
    material.live()
    _canonical(original, envelope, work)
    material.live()
    return material


def _produce_on_work(*, payload, issuer_policy_bytes, completion_bootstrap_bytes,
        proof_enrollment_bytes, intent_enrollment_bytes, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work, _continuity=None):
    capture._SharedLedger(work)
    private, root = root_private_key, root_public_key
    originals = _originals(issuer_policy_bytes, completion_bootstrap_bytes, proof_enrollment_bytes, intent_enrollment_bytes)
    owned = _capture(payload, work)
    _inventory(MAX_BYTES, originals, work)
    authorization._private(private)
    authorization._public(root)
    _payload_shape(owned, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(transport_deadline_ns, window[4]), work, _continuity)
    lifetime.current()
    material = _material(owned, b"", originals, root, lifetime, work)
    live = material.live
    live()
    keys._pair_on_work(private, root, work)
    live()
    envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(envelope)
    unsigned_size, unsigned_nodes = work.measure(owned)
    if max(size, unsigned_size) > MAX_BYTES or max(nodes, unsigned_nodes) > MAX_NODES:
        _fail("proof input issuer signature exceeds its output bounds")
    work.charge(input_bytes=4 * unsigned_size + size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + nodes)
    frame_bytes = 2 * len(SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("proof input issuer cannot reserve its signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("proof input issuer payload changed after measurement")
    message = plan._ascii(plan._frame(SCHEMA, (unsigned,), work), work)
    live()
    signature = production._sign_and_verify(private, root, message, work)
    live()
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("proof input issuer payload changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    original = plan.core.canonical_bytes({"schema": SCHEMA, "payload": owned, "signatureBase64Url": encoded})
    if len(original) != size:
        _fail("proof input issuer output differs from its reservation")
    live()
    readback = _read(original, work)
    live()
    _signature(readback, root, work)
    live()
    plan._same(readback["payload"], owned, work, "proof input issuer signed payload")
    live()
    return original
