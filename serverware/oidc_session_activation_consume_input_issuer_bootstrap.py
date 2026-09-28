"""Root-original six-FD launch for the one-shot consume-input issuer.

The independent policy and activation planner remain separate public originals.
Actual policy admission precedes private signer access by the cold owner. This
v1 has no worker staging endpoint. Explicit launch v2 adds only fixed staging;
neither version creates resources or acquires historical private-key custody.
Issuer policy v2 separately admits historical verification and current output
contexts inside the existing policy original; it adds no launch descriptor.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import authority_oidc_session_activation_consume_input_production as primitives
from serverware import authority_oidc_session_activation_consume_input_transport as transport
from serverware import oidc_session_activation_consume_input_issuer_policy as issuer
from serverware.authority_query_read_work import QueryReadWorkError


authorization, shape, plan = issuer.authorization, issuer.shape, issuer.plan
capture, production, clock = issuer.capture, issuer.production, issuer.clock
processing, authority, capability, keys = issuer.processing, issuer.authority, issuer.capability, issuer.keys
_Lifetime = primitives._Lifetime
ROLE = PROCESS_MODE = "oidc-session-activation-consume-input-issuer"
SERVICE_UID = SERVICE_GID = 65495
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, POLICY_FD, ACTIVATION_PLANNER_BOOTSTRAP_FD, KEY_FD = range(198, 204)
INHERITED_DESCRIPTORS = tuple(range(198, 204))
LISTENER_PATH = transport.LISTENER_PATH
LISTENER_NAME = "serverware-oidc-session-activation-consume-input-issuer"
PURPOSE = "launch-oidc-session-activation-consume-input-issuer"
SCHEMA = "serverware.signedOidcSessionActivationConsumeInputIssuerBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationConsumeInputIssuerBootstrap/v1"
LAUNCH_SCHEMA = "serverware.oidcSessionActivationConsumeInputIssuerLaunch/v1"
DELIVERY_LAUNCH_SCHEMA = "serverware.oidcSessionActivationConsumeInputIssuerLaunch/v2"
DELIVERY_SOCKET_PATH = "/run/serverware/oidc-session-activation/consume-bootstrap.sock"
IDENTITY_DOMAIN = "serverware.oidcSessionActivationConsumeInputIssuerBootstrapIdentity/v1"
MAX_BYTES = MAX_BOOTSTRAP_BYTES = 16 * 1024
MAX_POLICY_BYTES = issuer.MAX_BYTES
MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES = issuer.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES
MAX_KEY_BYTES = 16 * 1024
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES
MAX_NODES, MAX_DEPTH = 256, 6
MAX_RECEIPT_AGE_NS = issuer.MAX_RECEIPT_AGE_NS
_FD_FIELDS = (("rootPublicKeyFd", ROOT_FD), ("bootstrapFd", BOOTSTRAP_FD),
    ("listenerFd", LISTENER_FD), ("issuerPolicyFd", POLICY_FD),
    ("activationPlannerBootstrapFd", ACTIVATION_PLANNER_BOOTSTRAP_FD), ("rootSigningKeyFd", KEY_FD))
_LAUNCH_FIELDS = frozenset({"schema", "role", "processMode", "serviceUid", "serviceGid",
    "peerUid", "peerGid", *(name for name, _ in _FD_FIELDS), "inheritedFileDescriptors",
    "listenerPath", "requestTimeoutSeconds", "listenerSocketDevice", "listenerSocketInode",
    "listenerPathDevice", "listenerPathInode"})
_DELIVERY_LAUNCH_FIELDS = _LAUNCH_FIELDS | frozenset({"deliveryEndpoint"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "role", "trustMode",
    "issuerPolicyDigest", "activationPlannerBootstrapDigest", "rootSigningKey", "issuedAtEpochNs",
    "expiresAtEpochNs", "launch"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class ConsumeInputIssuerBootstrapError(ValueError):
    pass


def _fail(message):
    raise ConsumeInputIssuerBootstrapError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _IssuerMaterial:
    bootstrap_bytes: bytes
    issuer_policy_bytes: bytes
    activation_planner_bootstrap_bytes: bytes
    policy_material: issuer._IssuerPolicyMaterial
    launch: dict
    root_signing_key_byte_count: int
    root_signing_key_digest: str
    attestation_interval: tuple
    opening_sample: tuple
    live_window: tuple
    deadline_ns: int
    live: object
    delivery_endpoint: tuple | None = None


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("consume issuer bootstrap exceeds its structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("consume issuer bootstrap exceeds its node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _construction_on_work(work):
    """The cold owner starts this sole bracket before public-file/key I/O."""
    capture._SharedLedger(work)
    before, epoch, after = clock._sample_on_work(work)
    age, skew = authority.VERIFIER_RESPONSE_MAX_AGE_NS, authority.VERIFIER_MAX_CLOCK_SKEW_NS
    window = clock._validate((epoch, before, after, epoch + age, before + age, age, skew))
    return window, window[4]


def _delivery_endpoint(value):
    shape._object(value, frozenset({"path", "timeoutSeconds", "peerUid", "peerGid"}),
        "consume issuer fixed bootstrap delivery endpoint")
    shape._literal(value["path"], DELIVERY_SOCKET_PATH)
    shape._integer(value["timeoutSeconds"], 30, minimum=1)
    for name in ("peerUid", "peerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            _fail("consume issuer bootstrap staging requires the actual root peer")
    return value["path"], value["timeoutSeconds"], value["peerUid"], value["peerGid"]


def _launch_shape(value, work):
    if type(value) is not dict or type(value.get("schema")) is not str:
        _fail("consume issuer launch requires its explicit closed version")
    version = value["schema"]
    if version not in (LAUNCH_SCHEMA, DELIVERY_LAUNCH_SCHEMA):
        _fail("consume issuer launch version is not source fixed")
    shape._object(value, _DELIVERY_LAUNCH_FIELDS if version == DELIVERY_LAUNCH_SCHEMA else _LAUNCH_FIELDS,
        "consume input issuer launch")
    for name, expected in (("schema", version), ("role", ROLE),
            ("processMode", PROCESS_MODE), ("listenerPath", LISTENER_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), *_FD_FIELDS):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            _fail("consume issuer launch identity or descriptor is not source fixed")
    shape._array(value["inheritedFileDescriptors"], len(INHERITED_DESCRIPTORS), "consume issuer descriptors")
    for descriptor in value["inheritedFileDescriptors"]:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(value["inheritedFileDescriptors"], list(INHERITED_DESCRIPTORS), work,
        "consume issuer exact descriptor inventory")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("listenerSocketInode", "listenerPathInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)
    if version == DELIVERY_LAUNCH_SCHEMA:
        endpoint = _delivery_endpoint(value["deliveryEndpoint"])
        if endpoint[1] > value["requestTimeoutSeconds"]:
            _fail("consume issuer staging timeout exceeds its original launch timeout")


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "consume input issuer bootstrap")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("role", ROLE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("issuerPolicyDigest", "activationPlannerBootstrapDigest"):
        shape._digest(payload[name])
    key = payload["rootSigningKey"]
    shape._object(key, frozenset({"byteCount", "bytesDigest"}), "consume issuer signer original")
    shape._integer(key["byteCount"], MAX_KEY_BYTES, minimum=2)
    shape._digest(key["bytesDigest"])
    authorization._interval(payload, MAX_RECEIPT_AGE_NS)
    _launch_shape(payload["launch"], work)


def _read(original, work):
    raw = authorization._original(original, MAX_BYTES, "consume input issuer bootstrap")
    value = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(value, work)
    shape._object(owned, _ENVELOPE_FIELDS, "signed consume input issuer bootstrap")
    shape._literal(owned["schema"], SCHEMA)
    shape._base64url(owned["signatureBase64Url"], signature=True)
    _payload_shape(owned["payload"], work)
    _canonical(raw, owned, work)
    return owned


def _digest_on_work(original, work):
    raw = authorization._original(original, MAX_BYTES, "consume input issuer bootstrap")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _inventory(size, policy_original, activation_original, work):
    total = size + len(policy_original) + len(activation_original) + MAX_KEY_BYTES
    if total > MAX_ORIGINAL_BYTES:
        _fail("consume issuer originals exceed their 64 MiB aggregate bound")
    work.charge(input_bytes=total)


def _intake_reservation(sizes):
    """Fixed cold captures plus future derivation, before decoded intake.

    Root delivery supplies the sealed public lengths and a conservative private
    key maximum; startup supplies all five actual sealed lengths. The current
    planner original is already contained in policy v2, not an extra allowance.
    """
    limits = (MAX_BYTES, MAX_BYTES, MAX_POLICY_BYTES,
        MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, MAX_KEY_BYTES)
    if (type(sizes) is not tuple or len(sizes) != len(limits)
            or any(type(size) is not int or not 2 <= size <= maximum
                for size, maximum in zip(sizes, limits))):
        _fail("consume issuer intake requires its exact bounded cold lengths")
    held = (8 * sum(sizes)
        + primitives._cold_derivation_reservation(sizes[2], sizes[3]))
    remaining = (MAX_ORIGINAL_BYTES - held - primitives._OUTPUT_RESERVATION
        - transport.REQUEST_HEADER_BYTES - transport.RESPONSE_HEADER_BYTES)
    maximum_request = min(transport.MAX_REQUEST_BYTES, remaining // 8)
    if maximum_request <= len(transport.PURPOSE):
        _fail("consume issuer cold captures leave no bounded request derivation")
    return held, maximum_request


def _signature(envelope, root, work):
    unsigned = _wire(envelope["payload"], work)
    try:
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA,
            unsigned, capture._SharedLedger(work))
    except InvalidSignature as exc:
        raise ConsumeInputIssuerBootstrapError("consume issuer bootstrap root signature is invalid") from exc


def _material(payload, original, policy_original, activation_original, root, lifetime, work):
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    opening = lifetime.window[1], lifetime.window[0], lifetime.window[2]
    lifetime.narrow(interval[1], lifetime.window[5], lifetime.window[6])

    def launch_live():
        epoch = lifetime.base()
        if interval[0] > epoch + lifetime.window[6] or epoch >= interval[1]:
            _fail("consume issuer signed launch interval is not live")
        return epoch

    lifetime.attach(launch_live)
    current = lifetime.current
    policy_digest = issuer._digest_on_work(policy_original, work)
    current()
    activation_digest = issuer._activation_planner_bootstrap_digest_on_work(activation_original, work)
    current()
    plan._same(policy_digest, payload["issuerPolicyDigest"], work, "consume issuer exact policy original")
    plan._same(activation_digest, payload["activationPlannerBootstrapDigest"], work,
        "consume issuer exact activation planner original")
    current()
    policy = issuer._verify_on_work(policy_bytes=policy_original,
        activation_planner_bootstrap_bytes=activation_original, root_public_key=root,
        live_window=lifetime.window, transport_deadline_ns=lifetime.bound, work=work,
        _continuity=lifetime.continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("consume issuer launch requires actual policy-original admission")
    lifetime.attach(policy.live)
    lifetime.adopt(policy.live_window, policy.deadline_ns)
    if not policy.payload["issuedAtEpochNs"] <= interval[0] < interval[1] <= policy.payload["expiresAtEpochNs"]:
        _fail("consume issuer launch interval escapes its independently signed policy")
    plan._same(policy.policy_digest, payload["issuerPolicyDigest"], work,
        "consume issuer admitted policy identity")
    current()
    endpoint = (_delivery_endpoint(payload["launch"]["deliveryEndpoint"])
        if payload["launch"]["schema"] == DELIVERY_LAUNCH_SCHEMA else None)
    timeout = payload["launch"]["requestTimeoutSeconds"]
    if endpoint is not None:
        timeout = min(timeout, endpoint[1])
    lifetime.narrow(interval[1], min(lifetime.window[5], timeout * 1_000_000_000), lifetime.window[6])
    launch = _capture(payload["launch"], work)
    current()
    return _IssuerMaterial(original, policy_original, activation_original, policy, launch,
        payload["rootSigningKey"]["byteCount"], payload["rootSigningKey"]["bytesDigest"],
        interval, opening, lifetime.window, lifetime.bound, current, endpoint)


def _verify_on_work(*, bootstrap_bytes, issuer_policy_bytes, activation_planner_bootstrap_bytes,
        root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    capture._SharedLedger(work)
    root = root_public_key
    original = authorization._original(bootstrap_bytes, MAX_BYTES, "consume issuer bootstrap")
    policy_original = authorization._original(issuer_policy_bytes, MAX_POLICY_BYTES, "consume issuer policy")
    activation_original = authorization._original(activation_planner_bootstrap_bytes,
        MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, "consume issuer activation planner bootstrap")
    _inventory(len(original), policy_original, activation_original, work)
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(transport_deadline_ns, window[4]), work, _continuity)
    lifetime.current()
    envelope = _read(original, work)
    lifetime.current()
    _signature(envelope, root, work)
    lifetime.current()
    material = _material(envelope["payload"], original, policy_original, activation_original,
        root, lifetime, work)
    material.live()
    _canonical(original, envelope, work)
    material.live()
    return material


def _produce_on_work(*, payload, issuer_policy_bytes, activation_planner_bootstrap_bytes,
        root_private_key, root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    capture._SharedLedger(work)
    private, root = root_private_key, root_public_key
    policy_original = authorization._original(issuer_policy_bytes, MAX_POLICY_BYTES, "consume issuer policy")
    activation_original = authorization._original(activation_planner_bootstrap_bytes,
        MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, "consume issuer activation planner bootstrap")
    owned = _capture(payload, work)
    _inventory(MAX_BYTES, policy_original, activation_original, work)
    authorization._private(private)
    authorization._public(root)
    _payload_shape(owned, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    lifetime = _Lifetime(window, min(transport_deadline_ns, window[4]), work, _continuity)
    lifetime.current()
    material = _material(owned, b"", policy_original, activation_original, root, lifetime, work)
    live = material.live
    live()
    keys._pair_on_work(private, root, work)
    live()
    envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(envelope)
    unsigned_size, unsigned_nodes = work.measure(owned)
    if max(size, unsigned_size) > MAX_BYTES or max(nodes, unsigned_nodes) > MAX_NODES:
        _fail("consume issuer bootstrap signature exceeds its output bounds")
    work.charge(input_bytes=4 * unsigned_size + size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + nodes)
    frame_bytes = 2 * len(SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("consume issuer bootstrap cannot reserve its signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("consume issuer bootstrap changed after measurement")
    message = plan._ascii(plan._frame(SCHEMA, (unsigned,), work), work)
    live()
    signature = production._sign_and_verify(private, root, message, work)
    live()
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("consume issuer bootstrap changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    original = plan.core.canonical_bytes({"schema": SCHEMA, "payload": owned, "signatureBase64Url": encoded})
    if len(original) != size:
        _fail("consume issuer bootstrap output differs from its reservation")
    live()
    readback = _read(original, work)
    live()
    _signature(readback, root, work)
    live()
    plan._same(readback["payload"], owned, work, "consume issuer bootstrap signed payload")
    live()
    return original
