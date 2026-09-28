"""Root-original six-descriptor launch for the one-shot release grant issuer.

The policy and proof bootstrap stay separate original bytes. Genuine public
admission precedes access to the independently provisioned runtime root signer.
Resource pins are authority, not filesystem observations or provisioning proof.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import oidc_session_activation_release_grant_issuer_policy as issuer
from serverware.authority_query_read_work import QueryReadWorkError


authorization, shape, plan = issuer.authorization, issuer.shape, issuer.plan
capture, production, clock = issuer.capture, issuer.production, issuer.clock
processing, authority, capability, keys = issuer.processing, issuer.authority, issuer.capability, issuer.keys
ROLE = PROCESS_MODE = "oidc-session-activation-release-grant-issuer"
SERVICE_UID = SERVICE_GID = 65496
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, POLICY_FD, PROOF_BOOTSTRAP_FD, KEY_FD = range(198, 204)
INHERITED_DESCRIPTORS = tuple(range(198, 204))
LISTENER_PATH = "/run/serverware/oidc-session-activation-token-release/grants.sock"
LISTENER_NAME = "serverware-oidc-session-activation-release-grant-issuer"
PURPOSE = "launch-oidc-session-activation-release-grant-issuer"
SCHEMA = "serverware.signedOidcSessionActivationReleaseGrantIssuerBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseGrantIssuerBootstrap/v1"
LAUNCH_SCHEMA = "serverware.oidcSessionActivationReleaseGrantIssuerLaunch/v1"
DELIVERY_LAUNCH_SCHEMA = "serverware.oidcSessionActivationReleaseGrantIssuerLaunch/v2"
DELIVERY_SOCKET_PATH = "/run/serverware/oidc-session-activation-token-release/bootstrap.sock"
IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseGrantIssuerBootstrapIdentity/v1"
MAX_BYTES = MAX_BOOTSTRAP_BYTES = 16 * 1024
MAX_POLICY_BYTES = issuer.MAX_BYTES
MAX_PROOF_BOOTSTRAP_BYTES = issuer.MAX_PROOF_BOOTSTRAP_BYTES
MAX_KEY_BYTES = 16 * 1024
MAX_ORIGINAL_BYTES = issuer.MAX_ORIGINAL_BYTES
MAX_NODES, MAX_DEPTH = 256, 6
MAX_RECEIPT_AGE_NS = issuer.MAX_RECEIPT_AGE_NS
_FD_FIELDS = (("rootPublicKeyFd", ROOT_FD), ("bootstrapFd", BOOTSTRAP_FD),
    ("listenerFd", LISTENER_FD), ("issuerPolicyFd", POLICY_FD),
    ("proofBootstrapFd", PROOF_BOOTSTRAP_FD), ("rootSigningKeyFd", KEY_FD))
_LAUNCH_FIELDS = frozenset({"schema", "role", "processMode", "serviceUid", "serviceGid",
    "peerUid", "peerGid", *(name for name, _ in _FD_FIELDS), "inheritedFileDescriptors",
    "listenerPath", "requestTimeoutSeconds", "listenerSocketDevice", "listenerSocketInode",
    "listenerPathDevice", "listenerPathInode"})
_DELIVERY_LAUNCH_FIELDS = _LAUNCH_FIELDS | frozenset({"deliveryEndpoint"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "role", "trustMode",
    "issuerPolicyDigest", "proofBootstrapDigest", "rootSigningKey", "issuedAtEpochNs",
    "expiresAtEpochNs", "launch"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_construction_on_work = issuer.server._construction_on_work


class ReleaseGrantIssuerBootstrapError(ValueError):
    pass


def _fail(message):
    raise ReleaseGrantIssuerBootstrapError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _IssuerMaterial:
    bootstrap_bytes: bytes
    issuer_policy_bytes: bytes
    proof_bootstrap_bytes: bytes
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
            _fail("release issuer bootstrap exceeds its structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("release issuer bootstrap exceeds its node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _delivery_endpoint(value):
    shape._object(value, frozenset({"path", "timeoutSeconds", "peerUid", "peerGid"}),
        "release issuer fixed bootstrap delivery endpoint")
    shape._literal(value["path"], DELIVERY_SOCKET_PATH)
    shape._integer(value["timeoutSeconds"], 30, minimum=1)
    for name in ("peerUid", "peerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            _fail("release issuer bootstrap staging requires the actual root peer")
    return value["path"], value["timeoutSeconds"], value["peerUid"], value["peerGid"]


def _launch_shape(value, work):
    if type(value) is not dict or type(value.get("schema")) is not str:
        _fail("release issuer launch requires its explicit closed version")
    version = value["schema"]
    if version not in (LAUNCH_SCHEMA, DELIVERY_LAUNCH_SCHEMA):
        _fail("release issuer launch version is not source fixed")
    shape._object(value, _DELIVERY_LAUNCH_FIELDS if version == DELIVERY_LAUNCH_SCHEMA else _LAUNCH_FIELDS,
        "release grant issuer launch")
    for name, expected in (("schema", version), ("role", ROLE),
            ("processMode", PROCESS_MODE), ("listenerPath", LISTENER_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), *_FD_FIELDS):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            _fail("release issuer launch identity or descriptor is not source fixed")
    shape._array(value["inheritedFileDescriptors"], len(INHERITED_DESCRIPTORS), "release issuer descriptors")
    for descriptor in value["inheritedFileDescriptors"]:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(value["inheritedFileDescriptors"], list(INHERITED_DESCRIPTORS), work,
        "release issuer exact descriptor inventory")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("listenerSocketInode", "listenerPathInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)
    if version == DELIVERY_LAUNCH_SCHEMA:
        endpoint = _delivery_endpoint(value["deliveryEndpoint"])
        if endpoint[1] > value["requestTimeoutSeconds"]:
            _fail("release issuer staging timeout exceeds its original launch timeout")


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "release grant issuer bootstrap")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("role", ROLE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("issuerPolicyDigest", "proofBootstrapDigest"):
        shape._digest(payload[name])
    key = payload["rootSigningKey"]
    shape._object(key, frozenset({"byteCount", "bytesDigest"}), "release issuer root signer original")
    shape._integer(key["byteCount"], MAX_KEY_BYTES, minimum=2)
    shape._digest(key["bytesDigest"])
    authorization._interval(payload, MAX_RECEIPT_AGE_NS)
    _launch_shape(payload["launch"], work)


def _read(original, work):
    raw = authorization._original(original, MAX_BYTES, "release grant issuer bootstrap")
    value = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(value, work)
    shape._object(owned, _ENVELOPE_FIELDS, "signed release grant issuer bootstrap")
    shape._literal(owned["schema"], SCHEMA)
    shape._base64url(owned["signatureBase64Url"], signature=True)
    _payload_shape(owned["payload"], work)
    _canonical(raw, owned, work)
    return owned


def _digest_on_work(original, work):
    raw = authorization._original(original, MAX_BYTES, "release grant issuer bootstrap")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _inventory(size, policy_original, proof_original, key_size, work):
    total = size + len(policy_original) + len(proof_original) + key_size
    if total > MAX_ORIGINAL_BYTES:
        _fail("release issuer originals exceed the 64 MiB aggregate bound")
    work.charge(input_bytes=total)


def _signature(envelope, root, work):
    try:
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA,
            _wire(envelope["payload"], work), capture._SharedLedger(work))
    except InvalidSignature as exc:
        raise ReleaseGrantIssuerBootstrapError("release issuer bootstrap root signature is invalid") from exc


def _material(payload, original, policy_original, proof_original, root, window, bound,
        work, current, bind_interval, _continuity=None):
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    opening = window[1], window[0], window[2]
    launch_live = bind_interval(*interval)
    last_epoch = current()

    def launch_current():
        nonlocal last_epoch
        epoch = launch_live()
        if epoch < last_epoch:
            _fail("release issuer launch clock reversed")
        last_epoch = epoch
        return epoch

    launch_current()
    policy_digest = issuer._digest_on_work(policy_original, work)
    launch_current()
    proof_digest = issuer._proof_bootstrap_digest_on_work(proof_original, work)
    launch_current()
    plan._same(policy_digest, payload["issuerPolicyDigest"], work, "release issuer exact policy original")
    plan._same(proof_digest, payload["proofBootstrapDigest"], work, "release issuer exact proof original")
    launch_current()
    selected = processing._narrow(window, deadline_epoch_ns=interval[1],
        maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
    policy = issuer._verify_on_work(policy_bytes=policy_original, proof_bootstrap_bytes=proof_original,
        root_public_key=root, live_window=selected, transport_deadline_ns=min(bound, selected[4]), work=work,
        _continuity=_continuity)
    if type(policy) is not issuer._IssuerPolicyMaterial:
        _fail("release issuer bootstrap requires actual policy-original admission")

    def originals_current():
        nonlocal last_epoch
        for guarded in (policy.live, launch_live):
            epoch = guarded()
            shape._integer(epoch, minimum=1)
            if epoch < last_epoch:
                _fail("release issuer policy and launch clocks reversed")
            last_epoch = epoch
        return last_epoch

    originals_current()
    issuer.server._contains(interval, (policy.payload["issuedAtEpochNs"], policy.payload["expiresAtEpochNs"]))
    plan._same(policy.policy_digest, payload["issuerPolicyDigest"], work,
        "release issuer admitted policy identity")
    originals_current()
    endpoint = (_delivery_endpoint(payload["launch"]["deliveryEndpoint"])
        if payload["launch"]["schema"] == DELIVERY_LAUNCH_SCHEMA else None)
    timeout = payload["launch"]["requestTimeoutSeconds"]
    if endpoint is not None:
        timeout = min(timeout, endpoint[1])
    narrowed = processing._narrow(policy.live_window, deadline_epoch_ns=interval[1],
        maximum_lifetime_ns=min(policy.live_window[5], timeout * 1_000_000_000),
        maximum_clock_skew_ns=policy.live_window[6])
    deadline = min(bound, policy.deadline_ns, narrowed[4])
    if (narrowed[:3] != window[:3]
            or any(value > prior for value, prior in zip(narrowed[3:], window[3:]))):
        _fail("release issuer launch renewed the supplied processing allowance")
    checked, _bind = issuer._processing(narrowed, deadline, work, _continuity)

    def live():
        nonlocal last_epoch
        originals_current()
        epoch = checked()
        if epoch < last_epoch:
            _fail("release issuer narrowed clock reversed")
        last_epoch = epoch
        return epoch

    live()
    launch = _capture(payload["launch"], work)
    live()
    return _IssuerMaterial(original, policy_original, proof_original, policy, launch,
        payload["rootSigningKey"]["byteCount"], payload["rootSigningKey"]["bytesDigest"],
        interval, opening, narrowed, deadline, live, endpoint)


def _verify_on_work(*, bootstrap_bytes, issuer_policy_bytes, proof_bootstrap_bytes,
        root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    capture._SharedLedger(work)
    root = root_public_key
    original = authorization._original(bootstrap_bytes, MAX_BYTES, "release issuer bootstrap")
    policy_original = authorization._original(issuer_policy_bytes, MAX_POLICY_BYTES, "release issuer policy")
    proof_original = authorization._original(proof_bootstrap_bytes, MAX_PROOF_BOOTSTRAP_BYTES,
        "release issuer proof bootstrap")
    _inventory(len(original), policy_original, proof_original, MAX_KEY_BYTES, work)
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    current, bind_interval = issuer._processing(window, bound, work, _continuity)
    current()
    envelope = _read(original, work)
    current()
    _signature(envelope, root, work)
    current()
    material = _material(envelope["payload"], original, policy_original, proof_original,
        root, window, bound, work, current, bind_interval, _continuity)
    material.live()
    _canonical(original, envelope, work)
    material.live()
    return material


def _produce_on_work(*, payload, issuer_policy_bytes, proof_bootstrap_bytes,
        root_private_key, root_public_key, live_window, transport_deadline_ns, work, _continuity=None):
    capture._SharedLedger(work)
    private, root = root_private_key, root_public_key
    policy_original = authorization._original(issuer_policy_bytes, MAX_POLICY_BYTES, "release issuer policy")
    proof_original = authorization._original(proof_bootstrap_bytes, MAX_PROOF_BOOTSTRAP_BYTES,
        "release issuer proof bootstrap")
    owned = _capture(payload, work)
    _inventory(MAX_BYTES, policy_original, proof_original, MAX_KEY_BYTES, work)
    authorization._private(private)
    authorization._public(root)
    _payload_shape(owned, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    current, bind_interval = issuer._processing(window, bound, work, _continuity)
    current()
    material = _material(owned, b"", policy_original, proof_original, root, window, bound,
        work, current, bind_interval, _continuity)
    material.live()
    keys._pair_on_work(private, root, work)
    material.live()
    envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(envelope)
    unsigned_size, unsigned_nodes = work.measure(owned)
    if max(size, unsigned_size) > MAX_BYTES or max(nodes, unsigned_nodes) > MAX_NODES:
        _fail("release issuer bootstrap signature exceeds its output bounds")
    work.charge(input_bytes=4 * unsigned_size + size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + nodes)
    frame_bytes = 2 * len(SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("release issuer bootstrap cannot reserve signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("release issuer bootstrap changed after measurement")
    message = plan._ascii(plan._frame(SCHEMA, (unsigned,), work), work)
    material.live()
    signature = production._sign_and_verify(private, root, message, work)
    material.live()
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("release issuer bootstrap changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    original = plan.core.canonical_bytes({"schema": SCHEMA, "payload": owned, "signatureBase64Url": encoded})
    if len(original) != size:
        _fail("release issuer bootstrap output differs from its reservation")
    material.live()
    readback = _read(original, work)
    material.live()
    _signature(readback, root, work)
    material.live()
    plan._same(readback["payload"], owned, work, "release issuer bootstrap signed payload")
    material.live()
    return original
