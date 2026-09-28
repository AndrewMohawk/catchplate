"""Fresh root-original policy for one fixed live-release grant derivation.

This public-original admission layer authorizes root-selected resource pins; it
does not observe, create or deliver those resources. The independently supplied
proof bootstrap is genuinely admitted under the same current allowance. No
incoming material, root generation, private key delivery or service lives here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import oidc_session_activation_release_client_authorization as client
from serverware import oidc_session_activation_release_proof_bootstrap as proof_bootstrap
from serverware.authority_query_read_work import QueryReadWorkError


server = client.server
authorization, shape, plan = client.authorization, client.shape, client.plan
capture, production, clock = client.capture, client.production, client.clock
processing, authority, capability, keys = client.processing, client.authority, client.capability, client.keys
PURPOSE = "issue-oidc-session-activation-release-grants"
SCHEMA = "serverware.signedOidcSessionActivationReleaseGrantIssuerPolicy/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseGrantIssuerPolicy/v1"
SIGNATURE_DOMAIN = SCHEMA
IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseGrantIssuerPolicyIdentity/v1"
PROOF_BOOTSTRAP_IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseGrantIssuerProofBootstrapIdentity/v1"
MAX_BYTES = 16 * 1024
MAX_PROOF_BOOTSTRAP_BYTES = proof_bootstrap.MAX_BYTES
MAX_ORIGINAL_BYTES = proof_bootstrap.MAX_ORIGINAL_BYTES
MAX_NODES, MAX_DEPTH = 256, 6
MAX_RECEIPT_AGE_NS = server.MAX_RECEIPT_AGE_NS
PROFILE = server.LIVE_PROFILE
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "trustMode",
    "proofBootstrapDigest", "clientId", "clientIdentity", "endpoint", "releaseLaunch",
    "issuedAtEpochNs", "expiresAtEpochNs"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class OidcSessionActivationReleaseGrantIssuerPolicyError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseGrantIssuerPolicyError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _IssuerPolicyMaterial:
    """Same-call original-derived data, never accepted as authority input."""

    policy_bytes: bytes
    proof_bootstrap_bytes: bytes
    policy_digest: str
    payload: dict
    proof_material: proof_bootstrap._ProofMaterial
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
            _fail("release grant issuer policy exceeds its structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("release grant issuer policy exceeds its node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _payload_shape(payload, work):
    shape._object(payload, PAYLOAD_FIELDS, "release grant issuer policy")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    shape._digest(payload["proofBootstrapDigest"])
    authorization._token(payload["clientId"])
    shape.validate_identity_shape(payload["clientIdentity"])
    endpoint = client._endpoint(payload["endpoint"], work)
    server._launch_shape(payload["releaseLaunch"], work)
    launch = payload["releaseLaunch"]
    if (endpoint[0] != launch["listenerPath"]
            or endpoint[1] > launch["requestTimeoutSeconds"]
            or (launch["peerUid"], launch["peerGid"]) != (client.CLIENT_UID, client.CLIENT_GID)):
        _fail("release grant issuer client endpoint exceeds its fixed release launch")
    authorization._interval(payload, MAX_RECEIPT_AGE_NS)


def _read(original, work):
    """Own canonical data only; shape and parsing confer no authority."""
    raw = authorization._original(original, MAX_BYTES, "release grant issuer policy")
    decoded = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(decoded, work)
    shape._object(owned, _ENVELOPE_FIELDS, "signed release grant issuer policy")
    shape._literal(owned["schema"], SCHEMA)
    shape._base64url(owned["signatureBase64Url"], signature=True)
    _payload_shape(owned["payload"], work)
    _canonical(raw, owned, work)
    return owned


def _digest_on_work(original, work):
    raw = authorization._original(original, MAX_BYTES, "release grant issuer policy")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _proof_bootstrap_digest_on_work(original, work):
    """Frame the exact full original, not a payload or successful result."""
    raw = authorization._original(original, MAX_PROOF_BOOTSTRAP_BYTES, "release proof bootstrap")
    return plan._frame(PROOF_BOOTSTRAP_IDENTITY_DOMAIN, (raw,), work)


def _inventory(policy_size, proof_original, work):
    if policy_size + len(proof_original) > MAX_ORIGINAL_BYTES:
        _fail("release grant issuer original inventory exceeds 64 MiB")
    work.charge(input_bytes=policy_size + len(proof_original))


def _signature(envelope, root, work):
    unsigned = _wire(envelope["payload"], work)
    try:
        capability._signature(root, envelope["signatureBase64Url"], SIGNATURE_DOMAIN,
            unsigned, capture._SharedLedger(work))
    except InvalidSignature as exc:
        raise OidcSessionActivationReleaseGrantIssuerPolicyError(
            "release grant issuer policy root signature is invalid") from exc


def _join_proof(payload, proof_original, root, window, bound, current, bind_interval, work):
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    endpoint = client._endpoint(payload["endpoint"], work)
    policy_live = bind_interval(*interval)
    last_epoch = current()

    def policy_current():
        nonlocal last_epoch
        observed = policy_live()
        if observed < last_epoch:
            _fail("release grant issuer clock reversed across policy admission")
        last_epoch = observed
        return observed

    policy_current()
    identity = _proof_bootstrap_digest_on_work(proof_original, work)
    policy_current()
    plan._same(identity, payload["proofBootstrapDigest"], work,
        "release grant issuer exact proof bootstrap original")
    policy_current()
    selected = processing._narrow(window, deadline_epoch_ns=interval[1],
        maximum_lifetime_ns=window[5],
        maximum_clock_skew_ns=window[6])
    selected_bound = min(bound, selected[4])
    material = proof_bootstrap._verify_on_work(bootstrap_bytes=proof_original, root_public_key=root,
        live_window=selected, transport_deadline_ns=selected_bound, work=work)
    if type(material) is not proof_bootstrap._ProofMaterial:
        _fail("release grant issuer requires actual proof-bootstrap original admission")

    def originals_current():
        nonlocal last_epoch
        for guarded in (material.live, policy_live):
            observed = guarded()
            shape._integer(observed, minimum=1)
            if observed < last_epoch:
                _fail("release grant issuer policy and proof clocks reversed")
            last_epoch = observed
        return last_epoch

    originals_current()
    # Genuine proof admission already contains its exact intent, release
    # custody and completion intervals. The policy can only fit within it.
    server._contains(interval, material.attestation_interval)
    _created, delivery_expiry = server.custody._scope(material.expected_release["deliveryScope"], work)
    if interval[1] > delivery_expiry:
        _fail("release grant issuer policy extends the original delivery expiry")
    originals_current()
    narrowed = processing._narrow(material.live_window,
        deadline_epoch_ns=min(interval[1], delivery_expiry),
        maximum_lifetime_ns=min(material.live_window[5], endpoint[1] * 1_000_000_000),
        maximum_clock_skew_ns=material.live_window[6])
    deadline = min(bound, material.deadline_ns, narrowed[4])
    if (narrowed[:3] != window[:3]
            or any(actual > prior for actual, prior in zip(narrowed[3:], window[3:]))):
        _fail("release grant issuer admission renewed the supplied processing allowance")
    checked, _bind = server.storage._processing(narrowed, deadline, work)

    def live():
        nonlocal last_epoch
        originals_current()
        observed = checked()
        if observed < last_epoch or observed >= delivery_expiry:
            _fail("release grant issuer narrowed clock reversed or delivery expired")
        last_epoch = observed
        return observed

    live()
    return material, endpoint, narrowed, deadline, live


def _verify_on_work(*, policy_bytes, proof_bootstrap_bytes, root_public_key,
        live_window, transport_deadline_ns, work):
    """Authenticate root policy and the independently supplied proof original."""
    capture._SharedLedger(work)
    root = root_public_key
    raw = authorization._original(policy_bytes, MAX_BYTES, "release grant issuer policy")
    proof_original = authorization._original(proof_bootstrap_bytes, MAX_PROOF_BOOTSTRAP_BYTES,
        "release proof bootstrap")
    _inventory(len(raw), proof_original, work)
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    current, bind_interval = server.storage._processing(window, bound, work)
    current()
    envelope = _read(raw, work)
    current()
    _signature(envelope, root, work)
    current()
    payload = envelope["payload"]
    material, endpoint, narrowed, deadline, live = _join_proof(payload, proof_original,
        root, window, bound, current, bind_interval, work)
    live()
    _canonical(raw, envelope, work)
    live()
    identity = _digest_on_work(raw, work)
    live()
    owned = _capture(payload, work)
    client_identity = _capture(owned["clientIdentity"], work)
    launch = _capture(owned["releaseLaunch"], work)
    live()
    return _IssuerPolicyMaterial(raw, proof_original, identity, owned, material,
        owned["clientId"], client_identity, endpoint, launch, narrowed, deadline, live)


def _produce_on_work(*, payload, proof_bootstrap_bytes, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work):
    """Sign only after genuine proof-original admission; no resource inspection."""
    capture._SharedLedger(work)
    private, root = root_private_key, root_public_key
    proof_original = authorization._original(proof_bootstrap_bytes, MAX_PROOF_BOOTSTRAP_BYTES,
        "release proof bootstrap")
    owned = _capture(payload, work)
    _inventory(MAX_BYTES, proof_original, work)
    authorization._private(private)
    authorization._public(root)
    _payload_shape(owned, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    current, bind_interval = server.storage._processing(window, bound, work)
    current()
    _material, _endpoint, _narrowed, _deadline, live = _join_proof(owned, proof_original,
        root, window, bound, current, bind_interval, work)
    live()
    keys._pair_on_work(private, root, work)
    live()
    envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("release grant issuer policy signature exceeds its output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SIGNATURE_DOMAIN) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("release grant issuer policy cannot reserve its signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("release grant issuer policy changed after measurement")
    message = plan._ascii(plan._frame(SIGNATURE_DOMAIN, (unsigned,), work), work)
    live()
    signature = production._sign_and_verify(private, root, message, work)
    live()
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("release grant issuer policy changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    original = plan.core.canonical_bytes({"schema": SCHEMA, "payload": owned, "signatureBase64Url": encoded})
    if len(original) != envelope_size:
        _fail("release grant issuer policy output differs from its reservation")
    live()
    readback = _read(original, work)
    live()
    _signature(readback, root, work)
    live()
    plan._same(readback["payload"], owned, work, "release grant issuer signed policy differs")
    live()
    return original
