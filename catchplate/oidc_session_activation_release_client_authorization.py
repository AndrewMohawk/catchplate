"""Fresh public-key-only root authority for one exact private release exchange.

The original server bootstrap is genuinely admitted, never replaced by a
successful material input. Client/outcome identities are independent root pins,
not evidence of durable retention, current deployment or completed delivery.
No private release key, history owner, token opening or transport lives here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from catchplate import oidc_session_activation_release_bootstrap as server
from catchplate.authority_query_read_work import QueryReadWorkError


authorization, shape, plan = server.authorization, server.shape, server.plan
capture, production, clock = server.capture, server.production, server.clock
delivery, processing = server.delivery, server.processing
authority, capability, keys = server.authority, server.capability, server.keys
PURPOSE = "receive-oidc-session-activation-token-release"
SCHEMA = "catchplate.signedOidcSessionActivationReleaseClientAuthorization/v1"
PAYLOAD_SCHEMA = "catchplate.oidcSessionActivationReleaseClientAuthorization/v1"
SIGNATURE_DOMAIN = SCHEMA
IDENTITY_DOMAIN = "catchplate.oidcSessionActivationReleaseClientAuthorizationIdentity/v1"
SERVER_BOOTSTRAP_IDENTITY_DOMAIN = "catchplate.oidcSessionActivationReleaseClientServerBootstrapIdentity/v1"
CLIENT_UID = CLIENT_GID = 65532
SERVER_PEER_UID = SERVER_PEER_GID = 0
LISTENER_PATH = server.LISTENER_PATH
LIVE_PROFILE, RECOVERY_PROFILE = server.LIVE_PROFILE, server.RECOVERY_PROFILE
MAX_BYTES = 16 * 1024
MAX_SERVER_BOOTSTRAP_BYTES = server.MAX_BYTES
MAX_ORIGINAL_BYTES = authority.MAX_RESULT_BYTES
MAX_NODES, MAX_DEPTH = 512, 6
MAX_RECEIPT_AGE_NS = server.MAX_RECEIPT_AGE_NS
SCOPE_FIELDS = frozenset({"serverBootstrapDigest", "profile", "requestIdentity",
    "configurationDigest", "databaseId", "generationDigest", "runtimeClosureDigest",
    "clientId", "clientIdentity", "callerId", "receiverIdentity", "producerId",
    "producerIdentity", "stateReceiptDigest", "expectedRelease", "expectedOutcomeDigest", "endpoint"})
ENDPOINT_FIELDS = frozenset({"path", "timeoutSeconds", "peerUid", "peerGid"})
PAYLOAD_FIELDS = SCOPE_FIELDS | frozenset({"schema", "sourceRevision", "purpose",
    "clientUid", "clientGid", "trustMode", "issuedAtEpochNs", "expiresAtEpochNs"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class OidcSessionActivationReleaseClientAuthorizationError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseClientAuthorizationError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ClientAuthorization:
    """Same-call data and retained current guards, never an authority input."""

    payload: dict
    authorization_digest: str
    server_material: server._ReleaseMaterial
    live_window: tuple
    deadline_ns: int
    live: object


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("release client authorization exceeds its structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("release client authorization exceeds its node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _endpoint(value, work):
    shape._object(value, ENDPOINT_FIELDS, "release client fixed endpoint")
    shape._literal(value["path"], LISTENER_PATH)
    shape._integer(value["timeoutSeconds"], 30, minimum=1)
    for name, expected in (("peerUid", SERVER_PEER_UID), ("peerGid", SERVER_PEER_GID)):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != expected:
            _fail("release client endpoint is not the fixed root-created listener")
    return value["path"], value["timeoutSeconds"], value["peerUid"], value["peerGid"]


def _scope_shape(value, work):
    shape._object(value, SCOPE_FIELDS, "release client independent scope")
    if type(value["profile"]) is not str or value["profile"] not in (LIVE_PROFILE, RECOVERY_PROFILE):
        _fail("release client profile is not a fixed live or recovery purpose")
    for name in ("serverBootstrapDigest", "requestIdentity", "configurationDigest",
            "generationDigest", "runtimeClosureDigest", "stateReceiptDigest", "expectedOutcomeDigest"):
        shape._digest(value[name])
    for name in ("databaseId", "clientId", "callerId", "producerId"):
        authorization._token(value[name])
    for name in ("clientIdentity", "receiverIdentity", "producerIdentity"):
        shape.validate_identity_shape(value[name])
    server._release_shape(value["expectedRelease"], work)
    _endpoint(value["endpoint"], work)


def _scope(value, work):
    owned = _capture(value, work)
    _scope_shape(owned, work)
    return owned


def _payload_shape(payload, work):
    shape._object(payload, PAYLOAD_FIELDS, "release client authorization payload")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name, expected in (("clientUid", CLIENT_UID), ("clientGid", CLIENT_GID)):
        shape._integer(payload[name], 2**32 - 2, minimum=1)
        if payload[name] != expected:
            _fail("release client authorization selects a different fixed client identity")
    _scope_shape({name: payload[name] for name in SCOPE_FIELDS}, work)
    authorization._interval(payload, MAX_RECEIPT_AGE_NS)
    _created, expires = server.custody._scope(payload["expectedRelease"]["deliveryScope"], work)
    if payload["expiresAtEpochNs"] > expires:
        _fail("release client authority extends the original delivery expiry")


def _read(original, work):
    """Own canonical bounded data; parsing alone authenticates nothing."""
    raw = authorization._original(original, MAX_BYTES, "release client authorization")
    decoded = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(decoded, work)
    shape._object(owned, _ENVELOPE_FIELDS, "signed release client authorization")
    shape._literal(owned["schema"], SCHEMA)
    shape._base64url(owned["signatureBase64Url"], signature=True)
    _payload_shape(owned["payload"], work)
    _canonical(raw, owned, work)
    return owned


def _digest_on_work(original, work):
    raw = authorization._original(original, MAX_BYTES, "release client authorization")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _server_bootstrap_digest_on_work(original, work):
    """Exact original identity only, never server-root admission."""
    raw = authorization._original(original, MAX_SERVER_BOOTSTRAP_BYTES, "release server bootstrap")
    return plan._frame(SERVER_BOOTSTRAP_IDENTITY_DOMAIN, (raw,), work)


def _inventory(originals, work):
    if sum(len(original) for original in originals) > MAX_ORIGINAL_BYTES:
        _fail("release client original inventory exceeds its aggregate bound")
    work.charge(input_bytes=sum(len(original) for original in originals))


def _signature(envelope, root, work):
    unsigned = _wire(envelope["payload"], work)
    try:
        capability._signature(root, envelope["signatureBase64Url"], SIGNATURE_DOMAIN,
            unsigned, capture._SharedLedger(work))
    except InvalidSignature as exc:
        raise OidcSessionActivationReleaseClientAuthorizationError(
            "release client authorization root signature is invalid") from exc


def _join_server(payload, server_original, root, expected, window, bound, current, bind_interval, work,
        _continuity=None):
    for name in SCOPE_FIELDS:
        current()
        plan._same(payload[name], expected[name], work, "release client independent " + name)
        current()
    client_live = bind_interval(payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
    last_epoch = client_live()

    def client_current():
        nonlocal last_epoch
        observed = client_live()
        if observed < last_epoch:
            _fail("release client clock reversed across original admission")
        last_epoch = observed
        return observed

    client_current()
    identity = _server_bootstrap_digest_on_work(server_original, work)
    client_current()
    plan._same(identity, payload["serverBootstrapDigest"], work, "release client exact server original")
    client_current()
    endpoint = _endpoint(payload["endpoint"], work)
    client_window = processing._narrow(window, deadline_epoch_ns=payload["expiresAtEpochNs"],
        maximum_lifetime_ns=min(window[5], endpoint[1] * 1_000_000_000),
        maximum_clock_skew_ns=window[6])
    client_bound = min(bound, client_window[4])
    material = server._verify_on_work(bootstrap_bytes=server_original, root_public_key=root,
        live_window=client_window, transport_deadline_ns=client_bound, work=work,
        _continuity=_continuity)
    if type(material) is not server._ReleaseMaterial:
        _fail("release client did not obtain actual original server admission")

    def originals_current():
        nonlocal last_epoch
        # The first server sample is compared to the last actual client sample,
        # then the client clock must observe that server suffix as well.
        for check in (material.live, client_live):
            observed = check()
            if observed < last_epoch:
                _fail("release client and server original clocks reversed")
            last_epoch = observed
        return last_epoch

    originals_current()
    joined = {"profile": material.profile, "configurationDigest": material.configuration_digest,
        "databaseId": material.database_id, "generationDigest": material.generation_digest,
        "runtimeClosureDigest": material.runtime_closure_digest, "callerId": material.caller_id,
        "receiverIdentity": material.receiver_identity, "producerId": material.producer_id,
        "producerIdentity": material.producer_identity, "stateReceiptDigest": material.state_receipt_digest,
        "expectedRelease": material.expected_release}
    for name, actual in joined.items():
        originals_current()
        plan._same(actual, payload[name], work, "release client genuine server " + name)
        originals_current()
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    server._contains(interval, material.attestation_interval)
    if (endpoint[0] != material.launch["listenerPath"]
            or endpoint[1] > material.launch["requestTimeoutSeconds"]
            or (material.launch["peerUid"], material.launch["peerGid"]) != (CLIENT_UID, CLIENT_GID)):
        _fail("release client endpoint exceeds genuine server launch pins")
    if payload["profile"] == RECOVERY_PROFILE:
        plan._same(material.storage_scope["checkpoint"],
            {"recordCount": 1, "outcomeDigest": payload["expectedOutcomeDigest"]}, work,
            "release client exact recovery storage checkpoint")
        originals_current()
        plan._same(material.recovery_scope["outcomeDigest"], payload["expectedOutcomeDigest"], work,
            "release client exact recovery outcome")
    originals_current()
    _created, delivery_expiry = server.custody._scope(payload["expectedRelease"]["deliveryScope"], work)
    narrowed = processing._narrow(material.live_window,
        deadline_epoch_ns=min(interval[1], delivery_expiry),
        maximum_lifetime_ns=min(material.live_window[5], endpoint[1] * 1_000_000_000),
        maximum_clock_skew_ns=material.live_window[6])
    deadline = min(bound, material.deadline_ns, narrowed[4])
    if (narrowed[:3] != window[:3]
            or any(actual > prior for actual, prior in zip(narrowed[3:], window[3:]))):
        _fail("release client admission renewed the supplied processing allowance")
    checked, _bind = server.storage._processing(narrowed, deadline, work, _continuity)

    def live():
        nonlocal last_epoch
        originals_current()
        observed = checked()
        if observed < last_epoch or observed >= delivery_expiry:
            _fail("release client narrowed processing clock reversed or delivery expired")
        last_epoch = observed
        return observed

    live()
    return material, narrowed, deadline, live


def _verify_on_work(*, authorization_bytes, server_bootstrap_bytes, root_public_key,
        expected_scope, live_window, transport_deadline_ns, work, _continuity=None):
    """Authenticate actual root originals and separately held client scope17."""
    capture._SharedLedger(work)
    root = root_public_key
    raw = authorization._original(authorization_bytes, MAX_BYTES, "release client authorization")
    server_original = authorization._original(server_bootstrap_bytes, MAX_SERVER_BOOTSTRAP_BYTES,
        "release server bootstrap")
    expected = _capture(expected_scope, work)
    _inventory((raw, server_original), work)
    authorization._public(root)
    _scope_shape(expected, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    current, bind_interval = server.storage._processing(window, bound, work, _continuity)
    current()
    envelope = _read(raw, work)
    current()
    _signature(envelope, root, work)
    current()
    payload = envelope["payload"]
    material, narrowed, deadline, live = _join_server(payload, server_original, root,
        expected, window, bound, current, bind_interval, work, _continuity)
    live()
    _canonical(raw, envelope, work)
    live()
    identity = _digest_on_work(raw, work)
    live()
    owned = _capture(payload, work)
    live()
    return _ClientAuthorization(owned, identity, material, narrowed, deadline, live)


def _produce_on_work(*, payload, server_bootstrap_bytes, root_private_key, root_public_key,
        expected_scope, live_window, transport_deadline_ns, work, _continuity=None):
    """Sign only after genuine server/original-scope admission under this window."""
    capture._SharedLedger(work)
    private, root = root_private_key, root_public_key
    server_original = authorization._original(server_bootstrap_bytes, MAX_SERVER_BOOTSTRAP_BYTES,
        "release server bootstrap")
    owned, expected = _capture(payload, work), _capture(expected_scope, work)
    if len(server_original) + MAX_BYTES > MAX_ORIGINAL_BYTES:
        _fail("release client producer cannot reserve its output original")
    _inventory((server_original,), work)
    authorization._private(private)
    authorization._public(root)
    _payload_shape(owned, work)
    _scope_shape(expected, work)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    current, bind_interval = server.storage._processing(window, bound, work, _continuity)
    current()
    _material, _narrowed, _deadline, live = _join_server(owned, server_original, root,
        expected, window, bound, current, bind_interval, work, _continuity)
    live()
    keys._pair_on_work(private, root, work)
    live()
    envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("release client authorization signature exceeds its output bound")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SIGNATURE_DOMAIN) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("release client authorization cannot reserve its signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("release client authorization changed after measurement")
    message = plan._ascii(plan._frame(SIGNATURE_DOMAIN, (unsigned,), work), work)
    live()
    signature = production._sign_and_verify(private, root, message, work)
    live()
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("release client authorization changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    original = plan.core.canonical_bytes({"schema": SCHEMA, "payload": owned, "signatureBase64Url": encoded})
    if len(original) != envelope_size:
        _fail("release client authorization output differs from its reservation")
    live()
    readback = _read(original, work)
    live()
    _signature(readback, root, work)
    live()
    plan._same(readback["payload"], owned, work, "release client signed payload differs")
    live()
    return original
