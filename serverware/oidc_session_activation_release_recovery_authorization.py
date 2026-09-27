"""Fresh root-original authority to recover one unchanged release outcome.

This is separate from storage authorization and old release custody. It does
not renew an intent, proof or execution interval, inspect a directory, create
an outcome or claim that a token was delivered. Actual recovery separately
joins checkpoint-one storage and the still-live original delivery.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import time

from cryptography.exceptions import InvalidSignature

from serverware import oidc_session_activation_release_custody_bootstrap as bootstrap
from serverware import authority_successor_execution_window as processing
from serverware.authority_query_read_work import QueryReadWorkError


authorization, plan, shape = bootstrap.authorization, bootstrap.plan, bootstrap.shape
clock, production, capture = bootstrap.clock, bootstrap.production, bootstrap.capture
delivery, authority, capability = bootstrap.delivery, bootstrap.authority, bootstrap.capability
keys, registration = bootstrap.planner_bootstrap.keys, bootstrap.registration
PURPOSE = "recover-oidc-session-activation-release"
SCHEMA = "serverware.signedOidcSessionActivationReleaseRecoveryAuthorization/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseRecoveryAuthorization/v1"
SIGNATURE_DOMAIN = SCHEMA
IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseRecoveryAuthorizationIdentity/v1"
ROLE = PROCESS_MODE = bootstrap.PROCESS_MODE
SERVICE_UID, SERVICE_GID = bootstrap.SERVICE_UID, bootstrap.SERVICE_GID
MAX_BYTES = 16 * 1024
MAX_NODES, MAX_DEPTH = 256, 4
MAX_RECEIPT_AGE_NS = bootstrap.planner_bootstrap.MAX_RECEIPT_AGE_NS
SCOPE_FIELDS = frozenset({"configurationDigest", "databaseId", "generationDigest",
    "runtimeClosureDigest", "receiverIdentity", "callerId", "releaseCustodyDigest",
    "deliveryKeyDigest", "deliveryId", "outcomeDigest", "directory"})
DIRECTORY_FIELDS = frozenset({"device", "inode", "uid", "gid"})
PAYLOAD_FIELDS = SCOPE_FIELDS | frozenset({"schema", "sourceRevision", "purpose",
    "serviceUid", "serviceGid", "processMode", "trustMode", "issuedAtEpochNs", "expiresAtEpochNs"})
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})


class OidcSessionActivationReleaseRecoveryAuthorizationError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseRecoveryAuthorizationError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Authorization:
    """Owned same-call observations, never accepted instead of originals."""

    payload: dict
    authorization_digest: str
    live: object


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("release recovery authorization exceeds its fixed structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("release recovery authorization exceeds its fixed node bound")
        return result


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(original, value, work):
    return capability._canonical(original, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _fixed_owner(value, uid_field, gid_field):
    for field, expected in ((uid_field, SERVICE_UID), (gid_field, SERVICE_GID)):
        shape._integer(value[field], 2**32 - 2, minimum=1)
        if value[field] != expected:
            _fail("release recovery authorization names a different fixed service identity")


def _scope_shape(value, work):
    shape._object(value, SCOPE_FIELDS, "release recovery independent scope")
    for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "releaseCustodyDigest", "deliveryKeyDigest", "outcomeDigest"):
        shape._digest(value[name])
    for name in ("databaseId", "callerId"):
        authorization._token(value[name])
    registration._text(value["deliveryId"], "release recovery delivery identity",
        delivery._SCOPE_LIMITS["deliveryId"], work)
    shape.validate_identity_shape(value["receiverIdentity"])
    directory = value["directory"]
    shape._object(directory, DIRECTORY_FIELDS, "release recovery directory binding")
    shape._integer(directory["device"], 2**64 - 1)
    shape._integer(directory["inode"], 2**64 - 1, minimum=1)
    _fixed_owner(directory, "uid", "gid")


def _scope(value, work):
    """Own independent scope11 without learning any pin from storage."""
    owned = _capture(value, work)
    _scope_shape(owned, work)
    return owned


def _payload_shape(payload, work):
    shape._object(payload, PAYLOAD_FIELDS, "release recovery authorization")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("purpose", PURPOSE), ("processMode", PROCESS_MODE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[field], expected)
    _fixed_owner(payload, "serviceUid", "serviceGid")
    _scope_shape({name: payload[name] for name in SCOPE_FIELDS}, work)
    authorization._interval(payload, MAX_RECEIPT_AGE_NS)


def _read(original, work):
    """Own canonical bounded data, without authenticating root authority."""
    raw = authorization._original(original, MAX_BYTES, "release recovery authorization")
    decoded = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _capture(decoded, work)
    shape._object(owned, _ENVELOPE_FIELDS, "signed release recovery authorization")
    shape._literal(owned["schema"], SCHEMA)
    shape._base64url(owned["signatureBase64Url"], signature=True)
    _payload_shape(owned["payload"], work)
    _canonical(raw, owned, work)
    return owned


def _digest_on_work(original, work):
    """Exact-original domain identity, not an admission or recovery result."""
    raw = authorization._original(original, MAX_BYTES, "release recovery authorization")
    _read(raw, work)
    return plan._frame(IDENTITY_DOMAIN, (raw,), work)


def _processing(live_window, transport_deadline_ns, work):
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            _fail("release recovery authorization processing clocks expired or reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    def bind_interval(issued, expires):
        nonlocal window, bound
        # Fresh root permission cannot replace the caller's earlier opening,
        # shorter request lifetime, skew policy or transport bound.
        window = processing._narrow(window, deadline_epoch_ns=expires,
            maximum_lifetime_ns=window[5], maximum_clock_skew_ns=window[6])
        bound = min(bound, window[4])
        skew = window[6]

        def live():
            now = current()
            if issued > now + skew or now >= expires:
                _fail("release recovery authorization original interval is not live")
            return now

        return live

    return current, bind_interval


def _verify_on_work(*, authorization_bytes, root_public_key, expected_scope,
        live_window, transport_deadline_ns, work):
    """Admit this root original against independent scope and current bounds."""
    capture._SharedLedger(work)
    raw = authorization._original(authorization_bytes, MAX_BYTES, "release recovery authorization")
    root = root_public_key
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    expected = _scope(expected_scope, work)
    current, bind_interval = _processing(window, transport_deadline_ns, work)
    current()
    envelope = _read(raw, work)
    current()
    payload = envelope["payload"]
    unsigned = _wire(payload, work)
    current()
    try:
        capability._signature(root, envelope["signatureBase64Url"], SIGNATURE_DOMAIN,
            unsigned, capture._SharedLedger(work))
    except InvalidSignature as exc:
        raise OidcSessionActivationReleaseRecoveryAuthorizationError(
            "release recovery authorization root signature is invalid") from exc
    current()
    for name in SCOPE_FIELDS:
        plan._same(payload[name], expected[name], work, "release recovery authorization " + name)
    current()
    live = bind_interval(payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
    live()
    _canonical(raw, envelope, work)
    live()
    identity = _digest_on_work(raw, work)
    live()
    owned = _capture(payload, work)
    live()
    return _Authorization(owned, identity, live)


def _produce_on_work(*, payload, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work):
    """Sign only this purpose and genuinely admit the exact current output."""
    capture._SharedLedger(work)
    private, root = root_private_key, root_public_key
    authorization._private(private)
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    owned = _capture(payload, work)
    _payload_shape(owned, work)
    expected = _scope({name: owned[name] for name in SCOPE_FIELDS}, work)
    current, bind_interval = _processing(window, transport_deadline_ns, work)
    current()
    live = bind_interval(owned["issuedAtEpochNs"], owned["expiresAtEpochNs"])
    live()
    keys._pair_on_work(private, root, work)
    live()
    envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if max(unsigned_size, envelope_size) > MAX_BYTES or max(unsigned_nodes, envelope_nodes) > MAX_NODES:
        _fail("release recovery authorization signature exceeds its output bounds")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(SIGNATURE_DOMAIN) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("release recovery authorization cannot reserve its signature output")
    unsigned = plan.core.canonical_bytes(owned)
    if len(unsigned) != unsigned_size:
        _fail("release recovery authorization changed after measurement")
    message = plan._ascii(plan._frame(SIGNATURE_DOMAIN, (unsigned,), work), work)
    live()
    signature = production._sign_and_verify(private, root, message, work)
    live()
    if work.measure(owned) != (unsigned_size, unsigned_nodes) or plan.core.canonical_bytes(owned) != unsigned:
        _fail("release recovery authorization changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded, signature=True)
    original = plan.core.canonical_bytes({"schema": SCHEMA,
        "payload": owned, "signatureBase64Url": encoded})
    if len(original) != envelope_size:
        _fail("release recovery authorization output changed after reservation")
    live()
    verified = _verify_on_work(authorization_bytes=original, root_public_key=root,
        expected_scope=expected, live_window=window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    verified.live()
    plan._same(verified.payload, owned, work, "release recovery authorization signed payload differs")
    live()
    verified.live()
    return original
