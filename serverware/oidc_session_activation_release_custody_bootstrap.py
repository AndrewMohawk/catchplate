"""Fresh root-original custody for delivery metadata, never token release.

The original planner supplies historical key/configuration provenance only.
A separate fresh token-release purpose pins one delivery and expected intent
and consumption identities. Those identity pins do not verify an original
intent or committed consumption. This profile opens no key, file or socket.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import time

from cryptography.exceptions import InvalidSignature

from serverware import oidc_session_activation_planner_bootstrap as planner_bootstrap
from serverware import oidc_session_activation_delivery as delivery


authority, authorization = planner_bootstrap.authority, planner_bootstrap.authorization
capability, capture, plan = planner_bootstrap.capability, planner_bootstrap.capture, planner_bootstrap.plan
shape, clock = planner_bootstrap.shape, planner_bootstrap.clock
registration = delivery.registration
production = planner_bootstrap.configuration.production
SCHEMA = "serverware.signedOidcSessionActivationReleaseCustody/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseCustody/v1"
V2_SCHEMA = "serverware.signedOidcSessionActivationReleaseCustody/v2"
V2_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationReleaseCustody/v2"
CONSUMER_ROLE = "token-release"
ROLE = PROCESS_MODE = "oidc-session-activation-token-release"
SERVICE_UID = SERVICE_GID = 65502
ACTIVATION_OPERATION = "oidc.session.activate"
CONSUME_OPERATION = "oidc.session.activation-delivery.consume"
MAX_BYTES = 8 * 1024 * 1024
MAX_NODES, MAX_DEPTH = 256, 4
_FALSE_FIELDS = planner_bootstrap._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "consumerRole", "processMode",
    "serviceUid", "serviceGid", "receiverIdentity", "configurationDigest", "generationDigest",
    "runtimeClosureDigest", "deliveryKeyDigest", "plannerBootstrap", "activationRequestDigest",
    "activationOperationId", "deliveryEnvelopeDigest", "deliveryScope", "releaseIntentDigest",
    "consumeRequestDigest", "consumeOperation", "issuedAtEpochNs", "expiresAtEpochNs",
    "trustMode", *_FALSE_FIELDS})


class OidcSessionActivationReleaseCustodyBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReleaseCustodyMaterial:
    """Owned root claims, never evidence that intent/consumption was verified."""

    custody_bytes: bytes
    planner: planner_bootstrap._PlannerMaterial
    consumer_role: str
    process_mode: str
    service_uid: int
    service_gid: int
    receiver_identity: dict
    delivery_key_digest: str
    activation_request_digest: str
    activation_operation_id: str
    delivery_envelope_digest: str
    delivery_scope: dict
    release_intent_digest: str
    consume_request_digest: str
    consume_operation: str
    attestation_interval: tuple
    opening_sample: tuple
    intent_root_public_key: object = None
    intent_authority_interval: tuple | None = None
    intent_enrollment_bytes: bytes | None = None
    proof_enrollment_bytes: bytes | None = None
    proof_scope: dict | None = None
    historical_custody_bytes: bytes | None = None
    current_activation_planner: object = None


def _fail(message):
    raise OidcSessionActivationReleaseCustodyBootstrapError(message)


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("activation release custody exceeds its fixed shape bounds")
        return super().visit(value, depth, ancestors)


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(raw, value, work):
    return capability._canonical(raw, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _decode(raw, work):
    value = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    return _capture(value, work)


def _fresh(interval, work, opening=None):
    """Fresh release interval only; the original planner is not a live launch."""
    return planner_bootstrap._fresh(interval, work, opening=opening)


def _scope(value, work):
    """Original closed scalar grammar; no key, AEAD or successful row substitute."""
    registration._closed(value, frozenset(delivery._SCOPE_LIMITS), "root-pinned release delivery scope")
    for field, maximum in delivery._SCOPE_LIMITS.items():
        registration._text(value[field], "release delivery " + field, maximum, work)
    registration._encoded_original(value["credentialId"], 1024, work, minimum=1)
    for field in ("assertionDigest", "oldTokenDigest", "newTokenDigest"):
        registration._digest(value[field])
    if value["oldTokenDigest"] == value["newTokenDigest"]:
        _fail("root-pinned release delivery does not rotate its token")
    created = registration._utc(value["createdAt"], "release delivery creation", work)
    expires = registration._utc(value["expiresAt"], "release delivery expiry", work)
    if created.isoformat() != value["createdAt"] or expires.isoformat() != value["expiresAt"]:
        _fail("root-pinned release timestamps are not canonical UTC originals")
    created_ns, expires_ns = registration._now(created), registration._now(expires)
    if not 0 < expires_ns - created_ns <= delivery.MAX_DELIVERY_LIFETIME_NS:
        _fail("root-pinned release delivery lifetime exceeds its source bound")
    return created_ns, expires_ns


def _payload_shape(payload, work):
    if type(payload) is dict and payload.get("schema") == V2_PAYLOAD_SCHEMA:
        from serverware import oidc_session_activation_release_retained_authority as retained
        return retained._shape(payload, work)
    shape._object(payload, _PAYLOAD_FIELDS, "activation release custody payload")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("consumerRole", CONSUMER_ROLE), ("processMode", PROCESS_MODE),
            ("consumeOperation", CONSUME_OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(payload[field], expected)
    for field, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID)):
        shape._integer(payload[field], 2**32 - 2, minimum=1)
        if payload[field] != expected:
            _fail("activation release custody identity differs from its dedicated process")
    shape.validate_identity_shape(payload["receiverIdentity"])
    for field in ("configurationDigest", "generationDigest", "runtimeClosureDigest", "deliveryKeyDigest",
            "activationRequestDigest", "activationOperationId", "deliveryEnvelopeDigest",
            "releaseIntentDigest", "consumeRequestDigest"):
        shape._digest(payload[field])
    record = payload["plannerBootstrap"]
    shape._object(record, _ORIGINAL_FIELDS, "activation release original planner bootstrap")
    authorization.transport._transport_shape(record["base64Url"], record["byteCount"], planner_bootstrap.MAX_BYTES)
    shape._integer(record["byteCount"], planner_bootstrap.MAX_BYTES, minimum=2)
    shape._digest(record["bytesDigest"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[field], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= planner_bootstrap.MAX_RECEIPT_AGE_NS:
        _fail("activation release custody outer lifetime exceeds its source bound")
    _created, expires = _scope(payload["deliveryScope"], work)
    if payload["expiresAtEpochNs"] > expires:
        _fail("activation release custody cannot extend the original delivery expiry")
    if any(payload[field] is not False for field in _FALSE_FIELDS):
        _fail("activation release custody claims unsupported hardware or witness assurance")


def _continuity(current, work):
    if current is None:
        return None
    if not callable(current):
        _fail("release custody continuation is not callable")

    def floors(epoch, monotonic):
        before = current()
        sampled = production._callback(work, time.monotonic_ns)
        after = current()
        if (type(before) is not int or type(after) is not int or type(sampled) is not int
                or before < epoch or after < before or sampled < monotonic):
            _fail("release custody continuation reversed original clock floors")
        return after, sampled

    return floors


def _material(payload, original, root, window, deadline, opening, work, current, *, _current=None):
    if payload["schema"] == V2_PAYLOAD_SCHEMA:
        from serverware import oidc_session_activation_release_retained_authority as retained
        return retained._material(payload, original, root, window, deadline, opening,
            work, current, _current=_current)
    record = payload["plannerBootstrap"]
    current()
    planner_original = authorization.transport._decode(record["base64Url"], record["byteCount"],
        planner_bootstrap.MAX_BYTES, work)
    work.charge(hashes=1, input_bytes=len(planner_original))
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(planner_original).hexdigest())
    current()
    plan._same(digest, record["bytesDigest"], work, "activation release original planner bytes")
    admitted = planner_bootstrap._verify_historical_on_work(bootstrap_bytes=planner_original,
        root_public_key=root, live_window=window, transport_deadline_ns=deadline, work=work,
        _continuity=_continuity(_current, work))
    current()
    for field, expected in (("configurationDigest", admitted.configuration_digest),
            ("generationDigest", admitted.generation["digest"]),
            ("runtimeClosureDigest", admitted.runtime_closure_digest),
            ("deliveryKeyDigest", admitted.delivery_key_digest)):
        plan._same(payload[field], expected, work, "activation release custody/original planner " + field)
    # Genuine v3 admission checks delivery/bundle/journal key separation. Only
    # the delivery key is delivered to this role; none is serialized here.
    roles = admitted.configuration_payload["roles"]
    shape._object(roles, frozenset(planner_bootstrap.configuration._ROLE_NAMES), "release configured roles")
    for name in planner_bootstrap.configuration._ROLE_NAMES:
        for field in ("serviceUid", "serviceGid"):
            shape._integer(roles[name][field], 2**32 - 2)
            if roles[name][field] == SERVICE_UID:
                _fail("activation release process shares a configured generic role")
    operation_id = plan._frame("serverware.policyAuthorityOperation/v2",
        (plan._ascii(ACTIVATION_OPERATION, work), plan._ascii(payload["activationRequestDigest"], work)), work)
    plan._same(payload["activationOperationId"], operation_id, work, "root-pinned activation operation identity")
    delivery_id = registration.core._deterministic_uuid(operation=ACTIVATION_OPERATION,
        request_digest=payload["activationRequestDigest"], purpose="activation-delivery", work=work)
    plan._same(payload["deliveryScope"]["deliveryId"], delivery_id, work, "root-pinned activation delivery identity")
    created_ns, expires_ns = _scope(payload["deliveryScope"], work)
    if created_ns > current() + window[6] or current() >= expires_ns:
        _fail("activation release delivery is future-created or expired")
    if len(original) + len(planner_original) > authority.MAX_RESULT_BYTES:
        _fail("activation release original inventory exceeds its source bound")
    result = _ReleaseCustodyMaterial(original, admitted, CONSUMER_ROLE, PROCESS_MODE,
        SERVICE_UID, SERVICE_GID, payload["receiverIdentity"], payload["deliveryKeyDigest"],
        payload["activationRequestDigest"], payload["activationOperationId"], payload["deliveryEnvelopeDigest"],
        payload["deliveryScope"], payload["releaseIntentDigest"], payload["consumeRequestDigest"],
        CONSUME_OPERATION, (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]), opening)
    current()
    return result


def _verify_on_work(*, custody_bytes, root_public_key, live_window, transport_deadline_ns, work,
        _current=None):
    """Admit original root scope; never infer release intent or consumption."""
    try:
        original = authorization._original(custody_bytes, MAX_BYTES, "activation release custody")
        root = root_public_key
        authorization._public(root)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        deadline = min(window[4], transport_deadline_ns)
        inherited = planner_bootstrap._processing(window, deadline, work)
        inherited = delivery._join_current(inherited, _current, work)
        inherited()
        envelope = _decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed activation release custody")
        schema = envelope["schema"]
        if schema not in (SCHEMA, V2_SCHEMA):
            _fail("activation release custody signed schema is unsupported")
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("activation release custody payload is not an exact object")
        _canonical(original, envelope, work)
        payload = envelope["payload"]
        unsigned = _wire(payload, work)
        inherited()
        capability._signature(root, envelope["signatureBase64Url"], schema, unsigned, capture._SharedLedger(work))
        inherited()
        _canonical(original, envelope, work)
        _payload_shape(payload, work)
        shape._literal(schema, V2_SCHEMA if payload["schema"] == V2_PAYLOAD_SCHEMA else SCHEMA)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = (window[1], window[0], window[2])
        _fresh(interval, work, opening=opening)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        result = _material(payload, original, root, window, deadline, opening, work, current,
            _current=_current)
        _canonical(original, envelope, work)
        current()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationReleaseCustodyBootstrapError):
            raise
        raise OidcSessionActivationReleaseCustodyBootstrapError("activation release custody admission failed") from exc


def _verify_historical_on_work(*, custody_bytes, root_public_key, live_window,
        transport_deadline_ns, work, _current=None):
    """Authenticate old root custody as data, never as renewed release authority.

    The original outer interval remains unchanged and need not still be live.
    The supplied current processing allowance and original delivery expiry
    bound these checks; a separate fresh recovery purpose must authorize
    any later use. The real opening sample is not a renewed outer launch.
    """
    try:
        original = authorization._original(custody_bytes, MAX_BYTES,
            "historical activation release custody")
        root = root_public_key
        authorization._public(root)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        deadline = min(window[4], transport_deadline_ns)
        current = planner_bootstrap._processing(window, deadline, work)
        current = delivery._join_current(current, _current, work)
        current()
        envelope = _decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed historical activation release custody")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("historical activation release custody payload is not an exact object")
        _canonical(original, envelope, work)
        payload = envelope["payload"]
        unsigned = _wire(payload, work)
        current()
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned,
            capture._SharedLedger(work))
        current()
        _canonical(original, envelope, work)
        _payload_shape(payload, work)
        # Retiring the authority of a v2 delivery outcome is a separate bridge,
        # not this original v1 historical-custody profile.
        shape._literal(payload["schema"], PAYLOAD_SCHEMA)
        # Match historical planner admission: actual present time, no future
        # issue and no freshness call or backdated clock for the old interval.
        if payload["issuedAtEpochNs"] > current():
            _fail("historical activation release custody is future-issued")
        opening = clock._sample_on_work(work)
        current()
        # The shared material path genuinely admits the original planner,
        # preserves key/configuration joins and still rejects expired delivery.
        result = _material(payload, original, root, window, deadline, opening, work, current,
            _current=_current)
        _canonical(original, envelope, work)
        current()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationReleaseCustodyBootstrapError):
            raise
        raise OidcSessionActivationReleaseCustodyBootstrapError(
            "historical activation release custody admission failed") from exc


def _produce_on_work(*, payload, root_private_key, root_public_key, live_window,
        transport_deadline_ns, work, _current=None):
    """Sign independent custody pins; do not manufacture verified intent/proof."""
    try:
        private, root = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(root)
        owned = _capture(payload, work)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        deadline = min(window[4], transport_deadline_ns)
        inherited = planner_bootstrap._processing(window, deadline, work)
        inherited = delivery._join_current(inherited, _current, work)
        inherited()
        _payload_shape(owned, work)
        schema = V2_SCHEMA if owned["schema"] == V2_PAYLOAD_SCHEMA else SCHEMA
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = (window[1], window[0], window[2])
        _fresh(interval, work, opening=opening)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        unsigned = _wire(owned, work)
        _material(owned, unsigned, root, window, deadline, opening, work, current, _current=_current)
        planner_bootstrap.keys._pair_on_work(private, root, work)
        current()
        envelope = {"schema": schema, "payload": owned, "signatureBase64Url": "A" * 86}
        envelope_size, envelope_nodes = work.measure(envelope)
        payload_size, payload_nodes = work.measure(owned)
        if envelope_size > MAX_BYTES or envelope_nodes > MAX_NODES:
            _fail("activation release custody signed output exceeds its fixed bound")
        work.charge(input_bytes=envelope_size + 2 * payload_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=envelope_nodes + payload_nodes)
        message = plan._ascii(plan._frame(schema, (unsigned,), work), work)
        current()
        signature = production._sign_and_verify(private, root, message, work)
        current()
        if planner_bootstrap.codec._encode(owned) != unsigned:
            _fail("activation release custody payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = planner_bootstrap.codec._encode(envelope)
        if len(result) != envelope_size:
            _fail("activation release custody output changed after reservation")
        _canonical(result, envelope, work)
        current()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationReleaseCustodyBootstrapError):
            raise
        raise OidcSessionActivationReleaseCustodyBootstrapError("activation release custody production failed") from exc
