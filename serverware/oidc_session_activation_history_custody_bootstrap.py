"""Fresh root admission for historical activation completion custody only.

The original planner bootstrap is genuine historical evidence, not present
receiving authority. A distinct root-signed outer purpose authorizes one fixed
completion process for one fresh bounded interval. No live consumer is widened,
no expired launch is renewed, and no incoming successful material is accepted.
This module performs no key delivery, filesystem, transport, signing of
completion, SQL, token release or historical-cohort resolution.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature

from serverware import oidc_session_activation_planner_bootstrap as planner_bootstrap


authority, authorization = planner_bootstrap.authority, planner_bootstrap.authorization
capability, capture, plan = planner_bootstrap.capability, planner_bootstrap.capture, planner_bootstrap.plan
shape, clock = planner_bootstrap.shape, planner_bootstrap.clock
production = planner_bootstrap.configuration.production
SCHEMA = "serverware.signedOidcSessionActivationHistoryCustody/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationHistoryCustody/v1"
OPERATION = "oidc.session.activate"
CONSUMER_ROLE = "completion-history"
ROLE = PROCESS_MODE = "oidc-session-activation-completion"
SERVICE_UID = SERVICE_GID = 65503
MAX_BYTES = 8 * 1024 * 1024
MAX_NODES, MAX_DEPTH = 256, 4
_FALSE_FIELDS = planner_bootstrap._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "operation", "consumerRole",
    "processMode", "serviceUid", "serviceGid", "receiverIdentity", "configurationDigest",
    "generationDigest", "runtimeClosureDigest", "bundleKeyDigest", "deliveryKeyDigest",
    "plannerBootstrap", "issuedAtEpochNs", "expiresAtEpochNs", "trustMode", *_FALSE_FIELDS})


class OidcSessionActivationHistoryCustodyBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoryCustodyMaterial:
    """Owned same-call facts; no entrypoint accepts this as an authority input."""

    custody_bytes: bytes
    planner: planner_bootstrap._PlannerMaterial
    consumer_role: str
    process_mode: str
    service_uid: int
    service_gid: int
    receiver_identity: dict
    bundle_key_digest: str
    delivery_key_digest: str
    attestation_interval: tuple
    opening_sample: tuple


def _fail(message):
    raise OidcSessionActivationHistoryCustodyBootstrapError(message)


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("activation history custody exceeds its fixed outer shape bounds")
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
    """Fresh OUTER role interval only; never call this on planner history."""
    return planner_bootstrap._fresh(interval, work, opening=opening)


def _payload_shape(payload):
    shape._object(payload, _PAYLOAD_FIELDS, "activation history custody payload")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("operation", OPERATION), ("consumerRole", CONSUMER_ROLE), ("processMode", PROCESS_MODE),
            ("trustMode", "trusted-host-local")):
        shape._literal(payload[field], expected)
    for field, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID)):
        shape._integer(payload[field], 2**32 - 2, minimum=1)
        if payload[field] != expected:
            _fail("activation history custody process identity differs from its fixed purpose")
    shape.validate_identity_shape(payload["receiverIdentity"])
    for field in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "bundleKeyDigest", "deliveryKeyDigest"):
        shape._digest(payload[field])
    if payload["bundleKeyDigest"] == payload["deliveryKeyDigest"]:
        _fail("activation history custody bundle and delivery keys are not separate")
    record = payload["plannerBootstrap"]
    shape._object(record, _ORIGINAL_FIELDS, "historical planner bootstrap original")
    authorization.transport._transport_shape(record["base64Url"], record["byteCount"],
        planner_bootstrap.MAX_BYTES)
    shape._integer(record["byteCount"], planner_bootstrap.MAX_BYTES, minimum=2)
    shape._digest(record["bytesDigest"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[field], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= planner_bootstrap.MAX_RECEIPT_AGE_NS:
        _fail("activation history custody outer lifetime exceeds its fixed bound")
    if any(payload[field] is not False for field in _FALSE_FIELDS):
        _fail("activation history custody claims unsupported hardware or witness assurance")


def _admit_planner(payload, root, window, deadline, work, current):
    record = payload["plannerBootstrap"]
    current()
    original = authorization.transport._decode(record["base64Url"], record["byteCount"],
        planner_bootstrap.MAX_BYTES, work)
    work.charge(hashes=1, input_bytes=len(original))
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(original).hexdigest())
    current()
    plan._same(digest, record["bytesDigest"], work, "historical planner original digest differs")
    admitted = planner_bootstrap._verify_historical_on_work(bootstrap_bytes=original,
        root_public_key=root, live_window=window, transport_deadline_ns=deadline, work=work)
    current()
    for field, expected in (("configurationDigest", admitted.configuration_digest),
            ("generationDigest", admitted.generation["digest"]),
            ("runtimeClosureDigest", admitted.runtime_closure_digest),
            ("bundleKeyDigest", admitted.bundle_key_digest),
            ("deliveryKeyDigest", admitted.delivery_key_digest)):
        plan._same(payload[field], expected, work, "activation history custody/planner " + field + " differs")
    # The genuine v3 parser also separates these AES pins from the original
    # journal key. Old planner launch fields remain historical data only: the
    # fresh outer interval neither fits within nor renews that spent interval.
    current()
    return admitted


def _verify_on_work(*, custody_bytes, root_public_key, work, live_window, transport_deadline_ns):
    """Authenticate fresh outer purpose and genuine historical inner originals."""
    try:
        original, root = custody_bytes, root_public_key
        if type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES:
            _fail("activation history custody is not a bounded immutable original")
        authorization._public(root)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        deadline = min(window[4], transport_deadline_ns)
        inherited = planner_bootstrap._processing(window, deadline, work)
        inherited()
        envelope = _decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed activation history custody")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("activation history custody payload is not an exact object")
        _canonical(original, envelope, work)
        unsigned = _wire(envelope["payload"], work)
        inherited()
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned,
            capture._SharedLedger(work))
        inherited()
        _canonical(original, envelope, work)
        payload = envelope["payload"]
        _payload_shape(payload)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        admitted = _admit_planner(payload, root, window, deadline, work, current)
        material = _HistoryCustodyMaterial(original, admitted, CONSUMER_ROLE, PROCESS_MODE,
            SERVICE_UID, SERVICE_GID, payload["receiverIdentity"], payload["bundleKeyDigest"],
            payload["deliveryKeyDigest"], interval, opening)
        _canonical(original, envelope, work)
        current()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationHistoryCustodyBootstrapError):
            raise
        raise OidcSessionActivationHistoryCustodyBootstrapError("activation history custody admission failed") from exc


def _produce_on_work(*, payload, root_private_key, root_public_key, work,
        live_window, transport_deadline_ns):
    """Sign fresh independently established history scope, never invent its pins."""
    try:
        private, root = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(root)
        owned = _capture(payload, work)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        deadline = min(window[4], transport_deadline_ns)
        inherited = planner_bootstrap._processing(window, deadline, work)
        inherited()
        _payload_shape(owned)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        _admit_planner(owned, root, window, deadline, work, current)
        unsigned = _wire(owned, work)
        current()
        planner_bootstrap.keys._pair_on_work(private, root, work)
        current()
        envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
        envelope_size, envelope_nodes = work.measure(envelope)
        payload_size, payload_nodes = work.measure(owned)
        if envelope_size > MAX_BYTES or envelope_nodes > MAX_NODES:
            _fail("activation history custody output exceeds its outer bound")
        work.charge(input_bytes=envelope_size + 2 * payload_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=envelope_nodes + payload_nodes)
        message = plan._ascii(plan._frame(SCHEMA, (unsigned,), work), work)
        current()
        signature = production._sign_and_verify(private, root, message, work)
        current()
        if planner_bootstrap.codec._encode(owned) != unsigned:
            _fail("activation history custody payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = planner_bootstrap.codec._encode(envelope)
        if len(result) != envelope_size:
            _fail("activation history custody output changed after reservation")
        current()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationHistoryCustodyBootstrapError):
            raise
        raise OidcSessionActivationHistoryCustodyBootstrapError("activation history custody production failed") from exc
