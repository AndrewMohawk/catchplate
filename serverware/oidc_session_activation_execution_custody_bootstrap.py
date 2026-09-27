"""Independent receiving-purpose admission for private activation originals.

The outer root signature authorizes one fixed receiving process scope. The
embedded planner bootstrap remains an original requiring its own genuine v3
admission, never a supplied successful material object. This module performs
no process/key delivery, filesystem, transport, SQL or historical admission.
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
SCHEMA = "serverware.signedOidcSessionActivationExecutionCustody/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationExecutionCustody/v1"
OPERATION = "oidc.session.activate"
MAX_BYTES = 8 * 1024 * 1024
MAX_NODES, MAX_DEPTH = 256, 4
CONSUMERS = {
    "grant": ("oidc-session-activation-execution-authorizer", 65506, 65506),
    "reserve": ("oidc-session-activation-execution-reserver", 65505, 65505),
    "sql-issuer": ("oidc-session-activation-execution-sql", 65504, 65504),
}
_FALSE_FIELDS = planner_bootstrap._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "operation", "consumerRole",
    "processMode", "serviceUid", "serviceGid", "receiverIdentity", "configurationDigest",
    "generationDigest", "runtimeClosureDigest", "bundleKeyDigest", "deliveryKeyDigest",
    "plannerBootstrap", "issuedAtEpochNs", "expiresAtEpochNs", "trustMode", *_FALSE_FIELDS})


class OidcSessionActivationExecutionCustodyBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CustodyMaterial:
    """Owned same-call facts, never an accepted receiving-authority token."""

    custody_bytes: bytes
    planner: planner_bootstrap._PlannerMaterial
    consumer_role: str
    process_mode: str
    service_uid: int
    service_gid: int
    receiver_identity: dict
    attestation_interval: tuple
    opening_sample: tuple


def _fail(message):
    raise OidcSessionActivationExecutionCustodyBootstrapError(message)


def _consumer(value):
    if type(value) is not str or value not in CONSUMERS:
        _fail("activation receiving consumer is not a fixed live purpose")
    return CONSUMERS[value]


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("activation custody outer graph exceeds its fixed shape bounds")
        return super().visit(value, depth, ancestors)


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    # Unlike the configuration-containing bootstrap wire, this closed outer
    # graph is integer-only and has its own real 8 MiB encoder reservation.
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(raw, value, work):
    return capability._canonical(raw, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _decode(raw, work):
    value = capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    return _capture(value, work)


def _payload_shape(payload):
    shape._object(payload, _PAYLOAD_FIELDS, "activation receiving custody payload")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("operation", OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(payload[field], expected)
    mode, uid, gid = _consumer(payload["consumerRole"])
    shape._literal(payload["processMode"], mode)
    for field, expected in (("serviceUid", uid), ("serviceGid", gid)):
        shape._integer(payload[field], 2**32 - 2, minimum=1)
        if payload[field] != expected:
            _fail("activation receiving process identity differs from its fixed purpose")
    shape.validate_identity_shape(payload["receiverIdentity"])
    for field in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "bundleKeyDigest", "deliveryKeyDigest"):
        shape._digest(payload[field])
    if payload["bundleKeyDigest"] == payload["deliveryKeyDigest"]:
        _fail("activation receiving bundle and delivery key pins are not separate")
    record = payload["plannerBootstrap"]
    shape._object(record, _ORIGINAL_FIELDS, "activation original planner bootstrap")
    authorization.transport._transport_shape(record["base64Url"], record["byteCount"],
        planner_bootstrap.MAX_BYTES)
    shape._integer(record["byteCount"], planner_bootstrap.MAX_BYTES, minimum=2)
    shape._digest(record["bytesDigest"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[field], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= planner_bootstrap.MAX_RECEIPT_AGE_NS:
        _fail("activation receiving interval exceeds its original launch ceiling")
    if any(payload[field] is not False for field in _FALSE_FIELDS):
        _fail("activation receiving custody claims unsupported hardware or witness assurance")


def _admit_planner(payload, root, window, deadline, work, current):
    record = payload["plannerBootstrap"]
    current()
    original = authorization.transport._decode(record["base64Url"], record["byteCount"],
        planner_bootstrap.MAX_BYTES, work)
    work.charge(hashes=1, input_bytes=len(original))
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(original).hexdigest())
    current()
    plan._same(digest, record["bytesDigest"], work, "activation receiving planner original digest differs")
    admitted = planner_bootstrap._verify_on_work(bootstrap_bytes=original, root_public_key=root,
        work=work, live_window=window, transport_deadline_ns=deadline)
    current()
    for field, expected in (("configurationDigest", admitted.configuration_digest),
            ("generationDigest", admitted.generation["digest"]),
            ("runtimeClosureDigest", admitted.runtime_closure_digest),
            ("bundleKeyDigest", admitted.bundle_key_digest),
            ("deliveryKeyDigest", admitted.delivery_key_digest)):
        plan._same(payload[field], expected, work, "activation receiving/planner " + field + " differs")
    issued, expires = admitted.attestation_interval
    if not issued <= payload["issuedAtEpochNs"] < payload["expiresAtEpochNs"] <= expires:
        _fail("activation receiving interval escapes the original planner launch")
    # The actual v3 verifier also separates both of these keys from its journal
    # key and admits the real configuration/runtime/policy/state/vector inputs.
    current()
    planner_bootstrap._fresh(admitted.attestation_interval, work, opening=admitted.opening_sample)
    current()
    return admitted


def _guard_planner(admitted, current, work):
    def check():
        current()
        planner_bootstrap._fresh(admitted.attestation_interval, work, opening=admitted.opening_sample)
        return current()

    return check


def _verify_on_work(*, custody_bytes, root_public_key, expected_consumer_role, work,
        live_window=None, transport_deadline_ns=None):
    """Reverify both signed originals on one supplied work and original window."""
    try:
        original, root, role = custody_bytes, root_public_key, expected_consumer_role
        if type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES:
            _fail("activation receiving custody is not a bounded immutable original")
        _consumer(role)
        authorization._public(root)
        window = None if live_window is None else clock._validate(live_window)
        deadline = transport_deadline_ns
        inherited = planner_bootstrap._processing(window, deadline, work)
        inherited()
        envelope = _decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed activation receiving custody")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("activation receiving payload is not an exact object")
        _canonical(original, envelope, work)
        unsigned = _wire(envelope["payload"], work)
        inherited()
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned,
            capture._SharedLedger(work))
        inherited()
        _canonical(original, envelope, work)
        payload = envelope["payload"]
        _payload_shape(payload)
        shape._literal(payload["consumerRole"], role)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = planner_bootstrap._fresh(interval, work)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        admitted = _admit_planner(payload, root, window, deadline, work, current)
        live = _guard_planner(admitted, current, work)
        live()
        material = _CustodyMaterial(original, admitted, role, payload["processMode"],
            payload["serviceUid"], payload["serviceGid"], payload["receiverIdentity"], interval, opening)
        _canonical(original, envelope, work)
        live()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationExecutionCustodyBootstrapError):
            raise
        raise OidcSessionActivationExecutionCustodyBootstrapError("activation receiving custody admission failed") from exc


def _produce_on_work(*, payload, root_private_key, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Sign only independently supplied receiver claims and genuine inner bytes."""
    try:
        private, root = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(root)
        owned = _capture(payload, work)
        window = None if live_window is None else clock._validate(live_window)
        deadline = transport_deadline_ns
        inherited = planner_bootstrap._processing(window, deadline, work)
        inherited()
        _payload_shape(owned)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = planner_bootstrap._fresh(interval, work)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        admitted = _admit_planner(owned, root, window, deadline, work, current)
        live = _guard_planner(admitted, current, work)
        unsigned = _wire(owned, work)
        live()
        planner_bootstrap.keys._pair_on_work(private, root, work)
        live()
        envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
        envelope_size, envelope_nodes = work.measure(envelope)
        payload_size, payload_nodes = work.measure(owned)
        if envelope_size > MAX_BYTES or envelope_nodes > MAX_NODES:
            _fail("activation receiving signature output exceeds its outer bound")
        work.charge(input_bytes=envelope_size + 2 * payload_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=envelope_nodes + payload_nodes)
        message = plan._ascii(plan._frame(SCHEMA, (unsigned,), work), work)
        live()
        signature = production._sign_and_verify(private, root, message, work)
        live()
        if planner_bootstrap.codec._encode(owned) != unsigned:
            _fail("activation receiving payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = planner_bootstrap.codec._encode(envelope)
        if len(result) != envelope_size:
            _fail("activation receiving output changed after reservation")
        live()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationExecutionCustodyBootstrapError):
            raise
        raise OidcSessionActivationExecutionCustodyBootstrapError("activation receiving custody production failed") from exc
