"""Root-original receiving admission for consume-grant custody only.

All nested inputs are detached immutable originals bound by the outer root
signature. The actual consume planner and both distinct historical purposes
are admitted here; an incoming material object is never an authority input.
This module delivers no keys, opens no plaintext and issues no execution grant.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature

from serverware import oidc_session_activation_delivery_planner_bootstrap as planner_bootstrap
from serverware import oidc_session_activation_history_custody_bootstrap as history_bootstrap


shared = planner_bootstrap.shared
authority, authorization, capability = shared.authority, shared.authorization, shared.capability
capture, plan, shape, clock = shared.capture, shared.plan, shared.shape, shared.clock
production = shared.configuration.production
SCHEMA = "serverware.signedOidcSessionActivationDeliveryExecutionCustody/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationDeliveryExecutionCustody/v1"
OPERATION = planner_bootstrap.OPERATION
CONSUMER_ROLE = "grant"
PROCESS_MODE = "oidc-session-activation-delivery-execution-authorizer"
SERVICE_UID = SERVICE_GID = 65500
MAX_BYTES = 16 * 1024
MAX_ORIGINALS_BYTES = 64 * 1024 * 1024
MAX_NODES, MAX_DEPTH = 256, 4
_FALSE_FIELDS = shared._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_ORIGINAL_FIELDS = frozenset({"byteCount", "bytesDigest"})
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "operation", "consumerRole",
    "processMode", "serviceUid", "serviceGid", "receiverIdentity", "configurationDigest",
    "generationDigest", "runtimeClosureDigest", "executionBundleKeyDigest",
    "historicalBundleKeyDigest", "deliveryKeyDigest", "plannerBootstrap", "plannerHistoryCustody",
    "receivingHistoryCustody", "consumeRequest", "issuedAtEpochNs", "expiresAtEpochNs",
    "trustMode", *_FALSE_FIELDS})


class OidcSessionActivationDeliveryExecutionCustodyBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CustodyMaterial:
    """Same-call owned facts, not a successful-custody input or capability."""

    custody_bytes: bytes
    planner_bootstrap_bytes: bytes
    planner_history_custody_bytes: bytes
    receiving_history_custody_bytes: bytes
    planner: object
    history: object
    receiver_identity: dict
    attestation_interval: tuple
    opening_sample: tuple
    payload: dict


def _fail(message):
    raise OidcSessionActivationDeliveryExecutionCustodyBootstrapError(message)


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("consume receiving custody exceeds its fixed outer graph bounds")
        return super().visit(value, depth, ancestors)


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _wire(value, work):
    return capability._wire(value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _canonical(raw, value, work):
    return capability._canonical(raw, value, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _decode(raw, work):
    return _capture(capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH), work)


def _fresh(interval, work, opening=None):
    """Check an original current receiving launch, never old plan history."""
    return shared._fresh(interval, work, opening=opening)


def _originals(planner, planning_history, receiving_history, *, outer_bytes):
    originals = (planner, planning_history, receiving_history)
    maxima = (planner_bootstrap.MAX_BYTES, history_bootstrap.MAX_BYTES, history_bootstrap.MAX_BYTES)
    if (any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
            for raw, maximum in zip(originals, maxima))
            or outer_bytes + sum(len(raw) for raw in originals) > MAX_ORIGINALS_BYTES):
        _fail("consume receiving custody requires bounded immutable original bytes")
    return originals


def _payload_shape(payload):
    shape._object(payload, _PAYLOAD_FIELDS, "consume receiving custody payload")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("operation", OPERATION), ("consumerRole", CONSUMER_ROLE), ("processMode", PROCESS_MODE),
            ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID)):
        shape._integer(payload[name], 2**32 - 2, minimum=1)
        if payload[name] != expected:
            _fail("consume receiving process identity differs from its fixed grant purpose")
    shape.validate_identity_shape(payload["receiverIdentity"])
    for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "executionBundleKeyDigest", "historicalBundleKeyDigest", "deliveryKeyDigest"):
        shape._digest(payload[name])
    for name, maximum in (("plannerBootstrap", planner_bootstrap.MAX_BYTES),
            ("plannerHistoryCustody", history_bootstrap.MAX_BYTES),
            ("receivingHistoryCustody", history_bootstrap.MAX_BYTES),
            ("consumeRequest", history_bootstrap.MAX_CONSUME_REQUEST_BYTES)):
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "consume receiving original descriptor")
        shape._integer(record["byteCount"], maximum, minimum=2)
        shape._digest(record["bytesDigest"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[name], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= shared.MAX_RECEIPT_AGE_NS:
        _fail("consume receiving lifetime exceeds the fixed original launch ceiling")
    if any(payload[name] is not False for name in _FALSE_FIELDS):
        _fail("consume receiving custody claims unsupported hardware or witness assurance")


def _same_bytes(left, right, work, message):
    work.charge(input_bytes=len(left) + len(right))
    if left != right:
        _fail(message)


def _bind_original(record, original, current, work):
    current()
    if len(original) != record["byteCount"]:
        _fail("consume receiving detached original length differs")
    work.charge(hashes=1, input_bytes=len(original))
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(original).hexdigest())
    current()
    plan._same(digest, record["bytesDigest"], work, "consume receiving original digest differs")
    current()


def _admit_nested(payload, planner_original, planning_original, receiving_original,
        root, window, bound, current, work):
    for name, original in (("plannerBootstrap", planner_original),
            ("plannerHistoryCustody", planning_original), ("receivingHistoryCustody", receiving_original)):
        _bind_original(payload[name], original, current, work)
    planner = planner_bootstrap._verify_on_work(bootstrap_bytes=planner_original,
        history_custody_bytes=planning_original, root_public_key=root, live_window=window,
        transport_deadline_ns=bound, work=work)
    current()
    roles = planner.payload["configurationPayload"]["roles"]
    for name in shared.configuration._ROLE_NAMES:
        for field, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID)):
            shape._integer(roles[name][field], 2**32 - 2, minimum=1)
            if roles[name][field] == expected:
                _fail("consume receiving identity collides with an independently configured generic role")
    planning = planner.history_material
    planner_live = shared._launch_guard(planner.attestation_interval, planner.opening_sample, current, work)
    planning_live = shared._launch_guard(planning.attestation_interval, planning.opening_sample, planner_live, work)
    planning_live()
    receiving = history_bootstrap._verify_consume_grant_on_work(custody_bytes=receiving_original,
        root_public_key=root, live_window=window, transport_deadline_ns=bound, work=work)
    planning_live()
    live = shared._launch_guard(receiving.attestation_interval, receiving.opening_sample, planning_live, work)
    live()
    # These are fresh, distinct root grants. The embedded original activation
    # planner is historical; equality below never makes its spent interval live.
    for name, expected in (("consumer_role", history_bootstrap.CONSUME_GRANT_CONSUMER_ROLE),
            ("process_mode", PROCESS_MODE), ("service_uid", SERVICE_UID), ("service_gid", SERVICE_GID)):
        plan._same(getattr(receiving, name), expected, work, "consume receiving history purpose differs")
    _same_bytes(planner.consume_request_bytes, receiving.consume_request_bytes, work,
        "consume receiving history is bound to a different typed request")
    _same_bytes(planning.planner.bootstrap_bytes, receiving.planner.bootstrap_bytes, work,
        "consume receiving and planning history use different original activation bootstraps")
    _bind_original(payload["consumeRequest"], planner.consume_request_bytes, live, work)
    for name, expected in (("configurationDigest", planner.payload["configurationDigest"]),
            ("generationDigest", planner.payload["generation"]["digest"]),
            ("runtimeClosureDigest", planner.payload["runtimeClosureDigest"]),
            ("executionBundleKeyDigest", planner.execution_bundle_key_digest),
            ("historicalBundleKeyDigest", receiving.bundle_key_digest),
            ("deliveryKeyDigest", receiving.delivery_key_digest),
            ("receiverIdentity", receiving.receiver_identity)):
        plan._same(payload[name], expected, work, "consume receiving original cohort differs: " + name)
    plan._same((planner.payload["configurationDigest"], planner.payload["generation"]["digest"],
        planner.payload["runtimeClosureDigest"], planner.payload["runtimeRoleIdentities"]),
        (receiving.planner.configuration_digest, receiving.planner.generation["digest"],
        receiving.planner.runtime_closure_digest, receiving.planner.runtime_role_identities), work,
        "consume receiving configuration/runtime differs from the genuine historical cohort")
    pins = (payload["executionBundleKeyDigest"], payload["historicalBundleKeyDigest"],
        payload["deliveryKeyDigest"], planner.payload["journalKeyDigest"], receiving.planner.journal_key_digest)
    for position, left in enumerate(pins):
        for right in pins[position + 1:]:
            work.prepare_comparison(left, right)
            if left == right:
                _fail("consume receiving key purposes are not independently separated")
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    for original_interval in (planner.attestation_interval, planning.attestation_interval, receiving.attestation_interval):
        if not original_interval[0] <= interval[0] < interval[1] <= original_interval[1]:
            _fail("consume receiving interval escapes a genuine current nested launch")
    live()
    return planner, receiving, live


def _verify_on_work(*, custody_bytes, planner_bootstrap_bytes, planner_history_custody_bytes,
        receiving_history_custody_bytes, root_public_key, live_window, transport_deadline_ns, work):
    """Admit four original byte strings with the actual independent root key."""
    try:
        original = custody_bytes
        if type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES:
            _fail("consume receiving envelope is not a bounded immutable original")
        planner_original, planning_original, receiving_original = _originals(planner_bootstrap_bytes,
            planner_history_custody_bytes, receiving_history_custody_bytes, outer_bytes=len(original))
        root = root_public_key
        authorization._public(root)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(window[4], transport_deadline_ns)
        inherited = shared._processing(window, bound, work)
        inherited()
        envelope = _decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed consume receiving custody")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("consume receiving payload is not an exact object")
        _canonical(original, envelope, work)
        payload = envelope["payload"]
        unsigned = _wire(payload, work)
        inherited()
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned, capture._SharedLedger(work))
        inherited()
        _canonical(original, envelope, work)
        _payload_shape(payload)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = shared._launch_guard(interval, opening, inherited, work)
        planner, receiving, live = _admit_nested(payload, planner_original, planning_original,
            receiving_original, root, window, bound, current, work)
        live()
        material = _CustodyMaterial(original, planner_original, planning_original, receiving_original,
            planner, receiving, payload["receiverIdentity"], interval, opening, payload)
        _canonical(original, envelope, work)
        live()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationDeliveryExecutionCustodyBootstrapError):
            raise
        raise OidcSessionActivationDeliveryExecutionCustodyBootstrapError("consume receiving custody admission failed") from exc


def _produce_on_work(*, payload, planner_bootstrap_bytes, planner_history_custody_bytes,
        receiving_history_custody_bytes, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work):
    """Sign only captured claims after genuine admission of all nested originals."""
    try:
        private, root = root_private_key, root_public_key
        planner_original, planning_original, receiving_original = _originals(planner_bootstrap_bytes,
            planner_history_custody_bytes, receiving_history_custody_bytes, outer_bytes=MAX_BYTES)
        authorization._private(private)
        authorization._public(root)
        owned = _capture(payload, work)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(window[4], transport_deadline_ns)
        inherited = shared._processing(window, bound, work)
        inherited()
        _payload_shape(owned)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = shared._launch_guard(interval, opening, inherited, work)
        _planner, _receiving, live = _admit_nested(owned, planner_original, planning_original,
            receiving_original, root, window, bound, current, work)
        unsigned = _wire(owned, work)
        live()
        shared.keys._pair_on_work(private, root, work)
        live()
        envelope = {"schema": SCHEMA, "payload": owned, "signatureBase64Url": "A" * 86}
        envelope_size, envelope_nodes = work.measure(envelope)
        payload_size, payload_nodes = work.measure(owned)
        if (envelope_size > MAX_BYTES or envelope_nodes > MAX_NODES
                or envelope_size + len(planner_original) + len(planning_original) + len(receiving_original) > MAX_ORIGINALS_BYTES):
            _fail("consume receiving signature output exceeds its original bounds")
        work.charge(input_bytes=envelope_size + 2 * payload_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=envelope_nodes + payload_nodes)
        message = plan._ascii(plan._frame(SCHEMA, (unsigned,), work), work)
        live()
        signature = production._sign_and_verify(private, root, message, work)
        live()
        if shared.codec._encode(owned) != unsigned:
            _fail("consume receiving payload changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        shape._base64url(encoded, signature=True)
        envelope["signatureBase64Url"] = encoded
        result = shared.codec._encode(envelope)
        if len(result) != envelope_size:
            _fail("consume receiving output changed after reservation")
        live()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationDeliveryExecutionCustodyBootstrapError):
            raise
        raise OidcSessionActivationDeliveryExecutionCustodyBootstrapError("consume receiving custody production failed") from exc
