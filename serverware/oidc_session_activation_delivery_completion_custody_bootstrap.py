"""Fresh completion-only root authority over genuine historical consume scope.

Detached planner and planning-history originals are authenticated historical
data, never current launches. Only this outer root grant and the separate v6
activation-history grant authorize current processing. No key delivery, SQL,
signing of completion, plaintext release or cross-cohort resolution occurs here.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import oidc_session_activation_delivery_execution_custody_bootstrap as neutral


planner_bootstrap, history_bootstrap, shared = neutral.planner_bootstrap, neutral.history_bootstrap, neutral.shared
authority, authorization, capability = neutral.authority, neutral.authorization, neutral.capability
capture, plan, shape, clock, production = neutral.capture, neutral.plan, neutral.shape, neutral.clock, neutral.production
SCHEMA = "serverware.signedOidcSessionActivationDeliveryCompletionCustody/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationDeliveryCompletionCustody/v1"
OPERATION = planner_bootstrap.OPERATION
CONSUMER_ROLE = history_bootstrap.CONSUME_COMPLETION_CONSUMER_ROLE
PROCESS_MODE = history_bootstrap.CONSUME_COMPLETION_PROCESS_MODE
SERVICE_UID = SERVICE_GID = 65497
MAX_BYTES, MAX_ORIGINALS_BYTES = neutral.MAX_BYTES, neutral.MAX_ORIGINALS_BYTES
MAX_NODES, MAX_DEPTH = neutral.MAX_NODES, neutral.MAX_DEPTH
_PAYLOAD_FIELDS, _ENVELOPE_FIELDS = neutral._PAYLOAD_FIELDS, neutral._ENVELOPE_FIELDS
_ORIGINAL_FIELDS, _FALSE_FIELDS = neutral._ORIGINAL_FIELDS, neutral._FALSE_FIELDS
_capture, _wire, _canonical, _decode = neutral._capture, neutral._wire, neutral._canonical, neutral._decode
_fresh, _originals, _bind_original, _same_bytes = neutral._fresh, neutral._originals, neutral._bind_original, neutral._same_bytes


class DeliveryCompletionCustodyBootstrapError(ValueError):
    pass


def _fail(message):
    raise DeliveryCompletionCustodyBootstrapError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CustodyMaterial:
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


def _payload_shape(payload):
    shape._object(payload, _PAYLOAD_FIELDS, "consume completion custody payload")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("operation", OPERATION), ("consumerRole", CONSUMER_ROLE), ("processMode", PROCESS_MODE),
            ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("serviceUid", "serviceGid"):
        shape._integer(payload[name], 2**32 - 2, minimum=1)
        if payload[name] != SERVICE_UID:
            _fail("consume completion custody has another process identity")
    shape.validate_identity_shape(payload["receiverIdentity"])
    for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "executionBundleKeyDigest", "historicalBundleKeyDigest", "deliveryKeyDigest"):
        shape._digest(payload[name])
    for name, maximum in (("plannerBootstrap", planner_bootstrap.MAX_BYTES),
            ("plannerHistoryCustody", history_bootstrap.MAX_BYTES),
            ("receivingHistoryCustody", history_bootstrap.MAX_BYTES),
            ("consumeRequest", history_bootstrap.MAX_CONSUME_REQUEST_BYTES)):
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "consume completion original descriptor")
        shape._integer(record["byteCount"], maximum, minimum=2)
        shape._digest(record["bytesDigest"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[name], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= shared.MAX_RECEIPT_AGE_NS:
        _fail("consume completion outer lifetime exceeds its source bound")
    if any(payload[name] is not False for name in _FALSE_FIELDS):
        _fail("consume completion claims unsupported hardware or witness assurance")


def _admit_nested(payload, planner_original, planning_original, receiving_original,
        root, window, bound, current, work):
    for name, original in (("plannerBootstrap", planner_original),
            ("plannerHistoryCustody", planning_original), ("receivingHistoryCustody", receiving_original)):
        _bind_original(payload[name], original, current, work)
    planner = planner_bootstrap._verify_historical_on_work(bootstrap_bytes=planner_original,
        history_custody_bytes=planning_original, root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()
    if (type(planner) is not planner_bootstrap._HistoricalPlannerMaterial
            or type(planner.history_material) is not history_bootstrap._HistoricalPlanningMaterial):
        _fail("consume completion requires actual historical planning originals")
    roles = planner.payload["configurationPayload"]["roles"]
    for name in shared.configuration._ROLE_NAMES:
        for field in ("serviceUid", "serviceGid"):
            shape._integer(roles[name][field], 2**32 - 2, minimum=1)
            if roles[name][field] == SERVICE_UID:
                _fail("consume completion identity collides with a configured generic role")
    receiving = history_bootstrap._verify_consume_completion_on_work(custody_bytes=receiving_original,
        root_public_key=root, live_window=window, transport_deadline_ns=bound, work=work)
    current()
    live = shared._launch_guard(receiving.attestation_interval, receiving.opening_sample, current, work)
    live()
    for name, expected in (("consumer_role", CONSUMER_ROLE), ("process_mode", PROCESS_MODE),
            ("service_uid", SERVICE_UID), ("service_gid", SERVICE_GID)):
        plan._same(getattr(receiving, name), expected, work, "consume completion history purpose differs")
    planning = planner.history_material
    _same_bytes(planner.consume_request_bytes, receiving.consume_request_bytes, work,
        "consume completion root grants bind different requests")
    _same_bytes(planning.planner.bootstrap_bytes, receiving.planner.bootstrap_bytes, work,
        "consume completion history grants bind different activation originals")
    _bind_original(payload["consumeRequest"], planner.consume_request_bytes, live, work)
    for name, expected in (("configurationDigest", planner.payload["configurationDigest"]),
            ("generationDigest", planner.payload["generation"]["digest"]),
            ("runtimeClosureDigest", planner.payload["runtimeClosureDigest"]),
            ("executionBundleKeyDigest", planner.execution_bundle_key_digest),
            ("historicalBundleKeyDigest", receiving.bundle_key_digest),
            ("deliveryKeyDigest", receiving.delivery_key_digest),
            ("receiverIdentity", receiving.receiver_identity)):
        plan._same(payload[name], expected, work, "consume completion cohort differs: " + name)
    plan._same((planner.payload["configurationDigest"], planner.payload["generation"]["digest"],
        planner.payload["runtimeClosureDigest"], planner.payload["runtimeRoleIdentities"]),
        (receiving.planner.configuration_digest, receiving.planner.generation["digest"],
        receiving.planner.runtime_closure_digest, receiving.planner.runtime_role_identities), work,
        "consume completion historical configuration/runtime cohort differs")
    pins = (payload["executionBundleKeyDigest"], payload["historicalBundleKeyDigest"],
        payload["deliveryKeyDigest"], planner.payload["journalKeyDigest"], receiving.planner.journal_key_digest)
    for position, left in enumerate(pins):
        for right in pins[position + 1:]:
            work.prepare_comparison(left, right)
            if left == right:
                _fail("consume completion key purposes are not separate")
    interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
    if not receiving.attestation_interval[0] <= interval[0] < interval[1] <= receiving.attestation_interval[1]:
        _fail("consume completion interval escapes its fresh v6 history grant")
    # Old intervals are original metadata. They need not contain the current
    # processing window or the new completion-purpose launch.
    if max(planner.attestation_interval[0], planning.attestation_interval[0]) >= min(
            planner.attestation_interval[1], planning.attestation_interval[1]):
        _fail("consume original planner and planning-history launches never overlapped")
    live()
    return planner, receiving, live


def _verify_on_work(*, custody_bytes, planner_bootstrap_bytes, planner_history_custody_bytes,
        receiving_history_custody_bytes, root_public_key, live_window, transport_deadline_ns, work):
    try:
        original, root = custody_bytes, root_public_key
        if type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES:
            _fail("consume completion custody requires a bounded immutable root original")
        planner_original, planning_original, receiving_original = _originals(planner_bootstrap_bytes,
            planner_history_custody_bytes, receiving_history_custody_bytes, outer_bytes=len(original))
        authorization._public(root)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(window[4], transport_deadline_ns)
        inherited = shared._processing(window, bound, work)
        inherited()
        envelope = _decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed consume completion custody")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("consume completion custody payload is not an exact object")
        _canonical(original, envelope, work)
        unsigned = _wire(envelope["payload"], work)
        inherited()
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned, capture._SharedLedger(work))
        inherited()
        payload = envelope["payload"]
        _payload_shape(payload)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = shared._launch_guard(interval, opening, inherited, work)
        planner, history, live = _admit_nested(payload, planner_original, planning_original,
            receiving_original, root, window, bound, current, work)
        result = _CustodyMaterial(original, planner_original, planning_original, receiving_original,
            planner, history, payload["receiverIdentity"], interval, opening, payload)
        _canonical(original, envelope, work)
        live()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, DeliveryCompletionCustodyBootstrapError):
            raise
        raise DeliveryCompletionCustodyBootstrapError("consume completion custody admission failed") from exc


def _produce_on_work(*, payload, planner_bootstrap_bytes, planner_history_custody_bytes,
        receiving_history_custody_bytes, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work):
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
    _planner, _history, live = _admit_nested(owned, planner_original, planning_original,
        receiving_original, root, window, bound, current, work)
    unsigned = _wire(owned, work)
    live()
    original = shared.signing._sign(owned, SCHEMA, MAX_BYTES, private, root, work)
    live()
    _canonical(unsigned, owned, work)
    _verify_on_work(custody_bytes=original, planner_bootstrap_bytes=planner_original,
        planner_history_custody_bytes=planning_original, receiving_history_custody_bytes=receiving_original,
        root_public_key=root, live_window=window, transport_deadline_ns=bound, work=work)
    live()
    return original
