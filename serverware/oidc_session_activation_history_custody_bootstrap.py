"""Separate fresh root purposes for historical activation original custody.

The original planner bootstrap is genuine historical evidence, not present
receiving authority. A distinct root-signed outer purpose authorizes one fixed
completion or fixed consume process for a fresh bounded interval. Each consume
purpose binds the exact original request. The distinct v6 consume-completion
purpose cannot enter live planning, grant, reserve or SQL admission. No live consumer is widened,
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
CONSUME_SCHEMA = "serverware.signedOidcSessionActivationHistoryCustody/v2"
CONSUME_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationHistoryCustody/v2"
CONSUME_OPERATION = "oidc.session.activation-delivery.consume"
CONSUME_CONSUMER_ROLE = "consume-planning-history"
CONSUME_PROCESS_MODE = "oidc-session-activation-delivery-planner"
CONSUME_SERVICE_UID = CONSUME_SERVICE_GID = 65501
CONSUME_GRANT_SCHEMA = "serverware.signedOidcSessionActivationHistoryCustody/v3"
CONSUME_GRANT_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationHistoryCustody/v3"
CONSUME_GRANT_OPERATION = CONSUME_OPERATION
CONSUME_GRANT_CONSUMER_ROLE = "consume-grant-history"
CONSUME_GRANT_PROCESS_MODE = "oidc-session-activation-delivery-execution-authorizer"
CONSUME_GRANT_SERVICE_UID = CONSUME_GRANT_SERVICE_GID = 65500
CONSUME_RESERVE_SCHEMA = "serverware.signedOidcSessionActivationHistoryCustody/v4"
CONSUME_RESERVE_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationHistoryCustody/v4"
CONSUME_RESERVE_CONSUMER_ROLE = "consume-reserve-history"
CONSUME_RESERVE_PROCESS_MODE = "oidc-session-activation-delivery-execution-reserver"
CONSUME_RESERVE_SERVICE_UID = CONSUME_RESERVE_SERVICE_GID = 65499
CONSUME_SQL_ISSUER_SCHEMA = "serverware.signedOidcSessionActivationHistoryCustody/v5"
CONSUME_SQL_ISSUER_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationHistoryCustody/v5"
CONSUME_SQL_ISSUER_CONSUMER_ROLE = "consume-sql-issuer-history"
CONSUME_SQL_ISSUER_PROCESS_MODE = "oidc-session-activation-delivery-execution-sql"
CONSUME_SQL_ISSUER_SERVICE_UID = CONSUME_SQL_ISSUER_SERVICE_GID = 65498
CONSUME_COMPLETION_SCHEMA = "serverware.signedOidcSessionActivationHistoryCustody/v6"
CONSUME_COMPLETION_PAYLOAD_SCHEMA = "serverware.oidcSessionActivationHistoryCustody/v6"
CONSUME_COMPLETION_CONSUMER_ROLE = "consume-completion-history"
CONSUME_COMPLETION_PROCESS_MODE = "oidc-session-activation-delivery-completion"
CONSUME_COMPLETION_SERVICE_UID = CONSUME_COMPLETION_SERVICE_GID = 65497
MAX_CONSUME_REQUEST_BYTES = 2 * 1024 * 1024
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
    consume_request_bytes: bytes | None


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalPlanningMaterial(_HistoryCustodyMaterial):
    """Authenticated expired v2 data, never a fresh process grant."""


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


def _purpose_from_consume(consume):
    if type(consume) is not bool:
        _fail("historical custody purpose selector is not source-fixed")
    return CONSUME_CONSUMER_ROLE if consume else CONSUMER_ROLE


def _purpose_profile(purpose):
    if type(purpose) is not str:
        _fail("historical custody requires an exact fixed purpose")
    if purpose == CONSUMER_ROLE:
        return (SCHEMA, PAYLOAD_SCHEMA, OPERATION, CONSUMER_ROLE,
            PROCESS_MODE, SERVICE_UID, SERVICE_GID)
    if purpose == CONSUME_CONSUMER_ROLE:
        return (CONSUME_SCHEMA, CONSUME_PAYLOAD_SCHEMA, CONSUME_OPERATION,
            CONSUME_CONSUMER_ROLE, CONSUME_PROCESS_MODE, CONSUME_SERVICE_UID, CONSUME_SERVICE_GID)
    if purpose == CONSUME_GRANT_CONSUMER_ROLE:
        return (CONSUME_GRANT_SCHEMA, CONSUME_GRANT_PAYLOAD_SCHEMA, CONSUME_GRANT_OPERATION,
            CONSUME_GRANT_CONSUMER_ROLE, CONSUME_GRANT_PROCESS_MODE,
            CONSUME_GRANT_SERVICE_UID, CONSUME_GRANT_SERVICE_GID)
    if purpose == CONSUME_RESERVE_CONSUMER_ROLE:
        return (CONSUME_RESERVE_SCHEMA, CONSUME_RESERVE_PAYLOAD_SCHEMA, CONSUME_OPERATION,
            CONSUME_RESERVE_CONSUMER_ROLE, CONSUME_RESERVE_PROCESS_MODE,
            CONSUME_RESERVE_SERVICE_UID, CONSUME_RESERVE_SERVICE_GID)
    if purpose == CONSUME_SQL_ISSUER_CONSUMER_ROLE:
        return (CONSUME_SQL_ISSUER_SCHEMA, CONSUME_SQL_ISSUER_PAYLOAD_SCHEMA, CONSUME_OPERATION,
            CONSUME_SQL_ISSUER_CONSUMER_ROLE, CONSUME_SQL_ISSUER_PROCESS_MODE,
            CONSUME_SQL_ISSUER_SERVICE_UID, CONSUME_SQL_ISSUER_SERVICE_GID)
    if purpose == CONSUME_COMPLETION_CONSUMER_ROLE:
        return (CONSUME_COMPLETION_SCHEMA, CONSUME_COMPLETION_PAYLOAD_SCHEMA, CONSUME_OPERATION,
            CONSUME_COMPLETION_CONSUMER_ROLE, CONSUME_COMPLETION_PROCESS_MODE,
            CONSUME_COMPLETION_SERVICE_UID, CONSUME_COMPLETION_SERVICE_GID)
    _fail("historical custody purpose is not a supported fixed profile")


def _profile(consume):
    """Preserve the exact bool-only v1/v2 selector; no truthy v3 alias."""
    return _purpose_profile(_purpose_from_consume(consume))


def _requires_consume_request(purpose):
    _purpose_profile(purpose)
    return purpose in (CONSUME_CONSUMER_ROLE, CONSUME_GRANT_CONSUMER_ROLE,
        CONSUME_RESERVE_CONSUMER_ROLE, CONSUME_SQL_ISSUER_CONSUMER_ROLE,
        CONSUME_COMPLETION_CONSUMER_ROLE)


def _payload_shape(payload, *, consume=False):
    return _payload_for_purpose(payload, purpose=_purpose_from_consume(consume))


def _payload_for_purpose(payload, *, purpose):
    _schema, payload_schema, operation, role, mode, uid, gid = _purpose_profile(purpose)
    consume = _requires_consume_request(purpose)
    fields = _PAYLOAD_FIELDS | {"consumeRequest"} if consume else _PAYLOAD_FIELDS
    shape._object(payload, fields, "activation history custody payload")
    for field, expected in (("schema", payload_schema), ("sourceRevision", authority.SOURCE_REVISION),
            ("operation", operation), ("consumerRole", role), ("processMode", mode),
            ("trustMode", "trusted-host-local")):
        shape._literal(payload[field], expected)
    for field, expected in (("serviceUid", uid), ("serviceGid", gid)):
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
    if consume:
        record = payload["consumeRequest"]
        shape._object(record, _ORIGINAL_FIELDS, "root-bound consume request original")
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"],
            MAX_CONSUME_REQUEST_BYTES)
        shape._integer(record["byteCount"], MAX_CONSUME_REQUEST_BYTES, minimum=2)
        shape._digest(record["bytesDigest"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[field], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= planner_bootstrap.MAX_RECEIPT_AGE_NS:
        _fail("activation history custody outer lifetime exceeds its fixed bound")
    if any(payload[field] is not False for field in _FALSE_FIELDS):
        _fail("activation history custody claims unsupported hardware or witness assurance")


def _consume_request_on_work(value, work):
    """Capture and commit an ordinary typed original; not permission or effects."""
    from serverware import authority_request_commitment as commitment
    from serverware import authority_transition_oidc_session_activation_delivery as consumption

    ledger = capture._SharedLedger(work)
    owned = consumption.assertion._Capture(ledger,
        maximum_bytes=MAX_CONSUME_REQUEST_BYTES).visit(value)
    if type(owned) is not dict or owned.get("operation") != CONSUME_OPERATION:
        _fail("historical consume purpose requires the actual typed consume request")
    digest = commitment._typed_request_digest(owned, work=work)
    plan._same(owned["requestDigest"], digest, work, "root-bound consume request digest differs")
    operation_id = plan._frame("serverware.policyAuthorityOperation/v2",
        (plan._ascii(CONSUME_OPERATION, work), plan._ascii(digest, work)), work)
    plan._same(owned["operationId"], operation_id, work, "root-bound consume operation ID differs")
    consumption._arguments(owned["arguments"], work)
    return capability._wire(owned, ledger, MAX_CONSUME_REQUEST_BYTES,
        consumption.assertion.MAX_CONTEXT_NODES)


def _admit_consume_request(payload, work, current):
    record = payload["consumeRequest"]
    current()
    original = authorization.transport._decode(record["base64Url"], record["byteCount"],
        MAX_CONSUME_REQUEST_BYTES, work)
    work.charge(hashes=1, input_bytes=len(original))
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(original).hexdigest())
    current()
    plan._same(digest, record["bytesDigest"], work, "root-bound consume original digest differs")
    value = capability.wire._decode_object(original, work=work,
        maximum_bytes=MAX_CONSUME_REQUEST_BYTES, maximum_nodes=100_000, maximum_depth=12)
    canonical = _consume_request_on_work(value, work)
    work.charge(input_bytes=len(original) + len(canonical))
    if original != canonical:
        _fail("root-bound consume request is not canonical original bytes")
    current()
    return original


def _admit_planner(payload, root, window, deadline, work, current, *, _continuity=None):
    record = payload["plannerBootstrap"]
    current()
    original = authorization.transport._decode(record["base64Url"], record["byteCount"],
        planner_bootstrap.MAX_BYTES, work)
    work.charge(hashes=1, input_bytes=len(original))
    digest = production._callback(work, lambda: "sha256:" + hashlib.sha256(original).hexdigest())
    current()
    plan._same(digest, record["bytesDigest"], work, "historical planner original digest differs")
    admitted = planner_bootstrap._verify_historical_on_work(bootstrap_bytes=original,
        root_public_key=root, live_window=window, transport_deadline_ns=deadline, work=work,
        _continuity=_continuity)
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


def _verify_fixed_purpose(*, custody_bytes, root_public_key, work, live_window,
        transport_deadline_ns, purpose, _continuity=None):
    """Authenticate fresh outer purpose and genuine historical inner originals."""
    try:
        original, root = custody_bytes, root_public_key
        schema, _payload_schema, _operation, role, mode, uid, gid = _purpose_profile(purpose)
        consume = _requires_consume_request(purpose)
        if type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES:
            _fail("activation history custody is not a bounded immutable original")
        authorization._public(root)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        deadline = min(window[4], transport_deadline_ns)
        inherited = planner_bootstrap._processing(window, deadline, work, _continuity=_continuity)
        inherited()
        envelope = _decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed activation history custody")
        shape._literal(envelope["schema"], schema)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("activation history custody payload is not an exact object")
        _canonical(original, envelope, work)
        unsigned = _wire(envelope["payload"], work)
        inherited()
        capability._signature(root, envelope["signatureBase64Url"], schema, unsigned,
            capture._SharedLedger(work))
        inherited()
        _canonical(original, envelope, work)
        payload = envelope["payload"]
        _payload_for_purpose(payload, purpose=purpose)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work, _continuity=_continuity)
        admitted = _admit_planner(payload, root, window, deadline, work, current, _continuity=_continuity)
        request = _admit_consume_request(payload, work, current) if consume else None
        material = _HistoryCustodyMaterial(original, admitted, role, mode,
            uid, gid, payload["receiverIdentity"], payload["bundleKeyDigest"],
            payload["deliveryKeyDigest"], interval, opening, request)
        _canonical(original, envelope, work)
        current()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationHistoryCustodyBootstrapError):
            raise
        raise OidcSessionActivationHistoryCustodyBootstrapError("activation history custody admission failed") from exc


def _produce_fixed_purpose(*, payload, root_private_key, root_public_key, work,
        live_window, transport_deadline_ns, purpose, _continuity=None):
    """Sign fresh independently established history scope, never invent its pins."""
    try:
        private, root = root_private_key, root_public_key
        schema = _purpose_profile(purpose)[0]
        consume = _requires_consume_request(purpose)
        authorization._private(private)
        authorization._public(root)
        owned = _capture(payload, work)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        deadline = min(window[4], transport_deadline_ns)
        inherited = planner_bootstrap._processing(window, deadline, work, _continuity=_continuity)
        inherited()
        _payload_for_purpose(owned, purpose=purpose)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work, _continuity=_continuity)
        _admit_planner(owned, root, window, deadline, work, current, _continuity=_continuity)
        if consume:
            _admit_consume_request(owned, work, current)
        unsigned = _wire(owned, work)
        current()
        planner_bootstrap.keys._pair_on_work(private, root, work)
        current()
        envelope = {"schema": schema, "payload": owned, "signatureBase64Url": "A" * 86}
        envelope_size, envelope_nodes = work.measure(envelope)
        payload_size, payload_nodes = work.measure(owned)
        if envelope_size > MAX_BYTES or envelope_nodes > MAX_NODES:
            _fail("activation history custody output exceeds its outer bound")
        work.charge(input_bytes=envelope_size + 2 * payload_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=envelope_nodes + payload_nodes)
        message = plan._ascii(plan._frame(schema, (unsigned,), work), work)
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


def _verify_for_purpose(*, custody_bytes, root_public_key, work, live_window,
        transport_deadline_ns, consume, _continuity=None):
    return _verify_fixed_purpose(custody_bytes=custody_bytes, root_public_key=root_public_key,
        work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        purpose=_purpose_from_consume(consume), _continuity=_continuity)


def _produce_for_purpose(*, payload, root_private_key, root_public_key, work,
        live_window, transport_deadline_ns, consume, _continuity=None):
    return _produce_fixed_purpose(payload=payload, root_private_key=root_private_key,
        root_public_key=root_public_key, work=work, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, purpose=_purpose_from_consume(consume),
        _continuity=_continuity)


def _verify_on_work(*, custody_bytes, root_public_key, work, live_window, transport_deadline_ns):
    """Preserved completion-only v1 original admission."""
    return _verify_for_purpose(custody_bytes=custody_bytes, root_public_key=root_public_key,
        work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns, consume=False)


def _verify_consume_on_work(*, custody_bytes, root_public_key, work, live_window, transport_deadline_ns,
        _continuity=None):
    """Fixed request-bound consume-planning v2 original admission only."""
    return _verify_for_purpose(custody_bytes=custody_bytes, root_public_key=root_public_key,
        work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns, consume=True,
        _continuity=_continuity)


def _verify_consume_grant_on_work(*, custody_bytes, root_public_key, work, live_window,
        transport_deadline_ns):
    """Fixed request-bound consume-grant v3 original admission only."""
    return _verify_fixed_purpose(custody_bytes=custody_bytes, root_public_key=root_public_key,
        work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        purpose=CONSUME_GRANT_CONSUMER_ROLE)


def _verify_historical_consume_on_work(*, custody_bytes, root_public_key, work,
        live_window, transport_deadline_ns, _continuity=None):
    """Verify original v2 planning scope as data under a real current allowance."""
    try:
        original, root = custody_bytes, root_public_key
        if type(original) is not bytes or not 2 <= len(original) <= MAX_BYTES:
            _fail("historical consume planning custody requires bounded immutable bytes")
        authorization._public(root)
        window = clock._validate(live_window)
        shape._integer(transport_deadline_ns, minimum=1)
        bound = min(window[4], transport_deadline_ns)
        current = planner_bootstrap._processing(window, bound, work, _continuity=_continuity)
        current()
        envelope = _decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "historical consume planning custody")
        shape._literal(envelope["schema"], CONSUME_SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("historical planning custody payload is not an exact object")
        _canonical(original, envelope, work)
        unsigned = _wire(envelope["payload"], work)
        current()
        capability._signature(root, envelope["signatureBase64Url"], CONSUME_SCHEMA,
            unsigned, capture._SharedLedger(work))
        current()
        payload = envelope["payload"]
        _payload_for_purpose(payload, purpose=CONSUME_CONSUMER_ROLE)
        if payload["issuedAtEpochNs"] > current():
            _fail("historical planning custody is future-issued")
        planner = _admit_planner(payload, root, window, bound, work, current, _continuity=_continuity)
        request = _admit_consume_request(payload, work, current)
        opening = clock._sample_on_work(work)
        if _continuity is not None:
            current((opening[1], opening[2]))
        else:
            current()
        result = _HistoricalPlanningMaterial(original, planner, CONSUME_CONSUMER_ROLE,
            CONSUME_PROCESS_MODE, CONSUME_SERVICE_UID, CONSUME_SERVICE_GID,
            payload["receiverIdentity"], payload["bundleKeyDigest"], payload["deliveryKeyDigest"],
            (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]), opening, request)
        _canonical(original, envelope, work)
        current()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationHistoryCustodyBootstrapError):
            raise
        raise OidcSessionActivationHistoryCustodyBootstrapError("historical planning custody admission failed") from exc


def _verify_consume_completion_on_work(*, custody_bytes, root_public_key, work,
        live_window, transport_deadline_ns, _continuity=None):
    return _verify_fixed_purpose(custody_bytes=custody_bytes, root_public_key=root_public_key,
        work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        purpose=CONSUME_COMPLETION_CONSUMER_ROLE, _continuity=_continuity)


def _produce_consume_completion_on_work(*, payload, root_private_key, root_public_key, work,
        live_window, transport_deadline_ns):
    return _produce_fixed_purpose(payload=payload, root_private_key=root_private_key,
        root_public_key=root_public_key, work=work, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, purpose=CONSUME_COMPLETION_CONSUMER_ROLE)


def _produce_on_work(*, payload, root_private_key, root_public_key, work,
        live_window, transport_deadline_ns):
    return _produce_for_purpose(payload=payload, root_private_key=root_private_key,
        root_public_key=root_public_key, work=work, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, consume=False)


def _produce_consume_on_work(*, payload, root_private_key, root_public_key, work,
        live_window, transport_deadline_ns, _continuity=None):
    return _produce_for_purpose(payload=payload, root_private_key=root_private_key,
        root_public_key=root_public_key, work=work, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, consume=True, _continuity=_continuity)


def _produce_consume_grant_on_work(*, payload, root_private_key, root_public_key, work,
        live_window, transport_deadline_ns):
    return _produce_fixed_purpose(payload=payload, root_private_key=root_private_key,
        root_public_key=root_public_key, work=work, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, purpose=CONSUME_GRANT_CONSUMER_ROLE)


def _verify_consume_reserve_on_work(*, custody_bytes, root_public_key, work, live_window,
        transport_deadline_ns):
    """Fixed request-bound reserve v4 originals, never a grant-purpose fallback."""
    return _verify_fixed_purpose(custody_bytes=custody_bytes, root_public_key=root_public_key,
        work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        purpose=CONSUME_RESERVE_CONSUMER_ROLE)


def _produce_consume_reserve_on_work(*, payload, root_private_key, root_public_key, work,
        live_window, transport_deadline_ns):
    return _produce_fixed_purpose(payload=payload, root_private_key=root_private_key,
        root_public_key=root_public_key, work=work, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, purpose=CONSUME_RESERVE_CONSUMER_ROLE)


def _verify_consume_sql_issuer_on_work(*, custody_bytes, root_public_key, work, live_window,
        transport_deadline_ns):
    """Fixed request-bound SQL-issuer v5 originals, not permission to execute SQL."""
    return _verify_fixed_purpose(custody_bytes=custody_bytes, root_public_key=root_public_key,
        work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns,
        purpose=CONSUME_SQL_ISSUER_CONSUMER_ROLE)


def _produce_consume_sql_issuer_on_work(*, payload, root_private_key, root_public_key, work,
        live_window, transport_deadline_ns):
    return _produce_fixed_purpose(payload=payload, root_private_key=root_private_key,
        root_public_key=root_public_key, work=work, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, purpose=CONSUME_SQL_ISSUER_CONSUMER_ROLE)
