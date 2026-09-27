"""Canonical token-free outcome records, not proof or storage admission.

The exact record retains commitments and target metadata only. Shape, slot and
digest checks authenticate nothing: a caller must independently admit original
intent/proof/storage authority and perform actual protected durable retention.
No key, clock, file, token, ciphertext, signature or successful proof is used.
"""
from __future__ import annotations

from serverware import oidc_session_activation_release_proof as proof


authorization, shape, plan = proof.authorization, proof.shape, proof.plan
capture, authority, capability = proof.capture, proof.authority, proof.capability
bootstrap, delivery = proof.bootstrap, proof.delivery
registration = delivery.registration
SCHEMA = "serverware.oidcSessionActivationReleaseOutcome/v1"
IDENTITY_DOMAIN = "serverware.oidcSessionActivationReleaseOutcomeIdentity/v1"
SLOT_DOMAIN = "serverware.oidcSessionActivationReleaseOutcomeSlotIdentity/v1"
MAX_BYTES = 64 * 1024
MAX_NODES, MAX_DEPTH = 512, 6
RECORD_FIELDS = frozenset({"schema", "sourceRevision", "slotDigest", "scope",
    "releaseBinding", "evidenceBinding", "callerId"})
SCOPE_FIELDS, RELEASE_FIELDS = proof.SCOPE_FIELDS, proof.RELEASE_FIELDS
CONSUME_BINDING_FIELDS = proof.CONSUME_BINDING_FIELDS
EVIDENCE_FIELDS = frozenset({"releaseCustodyDigest", "releaseIntentDigest", "stateReceiptDigest",
    "releaseProofDigest", "proofEnrollmentDigest", "intentEnrollmentDigest"})


class OidcSessionActivationReleaseOutcomeError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationReleaseOutcomeError(message)


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("release outcome exceeds its fixed structural bound")
        owned = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("release outcome exceeds its fixed node bound")
        return owned


def _capture(value, work):
    return _Capture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(value)


def _closed(value, fields, label):
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(name) is not str or name not in fields for name in value)):
        _fail(label + " is not a closed exact object")


def _scalars(value, limits, label):
    """Own immutable scalar references without coercion or native callbacks."""
    _closed(value, frozenset(limits), label)
    owned = {}
    for name, maximum in limits.items():
        item = value[name]
        if type(item) is not str or not 1 <= len(item) <= maximum:
            _fail(label + " contains an invalid bounded scalar")
        owned[name] = item
    return owned


def _graphs(scope, release, evidence_values, caller):
    # Detach all input graphs before the first encoding/hash callback. Exact
    # dict/string checks never call arbitrary mapping or scalar conversions.
    _closed(scope, SCOPE_FIELDS, "release outcome scope")
    _closed(release, RELEASE_FIELDS, "release outcome release binding")
    if type(caller) is not str or not 1 <= len(caller) <= 128:
        _fail("release outcome caller is not bounded exact text")
    scalar_scope = {name: scope[name] for name in SCOPE_FIELDS
        if name not in ("producerIdentity", "receiverIdentity")}
    owned_scope = _scalars(scalar_scope,
        {name: (128 if name in ("databaseId", "producerId") else 71) for name in scalar_scope},
        "release outcome scope scalars")
    for name in ("producerIdentity", "receiverIdentity"):
        owned_scope[name] = _scalars(scope[name],
            {field: 71 for field in bootstrap.planner_bootstrap._IDENTITY_FIELDS},
            "release outcome " + name)
    scalar_release = {name: release[name] for name in RELEASE_FIELDS
        if name not in ("deliveryScope", "consumeBinding")}
    owned_release = _scalars(scalar_release, {name: 71 for name in scalar_release},
        "release outcome release scalars")
    owned_release["deliveryScope"] = _scalars(release["deliveryScope"], delivery._SCOPE_LIMITS,
        "release outcome delivery scope")
    owned_release["consumeBinding"] = _scalars(release["consumeBinding"],
        {name: 71 for name in CONSUME_BINDING_FIELDS}, "release outcome consume binding")
    owned_evidence = _scalars(evidence_values, {name: 71 for name in EVIDENCE_FIELDS},
        "release outcome evidence binding")
    return owned_scope, owned_release, owned_evidence, caller


def _slot_digest_on_work(*, database_id, generation_digest, delivery_id, work):
    """A stable metadata slot only; no caller/intent/source/configuration salt."""
    capture._SharedLedger(work)
    database, generation, target = database_id, generation_digest, delivery_id
    authorization._token(database)
    shape._digest(generation)
    authorization._token(target)
    return plan._frame(SLOT_DOMAIN,
        (plan._ascii(database, work), plan._ascii(generation, work), plan._ascii(target, work)), work)


def _bindings_on_work(record, work):
    """Check closed data and return its recomputed slot, never proof facts."""
    shape._object(record, RECORD_FIELDS, "activation release outcome")
    shape._literal(record["schema"], SCHEMA)
    shape._literal(record["sourceRevision"], authority.SOURCE_REVISION)
    shape._digest(record["slotDigest"])
    authorization._token(record["callerId"])
    scope, release, evidence_values = record["scope"], record["releaseBinding"], record["evidenceBinding"]
    proof.enrollments._scope_shape(scope)
    shape._object(release, RELEASE_FIELDS, "release outcome release binding")
    for name in RELEASE_FIELDS - {"deliveryScope", "consumeBinding"}:
        shape._digest(release[name])
    shape._object(release["consumeBinding"], CONSUME_BINDING_FIELDS, "release outcome consume binding")
    for name in CONSUME_BINDING_FIELDS:
        shape._digest(release["consumeBinding"][name])
    shape._object(evidence_values, EVIDENCE_FIELDS, "release outcome evidence binding")
    for name in EVIDENCE_FIELDS:
        shape._digest(evidence_values[name])
    # Canonical UTC/positive original delivery lifetime is algebraic data
    # validation here, never a sample or an assertion of current freshness.
    bootstrap._scope(release["deliveryScope"], work)
    activation_operation = plan._frame("serverware.policyAuthorityOperation/v2",
        (plan._ascii(bootstrap.ACTIVATION_OPERATION, work),
         plan._ascii(release["activationRequestDigest"], work)), work)
    plan._same(activation_operation, release["activationOperationId"], work,
        "release outcome deterministic activation operation")
    delivery_id = registration.core._deterministic_uuid(operation=bootstrap.ACTIVATION_OPERATION,
        request_digest=release["activationRequestDigest"], purpose="activation-delivery", work=work)
    plan._same(delivery_id, release["deliveryScope"]["deliveryId"], work,
        "release outcome deterministic delivery identity")
    return _slot_digest_on_work(database_id=scope["databaseId"], generation_digest=scope["generationDigest"],
        delivery_id=delivery_id, work=work)


def _encode_on_work(*, scope, release_binding, evidence_binding, caller_id, work):
    """Encode ordinary bindings; this neither admits nor stores an outcome."""
    capture._SharedLedger(work)
    owned_scope, release, evidence_values, caller = _graphs(scope, release_binding, evidence_binding, caller_id)
    record = _capture({"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "slotDigest": "sha256:" + "0" * 64, "scope": owned_scope, "releaseBinding": release,
        "evidenceBinding": evidence_values, "callerId": caller}, work)
    record["slotDigest"] = _bindings_on_work(record, work)
    return capability._wire(record, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)


def _decode_on_work(original_bytes, work):
    """Return owned canonical record data, not authenticated durable state."""
    capture._SharedLedger(work)
    original = authorization._original(original_bytes, MAX_BYTES, "release outcome original")
    decoded = capability.wire._decode_object(original, work=work, maximum_bytes=MAX_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    record = _capture(decoded, work)
    slot = _bindings_on_work(record, work)
    plan._same(record["slotDigest"], slot, work, "release outcome original slot")
    capability._canonical(original, record, capture._SharedLedger(work), MAX_BYTES, MAX_NODES)
    return record


def _digest_on_work(original_bytes, work):
    """Identity of one exact canonical record, never admission or receipt."""
    original = authorization._original(original_bytes, MAX_BYTES, "release outcome original")
    _decode_on_work(original, work)
    return plan._frame(IDENTITY_DOMAIN, (original,), work)
