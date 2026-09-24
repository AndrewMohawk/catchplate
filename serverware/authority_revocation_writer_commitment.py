"""Private signed commitments to detached original writer bodies.

Verifier intent and planner relay retain the eleven-field internal/v3 envelope.
The four-MiB controls never embed the original plan, context or fourteen-field
history. Local byte/node/depth ceilings do not promise that maximum-sized bodies
fit the unchanged cumulative work budget after all repeated checks.

Signatures authenticate role claims, not caller provenance, truthful clocks,
current roots, measured-configuration admission or successful plan proofs.
Historical policy must still match the same owned measured payload at the real
writer action; both stores still genuinely replay. No API accepts the ordinary
observations below as an authorization token. There is no clock, SQL, transport,
registry activation, durable retry custody or acknowledgment implementation.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_contract as authority
from serverware import authority_revocation_capability as capability
from serverware import authority_revocation_capability_production as production
from serverware import authority_revocation_retention as retention
from serverware import authority_revocation_writer_action as action
from serverware.authority_query_read_work import QueryReadValidationMetrics, QueryReadWorkError


plan, wire, capture = retention.plan, retention.wire, retention.capture
ENVELOPE_SCHEMA = authority.INTERNAL_ENVELOPE_SCHEMA
INTENT_SCHEMA = "serverware.policyAuthorityRevocationWriterIntent/v1"
RELAY_SCHEMA = "serverware.policyAuthorityRevocationWriterRelay/v1"
INTENT_PURPOSE = "authorize-revocation-writer-custody"
RELAY_PURPOSE = "relay-revocation-writer-custody"
INTENT_ID_DOMAIN = "serverware.policyAuthorityRevocationWriterIntentEnvelope/v1"
RELAY_ID_DOMAIN = "serverware.policyAuthorityRevocationWriterRelayEnvelope/v1"
MAX_CONTROL_BYTES = authority.MAX_REQUEST_BYTES
MAX_CONTROL_NODES = 4096
MAX_CONTROL_DEPTH = 2
MAX_HISTORY_BYTES = capture.MAX_TOTAL_INPUT_BYTES
MAX_HISTORY_NODES = capture.MAX_TOTAL_JSON_NODES
MAX_HISTORY_DEPTH = capture.MAX_JSON_DEPTH
ENVELOPE_FIELDS = frozenset({"schema", "envelopeId", "parentEnvelopeId", "purpose",
    "configurationDigest", "issuedAtEpochNs", "issuedMonotonicNs", "deadlineMonotonicNs",
    "fence", "payload", "signature"})
INTENT_FIELDS = frozenset({"schema", "sourceRevision", "generationSequence", "generationDigest",
    "capabilityId", "plannerTransactionId", "executionEnvelopeId", "plannedAtEpochNs", "databaseCutoffUs",
    "planEnvelopeDigest", "planEnvelopeByteCount", "evaluationContextDigest", "evaluationContextByteCount",
    "historicalExpectationsDigest", "historicalExpectationsByteCount"})
RELAY_FIELDS = frozenset({"schema", "sourceRevision", "generationSequence", "generationDigest",
    "verifierIntentDigest", "verifierIntentByteCount"})
HISTORY_FIELDS = action._EXTERNAL_FIELDS - {"database_now"}
_PHASES = ("capture", "transport", "key_binding", "authentication", "bindings", "signing")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_FAILURES = (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature)


class RevocationWriterCommitmentError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CommitmentMetrics:
    capture: QueryReadValidationMetrics
    transport: QueryReadValidationMetrics
    key_binding: QueryReadValidationMetrics
    authentication: QueryReadValidationMetrics
    bindings: QueryReadValidationMetrics
    signing: QueryReadValidationMetrics
    signing_attempts: int
    signature_verifications: int
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class _ProducedIntent:
    intent_bytes: bytes
    historical_expectations_bytes: bytes
    metrics: CommitmentMetrics


@dataclass(frozen=True, slots=True)
class _ProducedRelay:
    relay_bytes: bytes
    metrics: CommitmentMetrics
    freshness_pins: tuple


@dataclass(frozen=True, slots=True)
class _AuthenticatedCommitments:
    """Owned claims and original bytes, never an accepted successful token."""

    intent_envelope: dict
    relay_envelope: dict
    intent_bytes: bytes
    relay_bytes: bytes
    envelope_bytes: bytes
    evaluation_context_bytes: bytes
    historical_expectations_bytes: bytes
    arguments: dict
    expectations: dict
    metrics: CommitmentMetrics


def _phases():
    return {name: QueryReadValidationMetrics(0, 0, 0) for name in _PHASES}


def _metrics(phases, signing, verified, work):
    return CommitmentMetrics(*(phases[name] for name in _PHASES), signing, verified,
        work.hash_work, work.input_bytes, work.json_nodes)


def _raw(raw, maximum):
    if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
        raise RevocationWriterCommitmentError("writer commitment requires bounded original immutable bytes")


def _body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes):
    _raw(envelope_bytes, plan.contract.MAX_PAYLOAD_BYTES)
    _raw(evaluation_context_bytes, retention.MAX_CONTEXT_BYTES)
    _raw(historical_expectations_bytes, MAX_HISTORY_BYTES)


def _pins(configuration, sequence, generation):
    plan.contract._digest(configuration)
    plan.contract._integer(sequence, minimum=1)
    plan.contract._digest(generation)


def _current(now_epoch, now_monotonic, age, skew):
    for value in (now_epoch, now_monotonic, age):
        plan.contract._integer(value, minimum=1)
    plan.contract._integer(skew)
    if skew != authority.VERIFIER_MAX_CLOCK_SKEW_NS:
        raise RevocationWriterCommitmentError("writer commitment skew differs from its source policy")


def _public_keys(planner_key, verifier_key):
    if any(not isinstance(key, Ed25519PublicKey) for key in (planner_key, verifier_key)):
        raise RevocationWriterCommitmentError("writer commitment requires independently pinned Ed25519 public keys")


def _distinct_public_keys(planner_key, verifier_key, work):
    work.charge(input_bytes=2 * 32 + 2 * 32)
    planner = production._callback(work, lambda: planner_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    verifier = production._callback(work, lambda: verifier_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    if (any(type(raw) is not bytes or len(raw) != 32 for raw in (planner, verifier))
            or planner == verifier):
        raise RevocationWriterCommitmentError("writer commitment verifier and planner keys are not distinct raw32")


def _signed_cutoff(cutoff):
    # Unlike issuance history, the actual plan cutoff is a SIGNED int64.
    if type(cutoff) is not int or not -(2**63) <= cutoff < 2**63:
        raise RevocationWriterCommitmentError("writer commitment cutoff is not an exact signed int64")


def _utc(cutoff):
    _signed_cutoff(cutoff)
    instant = _EPOCH + timedelta(microseconds=cutoff)
    if plan.semantics.complete.cutoff_microseconds(instant) != cutoff:
        raise RevocationWriterCommitmentError("writer commitment cutoff does not round-trip through exact UTC")
    return instant


def _intent_id(execution_id, planner_id, work):
    return plan._frame(INTENT_ID_DOMAIN,
        (plan._ascii(execution_id, work), plan._ascii(planner_id, work)), work)


def _relay_id(intent_id, work):
    return plan._frame(RELAY_ID_DOMAIN, (plan._ascii(intent_id, work),), work)


def _shape(envelope, *, relay):
    shape = plan.contract
    shape._object(envelope, ENVELOPE_FIELDS, "writer commitment envelope")
    shape._literal(envelope["schema"], ENVELOPE_SCHEMA)
    shape._literal(envelope["purpose"], RELAY_PURPOSE if relay else INTENT_PURPOSE)
    for name in ("envelopeId", "parentEnvelopeId", "configurationDigest"):
        shape._digest(envelope[name])
    for name in ("issuedAtEpochNs", "issuedMonotonicNs", "deadlineMonotonicNs", "fence"):
        shape._integer(envelope[name], minimum=1)
    if envelope["issuedMonotonicNs"] >= envelope["deadlineMonotonicNs"]:
        raise RevocationWriterCommitmentError("writer commitment issuance does not precede its deadline")
    shape._base64url(envelope["signature"], signature=True)
    payload = envelope["payload"]
    shape._object(payload, RELAY_FIELDS if relay else INTENT_FIELDS, "writer commitment payload")
    shape._literal(payload["schema"], RELAY_SCHEMA if relay else INTENT_SCHEMA)
    shape._literal(payload["sourceRevision"], authority.SOURCE_REVISION)
    shape._integer(payload["generationSequence"], minimum=1)
    shape._digest(payload["generationDigest"])
    if relay:
        shape._digest(payload["verifierIntentDigest"])
        shape._integer(payload["verifierIntentByteCount"], MAX_CONTROL_BYTES, minimum=2)
    else:
        for name in ("capabilityId", "plannerTransactionId", "executionEnvelopeId",
                     "planEnvelopeDigest", "evaluationContextDigest", "historicalExpectationsDigest"):
            shape._digest(payload[name])
        shape._integer(payload["plannedAtEpochNs"], minimum=1)
        # Only shape is used before authentication. Exact UTC construction and
        # representability are checked by _bind_intent after the real signature.
        _signed_cutoff(payload["databaseCutoffUs"])
        for name, maximum in (("planEnvelopeByteCount", shape.MAX_PAYLOAD_BYTES),
                              ("evaluationContextByteCount", retention.MAX_CONTEXT_BYTES),
                              ("historicalExpectationsByteCount", MAX_HISTORY_BYTES)):
            shape._integer(payload[name], maximum, minimum=2)


def _read_control(raw, ledger, *, relay):
    value = wire._decode_object(raw, work=ledger.work, maximum_bytes=MAX_CONTROL_BYTES,
        maximum_nodes=MAX_CONTROL_NODES, maximum_depth=MAX_CONTROL_DEPTH)
    _shape(value, relay=relay)
    capability._canonical(raw, value, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    ledger.work.prepare_copy(value)
    unsigned = value.copy()
    signature = unsigned.pop("signature")
    unsigned_wire = capability._wire(unsigned, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    return value, signature, unsigned_wire


def _bind_configuration(envelope, configuration, sequence, generation, work):
    payload = envelope["payload"]
    plan._same((envelope["configurationDigest"], payload["generationSequence"], payload["generationDigest"]),
        (configuration, sequence, generation), work, "writer commitment differs from independent configuration or generation")


def _fresh(envelope, history, now_epoch, now_monotonic, age, skew):
    remaining_mono = envelope["deadlineMonotonicNs"] - now_monotonic
    remaining_epoch = history["deadline_epoch_ns"] - now_epoch
    if (envelope["issuedMonotonicNs"] > now_monotonic
            or now_monotonic - envelope["issuedMonotonicNs"] > age
            or envelope["issuedAtEpochNs"] > now_epoch + skew
            or now_epoch - envelope["issuedAtEpochNs"] > age
            or remaining_mono <= 0 or remaining_epoch <= 0
            or remaining_mono > age or remaining_epoch > age + skew
            or abs(remaining_epoch - remaining_mono) > skew):
        raise RevocationWriterCommitmentError("writer commitment current clocks or deadlines are not fresh and consistent")


def _check_freshness_pins(pins, *, now_epoch_ns, now_monotonic_ns,
        maximum_age_ns, maximum_clock_skew_ns):
    """Recheck held authenticated times; these scalars are not proof inputs.

    Callers capture the fixed tuple before later callbacks. A caller checking
    only an intent duplicates its issuance pair in the second pair of slots;
    that does not invent a relay or authenticate one. No historical value is
    replaced with the new current clocks and no work allowance is allocated.
    """
    if type(pins) is not tuple or len(pins) != 6:
        raise RevocationWriterCommitmentError("writer commitment freshness pins are not a fixed six-tuple")
    for value in pins:
        plan.contract._integer(value, minimum=1)
    _current(now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)
    intent_epoch, intent_mono, relay_epoch, relay_mono, deadline_epoch, deadline_mono = pins
    if intent_mono >= deadline_mono or relay_mono >= deadline_mono:
        raise RevocationWriterCommitmentError("writer commitment issuance does not precede its held deadline")
    for epoch, monotonic in ((intent_epoch, intent_mono), (relay_epoch, relay_mono)):
        _fresh({"issuedAtEpochNs": epoch, "issuedMonotonicNs": monotonic,
                "deadlineMonotonicNs": deadline_mono},
            {"deadline_epoch_ns": deadline_epoch}, now_epoch_ns, now_monotonic_ns,
            maximum_age_ns, maximum_clock_skew_ns)


def _bind_intent(intent, envelope_bytes, evaluation_context_bytes, historical_expectations_bytes,
                 configuration, sequence, generation, now_epoch, now_monotonic, age, skew, ledger):
    work, payload = ledger.work, intent["payload"]
    _bind_configuration(intent, configuration, sequence, generation, work)
    for raw, digest_name, count_name in (
            (envelope_bytes, "planEnvelopeDigest", "planEnvelopeByteCount"),
            (evaluation_context_bytes, "evaluationContextDigest", "evaluationContextByteCount"),
            (historical_expectations_bytes, "historicalExpectationsDigest", "historicalExpectationsByteCount")):
        plan._same((retention._bytes_digest(raw, work), len(raw)),
            (payload[digest_name], payload[count_name]), work, "writer commitment detached original body changed")
    history = wire._decode_object(historical_expectations_bytes, work=work,
        maximum_bytes=MAX_HISTORY_BYTES, maximum_nodes=MAX_HISTORY_NODES, maximum_depth=MAX_HISTORY_DEPTH)
    plan.contract._object(history, HISTORY_FIELDS, "writer commitment detached history")
    capability._canonical(historical_expectations_bytes, history, ledger, MAX_HISTORY_BYTES, MAX_HISTORY_NODES)
    arguments, owned = action._capture_action_inputs(envelope_bytes=envelope_bytes,
        evaluation_context_bytes=evaluation_context_bytes, planned_at_epoch_ns=payload["plannedAtEpochNs"],
        envelope_id=payload["executionEnvelopeId"], planner_transaction_id=payload["plannerTransactionId"],
        work=work, database_now=_utc(payload["databaseCutoffUs"]), **history)
    expected_id = _intent_id(arguments["envelope_id"], arguments["planner_transaction_id"], work)
    plan._same((intent["envelopeId"], intent["parentEnvelopeId"], intent["fence"], intent["deadlineMonotonicNs"],
                payload["capabilityId"], payload["plannerTransactionId"]),
        (expected_id, owned["expected_planner_transaction_id"], owned["expected_fence"],
         owned["deadline_monotonic_ns"], owned["expected_capability_id"], owned["expected_planner_transaction_id"]),
        work, "writer intent header differs from its detached historical bindings")
    if not owned["reserved_at_epoch_ns"] <= arguments["planned_at_epoch_ns"] < owned["deadline_epoch_ns"]:
        raise RevocationWriterCommitmentError("writer commitment planned timestamp is outside its original reservation")
    _fresh(intent, owned, now_epoch, now_monotonic, age, skew)
    return arguments, owned


def _sign_wire(unsigned, private_key, public_key, work, *, relay):
    """Reserve complete output before signing; re-encode after the callback."""
    envelope = {**unsigned, "signature": "A" * 86}
    _shape(envelope, relay=relay)
    unsigned_size, unsigned_nodes = work.measure(unsigned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_CONTROL_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_CONTROL_NODES):
        raise RevocationWriterCommitmentError("writer commitment output exceeds its full control bound")
    work.charge(input_bytes=4 * unsigned_size + envelope_size + production._SIGNATURE_TRANSPORT_BYTES,
                json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(ENVELOPE_SCHEMA) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise QueryReadWorkError("writer commitment cannot reserve its complete signed output")
    original = plan.core.canonical_bytes(unsigned)
    if len(original) != unsigned_size:
        raise RevocationWriterCommitmentError("writer commitment unsigned graph changed after measurement")
    message = plan._ascii(plan._frame(ENVELOPE_SCHEMA, (original,), work), work)
    signature = production._sign_and_verify(private_key, public_key, message, work)
    if work.measure(unsigned) != (unsigned_size, unsigned_nodes):
        raise RevocationWriterCommitmentError("writer commitment unsigned graph changed during signing")
    if plan.core.canonical_bytes(unsigned) != original:
        raise RevocationWriterCommitmentError("writer commitment unsigned graph changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    plan.contract._base64url(encoded, signature=True)
    result = plan.core.canonical_bytes({**unsigned, "signature": encoded})
    if len(result) != envelope_size:
        raise RevocationWriterCommitmentError("writer commitment final envelope changed after measurement")
    return result


def _unsigned(payload, *, identity, parent, relay, configuration, epoch, monotonic, deadline, fence):
    return {"schema": ENVELOPE_SCHEMA, "envelopeId": identity, "parentEnvelopeId": parent,
        "purpose": RELAY_PURPOSE if relay else INTENT_PURPOSE, "configurationDigest": configuration,
        "issuedAtEpochNs": epoch, "issuedMonotonicNs": monotonic,
        "deadlineMonotonicNs": deadline, "fence": fence, "payload": payload}


def _produce_intent_on_work(*, envelope_bytes, evaluation_context_bytes, planned_at_epoch_ns,
        envelope_id, planner_transaction_id, verifier_private_key, verifier_public_key,
        planner_public_key, configuration_digest, generation_sequence, generation_digest,
        issued_at_epoch_ns, issued_monotonic_ns, work, **expectations):
    """Sign owned verifier claims, without accepting a prior handoff as proof.

    The actual verifier must establish independent provenance and genuinely
    check the original plan before invoking this separate signing boundary.
    Private/public pairing and distinct planner/verifier keys cost the actual
    existing 224B primitive. Detached history has exactly fourteen root fields;
    UTC lives only in the fixed signed control payload, not a deeper wrapper.
    """
    try:
        ledger, phases = capture._SharedLedger(work), _phases()
        _public_keys(planner_public_key, verifier_public_key)
        if not isinstance(verifier_private_key, Ed25519PrivateKey):
            raise RevocationWriterCommitmentError("writer intent requires a verifier Ed25519 private key")
        _pins(configuration_digest, generation_sequence, generation_digest)
        for value in (issued_at_epoch_ns, issued_monotonic_ns):
            plan.contract._integer(value, minimum=1)
        before = work.metrics
        arguments, owned = action._capture_action_inputs(envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes, planned_at_epoch_ns=planned_at_epoch_ns,
            envelope_id=envelope_id, planner_transaction_id=planner_transaction_id, work=work, **expectations)
        if not owned["reserved_at_epoch_ns"] <= planned_at_epoch_ns < owned["deadline_epoch_ns"]:
            raise RevocationWriterCommitmentError("writer intent planned timestamp is outside its original reservation")
        phases["capture"] = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        history = {name: value for name, value in owned.items() if name != "database_now"}
        historical_bytes = capability._wire(history, ledger, MAX_HISTORY_BYTES, MAX_HISTORY_NODES)
        phases["transport"] = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        # The existing primitive's 'witness' parameter is deliberately the
        # independently pinned other role here; the checks are raw key pairing
        # and inequality only, not witness/plan admission.
        production._key_binding(verifier_private_key, verifier_public_key, planner_public_key, work)
        phases["key_binding"] = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        cutoff = plan.semantics.complete.cutoff_microseconds(owned["database_now"])
        payload = {"schema": INTENT_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "generationSequence": generation_sequence, "generationDigest": generation_digest,
            "capabilityId": owned["expected_capability_id"], "plannerTransactionId": planner_transaction_id,
            "executionEnvelopeId": envelope_id, "plannedAtEpochNs": planned_at_epoch_ns,
            "databaseCutoffUs": cutoff,
            "planEnvelopeDigest": retention._bytes_digest(envelope_bytes, work),
            "planEnvelopeByteCount": len(envelope_bytes),
            "evaluationContextDigest": retention._bytes_digest(evaluation_context_bytes, work),
            "evaluationContextByteCount": len(evaluation_context_bytes),
            "historicalExpectationsDigest": retention._bytes_digest(historical_bytes, work),
            "historicalExpectationsByteCount": len(historical_bytes)}
        unsigned = _unsigned(payload, identity=_intent_id(envelope_id, planner_transaction_id, work),
            parent=planner_transaction_id, relay=False, configuration=configuration_digest,
            epoch=issued_at_epoch_ns, monotonic=issued_monotonic_ns,
            deadline=owned["deadline_monotonic_ns"], fence=owned["expected_fence"])
        phases["bindings"] = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        raw = _sign_wire(unsigned, verifier_private_key, verifier_public_key, work, relay=False)
        phases["signing"] = plan.mixed._delta(before, work.metrics)
        return _ProducedIntent(raw, historical_bytes, _metrics(phases, 1, 1, work))
    except _FAILURES as exc:
        if isinstance(exc, RevocationWriterCommitmentError):
            raise
        raise RevocationWriterCommitmentError("writer intent production failed") from exc


def _produce_relay_on_work(*, intent_bytes, envelope_bytes, evaluation_context_bytes,
        historical_expectations_bytes, planner_private_key, planner_public_key, verifier_public_key,
        expected_configuration_digest, expected_generation_sequence, expected_generation_digest,
        now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns, work):
    """Authenticate original verifier intent and bodies before planner signing.

    Freshness uses independent current clocks and measured writer age. It does
    not overwrite historical clocks or refresh the original intent. This is
    actual signature/body authentication, not a semantic replay or DB result.
    """
    try:
        ledger, phases = capture._SharedLedger(work), _phases()
        _raw(intent_bytes, MAX_CONTROL_BYTES)
        _body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)
        _pins(expected_configuration_digest, expected_generation_sequence, expected_generation_digest)
        _current(now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)
        _public_keys(planner_public_key, verifier_public_key)
        if not isinstance(planner_private_key, Ed25519PrivateKey):
            raise RevocationWriterCommitmentError("writer relay requires a planner Ed25519 private key")
        before = work.metrics
        intent, signature, unsigned_wire = _read_control(intent_bytes, ledger, relay=False)
        phases["transport"] = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        production._key_binding(planner_private_key, planner_public_key, verifier_public_key, work)
        phases["key_binding"] = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        capability._signature(verifier_public_key, signature, ENVELOPE_SCHEMA, unsigned_wire, ledger)
        phases["authentication"] = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        _, history = _bind_intent(intent, envelope_bytes, evaluation_context_bytes, historical_expectations_bytes,
            expected_configuration_digest, expected_generation_sequence, expected_generation_digest,
            now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns, ledger)
        payload = {"schema": RELAY_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
            "generationSequence": expected_generation_sequence, "generationDigest": expected_generation_digest,
            "verifierIntentDigest": retention._bytes_digest(intent_bytes, work),
            "verifierIntentByteCount": len(intent_bytes)}
        unsigned = _unsigned(payload, identity=_relay_id(intent["envelopeId"], work),
            parent=intent["envelopeId"], relay=True, configuration=expected_configuration_digest,
            epoch=now_epoch_ns, monotonic=now_monotonic_ns,
            deadline=history["deadline_monotonic_ns"], fence=history["expected_fence"])
        # Hold actual authenticated intent times and this relay's issuance
        # before signing callbacks. These observations only support a later
        # current-clock recheck; they are never accepted as authentication.
        freshness_pins = (intent["issuedAtEpochNs"], intent["issuedMonotonicNs"],
            now_epoch_ns, now_monotonic_ns, history["deadline_epoch_ns"],
            history["deadline_monotonic_ns"])
        phases["bindings"] = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        raw = _sign_wire(unsigned, planner_private_key, planner_public_key, work, relay=True)
        phases["signing"] = plan.mixed._delta(before, work.metrics)
        return _ProducedRelay(raw, _metrics(phases, 1, 2, work), freshness_pins)
    except _FAILURES as exc:
        if isinstance(exc, RevocationWriterCommitmentError):
            raise
        raise RevocationWriterCommitmentError("writer relay production failed") from exc


def _verify_intent_on_work(*, intent_bytes, envelope_bytes, evaluation_context_bytes,
        historical_expectations_bytes, planner_public_key, verifier_public_key,
        expected_configuration_digest, expected_generation_sequence, expected_generation_digest,
        now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns, work):
    """Authenticate originals before requesting a separate planner relay.

    Return ordinary arguments, owned historical expectations and held times,
    not semantic-plan admission. The absent relay's two freshness slots repeat
    the authenticated intent times. Existing two-control verification remains
    required after a real relay response and before any custody forwarding.
    """
    try:
        ledger = capture._SharedLedger(work)
        _raw(intent_bytes, MAX_CONTROL_BYTES)
        _body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)
        _pins(expected_configuration_digest, expected_generation_sequence, expected_generation_digest)
        _current(now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)
        _public_keys(planner_public_key, verifier_public_key)
        intent, signature, unsigned_wire = _read_control(intent_bytes, ledger, relay=False)
        _distinct_public_keys(planner_public_key, verifier_public_key, work)
        capability._signature(verifier_public_key, signature, ENVELOPE_SCHEMA, unsigned_wire, ledger)
        # Recheck the complete graph after the callback before adopting any
        # header, body commitment or historical value from that graph.
        capability._canonical(intent_bytes, intent, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
        arguments, history = _bind_intent(intent, envelope_bytes, evaluation_context_bytes,
            historical_expectations_bytes, expected_configuration_digest, expected_generation_sequence,
            expected_generation_digest, now_epoch_ns, now_monotonic_ns, maximum_age_ns,
            maximum_clock_skew_ns, ledger)
        pins = (intent["issuedAtEpochNs"], intent["issuedMonotonicNs"],
            intent["issuedAtEpochNs"], intent["issuedMonotonicNs"],
            history["deadline_epoch_ns"], history["deadline_monotonic_ns"])
        return arguments, history, pins
    except _FAILURES as exc:
        if isinstance(exc, RevocationWriterCommitmentError):
            raise
        raise RevocationWriterCommitmentError("writer intent authentication failed") from exc


def _verify_commitments_on_work(*, intent_bytes, relay_bytes, envelope_bytes, evaluation_context_bytes,
        historical_expectations_bytes, planner_public_key, verifier_public_key,
        expected_configuration_digest, expected_generation_sequence, expected_generation_digest,
        now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns, work):
    """Verify both original controls and all detached bodies on existing work.

    Both complete authenticated envelopes survive in the ordinary result.
    Stable purpose-specific IDs are NOT replay protection without durable
    exact-original custody; re-signing a different message under the same ID
    remains a future durable conflict check, not authorization supplied here.
    """
    try:
        ledger, phases = capture._SharedLedger(work), _phases()
        _raw(intent_bytes, MAX_CONTROL_BYTES)
        _raw(relay_bytes, MAX_CONTROL_BYTES)
        _body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)
        _pins(expected_configuration_digest, expected_generation_sequence, expected_generation_digest)
        _current(now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)
        _public_keys(planner_public_key, verifier_public_key)
        before = work.metrics
        relay, relay_signature, relay_unsigned = _read_control(relay_bytes, ledger, relay=True)
        intent, intent_signature, intent_unsigned = _read_control(intent_bytes, ledger, relay=False)
        phases["transport"] = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        _distinct_public_keys(planner_public_key, verifier_public_key, work)
        phases["key_binding"] = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        capability._signature(planner_public_key, relay_signature, ENVELOPE_SCHEMA, relay_unsigned, ledger)
        capability._signature(verifier_public_key, intent_signature, ENVELOPE_SCHEMA, intent_unsigned, ledger)
        phases["authentication"] = plan.mixed._delta(before, work.metrics)
        before = work.metrics
        arguments, history = _bind_intent(intent, envelope_bytes, evaluation_context_bytes,
            historical_expectations_bytes, expected_configuration_digest, expected_generation_sequence,
            expected_generation_digest, now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns, ledger)
        _bind_configuration(relay, expected_configuration_digest, expected_generation_sequence,
            expected_generation_digest, work)
        payload = relay["payload"]
        plan._same((retention._bytes_digest(intent_bytes, work), len(intent_bytes)),
            (payload["verifierIntentDigest"], payload["verifierIntentByteCount"]), work,
            "writer relay does not commit to the original verifier intent")
        plan._same((relay["envelopeId"], relay["parentEnvelopeId"], relay["fence"], relay["deadlineMonotonicNs"]),
            (_relay_id(intent["envelopeId"], work), intent["envelopeId"], history["expected_fence"],
             history["deadline_monotonic_ns"]), work, "writer relay header differs from its original intent")
        _fresh(relay, history, now_epoch_ns, now_monotonic_ns, maximum_age_ns, maximum_clock_skew_ns)
        phases["bindings"] = plan.mixed._delta(before, work.metrics)
        return _AuthenticatedCommitments(intent, relay, intent_bytes, relay_bytes, envelope_bytes,
            evaluation_context_bytes, historical_expectations_bytes, arguments, history,
            _metrics(phases, 0, 2, work))
    except _FAILURES as exc:
        if isinstance(exc, RevocationWriterCommitmentError):
            raise
        raise RevocationWriterCommitmentError("writer commitment authentication failed") from exc
