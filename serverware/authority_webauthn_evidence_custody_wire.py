"""Bounded retain-only intent/relay control mechanics for evidence plans.

The flat controls commit detached originals under separate source-fixed
signature domains. No legacy v3/v4 envelope, execution capability, reservation,
fence or durable receipt is created. Public keys, configuration/generation and
historical expectations require independent admission by the actual caller.
Signatures authenticate these control claims, not successful plan replay.

Decoded controls, commitment dictionaries and timing pairs are ordinary data,
never accepted proof tokens. The owning flow must genuinely verify originals
and bind all expected fields. Local byte ceilings do not grant another work
allowance or promise that maximum-sized inputs fit repeated verification.
There is no SQL, transport, registry activation, signing-key enrollment or retry.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware import authority_webauthn_evidence_plan_retention as retention


evidence, authority = retention.evidence, retention.evidence.authority
INTENT_SCHEMA = "serverware.signedPolicyAuthorityWebAuthnEvidenceCustodyIntent/v1"
RELAY_SCHEMA = "serverware.signedPolicyAuthorityWebAuthnEvidenceCustodyRelay/v1"
INTENT_PURPOSE = "retain-evidence-plan"
RELAY_PURPOSE = "relay-evidence-plan-custody"
MAX_CONTROL_BYTES = authority.MAX_REQUEST_BYTES
MAX_CONTROL_NODES = 4096
MAX_CONTROL_DEPTH = 1
MAX_HISTORY_BYTES = retention.context_wire.MAX_BYTES
_COMMON_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "configurationDigest",
    "generationSequence", "generationDigest", "operation", "retainedRecordDigest",
    "issuedAtEpochNs", "expiresAtEpochNs"})
_BODY_FIELDS = frozenset({"envelopeBytesDigest", "envelopeByteCount", "inputsBytesDigest",
    "inputsByteCount", "contextBytesDigest", "contextByteCount", "historyBytesDigest", "historyByteCount"})
INTENT_FIELDS = _COMMON_FIELDS | _BODY_FIELDS | {"signatureBase64Url"}
RELAY_FIELDS = _COMMON_FIELDS | {"intentBytesDigest", "intentByteCount", "signatureBase64Url"}
_TIME_FIELDS = frozenset({"issuedAtEpochNs", "expiresAtEpochNs"})
_BODY_LIMITS = (retention.plan.contract.MAX_BYTES, retention.plan.inputs_wire.MAX_BYTES,
    retention.context_wire.MAX_BYTES, MAX_HISTORY_BYTES)
_BODY_NAMES = ("envelope", "inputs", "context", "history")


class WebAuthnEvidenceCustodyWireError(ValueError):
    pass


def _schema(relay):
    if type(relay) is not bool:
        raise WebAuthnEvidenceCustodyWireError("evidence custody control kind is not exact")
    return RELAY_SCHEMA if relay else INTENT_SCHEMA


def _pins(configuration_digest, generation_sequence, generation_digest, operation):
    shape = evidence.plan.contract
    shape._digest(configuration_digest)
    shape._integer(generation_sequence, minimum=1)
    shape._digest(generation_digest)
    if type(operation) is not str or operation not in retention.plan.contract.OPERATIONS:
        raise WebAuthnEvidenceCustodyWireError("evidence custody operation is not source fixed")
    return configuration_digest, generation_sequence, generation_digest, operation


def _shape(value, *, relay, signed=True):
    schema = _schema(relay)
    shape = evidence.plan.contract
    fields = RELAY_FIELDS if relay else INTENT_FIELDS
    shape._object(value, fields if signed else fields - {"signatureBase64Url"}, "evidence custody control")
    shape._literal(value["schema"], schema)
    shape._literal(value["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(value["purpose"], RELAY_PURPOSE if relay else INTENT_PURPOSE)
    _pins(value["configurationDigest"], value["generationSequence"], value["generationDigest"], value["operation"])
    shape._digest(value["retainedRecordDigest"])
    for name in _TIME_FIELDS:
        shape._integer(value[name], minimum=1)
    if value["issuedAtEpochNs"] >= value["expiresAtEpochNs"]:
        raise WebAuthnEvidenceCustodyWireError("evidence custody issuance does not precede expiry")
    if relay:
        shape._digest(value["intentBytesDigest"])
        shape._integer(value["intentByteCount"], MAX_CONTROL_BYTES, minimum=2)
    else:
        for name, maximum in zip(_BODY_NAMES, _BODY_LIMITS):
            shape._digest(value[name + "BytesDigest"])
            shape._integer(value[name + "ByteCount"], maximum, minimum=2)
    if signed:
        shape._base64url(value["signatureBase64Url"], signature=True)


def _control(value):
    """Close a full signed or unsigned flat control without authenticating it."""
    if type(value) is not dict or type(value.get("schema")) is not str:
        raise WebAuthnEvidenceCustodyWireError("evidence custody control is not an exact object")
    if value["schema"] not in (INTENT_SCHEMA, RELAY_SCHEMA):
        raise WebAuthnEvidenceCustodyWireError("evidence custody schema is not source fixed")
    relay = value["schema"] == RELAY_SCHEMA
    _shape(value, relay=relay, signed="signatureBase64Url" in value)
    return relay


def _raw4(envelope_bytes, inputs_bytes, evaluation_context_bytes, historical_expectations_bytes):
    values = envelope_bytes, inputs_bytes, evaluation_context_bytes, historical_expectations_bytes
    for raw, maximum in zip(values, _BODY_LIMITS):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnEvidenceCustodyWireError("evidence custody requires bounded immutable originals")
    return values


def _body_commitments_on_work(*, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes, work):
    evidence.capture._SharedLedger(work)
    values = _raw4(envelope_bytes, inputs_bytes, evaluation_context_bytes, historical_expectations_bytes)
    result = {}
    for name, raw in zip(_BODY_NAMES, values):
        result[name + "BytesDigest"] = retention._bytes_digest(raw, work)
        result[name + "ByteCount"] = len(raw)
    return result


def _read_control(raw, *, relay, work):
    ledger = evidence.capture._SharedLedger(work)
    _schema(relay)
    value = evidence.wire._decode_object(raw, work=work, maximum_bytes=MAX_CONTROL_BYTES,
        maximum_nodes=MAX_CONTROL_NODES, maximum_depth=MAX_CONTROL_DEPTH)
    _shape(value, relay=relay)
    evidence.capability._canonical(raw, value, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    work.prepare_copy(value)
    unsigned = value.copy()
    signature = unsigned.pop("signatureBase64Url")
    unsigned_wire = evidence.capability._wire(unsigned, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    return value, signature, unsigned_wire


def _sign_control(unsigned, *, relay, private_key, public_key, work):
    ledger = evidence.capture._SharedLedger(work)
    schema = _schema(relay)
    if (not isinstance(private_key, retention.plan.Ed25519PrivateKey)
            or not isinstance(public_key, retention.plan.Ed25519PublicKey)):
        raise WebAuthnEvidenceCustodyWireError("evidence custody signing requires real independently held Ed25519 keys")
    _shape(unsigned, relay=relay, signed=False)
    owned = evidence.capture._JSONCapture(ledger, maximum_bytes=MAX_CONTROL_BYTES).visit(unsigned)
    envelope = {**owned, "signatureBase64Url": "A" * 86}
    _shape(envelope, relay=relay)
    unsigned_size, unsigned_nodes = work.measure(owned)
    envelope_size, envelope_nodes = work.measure(envelope)
    if (max(unsigned_size, envelope_size) > MAX_CONTROL_BYTES
            or max(unsigned_nodes, envelope_nodes) > MAX_CONTROL_NODES):
        raise WebAuthnEvidenceCustodyWireError("evidence custody signed output exceeds its control bound")
    # The actual encoder, post-callback encoder/comparison, final envelope and
    # signature transport are reserved before the first signing callback.
    work.charge(input_bytes=4 * unsigned_size + envelope_size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=2 * unsigned_nodes + envelope_nodes)
    frame_bytes = 2 * len(schema) + 9 + unsigned_size + 2 * 71
    if (work.limits.max_hashes - work.hash_work < 1
            or work.limits.max_input_bytes - work.input_bytes < frame_bytes + unsigned_size
            or work.limits.max_json_nodes - work.json_nodes < 4 + unsigned_nodes):
        raise WebAuthnEvidenceCustodyWireError("evidence custody cannot reserve its complete signature output")
    original = evidence.plan.core.canonical_bytes(owned)
    if len(original) != unsigned_size:
        raise WebAuthnEvidenceCustodyWireError("evidence custody unsigned bytes changed after measurement")
    message = evidence.plan._ascii(evidence.plan._frame(schema, (original,), work), work)
    signature = evidence.production._sign_and_verify(private_key, public_key, message, work)
    if work.measure(owned) != (unsigned_size, unsigned_nodes):
        raise WebAuthnEvidenceCustodyWireError("evidence custody graph changed during signing")
    if evidence.plan.core.canonical_bytes(owned) != original:
        raise WebAuthnEvidenceCustodyWireError("evidence custody unsigned bytes changed during signing")
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    evidence.plan.contract._base64url(encoded, signature=True)
    result = evidence.plan.core.canonical_bytes({**owned, "signatureBase64Url": encoded})
    if len(result) != envelope_size:
        raise WebAuthnEvidenceCustodyWireError("evidence custody final output changed after measurement")
    return result


def _bind_control(value, *, configuration_digest, generation_sequence, generation_digest, operation, work):
    evidence.capture._SharedLedger(work)
    expected = _pins(configuration_digest, generation_sequence, generation_digest, operation)
    _control(value)
    evidence.plan._same((value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"]), expected, work,
        "evidence custody control differs from independent configuration, generation or operation")


def _time_pins(value, maximum_age_ns, maximum_clock_skew_ns):
    shape = evidence.plan.contract
    shape._integer(maximum_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(maximum_clock_skew_ns, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if type(value) is dict and len(value) == 2:
        shape._object(value, _TIME_FIELDS, "evidence custody timing pair")
    else:
        _control(value)
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    shape._integer(issued, minimum=1)
    shape._integer(expires, minimum=1)
    if issued >= expires or expires - issued > maximum_age_ns:
        raise WebAuthnEvidenceCustodyWireError("evidence custody signed lifetime exceeds its policy")
    return issued, expires


def _fresh_on_work(value, *, window, maximum_age_ns, maximum_clock_skew_ns, work):
    # Hold immutable original times before clock callbacks. A two-field timing
    # pair is ordinary continuation data, never a substitute for a signature.
    issued, expires = _time_pins(value, maximum_age_ns, maximum_clock_skew_ns)
    window = clock._validate(window)
    if window[5] > maximum_age_ns or window[6] > maximum_clock_skew_ns:
        raise WebAuthnEvidenceCustodyWireError("evidence custody clock window widens its policy")
    now = clock._check_on_work(window, work=work)
    if issued > now + maximum_clock_skew_ns or now - issued > maximum_age_ns or now >= expires:
        raise WebAuthnEvidenceCustodyWireError("evidence custody control is stale, future-issued or expired")
    return now


def _open_control_window_on_work(value, *, maximum_age_ns, maximum_clock_skew_ns, work):
    issued, expires = _time_pins(value, maximum_age_ns, maximum_clock_skew_ns)
    window = clock._open_on_work(deadline_epoch_ns=expires,
        maximum_lifetime_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    _fresh_on_work({"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}, window=window,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    return window


def _signature(signature, unsigned_wire, *, relay, public_key, work):
    ledger = evidence.capture._SharedLedger(work)
    schema = _schema(relay)
    if not isinstance(public_key, retention.plan.Ed25519PublicKey):
        raise WebAuthnEvidenceCustodyWireError("evidence custody signature requires an independently held Ed25519 key")
    if type(unsigned_wire) is not bytes or not 2 <= len(unsigned_wire) <= MAX_CONTROL_BYTES:
        raise WebAuthnEvidenceCustodyWireError("evidence custody unsigned bytes exceed the control bound")
    evidence.capability._signature(public_key, signature, schema, unsigned_wire, ledger)


def _distinct_keys(planner_key, verifier_key, work):
    evidence.capture._SharedLedger(work)
    if any(not isinstance(key, retention.plan.Ed25519PublicKey) for key in (planner_key, verifier_key)):
        raise WebAuthnEvidenceCustodyWireError("evidence custody requires real independent role keys")
    # Two real raw32 exports and their full comparison, charged before either
    # finally-guarded callback. No copied key digest can substitute for them.
    work.charge(input_bytes=2 * 32 + 2 * 32)
    planner = evidence.production._callback(work, lambda: planner_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    verifier = evidence.production._callback(work, lambda: verifier_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
    if (any(type(raw) is not bytes or len(raw) != 32 for raw in (planner, verifier))
            or planner == verifier):
        raise WebAuthnEvidenceCustodyWireError("evidence custody planner and verifier keys are not distinct raw32")
