"""Signed original JIT planning scope, never request or execution authority.

The verifier signs its actual original clock bracket and exact request/root
observations. A receiver supplies its OWN native sampled window and independent
key/configuration/generation/peer pins. Only after genuine signature admission
may the authenticated sender bracket reach the fixed producer; it is never
relabeled as a receiving sample. Both original and receiving bounds remain live.
No allowance, clock window, SQL, socket, current-root or successful proof is made.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import re
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from catchplate import authority_jit_compound_plan as parent
from catchplate import authority_jit_compound_service as production_service
from catchplate.authority_query_read_work import _ValidationWork


source, evidence, clock = parent.source, parent.evidence, parent.clock
OPERATION = "jit.assertion.issue"
SCHEMA = "catchplate.policyAuthorityJitCompoundPlanningRequest/v1"
ENVELOPE_SCHEMA = "catchplate.signedPolicyAuthorityJitCompoundPlanningRequest/v1"
PURPOSE = "produce-jit-compound-plan"
SIGNATURE_DOMAIN = "catchplate.policyAuthorityJitCompoundRequestSignature/v1"
IDENTITY_DOMAIN = "catchplate.policyAuthorityJitCompoundRequestIdentity/v1"
MAX_CONTROL_BYTES, MAX_CONTROL_NODES, MAX_CONTROL_DEPTH = 32768, 4096, 12
MAX_REQUEST_BYTES = source.authority.MAX_REQUEST_BYTES
RAW4_MAXIMA = (parent.MAX_PARENT_BYTES, MAX_REQUEST_BYTES,
    parent.MAX_CONTEXT_BYTES, parent.MAX_MANIFEST_BYTES)
PIN_FIELDS = frozenset({"configurationDigest", "generationSequence", "generationDigest",
    "verifierIdentity", "verifierSpkiDigest", "plannerIdentity", "plannerSpkiDigest"})
FIELDS = PIN_FIELDS | frozenset({"schema", "sourceRevision", "purpose", "operation",
    "requestDigest", "operationId", "requestBytesDigest", "requestByteCount",
    "businessBeforeRoots", "authorizationBeforeRoots", "countedBeforeHeads",
    "originalWindow", "issuedAtEpochNs", "expiresAtEpochNs", "originalDeadlineNs",
    "senderProcessId", "senderBootId"})
_BOOT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


class JitCompoundRequestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _VerifiedRequest:
    """Same-call output only; the measured owner accepts original bytes only."""

    payload: dict
    request: dict
    original_window: tuple


def _require(value):
    if not value:
        raise JitCompoundRequestError("JIT planning request differs from its original signed scope")


def _raw(value, maximum):
    _require(type(value) is bytes and 2 <= len(value) <= maximum)
    return value


def _boot(value):
    _require(type(value) is str and _BOOT.fullmatch(value) is not None)
    return value


def _pins(value, work):
    parent._object(value, PIN_FIELDS)
    owned = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work),
        maximum_bytes=8192).visit(value)
    for name in ("configurationDigest", "generationDigest", "verifierSpkiDigest", "plannerSpkiDigest"):
        source.shape._digest(owned[name])
    source.shape._integer(owned["generationSequence"])
    for name in ("verifierIdentity", "plannerIdentity"):
        evidence._identity(owned[name])
    _require(owned["verifierSpkiDigest"] != owned["plannerSpkiDigest"])
    return owned


def _inputs(request_bytes, business, authorization, heads, work):
    _raw(request_bytes, MAX_REQUEST_BYTES)
    request = parent._decode(request_bytes, MAX_REQUEST_BYTES, work,
        nodes=source.reads.MAX_JSON_NODES, depth=source.reads.MAX_JSON_DEPTH)
    return production_service._inputs_on_work(request, business, authorization, heads, work)


def _shape(payload, work):
    parent._object(payload, FIELDS)
    _require(payload["schema"] == SCHEMA and payload["sourceRevision"] == source.authority.SOURCE_REVISION
        and payload["purpose"] == PURPOSE and payload["operation"] == OPERATION)
    work.charge(input_bytes=16384, json_nodes=1024)
    _pins({name: payload[name] for name in PIN_FIELDS}, work)
    for name in ("requestDigest", "operationId", "requestBytesDigest"):
        source.shape._digest(payload[name])
    source.shape._integer(payload["requestByteCount"], MAX_REQUEST_BYTES, minimum=2)
    for name in ("issuedAtEpochNs", "expiresAtEpochNs", "originalDeadlineNs"):
        source.shape._integer(payload[name], minimum=1)
    source.shape._integer(payload["senderProcessId"], 2**31 - 1, minimum=1)
    _boot(payload["senderBootId"])
    _require(type(payload["originalWindow"]) is list and len(payload["originalWindow"]) == 7)
    original = clock._validate(tuple(payload["originalWindow"]))
    _require(original[2] < payload["originalDeadlineNs"] <= original[4]
        and payload["issuedAtEpochNs"] == original[0]
        and payload["expiresAtEpochNs"] == original[0] + payload["originalDeadlineNs"] - original[1])
    # Structural source rosters only; these signed observations do not prove
    # currentness. The native producer later matches the actual database roots.
    contracts = source.primary_contract.primary_table_contracts(OPERATION)
    for name, root_class in (("businessBeforeRoots", "business"),
            ("authorizationBeforeRoots", "authorization")):
        values = payload[name]
        _require(type(values) is list and len(values) == 4)
        for value in values:
            parent._object(value, parent._ROOT_FIELDS)
            source.shape._digest(value["rootDigest"])
            source.shape._integer(value["rootRevision"])
            source.shape._integer(value["leafCount"])
        _require(tuple(value["table"] for value in values)
            == tuple(item.table for item in contracts if item.root_class == root_class))
    heads = payload["countedBeforeHeads"]
    _require(type(heads) is list and len(heads) == 12)
    for value in heads:
        parent._object(value, parent._HEAD_FIELDS)
        source.shape._digest(value["rootDigest"])
        source.shape._integer(value["indexRevision"])
        source.shape._integer(value["leafCount"])
    _require(tuple(value["indexId"] for value in heads) == source.heads._jit_receipt_ids())
    return original


def _control(control_bytes, work):
    _raw(control_bytes, MAX_CONTROL_BYTES)
    envelope = parent._decode(control_bytes, MAX_CONTROL_BYTES, work,
        nodes=MAX_CONTROL_NODES, depth=MAX_CONTROL_DEPTH)
    parent._object(envelope, frozenset({"schema", "payload", "signatureBase64Url"}))
    _require(envelope["schema"] == ENVELOPE_SCHEMA)
    _shape(envelope["payload"], work)
    source.shape._base64url(envelope["signatureBase64Url"], signature=True)
    return envelope


def decode_control(control_bytes, *, work):
    """Canonical shape only. Parsed time fields can only restrict pre-admission."""
    return _control(control_bytes, work)["payload"]


def _live(original, receiver, deadline, work):
    """Original signed bracket and independently sampled receiver, kept distinct."""
    receiving_now = clock._check_on_work(receiver, work=work)
    now = clock._check_on_work(original, work=work)
    expires = original[0] + deadline - original[1]
    _require(now >= receiving_now and original[0] <= now + receiver[6]
        and now - original[0] <= receiver[5] and now < min(expires, receiver[3]))
    mono = evidence.production._callback(work, time.monotonic_ns)
    _require(type(mono) is int and original[2] <= mono < min(deadline, receiver[4]))
    return now


def _bind(payload, request_bytes, request, pins, work):
    for name in PIN_FIELDS:
        parent._same(payload[name], pins[name], work)
    for name in ("requestDigest", "operationId"):
        parent._same(payload[name], request[name], work)
    parent._same(payload["requestByteCount"], len(request_bytes), work)
    parent._same(payload["requestBytesDigest"],
        evidence.plan._frame(parent.REQUEST_DOMAIN, (request_bytes,), work), work)


def _sign(payload, private, public, work):
    _shape(payload, work)
    ledger = evidence.capture._SharedLedger(work)
    unsigned = evidence.capability._wire(payload, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    message = evidence.plan._ascii(evidence.plan._frame(SIGNATURE_DOMAIN, (unsigned,), work), work)
    work.charge(input_bytes=512, json_nodes=16)
    placeholder = {"schema": ENVELOPE_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(placeholder)
    payload_size, payload_nodes = work.measure(payload)
    _require(size <= MAX_CONTROL_BYTES and nodes <= MAX_CONTROL_NODES)
    work.charge(input_bytes=3 * payload_size + size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=payload_nodes + nodes)
    _require(work.limits.max_input_bytes - work.input_bytes >= payload_size
        and work.limits.max_json_nodes - work.json_nodes >= payload_nodes)
    signature = evidence.production._sign_and_verify(private, public, message, work)
    _require(work.measure(payload) == (payload_size, payload_nodes)
        and evidence.plan.core.canonical_bytes(payload) == unsigned)
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    source.shape._base64url(encoded, signature=True)
    result = evidence.plan.core.canonical_bytes({"schema": ENVELOPE_SCHEMA,
        "payload": payload, "signatureBase64Url": encoded})
    _require(len(result) == size)
    return result


def sign_request(*, request_bytes, business_before_roots, authorization_before_roots,
        expected_counted_heads, pins, verifier_private_key, verifier_public_key,
        original_window, original_deadline_ns, sender_process_id, sender_boot_id, work):
    _require(type(work) is _ValidationWork and isinstance(verifier_private_key, Ed25519PrivateKey)
        and isinstance(verifier_public_key, Ed25519PublicKey))
    request, business, authorization, heads = _inputs(request_bytes,
        business_before_roots, authorization_before_roots, expected_counted_heads, work)
    held_pins = _pins(pins, work)
    original = clock._validate(original_window)
    source.shape._integer(original_deadline_ns, minimum=1)
    _require(original[2] < original_deadline_ns <= original[4])
    source.shape._integer(sender_process_id, 2**31 - 1, minimum=1)
    _boot(sender_boot_id)
    work.charge(input_bytes=MAX_CONTROL_BYTES, json_nodes=MAX_CONTROL_NODES)
    payload = {"schema": SCHEMA, "sourceRevision": source.authority.SOURCE_REVISION,
        "purpose": PURPOSE, "operation": OPERATION, **held_pins,
        "requestDigest": request["requestDigest"], "operationId": request["operationId"],
        "requestBytesDigest": evidence.plan._frame(parent.REQUEST_DOMAIN, (request_bytes,), work),
        "requestByteCount": len(request_bytes), "businessBeforeRoots": list(business),
        "authorizationBeforeRoots": list(authorization), "countedBeforeHeads": list(heads),
        "originalWindow": list(original), "issuedAtEpochNs": original[0],
        "expiresAtEpochNs": original[0] + original_deadline_ns - original[1],
        "originalDeadlineNs": original_deadline_ns, "senderProcessId": sender_process_id,
        "senderBootId": sender_boot_id}
    _live(original, original, original_deadline_ns, work)
    evidence.keys._public_binding(verifier_public_key, held_pins["verifierSpkiDigest"], work)
    evidence.keys._pair_on_work(verifier_private_key, verifier_public_key, work)
    result = _sign(payload, verifier_private_key, verifier_public_key, work)
    _live(original, original, original_deadline_ns, work)
    return result


def verify_request(*, control_bytes, request_bytes, pins, verifier_public_key,
        receiver_window, expected_sender_process_id, expected_boot_id, work):
    _require(type(work) is _ValidationWork and isinstance(verifier_public_key, Ed25519PublicKey))
    held_pins = _pins(pins, work)
    receiver = clock._validate(receiver_window)
    source.shape._integer(expected_sender_process_id, 2**31 - 1, minimum=1)
    _boot(expected_boot_id)
    envelope = _control(control_bytes, work)
    payload = envelope["payload"]
    work.charge(input_bytes=32768, json_nodes=1024)
    request, _business, _authorization, _heads = _inputs(request_bytes,
        tuple(payload["businessBeforeRoots"]), tuple(payload["authorizationBeforeRoots"]),
        tuple(payload["countedBeforeHeads"]), work)
    _bind(payload, request_bytes, request, held_pins, work)
    parent._same(payload["senderProcessId"], expected_sender_process_id, work)
    parent._same(payload["senderBootId"], expected_boot_id, work)
    original = clock._validate(tuple(payload["originalWindow"]))
    _require(original[5] <= receiver[5] and original[6] <= receiver[6])
    # Before authentication this can only refuse; no native producer or output
    # receives the supplied original tuple until the genuine signature passes.
    _live(original, receiver, payload["originalDeadlineNs"], work)
    ledger = evidence.capture._SharedLedger(work)
    unsigned = evidence.capability._wire(payload, ledger, MAX_CONTROL_BYTES, MAX_CONTROL_NODES)
    evidence.keys._public_binding(verifier_public_key, held_pins["verifierSpkiDigest"], work)
    evidence.capability._signature(verifier_public_key, envelope["signatureBase64Url"],
        SIGNATURE_DOMAIN, unsigned, ledger)
    _live(original, receiver, payload["originalDeadlineNs"], work)
    return _VerifiedRequest(payload, request, original)


def _join_parent(raw4, payload, pins, planner_public_key, work):
    """Cheap same-call raw4/signature join, NOT independent receiving replay."""
    _require(type(raw4) is tuple and len(raw4) == 4)
    for raw, maximum in zip(raw4, RAW4_MAXIMA, strict=True):
        _raw(raw, maximum)
    envelope = parent._decode(raw4[0], parent.MAX_PARENT_BYTES, work, nodes=2048, depth=12)
    parent._object(envelope, frozenset({"schema", "payload", "signatureBase64Url"}))
    _require(envelope["schema"] == parent.ENVELOPE_SCHEMA)
    signed = envelope["payload"]
    parent._payload_shape(signed)
    for name in ("requestDigest", "operationId", "configurationDigest", "plannerIdentity",
            "plannerSpkiDigest", "issuedAtEpochNs", "expiresAtEpochNs"):
        parent._same(signed[name], payload[name], work)
    for raw, domain, digest_name, count_name in (
            (raw4[1], parent.REQUEST_DOMAIN, "requestBytesDigest", "requestByteCount"),
            (raw4[2], parent.compound.CONTEXT_DOMAIN, "contextDigest", "contextByteCount"),
            (raw4[3], parent.MANIFEST_DOMAIN, "manifestDigest", "manifestByteCount")):
        parent._same(signed[count_name], len(raw), work)
        parent._same(signed[digest_name], evidence.plan._frame(domain, (raw,), work), work)
    parent._same(signed["requestBytesDigest"], payload["requestBytesDigest"], work)
    ledger = evidence.capture._SharedLedger(work)
    unsigned = evidence.capability._wire(signed, ledger, parent.MAX_PARENT_BYTES, 2048)
    evidence.keys._public_binding(planner_public_key, pins["plannerSpkiDigest"], work)
    evidence.capability._signature(planner_public_key, envelope["signatureBase64Url"],
        parent.SIGNATURE_DOMAIN, unsigned, ledger)
