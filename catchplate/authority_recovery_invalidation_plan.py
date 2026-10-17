"""Signed invalidation originals with independent terminal/indexed replay.

The signature commits actual request, proof and independently held context
bytes. It does not claim a recovery witness, current roots, native acquisition,
durable retention or permission to execute. Both signing and verification run
the genuine raw proof engines; no supplied mutation/result observation enters.
All work and clocks are borrowed originals, never a renewed window or meter.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from catchplate import authority_recovery_invalidation_acquisition as acquisition
from catchplate import authority_webauthn_evidence as evidence
from catchplate import authority_webauthn_evidence_plan_clock as clock
from catchplate.authority_query_read_work import _ValidationWork


proof, shape = acquisition.proof, acquisition.shape
OPERATION = proof.OPERATION
SCHEMA = "catchplate.policyAuthorityRecoveryInvalidationPlan/v1"
ENVELOPE_SCHEMA = "catchplate.policyAuthorityRecoveryInvalidationPlanEnvelope/v1"
SIGNATURE_DOMAIN = "catchplate.policyAuthorityRecoveryInvalidationPlanSignature/v1"
IDENTITY_DOMAIN = "catchplate.policyAuthorityRecoveryInvalidationPlanIdentity/v1"
REQUEST_DOMAIN = "catchplate.policyAuthorityRecoveryInvalidationRequestIdentity/v1"
PROOF_DOMAIN = "catchplate.policyAuthorityRecoveryInvalidationProofIdentity/v1"
CONTEXT_DOMAIN = "catchplate.policyAuthorityRecoveryInvalidationContextIdentity/v1"
MAX_PARENT_BYTES = 32768
# The context repeats source-bounded request arguments and five/nine anchors;
# do not impose a smaller authorization policy than the original request.
MAX_CONTEXT_BYTES = proof.contract.MAX_REQUEST_BYTES + 16384
EXPECTATION_FIELDS = frozenset({"context", "configurationDigest", "plannerIdentity",
    "plannerSpkiDigest", "operationId", "originalDeadlineNs", "maximumPlanAgeNs",
    "maximumClockSkewNs"})
PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "operation", "operationId", "requestDigest",
    "configurationDigest", "plannerIdentity", "plannerSpkiDigest", "requestBytesDigest",
    "requestByteCount", "proofDigest", "proofByteCount", "contextDigest", "contextByteCount",
    "issuedAtEpochNs", "expiresAtEpochNs", "originalDeadlineNs"})


class RecoveryInvalidationPlanError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class VerifiedRecoveryInvalidationPlan:
    """Actual same-call replay output, never an accepted authority input."""

    envelope_bytes: bytes
    request_bytes: bytes
    proof_bytes: bytes
    context_bytes: bytes
    plan_digest: str
    replay: proof._Computation


def _require(value):
    if not value:
        raise RecoveryInvalidationPlanError("invalidation plan differs from independent originals or live bounds")


def _object(value, fields):
    _require(type(value) is dict and len(value) == len(fields)
        and all(type(name) is str for name in value) and set(value) == fields)


def _decode(raw, maximum, work, *, nodes=proof.MAX_JSON_NODES, depth=proof.MAX_JSON_DEPTH):
    value = proof.wire._decode_object(raw, work=work, maximum_bytes=maximum,
        maximum_nodes=nodes, maximum_depth=depth)
    canonical = work.wire(value)
    work.charge(input_bytes=len(raw) + len(canonical))
    _require(raw == canonical)
    return value


def _cutoff_ns(value):
    _require(type(value) is str and len(value) <= 40)
    now = datetime.fromisoformat(value)
    _require(now.tzinfo is timezone.utc and now.isoformat() == value)
    delta = now - datetime(1970, 1, 1, tzinfo=timezone.utc)
    result = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
    shape._integer(result, minimum=1)
    return result


def _originals(request_bytes, proof_bytes, expectations, work):
    _require(type(work) is _ValidationWork)
    _object(expectations, EXPECTATION_FIELDS)
    expected = proof._own(expectations, work)
    for name in ("configurationDigest", "plannerSpkiDigest", "operationId"):
        shape._digest(expected[name])
    evidence._identity(expected["plannerIdentity"])
    shape._integer(expected["originalDeadlineNs"], minimum=1)
    shape._integer(expected["maximumPlanAgeNs"], proof.contract.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(expected["maximumClockSkewNs"], proof.contract.VERIFIER_MAX_CLOCK_SKEW_NS)
    _require(type(proof_bytes) is bytes and 2 <= len(proof_bytes) <= proof.MAX_INPUT_BYTES)
    request = _decode(request_bytes, proof.contract.MAX_REQUEST_BYTES, work)
    acquisition._request(request, work)
    proof._parts(expected["context"], work)
    proof._same(request["arguments"], expected["context"]["arguments"], work)
    proof._same(request["requestDigest"], expected["context"]["requestDigest"], work)
    proof._same(request["operationId"], expected["operationId"], work)
    context_bytes = work.wire(expected["context"])
    _require(len(context_bytes) <= MAX_CONTEXT_BYTES)
    return expected, request, context_bytes


def _bind(payload, expected, request, request_bytes, proof_bytes, context_bytes, work):
    _object(payload, PAYLOAD_FIELDS)
    _require(payload["schema"] == SCHEMA and payload["sourceRevision"] == proof.contract.SOURCE_REVISION
        and type(payload["operation"]) is str and payload["operation"] == OPERATION)
    evidence._identity(payload["plannerIdentity"])
    for name in ("operationId", "requestDigest", "configurationDigest", "plannerSpkiDigest",
            "requestBytesDigest", "proofDigest", "contextDigest"):
        shape._digest(payload[name])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs", "originalDeadlineNs"):
        shape._integer(payload[name], minimum=1)
    for name in ("configurationDigest", "plannerIdentity", "plannerSpkiDigest",
            "operationId", "originalDeadlineNs"):
        proof._same(payload[name], expected[name], work)
    proof._same(payload["requestDigest"], request["requestDigest"], work)
    for raw, domain, digest, count, maximum in (
        (request_bytes, REQUEST_DOMAIN, "requestBytesDigest", "requestByteCount", proof.contract.MAX_REQUEST_BYTES),
        (proof_bytes, PROOF_DOMAIN, "proofDigest", "proofByteCount", proof.MAX_INPUT_BYTES),
        (context_bytes, CONTEXT_DOMAIN, "contextDigest", "contextByteCount", MAX_CONTEXT_BYTES),
    ):
        shape._integer(payload[count], maximum, minimum=2)
        proof._same(payload[count], len(raw), work)
        proof._same(payload[digest], evidence.plan._frame(domain, (raw,), work), work)


class _Live:
    def __init__(self, expected, payload, window, check, work):
        _require(callable(check) and type(work) is _ValidationWork)
        self.window = clock._validate(window)
        self.issued, self.expires = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        self.maximum, self.skew = expected["maximumPlanAgeNs"], expected["maximumClockSkewNs"]
        _require(self.window[5] <= self.maximum and self.window[6] <= self.skew)
        self.deadline = min(expected["originalDeadlineNs"], self.window[4],
            self.window[1] + self.expires - self.window[0])
        self.cutoff = _cutoff_ns(expected["context"]["databaseNow"])
        self.work, self.limits, self.callback = work, work.limits, check
        self.maximums = (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes)
        self.metrics = work.hash_work, work.input_bytes, work.json_nodes
        self.identity = os.getpid(), threading.get_ident()
        self.busy = self.failed = False
        self.last = 0

    def local(self):
        _require(not self.failed and self.identity == (os.getpid(), threading.get_ident())
            and self.work.limits is self.limits
            and (self.limits.max_hashes, self.limits.max_input_bytes, self.limits.max_json_nodes) == self.maximums)
        proof.batch._SharedLedger(self.work)
        actual = self.work.hash_work, self.work.input_bytes, self.work.json_nodes
        _require(all(type(value) is int and value >= before for value, before in zip(actual, self.metrics)))
        self.metrics = actual
        now = clock._check_on_work(self.window, work=self.work)
        _require(0 < self.issued < self.expires and self.expires - self.issued <= self.maximum
            and self.issued <= now + self.skew and now - self.issued <= self.maximum and now < self.expires
            and abs(self.cutoff - self.issued) <= self.skew and self.cutoff < self.expires)
        mono = evidence.production._callback(self.work, time.monotonic_ns)
        _require(type(mono) is int and self.last <= mono < self.deadline)
        self.last = mono

    def checked(self):
        try:
            _require(not self.busy)
            self.busy = True
            self.local()
            _require(evidence.production._callback(self.work, self.callback) is None)
            self.local()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False


def _sign_payload(payload, private, public, work):
    ledger = evidence.capture._SharedLedger(work)
    encoded = evidence.capability._wire(payload, ledger, MAX_PARENT_BYTES, 2048)
    message = evidence.plan._ascii(evidence.plan._frame(SIGNATURE_DOMAIN, (encoded,), work), work)
    placeholder = {"schema": ENVELOPE_SCHEMA, "payload": payload, "signatureBase64Url": "A" * 86}
    size, nodes = work.measure(placeholder)
    payload_size, payload_nodes = work.measure(payload)
    _require(size <= MAX_PARENT_BYTES and nodes <= 2048)
    work.charge(input_bytes=3 * payload_size + size + evidence.production._SIGNATURE_TRANSPORT_BYTES,
        json_nodes=payload_nodes + nodes)
    _require(work.limits.max_input_bytes - work.input_bytes >= payload_size
        and work.limits.max_json_nodes - work.json_nodes >= payload_nodes)
    signature = evidence.production._sign_and_verify(private, public, message, work)
    _require(work.measure(payload) == (payload_size, payload_nodes)
        and evidence.plan.core.canonical_bytes(payload) == encoded)
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    shape._base64url(encoded_signature, signature=True)
    result = evidence.plan.core.canonical_bytes({"schema": ENVELOPE_SCHEMA,
        "payload": payload, "signatureBase64Url": encoded_signature})
    _require(len(result) == size)
    return result


def _produce_on_work(*, request_bytes, proof_bytes, expectations, planner_private_key,
        planner_public_key, issued_at_epoch_ns, expires_at_epoch_ns, live_window, check, work):
    """Replay raw originals before signing; no native observation input."""
    _require(isinstance(planner_private_key, Ed25519PrivateKey)
        and isinstance(planner_public_key, Ed25519PublicKey))
    expected, request, context_bytes = _originals(request_bytes, proof_bytes, expectations, work)
    window = clock._validate(live_window)
    _require(issued_at_epoch_ns == window[0]
        and expected["maximumPlanAgeNs"] == window[5] and expected["maximumClockSkewNs"] == window[6]
        and expected["originalDeadlineNs"] <= window[4]
        and expires_at_epoch_ns == window[0] + expected["originalDeadlineNs"] - window[1])
    work.charge(input_bytes=8192, json_nodes=256)
    payload = {"schema": SCHEMA, "sourceRevision": proof.contract.SOURCE_REVISION, "operation": OPERATION,
        **{name: expected[name] for name in ("operationId", "configurationDigest", "plannerIdentity",
            "plannerSpkiDigest", "originalDeadlineNs")}, "requestDigest": request["requestDigest"],
        "requestBytesDigest": evidence.plan._frame(REQUEST_DOMAIN, (request_bytes,), work),
        "requestByteCount": len(request_bytes), "proofDigest": evidence.plan._frame(PROOF_DOMAIN, (proof_bytes,), work),
        "proofByteCount": len(proof_bytes), "contextDigest": evidence.plan._frame(CONTEXT_DOMAIN, (context_bytes,), work),
        "contextByteCount": len(context_bytes), "issuedAtEpochNs": issued_at_epoch_ns,
        "expiresAtEpochNs": expires_at_epoch_ns}
    _bind(payload, expected, request, request_bytes, proof_bytes, context_bytes, work)
    live = _Live(expected, payload, window, check, work)
    try:
        live.checked()
        evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
        evidence.keys._pair_on_work(planner_private_key, planner_public_key, work)
        live.checked()
        replayed = proof.replay_originals(proof_bytes, expected_context=expected["context"], work=work)
        live.checked()
        envelope = _sign_payload(payload, planner_private_key, planner_public_key, work)
        live.checked()
        work.charge(input_bytes=1024, json_nodes=32)
        result = VerifiedRecoveryInvalidationPlan(envelope, request_bytes, proof_bytes, context_bytes,
            evidence.plan._frame(IDENTITY_DOMAIN, (envelope,), work), replayed)
        live.checked()
        return result
    except BaseException:
        live.failed = True
        raise


def verify_originals(*, envelope_bytes, request_bytes, proof_bytes, expectations,
        planner_public_key, live_window, check, work):
    """Authenticate original bytes then replay against independent context."""
    _require(isinstance(planner_public_key, Ed25519PublicKey))
    expected, request, context_bytes = _originals(request_bytes, proof_bytes, expectations, work)
    envelope = _decode(envelope_bytes, MAX_PARENT_BYTES, work, nodes=2048, depth=8)
    _object(envelope, {"schema", "payload", "signatureBase64Url"})
    _require(envelope["schema"] == ENVELOPE_SCHEMA)
    shape._base64url(envelope["signatureBase64Url"], signature=True)
    payload = envelope["payload"]
    _bind(payload, expected, request, request_bytes, proof_bytes, context_bytes, work)
    live = _Live(expected, payload, live_window, check, work)
    try:
        live.checked()
        evidence.keys._public_binding(planner_public_key, expected["plannerSpkiDigest"], work)
        encoded = work.wire(payload)
        evidence.capability._signature(planner_public_key, envelope["signatureBase64Url"],
            SIGNATURE_DOMAIN, encoded, evidence.capture._SharedLedger(work))
        evidence.capability._canonical(encoded, payload, evidence.capture._SharedLedger(work),
            MAX_PARENT_BYTES, 2048)
        live.checked()
        replayed = proof.replay_originals(proof_bytes, expected_context=expected["context"], work=work)
        live.checked()
        work.charge(input_bytes=1024, json_nodes=32)
        result = VerifiedRecoveryInvalidationPlan(envelope_bytes, request_bytes, proof_bytes, context_bytes,
            evidence.plan._frame(IDENTITY_DOMAIN, (envelope_bytes,), work), replayed)
        live.checked()
        return result
    except BaseException:
        live.failed = True
        raise
